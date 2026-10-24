"""Conservative persisted Malaysian-calendar-day CHILD counter accounting.

Only deltas with both endpoints within the named day are counted. An unseen
CHILD is a baseline, never a reason to import its complete lifetime into today.
"""
import copy
import datetime as dt
import math
import re
from zoneinfo import ZoneInfo

TIMEZONE='Asia/Kuala_Lumpur'
TZ=ZoneInfo(TIMEZONE)
LIMITATION=('今日为马来西亚日历日的已采样小计。首次发现会话仅建立基线；跨午夜增量、'
            '未采到的短会话及删除前尾部可能遗漏。采样缺口后仍能归属同日的已知会话增量可补入。'
            '这不是完整流量账单；空白或统计不可用不代表0。')


def stamp(value):
    return dt.datetime.fromtimestamp(value,dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')


def timestamp(value):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0:
        raise ValueError('invalid timestamp')
    try:stamp(value)
    except (OverflowError, OSError) as exc:
        raise ValueError('timestamp outside supported range') from exc
    return value


def day_info(wall):
    local=dt.datetime.fromtimestamp(timestamp(wall),TZ)
    start=dt.datetime.combine(local.date(),dt.time(),TZ).timestamp()
    return local.date().isoformat(),start


def uint(value,limit=2**64):
    if type(value)is not int or not 0<=value<limit:raise ValueError('invalid counter')
    return value


def text(value,pattern):
    if not isinstance(value,str) or not re.fullmatch(pattern,value):raise ValueError('invalid identity')
    return value


class Ledger:
    def __init__(self,devices,epoch,wall,persisted=None):
        text(epoch,r'[A-Za-z0-9_-]{1,48}')
        timestamp(wall)
        if not isinstance(devices,dict) or not 1<=len(devices)<=100:raise ValueError('invalid devices')
        self.names={}
        for key,name in devices.items():
            text(key,r'[A-Za-z0-9_-]{1,48}')
            if not isinstance(name,str) or not 1<=len(name)<=80 or any(ord(c)<32 or ord(c)==127 for c in name):
                raise ValueError('invalid display name')
            self.names[key]=name
        self.epoch=epoch
        self.started=stamp(wall)
        self.day,self.day_start=day_info(wall)
        self.observed_since=None
        self.devices={key:dict(up=0,down=0,seen=False,since=None) for key in self.names}
        self.sas={}
        self.last_wall=None
        self.last_mono=None
        self.last_snapshot=None
        self.interrupted=True
        if persisted is not None:
            self._restore(persisted,wall)

    def _restore(self,raw,wall):
        keys={'version','timezone','epoch','day','day_start','observed_since','last_wall','names','devices','sas'}
        if not isinstance(raw,dict) or set(raw)!=keys or type(raw['version'])is not int or raw['version']!=2:
            raise ValueError('invalid persisted ledger')
        if raw['timezone']!=TIMEZONE or raw['names']!=self.names:
            raise ValueError('changed ledger scope')
        text(raw['epoch'],r'[A-Za-z0-9_-]{1,48}')
        saved_day,saved_start=day_info(raw['day_start'])
        if raw['day']!=saved_day or raw['day_start']!=saved_start or saved_day>self.day:
            raise ValueError('future or invalid day')
        seen_at=raw['observed_since'];last=raw['last_wall']
        if (seen_at is None)!=(last is None):raise ValueError('incomplete observation range')
        if last is not None:
            timestamp(seen_at);timestamp(last)
            if day_info(seen_at)[0]!=saved_day or day_info(last)[0]!=saved_day or not seen_at<=last<=wall+0.001:
                raise ValueError('invalid or future observation range')
        if not isinstance(raw['devices'],dict) or set(raw['devices'])!=set(self.names):
            raise ValueError('device scope differs')
        for d in raw['devices'].values():
            if not isinstance(d,dict) or set(d)!= {'up','down','seen','since'} or type(d['seen'])is not bool:
                raise ValueError('invalid device ledger')
            uint(d['up'],10**30);uint(d['down'],10**30)
            if d['since'] is not None:
                timestamp(d['since'])
                if last is None or not seen_at<=d['since']<=last or day_info(d['since'])[0]!=saved_day:
                    raise ValueError('invalid device baseline')
            if d['seen'] and d['since'] is None:raise ValueError('missing device baseline')
            if not d['seen'] and (d['up'] or d['down']):raise ValueError('unobserved nonzero subtotal')
        if not isinstance(raw['sas'],dict) or len(raw['sas'])>20000:raise ValueError('SA journal limit')
        for key,v in raw['sas'].items():
            text(key,r'[A-Za-z0-9_:-]{1,256}')
            if (not isinstance(v,dict) or set(v)!= {'device','up','down','active','regressed','last_seen','since'}
                    or v['device'] not in self.names or type(v['active'])is not bool or type(v['regressed'])is not bool):
                raise ValueError('invalid highwater')
            uint(v['up']);uint(v['down']);timestamp(v['last_seen']);timestamp(v['since'])
            if last is None or not seen_at<=v['last_seen']<=last or v['since']>v['last_seen']+5:
                raise ValueError('invalid highwater range')
            device_since = raw['devices'][v['device']]['since']
            if device_since is None or device_since > v['last_seen']:
                raise ValueError('highwater has no earlier device baseline')
        self.epoch=raw['epoch']
        # A previous day is validated in full before a new day may be started.
        # No persisted pre-midnight lifetime or crossing delta is imported.
        if saved_day==self.day:
            self.day_start=saved_start;self.observed_since=seen_at;self.last_wall=last
            self.devices=copy.deepcopy(raw['devices']);self.sas=copy.deepcopy(raw['sas'])
            if last is not None:self.last_snapshot=self._render(last,'unavailable','unknown',None,None)

    def to_journal(self):
        return copy.deepcopy(dict(version=2,timezone=TIMEZONE,epoch=self.epoch,day=self.day,
            day_start=self.day_start,observed_since=self.observed_since,last_wall=self.last_wall,
            names=self.names,devices=self.devices,sas=self.sas))

    def _render(self,wall,collector,server,sums,dt_mono):
        rows=[]
        for key,total in self.devices.items():
            current=sums[key] if sums is not None else None
            # A mixed fresh sample must not export frozen unknown-device totals
            # as a new measured zero interval. The persisted subtotal is kept.
            measured=total['seen'] and (sums is None or current is not None)
            online=bool(current and current['since'])
            rates=bool(current and current['rates'] and online and dt_mono is not None)
            rows.append(dict(id=key,name=self.names[key],state=('online' if online else 'offline') if current is not None else 'unknown',
                connected_since=stamp(min(current['since'])) if online else None,
                upload_bps=current['up']*8/dt_mono if rates else None,
                download_bps=current['down']*8/dt_mono if rates else None,
                rate_window_ms=max(1,round(dt_mono*1000)) if rates else None,
                upload_bytes=str(total['up']) if measured else None,
                download_bytes=str(total['down']) if measured else None,
                totals_since=stamp(total['since']) if measured else None,
                counter_epoch=('daily_'+self.epoch+'_'+self.day.replace('-','')) if measured else None,
                counter_state='partial' if measured else 'unavailable'))
        return dict(schema_version=2,observed_at=stamp(wall) if wall is not None else None,
            collector=dict(state=collector,started_at=self.started),server=dict(state=server),
            coverage=dict(kind='ipsec_child_counters',totals_scope='calendar_day',timezone=TIMEZONE,
                day=self.day,day_started_at=stamp(self.day_start),
                observed_since=stamp(self.observed_since) if self.observed_since is not None else None,
                limitation=LIMITATION),devices=rows)

    def unavailable(self):
        self.interrupted=True
        return self._render(self.last_wall,'unavailable','unknown',None,None)

    def observe(self,rows,*,wall,mono,server_running,unknown_devices=()):
        timestamp(wall);timestamp(mono)
        if (type(unknown_devices) not in (list,tuple) or any(type(d)is not str or d not in self.names for d in unknown_devices)
                or len(set(unknown_devices))!=len(unknown_devices) or (unknown_devices and server_running is not True)):
            raise ValueError('invalid unknown device scope')
        unknown=set(unknown_devices)
        if (type(server_running)is not bool or not isinstance(rows,list) or len(rows)>200 or
                (self.last_mono is not None and mono<=self.last_mono) or (rows and not server_running)):
            raise ValueError('invalid complete sample')
        newday,start=day_info(wall)
        if newday<self.day or (self.last_wall is not None and wall<self.last_wall):
            raise ValueError('wall clock regressed')
        validated=[];keys=set()
        for row in rows:
            if not isinstance(row,dict) or set(row)!= {'device','sa_key','upload_bytes','download_bytes','connected_since'}:
                raise ValueError('invalid sample row')
            device,key,since=row['device'],row['sa_key'],row['connected_since']
            text(key,r'[A-Za-z0-9_:-]{1,256}');timestamp(since)
            if device not in self.names or device in unknown or key in keys or since>wall+5:
                raise ValueError('unattributed or duplicate sample')
            up,down=uint(row['upload_bytes']),uint(row['download_bytes'])
            old=self.sas.get(key)
            if old and old['device']!=device:raise ValueError('highwater identity reassigned')
            keys.add(key);validated.append((device,key,up,down,since))
        if newday==self.day and len(set(self.sas)|keys)>20000:raise ValueError('accounting capacity reached')
        # Complete input validation precedes every mutation.
        dt_mono=mono-self.last_mono if self.last_mono is not None else None
        clock_ok=self.last_wall is None or (dt_mono is not None and abs(wall-self.last_wall-dt_mono)<=2)
        continuity=dt_mono is not None and dt_mono<=15 and not self.interrupted and clock_ok
        if newday!=self.day:
            self.day,self.day_start=newday,start
            self.observed_since=None;self.last_wall=None;self.last_mono=None
            self.devices={key:dict(up=0,down=0,seen=False,since=None) for key in self.names}
            self.sas={};continuity=False;dt_mono=None
        previous_sample=self.last_wall is not None
        if self.observed_since is None:self.observed_since=wall
        sums={key:None if key in unknown else dict(up=0,down=0,rates=continuity,since=[]) for key in self.names}
        old_active={key for key,v in self.sas.items() if v['active']}
        for device in self.devices:
            if device in unknown:continue
            device_had_sample = self.devices[device]['since'] is not None
            if not device_had_sample:self.devices[device]['since']=wall
            # A newly registered device needs its own second complete sample.
            # Existing devices keep their same-day baseline across a restart.
            if previous_sample and device_had_sample:self.devices[device]['seen']=True
        for device,key,up,down,since in validated:
            total,current=self.devices[device],sums[device]
            old=self.sas.get(key);current['since'].append(since)
            if old is None:
                current['rates']=False
            else:
                du,dd=max(0,up-old['up']),max(0,down-old['down'])
                total['up']+=du;total['down']+=dd
                current['up']+=du;current['down']+=dd
                if (not old['active'] or old['regressed'] or up<old['up'] or down<old['down']):
                    current['rates']=False
            self.sas[key]=dict(device=device,up=max(up,old['up']) if old else up,
                down=max(down,old['down']) if old else down,active=True,
                regressed=bool(old and (up<old['up'] or down<old['down'])),last_seen=wall,since=since)
        for key in old_active-keys:
            self.sas[key]['active']=False
            current=sums[self.sas[key]['device']]
            if current is not None:current['rates']=False
        for current in sums.values():
            if current is not None and current['rates'] and max(current['up'],current['down'])*8/dt_mono>1e15:current['rates']=False
        self.last_wall,self.last_mono=wall,mono
        self.last_snapshot=self._render(wall,'ok','running' if server_running else 'stopped',sums,dt_mono)
        self.interrupted=False
        return self.last_snapshot
