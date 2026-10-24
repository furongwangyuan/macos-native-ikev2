"""Whitelist reconstruction for local telemetry; never serve arbitrary JSON."""
import datetime as dt
import math
import re
from ledger_core_v3 import LIMITATION, TIMEZONE, day_info

EMPTY = dict(schema_version=3, registry_revision=None, observed_at=None,
             collector=dict(state='unavailable', started_at=None), server=dict(state='unknown'),
             coverage=dict(kind='ipsec_child_counters', totals_scope='calendar_day', timezone=TIMEZONE,
                 day=None,day_started_at=None,observed_since=None,limitation=LIMITATION), devices=[])

def reject():
    raise ValueError('invalid telemetry contract')

def text(value, size):
    if not isinstance(value,str) or not 1<=len(value)<=size or any(ord(c)<32 or ord(c)==127 for c in value): reject()
    return value

def date(value):
    if value is None:return None
    if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z',value):reject()
    # macOS system Python 3.9 accepts three/six fractional digits, unlike the
    # wider input grammar. Normalize before parsing and before string ordering.
    main,sep,fraction=value[:-1].partition('.')
    canonical=main+'.'+(fraction if sep else '').ljust(3,'0')+'Z'
    dt.datetime.fromisoformat(canonical.replace('Z','+00:00'))
    return canonical

def enum(value, options):
    if value not in options or not isinstance(value,str):reject()
    return value

def mapping(value, keys):
    if not isinstance(value,dict) or set(value)!=set(keys):reject()
    return value

def number(value):
    if value is None:return None
    if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=1e15:reject()
    return value

def bytestring(value):
    if value is None:return None
    if not isinstance(value,str) or not re.fullmatch(r'0|[1-9][0-9]{0,29}',value):reject()
    return value

def sanitize(raw):
    raw=mapping(raw,EMPTY)
    if type(raw['schema_version']) is not int or raw['schema_version']!=3:reject()
    revision=raw['registry_revision']
    if revision is not None and (type(revision) is not int or not 1<=revision<2**53):reject()
    c=mapping(raw['collector'],('state','started_at'));s=mapping(raw['server'],('state',));v=mapping(raw['coverage'],('kind','totals_scope','timezone','day','day_started_at','observed_since','limitation'))
    output=dict(schema_version=3,registry_revision=revision,observed_at=date(raw['observed_at']),
      collector=dict(state=enum(c['state'],('ok','unavailable')),started_at=date(c['started_at'])),
      server=dict(state=enum(s['state'],('running','stopped','unknown'))),
      coverage=dict(kind=enum(v['kind'],('ipsec_child_counters',)),totals_scope=enum(v['totals_scope'],('calendar_day',)),
        timezone=enum(v['timezone'],(TIMEZONE,)),day=v['day'],day_started_at=date(v['day_started_at']),
        observed_since=date(v['observed_since']),limitation=text(v['limitation'],600)),devices=[])
    coverage=output['coverage']
    if (coverage['day'] is None)!=(coverage['day_started_at'] is None):reject()
    if coverage['day'] is not None:
        if not isinstance(coverage['day'],str) or not re.fullmatch(r'\d{4}-\d\d-\d\d',coverage['day']):reject()
        midnight=dt.datetime.fromisoformat(coverage['day_started_at'].replace('Z','+00:00')).timestamp()
        if day_info(midnight)!=(coverage['day'],midnight):reject()
    for item in (coverage['observed_since'],output['observed_at']):
        if item is not None:
            if coverage['day'] is None or day_info(dt.datetime.fromisoformat(item.replace('Z','+00:00')).timestamp())[0]!=coverage['day']:reject()
    if coverage['observed_since'] is not None and (output['observed_at'] is None or coverage['observed_since']>output['observed_at']):reject()
    if output['collector']['state']=='ok' and output['observed_at'] is None:reject()
    if not isinstance(raw['devices'],list) or len(raw['devices'])>16:reject()
    ids=set()
    for raw_device in raw['devices']:
        d=mapping(raw_device,('id','name','state','registration_state','connected_since','rate_window_ms','upload_bps','download_bps','upload_bytes','download_bytes','totals_since','counter_epoch','counter_state'))
        ident=text(d['id'],48)
        if not re.fullmatch('[A-Za-z0-9_-]+',ident) or ident in ids:reject()
        ids.add(ident);window=d['rate_window_ms']
        if window is not None and (type(window) is not int or not 1<=window<=3600000):reject()
        item=dict(id=ident,name=text(d['name'],80),state=enum(d['state'],('online','offline','unknown')),
          registration_state=enum(d['registration_state'],('enabled','disabled','revoked')),
          connected_since=date(d['connected_since']),rate_window_ms=window,
          upload_bps=number(d['upload_bps']),download_bps=number(d['download_bps']),
          upload_bytes=bytestring(d['upload_bytes']),download_bytes=bytestring(d['download_bytes']),
          totals_since=date(d['totals_since']),counter_epoch=None if d['counter_epoch'] is None else text(d['counter_epoch'],80),
          counter_state=enum(d['counter_state'],('partial','unavailable')))
        if window is None and (item['upload_bps'] is not None or item['download_bps'] is not None):reject()
        if item['counter_state']=='partial':
            if any(item[k] is None for k in ('upload_bytes','download_bytes','totals_since','counter_epoch')):reject()
            if coverage['observed_since'] is None or not coverage['observed_since']<=item['totals_since']<=output['observed_at']:reject()
            if not re.fullmatch(r'daily_[A-Za-z0-9_-]{1,48}_'+coverage['day'].replace('-',''),item['counter_epoch']):reject()
        elif any(item[k] is not None for k in ('upload_bytes','download_bytes','totals_since','counter_epoch')):reject()
        if item['state']=='online' and output['server']['state']=='stopped':reject()
        if item['connected_since'] and output['observed_at'] and dt.datetime.fromisoformat(item['connected_since'].replace('Z','+00:00'))>dt.datetime.fromisoformat(output['observed_at'].replace('Z','+00:00')):reject()
        output['devices'].append(item)
    if revision is None and (output['devices'] or output['collector']['state']!='unavailable'):reject()
    return output
