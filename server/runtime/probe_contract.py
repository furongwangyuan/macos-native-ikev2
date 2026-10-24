"""Fixed ordinary synthetic probe scope; no native-policy authorization."""
import json,math,re
from pathlib import Path
BASE=Path('/usr/local/family-vpn/production-guardian')
GATE=BASE/'probe_gate.py'
PUBLIC=Path('/usr/local/libexec/family-vpn-probe')
BINARY=PUBLIC/'native-probe'
UID=501;GID=20;PORT=47729;BIND='192.0.2.8'
BINARY_SHA='1ed70d0007319044e8c1e85384802227adc06610ada79a4f61835cf80bdf83aa'
PAGE_SHA='2e320f9562e28c503177b877a77801b546f12edebdb25bad89f42550e53b92a4'
PAGE_LENGTH=11763 # reviewed embedded page bytes
PROFILE='bounded-probe-child-v1'
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'}
class Refused(RuntimeError):pass

def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(items):
  out={}
  for key,value in items:
   if key in out:raise Refused('duplicate_key')
   out[key]=value
  return out
 try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('nonfinite')))
 except (ValueError,UnicodeError) as error:raise Refused('unknown_json') from error

def spec(peer,seconds):
 if type(peer)is not str or peer not in {'10.77.26.'+str(i) for i in range(10,101)}:raise Refused('fixed_vpn_peer_required')
 if type(seconds)is not int or not 1<=seconds<=900:raise Refused('fixed_duration_required')
 return {'peer':peer,'seconds':seconds}
def ready(peer,seconds):
 spec(peer,seconds)
 return dict(event='ready',bind=BIND,port=PORT,peer=peer,seconds=seconds,budget=80000000,page_sha256=PAGE_SHA)
def frame(value):
 if type(value)is not dict or set(value)!={'version','profile','go','run','peer','seconds'} or type(value['version'])is not int or value['version']!=1 or value['profile']!=PROFILE or value['go']is not True:raise Refused('unknown_go_frame')
 if type(value['run'])is not str or not re.fullmatch('[0-9a-f]{32}',value['run']):raise Refused('run_scope')
 spec(value['peer'],value['seconds']);return value

def identity(value):
 keys={'pid','uid','pgid','started_sec','started_usec','path'}
 if (type(value)is not dict or set(value)!=keys or any(type(value[k])is not int for k in keys-{'path'})
  or value['pid']<=1 or value['pgid']!=value['pid'] or value['uid']not in(0,UID)
  or value['started_sec']<=0 or not 0<=value['started_usec']<1000000
  or type(value['path'])is not str or not value['path'].startswith('/') or any(x in value['path'] for x in ('\0','\n','\r'))):raise Refused('probe_identity_schema')
 return value

def record(value):
 keys={'version','profile','boot','run','phase','peer','seconds','identity','exit'}
 if (type(value)is not dict or set(value)!=keys or type(value['version'])is not int or value['version']!=1
  or value['profile']!=PROFILE or type(value['boot'])is not str or not value['boot'] or len(value['boot'])>256
  or type(value['run'])is not str or not re.fullmatch('[0-9a-f]{32}',value['run'])
  or value['phase']not in ('spawn-intent','go-intent','running','stop-intent','exited','retired-no-go')):raise Refused('probe_record_schema')
 spec(value['peer'],value['seconds'])
 who=value['identity']
 if who is not None:
  identity(who)
  if who['uid']!=0:raise Refused('original_gate_not_root')
 if who is None and value['phase']not in('spawn-intent','exited','retired-no-go'):raise Refused('probe_identity_missing')
 if value['phase']=='retired-no-go':
  e=value['exit']
  if (who is not None or type(e)is not dict or set(e)!={'own_reap','process_absent','group_absent','never_sent_go','listener_absence_verified'}
      or e['own_reap']is not False or e['process_absent']is not None or e['group_absent']is not None
      or e['never_sent_go']is not True or e['listener_absence_verified']is not True):raise Refused('unknown_pre_go_retirement')
 elif value['phase']=='exited':
  e=value['exit']
  if (type(e)is not dict or set(e)!={'own_reap','process_absent','group_absent','never_sent_go'}
   or any(type(x)is not bool for x in e.values()) or not(e['process_absent'] and e['group_absent'])
   or e['never_sent_go']!=(who is None)):raise Refused('probe_exit_evidence_schema')
 elif value['exit']is not None:raise Refused('exit_before_exited')
 return value
