"""Reproduce valid authenticated transition poisoning a second device's sample."""
import copy,hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));import fixture as f
REG=f.registry(2)
def complete(event,number):
 ike=next(iter(event.values()));d=REG['devices'][number]
 ike['remote-vips']=[d['vip4'].encode(),d['vip6'].encode()]
 for child in ike['child-sas'].values():
  child['reqid']=str(number+1).encode()
  child['local-ts']=[b'0.0.0.0/0',b'::/0']
  child['remote-ts']=[(d['vip4']+'/32').encode(),(d['vip6']+'/128').encode()]
 return event
def reconnect():
 old=complete(f.event('phone00',1,101,1100,100),0)
 ike=next(iter(old.values()));ike['state']=b'DELETING';ike.pop('established')
 return [old,complete(f.event('phone00',3,201,10,20),0),complete(f.event('phone01',2,102,1120,200),1)]
def deleted():
 old=complete(f.event('phone00',1,101,1100,100,child_state='DELETED'),0)
 child=complete(f.event('phone00',1,201,10,20),0)
 next(iter(old.values()))['child-sas'].update(next(iter(child.values()))['child-sas'])
 return [old,complete(f.event('phone01',2,102,1120,200),1)]
def rekeying():
 data=[complete(f.events(2,2)[0],0),complete(f.events(2,2)[1],1)]
 ike=next(iter(data[0].values()));ike['state']=b'REKEYING';ike.pop('established')
 return data
if __name__=='__main__':
 cases=[]
 for name,events in [('deleting_ike_with_child_vip_and_new_winner',reconnect()),('deleted_child_and_installed_winner',deleted()),('rekeying_ike_with_full_child_and_vips',rekeying())]:
  try:f.parse_events(events,f.EPOCH,f.BASE+2,REG,with_unknown=True)
  except ValueError as e:cases.append({'case':name,'whole_sample_rejected':True,'reason':str(e)})
  else:cases.append({'case':name,'whole_sample_rejected':False})
 report={'cases':cases,'source_sha256':hashlib.sha256((f.CURRENT/'source.py').read_bytes()).hexdigest(),
  'scope':'Actual installed source parser, complete synthetic authenticated A transition and stable B; normal VICI shape independently established in upstream source, not real simultaneous phone test.'}
 (HERE/'transition-baseline.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
