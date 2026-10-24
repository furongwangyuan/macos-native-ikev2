"""Read-only current-runtime IKE rekey reproduction; all native effects fake."""
import copy, importlib.util, json, os, sys, unittest
from dataclasses import replace
from pathlib import Path
if os.geteuid() == 0: raise SystemExit('ordinary user only')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parents[1]/'server/runtime'
sys.path.insert(0,str(RUNTIME))
import fleet_vici as original_parser
from fleet_coordinator import Coordinator,FakeAdapter,Observation,Route,Routes
from fleet_policy import Snapshot,Fault
from fleet_native import NativeFleetAdapter
from vici.protocol import Message,FiniteStream
REG = dict(version=1,revision=1,usage_timezone='Asia/Kuala_Lumpur',devices=[
 dict(device_id='device01',display_name='A',state='enabled',ike_identity='device01.family.home.arpa',vip4='10.77.26.10',vip6='fd6d:fe83:ab27:2600::10'),
 dict(device_id='device02',display_name='B',state='enabled',ike_identity='device02.family.home.arpa',vip4='10.77.26.11',vip6='fd6d:fe83:ab27:2600::11')])

def event(device=0,ikeid=1,childid=1,state='ESTABLISHED',children=True,vips=True,child_state='INSTALLED'):
 d=REG['devices'][device]
 child=dict(name=b'internet',uniqueid=str(childid).encode(),reqid=str(childid).encode(),state=child_state.encode(),mode=b'TUNNEL',protocol=b'ESP',encap=b'yes',**{
  'spi-in':format(0x10000000+childid,'08x').encode(),'spi-out':format(0x20000000+childid,'08x').encode(),
  'encr-alg':b'AES_GCM_16','encr-keysize':b'256','bytes-in':b'100','bytes-out':b'200','packets-in':b'10','packets-out':b'20','install-time':b'20',
  'local-ts':[b'0.0.0.0/0',b'::/0'],'remote-ts':[(d['vip4']+'/32').encode(),(d['vip6']+'/128').encode()]})
 ike=dict(uniqueid=str(ikeid).encode(),version=b'2',state=state.encode(),**{
  'local-host':b'192.0.2.8','local-port':b'4500','local-id':b'vpn.family.home.arpa',
  'remote-host':b'203.0.113.101','remote-port':b'45000','remote-id':d['ike_identity'].encode(),
  'initiator-spi':format(0x1000000000000000+ikeid,'016x').encode(),'responder-spi':format(0x2000000000000000+ikeid,'016x').encode(),
  'encr-alg':b'AES_GCM_16','encr-keysize':b'256','prf-alg':b'PRF_HMAC_SHA2_256','dh-group':b'ECP_256',
  'nat-local':b'yes','nat-remote':b'yes','child-sas':{'internet-'+str(childid):child} if children else {}})
 if state=='ESTABLISHED':ike['established']=b'60'
 if vips:ike['remote-vips']=[d['vip4'].encode(),d['vip6'].encode()]
 return {'family-vpn-'+d['device_id']:ike}

def inner(raw):return next(iter(raw.values()))
def decode(events):return [Message.deserialize(FiniteStream(Message.serialize(e))) for e in events]
def record(i,src,dst,direction,kind,requests=()):return dict(id=i,src=src,dst=dst,direction=direction,kind=kind,requests=list(requests))
NATIVE=[record(1,'0.0.0.0/0','10.77.26.0/24','out','generate'),record(2,'::/0','fd6d:fe83:ab27:2600::/64','out','generate'),record(3,'0.0.0.0/0','10.77.26.253/32','out','discard')]
def hosts(g,offset):
 result=[]
 for vip,suffix,anynet in ((g.vip4,'/32','0.0.0.0/0'),(g.vip6,'/128','::/0')):
  for direction in ('in','out'):
   src,dst=(vip+suffix,anynet) if direction=='in' else (anynet,vip+suffix)
   outer=(g.peer4,g.local4) if direction=='in' else (g.local4,g.peer4)
   result.append(record(offset+len(result),src,dst,direction,'ipsec',['esp/tunnel/'+'-'.join(outer)+'/unique:'+str(g.reqid)]))
 return result
def frame(parser,events,*,policy_events=None):
 try:parsed=parser.parse_events(decode(events+[event(1,10,10)]),REG)
 except Exception as e:return e
 policy=parser.parse_events(decode((events if policy_events is None else policy_events)+[event(1,10,10)]),REG)
 rows=copy.deepcopy(NATIVE);routes={}
 for idx,(ident,snap) in enumerate(policy.snapshots.items()):
  if not snap.generations:continue
  g=snap.generations[-1];rows+=hosts(g,20+10*idx)
  routes[ident]=Routes(g,Route(g.vip4,'en0',True,True),Route(g.vip6,'en0',True,True),Route(g.peer4,'en0',True,False))
 # Candidate imported under another name has a separate dataclass identity;
 # native deployment loads it as fleet_vici, so bridge only that class token.
 parsed=original_parser.ParseResult(parsed.snapshots,parsed.unattributed_pending_count)
 return Observation(REG,parsed,rows,{r['id']:True for r in rows},NATIVE,routes,'a'*32)
def coordinator(frames):
 fake=FakeAdapter(frames);adapter=object.__new__(NativeFleetAdapter)
 for name in ('observe','inventory','route','narrow','publish','guard_all'):setattr(adapter,name,getattr(fake,name))
 return Coordinator(REG,adapter),fake
def simulate(parser,events):
 initial=frame(parser,[event()]);item=frame(parser,events)
 c,f=coordinator([initial]*3+[item]*3)
 first=c.step();result=c.step()
 return dict(initial=first.state,after=result.state,active=list(result.active),reason=result.reason,publishes=f.calls.get('publish',0))
