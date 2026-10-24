"""Isolated synthetic input for the actual currently installed monitor functions."""
import copy,datetime as dt,hashlib,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
CURRENT=HERE.parent/'runtime'
DEPENDENCIES=CURRENT
if os.geteuid()==0:raise RuntimeError('ordinary user only')
sys.path[:0]=[str(CURRENT),str(DEPENDENCIES)]
from ledger import RegistryLedger
from source import parse_events
import ledger_core_v3,collector,journal,schema
BASE=dt.datetime.fromisoformat('2026-10-24T12:00:00+08:00').timestamp()
EPOCH='a'*64
def registry(count):
 return {'version':1,'revision':1,'usage_timezone':'Asia/Kuala_Lumpur','devices':[
  {'device_id':'phone%02d'%i,'display_name':'Synthetic %02d'%i,'ike_identity':'phone%02d.family.home.arpa'%i,
   'state':'enabled','vip4':'10.77.26.'+str(10+i),'vip6':'fd6d:fe83:ab27:2600::'+format(16+i,'x')}
  for i in range(count)]}
def event(device,ike,child,up,down=0,spi=None,age=60,child_state='INSTALLED'):
 spi=child if spi is None else spi
 c={'state':child_state.encode(),'uniqueid':str(child).encode(),'name':b'internet','protocol':b'ESP','mode':b'TUNNEL',
    'spi-in':format(0x10000000+spi,'08x').encode(),'spi-out':format(0x20000000+spi,'08x').encode(),
    'bytes-in':str(up).encode(),'bytes-out':str(down).encode()}
 return {'family-vpn-'+device:{'state':b'ESTABLISHED','remote-id':(device+'.family.home.arpa').encode(),
   'remote-host':b'203.0.113.7','remote-port':str(45000+ike).encode(),'local-id':b'vpn.family.home.arpa',
   'version':b'2','uniqueid':str(ike).encode(),'established':str(age).encode(),'child-sas':{'internet-'+str(child):c}}}
def events(count,second=0):return [event('phone%02d'%i,i+1,i+101,1000+i*100+second*(i+1)*10,second*(i+1)*100,age=60+second) for i in range(count)]
def observe(book,data,registry,wall,mono,unknown=None,epoch=EPOCH):
 inventory=parse_events(data,epoch,wall,registry,with_unknown=True)
 if unknown is not None:inventory['unknown_devices']=unknown
 return book.observe(inventory['rows'],wall=wall,mono=mono,server_running=True,unknown_devices=inventory['unknown_devices'])
def totals(snapshot):return {d['id']:(None if d['upload_bytes'] is None else int(d['upload_bytes']),None if d['download_bytes'] is None else int(d['download_bytes'])) for d in snapshot['devices']}
def pins():return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in CURRENT.glob('*.py')}
