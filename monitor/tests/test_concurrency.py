"""Candidate actual functions, strict transition isolation and registry comparison."""
import copy,hashlib,importlib.util,json,sys,unittest
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE.parent/'runtime'),str(HERE)]
import collector,source,ledger,worker,schema
import fixture as f
spec=importlib.util.spec_from_file_location('transitions',HERE/'reproduce-transition.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
REG=t.REG;RAW=json.dumps(REG,separators=(',',':')).encode();SHA=hashlib.sha256(RAW).hexdigest();REGISTERED=SimpleNamespace(raw=RAW,sha256=SHA,value=REG)
class Checks(unittest.TestCase):
 def test_deleting_ike_and_deleted_child_keep_b_and_mark_only_a_unknown(self):
  for data in (t.reconnect(),t.deleted(),t.rekeying()):
   for order in (data,list(reversed(data))):
    result=source.parse_events(order,f.EPOCH,f.BASE+2,REG,with_unknown=True)
    self.assertEqual(result['unknown_devices'],['phone00']);self.assertEqual([r['device'] for r in result['rows']],['phone01'])
    with self.assertRaises(ValueError):source.parse_events(order,f.EPOCH,f.BASE+2,REG)
 def test_each_complete_collision_phase_retains_the_other_device(self):
  for states in (('DELETING','DELETED','INSTALLED'),('DELETED','DELETED','INSTALLED')):
   data=t.deleted();ike=next(iter(data[0].values()));ike['child-sas']={}
   for i,state in enumerate(states):
    extra=t.complete(f.event('phone00',1,301+i,10+i,20+i,child_state=state),0)
    ike['child-sas'].update(next(iter(extra.values()))['child-sas'])
   result=source.parse_events(data,f.EPOCH,f.BASE+2,REG,with_unknown=True)
   self.assertEqual(result['unknown_devices'],['phone00']);self.assertEqual(len(result['rows']),1)
 def test_malformed_authenticated_transition_still_rejects_entire_sample(self):
  for builder in (t.reconnect,t.deleted,t.rekeying):
   for field,value,child in [('remote-id',b'phone01.family.home.arpa',False),('remote-vips',[b'10.77.26.11',b'fd6d:fe83:ab27:2600::11'],False),
      ('remote-vips',[],False),('reqid',b'0',True),('reqid',b'bad',True),('local-ts',[b'0.0.0.0/0'],True),
      ('remote-ts',[b'10.77.26.11/32',b'fd6d:fe83:ab27:2600::11/128'],True),('spi-in',b'00000000',True),
      ('protocol',b'AH',True),('bytes-in',b'-1',True),('state',b'BROKEN',True)]:
    data=builder();ike=next(iter(data[0].values()));row=next(iter(ike['child-sas'].values())) if child else ike;row[field]=value
    with self.subTest(builder=builder.__name__,field=field),self.assertRaises(ValueError):source.parse_events(data,f.EPOCH,f.BASE+2,REG,with_unknown=True)
 def test_deleting_without_children_but_exact_vips_is_unknown_not_offline(self):
  data=t.reconnect();next(iter(data[0].values()))['child-sas']={}
  parsed=source.parse_events(data,f.EPOCH,f.BASE+2,REG,with_unknown=True)
  self.assertEqual(parsed['unknown_devices'],['phone00'])
 def test_rekeying_does_not_gain_empty_retired_or_third_counted_exception(self):
  data=t.rekeying();ike=next(iter(data[0].values()));ike['child-sas']={};ike.pop('remote-vips')
  with self.assertRaises(ValueError):source.parse_events(data,f.EPOCH,f.BASE+2,REG,with_unknown=True)
  data=t.rekeying();second=copy.deepcopy(data[0]);next(iter(second.values()))['uniqueid']=b'3'
  next(iter(second.values()))['child-sas']={}
  data.extend([second,t.complete(f.event('phone00',4,401,1,1),0)])
  with self.assertRaisesRegex(ValueError,'excessive counted IKE'):source.parse_events(data,f.EPOCH,f.BASE+2,REG,with_unknown=True)
 def test_actual_collector_keeps_b_rates_and_a_private_subtotal_through_transition(self):
  for builder in (t.reconnect,t.deleted,t.rekeying):
   class Run:
    now=0
    def __init__(self):self.snapshots=[];self.saves=[]
    def is_set(self):return self.now>=5
    def wait(self,_):self.now+=1
    def load(self):return None
    def save(self,value):self.saves.append(copy.deepcopy(value))
    def query(self):
     data=f.events(2,self.now)
     if self.now==2:
      data=builder();data[-1]=t.complete(f.events(2,self.now)[1],1)
     elif self.now>=3 and builder!=t.rekeying:data[0]=t.complete(f.event('phone00',3,201,10+(self.now-2)*20,20),0)
     return worker.sample(None,identify=lambda:('synthetic-daemon',1),events=lambda _:data,read_registry=lambda:REGISTERED,wall=lambda:f.BASE+self.now,mono=lambda:self.now)
   run=Run();collector.run(6,query=run.query,emit=lambda x:run.snapshots.append(schema.sanitize(x)),clock=lambda:run.now,wall=lambda:f.BASE,stop=run,report=lambda _:None,store=run,registry_reader=lambda:REGISTERED)
   mixed=run.snapshots[2];a,b=mixed['devices']
   self.assertEqual((mixed['collector']['state'],a['state'],a['upload_bytes']),('ok','unknown',None))
   self.assertEqual((b['state'],b['upload_bps'],b['upload_bytes']),('online',160.,'40'))
   self.assertEqual(run.saves[2]['accounting']['devices']['phone00']['up'],10)
   self.assertEqual(f.totals(run.snapshots[4])['phone00'][0],40 if builder==t.rekeying else 30)
   self.assertEqual(f.totals(run.snapshots[4])['phone01'][0],80)
 def test_registry_comparison_same_changed_and_no_mutable_reference(self):
  book=ledger.RegistryLedger(REG,'compare',f.BASE)
  value=copy.deepcopy(REG);before=book.to_journal()
  self.assertIs(book.matches_registry(value),True)
  value['revision']+=1;self.assertIs(book.matches_registry(value),False)
  value['devices'][0]['display_name']='Modified';self.assertEqual(book.to_journal(),before)
  with unittest.mock.patch.object(book,'to_journal',side_effect=AssertionError('full history read')):
   self.assertIs(book.matches_registry(copy.deepcopy(REG)),True)
if __name__=='__main__':
 import unittest.mock
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
 report={'tests':result.testsRun,'passed':result.wasSuccessful(),'failures':len(result.failures),'errors':len(result.errors),
  'candidate_files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE.parent/'runtime').glob('*.py')},
  'scope':'Actual candidate parser/collector/ledger and existing worker; synthetic authenticated transitions and clocks/store only. No root, VICI, real clients or online writes.'}
 print(json.dumps(report));raise SystemExit(0 if result.wasSuccessful() else 1)
