"""Ordinary tests of concrete adapter/Owner/Gate methods; every native boundary mocked."""
import copy,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import ExitStack
if os.geteuid()==0:raise SystemExit('ordinary user only')
HERE=Path(__file__).resolve().parent;R=HERE.parents[1]/'server/runtime';sys.path.insert(0,str(R))
import native_runtime as runtime,native_support as s,native_gate,alf_transaction as alf
import fleet_session as fs,fleet_policy as policy,fleet_coordinator as fc,fleet_tables
import fleet_native as fn,fleet_controller as controller,mutation_spec
from fleet_vici import ParseResult
from mutation_dispatch import Dispatcher


def fixture(outer_endpoints=None, peer6=None):
    reg=json.loads((HERE/'registry.example.json').read_text())
    reg['devices'].append(dict(device_id='device02',display_name='Second',ike_identity='device02.family.home.arpa',
        state='enabled',vip4='10.77.26.11',vip6='fd6d:fe83:ab27:2600::11'))
    raw=json.dumps(reg).encode();binding=fs.static(raw,outer_endpoints);reg=binding['registry']
    def record(i,src,dst,direction,kind,requests=()):return dict(id=i,src=src,dst=dst,direction=direction,kind=kind,requests=list(requests))
    native=[record(1,'0.0.0.0/0','10.77.26.0/24','out','generate'),record(2,'::/0','fd6d:fe83:ab27:2600::/64','out','generate'),record(3,'0.0.0.0/0','10.77.26.253/32','out','discard')]
    records=copy.deepcopy(native);snaps={}
    for i,d in enumerate(reg['devices']):
        dual=outer_endpoints is not None and len(outer_endpoints)==2 and i==0
        g=policy.Generation(i+1,i+1,i+1,d['ike_identity'],peer6 if dual else '203.0.113.101',45000+i,outer_endpoints[1] if dual else '192.0.2.8',4500,
            d['vip4'],d['vip6'],format(0x10000000+i,'08x'),format(0x20000000+i,'08x'))
        snaps[d['device_id']]=policy.Snapshot('unique',(g,))
        for vip,suffix,anynet in ((g.vip4,'/32','0.0.0.0/0'),(g.vip6,'/128','::/0')):
            for direction in ('in','out'):
                src,dst=(vip+suffix,anynet) if direction=='in' else (anynet,vip+suffix)
                endpoints=(g.peer4,g.local4) if direction=='in' else (g.local4,g.peer4)
                records.append(record(10+len(records),src,dst,direction,'ipsec',['esp/tunnel/'+'-'.join(endpoints)+'/unique:'+str(g.reqid)]))
    active={r['id']:True for r in records};proof=policy.audit(reg,snaps,records,active,native,outer_endpoints=fs.endpoints(binding))
    before=dict(global_state=2,blockall=True,stealth="Firewall stealth mode is off",builtin=False,downloaded=False,apps={str(s.CHARON):False})
    sess=dict(version=8,profile=fs.PROFILE,boot='synthetic',allow_data=True,probe_mode='off',fleet=binding,fleet_active=[],
        active=True,phase='WAITING',baseline={**{k:0 for k in s.SYS},s.ESP:0},alf_before=before,
        alf_transaction=alf.new(before),health={'public4':'203.0.113.10'},knobs={},files={},
        floors=[dict(r,status='owned') for r in native[:2]],keepers=[dict(native[2],status='owned')])
    if outer_endpoints is not None:
        sess['health'].update(lan4=outer_endpoints[0],stable6=outer_endpoints[1])
    class Store:
        def __init__(self):self.durable=copy.deepcopy(sess);self.saved=[]
        def save(self,value):s.session_history(value);self.durable=copy.deepcopy(value);self.saved.append(copy.deepcopy(value))
    store=Store();owner=fn.FleetOwner(sess,store,SimpleNamespace(fingerprint='fixed'),lambda:0);owner.registry_bytes=raw
    return raw,owner,proof,snaps,records,active,native

class Kernel:
    def __init__(self,owner):
        self.owner=owner;self.trace=[];self.rules={'filters':['guard'],'nat':[]};self.tables={'active4':[],'active6':[]};self.pending=None
        owner.session['pf']={'guard':copy.deepcopy(self.rules)};owner.gate.state.update(installed=True,mode='guarded')
        self.values={k:0 for k in s.SYS};self.states='';self.guard_count=0
    def compile(self,text,name):
        import re,ipaddress
        self.pending={k:sorted(str(ipaddress.ip_network(x.strip()).network_address) for x in re.search(r'table <familyvpn_'+k+r'> const \{ ([^}]*) \}',text)[1].split(',') if x.strip()) for k in ('active4','active6')}
        return s.RUN/name,{'filters':['active'],'nat':['nat']}
    def run(self,args,**kwargs):
        args=list(map(str,args));self.trace.append(args)
        if args[:4]==['/sbin/pfctl','-a',native_gate.ANCHOR,'-f']:
            self.rules={'filters':['active'],'nat':['nat']};self.tables=copy.deepcopy(self.pending)
        if args[-2:]==['-T','show']:
            k='active4' if args[4].endswith('4') else 'active6';return SimpleNamespace(stdout='\n'.join(self.tables[k]),stderr='',returncode=0)
        if args==['/sbin/pfctl','-ss']:return SimpleNamespace(stdout=self.states,stderr='',returncode=0)
        if args[:3]==['/sbin/route','-n','get']:
            return SimpleNamespace(stdout='destination: '+args[-1]+'\ninterface: en0\nflags: <UP,HOST>\n',stderr='',returncode=0)
        if args==['/usr/sbin/setkey','-DP']:return SimpleNamespace(stdout='fixed synthetic SPD',stderr='',returncode=0)
        return SimpleNamespace(stdout='',stderr='',returncode=0)
    def guard(self,*args):
        self.guard_count+=1;self.rules={'filters':['guard'],'nat':[]};self.values={k:0 for k in s.SYS}
        self.owner.gate.state['mode']='guarded';self.owner.session['fleet_active']=[]
    def bind(self,stack):
        o=self.owner
        for name,method in [('check_local',lambda _timeout:None),('guard',self.guard)]:stack.enter_context(patch.object(o,name,side_effect=method))
        for name,method in [('compile_rules',self.compile),('rules_equal',lambda r:r==self.rules),('root_intact',lambda:None),('enabled',lambda:True),('token_present',lambda:True),('set_knob',lambda k,v:self.values.update({k:v})),('closed',lambda:self.rules=={'filters':['guard'],'nat':[]} and not any(self.values[k] for k in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding')))]:
            stack.enter_context(patch.object(o.gate,name,side_effect=method))
        stack.enter_context(patch.object(s,'run',side_effect=self.run));stack.enter_context(patch.object(s,'values',side_effect=lambda:dict(self.values)))
        original=(R/'family-vpn.fleet.pf').read_bytes();stack.enter_context(patch.object(s,'read',side_effect=lambda path,**kw:o.registry_bytes if path==fs.REGISTRY else original))

class NativeFleet(unittest.TestCase):
    def tearDown(self):s.MUTATOR=None;runtime.STOP.clear()
    def test_real_owner_uses_single_dispatcher_and_generated_registry(self):
        raw,o,proof,*_=fixture();self.assertIs(s.MUTATOR,o.dispatcher);self.assertIs(type(o.fleet_adapter),fn.NativeFleetAdapter)
        with patch.object(s,'read',return_value=raw):
            content=o.connection_configuration()
        self.assertIn(b'family-vpn-device02',content);self.assertIn(b'family-vpn-device01',content)
        self.assertEqual(fs.sha(content),o.session['fleet']['connection_sha256'])
        with self.assertRaises(s.Refused):o.activate(None,None,1)
    def test_coordinator_rejects_fake_adapter(self):
        _,o,*_=fixture()
        with self.assertRaises(policy.Fault):fc.Coordinator(o.session['fleet']['registry'],fc.FakeAdapter([]))
    def test_concrete_two_device_tick_then_remove_a_keeps_b_without_global_close(self):
        _,o,proof,snaps,records,active,native=fixture();k=Kernel(o);a=o.fleet_adapter
        with ExitStack() as st:
            k.bind(st)
            def read(_=10):a.last_context='a'*32;return ParseResult(copy.deepcopy(snaps),0)
            st.enter_context(patch.object(a,'read_fleet',side_effect=read))
            st.enter_context(patch.object(runtime.policies,'parse_spd',side_effect=lambda _:copy.deepcopy(records)))
            st.enter_context(patch.object(runtime.policies,'policy_id_active',side_effect=lambda ident,*args,**kwargs:active[ident]))
            c=fc.Coordinator(o.session['fleet']['registry'],a)
            self.assertEqual(c.step().active,('device01','device02'));self.assertEqual(k.guard_count,1)
            before=len(k.trace);victim=next(d for d in proof.devices if d.device_id=='device01')
            snaps['device01']=policy.Snapshot('absent')
            for i in victim.policy_ids:active[i]=False
            result=c.step();self.assertEqual(result.active,('device02',));self.assertEqual(k.guard_count,1)
            kills=[x for x in k.trace[before:] if '-k' in x]
            self.assertEqual([x[-1] for x in kills],[victim.generation.vip4]*2+[victim.generation.vip6]*2)
            self.assertTrue(all('/24' not in ' '.join(x) and '/64' not in ' '.join(x) for x in kills))
            self.assertEqual(k.tables,{'active4':['10.77.26.11'],'active6':['fd6d:fe83:ab27:2600::11']})
            self.assertEqual(o.session['fleet_closing']['phase'],'verified')
    def test_table_mismatch_after_publish_no_receipt_and_recoverable_both_rules(self):
        _,o,proof,*_=fixture();k=Kernel(o)
        with ExitStack() as st:
            k.bind(st);st.enter_context(patch.object(fleet_tables,'read',return_value={'active4':[],'active6':[]}))
            with self.assertRaisesRegex(s.Refused,'rules_or_tables'):o.fleet_adapter.publish((),proof.devices,proof)
        self.assertEqual(o.session['fleet_active'],[]);self.assertEqual(o.session['gate_intent']['phase'],'apply-intent')
        self.assertEqual(o.session['gate_intent']['previous'],{'filters':['guard'],'nat':[]})
    def test_a_state_residual_fails_narrow_without_false_receipt(self):
        _,o,proof,*_=fixture();k=Kernel(o)
        with ExitStack() as st:
            k.bind(st);o.fleet_adapter.publish((),proof.devices,proof)
            d=next(x for x in proof.devices if x.device_id=='device01');other=tuple(x for x in proof.devices if x!=d)
            k.states='all tcp '+d.generation.vip4+':1234 -> 1.1.1.1:443 ESTABLISHED:ESTABLISHED\n'
            with self.assertRaisesRegex(s.Refused,'states_remain'):o.fleet_adapter.narrow(proof.devices,other,(fc.CloseRequest(d.device_id,d.generation,d.generation.vip4,d.generation.vip6,d.hosts),))
            self.assertEqual(fs.decode_active(o.session['fleet_active'],o.session['fleet']['registry']),other)
            self.assertEqual(o.session['fleet_closing']['phase'],'intent')
    def test_mutation_grammar_and_durable_retirement_precede_popen(self):
        _,o,proof,*_=fixture()
        self.assertEqual(mutation_spec.classification(['/sbin/pfctl','-k','10.77.26.10']),'mutate')
        with self.assertRaises(mutation_spec.InvalidMutation):mutation_spec.classification(['/sbin/pfctl','-k','192.0.2.8'])
        o.dispatcher.popen=lambda *a,**k:(_ for _ in ()).throw(AssertionError('spawn must not occur'))
        with self.assertRaisesRegex(fs.Invalid,'durable_intent'):o.dispatcher.run(['/sbin/pfctl','-k','10.77.26.10'])
        o.session['fleet_closing']=dict(version=1,devices=['device01'],phase='intent');o.save()
        with self.assertRaisesRegex(fs.Invalid,'not_registered'):o.dispatcher.run(['/sbin/pfctl','-k','10.77.26.11'])
        with self.assertRaisesRegex(AssertionError,'spawn must not occur'):o.dispatcher.run(['/sbin/pfctl','-k','10.77.26.10'])
        self.assertEqual(o.store.durable['mutation']['phase'],'spawn-intent')
    def test_v8_active_registry_changed_and_aliases_rejected(self):
        _,o,proof,*_=fixture();fs.history(o.session)
        for field,value in [('version',7),('probe_mode','synthetic-local-v1'),('fleet_active',[dict(fs.encode_device(proof.devices[0]),ready=1)])]:
            value_session=copy.deepcopy(o.session);value_session[field]=value
            with self.assertRaises(ValueError):fs.history(value_session)
        value=copy.deepcopy(o.session);value['fleet']['registry']['revision']+=1
        with self.assertRaises(ValueError):fs.history(value)
    def test_full_inventory_queries_all_policy_ids_and_routes(self):
        _,o,proof,snaps,records,active,native=fixture();k=Kernel(o)
        with ExitStack() as st:
            k.bind(st);st.enter_context(patch.object(runtime.policies,'parse_spd',return_value=records))
            spy=st.enter_context(patch.object(runtime.policies,'policy_id_active',return_value=True))
            got=o.fleet_adapter.inventory();self.assertEqual(got,(records,active,native));self.assertEqual(spy.call_count,len(records))
            for d in proof.devices:self.assertEqual(o.fleet_adapter.route(d).generation,d.generation)
    def test_actual_store_rejects_valid_changed_registry_before_any_write(self):
        raw,o,*_=fixture();changed=json.loads(raw);changed['revision']+=1
        value=copy.deepcopy(o.session);value['fleet']=fs.static(json.dumps(changed).encode())
        store=s.Store();store.durable=copy.deepcopy(o.session)
        with patch.object(s,'atomic') as writes:
            with self.assertRaisesRegex(s.Refused,'active_session_mode_change'):store.save(value)
            writes.assert_not_called()
    def test_recovery_guard_accepts_durable_previous_rules_then_clears_active(self):
        _,o,proof,*_=fixture();k=Kernel(o)
        with ExitStack() as st:
            k.bind(st);o.fleet_adapter.publish((),proof.devices,proof)
            old_rules=copy.deepcopy(k.rules);old_tables=copy.deepcopy(k.tables)
            o.session['gate_intent']=dict(phase='apply-intent',sha256='a'*64,
                previous=old_rules,expected={'filters':['replacement'],'nat':['new']},
                fleet_tables_before=old_tables,fleet_tables_after={'active4':[],'active6':[]})
            o.save()
            # Call the actual inherited global recovery guard, not Kernel.guard.
            def run(args,**kwargs):
                if list(map(str,args))==['/sbin/pfctl','-a',native_gate.ANCHOR,'-f',str(s.RUN/'guard.pf')]:
                    k.rules={'filters':['guard'],'nat':[]};return SimpleNamespace(stdout='',stderr='',returncode=0)
                return k.run(args,**kwargs)
            st.enter_context(patch.object(s,'run',side_effect=run))
            st.enter_context(patch.object(o.gate,'compile_rules',return_value=(s.RUN/'guard.pf',{'filters':['guard'],'nat':[]})))
            o.gate.guard('recovery')
            self.assertEqual(o.session['fleet_active'],[]);self.assertEqual(o.gate.state['mode'],'guarded')
    def test_unknown_state_output_is_not_absence(self):
        from fleet_gate import no_address_state
        with self.assertRaisesRegex(s.Refused,'state_line_unknown'):no_address_state('unrecognized diagnostic',('10.77.26.10',))
        self.assertFalse(no_address_state('all tcp fd6d:fe83:ab27:2600::10[443] -> 2001:4860::8888[443] ESTABLISHED:ESTABLISHED',('fd6d:fe83:ab27:2600::10',)))

    def test_registry_drift_refuses_before_swanctl_or_vici(self):
        raw,o,*_=fixture();value=json.loads(raw);value['revision']+=1
        with patch.object(s,'read',return_value=json.dumps(value).encode()),patch.object(s,'run') as calls:
            with self.assertRaisesRegex(s.Refused,'registry_changed'):o.connection_configuration()
            calls.assert_not_called()

if __name__=='__main__':unittest.main()
