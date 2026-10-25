"""Concrete coordinator/adapter/gate offline tests for deferred VIP retirement."""
import copy,json,os,subprocess,sys,types,unittest
from contextlib import contextmanager,ExitStack
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

if os.geteuid()==0:raise SystemExit('ordinary user only')
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
R=HERE.parents[1]/'server/runtime'
sys.path[:0]=[str(HERE),str(R)]
import test_native_fleet as h
from fleet_gate import no_address_state
A4='10.77.26.10';A6='fd6d:fe83:ab27:2600::10'
B4='10.77.26.11';B6='fd6d:fe83:ab27:2600::11'
BSTATE='en0 tcp '+B4+':62098 -> 192.0.2.8:42513 -> 1.1.1.1:443 ESTABLISHED:SYN_SENT\n'
UNKNOWN='future valid-but-unrecognized PF state display\n'

@contextmanager
def environment():
    outer=('192.0.2.8','2001:4860:1234:5678::8')
    _,o,proof,snaps,records,active,native=h.fixture(outer_endpoints=outer,peer6='2001:4860:abcd::101')
    k=h.Kernel(o);a=o.fleet_adapter
    with ExitStack() as st:
        k.bind(st)
        def read(_=10):a.last_context='a'*32;return h.ParseResult(copy.deepcopy(snaps),0)
        st.enter_context(patch.object(a,'read_fleet',side_effect=read))
        st.enter_context(patch.object(h.runtime.policies,'parse_spd',side_effect=lambda _:copy.deepcopy(records)))
        st.enter_context(patch.object(h.runtime.policies,'policy_id_active',side_effect=lambda ident,*args,**kwargs:active[ident]))
        c=h.fc.Coordinator(o.session['fleet']['registry'],a,outer_endpoints=outer)
        assert c.step().active==('device01','device02')
        yield types.SimpleNamespace(o=o,k=k,a=a,c=c,proof=proof,snaps=snaps,records=records,active=active,stack=st)

def remove_a(e):
    victim=next(d for d in e.proof.devices if d.device_id=='device01')
    e.snaps['device01']=h.policy.Snapshot('absent')
    for i in victim.policy_ids:e.active[i]=False
    return victim

def rejoin_a(e,victim):
    new=replace(victim.generation,ike_id=101,child_id=101,spi_in='10000101',spi_out='20000101')
    e.snaps['device01']=h.policy.Snapshot('unique',(new,))
    e.records[:]=[dict(r,id=r['id']+100) if r['id'] in victim.policy_ids else r for r in e.records]
    e.active.clear();e.active.update({r['id']:True for r in e.records})
    return new

class DeferredRetirement(unittest.TestCase):
    def tearDown(self):h.s.MUTATOR=None;h.s.DEADLINE=None;h.runtime.STOP.clear()
    def assert_b_survives(self,e,saved_b):
        self.assertEqual(e.c.last_result.state,'ACTIVE')
        self.assertEqual(e.c.last_result.active,('device02',))
        self.assertEqual(e.c.last_result.reason,'fleet_retirement_pending')
        self.assertEqual(e.c.active['device02'],saved_b)
        self.assertEqual(e.a.gate.current(),(saved_b,))
        self.assertEqual(e.k.tables,{'active4':[B4],'active6':[B6]})
        self.assertEqual(set(e.c.pending_retirements),{'device01'})
        self.assertEqual(e.k.guard_count,1)
        self.assertIsNone(e.c.failure)
    def test_persistent_unknown_blocks_new_a_keeps_b_then_recovers(self):
        with environment() as e:
            b=e.c.active['device02'];victim=remove_a(e);e.k.states=UNKNOWN+BSTATE
            e.c.step();self.assert_b_survives(e,b)
            self.assertEqual(e.o.session['fleet_closing']['phase'],'intent')
            new=rejoin_a(e,victim)
            for _ in range(6):
                before=len(e.k.trace);e.c.step();self.assert_b_survives(e,b)
                trace=e.k.trace[before:]
                self.assertEqual(trace.count(['/sbin/pfctl','-ss']),1)
                self.assertEqual([x[-1] for x in trace if '-k' in x],[A4,A4,A6,A6])
                self.assertFalse(any(x[:4]==['/sbin/pfctl','-a',h.native_gate.ANCHOR,'-f'] for x in trace))
            e.k.states=BSTATE;e.c.step()
            self.assertEqual(e.c.last_result.active,('device01','device02'))
            self.assertEqual(e.c.active['device01'].generation,new)
            self.assertEqual(e.c.active['device02'],b)
            self.assertEqual(e.c.pending_retirements,{})
            self.assertEqual(e.o.session['fleet_closing']['phase'],'verified')
            self.assertEqual(e.k.guard_count,1)
            self.assertEqual(e.k.states,BSTATE)
    def test_residual_states_are_deferred_not_false_absence(self):
        with environment() as e:
            b=e.c.active['device02'];remove_a(e)
            e.k.states=BSTATE+f'en0 tcp {A4}:3456 -> 1.1.1.1:443 ESTABLISHED:ESTABLISHED\n'
            e.c.step();self.assert_b_survives(e,b)
            self.assertEqual(e.o.session['fleet_closing']['phase'],'intent')
            e.k.states=BSTATE;e.c.step()
            self.assertEqual(e.c.pending_retirements,{})
            self.assertEqual(e.c.last_result.active,('device02',))
            self.assertEqual(e.k.guard_count,1)
    def test_only_known_state_read_failures_defer(self):
        cases=('timeout','nonzero','stderr','decode','limit')
        for case in cases:
            with self.subTest(case=case),environment() as e:
                b=e.c.active['device02'];remove_a(e);raw=e.k.run
                def run(args,**kwargs):
                    if list(args)==['/sbin/pfctl','-ss']:
                        if case=='timeout':raise subprocess.TimeoutExpired(list(args),2)
                        if case=='decode':raise UnicodeDecodeError('utf8',b'\xff',0,1,'bad output')
                        if case=='limit':raise h.s.Refused('command_output_limit')
                        return types.SimpleNamespace(stdout='',stderr='temporary issue' if case=='stderr' else '',returncode=1 if case=='nonzero' else 0)
                    return raw(args,**kwargs)
                with patch.object(h.s,'run',side_effect=run):e.c.step()
                self.assert_b_survives(e,b)
    def test_wrong_command_timeout_not_swallowed(self):
        with environment() as e:
            remove_a(e);raw=e.k.run
            def run(args,**kwargs):
                if list(args)==['/sbin/pfctl','-ss']:raise subprocess.TimeoutExpired(['/sbin/pfctl','-k',A4],2)
                return raw(args,**kwargs)
            with patch.object(h.s,'run',side_effect=run):result=e.c.step()
            self.assertEqual(result.state,'STOPPED')
            self.assertIs(type(e.c.failure),subprocess.TimeoutExpired)
    def test_delete_failure_remains_visible(self):
        with environment() as e:
            remove_a(e);raw=e.k.run
            def run(args,**kwargs):
                if '-k' in args:raise h.s.Refused('fixed_command_failed')
                return raw(args,**kwargs)
            with patch.object(h.s,'run',side_effect=run):result=e.c.step()
            self.assertEqual(result.state,'STOPPED')
            self.assertEqual(e.c.failure.args,('fixed_command_failed',))
    def test_unknown_read_does_not_hide_real_table_change(self):
        with environment() as e:
            remove_a(e);raw=e.k.run
            def run(args,**kwargs):
                if list(args)==['/sbin/pfctl','-ss']:
                    e.k.tables['active4']=[]
                    return types.SimpleNamespace(stdout=UNKNOWN,stderr='',returncode=0)
                return raw(args,**kwargs)
            with patch.object(h.s,'run',side_effect=run):result=e.c.step()
            self.assertEqual(result.state,'STOPPED')
            self.assertEqual(e.c.failure.args,('fleet_narrow_gate_changed',))
    def test_retry_checks_owner_and_current_active_set(self):
        with environment() as e:
            remove_a(e);e.k.states=UNKNOWN;e.c.step()
            with patch.object(e.o,'check_local',side_effect=h.s.Refused('owned_daemon_changed')):result=e.c.step()
            self.assertEqual(result.state,'STOPPED')
            self.assertEqual(e.c.failure.args,('owned_daemon_changed',))
    def test_malformed_partial_receipt_is_rejected(self):
        with environment() as e:
            d=e.c.active['device01'];b=e.c.active['device02']
            r=h.fc.CloseRequest(d.device_id,d.generation,d.generation.vip4,d.generation.vip6,d.hosts)
            for receipt in (h.fc.NarrowReceipt((b,),()),h.fc.NarrowReceipt((b,),(r,),(r,)),h.fc.NarrowReceipt((b,),(),(replace(r,vip4=B4),))):
                with self.subTest(receipt=receipt),self.assertRaises(h.policy.Fault):
                    e.c._retirement_receipt((b,),(r,),receipt)
    def test_pending_device_not_active_before_retry_kills(self):
        with environment() as e:
            remove_a(e);e.k.states=UNKNOWN;e.c.step();seen=[];raw=e.k.run
            def run(args,**kwargs):
                if '-k' in args:
                    seen.append((tuple(e.c.active),tuple(d.device_id for d in e.a.gate.current())))
                return raw(args,**kwargs)
            with patch.object(h.s,'run',side_effect=run):e.c.step()
            self.assertEqual(seen,[(('device02',),('device02',))]*4)

if __name__=='__main__':unittest.main()
