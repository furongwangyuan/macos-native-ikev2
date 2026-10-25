"""Offline regression for the exact three-endpoint Darwin PF NAT display."""
import copy,json,os,sys,types,unittest
from contextlib import ExitStack
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
A4='10.77.26.10';B4='10.77.26.11'
A6='fd6d:fe83:ab27:2600::10';B6='fd6d:fe83:ab27:2600::11'
# Literal shapes observed during a real concurrency failure. Home IP/GUA and
# client-specific address were replaced by documentation/fixture addresses.
CHAIN4='en0 tcp 10.77.26.11:62098 -> 192.0.2.8:42513 -> 1.1.1.1:443       ESTABLISHED:SYN_SENT'
CHAIN6='en0 tcp fd6d:fe83:ab27:2600::11[62096] -> 2001:db8::8[37204] -> 2001:db8:100::[443]       ESTABLISHED:SYN_SENT'

class NatChain(unittest.TestCase):
    def tearDown(self):h.s.MUTATOR=None;h.s.DEADLINE=None;h.runtime.STOP.clear()
    def test_actual_shape_both_families_directions(self):
        for line,vip in ((CHAIN4,B4),(CHAIN6,B6)):
            for arrow in ('->','<-'):
                text=line.replace('->',arrow)
                self.assertFalse(no_address_state(text,(vip,)))
                self.assertTrue(no_address_state(text,(A4,A6)))
    def test_every_endpoint_is_examined(self):
        for line,addresses in ((CHAIN4,(B4,'192.0.2.8','1.1.1.1')),(CHAIN6,(B6,'2001:db8::8','2001:db8:100::'))):
            for address in addresses:self.assertFalse(no_address_state(line,(address,)))
    def test_expanded_ipv6_is_normalized(self):
        text=CHAIN6.replace(B6,'fd6d:fe83:ab27:2600:0:0:0:11')
        self.assertFalse(no_address_state(text,(B6,)))
    def test_parenthesized_forms_preserved(self):
        for text in (f'en0 tcp 192.0.2.8:555 ({B4}:444) -> 1.1.1.1:443 ESTABLISHED:ESTABLISHED',
                     f'en0 tcp 1.1.1.1:443 <- 192.0.2.8:555 ({B4}:444) ESTABLISHED:ESTABLISHED',
                     f'en0 tcp 2001:db8::8[555] ({B6}[444]) -> 2001:4860::8888[443] ESTABLISHED:ESTABLISHED'):
            self.assertFalse(no_address_state(text,(B4,B6)))
            self.assertTrue(no_address_state(text,(A4,A6)))
    def test_malformed_chains_not_silently_ignored(self):
        for text in (CHAIN4.replace(' -> 1.1.1.1',' <- 1.1.1.1'),CHAIN4.replace('192.0.2.8:42513','not-an-endpoint'),CHAIN4.replace(':42513',':99999'),CHAIN4.replace(' -> 1.1.1.1:443',' -> -> 1.1.1.1:443'),CHAIN4+' extra', 'unrecognized diagnostic'):
            with self.assertRaises(h.s.Refused):no_address_state(text,(A4,A6))
    def test_target_and_unrelated_states_mixed(self):
        text=CHAIN4+'\n'+CHAIN6+'\n'+CHAIN4.replace(B4,A4)
        self.assertFalse(no_address_state(text,(A4,A6)))
    def test_distinct_host_not_prefix_matched(self):
        self.assertTrue(no_address_state(CHAIN4.replace(B4,'10.77.26.110'),(B4,)))
        self.assertTrue(no_address_state(CHAIN6.replace(B6,'fd6d:fe83:ab27:2600::110'),(B6,)))
    def test_real_adapter_retire_a_keeps_b_and_rejoins(self):
        outer=('192.0.2.8','2001:4860:1234:5678::8')
        _,o,proof,snaps,records,active,native=h.fixture(outer_endpoints=outer,peer6='2001:4860:abcd::101')
        k=h.Kernel(o);adapter=o.fleet_adapter
        with ExitStack() as st:
            k.bind(st)
            def read(_=10):adapter.last_context='a'*32;return h.ParseResult(copy.deepcopy(snaps),0)
            st.enter_context(patch.object(adapter,'read_fleet',side_effect=read))
            st.enter_context(patch.object(h.runtime.policies,'parse_spd',side_effect=lambda _:copy.deepcopy(records)))
            st.enter_context(patch.object(h.runtime.policies,'policy_id_active',side_effect=lambda ident,*args,**kwargs:active[ident]))
            c=h.fc.Coordinator(o.session['fleet']['registry'],adapter,outer_endpoints=outer)
            self.assertEqual(c.step().active,('device01','device02'))
            self.assertEqual(k.guard_count,1)
            victim=next(d for d in proof.devices if d.device_id=='device01')
            survivor=next(d for d in proof.devices if d.device_id=='device02')
            saved_b=c.active['device02']
            k.states=CHAIN4+'\n'+CHAIN6
            before=len(k.trace)
            snaps['device01']=h.policy.Snapshot('absent')
            for i in victim.policy_ids:active[i]=False
            result=c.step()
            self.assertEqual((result.state,result.active),('ACTIVE',('device02',)))
            self.assertIsNone(c.failure)
            self.assertEqual(k.guard_count,1)
            self.assertEqual(c.active['device02'],saved_b)
            self.assertEqual(k.states,CHAIN4+'\n'+CHAIN6)
            self.assertEqual(k.tables,{'active4':[B4],'active6':[B6]})
            self.assertEqual(o.session['fleet_closing']['phase'],'verified')
            kills=[x for x in k.trace[before:] if '-k' in x]
            self.assertEqual([x[-1] for x in kills],[A4,A4,A6,A6])
            self.assertEqual(k.values,h.s.SYS)
            new=replace(victim.generation,ike_id=101,child_id=101,spi_in='10000101',spi_out='20000101')
            snaps['device01']=h.policy.Snapshot('unique',(new,))
            records[:]=[dict(r,id=r['id']+100) if r['id'] in victim.policy_ids else r for r in records]
            active.clear();active.update({r['id']:True for r in records})
            result=c.step()
            self.assertEqual((result.state,result.active),('ACTIVE',('device01','device02')))
            self.assertEqual(k.guard_count,1)
            self.assertIsNone(c.failure)
            self.assertEqual(c.active['device02'],saved_b)
            self.assertEqual(k.states,CHAIN4+'\n'+CHAIN6)

if __name__=='__main__':unittest.main()
