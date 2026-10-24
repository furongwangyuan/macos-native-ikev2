"""Real coordinator/controller with concrete adapter and inert OS boundaries."""
import copy
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

if os.geteuid()==0:raise SystemExit('ordinary user only')
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent;R=D.parents[1]/'server/runtime'
p=D/'test_native_fleet.py'
source=p.read_text()
h=types.ModuleType('soft_pause_native_fixture');h.__file__=str(p)
sys.modules[h.__name__]=h;exec(compile(source,str(p),'exec'),h.__dict__)
import fleet_transport as transport
import service_supervisor as service
REPORT={}


class Harness:
    def __init__(self):
        _,self.owner,self.proof,self.snaps,self.records,self.activity,_=h.fixture()
        self.kernel=h.Kernel(self.owner);self.adapter=self.owner.fleet_adapter
        self.stack=ExitStack();self.kernel.bind(self.stack)
        self.reads=0;self.failures={};self.trace=[]
        self.stack.enter_context(patch.object(self.adapter,'read_fleet',side_effect=self.read))
        self.stack.enter_context(patch.object(h.runtime.policies,'parse_spd',side_effect=lambda _:copy.deepcopy(self.records)))
        self.stack.enter_context(patch.object(h.runtime.policies,'policy_id_active',side_effect=lambda ident,*a,**k:self.activity[ident]))
        self.c=h.fc.Coordinator(self.owner.session['fleet']['registry'],self.adapter)
    def read(self,_=10):
        self.reads+=1;self.trace.append(('read',self.reads))
        if self.reads in self.failures:raise self.failures[self.reads]
        self.adapter.last_context='a'*32
        return h.ParseResult(copy.deepcopy(self.snaps),0)
    def fail_next(self,offset=1,code='vici_exchange_timeout'):
        error=transport.TransientTransportFault(code);self.failures[self.reads+offset]=error;return error
    def healthy(self):return self.c.step()
    def close(self):self.stack.close();h.s.MUTATOR=None;h.s.DEADLINE=None;h.runtime.STOP.clear()


class Checks(unittest.TestCase):
    def make(self):
        x=Harness();self.addCleanup(x.close);return x
    def established(self):
        x=self.make();self.assertEqual(x.healthy().active,('device01','device02'));return x

    def test_first_second_and_post_read_failures_close_then_freshly_resume_same_owner(self):
        for offset in (1,2,3):
            x=self.established();owner=x.owner;prior=copy.deepcopy(x.c.last_activated)
            x.fail_next(offset);result=x.healthy()
            self.assertEqual((result.state,result.active,result.global_guard_confirmed),('GUARDED',(),True))
            self.assertEqual(x.c.transient_pauses,1);self.assertIsNone(x.c.failure)
            self.assertEqual(x.c.last_activated,prior)
            self.assertEqual(x.owner.session['fleet_active'],[])
            self.assertFalse(any(x.kernel.values[k] for k in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding')))
            before=x.reads;self.assertEqual(x.healthy().active,('device01','device02'))
            self.assertEqual(x.reads-before,3);self.assertEqual(x.c.transient_pauses,0)
            self.assertIs(x.owner,owner);self.assertEqual(x.kernel.guard_count,2)
            REPORT['frame_'+str(offset)]={'same_owner':True,'partial_reused':False,'fresh_resume_frames':3}
            x.close()

    def test_four_exact_transient_codes_and_no_other_types(self):
        for code in ('vici_exchange_timeout','vici_exchange_eof','vici_exchange_io','vici_exchange_capacity'):
            x=self.established();x.fail_next(code=code)
            self.assertEqual(x.healthy().state,'GUARDED');self.assertEqual(x.c.transient_pauses,1);x.close()
        class Derived(transport.TransientTransportFault):pass
        for error in (transport.TransportFault('vici_exchange_timeout'),Derived('vici_exchange_timeout'),
                      transport.TransientTransportFault('unreviewed'),transport.TransientTransportFault('vici_exchange_timeout','extra')):
            x=self.established();x.failures[x.reads+1]=error
            self.assertEqual(x.healthy().state,'STOPPED');self.assertIs(x.c.failure,error);x.close()

    def test_third_consecutive_failure_uses_existing_stopped_fallback(self):
        x=self.established();last=None
        for index in range(3):
            last=x.fail_next();result=x.healthy()
            self.assertEqual(result.state,'GUARDED' if index<2 else 'STOPPED')
        self.assertEqual(x.c.transient_pauses,2);self.assertIs(x.c.failure,last)
        # The actual controller wraps that retained cause, and the original
        # service classifier still sends the third failure to full recovery.
        controller=object.__new__(h.controller.Controller)
        controller.owner=x.owner;controller.deadline=10;controller.clock=lambda:0
        controller.coordinator=x.c;controller.failure=None
        with patch.object(h.controller,'Controller',lambda *args:controller),self.assertRaises(service.ViciUnavailable):
            service.NativeDependencies.serve(types.SimpleNamespace(clock=lambda:0),x.owner)

    def test_guard_failure_cannot_become_a_successful_soft_pause(self):
        x=self.established();error=x.fail_next()
        with patch.object(x.adapter,'guard_all',side_effect=h.s.Refused('closed_gate_unverified')):
            result=x.healthy()
        self.assertEqual(result.state,'STOPPED');self.assertFalse(result.global_guard_confirmed)
        self.assertEqual(x.c.transient_pauses,0);self.assertIs(x.c.failure,error)

    def test_counter_resets_only_after_successful_complete_tick(self):
        x=self.established()
        for _ in range(2):x.fail_next();self.assertEqual(x.healthy().state,'GUARDED')
        self.assertEqual(x.c.transient_pauses,2)
        self.assertEqual(x.healthy().active,('device01','device02'));self.assertEqual(x.c.transient_pauses,0)
        x.fail_next();self.assertEqual(x.healthy().state,'GUARDED');self.assertEqual(x.c.transient_pauses,1)

    def test_post_publish_failure_retains_new_generation_closed_provenance(self):
        x=self.established();old=x.snaps['device01'].generations[0]
        new=replace(old,ike_id=71,child_id=71,reqid=71,spi_in='a1000071',spi_out='b1000071')
        x.snaps['device01']=h.policy.Snapshot('unique',(new,))
        for row in x.records:
            if row['kind']=='ipsec' and any(old.vip4 in row[k] or old.vip6 in row[k] for k in ('src','dst')):
                row['requests']=[request.rsplit('/unique:',1)[0]+'/unique:71' for request in row['requests']]
        x.fail_next(3);self.assertEqual(x.healthy().state,'GUARDED')
        self.assertEqual(x.c.last_activated['device01'].generation,new)
        before=x.reads;self.assertEqual(x.healthy().active,('device01','device02'))
        self.assertEqual(x.reads-before,3);self.assertEqual(x.c.active['device01'].generation,new)
        self.assertEqual(x.kernel.guard_count,2)

    def test_actual_controller_continues_after_soft_pause_without_daemon_cleanup(self):
        x=self.make();now=[0];snapshots=[]
        def wait(seconds):
            snapshots.append((x.controller.coordinator.last_result.state,
                              x.controller.coordinator.last_result.active))
            now[0]+=seconds
        x.owner.wait=wait
        x.failures[4]=transport.TransientTransportFault('vici_exchange_eof')
        x.controller=h.controller.Controller(x.owner,3,lambda:now[0])
        x.controller.run()
        self.assertIsNone(x.controller.failure)
        self.assertEqual(snapshots,[('ACTIVE',('device01','device02')),('GUARDED',()),('ACTIVE',('device01','device02'))])
        self.assertEqual(x.reads,7)
        self.assertEqual(x.kernel.guard_count,3) # initial, soft closure, normal finite-test exit only
        self.assertFalse(any(args[0] in ('/bin/kill','/usr/bin/pkill','/usr/bin/kill') for args in x.kernel.trace))
        REPORT['controller']={'actual_loop':'ACTIVE -> GUARDED -> ACTIVE','daemon_cleanup_called':False}


if __name__=='__main__':
    unittest.main(verbosity=2)
