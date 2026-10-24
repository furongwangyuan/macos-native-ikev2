"""Actual Coordinator, NativeFleetAdapter, PF gate and registry; OS effects inert."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch, Mock

if os.geteuid()==0:raise SystemExit('ordinary user only')
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent;R=D.parents[1]/'server/runtime'
fixture_path=D/'test_native_fleet.py'
source=fixture_path.read_text()
source=source.replace("'203.0.113.101',45000+i", "'203.0.113.'+str(101+i),45000+i")
h=types.ModuleType('route_isolation_fixture');h.__file__=str(fixture_path)
sys.modules[h.__name__]=h;exec(compile(source,str(fixture_path),'exec'),h.__dict__)
REPORT={}


class RouteIsolation(unittest.TestCase):
    def tearDown(self):h.s.MUTATOR=None;h.s.DEADLINE=None;h.runtime.STOP.clear()

    def scenario(self,which,mode):
        _,owner,proof,snaps,records,activity,_=h.fixture()
        kernel=h.Kernel(owner);adapter=owner.fleet_adapter
        a=next(d for d in proof.devices if d.device_id=='device01')
        b=next(d for d in proof.devices if d.device_id=='device02')
        target={'ipv4':a.generation.vip4,'ipv6':a.generation.vip6,'peer':a.generation.peer4}[which]
        fault={'enabled':False};queries=[]
        def run(args,**kwargs):
            args=list(map(str,args))
            if args[:3]==['/sbin/route','-n','get']:
                self.assertIs(kwargs.get('check'),False)
                queries.append(args[-1])
                if fault['enabled'] and args[-1]==target:
                    kernel.trace.append(args)
                    if mode=='timeout':raise subprocess.TimeoutExpired(args,5)
                    return SimpleNamespace(stdout='',stderr='route lookup unavailable',returncode=1)
            return kernel.run(args,**kwargs)
        with ExitStack() as stack:
            kernel.bind(stack)
            stack.enter_context(patch.object(h.s,'run',side_effect=run))
            def read(_=10):
                adapter.last_context='a'*32
                return h.ParseResult(copy.deepcopy(snaps),0)
            stack.enter_context(patch.object(adapter,'read_fleet',side_effect=read))
            stack.enter_context(patch.object(h.runtime.policies,'parse_spd',side_effect=lambda _:copy.deepcopy(records)))
            stack.enter_context(patch.object(h.runtime.policies,'policy_id_active',side_effect=lambda ident,*a,**k:activity[ident]))
            coordinator=h.fc.Coordinator(owner.session['fleet']['registry'],adapter)
            self.assertEqual(coordinator.step().active,('device01','device02'))
            self.assertEqual(kernel.guard_count,1)
            before=len(kernel.trace);queries.clear();fault['enabled']=True
            result=coordinator.step()
            self.assertEqual((result.state,result.active),('ACTIVE',('device02',)))
            self.assertIsNone(coordinator.failure)
            self.assertEqual(kernel.guard_count,1)
            self.assertEqual(kernel.values,h.s.SYS)
            for target_b in (b.generation.vip4,b.generation.vip6,b.generation.peer4):
                self.assertEqual(queries.count(target_b),3)
            kills=[args for args in kernel.trace[before:] if '-k' in args]
            self.assertEqual([args[-1] for args in kills],[a.generation.vip4]*2+[a.generation.vip6]*2)
            self.assertTrue(all(b.generation.vip4 not in args and b.generation.vip6 not in args for args in kills))
            self.assertEqual(kernel.tables,{'active4':[b.generation.vip4],'active6':[b.generation.vip6]})
            self.assertFalse(any(args[0] in ('/bin/kill','/usr/bin/kill','/usr/bin/pkill') for args in kernel.trace))
            fault['enabled']=False
            self.assertEqual(coordinator.step().active,('device01','device02'))
            self.assertEqual(kernel.guard_count,1)
            REPORT[which+'_'+mode]={'b_retained':True,'b_fresh_route_frames':3,
                'global_guards_after_initial':0,'only_a_states_cleared':True,'a_resumed':True}

    def test_ipv4_ipv6_peer_command_failures_only_narrow_affected_device(self):
        for which in ('ipv4','ipv6','peer'):
            with self.subTest(which=which):self.scenario(which,'exit')

    def test_ipv4_ipv6_peer_timeouts_only_narrow_affected_device(self):
        for which in ('ipv4','ipv6','peer'):
            with self.subTest(which=which):self.scenario(which,'timeout')

    def test_timeout_classification_does_not_swallow_wrong_commands_or_unknown_errors(self):
        _,owner,proof,*_=h.fixture();adapter=owner.fleet_adapter;device=proof.devices[0]
        args=['/sbin/route','-n','get','-inet',device.generation.vip4]
        class Derived(subprocess.TimeoutExpired):pass
        errors=[subprocess.TimeoutExpired(['/usr/sbin/sysctl','-n','kern.boottime'],5),
                subprocess.TimeoutExpired(args,6),subprocess.TimeoutExpired(args,0),
                Derived(args,5),h.s.Refused('command_budget'),OSError('unknown')]
        for error in errors:
            with self.subTest(error=type(error).__name__),patch.object(h.s,'run',side_effect=error),self.assertRaises(type(error)):
                adapter.route(device)

    def test_malformed_successful_route_remains_unavailable(self):
        _,owner,proof,*_=h.fixture()
        with patch.object(h.s,'run',return_value=SimpleNamespace(stdout='unknown route',stderr='',returncode=0)):
            self.assertIsNone(owner.fleet_adapter.route(proof.devices[0]))

    def context_case(self,current,exit_after_first):
        owner=SimpleNamespace(same_boot=lambda:None,
            daemon=SimpleNamespace(poll=Mock(side_effect=[None,0 if exit_after_first else None])))
        owner.known_child_alive=types.MethodType(h.fn.service.ServiceOwner.known_child_alive,owner)
        owner.owned_process=Mock(side_effect=current) if isinstance(current,Exception) else Mock(return_value=current)
        adapter=object.__new__(h.fn.NativeFleetAdapter);adapter.owner=owner
        return owner,adapter

    def test_owned_child_exit_between_poll_and_missing_libproc_is_known_exit(self):
        for value in (None,h.s.Refused('process_identity_unavailable'),h.s.Refused('process_path_unavailable')):
            owner,adapter=self.context_case(value,True)
            with self.subTest(value=repr(value)),self.assertRaises(h.fn.service.OwnedDaemonExit):adapter._context()
            self.assertEqual(owner.daemon.poll.call_count,2)

    def test_missing_process_metadata_without_owned_exit_keeps_original_error(self):
        for value,code in ((None,'fleet_charon_identity'),
                           (h.s.Refused('process_identity_unavailable'),'process_identity_unavailable'),
                           (h.s.Refused('process_path_unavailable'),'process_path_unavailable')):
            owner,adapter=self.context_case(value,False)
            with self.subTest(code=code),self.assertRaises(h.s.Refused) as cm:adapter._context()
            self.assertEqual(cm.exception.args,(code,));self.assertEqual(owner.daemon.poll.call_count,2)

    def test_changed_identity_and_unrecognized_errors_are_not_exit_reclassified(self):
        class Derived(h.s.Refused):pass
        for value in ({'path':'/unknown/process'},h.s.Refused('owned_child_identity_changed'),
                      h.s.Refused('process_identity_unavailable','extra'),Derived('process_identity_unavailable')):
            owner,adapter=self.context_case(value,True)
            with self.subTest(value=repr(value)),self.assertRaises(h.s.Refused):adapter._context()
            self.assertEqual(owner.daemon.poll.call_count,1)


if __name__=='__main__':
    unittest.main(verbosity=2)
