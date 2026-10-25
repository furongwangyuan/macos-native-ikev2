"""Known stopped-owner recovery and optional-output boundaries; zero native IO."""
import copy
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2] / 'server/runtime'
sys.path.insert(0, str(ROOT))
import supervisor_core as core
import service_supervisor as service
import native_runtime as runtime

KNOWN = ((core.OwnedDaemonExit, 'known_daemon_exit'),
         (core.KnownUplinkChange, 'known_uplink_change'),
         (core.MaintenanceDue, 'scheduled_maintenance'),
         (core.ViciUnavailable, 'vici_unavailable'),
         (core.GateReadbackUnavailable, 'gate_readback_unavailable'))


class Store:
    def __init__(self): self.value = None; self.history = []
    def load(self): return copy.deepcopy(self.value)
    def save(self, value):
        self.value = copy.deepcopy(value); self.history.append(copy.deepcopy(value))


class Deps:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes); self.now = 100.; self.stop = False
        self.calls = []; self.failures = []; self.clean = True; self.starts = []
        self.recovered = []; self.config = core.Configuration(True, 'a' * 64)
    def configuration(self): return self.config
    def boot(self): return 'current-boot'
    def authorize(self, config): pass
    def recover(self, expected_owner=False): self.recovered.append(expected_owner); return self.clean
    def preflight(self): self.calls.append('preflight'); return {}
    def prepare(self, session): self.calls.append('prepare'); self.starts.append(self.now); return object()
    def setup(self, owner): self.calls.append('setup')
    def serve(self, owner):
        self.calls.append('serve'); outcome = self.outcomes.pop(0)
        if outcome is None: self.stop = True; return
        raise outcome
    def cleanup(self, owner): self.calls.append('cleanup'); return self.clean
    def wait(self, seconds): self.now += seconds
    def stopped(self): return self.stop
    def event(self, *args): pass
    def failure(self, error): self.failures.append(error)


def saved(reason, phase='BACKOFF', boot='current-boot'):
    return dict(version=1, phase=phase, boot=boot, fingerprint='a'*64,
                attempts=[100, 105, 120], next_due=220 if phase=='BACKOFF' else 0,
                reason=reason, updated=180)


class RecoveryCooldown(unittest.TestCase):
    def run_case(self, deps, state=None):
        store = Store(); store.value = state
        self.assertEqual(core.Supervisor(deps, store, lambda: deps.now).run(), 0)
        return store

    def test_all_known_serve_failures_wait_for_budget_then_retry(self):
        for kind, reason in KNOWN:
            with self.subTest(reason=reason):
                d = Deps([kind('known') for _ in range(4)] + [None]); store = self.run_case(d)
                self.assertEqual((store.value['phase'],store.value['reason']),('STOPPED','manual_stop'))
                self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))
                self.assertEqual(d.calls.count('serve'), 5); self.assertEqual(d.calls.count('cleanup'), 5)
                for start in d.starts:
                    self.assertLessEqual(sum(0 <= start-earlier < 900 for earlier in d.starts), 3)
                self.assertEqual(d.starts[:4], [100, 105, 120, 1000])
                self.assertTrue(any(x['phase']=='BACKOFF' and x['reason']==reason for x in store.history))
                self.assertTrue(all(x['next_due']<=x['updated']+60 for x in store.history))
        self.assertEqual((core.MAX_ATTEMPTS,core.RETRY_WINDOW,core.RETRY_DELAYS),(3,900,(5,15,60)))

    def test_full_cleanup_remains_before_each_restart(self):
        for kind, reason in KNOWN:
            with self.subTest(reason=reason):
                d=Deps([kind('known'),None]);self.run_case(d)
                self.assertEqual(d.calls,['preflight','prepare','setup','serve','cleanup']*2)

    def test_cleanup_failure_still_stops_every_known_reason(self):
        for kind, reason in KNOWN:
            with self.subTest(reason=reason):
                d=Deps([kind('known')])
                original=d.serve
                def fail_cleanup(owner):
                    d.clean=False;return original(owner)
                d.serve=fail_cleanup
                d.wait=lambda seconds:setattr(d,'stop',True)
                store=self.run_case(d)
                self.assertEqual((store.value['phase'],store.value['reason']),('ATTENTION','recovery_not_proven'))
                self.assertEqual(d.calls.count('serve'),1)
                self.assertFalse(any(x['phase']=='BACKOFF' for x in store.history))

    def test_resume_backoff_and_interrupted_recovery_preserve_known_reason(self):
        for _,reason in KNOWN:
            for phase in ('BACKOFF','RECOVERING'):
                with self.subTest(reason=reason,phase=phase):
                    d=Deps([None]);d.now=200;store=self.run_case(d,saved(reason,phase))
                    self.assertEqual(d.recovered,[phase=='RECOVERING']);self.assertEqual(d.starts,[1000])
                    self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))
                    self.assertTrue(any(x['phase']=='BACKOFF' and x['reason']==reason for x in store.history))

    def test_resumed_wait_requires_fresh_recovery(self):
        for _,reason in KNOWN:
            with self.subTest(reason=reason):
                d=Deps([None]);d.now=200;d.clean=False
                d.wait=lambda seconds:setattr(d,'stop',True)
                store=self.run_case(d,saved(reason))
                self.assertEqual(store.value['reason'],'recovery_not_proven');self.assertEqual(d.starts,[])

    def test_wait_honors_manual_stop_and_configuration_changes(self):
        for _,reason in KNOWN:
            for change in ('stop','configuration'):
                with self.subTest(reason=reason,change=change):
                    d=Deps([]);d.now=200;wait=d.wait
                    def update(seconds):
                        wait(seconds)
                        if d.now>=225:
                            if change=='stop':d.stop=True
                            else:d.config=core.Configuration(True,'b'*64)
                        if change=='configuration' and d.now>=226:d.stop=True
                    d.wait=update;store=self.run_case(d,saved(reason))
                    self.assertEqual(d.starts,[])
                    self.assertEqual(store.value['reason'],'manual_stop' if change=='stop' else 'configuration_changed')

    def test_manual_stop_during_newly_exhausted_budget_never_restarts(self):
        for kind,reason in KNOWN:
            with self.subTest(reason=reason):
                d=Deps([kind('known') for _ in range(3)]);wait=d.wait
                def stop_later(seconds):
                    wait(seconds)
                    if d.now>=200:d.stop=True
                d.wait=stop_later;store=self.run_case(d)
                self.assertEqual((store.value['phase'],store.value['reason']),('STOPPED','manual_stop'))
                self.assertEqual(d.starts,[100,105,120]);self.assertEqual(d.calls.count('cleanup'),3)

    def test_unknown_or_subclass_failure_requires_full_fresh_recovery(self):
        class Derived(core.OwnedDaemonExit): pass
        for error in (RuntimeError('owned_charon_exited'),Derived('owned_charon_exited')):
            with self.subTest(error=type(error).__name__):
                d=Deps([error,None]);store=self.run_case(d)
                self.assertTrue(any(x['reason']=='unknown_failure' for x in store.history))
                self.assertEqual(len(d.starts),2);self.assertEqual(d.calls.count('cleanup'),2)
                self.assertFalse(any(x['phase']=='BACKOFF' for x in store.history))

    def test_setup_failure_recovers_before_fresh_start(self):
        d=Deps([None]);attempt=[0]
        def setup(_):
            attempt[0]+=1
            if attempt[0]==1:raise core.OwnedDaemonExit('setup_failed')
        d.setup=setup;store=self.run_case(d)
        self.assertTrue(any(x['reason']=='unknown_failure' for x in store.history))
        self.assertEqual(len(d.starts),2);self.assertEqual(d.calls.count('cleanup'),2)

    def test_unknown_backoff_keeps_budget_and_cross_boot_waits(self):
        d=Deps([None]);d.now=200;store=self.run_case(d,saved('unknown_failure'))
        self.assertTrue(any(x['reason']=='retry_budget_exhausted' for x in store.history))
        self.assertEqual(d.starts,[1000])
        for _,reason in KNOWN:
            with self.subTest(reason=reason):
                d=Deps([]);d.now=200;d.wait=lambda seconds:setattr(d,'stop',True)
                store=self.run_case(d,saved(reason,boot='old-boot'))
                self.assertEqual(store.value['reason'],'cross_boot_unfinished');self.assertEqual(d.starts,[])

    def test_optional_event_log_failure_does_not_stop_healthy_run(self):
        d=Deps([None]);d.event=Mock(side_effect=OSError('log unavailable'))
        store=self.run_case(d)
        self.assertEqual(store.value['reason'],'manual_stop');self.assertEqual(d.calls.count('serve'),1)
        self.assertTrue(any(x['phase']=='RUNNING' for x in store.history))
        self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))


class ChildExitRace(unittest.TestCase):
    def owner(self, outcome, polls):
        owner=object.__new__(service.ServiceOwner)
        owner.daemon=SimpleNamespace(pid=123,poll=Mock(side_effect=polls))
        owner.clock=lambda:0;owner.config_checked=0;owner.same_boot=lambda:None
        owner.owned_process=Mock(side_effect=outcome) if isinstance(outcome,Exception) else Mock(return_value=outcome)
        return owner

    def test_exit_between_two_polls_becomes_owned_exit(self):
        owner=self.owner(None,[None,0,0])
        with self.assertRaises(core.OwnedDaemonExit):owner.check_local(5)
        self.assertEqual(owner.daemon.poll.call_count,3)

    def test_exact_libproc_unavailability_only_maps_after_owned_exit(self):
        for code in ('process_identity_unavailable','process_path_unavailable'):
            with self.subTest(code=code):
                owner=self.owner(service.s.Refused(code),[None,None,0])
                with self.assertRaises(core.OwnedDaemonExit):owner.check_local(5)

    def test_live_owned_process_unavailability_stays_unknown(self):
        for outcome in (None,service.s.Refused('process_identity_unavailable'),service.s.Refused('process_path_unavailable')):
            with self.subTest(outcome=outcome):
                owner=self.owner(outcome,[None,None,None])
                with self.assertRaises((runtime.ctl.Fault,service.s.Refused)) as error:owner.check_local(5)
                self.assertNotIsInstance(error.exception,core.OwnedDaemonExit)

    def test_changed_identity_and_other_failures_are_not_mapped(self):
        for code in ('owned_child_identity_changed','unknown_native_journal'):
            with self.subTest(code=code):
                owner=self.owner(service.s.Refused(code),[None,None,0])
                with self.assertRaises(service.s.Refused) as error:owner.check_local(5)
                self.assertEqual(error.exception.args,(code,));self.assertEqual(owner.daemon.poll.call_count,2)

    def test_observed_wrong_executable_is_not_reclassified_after_exit(self):
        owner=self.owner({'path':'/fixture/spawn-gate'},[None,None,0])
        with self.assertRaises(runtime.ctl.Fault) as error:owner.check_local(5)
        self.assertEqual(error.exception.args,('charon_exited_or_changed',))
        self.assertEqual(owner.daemon.poll.call_count,2)

    def test_absence_diagnostic_remains_identifiable(self):
        record=service.failure_record(runtime.ctl.Fault('charon_process_absent'))
        self.assertEqual(record['errors'][0],{'type':'Fault','code':'charon_process_absent'})


class ClosedFaultCompatibility(unittest.TestCase):
    def run_fault(self,code):
        tick={'now':0,'signalled':False}
        def wait(seconds):tick['now']+=seconds;return False
        def signal(pid,number):tick['signalled']=True
        def check(timeout):
            if tick['signalled']:raise runtime.ctl.Fault(code)
        owner=SimpleNamespace(session={},check_local=check,
            owned_process=lambda:{'pid':123,'path':str(runtime.s.CHARON)},
            daemon=SimpleNamespace(pid=123,poll=lambda:None),save=Mock(),guard=Mock(),
            gate=SimpleNamespace(closed=lambda:True))
        with patch.object(runtime.STOP,'wait',side_effect=wait), \
                patch.object(runtime.os,'kill',side_effect=signal), \
                patch.object(runtime.policies,'verify_native_protection',return_value=None), \
                patch.object(runtime.s,'say',return_value=None):
            runtime.closed_loop(owner,'closed-charon-term-test',lambda:tick['now'])
        return owner

    def test_exact_absence_after_injected_exit_is_recognized(self):
        owner=self.run_fault('charon_process_absent')
        self.assertEqual(owner.session['fault_control']['phase'],'detected-and-closed')
        owner.guard.assert_called_once()

    def test_wrong_executable_after_injection_is_not_success(self):
        with self.assertRaises(runtime.ctl.Fault) as error:self.run_fault('charon_exited_or_changed')
        self.assertEqual(error.exception.args,('charon_exited_or_changed',))


class CleanupOutput(unittest.TestCase):
    def owner(self):
        owner=object.__new__(runtime.Owner)
        owner.session={'phase':'ACTIVE','active':True,'pf':{'phase':'applied'},'alf_before':{'baseline':True}}
        owner.same_boot=lambda:None;owner.dispatcher=SimpleNamespace(settle=lambda:None)
        owner.alf_transaction=None;owner.probe=SimpleNamespace(stop=lambda:None)
        owner.stop_child=lambda:None;owner.restore_files=lambda:None
        owner.gate=SimpleNamespace(protect=lambda:True,restore_sysctls=lambda:None,
                                   restore_pf=lambda:None,closed=lambda:True)
        owner.data_mode=True;owner.save=Mock()
        return owner

    def run_cleanup(self,owner):
        with patch.object(runtime.s,'run',return_value=SimpleNamespace(returncode=1)), \
                patch.object(runtime.s,'sad_empty',return_value=True), \
                patch.object(runtime.policies,'read_spd',return_value=([],None)), \
                patch.object(runtime.alf,'snapshot',return_value={'baseline':True}), \
                patch.object(runtime.s,'say',side_effect=BrokenPipeError('stdout closed')):
            return owner.cleanup()

    def test_optional_output_failure_does_not_replace_restored_result(self):
        owner=self.owner();self.assertTrue(self.run_cleanup(owner))
        self.assertEqual((owner.session['phase'],owner.session['active']),('RESTORED',False))
        self.assertEqual(owner.session['cleanup_codes'],[])

    def test_durable_save_failure_still_raises(self):
        owner=self.owner();owner.save=Mock(side_effect=OSError('disk write failed'))
        with self.assertRaises(OSError):self.run_cleanup(owner)

    def test_real_cleanup_failure_remains_false_despite_output_failure(self):
        owner=self.owner();owner.gate.restore_pf=Mock(side_effect=service.s.Refused('pf_changed'))
        self.assertFalse(self.run_cleanup(owner))
        self.assertEqual((owner.session['phase'],owner.session['active']),('ATTENTION',True))
        self.assertEqual(owner.session['cleanup_codes'],['owned_recovery'])


def forbidden(*args,**kwargs):raise AssertionError('real native/network effect forbidden')


if __name__=='__main__':
    if os.geteuid()==0:raise SystemExit('ordinary user only')
    with patch.object(subprocess,'Popen',side_effect=forbidden), \
            patch.object(socket,'socket',side_effect=forbidden), \
            patch.object(os,'system',side_effect=forbidden):
        unittest.main(verbosity=2)
