"""Exact PF readback recovery classification and lifecycle; no kernel effects."""
import copy
import json
import math
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

if os.geteuid() == 0:
    raise SystemExit('ordinary user only')
ROOT = Path(__file__).resolve().parents[2] / 'server/runtime'
sys.path.insert(0, str(ROOT))
import supervisor_core as core
import service_supervisor as service
import fleet_controller
import fleet_coordinator


class Store:
    def __init__(self): self.value = None; self.history = []
    def load(self): return copy.deepcopy(self.value)
    def save(self, value): self.value = copy.deepcopy(value); self.history.append(copy.deepcopy(value))


class Deps:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes); self.now = 100.; self.stop = False
        self.calls = []; self.failures = []; self.clean = True; self.starts = []
    def configuration(self): return core.Configuration(True, 'a' * 64)
    def boot(self): return 'current-boot'
    def authorize(self, config): pass
    def recover(self, expected_owner=False): return True
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


class Checks(unittest.TestCase):
    def tearDown(self): service.runtime.STOP.clear()

    def run_case(self, deps):
        store = Store()
        self.assertEqual(core.Supervisor(deps, store, lambda: deps.now).run(), 0)
        return store

    def boundary(self, cause, confirmed=True, *, final_guard_error=None, wrapper='fleet_controller_stopped', changed_cause=False):
        result = fleet_coordinator.Result('STOPPED', (), 0, 'readback', confirmed)
        coordinator = SimpleNamespace(failure=cause, last_result=result, step=lambda: result)
        guard_calls = []
        def guard(*args):
            guard_calls.append(args)
            if final_guard_error is not None: raise final_guard_error
        # Exercise the actual controller's finally guard on the normal path.
        actual = object.__new__(fleet_controller.Controller)
        actual.owner = SimpleNamespace(session={}, guard=guard)
        actual.deadline = math.inf; actual.clock = lambda: 0
        actual.coordinator = coordinator; actual.failure = None
        if wrapper != 'fleet_controller_stopped' or changed_cause:
            def altered():
                raise service.runtime.ctl.Fault(wrapper) from (ValueError('other') if changed_cause else cause)
            actual.run = altered
        with patch.object(fleet_controller, 'Controller', lambda *args: actual):
            try:
                service.NativeDependencies.serve(SimpleNamespace(clock=lambda: 0), object())
            finally:
                if wrapper == 'fleet_controller_stopped' and not changed_cause:
                    self.assertEqual(len(guard_calls), 1)

    def test_two_exact_readback_errors_recover_after_confirmed_guard(self):
        for code in ('fleet_active_rules_or_tables_readback', 'fleet_active_postreadback'):
            with self.subTest(code=code), self.assertRaises(core.GateReadbackUnavailable) as cm:
                self.boundary(service.s.Refused(code))
            self.assertEqual(cm.exception.args, ('gate_readback_unavailable',))

    def test_unconfirmed_guard_never_maps_to_retry(self):
        for value in (False, None, 1):
            with self.subTest(value=value), self.assertRaises(service.runtime.ctl.Fault):
                self.boundary(service.s.Refused('fleet_active_rules_or_tables_readback'), confirmed=value)

    def test_unknown_actual_rules_or_tables_and_final_guard_failure_remain_hard(self):
        for code in ('anchor_changed_preserve_external', 'fleet_active_tables_external_change',
                     'closed_gate_unverified'):
            with self.subTest(code=code), self.assertRaises(service.s.Refused) as cm:
                self.boundary(service.s.Refused('fleet_active_rules_or_tables_readback'),
                              final_guard_error=service.s.Refused(code))
            self.assertEqual(cm.exception.args, (code,))

    def test_changed_wrapper_or_cause_never_maps_to_retry(self):
        for kwargs in ({'wrapper': 'cleanup_failed'}, {'changed_cause': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(service.runtime.ctl.Fault):
                self.boundary(service.s.Refused('fleet_active_rules_or_tables_readback'), **kwargs)

    def test_wrong_type_extra_arguments_and_unrelated_codes_stay_hard(self):
        class Derived(service.s.Refused): pass
        for error in (RuntimeError('fleet_active_rules_or_tables_readback'),
                      Derived('fleet_active_rules_or_tables_readback'),
                      service.s.Refused('fleet_active_rules_or_tables_readback', 'extra'),
                      service.s.Refused('fixed_command_failed'), service.s.Refused('fleet_existing_gate_unverified')):
            with self.subTest(error=repr(error)), self.assertRaises(service.runtime.ctl.Fault):
                self.boundary(error)

    def test_full_close_precedes_retry_and_existing_backoff_is_used(self):
        deps = Deps([core.GateReadbackUnavailable('gate_readback_unavailable'), None])
        store = self.run_case(deps)
        self.assertEqual(deps.calls, ['preflight', 'prepare', 'setup', 'serve', 'cleanup',
                                     'preflight', 'prepare', 'setup', 'serve', 'cleanup'])
        self.assertEqual((store.value['phase'], store.value['reason']), ('STOPPED', 'manual_stop'))
        self.assertTrue(any(x['phase'] == 'BACKOFF' and x['reason'] == 'gate_readback_unavailable'
                            for x in store.history))
        self.assertGreaterEqual(deps.now, 105)
        self.assertEqual(len(deps.failures), 1)

    def test_unverified_cleanup_prevents_retry(self):
        deps = Deps([core.GateReadbackUnavailable('gate_readback_unavailable')]); deps.clean = False
        store = self.run_case(deps)
        self.assertEqual((store.value['phase'], store.value['reason']), ('ATTENTION', 'recovery_not_proven'))
        self.assertEqual(deps.calls.count('serve'), 1)
        self.assertFalse(any(x['phase'] == 'BACKOFF' for x in store.history))

    def test_persistent_known_failure_waits_out_existing_budget_without_latch(self):
        deps = Deps([core.GateReadbackUnavailable('gate_readback_unavailable') for _ in range(4)] + [None])
        store = self.run_case(deps)
        self.assertEqual((store.value['phase'], store.value['reason']), ('STOPPED', 'manual_stop'))
        self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))
        self.assertEqual((deps.calls.count('serve'), deps.calls.count('cleanup')), (5, 5))
        self.assertGreaterEqual(deps.starts[3]-deps.starts[0], 900)
        for start in deps.starts:
            self.assertLessEqual(sum(0 <= start-earlier < 900 for earlier in deps.starts), 3)
        self.assertTrue(all(x['next_due'] <= x['updated']+60 for x in store.history))
        self.assertEqual((core.MAX_ATTEMPTS, core.RETRY_WINDOW, core.RETRY_DELAYS), (3, 900, (5, 15, 60)))

    def test_known_failure_cooldown_honors_manual_stop(self):
        deps = Deps([core.GateReadbackUnavailable('gate_readback_unavailable') for _ in range(3)])
        wait = deps.wait
        def stop_later(seconds):
            wait(seconds)
            if deps.now >= 200: deps.stop=True
        deps.wait = stop_later
        store=self.run_case(deps)
        self.assertEqual((store.value['phase'],store.value['reason']),('STOPPED','manual_stop'))
        self.assertEqual(deps.calls.count('serve'),3)

    def test_resume_known_cooldown_requires_fresh_recovery_and_keeps_budget(self):
        deps=Deps([None]);deps.now=200
        recovered=[]
        deps.recover=lambda expected_owner=False: recovered.append(expected_owner) or True
        store=Store()
        store.value=dict(version=1,phase='BACKOFF',boot='current-boot',fingerprint='a'*64,
                         attempts=[100,105,120],next_due=220,reason='gate_readback_unavailable',updated=180)
        self.assertEqual(core.Supervisor(deps,store,lambda:deps.now).run(),0)
        self.assertEqual(recovered,[False]);self.assertEqual(deps.starts,[1000])
        self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))

    def test_resume_cooldown_failed_recovery_cannot_retry(self):
        deps=Deps([None]);deps.now=200;deps.recover=lambda expected_owner=False: False
        store=Store()
        store.value=dict(version=1,phase='BACKOFF',boot='current-boot',fingerprint='a'*64,
                         attempts=[100,105,120],next_due=220,reason='gate_readback_unavailable',updated=180)
        self.assertEqual(core.Supervisor(deps,store,lambda:deps.now).run(),0)
        self.assertEqual((store.value['phase'],store.value['reason']),('ATTENTION','recovery_not_proven'))
        self.assertEqual(deps.starts,[])

    def test_resume_interrupted_known_recovery_with_full_budget_waits_without_latch(self):
        deps=Deps([None]);deps.now=200
        recovered=[]
        deps.recover=lambda expected_owner=False: recovered.append(expected_owner) or True
        store=Store()
        store.value=dict(version=1,phase='RECOVERING',boot='current-boot',fingerprint='a'*64,
                         attempts=[100,105,120],next_due=0,reason='gate_readback_unavailable',updated=180)
        self.assertEqual(core.Supervisor(deps,store,lambda:deps.now).run(),0)
        self.assertEqual(recovered,[True]);self.assertEqual(deps.starts,[1000])
        self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))
        self.assertTrue(any(x['phase']=='BACKOFF' and x['reason']=='gate_readback_unavailable'
                            for x in store.history))

    def test_other_known_transient_types_wait_out_existing_budget(self):
        deps=Deps([core.ViciUnavailable('vici_unavailable') for _ in range(3)]+[None])
        store=self.run_case(deps)
        self.assertEqual((store.value['phase'],store.value['reason']),('STOPPED','manual_stop'))
        self.assertFalse(any(x['phase']=='ATTENTION' for x in store.history))
        self.assertEqual(deps.calls.count('serve'),4)
        self.assertGreaterEqual(deps.starts[3]-deps.starts[0],900)

    def test_diagnostics_and_saved_state_accept_new_fixed_reason(self):
        error = core.GateReadbackUnavailable('gate_readback_unavailable')
        record = service.failure_record(error)
        self.assertEqual(record['errors'][0], {'type': 'GateReadbackUnavailable', 'code': 'gate_readback_unavailable'})
        service.valid_failure_record(json.dumps(record).encode())
        for code in ('fleet_active_rules_or_tables_readback', 'fleet_active_postreadback'):
            self.assertEqual(service.failure_record(service.s.Refused(code))['errors'][0]['code'], code)
        state = dict(version=1, phase='BACKOFF', boot='boot', fingerprint='a'*64,
                     attempts=[100], next_due=105, reason='gate_readback_unavailable', updated=100)
        self.assertEqual(core.valid_state(state), state)


if __name__ == '__main__':
    unittest.main(verbosity=2)
