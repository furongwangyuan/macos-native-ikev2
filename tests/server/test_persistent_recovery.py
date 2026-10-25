"""Persistent recovery preserves native ownership, durable state and start limits."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2] / 'server/runtime'
sys.path.insert(0, str(ROOT))
import supervisor_core as core


class Exhausted(BaseException): pass


class Store:
    def __init__(self):
        self.value = None; self.history = []; self.before_load = lambda: None
        self.before_save = lambda value: None
    def load(self):
        self.before_load(); return copy.deepcopy(self.value)
    def save(self, value):
        self.before_save(value)
        self.value = copy.deepcopy(value); self.history.append(copy.deepcopy(value))


class Deps:
    def __init__(self, outcomes=(None,)):
        self.outcomes = list(outcomes); self.now = 100.; self.stop = False
        self.config = core.Configuration(True, 'a'*64); self.calls = []; self.starts = []
        self.owners = []; self.cleaned = []; self.pending = False; self.failures = []
        self.cleanup_results = []; self.recover_results = []; self.wait_hook = lambda: None
    def configuration(self): return self.config
    def boot(self): return 'current-boot'
    def authorize(self, config): self.calls.append('authorize')
    def recover(self, expected_owner=False):
        self.calls.append('recover')
        result = self.recover_results.pop(0) if self.recover_results else True
        if isinstance(result, Exception): raise result
        if result is True: self.pending = False
        return result
    def preflight(self): self.calls.append('preflight'); return {}
    def prepare(self, session):
        if self.pending: raise Exhausted('new owner before prior native recovery')
        self.calls.append('prepare'); self.starts.append(self.now); self.pending = True
        owner = object(); self.owners.append(owner); return owner
    def setup(self, owner): self.calls.append('setup')
    def serve(self, owner):
        self.calls.append('serve')
        if not self.outcomes: raise Exhausted('unexpected extra serve')
        outcome = self.outcomes.pop(0)
        if outcome is None: self.stop = True; return
        raise outcome
    def cleanup(self, owner):
        self.calls.append('cleanup'); self.cleaned.append(owner)
        result = self.cleanup_results.pop(0) if self.cleanup_results else True
        if isinstance(result, Exception): raise result
        if result is True: self.pending = False
        return result
    def wait(self, seconds):
        self.now += seconds
        if self.now > 2200: raise Exhausted('bounded test exceeded')
        self.wait_hook()
    def stopped(self): return self.stop
    def event(self, *args): pass
    def failure(self, error): self.failures.append(error)


def state(phase='ATTENTION', reason='unknown_failure', attempts=None, boot='current-boot'):
    return dict(version=1, phase=phase, reason=reason, boot=boot, fingerprint='a'*64,
                attempts=[] if attempts is None else attempts, next_due=0, updated=100.)


class PersistentRecovery(unittest.TestCase):
    def run_case(self, deps=None, store=None):
        d = deps or Deps(); s = store or Store(); owner = core.Supervisor(d,s,lambda:d.now)
        self.assertEqual(owner.run(),0)
        return d,s,owner

    def test_unknown_serve_error_recovers_then_freshly_authorizes(self):
        d,s,_ = self.run_case(Deps([ValueError('unclassified'), None]))
        self.assertEqual(len(d.starts),2)
        self.assertGreaterEqual(d.starts[1]-d.starts[0],5)
        self.assertEqual(d.calls.count('authorize'),2)
        self.assertTrue(any(x['reason']=='unknown_failure' for x in s.history))
        self.assertEqual(s.value['reason'],'manual_stop')

    def test_preexisting_attention_is_recovered_not_latched(self):
        s=Store();s.value=state(attempts=[90]);d,s,_=self.run_case(store=s)
        self.assertEqual(d.calls[:2],['recover','authorize'])
        self.assertEqual(next(x['attempts'] for x in s.history if x['phase']=='STARTING'),[90,100])

    def test_cleanup_false_or_exception_keeps_exact_owner_until_true(self):
        for results in ([False,False,True],[OSError('busy'),False,True]):
            with self.subTest(results=results):
                d=Deps([ValueError('unknown'),None]);d.cleanup_results=list(results)
                d,s,supervisor=self.run_case(d)
                self.assertEqual(d.cleaned[:3],[d.owners[0]]*3)
                self.assertIsNone(supervisor.owner)
                self.assertEqual(len(d.starts),2)
                self.assertGreaterEqual(d.starts[1],110)

    def test_prepare_exception_recovers_journal_without_owner_handle(self):
        d=Deps();prepare=d.prepare;failed=[False]
        def once(session):
            if not failed[0]:
                failed[0]=True;d.pending=True;d.calls.append('prepare_failed')
                raise OSError('after native journal commit')
            return prepare(session)
        d.prepare=once;self.run_case(d)
        start=d.calls.index('prepare_failed');end=d.calls.index('prepare')
        self.assertIn('recover',d.calls[start+1:end]);self.assertEqual(len(d.starts),1)

    def test_recovery_false_or_exception_cannot_prepare_until_verified(self):
        d=Deps();d.recover_results=[False,OSError('busy'),True]
        self.run_case(d)
        self.assertEqual(d.calls[:3],['recover']*3);self.assertEqual(d.starts,[110])

    def test_unreadable_or_invalid_saved_state_never_becomes_initial(self):
        for broken in ('unreadable','invalid'):
            with self.subTest(broken=broken):
                s=Store();s.value=state(attempts=[90]);saved=copy.deepcopy(s.value);d=Deps()
                if broken=='unreadable':
                    def load():
                        if d.now<105: raise OSError('unreadable')
                    s.before_load=load
                else:s.value={'invalid':True}
                def restore():
                    self.assertEqual(s.history,[])
                    if d.now>=105:s.value=copy.deepcopy(saved)
                d.wait_hook=restore;self.run_case(d,s)
                self.assertEqual(d.starts,[105]);self.assertIn(90,s.history[1]['attempts'])

    def test_missing_seen_state_cannot_reset_start_budget(self):
        d=Deps([ValueError('one'),ValueError('two'),ValueError('three'),None]);s=Store()
        held=[None];removed=[False]
        def disappear():
            if len(d.starts)==3 and not removed[0]:
                held[0]=copy.deepcopy(s.value);s.value=None;removed[0]=True
            if removed[0] and d.now<1000:
                self.assertIsNone(s.value)
                self.assertEqual(len(d.starts),3)
            if removed[0] and d.now>=1000 and s.value is None:s.value=held[0]
        d.wait_hook=disappear;self.run_case(d,s)
        self.assertGreaterEqual(d.starts[3],1000)
        self.assertTrue(any(str(x)=='service_state_disappeared' for x in d.failures))

    def test_first_config_unreadable_never_creates_zero_fingerprint(self):
        d=Deps();s=Store()
        def config():
            if d.now<105:raise OSError('config temporarily unreadable')
            return d.config
        d.configuration=config
        d.wait_hook=lambda:self.assertEqual(s.history,[]) if d.now<=105 else None
        self.run_case(d,s)
        self.assertEqual(d.starts,[105]);self.assertTrue(all(x['fingerprint']=='a'*64 for x in s.history))

    def test_boot_read_failure_recovers_without_creating_saved_state(self):
        d=Deps();s=Store()
        def boot():
            if d.now<105:raise OSError('boot unavailable')
            return 'current-boot'
        d.boot=boot;self.run_case(d,s);self.assertEqual(d.starts,[105])

    def test_source_authorization_waits_for_external_repair(self):
        d=Deps()
        def authorize(config):
            d.calls.append('authorize')
            if d.now<115:raise ValueError('source mismatch')
        d.authorize=authorize;d,s,_=self.run_case(d)
        self.assertEqual(d.starts,[115]);self.assertEqual(d.config.fingerprint,'a'*64)
        self.assertTrue(any(x['reason']=='activation_not_accepted' for x in s.history))

    def test_changed_configuration_waits_for_original_without_rewriting_it(self):
        d=Deps();s=Store();s.value=state();d.config=core.Configuration(True,'b'*64)
        def restore():
            if d.now>=115:d.config=core.Configuration(True,'a'*64)
        d.wait_hook=restore;self.run_case(d,s)
        self.assertEqual(d.starts,[115]);self.assertTrue(all(x['fingerprint']=='a'*64 for x in s.history))

    def test_durable_write_failures_require_recovery_before_next_owner(self):
        for phase in ('PREFLIGHT','STARTING','RUNNING','ATTENTION','STOPPED'):
            with self.subTest(phase=phase):
                d=Deps([ValueError('one'),None] if phase=='ATTENTION' else [None]);s=Store();failed=[False]
                def save(value):
                    if value['phase']==phase and not failed[0]:
                        failed[0]=True;d.calls.append('save_failed');raise OSError('store temporarily unavailable')
                s.before_save=save;self.run_case(d,s)
                self.assertTrue(failed[0]);pos=d.calls.index('save_failed')
                after=d.calls[pos+1:]
                if 'prepare' in after:
                    self.assertTrue(any(x in ('cleanup','recover') for x in after[:after.index('prepare')]))
                self.assertFalse(d.pending)

    def test_unknown_failures_keep_three_starts_per_900_seconds(self):
        d,s,_=self.run_case(Deps([ValueError('unknown')]*4+[None]))
        self.assertEqual(d.starts[:4],[100,105,120,1000])
        for at in d.starts:self.assertLessEqual(sum(0<=at-other<900 for other in d.starts),3)
        self.assertTrue(any(x['reason']=='retry_budget_exhausted' for x in s.history))

    def test_stop_or_disable_during_unproven_cleanup_does_not_start_again(self):
        for result in (False,OSError('cleanup failed')):
            for stop in ('signal','disable'):
                with self.subTest(result=result,stop=stop):
                    d=Deps([ValueError('unknown')]);d.cleanup_results=[result]*10
                    def finish():
                        if stop=='signal':d.stop=True
                        else:d.config=core.Configuration(False,'a'*64)
                    d.wait_hook=finish;d,s,supervisor=self.run_case(d)
                    self.assertEqual(len(d.starts),1);self.assertIs(supervisor.owner,d.owners[0])
                    self.assertNotIn(s.value['phase'],('STOPPED','DISABLED'))

    def test_wait_failure_keeps_instance_and_owner_for_entry_fallback(self):
        d=Deps([ValueError('one'),None]);d.cleanup_results=[False,True];wait=d.wait;failed=[False]
        def flaky(seconds):
            if not failed[0]:failed[0]=True;raise OSError('wait hook')
            wait(seconds)
        d.wait=flaky;s=Store();supervisor=core.Supervisor(d,s,lambda:d.now)
        with self.assertRaises(OSError):supervisor.run()
        self.assertIs(supervisor.owner,d.owners[0])
        # Entry performs an independent STOP.wait, then reuses this same object.
        d.now+=5;self.assertEqual(supervisor.run(),0)
        self.assertEqual(d.cleaned[:2],[d.owners[0]]*2);self.assertEqual(len(d.starts),2)

    def test_cross_boot_unknown_owner_waits_without_reusing_monotonic_budget(self):
        d=Deps([]);s=Store();s.value=state(boot='prior-boot',attempts=[90])
        d.wait_hook=lambda:setattr(d,'stop',True)
        self.run_case(d,s)
        self.assertEqual(d.starts,[]);self.assertEqual(s.value['boot'],'prior-boot')
        self.assertEqual(s.value['attempts'],[90]);self.assertEqual(s.value['reason'],'cross_boot_unfinished')


if __name__=='__main__':unittest.main(verbosity=2)
