"""Resident entry retry and reboot admission boundaries; no native effects."""
from contextlib import contextmanager, ExitStack
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'server/runtime'))
import boot_native
import native_quiescent
import production_boot
import production_source
import service_supervisor as service


class Stop:
    def __init__(self): self.value=False; self.waits=[]; self.on_wait=None
    def is_set(self): return self.value
    def set(self): self.value=True
    def wait(self, seconds):
        self.waits.append(seconds)
        if self.on_wait: self.on_wait()
        if len(self.waits)>8: raise AssertionError('unbounded fixture retry')
        return self.value


class EntryRecovery(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack(); self.addCleanup(self.stack.close)
        self.stop=Stop(); self.instances=[]; self.deps=SimpleNamespace(failure=Mock(),assert_held=None)
        self.p(service.runtime,'STOP',self.stop)
        self.p(service.sys,'argv',['service_supervisor.py'])
        self.p(service.os,'umask',Mock())
        self.p(service.signal,'signal',Mock())
        self.trusted=self.p(service.s,'trusted',Mock())
        self.p(service.s,'say',Mock())
        self.p(service,'make_clock',Mock(return_value=lambda:100.))
        self.p(service,'NativeDependencies',Mock(return_value=self.deps))
        instances=self.instances
        class Native:
            installed_scope=Mock()
            def __init__(self): self.writer=None;self.lease=False;instances.append(self)
            @contextmanager
            def locked(self):
                self.lease=True
                try:yield self
                finally:self.lease=False
            def held(self):
                if not self.lease:raise AssertionError('lock released early')
        self.p(boot_native,'Native',Native)
        self.recover=self.p(production_boot,'recover_locked',Mock())
        self.run=self.p(service,'run_locked',Mock(return_value=0))
    def p(self,obj,name,value):return self.stack.enter_context(patch.object(obj,name,value))

    def test_boot_failure_retries_with_fresh_native_and_keeps_dependencies(self):
        def recover(io,clock):
            io.held(); self.assertIsNone(io.writer);io.writer=object()
            if len(self.instances)==1:raise OSError('temporary boot write failure')
        self.recover.side_effect=recover
        self.assertEqual(service.main(),0)
        self.assertEqual(len(self.instances),2);self.assertEqual(self.stop.waits,[5])
        self.assertTrue(all(not io.lease for io in self.instances))
        self.run.assert_called_once();self.assertIs(self.run.call_args.args[0],self.deps)
        self.assertIsNone(self.deps.assert_held)

    def test_trust_read_failure_recovers_without_constructing_untrusted_owner(self):
        count=0
        def trusted(*args):
            nonlocal count
            count+=1
            if count==1:raise PermissionError('temporary unavailable path')
        self.trusted.side_effect=trusted
        self.assertEqual(service.main(),0);self.assertEqual(self.stop.waits,[5])
        self.assertEqual(len(self.instances),1);self.run.assert_called_once()

    def test_busy_recovery_lock_waits_and_manual_stop_exits(self):
        self.recover.side_effect=BlockingIOError()
        self.stop.on_wait=self.stop.set
        self.assertEqual(service.main(),0);self.run.assert_not_called()
        self.assertEqual(self.stop.waits,[5]);self.assertFalse(self.instances[0].lease)

    def test_optional_diagnostic_failure_cannot_stop_entry_retry(self):
        self.deps.failure.side_effect=OSError('log unavailable')
        self.p(service.s,'say',Mock(side_effect=BrokenPipeError()))
        self.recover.side_effect=[OSError('retry'),None]
        self.assertEqual(service.main(),0);self.assertEqual(len(self.instances),2)

    def test_escaped_core_exception_reuses_supervisor_and_owner(self):
        # Restore the real function while retaining the harmless dependencies.
        self.p(service,'run_locked',REAL_RUN_LOCKED)
        owner=object(); supervisor=SimpleNamespace(owner=owner,run=Mock(side_effect=[OSError(),0]),close=Mock())
        factory=self.p(service,'Supervisor',Mock(return_value=supervisor))
        self.assertEqual(service.run_locked(self.deps,lambda:100.),0)
        factory.assert_called_once();self.assertEqual(supervisor.run.call_count,2)
        self.assertIs(supervisor.owner,owner);supervisor.close.assert_not_called()

    def test_stop_after_escaped_failure_attempts_close_once_then_returns(self):
        self.p(service,'run_locked',REAL_RUN_LOCKED)
        supervisor=SimpleNamespace(run=Mock(side_effect=OSError()),close=Mock(side_effect=OSError()))
        self.p(service,'Supervisor',Mock(return_value=supervisor))
        self.stop.on_wait=self.stop.set
        self.assertEqual(service.run_locked(self.deps,lambda:100.),0)
        supervisor.close.assert_called_once();supervisor.run.assert_called_once()


REAL_RUN_LOCKED=service.run_locked


class ServiceAttentionBoot(unittest.TestCase):
    def fixture(self):
        encode=lambda value:json.dumps(value,sort_keys=True).encode()
        config=encode(dict(version=1,allow_data=True));supervisor=encode(dict(version=1,enabled=True))
        fp=production_source.digest(supervisor+b'\0'+config)
        state=dict(version=1,phase='ATTENTION',boot='old-boot',fingerprint=fp,attempts=[1],next_due=0,
                   reason='unknown_failure',updated=2)
        raw_intent=b'fixture-intent'
        files={'intent':raw_intent,'service-state':encode(state),'native-config':config,'supervisor-config':supervisor}
        mark=dict(run_id='a'*32,intent_sha256=production_source.digest(raw_intent))
        intent=dict(run='a'*32,boot='old-boot',configuration_sha256=fp)
        return files,mark,intent

    def test_service_attention_keeps_all_source_and_permission_bindings(self):
        files,mark,intent=self.fixture()
        with patch.object(production_source,'marker',return_value=mark), \
             patch.object(production_source,'unpack',return_value=files), \
             patch.object(production_source,'intent',return_value=intent), \
             patch.object(production_source.s,'json_value',side_effect=lambda b:intent if b==b'fixture-intent' else json.loads(b)):
            result=production_source.validate({'boot':'old-boot'},b'context')
            self.assertEqual(result['boot'],'old-boot')
            with self.assertRaises(production_source.Refused):
                production_source.validate({'boot':'different'},b'context')
            files['supervisor-config']=json.dumps(dict(version=1,enabled=False)).encode()
            with self.assertRaises(production_source.Refused):
                production_source.validate({'boot':'old-boot'},b'context')

    def test_retirement_requires_completed_native_readback_before_old_attention(self):
        files,_,_=self.fixture(); io=Mock();store=Mock();record={}
        class ReachedRecordRead(Exception):pass
        with patch.object(production_boot,'closed_readback',side_effect=OSError('not restored')), \
             patch.object(production_boot.s,'read') as read:
            with self.assertRaises(OSError):production_boot.finish(io,store,record,lambda:1.)
            read.assert_not_called();store.write_new.assert_not_called()
        with patch.object(production_boot,'closed_readback',return_value=(b'old',b'context')), \
             patch.object(production_boot.production,'unpack',return_value=files), \
             patch.object(production_boot.s,'read',side_effect=ReachedRecordRead):
            with self.assertRaises(ReachedRecordRead):production_boot.finish(io,store,record,lambda:1.)
            store.write_new.assert_not_called()


class MissingJournalRecovery(unittest.TestCase):
    def test_missing_journal_requires_complete_fresh_native_baseline(self):
        deps=service.NativeDependencies(lambda:1.);deps.store=Mock();deps.store.load.return_value=None
        deps.assert_held=Mock(return_value=None);old_mutator=object()
        with patch.object(service.s,'boot',return_value='current'), \
             patch.object(service.s,'MUTATOR',old_mutator), \
             patch.object(native_quiescent,'verify') as verify:
            def read_only(callback):
                self.assertIsNone(service.s.MUTATOR);self.assertIs(callback,deps.assert_held)
                return {'boot':'current'}
            verify.side_effect=read_only
            self.assertTrue(deps.recover(expected_owner=True))
            self.assertIs(service.s.MUTATOR,old_mutator);deps.store.save.assert_not_called()
            verify.side_effect=OSError('native residue or read failure')
            with self.assertRaises(OSError):deps.recover()
            self.assertIs(service.s.MUTATOR,old_mutator);deps.store.save.assert_not_called()

    def test_journal_or_boot_change_during_empty_baseline_rejects_resume(self):
        for journal,boot in (({'active':True},'current'),(None,'changed')):
            with self.subTest(journal=journal,boot=boot):
                deps=service.NativeDependencies(lambda:1.);deps.store=Mock()
                deps.store.load.side_effect=[None,journal];deps.assert_held=lambda:None
                with patch.object(service.s,'boot',side_effect=['current',boot]), \
                     patch.object(native_quiescent,'verify',return_value={'boot':'current'}):
                    with self.assertRaises(service.Attention):deps.recover()
                    deps.store.save.assert_not_called()


if __name__=='__main__':unittest.main()
