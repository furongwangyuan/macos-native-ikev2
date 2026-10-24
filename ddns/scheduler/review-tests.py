#!/usr/bin/python3
"""Offline only: synthetic metadata and fake child processes; never sudo/network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

if os.geteuid() == 0:
    raise SystemExit('Run only as ordinary user.')
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate', HERE / 'scheduler.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


class Schedule(unittest.TestCase):
    def test_first_tick_only_schedules(self):
        saved = []
        self.assertEqual(s.tick(None, now=lambda:1000, jitter=lambda:30,
            save=saved.append, execute=lambda:self.fail('unexpected update')), 'scheduled')
        self.assertEqual(saved[0]['next_due'], 1330)
        self.assertEqual(saved[0]['failures'], 0)

    def test_not_due_does_not_execute_or_write(self):
        previous = s.record(1000,0,'scheduled')
        self.assertEqual(s.tick(previous, now=lambda:1200,
            save=lambda _:self.fail('unexpected write'),
            execute=lambda:self.fail('unexpected update')), 'not_due')

    def test_success_write_ahead_and_reset_backoff(self):
        saved=[]
        def execute():
            self.assertEqual(saved[-1]['outcome'],'running')
            self.assertEqual(saved[-1]['failures'],5)
            return 'success'
        prior=s.record(1000,5,'failed')
        times=iter([5000,5010])
        self.assertEqual(s.tick(prior,now=lambda:next(times),jitter=lambda:12,
            save=saved.append,execute=execute),'success')
        self.assertEqual(saved[-1],s.record(5010,0,'success',started=5000,jitter=12))

    def test_failure_backoff_caps_and_crash_record_is_persisted(self):
        prior=s.record(1000,0,'scheduled')
        for expected,period in [(1,300),(2,600),(3,1200),(4,2400),(5,3600),(5,3600)]:
            moment=prior['next_due'];saved=[]
            self.assertEqual(s.tick(prior,now=lambda:moment,jitter=lambda:0,
                save=saved.append,execute=lambda:'failed'),'failed')
            self.assertEqual(saved[0]['outcome'],'running')
            self.assertEqual(saved[0]['next_due'],moment+period)
            self.assertEqual(saved[-1]['failures'],expected)
            prior=saved[-1]

    def test_interruption_never_looks_successful(self):
        prior=s.record(1000,0,'scheduled');saved=[]
        def interrupted():raise s.Stopped()
        with self.assertRaises(s.Stopped):
            s.tick(prior,now=lambda:1400,jitter=lambda:0,save=saved.append,execute=interrupted)
        self.assertEqual(saved[-1]['outcome'],'interrupted')
        self.assertEqual(saved[-1]['next_due'],1700)

    def test_timeout_and_unknown_exception_safe(self):
        for operation,expected in [(lambda:'timeout','timeout'),
            (lambda:(_ for _ in ()).throw(ValueError('synthetic-private-text')),'failed')]:
            saved=[]
            self.assertEqual(s.tick(s.record(1000,0,'scheduled'),now=lambda:1400,
                jitter=lambda:0,save=saved.append,execute=operation),expected)
            self.assertNotIn('synthetic-private-text',json.dumps(saved))

    def test_clock_rollback_reschedules_and_forward_jump_runs_once(self):
        prior=s.record(2000,3,'failed');saved=[]
        self.assertEqual(s.tick(prior,now=lambda:1000,jitter=lambda:0,
            save=saved.append,execute=lambda:self.fail('unexpected update')),'clock_reset')
        calls=[]
        s.tick(saved[-1],now=lambda:100000,jitter=lambda:0,save=saved.append,
            execute=lambda:calls.append(1) or 'success')
        self.assertEqual(calls,[1])

    def test_bad_status_and_inputs_fail_before_update(self):
        good=s.record(1000,0,'scheduled')
        for field,value in [('version',True),('failures',True),('failures',6),
            ('next_due',float('inf')),('next_due',99999),('outcome','secret'),
            ('last_started',-1)]:
            bad=dict(good,**{field:value})
            with self.assertRaises(s.Failure):s.tick(bad,now=lambda:100000,
                execute=lambda:self.fail('unexpected update'))
        for failures,jitter in [(6,0),(0,31),(True,1),(1,-1)]:
            with self.assertRaises(s.Failure):s.delay(failures,jitter)


class ProcessAndFiles(unittest.TestCase):
    def test_child_scope_and_no_raw_output(self):
        child=MagicMock();child.wait.return_value=0;child.poll.return_value=0
        with patch.object(s.subprocess,'Popen',return_value=child) as pop:
            self.assertEqual(s.execute_helper(),'success')
        args,kw=pop.call_args
        self.assertEqual(args[0],['/usr/bin/python3','-I',str(s.HELPER),'update'])
        for stream in ['stdin','stdout','stderr']:self.assertEqual(kw[stream],subprocess.DEVNULL)
        self.assertFalse(kw['start_new_session']);self.assertTrue(kw['close_fds'])
        self.assertEqual(kw['env'],s.ENV);child.wait.assert_called_once_with(timeout=140)

    def test_timeout_stops_direct_child_with_bounded_kill_fallback(self):
        child=MagicMock();child.poll.return_value=None
        child.wait.side_effect=[subprocess.TimeoutExpired('fixed',140),
            subprocess.TimeoutExpired('fixed',3),-9]
        with patch.object(s.subprocess,'Popen',return_value=child):
            self.assertEqual(s.execute_helper(),'timeout')
        child.terminate.assert_called_once();child.kill.assert_called_once()
        self.assertEqual([x.kwargs['timeout'] for x in child.wait.call_args_list],[140,3,3])

    def test_signal_interruption_cleans_direct_child(self):
        child=MagicMock();child.poll.return_value=None;child.wait.side_effect=[s.Stopped(),-15]
        with patch.object(s.subprocess,'Popen',return_value=child):
            with self.assertRaises(s.Stopped):s.execute_helper()
        child.terminate.assert_called_once();child.kill.assert_not_called()

    def test_real_lock_and_atomic_metadata_in_unprivileged_temp(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(s,'trusted'):
            root=Path(tmp);lock=root/'lock'
            with s.locked_path(lock,create=True):
                with self.assertRaises(BlockingIOError):
                    with s.locked_path(lock):self.fail('duplicate owner')
            with patch.object(s,'STATE',root):
                expected=s.record(1000,0,'success')
                s.atomic_status(expected)
                self.assertEqual(s.load_status(),expected)
                self.assertEqual((root/'status.json').stat().st_mode&0o777,0o600)
                (root/'status.json').write_text('{"version":1,"version":1}')
                with self.assertRaises(s.Failure):s.load_status()

    def test_helper_pin_and_plist_contract(self):
        source=HERE.parent/'helper/update.py'
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),s.HELPER_SHA)
        p=plistlib.loads((HERE/'org.familyvpn.ddns.plist').read_bytes())
        self.assertEqual(p['ProgramArguments'],['/usr/bin/python3','-I',str(s.BASE/'scheduler.py')])
        self.assertEqual(p['Label'],'org.familyvpn.ddns');self.assertEqual(p['UserName'],'root')
        self.assertEqual(p['Umask'],0o077);self.assertEqual(p['StartInterval'],60)
        self.assertFalse(p['AbandonProcessGroup']);self.assertTrue(p['RunAtLoad'])
        self.assertEqual(p['ExitTimeOut'],10)
        for name in ['KeepAlive','Disabled','WatchPaths','StartCalendarInterval']:self.assertNotIn(name,p)
        for name in ['StandardInPath','StandardOutPath','StandardErrorPath']:self.assertEqual(p[name],'/dev/null')


if __name__=='__main__':unittest.main(verbosity=2)
