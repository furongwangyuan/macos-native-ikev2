#!/usr/bin/python3
"""Ordinary-user mocks/temp files only; no launchctl, root, credentials or network."""
import contextlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

if os.geteuid()==0:raise SystemExit('Run offline as ordinary user.')
HERE=Path(__file__).resolve().parent


def load():
    return runpy.run_path(str(HERE/'control-root.py'),run_name='offline_watch')['main'].__globals__


def status(start=100,finish=100,outcome='scheduled'):
    return dict(version=1,last_started=start,last_finished=finish,next_due=finish+300,
        failures=0 if outcome in ('success','scheduled') else 1,outcome=outcome)


class Clock:
    def __init__(self):self.now=0
    def monotonic(self):return self.now
    def sleep(self,seconds):
        assert 0<=seconds<=5
        self.now+=seconds


@contextlib.contextmanager
def watch_tree(sequence):
    g=load();_,lib=g['resources'](HERE);clock=Clock();events=[];reads=[];jobs=[]
    samples=iter(sequence);last=[None]
    with tempfile.TemporaryDirectory() as tmp:
        g['STATE']=Path(tmp)
        def sample(*args):
            try:last[0]=next(samples)
            except StopIteration:pass
            reads.append(clock.now)
            if isinstance(last[0],Exception):raise last[0]
            return lib['validate_status'](last[0])
        def job(timeout=6):
            jobs.append((clock.now,timeout));assert 0<timeout<=6
            return dict(state='not running',runs=2,last_exit_code=0)
        g.update(watch_status=sample,job=job,say=lambda event,**fields:events.append((event,fields)))
        # Any accidental command outside the exact read-only job stub fails.
        g['run']=lambda *a,**kw:(_ for _ in ()).throw(AssertionError('Unexpected command'))
        with patch.object(g['time'],'monotonic',clock.monotonic),patch.object(g['time'],'sleep',clock.sleep):
            yield g,lib,clock,events,reads,jobs


class WatchTests(unittest.TestCase):
    def test_scheduled_running_success_is_new_actual_completion(self):
        with watch_tree([status(),status(400,400,'running'),status(400,410,'success')]) as (g,lib,c,e,r,j):
            self.assertEqual(g['watch'](lib),0)
            self.assertEqual([x[0] for x in e],['watch_initial','watch_check','watch_check','watch_final'])
            self.assertEqual(e[-1][1]['result'],'success');self.assertEqual(c.now,10)
            self.assertTrue(e[-1][1]['helper_not_invoked_by_watcher'])

    def test_stale_success_and_not_due_never_count_as_new_run(self):
        with watch_tree([status(90,100,'success')]) as (g,lib,c,e,r,j):
            self.assertEqual(g['watch'](lib),2)
            self.assertEqual(c.now,480);self.assertEqual(e[-1][1]['result'],'inconclusive')
            self.assertEqual(e[-1][1]['code'],'no_new_completed_run_before_deadline')
            self.assertTrue(all(x[1]['job_last_exit_code']==0 for x in e if x[0]=='watch_check'))
            self.assertLessEqual(len(e),10)

    def test_preexisting_running_accepts_its_later_completion(self):
        with watch_tree([status(80,80,'running'),status(80,105,'success')]) as (g,lib,c,e,r,j):
            self.assertEqual(g['watch'](lib),0)

    def test_actual_failure_timeout_interrupted_are_failed_not_dns_detail(self):
        for outcome in ('failed','timeout','interrupted'):
            with self.subTest(outcome=outcome),watch_tree([status(),status(400,410,outcome)]) as (g,lib,c,e,r,j):
                self.assertEqual(g['watch'](lib),1)
                self.assertEqual(e[-1][1]['result'],'failed')
                self.assertEqual(e[-1][1]['status']['outcome'],outcome)

    def test_unknown_status_has_only_fixed_sanitized_failure(self):
        private='private-provider-value-not-for-log'
        with watch_tree([status(),status(outcome=private)]) as (g,lib,c,e,r,j):
            self.assertEqual(g['watch'](lib),2)
            self.assertEqual(e[-1][1]['code'],'read_only_metadata_unavailable')
            self.assertNotIn(private,json.dumps(e))

    def test_removed_or_unqueryable_job_does_not_confirm_success(self):
        for value in (None,ValueError('raw-launchctl-not-for-log')):
            with watch_tree([status(),status(400,410,'success')]) as (g,lib,c,e,r,j):
                original=g['job'];calls=[0]
                def job(timeout=6):
                    calls[0]+=1
                    if calls[0]==1:return original(timeout)
                    if isinstance(value,Exception):raise value
                    return value
                g['job']=job
                self.assertEqual(g['watch'](lib),2)
                self.assertNotIn('raw-launchctl',json.dumps(e))

    def test_late_job_query_cannot_report_success_past_deadline(self):
        with watch_tree([status(),status(400,410,'success')]) as (g,lib,c,e,r,j):
            original=g['job'];calls=[0]
            def job(timeout=6):
                calls[0]+=1;result=original(timeout)
                if calls[0]==2:c.now=481
                return result
            g['job']=job
            self.assertEqual(g['watch'](lib),2)
            self.assertEqual(e[-1][1]['result'],'inconclusive')

    def test_cancel_is_read_only_and_keeps_installed_job(self):
        with watch_tree([status()]) as (g,lib,c,e,r,j):
            def cancel(_):raise KeyboardInterrupt()
            with patch.object(g['time'],'sleep',cancel):self.assertEqual(g['watch'](lib),2)
            self.assertEqual(e[-1][1]['code'],'observation_cancelled')
            self.assertTrue(e[-1][1]['scheduler_kept_installed'])

    def test_real_status_parser_anchor_schema_and_no_writes(self):
        g=load();_,lib=g['resources'](HERE)
        with tempfile.TemporaryDirectory() as tmp:
            g['STATE']=Path(tmp);p=g['STATE']/'status.json';p.write_text(json.dumps(status()));p.chmod(0o600)
            before=(p.stat().st_ino,p.read_bytes());anchor=g['directory_identity'](g['STATE'])
            original=g['raw_read'];calls=[]
            def read(path,**kw):
                calls.append(kw);return original(path,limit=kw['limit']) # ordinary-user fixture only
            g['raw_read']=read
            self.assertEqual(g['watch_status'](lib,anchor),status())
            self.assertEqual(calls,[dict(root_metadata=True,limit=4096)])
            self.assertEqual(before,(p.stat().st_ino,p.read_bytes()))
            with self.assertRaises(g['Failure']):g['watch_status'](lib,('changed',))
            p.write_text('{"version":1,"version":1}')
            with self.assertRaises(g['Failure']):g['watch_status'](lib,anchor)

    def test_status_rejects_nonroot_symlink_hardlink_fifo_and_size(self):
        g=load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/'status';p.write_text('{}');p.chmod(0o600)
            with self.assertRaises(g['Failure']):g['raw_read'](p,root_metadata=True,limit=4096)
            link=root/'sym';link.symlink_to(p)
            with self.assertRaises(g['Failure']):g['raw_read'](link)
            link.unlink();os.link(p,link)
            with self.assertRaises(g['Failure']):g['raw_read'](p)
            link.unlink();p.write_bytes(b'x'*4097)
            with self.assertRaises(g['Failure']):g['raw_read'](p,limit=4096)
            fifo=root/'fifo';os.mkfifo(fifo)
            with self.assertRaises(g['Failure']):g['raw_read'](fifo)

    def test_install_and_watch_releases_installer_lock_before_observing(self):
        g=load();held=[];calls=[]
        @contextlib.contextmanager
        def locked(*a,**k):
            held.append(True)
            try:yield
            finally:held.pop()
        lib=dict(trusted=lambda *a,**k:None,locked_path=locked)
        g.update(resources=lambda _:({},lib),helper_gate=lambda _:None,disabled_gate=lambda:None,
            ensure_directory=lambda *a:None,install=lambda *a:calls.append(('install',bool(held))))
        def watch(_):calls.append(('watch',bool(held)));return 2
        g['watch']=watch
        with patch.object(g['os'],'geteuid',return_value=0),patch.object(g['os'],'umask'),patch.object(g['sys'],'argv',['fixed','install-and-watch',str(HERE)]):
            self.assertEqual(g['main'](),2)
        self.assertEqual(calls,[('install',True),('watch',False)])


if __name__=='__main__':unittest.main(verbosity=2)
