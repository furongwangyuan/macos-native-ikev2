#!/usr/bin/python3
"""Ordinary-user temp trees and mocks only. No real launchctl/root/API/credentials."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if os.geteuid()==0:raise SystemExit('Run offline as ordinary user.')
HERE=Path(__file__).resolve().parent


def load():
    value=runpy.run_path(str(HERE/'control-root.py'),run_name='offline_review')
    return value['main'].__globals__


@contextlib.contextmanager
def tree():
    g=load();content,lib=g['resources'](HERE)
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);base=root/'code';state=root/'state';plist=root/'LaunchDaemons'/'org.familyvpn.ddns.plist'
        helper=root/'helper'/'update.py';helperstate=root/'helper-state'
        for p in [base,state,plist.parent,helper.parent,helperstate]:p.mkdir(mode=0o700)
        for p in [helper.parent/'.installer.lock',helperstate/'lock']:
            p.write_bytes(b'');p.chmod(0o600)
        g.update(BASE=base,STATE=state,PLIST=plist,HELPER_STATE=helperstate)
        lib.update(BASE=base,STATE=state,HELPER=helper,trusted=lambda *a,**k:None)
        calls=[];loaded=[None]
        g.update(helper_gate=lambda _:calls.append('helper-metadata-pin'),disabled_gate=lambda:None,
            job=lambda:loaded[0],group_absent=lambda groups:True,say=lambda event,**kw:calls.append((event,kw)))
        def command(args,timeout=6):
            calls.append(tuple(args))
            if args[:3]==['/bin/launchctl','bootstrap','system']:
                loaded[0]={'loaded':True,'pid':None,'state':'not running','last_exit_code':None}
            elif args==['/bin/launchctl','bootout',g['TARGET']]:loaded[0]=None
            else:raise AssertionError('Unmocked command')
            return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        g['run']=command
        yield g,lib,content,calls,loaded


class Packaging(unittest.TestCase):
    def test_all_pins_and_launchers_no_secret_input(self):
        manifest=json.loads((HERE/'package-digests.json').read_text())
        self.assertEqual(len(manifest),7)
        for name,digest in manifest.items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest,name)
            if name.endswith('.command'):
                text=(HERE/name).read_text()
                self.assertIn(manifest['control-root.py'],text)
                self.assertIn('</dev/null',text);self.assertNotIn('getpass',text)
                self.assertIn('result=${PIPESTATUS[0]}',text)
                self.assertEqual(subprocess.run(['/bin/bash','-n',str(HERE/name)]).returncode,0)
        g=load()
        self.assertEqual(g['EXPECTED'],{k:v for k,v in manifest.items() if k in ('scheduler.py','org.familyvpn.ddns.plist')})

    def test_live_style_launchctl_layout_and_unknown_rejected(self):
        g=load();text='''system/org.familyvpn.ddns = {
\tactive count = 0
\tpath = /Library/LaunchDaemons/org.familyvpn.ddns.plist
\ttype = LaunchDaemon
\tstate = not running
\tprogram = /usr/bin/python3
\targuments = {
\t\t/usr/bin/python3
\t\t-I
\t\t/usr/local/family-vpn/ddns-production/scheduler.py
\t}
\tdomain = system
\tlast exit code = 0
}
'''
        result=SimpleNamespace(returncode=0,stdout=text.encode(),stderr=b'')
        self.assertEqual(g['parse_job'](result)['last_exit_code'],0)
        for raw in [text.replace('scheduler.py','other.py'),text.replace('domain = system','domain = user'),
                    text.replace('\tprogram =','\tprogram = /evil\n\tprogram =')]:
            with self.assertRaises(g['Failure']):g['parse_job'](SimpleNamespace(returncode=0,stdout=raw.encode(),stderr=b''))
        absent=b'Bad request.\nCould not find service "org.familyvpn.ddns" in domain for system\n'
        self.assertIsNone(g['parse_job'](SimpleNamespace(returncode=113,stdout=b'',stderr=absent)))
        with self.assertRaises(g['Failure']):g['parse_job'](SimpleNamespace(returncode=5,stdout=b'',stderr=b'unknown'))

    def test_install_is_write_ahead_delayed_and_idempotent(self):
        with tree() as (g,lib,content,calls,loaded):
            original=g['run']
            def command(args,timeout=6):
                if 'bootstrap' in args:
                    self.assertEqual(g['read_journal'](lib)['phase'],'bootstrap-intent')
                    status=lib['load_status']()
                    self.assertEqual(status['outcome'],'scheduled')
                    self.assertGreaterEqual(status['next_due']-status['last_finished'],300)
                    self.assertEqual(g['PLIST'].stat().st_mode&0o777,0o644)
                return original(args,timeout)
            g['run']=command
            g['install'](lib,content)
            self.assertEqual(g['read_journal'](lib)['phase'],'installed')
            self.assertEqual((g['BASE']/'scheduler.py').stat().st_mode&0o777,0o600)
            first=(g['BASE']/'scheduler.py').stat().st_ino
            g['install'](lib,content)
            self.assertEqual(first,(g['BASE']/'scheduler.py').stat().st_ino)
            self.assertEqual(sum(isinstance(x,tuple) and 'bootstrap' in x for x in calls),1)

    def test_ambiguous_bootstrap_failure_keeps_intent_then_converges(self):
        with tree() as (g,lib,content,calls,loaded):
            original=g['run']
            g['run']=lambda *a,**k:(_ for _ in ()).throw(subprocess.TimeoutExpired('fixed',12))
            with self.assertRaises(g['Failure']):g['install'](lib,content)
            self.assertEqual(g['read_journal'](lib)['phase'],'bootstrap-intent')
            self.assertTrue(g['PLIST'].exists())
            g['run']=original;g['install'](lib,content)
            self.assertEqual(g['read_journal'](lib)['phase'],'installed')
        with tree() as (g,lib,content,calls,loaded):
            def failing_but_loaded(*a,**k):
                loaded[0]={'loaded':True,'pid':None,'state':'not running','last_exit_code':None}
                return SimpleNamespace(returncode=5,stdout=b'',stderr=b'')
            g['run']=failing_but_loaded;g['install'](lib,content)
            self.assertEqual(g['read_journal'](lib)['phase'],'installed')

    def test_unknown_existing_source_and_changed_owned_source_never_bootout(self):
        with tree() as (g,lib,content,calls,loaded):
            (g['BASE']/'scheduler.py').write_bytes(content['scheduler.py'])
            with self.assertRaises(g['Failure']):g['install'](lib,content)
            self.assertIsNone(g['read_journal'](lib));self.assertFalse(g['PLIST'].exists())
        with tree() as (g,lib,content,calls,loaded):
            g['install'](lib,content);calls.clear()
            (g['BASE']/'scheduler.py').write_bytes(b'unknown')
            with self.assertRaises(g['Failure']):g['remove'](lib,content)
            self.assertFalse(any(isinstance(x,tuple) and 'bootout' in x for x in calls))
            self.assertTrue(g['PLIST'].exists())

    def test_remove_bootout_before_locks_preserves_source_and_idempotent(self):
        with tree() as (g,lib,content,calls,loaded):
            g['install'](lib,content);calls.clear()
            original=lib['locked_path'];held=[]
            @contextlib.contextmanager
            def lock(path,**kwargs):
                self.assertIsNone(loaded[0],'lock acquired before bootout')
                held.append(path)
                with original(path,**kwargs):yield
            lib['locked_path']=lock
            g['remove'](lib,content)
            self.assertEqual(held,[g['STATE']/'scheduler.lock',lib['HELPER'].parent/'.installer.lock',g['HELPER_STATE']/'lock'])
            self.assertFalse(g['PLIST'].exists());self.assertTrue((g['BASE']/'scheduler.py').exists())
            self.assertEqual(g['read_journal'](lib)['phase'],'removed')
            g['remove'](lib,content)

    def test_remaining_process_group_keeps_plist_and_removal_intent(self):
        with tree() as (g,lib,content,calls,loaded):
            g['install'](lib,content)
            lib['atomic_metadata']('process.json',dict(version=1,pid=77777,pgid=77777,started=1000))
            g['group_absent']=lambda groups:False
            with patch.object(g['time'],'monotonic',side_effect=[0,17]):
                with self.assertRaises(g['Failure']):g['remove'](lib,content)
            self.assertTrue(g['PLIST'].exists());self.assertEqual(g['read_journal'](lib)['phase'],'removing')

    def test_check_read_only_no_secret_or_network_calls(self):
        with tree() as (g,lib,content,calls,loaded):
            g['install'](lib,content);calls.clear()
            before={p:(p.stat().st_ino,p.read_bytes()) for p in [g['PLIST'],g['STATE']/'install.json',g['STATE']/'status.json',g['BASE']/'scheduler.py']}
            g['run']=lambda *a,**k:(_ for _ in ()).throw(AssertionError('unexpected command'))
            g['check'](lib,content)
            self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes()) for p in before})
            report=calls[-1]
            self.assertEqual(report[0],'read_only_status')
            self.assertTrue(report[1]['credential_content_not_read']);self.assertTrue(report[1]['live_dns_not_queried'])

    def test_source_hash_tamper_rejected_before_any_installation(self):
        g=load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in g['EXPECTED']:(root/name).write_bytes((HERE/name).read_bytes())
            (root/'scheduler.py').write_text('not reviewed')
            with self.assertRaises(g['Failure']):g['resources'](root)


if __name__=='__main__':unittest.main(verbosity=2)
