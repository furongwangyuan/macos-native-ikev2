"""Ordinary real-file checks; uid-only metadata fixture, no server/root/job."""
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if os.geteuid()==0:raise SystemExit('ordinary user required')
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,'/usr/local/share/family-vpn-monitor')
spec=importlib.util.spec_from_file_location('candidate_monitor_server',HERE/'server.py')
server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)

@contextlib.contextmanager
def root_uid_only():
    fstat=os.fstat;lstat=Path.lstat
    def uid(info):
        data={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
        data['st_uid']=0
        return SimpleNamespace(**data)
    with patch.object(os,'fstat',lambda fd:uid(fstat(fd))),\
         patch.object(Path,'lstat',lambda p:uid(lstat(p))):yield

def write(path,value):
    path.write_bytes(value if type(value)is bytes else json.dumps(value).encode())
    path.chmod(0o644)

class Checks(unittest.TestCase):
    def test_atomic_replacement_reopens_and_returns_only_new_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json';write(path,server.EMPTY)
            new=copy.deepcopy(server.EMPTY);new['server']['state']='stopped'
            calls=[];actual=server.snapshot_no_acl
            def once(fd):
                calls.append(fd);actual(fd)
                if len(calls)==1:
                    other=path.with_name('next.json');write(other,new);os.replace(other,path)
            with root_uid_only(),patch.object(server,'snapshot_no_acl',side_effect=once):
                self.assertEqual(server.read_snapshot(path),server.sanitize(new))
            self.assertEqual(len(calls),2)
            for fd in calls:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_second_replacement_stops_and_atime_is_not_a_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json';write(path,server.EMPTY)
            calls=[];actual=server.snapshot_no_acl
            def every(fd):
                calls.append(fd);actual(fd)
                other=path.with_name('next.json');write(other,server.EMPTY);os.replace(other,path)
            with root_uid_only(),patch.object(server,'snapshot_no_acl',side_effect=every):
                with self.assertRaises(server.SnapshotReplaced):server.read_snapshot(path)
            self.assertEqual(len(calls),2)
            info=path.stat();values={k:getattr(info,k) for k in dir(info) if k.startswith('st_')}
            values.update(st_atime=0,st_atime_ns=0)
            self.assertEqual(server.snapshot_stamp(info),server.snapshot_stamp(SimpleNamespace(**values)))

    def test_permission_acl_and_data_faults_do_not_retry(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'status.json'
            for fault in ('mode','owner','json','schema','acl','in_place'):
                with self.subTest(fault=fault):
                    write(path,b'{' if fault=='json' else {} if fault=='schema' else server.EMPTY)
                    if fault=='mode':path.chmod(0o600)
                    opens=[];actual_open=os.open;actual_acl=server.snapshot_no_acl
                    def capture(*args,**kwargs):
                        fd=actual_open(*args,**kwargs);opens.append(fd);return fd
                    def acl(fd):
                        actual_acl(fd)
                        if fault=='acl':raise ValueError('extended telemetry ACL')
                        if fault=='in_place':path.write_bytes(b'{}')
                    owner=contextlib.nullcontext() if fault=='owner' else root_uid_only()
                    with owner,patch.object(os,'open',side_effect=capture),\
                         patch.object(server,'snapshot_no_acl',side_effect=acl):
                        with self.assertRaises(ValueError):server.read_snapshot(path)
                    self.assertEqual(len(opens),1)
                    with self.assertRaises(OSError):os.fstat(opens[0])

if __name__=='__main__':unittest.main()
