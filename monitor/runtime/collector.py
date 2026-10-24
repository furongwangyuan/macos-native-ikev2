#!/usr/bin/python3
"""Bounded read-only monitor supervisor. Not installed; no VPN mutations.

Only a future fixed root-owned installation may run main(). Individual sampling
workers have a cooperative three-second continuous-clock budget plus bounded
cleanup waits. System suspension/kernel stalls are not hard real-time guarantees.
"""
import argparse
import copy
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import syslog
import threading
import time
import uuid

BASE=Path('/usr/local/family-vpn/monitor')
STORE=Path('/var/run/family-vpn-monitor')
STATUS=STORE/'status.json'
STOP=threading.Event()
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'}

def diagnostic(code):
    # Fixed categories only: no exception text, identity, IP, or VICI payload.
    if code not in ('collector_started','collector_stopped','sampling_unavailable','sampling_exception','sample_rejected','sampling_recovered','journal_unavailable'):return
    syslog.syslog(syslog.LOG_DAEMON|syslog.LOG_NOTICE,'family-vpn-monitor '+code)
    try:print('MONITOR_DIAGNOSTIC '+code,file=sys.stderr,flush=True)
    except OSError:pass

@contextmanager
def exclusive_run_lock():
    # The same inode remains after exit. An OS lock, rather than a PID marker,
    # prevents two collectors publishing different ledgers to one status file.
    fd=os.open(STORE/'collector.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
            raise ValueError('unexpected collector lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)

def query_sample(popen=subprocess.Popen):
    from worker_process import query_worker
    return query_worker(popen=popen)

def publish(snapshot):
    # Installation owns this 0755 directory. Only sanitized dashboard metadata
    # is made 0644 for the ordinary-user loopback server; never VICI/raw samples.
    from schema import sanitize
    data=json.dumps(sanitize(snapshot),ensure_ascii=False,allow_nan=False).encode('utf-8')
    if len(data)>131072:raise ValueError('export too large')
    if STATUS.exists() or STATUS.is_symlink():
        s=STATUS.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o644:raise ValueError('unexpected status file')
    temp=STORE/('status.new.'+str(os.getpid()))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
        os.replace(temp,STATUS)
    finally:
        if temp.exists():temp.unlink()

def run(seconds, query=query_sample, emit=publish, clock=time.monotonic, wall=time.time,
        stop=STOP, report=diagnostic, store=None, registry_reader=None, legacy_reader=None):
    from ledger import RegistryLedger, migrate_v2
    from schema import EMPTY
    from journal import Store
    from registry_source import read_registry, legacy_registry
    read_registered=read_registry if registry_reader is None else registry_reader
    read_legacy=legacy_registry if legacy_reader is None else legacy_reader
    store=Store() if store is None else store
    epoch='monitor_'+uuid.uuid4().hex
    ledger=None;broken=False;initial_retry_at=None
    def initialize():
        nonlocal ledger,broken,initial_retry_at
        try:
            try:
                registered=read_registered();saved=store.load()
            except OSError:
                # Only a failed initial read may retry. Read and validate both
                # inputs afresh; no ledger reset, partial reuse or zero estimate.
                broken=True;initial_retry_at=clock()+5
                return
            now=wall()
            if saved is not None and type(saved.get('version'))is int and saved['version']==2:
                saved=migrate_v2(saved,previous_registry=read_legacy(store.previous_raw),
                                 registry=registered.value,epoch=epoch,wall=now)
            ledger=RegistryLedger(registered.value,epoch,now,persisted=saved)
        except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError):
            # Invalid/changed accounting and failed migration stay latched.
            broken=True;initial_retry_at=None
        else:
            broken=False;initial_retry_at=None
    initialize()
    deadline=clock()+seconds;last_issue=None
    try:
        while not stop.is_set() and clock()<deadline:
            started=clock();issue=None;phase='query'
            if broken and initial_retry_at is not None and started>=initial_retry_at:
                initialize()
            try:
                if broken:
                    result=copy.deepcopy(EMPTY);issue='journal_unavailable';sample=None
                else:
                    sampled_registry=read_registered()
                    sample=query()
                sampled_mono=clock();phase='ledger'
                if not broken:
                    if sample is not None:
                        required={'server_running','wall','mono','rows','registry_sha256','registry_revision'}
                        if (type(sample)is not dict or set(sample) not in (required,required|{'unknown_devices'})
                                or type(sample['registry_revision'])is not int
                                or sample['registry_revision']!=sampled_registry.value['revision']
                                or sample['registry_sha256']!=sampled_registry.sha256):
                            raise ValueError('sample registry differs')
                        after=read_registered()
                        if after.raw!=sampled_registry.raw or after.sha256!=sampled_registry.sha256:
                            raise ValueError('registry changed across worker sample')
                        if ledger.matches_registry(sampled_registry.value):
                            candidate=copy.deepcopy(ledger)
                        else:
                            # Monotone registry updates preserve permanent IDs and
                            # daily highwaters; rename never creates a new account.
                            candidate=RegistryLedger(sampled_registry.value,epoch,sample['wall'],persisted=ledger.to_journal())
                        result=candidate.observe(sample['rows'],wall=sample['wall'],mono=sampled_mono,server_running=sample['server_running'],
                                                 unknown_devices=sample.get('unknown_devices',[]))
                        phase='journal';store.save(candidate.to_journal());ledger=candidate
                    else:
                        result=ledger.unavailable();issue='sampling_unavailable'
            except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError):
                if phase=='journal':
                    broken=True;result=copy.deepcopy(EMPTY);issue='journal_unavailable'
                else:
                    result=ledger.unavailable()
                    issue='sampling_exception' if phase=='query' else 'sample_rejected'
            if issue!=last_issue:
                report(issue or 'sampling_recovered');last_issue=issue
            emit(result)
            stop.wait(max(0,min(1-(clock()-started),deadline-clock())))
    finally:
        emit(copy.deepcopy(EMPTY) if broken else ledger.unavailable())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds',type=int,default=900)
    args=parser.parse_args()
    if not 1<=args.seconds<=86400 or os.geteuid()!=0 or Path(__file__)!=BASE/'collector.py':
        raise ValueError('fixed root installation and bounded duration required')
    # Isolated Python does not add the script directory; use only this fixed
    # installation. Its files and source pins are to be checked by the installer.
    if BASE.is_symlink() or BASE.stat().st_uid!=0 or stat.S_IMODE(BASE.stat().st_mode)!=0o700:raise ValueError('untrusted collector directory')
    sys.path.insert(0,str(BASE))
    from worker import trusted
    for path in [BASE/'ledger.py',BASE/'source.py',BASE/'schema.py',BASE/'worker.py',BASE/'journal.py',BASE/'journal_acl.py',BASE/'worker_process.py',BASE/'registry.py',BASE/'registry_source.py',BASE/'ledger_core_v3.py']:
        trusted(path,0o600)
    from journal import ROOT, trusted as trusted_journal
    trusted_journal(ROOT,directory=True)
    trusted(STORE,0o755)
    os.umask(0o077)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,lambda *_:STOP.set())
    from worker_process import continuous_seconds
    with exclusive_run_lock():
        diagnostic('collector_started')
        try:run(args.seconds,clock=continuous_seconds)
        finally:diagnostic('collector_stopped')

if __name__=='__main__':
    try:main()
    except Exception:
        # Only a fixed diagnostic; never log raw sample content.
        print('Telemetry stopped; review the local fixed installation.',file=sys.stderr)
        sys.exit(1)
