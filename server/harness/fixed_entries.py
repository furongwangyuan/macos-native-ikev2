"""Prospective fixed native entries. No installer/launchd job is shipped.

Nothing here is run by author tests. An installed launch requires root, the
exact reviewed location, a complete root-owned resource manifest, pre-existing
private state and lock, no previous run and no prior v3 journal.
"""
import fcntl
import contextlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from native_adapter import Native, sources, resource_snapshot, old_job_absent, prior_allowed, s, CLOSURE_SHA, PROFILE, COMMON, INSTALLED_COMMON
from fault_protocol import Refused, digest
from receipt_store import Receipts, decode, encode
from coordinator_logic import Processes, run
from role_logic import owner_role, observer_role

BASE=Path('/usr/local/family-vpn/production-owner-fault')
STATE=Path('/private/var/db/family-vpn/production-owner-fault')
ENTRIES={'coordinator':'coordinator_entry.py','owner':'owner_entry.py','observer':'observer_entry.py'}


def installed(role):
    if os.geteuid()!=0 or len(sys.argv)!=1 or Path(sys.argv[0])!=BASE/ENTRIES[role]:
        raise Refused('fixed_installed_root_entry_only')
    if Path(__file__).parent!=BASE or s.BASE!=INSTALLED_COMMON or COMMON!=INSTALLED_COMMON:raise Refused('fixed_closure_location')
    s.trusted(BASE,0o700);s.trusted(STATE,0o700)
    pins=decode(s.read(BASE/'integration-pins.json'))
    if type(pins)is not dict or not pins:raise Refused('integration_manifest')
    for name,expected in pins.items():
        if '/' in name or name in ('.','..') or type(expected)is not str:raise Refused('integration_manifest_name')
        if s.digest(s.read(BASE/name,mode=0o600))!=expected:raise Refused('integration_source_changed')
    allowed=set(pins)|{'integration-pins.json'}
    if set(x.name for x in BASE.iterdir())!=allowed:raise Refused('integration_extra_files')
    s.trusted(COMMON,0o700)
    sources()


def current(role):
    value=decode(s.read(STATE/'current.json'))
    if (type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int
            or value['version']!=1 or type(value['run'])is not str or len(value['run'])!=32
            or any(x not in '0123456789abcdef' for x in value['run'])):raise Refused('current_run')
    return Receipts(STATE/value['run'],s.trusted,0,role)


def spawn(role):
    if role not in ('owner','observer'):raise Refused('fixed_child_role')
    return subprocess.Popen(['/usr/bin/python3','-I','-B',str(BASE/ENTRIES[role])],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,
        start_new_session=True,cwd='/',env=s.ENV)


def coordinator():
    installed('coordinator');os.umask(0o077)
    if os.getpgrp()!=os.getpid():os.setsid()
    # A pre-existing fixed lock is installed by a future reviewed installer;
    # this candidate does not create an authority/daemon or repair permissions.
    lockpath=STATE/'lock';info=s.trusted(lockpath,0o600)
    lock=os.open(lockpath,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(info.st_mode) or s.signature(os.fstat(lock))!=s.signature(info):raise Refused('outer_lock_changed')
        if os.get_inheritable(lock):raise Refused('outer_lock_inherited')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (STATE/'current.json').exists() or (STATE/'current.json').is_symlink():
            raise Refused('single_run_candidate_requires_reviewed_archival')
        # Read-only admission under native locks, released BEFORE forking. Old
        # fixed job must be removed via its own reviewed installer beforehand.
        with s.locks():
            previous=prior_allowed(s.Store());old_job_absent();sources()
            intent=dict(version=1,run=secrets.token_hex(16),boot=s.boot(),closure_sha256=CLOSURE_SHA,
                        prior_session_sha256=digest(previous) if previous is not None else None,
                        resources=resource_snapshot(),profile='production-native-fleet-v1',allow_data=False,probe_mode='off')
        s.directory(STATE/intent['run']);receipts=Receipts(STATE/intent['run'],s.trusted,0,'coordinator')
        receipts.write('intent.json',intent)
        s.atomic(STATE/'current.json',encode(dict(version=1,run=intent['run'])))
        # Re-read current before children; immutable current is never replaced
        # by a later run while an old observer might still recover.
        if current('coordinator').read('intent.json')!=intent:raise Refused('current_readback')
        return run(Processes(receipts,spawn),Native(intent,receipts),receipts)
    finally:os.close(lock)


def child(role):
    installed(role);os.umask(0o077)
    receipts=current(role);intent=receipts.read('intent.json');native=Native(intent,receipts)
    with contextlib.redirect_stdout(sys.stderr):
        return owner_role(receipts,native) if role=='owner' else observer_role(receipts,native)
