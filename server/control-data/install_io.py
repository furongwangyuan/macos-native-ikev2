#!/usr/bin/python3
"""Fixed installer IO inherited from reviewed owner-fault package; no CLI.

EXPECTED is replaced by build.py. Only verified bytes are installed. Root
payload imports occur only after complete installed inventory/hash verification.
"""
import contextlib
import fcntl
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

EXPECTED = {} # BUILD_REPLACE
BASE=Path('/usr/local/family-vpn/production-guardian')
STATE=Path('/private/var/db/family-vpn/production-acceptance')
MANAGER=Path('/private/var/db/family-vpn/production-acceptance-install')
NATIVE=Path('/private/var/db/family-vpn/production-guardian')
OLD_BASE=Path('/usr/local/family-vpn/production-guardian')
CONF=Path('/usr/local/etc/family-vpn/production-guardian')
RUN=Path('/private/var/run/family-vpn/production-guardian')
LEGACY=tuple(Path('/private/var/db/family-vpn')/x for x in
    ('lan-full-test','lan-floor-test','lan-floor-lifecycle','wan-full-test','reconnect-test'))
OLD_JOB=Path('/Library/LaunchDaemons/org.familyvpn.guardian-recovery.plist')
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}
ACTIONS=('inspect','install-and-test','recover','report')
LIMIT=1048576
UID=0 # No runtime argument/environment override; tests may patch internal globals.


class Failure(RuntimeError):pass


def exists(path):
    try:path.lstat();return True
    except FileNotFoundError:return False


def digest(raw):return hashlib.sha256(raw).hexdigest()

def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()

def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise Failure('duplicate_metadata')
            value[key]=item
        return value
    def finite(text):
        value=float(text)
        if not math.isfinite(value):raise Failure('nonfinite_metadata')
        return value
    def nonfinite(_):raise Failure('nonfinite_metadata')
    return json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite,parse_float=finite)


def stamp(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def trusted(path,*,directory=False,mode=None):
    path=Path(path)
    for item in (path,*path.parents):
        info=item.lstat()
        system_run=(item==Path('/private/var/run') and
            (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(0,1,0o775))
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=UID or (info.st_mode&0o022 and not system_run):
            raise Failure('untrusted_root_path')
        if item!=path and not stat.S_ISDIR(info.st_mode):raise Failure('untrusted_ancestor')
        check=subprocess.run(['/bin/ls','-lde',str(item)],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=3,close_fds=True,start_new_session=True)
        if check.returncode or len(check.stdout.splitlines())!=1:raise Failure('acl_or_metadata_refused')
    final=path.lstat()
    if not (stat.S_ISDIR(final.st_mode) if directory else stat.S_ISREG(final.st_mode)):
        raise Failure('root_path_type')
    if not directory and final.st_nlink!=1:raise Failure('root_hardlink_refused')
    if mode is not None and stat.S_IMODE(final.st_mode)!=mode:raise Failure('root_mode')
    return final


def read(path,*,installed=False,limit=LIMIT):
    path=Path(path)
    before=trusted(path,mode=0o600) if installed else path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:
        raise Failure('file_type_or_limit')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd);data=bytearray()
        if stamp(opened)!=stamp(before):raise Failure('file_changed')
        while True:
            more=os.read(fd,min(8192,limit+1-len(data)))
            if not more:break
            data.extend(more)
            if len(data)>limit:raise Failure('file_limit')
        if stamp(os.fstat(fd))!=stamp(opened) or stamp(path.lstat())!=stamp(opened) or len(data)!=opened.st_size:
            raise Failure('file_changed')
        return bytes(data)
    finally:os.close(fd)


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def directory(path):
    trusted(path.parent,directory=True)
    if not exists(path):
        path.mkdir(mode=0o700);os.chown(path,UID,0);sync_dir(path.parent)
    return trusted(path,directory=True,mode=0o700)


def write_new(path,raw):
    """Create-only durable publish, never replace an existing unknown file."""
    trusted(path.parent,directory=True,mode=0o700)
    if exists(path):
        if read(path,installed=True)!=raw:raise Failure('existing_file_differs')
        return
    if len(raw)>LIMIT:raise Failure('write_limit')
    temp=path.parent/('.closed-install-'+secrets.token_hex(12))
    fd=None
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);offset=0
        while offset<len(raw):
            n=os.write(fd,raw[offset:])
            if n<=0:raise Failure('short_write')
            offset+=n
        os.fchmod(fd,0o600);os.fsync(fd);os.close(fd);fd=None
        try:os.link(temp,path,follow_symlinks=False)
        except FileExistsError:
            if read(path,installed=True)!=raw:raise Failure('create_only_race')
        temp.unlink();sync_dir(path.parent)
        if read(path,installed=True)!=raw:raise Failure('write_readback')
    finally:
        if fd is not None:os.close(fd)
        if exists(temp):temp.unlink()


@contextlib.contextmanager
def lock(path,*,create=False):
    trusted(path.parent,directory=True,mode=0o700)
    if create:write_new(path,b'')
    read(path,installed=True,limit=4096)
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=trusted(path,mode=0o600)
        if stamp(os.fstat(fd))!=stamp(info) or os.get_inheritable(fd):raise Failure('lock_changed_or_inherited')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        def held():
            current=trusted(path,mode=0o600)
            if stamp(os.fstat(fd))!=stamp(current) or os.get_inheritable(fd):raise Failure('original_lock_lease_changed')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield held
    finally:os.close(fd)

