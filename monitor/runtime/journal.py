"""Same daily store with a v3 envelope and exact create-only v2 archive.

The epoch marker remains version2 deliberately: migration replaces only ledger,
so an interrupted migration retains either valid v2 or valid v3 under that same
marker. No reset, arbitrary archive path or certificate operation is exposed.
The caller owns the existing collector lock for the entire load/save lifetime.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
from journal_acl import trusted_path, absent
from ledger import loads

ROOT=Path('/private/var/db/family-vpn/monitor-daily')
LIMIT=8*1024*1024


def trusted(path,*,directory=False):trusted_path(path,directory=directory)

def identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def exists(path):
    try:path.lstat();return True
    except FileNotFoundError:return False


def read_raw(path):
    trusted(path);before=path.lstat()
    if not 0<before.st_size<=LIMIT:raise ValueError('journal limit')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd);absent(fd)
        with os.fdopen(fd,'rb',closefd=False) as handle:data=handle.read(LIMIT+1)
        if (identity(before)!=identity(opened) or identity(os.fstat(fd))!=identity(opened)
                or identity(path.lstat())!=identity(opened) or len(data)!=opened.st_size or len(data)>LIMIT):
            raise ValueError('journal changed during read')
        return data
    finally:os.close(fd)


def read(path):return loads(read_raw(path))

def sync_dir():
    fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def encode(data):
    raw=(json.dumps(data,separators=(',',':'),sort_keys=True,allow_nan=False)+'\n').encode('utf-8')
    if len(raw)>LIMIT:raise ValueError('journal limit')
    return raw


def atomic_raw(path,raw,*,new=False):
    trusted(ROOT,directory=True)
    if exists(path):
        trusted(path)
        if new:raise ValueError('create-only path already exists')
    if not 0<len(raw)<=LIMIT:raise ValueError('journal limit')
    temporary=ROOT/('.journal-'+secrets.token_hex(16));fd=None
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb',closefd=False) as handle:
            handle.write(raw);handle.flush();os.fsync(fd)
        os.close(fd);fd=None
        if new:
            os.link(temporary,path,follow_symlinks=False)
            temporary.unlink()
        else:os.replace(temporary,path)
        sync_dir()
        if read_raw(path)!=raw:raise ValueError('journal publication readback')
    finally:
        if fd is not None:os.close(fd)
        if exists(temporary):temporary.unlink()


def atomic(path,data,*,new=False):atomic_raw(path,encode(data),new=new)


def accounting(value):
    if type(value)is not dict or type(value.get('version'))is not int:raise ValueError('invalid journal envelope')
    if value['version']==2:return value
    if value['version']==3 and set(value)=={'version','registry','accounting'} and type(value['accounting'])is dict:
        inner=value['accounting']
        if type(inner.get('version'))is int and inner['version']==2:return inner
    raise ValueError('invalid journal envelope')


class Store:
    def __init__(self):self.loaded=False;self.previous=None;self.previous_raw=None

    def load(self):
        trusted(ROOT,directory=True)
        marker,ledger=ROOT/'initialized.json',ROOT/'ledger.json'
        has_marker,has_ledger=exists(marker),exists(ledger)
        if not has_marker and not has_ledger:
            self.loaded=True;self.previous=None;self.previous_raw=None;return None
        if not has_marker or not has_ledger:raise ValueError('incomplete persisted ledger')
        identity=read(marker);raw=read_raw(ledger);value=loads(raw);inner=accounting(value)
        if (type(identity)is not dict or set(identity)!= {'version','epoch'} or type(identity['version'])is not int
                or identity['version']!=2 or type(inner.get('epoch'))is not str or inner['epoch']!=identity['epoch']):
            raise ValueError('ledger identity differs')
        self.loaded=True;self.previous=copy.deepcopy(value);self.previous_raw=raw
        return value

    def save(self,value):
        if not self.loaded:raise ValueError('load journal before save')
        if type(value)is not dict or type(value.get('version'))is not int or value['version']!=3:
            raise ValueError('v3 commit required')
        inner=accounting(value)
        if type(inner.get('epoch'))is not str:raise ValueError('invalid journal epoch')
        marker,ledger=ROOT/'initialized.json',ROOT/'ledger.json'
        expected=dict(version=2,epoch=inner['epoch'])
        if not exists(marker):
            if exists(ledger) or self.previous is not None:raise ValueError('ledger without marker preserved')
            atomic(marker,expected,new=True)
        else:
            if read(marker)!=expected:raise ValueError('journal identity changed')
            if not exists(ledger):raise ValueError('lost ledger preserved')
            if self.previous_raw is None or read_raw(ledger)!=self.previous_raw:
                raise ValueError('persisted ledger changed externally')
        if self.previous is not None and self.previous['version']==2:
            archive=ROOT/('ledger-v2-'+hashlib.sha256(self.previous_raw).hexdigest()+'.json')
            if exists(archive):
                if read_raw(archive)!=self.previous_raw:raise ValueError('legacy archive changed')
            else:atomic_raw(archive,self.previous_raw,new=True)
            # A failure here retains old valid ledger + exact archive; restart
            # revalidates the explicit migration binding rather than resetting.
            if read_raw(ledger)!=self.previous_raw:raise ValueError('legacy ledger changed before replace')
        raw=encode(value);atomic_raw(ledger,raw)
        self.previous=copy.deepcopy(value);self.previous_raw=raw
