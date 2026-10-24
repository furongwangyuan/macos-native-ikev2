"""Private, bounded, durable receipts. No directory creation or writes on import.

Production supplies native_support.trusted and uid=0; ordinary tests explicitly
supply a tempfile checker and their own uid. No CLI selects that test authority.
"""
import fcntl
import json
import math
import os
from pathlib import Path
import secrets
import stat
from fault_protocol import Refused

NAMES=frozenset(('intent.json','owner.json','observer.json','coordinator.json','watch.json',
                'checkpoint.json','armed.json','injection.json','abort.json','recovery.json',
                'result.json','baseline.json','coordinator-attention.json','observer-attention.json'))
IMMUTABLE=NAMES-{'injection.json','coordinator-attention.json','observer-attention.json'}
WRITES={
    'coordinator':{'intent.json','owner.json','observer.json','coordinator.json','injection.json',
                   'abort.json','result.json','coordinator-attention.json'},
    'owner':{'baseline.json','checkpoint.json'},
    'observer':{'watch.json','armed.json','recovery.json','observer-attention.json'},
}
LIMIT=131072


def encode(value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    if len(raw)>LIMIT:raise Refused('receipt_limit')
    return raw


def decode(raw):
    def pairs(values):
        result={}
        for k,v in values:
            if k in result:raise Refused('duplicate_receipt_key')
            result[k]=v
        return result
    def bad(_):raise Refused('nonfinite_receipt')
    def finite(text):
        value=float(text)
        if not math.isfinite(value):raise Refused('nonfinite_receipt')
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad,parse_float=finite)


def stamp(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


class Receipts:
    def __init__(self,path,trust,uid,writer=None):
        if writer not in WRITES and not (writer is None and uid!=0):raise Refused('receipt_writer_required')
        self.path=Path(path);self.trust=trust;self.uid=uid;self.writer=writer
        self._directory()
    def _directory(self):
        info=self.trust(self.path,0o700)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.uid:raise Refused('receipt_directory')
        return info
    def _name(self,name):
        if name not in NAMES:raise Refused('receipt_name')
        return self.path/name
    def exists(self,name):
        path=self._name(name)
        if path.exists() or path.is_symlink():self.read(name);return True
        return False
    def read(self,name):
        self._directory();path=self._name(name);before=self.trust(path,0o600)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=self.uid or before.st_nlink!=1
                or before.st_size>LIMIT):raise Refused('receipt_file')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            opened=os.fstat(fd);chunks=[];total=0
            if stamp(opened)!=stamp(before):raise Refused('receipt_changed')
            while True:
                more=os.read(fd,min(8192,LIMIT+1-total))
                if not more:break
                chunks.append(more);total+=len(more)
                if total>LIMIT:raise Refused('receipt_limit')
            if (stamp(os.fstat(fd))!=stamp(opened) or stamp(path.lstat())!=stamp(opened)
                    or total!=opened.st_size):raise Refused('receipt_changed')
            return decode(b''.join(chunks))
        finally:os.close(fd)
    def write(self,name,value):
        if self.writer is not None and name not in WRITES[self.writer]:raise Refused('receipt_wrong_writer')
        path=self._name(name);raw=encode(value);before_dir=self._directory()
        if path.exists() or path.is_symlink():
            old=self.read(name)
            if name in IMMUTABLE:
                if encode(old)==raw:return
                raise Refused('immutable_receipt_changed')
        tmp=self.path/('.receipt-'+secrets.token_hex(12));fd=None
        try:
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            if os.get_inheritable(fd):raise Refused('receipt_fd_inherited')
            offset=0
            while offset<len(raw):
                n=os.write(fd,raw[offset:])
                if n<=0:raise Refused('receipt_short_write')
                offset+=n
            os.fchmod(fd,0o600);os.fsync(fd);os.close(fd);fd=None
            now=self._directory()
            if (now.st_dev,now.st_ino)!=(before_dir.st_dev,before_dir.st_ino):raise Refused('receipt_directory_changed')
            if name in IMMUTABLE:
                try:os.link(tmp,path,follow_symlinks=False)
                except FileExistsError:
                    if encode(self.read(name))!=raw:raise Refused('immutable_receipt_raced')
                tmp.unlink()
            else:os.replace(tmp,path)
            directory=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(directory)
            finally:os.close(directory)
            if encode(self.read(name))!=raw:raise Refused('receipt_readback')
        finally:
            if fd is not None:os.close(fd)
            if tmp.exists():tmp.unlink()
