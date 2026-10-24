"""Fixed root monitor service entry. Source candidate, never run from workspace.

After trusted preflight, exec the collector in the same launchd job PID/group.
There is no service controller, command argument or VPN mutation capability.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

EXPECTED={'collector.py': 'b79d5b86292a7549105d954c4ae023b633ec606b27926b47dc7c3d6a201b4446', 'journal.py': '59f5b0dbc5a9a67b397e99802bba9786e82ed8c6aa9cee0e9aa2b808cdc7271d', 'journal_acl.py': '0af2aace116f71f3927cf8d96ab2f4123310b5d78977cee61f76f81c87fe656e', 'ledger.py': '64708fcd5f59983cd8300040015fae5aa4607882b035f2a3646995174d5bede8', 'ledger_core_v3.py': 'c98f0bdaed6adf8c7a463a8a270e396def90569b8beff17b7d1aae5fb7869882', 'registry.py': '745135b5c0d12ae2065ad7dde0820788191a2fc60c272b23496e96cf762027b3', 'registry_source.py': '0a1e4f23592802b157ee3b2b814980284763a7f468ab30688acbbab60996c9fd', 'schema.py': '38b6cec74f315267cb9f989798e79767dc15bd7d59fe3e6c2d33e1b6b1323572', 'source.py': 'f2daf460bfabeaeadb848a01848c7e0a3fec4db8b959012858f00227b2592423', 'vendor-pins.json': 'faf3b612df9637a360009390d120171f4c8f56e85a174b65e25c6d70680bed48', 'vendor/LICENSE': '7cf763909a5be21bcc7dabb9dc92dbf60bd8afff850a1a01c7621174ce72ce7d', 'vendor/vici/__init__.py': 'f77019594ecc7a2198c796d7ca62bf22e90d8e0258b0831e4467b572a2393c52', 'vendor/vici/command_wrappers.py': '0ee5f892bacfbcdcf7ceff3f45d76a471de30d3ec8cfda15d69fb6b350205f4f', 'vendor/vici/event_listener.py': '85c57c1fb4cbdadc03a5341963cf3aa28f62709d3443d46e71ead3f75c6bf448', 'vendor/vici/exception.py': '97ef178d3a97b71eb1be45e9ef369de6b0fd96a376526b21044f204b8712feb3', 'vendor/vici/protocol.py': 'f86247d58ce36a84a651bc7fcce9b5acd789b185c056e8fc6dc7015bfc07d3a5', 'vendor/vici/session.py': '78c4ba125b0dc8d83703f03055de39c9fb80180965b52512de836b4f68dbdb59', 'worker.py': '52895eb7203b89beeb658f94b830031557ad43420a36240fea06ba6d1f71a732', 'worker_process.py': '70dd4ed579c4b22195ef1181aa60d2ef6d0af84844499e8c0bd0ccf82f7ab8a1'}
BASE=Path('/usr/local/family-vpn/monitor')
ENTRY=Path('/usr/local/family-vpn/monitor-service/service.py')
STORE=Path('/private/var/run/family-vpn-monitor')
PRIVATE=Path('/private/var/db/family-vpn/monitor-daily')
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}


def acl_absent(fd):
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int];lib.acl_get_fd_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p];lib.acl_free.restype=ctypes.c_int
    ctypes.set_errno(0);acl=lib.acl_get_fd_np(fd,0x100);error=ctypes.get_errno()
    if acl:
        try:raise ValueError('extended service ACL')
        finally:
            if lib.acl_free(acl)!=0:raise ValueError('ACL release failed')
    if error!=errno.ENOENT:raise ValueError('ACL status unknown')


def trusted(path,mode=None,directory=False):
    path=Path(path)
    for part in [path,*path.parents]:
        info=part.lstat()
        exception=part==Path('/private/var/run') and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(0,1,0o775)
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or (info.st_mode&0o022 and not exception):
            raise ValueError('untrusted service path')
        is_dir=(part!=path or directory)
        if is_dir and not stat.S_ISDIR(info.st_mode):raise ValueError('service directory required')
        if not is_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1):raise ValueError('service regular file required')
        if part==path and mode is not None and stat.S_IMODE(info.st_mode)!=mode:raise ValueError('service mode differs')
        fd=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|(os.O_DIRECTORY if is_dir else 0))
        try:
            if os.fstat(fd)!=info:raise ValueError('service object changed')
            acl_absent(fd)
            if os.fstat(fd)!=info or part.lstat()!=info:raise ValueError('service trust check raced')
        finally:os.close(fd)


def resource_bytes(path):
    trusted(path,0o600)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>262144:raise ValueError('service resource bound')
        parts=[];size=0
        while True:
            data=os.read(fd,min(65536,262145-size))
            if not data:break
            parts.append(data);size+=len(data)
            if size>262144:raise ValueError('service resource bound')
        if os.fstat(fd)!=before or path.lstat()!=before or size!=before.st_size:
            raise ValueError('service resource changed')
        return b''.join(parts)
    finally:os.close(fd)


def verify_runtime():
    trusted(BASE,0o700,directory=True)
    parents={str(p) for name in EXPECTED for p in Path(name).parents if str(p)!='.'}
    def inventory(parent):
        for item in parent.iterdir():
            rel=str(item.relative_to(BASE))
            if parent==BASE and re.fullmatch(r'backup-[0-9]+',item.name):
                trusted(item,0o700,directory=True)
            elif rel in parents:
                trusted(item,0o700,directory=True);inventory(item)
            elif rel in EXPECTED or (parent==BASE and item.name=='installed-manifest.json'):
                trusted(item,0o600)
            else:raise ValueError('unexpected monitor resource preserved')
    inventory(BASE)
    def unique(pairs):
        data={}
        for key,value in pairs:
            if key in data:raise ValueError('duplicate install manifest field')
            data[key]=value
        return data
    if json.loads(resource_bytes(BASE/'installed-manifest.json'),object_pairs_hook=unique)!=EXPECTED:
        raise ValueError('monitor install manifest uncommitted or different')
    for name,digest in EXPECTED.items():
        if hashlib.sha256(resource_bytes(BASE/name)).hexdigest()!=digest:
            raise ValueError('monitor source differs')


def prepare_volatile_store():
    trusted(STORE.parent,directory=True)
    try:STORE.mkdir(mode=0o755)
    except FileExistsError:pass
    else:
        os.chown(STORE,0,0);os.chmod(STORE,0o755)
    trusted(STORE,0o755,directory=True)
    trusted(PRIVATE,0o700,directory=True)


def main():
    if os.geteuid()!=0 or len(sys.argv)!=1 or Path(__file__)!=ENTRY:
        raise ValueError('fixed installed root service only')
    os.umask(0o077)
    trusted(ENTRY.parent,0o700,directory=True);trusted(ENTRY,0o600)
    verify_runtime();prepare_volatile_store()
    os.execve('/usr/bin/python3', ['/usr/bin/python3','-I','-B',str(BASE/'collector.py'),'--seconds','86400'],ENV)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1)
