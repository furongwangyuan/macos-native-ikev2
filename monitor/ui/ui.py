"""Fixed ordinary-user loopback dashboard entry; no runtime controls."""
import hashlib
import ctypes
import errno
import os
from pathlib import Path
import runpy
import stat
import sys

BASE=Path('/usr/local/share/family-vpn-monitor')
EXPECTED={'ledger_core_v3.py': '9eaebc8d21cd3f807ba7376514c998e72612f96bce6ddd9fdf2be7d48f6107df', 'schema.py': '38b6cec74f315267cb9f989798e79767dc15bd7d59fe3e6c2d33e1b6b1323572', 'server.py': '425d1151606e24aeb199b7a494b06463a145613bb1d7d6309512eb6472766855', 'site/app.mjs': 'a59c4098601f1e716f2e44cbed5ddb2221c56c1bc47d9cf4cd8e0d21528c473f', 'site/daily_model_v2.mjs': '7bae88f9f15b9b3b383a2a1218df535fad877f404996da9c729196926c9bc0d8', 'site/index.html': '09a846908cf2c063b690e3cfd32d14fca1e20f6228bc9ca0df06973d1c89dd22', 'site/model.mjs': '116cea41072a4d2ed87a73d2e719f3a30f60924e919b48c0baa5b20315f28eb2', 'site/style.css': 'acd471126c10ed1d08badd1f04b3196717554c88aa0ba529c3c53d858fdab146'}


def no_acl(fd):
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int];lib.acl_get_fd_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p];lib.acl_free.restype=ctypes.c_int
    ctypes.set_errno(0);acl=lib.acl_get_fd_np(fd,0x100);error=ctypes.get_errno()
    if acl:
        try:raise ValueError('extended dashboard ACL')
        finally:
            if lib.acl_free(acl)!=0:raise ValueError('dashboard ACL release failed')
    if error!=errno.ENOENT:raise ValueError('dashboard ACL status unknown')


def verify():
    allowed=set(EXPECTED)|{'ui.py'}
    if {p.name for p in BASE.iterdir()}!={Path(p).parts[0] for p in allowed}:
        raise ValueError('unexpected dashboard import source')
    if {p.name for p in (BASE/'site').iterdir()}!={Path(p).name for p in EXPECTED if p.startswith('site/')}:
        raise ValueError('unexpected dashboard asset')
    for name,digest in dict(EXPECTED,**{'ui.py':None}).items():
        path=BASE/name
        for part in [path,*path.parents]:
            info=part.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                raise ValueError('untrusted local monitor source')
            if part!=path and not stat.S_ISDIR(info.st_mode):raise ValueError('invalid dashboard parent')
            fd=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                if os.fstat(fd)!=info:raise ValueError('dashboard object changed')
                no_acl(fd)
                if os.fstat(fd)!=info or part.lstat()!=info:raise ValueError('dashboard metadata changed')
            finally:os.close(fd)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            with os.fdopen(fd,'rb',closefd=False) as source:
                before=os.fstat(source.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_size>262144 or before.st_nlink!=1
                        or stat.S_IMODE(before.st_mode)!=0o644):
                    raise ValueError('invalid dashboard file')
                data=source.read(262145)
                if len(data)!=before.st_size or os.fstat(source.fileno())!=before or path.lstat()!=before:
                    raise ValueError('dashboard file changed')
        finally:os.close(fd)
        if digest is not None and hashlib.sha256(data).hexdigest()!=digest:raise ValueError('dashboard source differs')


def main():
    if os.geteuid()==0 or len(sys.argv)!=1 or Path(__file__)!=BASE/'ui.py':
        raise ValueError('fixed ordinary-user local monitor only')
    verify()
    sys.path.insert(0,str(BASE))
    sys.argv=[str(BASE/'server.py'),'--root',str(BASE/'site'),'--snapshot',
              '/private/var/run/family-vpn-monitor/status.json','--port','8767']
    runpy.run_path(str(BASE/'server.py'),run_name='__main__')


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1)
