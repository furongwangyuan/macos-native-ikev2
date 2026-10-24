"""Fixed root loader: execute the exact bounded bytes just verified."""
import hashlib
import os
from pathlib import Path
import stat
import sys

EXPECTED=__ROOT_SHA__
ACTIONS=__ROOT_ACTIONS__

def stamp(info):
    return tuple(getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_uid',
        'st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=1048576:
            raise ValueError('bounded fixed installer required')
        raw=bytearray()
        while len(raw)<=1048576:
            part=os.read(fd,min(8192,1048577-len(raw)))
            if not part:break
            raw.extend(part)
        if len(raw)!=before.st_size or stamp(os.fstat(fd))!=stamp(before) or stamp(path.lstat())!=stamp(before):
            raise ValueError('installer changed while reading')
        return bytes(raw)
    finally:os.close(fd)

def main():
    if (os.geteuid()!=0 or len(sys.argv)<3 or sys.argv[2] not in ACTIONS
            or len(sys.argv)!=3+ACTIONS[sys.argv[2]]):
        raise ValueError('fixed administrator loader action required')
    path=Path(sys.argv[1]);action=sys.argv[2]
    if not path.is_absolute() or path.name!='installer-root.py':raise ValueError('fixed installer basename')
    raw=read(path)
    if hashlib.sha256(raw).hexdigest()!=EXPECTED:raise ValueError('installer digest changed')
    sys.argv=[str(path),action,*sys.argv[3:]]
    exec(compile(raw,'fixed-family-vpn-v9-installer','exec'),{'__name__':'__main__','__file__':str(path)})

if __name__=='__main__':
    try:main()
    except Exception:
        print('{"event":"fixed_installer_loader_failed","state_may_remain":true}',flush=True)
        raise SystemExit(2)
