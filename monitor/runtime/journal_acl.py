"""Darwin FD-bound journal trust checks. No subprocess, cache of ACLs or writes.

Only the fixed libSystem function bindings are cached. Every call reopens and
checks the complete path, including the retained parent descriptors and names.
The private relative-FD helper exists for ordinary temporary-file tests; it is
not a privileged entry, configurable owner policy, or installation interface.
"""
import ctypes
import errno
from functools import lru_cache
import os
from pathlib import Path
import stat


@lru_cache(maxsize=1)
def _api():
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int]
    lib.acl_get_fd_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p]
    lib.acl_free.restype=ctypes.c_int
    return lib


def absent(fd):
    """Require absent ACL property; unknown errors/allocated-empty ACL refuse."""
    lib=_api();ctypes.set_errno(0)
    acl=lib.acl_get_fd_np(fd,0x100) # Darwin ACL_TYPE_EXTENDED
    error=ctypes.get_errno()
    if acl:
        try:raise ValueError('extended journal ACL')
        finally:
            if lib.acl_free(acl)!=0:raise ValueError('journal ACL free failed')
    if error!=errno.ENOENT:raise ValueError('journal ACL status unknown')


def _identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def _metadata(fd,uid,*,final,directory):
    info=os.fstat(fd)
    if info.st_uid!=uid or info.st_mode&0o022:raise ValueError('untrusted journal path')
    if not final:
        if not stat.S_ISDIR(info.st_mode):raise ValueError('invalid ancestor')
    elif directory:
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('private journal directory required')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
        raise ValueError('private regular journal required')
    absent(fd)
    if _identity(os.fstat(fd))!=_identity(info):raise ValueError('journal metadata changed during ACL')
    return _identity(info)


def _trusted_at(root_fd,parts,uid,*,directory=False):
    if (type(parts)is not tuple or type(uid)is not int or uid<0 or
            any(type(x)is not str or not x or x in ('.','..') or '/' in x or '\0' in x for x in parts)):
        raise ValueError('journal relative path scope')
    fds=[];states=[]
    try:
        fds.append(os.dup(root_fd))
        states.append(_metadata(fds[-1],uid,final=not parts,directory=directory))
        for index,name in enumerate(parts):
            final=index==len(parts)-1
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
            if not final or directory:flags|=os.O_DIRECTORY
            fd=os.open(name,flags,dir_fd=fds[-1]);fds.append(fd)
            states.append(_metadata(fd,uid,final=final,directory=directory))
        for index,fd in enumerate(fds):
            if _metadata(fd,uid,final=index==len(fds)-1,directory=directory)!=states[index]:
                raise ValueError('journal path changed during trust check')
        for index,name in enumerate(parts,1):
            current=os.stat(name,dir_fd=fds[index-1],follow_symlinks=False)
            if _identity(current)!=states[index]:raise ValueError('journal path name replaced')
    finally:
        failure=None
        for fd in reversed(fds):
            try:os.close(fd)
            except OSError as error:failure=error
        if failure is not None:raise ValueError('journal descriptor cleanup failed') from failure


def trusted_path(path,*,directory=False):
    """Production policy: absolute root-owned path, no symlink in any segment."""
    path=Path(path)
    if not path.is_absolute() or any(x in ('.','..') for x in path.parts):
        raise ValueError('absolute journal path required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:_trusted_at(fd,tuple(path.parts[1:]),0,directory=directory)
    finally:os.close(fd)
