"""Bounded Darwin process evidence. Read-only; no process-name ownership guesses."""
import ctypes
import errno
import os
import time
from fault_protocol import Observation, Refused, identity


class BSDInfo(ctypes.Structure):
    _fields_=[(x,ctypes.c_uint32) for x in ['flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved']]+[
        ('comm',ctypes.c_char*16),('name',ctypes.c_char*32)]+[(x,ctypes.c_uint32) for x in ['nfiles','pgid','jobc','tdev','tpgid']]+[
        ('nice',ctypes.c_int32),('started_sec',ctypes.c_uint64),('started_usec',ctypes.c_uint64)]


def _one(pid):
    if type(pid)is not int or pid<=1:raise Refused('pid_schema')
    lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    info=BSDInfo();call=lib.proc_pidinfo
    call.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
    call.restype=ctypes.c_int;ctypes.set_errno(0)
    n=call(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
    if n==0 and ctypes.get_errno() in (errno.ESRCH,errno.ENOENT):return None
    if n!=ctypes.sizeof(info) or info.pid!=pid:raise Refused('identity_unavailable')
    path=ctypes.create_string_buffer(4096);call=lib.proc_pidpath
    call.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];call.restype=ctypes.c_int
    if call(pid,path,len(path))<=0:raise Refused('path_unavailable')
    value=identity(dict(pid=pid,uid=info.uid,pgid=info.pgid,started_sec=info.started_sec,
                        started_usec=info.started_usec,path=os.fsdecode(path.value)))
    if info.status not in (1,2,3,4,5):raise Refused('process_state_unknown')
    return value,info.status==4  # SSTOP=4 in the local SDK sys/proc.h.


def group(pgid):
    if type(pgid)is not int or pgid<=1:raise Refused('pgid_schema')
    lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True);call=lib.proc_listpids
    call.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int];call.restype=ctypes.c_int
    buffer=(ctypes.c_int*1024)();n=call(2,pgid,buffer,ctypes.sizeof(buffer))
    if n<0 or n>=ctypes.sizeof(buffer) or n%ctypes.sizeof(ctypes.c_int):raise Refused('group_unavailable')
    return tuple(sorted(x for x in list(buffer)[:n//ctypes.sizeof(ctypes.c_int)] if x))


def observe(pid):
    """Two-view bounded recheck; no signal or permission follows an unknown view."""
    end=time.monotonic()+0.5
    while True:
        try:value=_one(pid);path_race=False
        except Refused as e:
            if str(e)!='path_unavailable':raise
            value=None;path_race=True
        members=group(pid)
        if value is not None:
            ident,stopped=value
            return Observation(ident,stopped,members)
        if not path_race and not members:return None
        # A disappearing owned leader can briefly remain in listpids. This is
        # never treated as empty; wait for BOTH views to become empty.
        if members not in ((),(pid,)):raise Refused('unattributed_group_survivor')
        if time.monotonic()>=end:raise Refused('process_exit_views_unsettled')
        time.sleep(.01)
