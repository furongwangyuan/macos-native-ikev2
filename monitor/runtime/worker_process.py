"""Bounded sampling of one exact owned worker, in the launchd job group.

No group signals, arbitrary commands, VPN control or private data logging.
Deadlines are cooperative user-space limits, not a guarantee during kernel stalls.
"""
import ctypes
import json
import math
import os
import selectors
import subprocess

COMMAND=('/usr/bin/python3','-I','-B','/usr/local/family-vpn/monitor/worker.py')
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}
LIMIT=131072


class ClockScale(ctypes.Structure):
    _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]


_lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
_lib.mach_continuous_time.argtypes=[]
_lib.mach_continuous_time.restype=ctypes.c_uint64
_lib.mach_timebase_info.argtypes=[ctypes.POINTER(ClockScale)]
_lib.mach_timebase_info.restype=ctypes.c_int
_scale=ClockScale()
if _lib.mach_timebase_info(ctypes.byref(_scale))!=0 or not _scale.numer or not _scale.denom:
    raise RuntimeError('monitor clock unavailable')


def continuous_seconds():
    return _lib.mach_continuous_time()*_scale.numer/_scale.denom/1e9


class CleanupFailure(RuntimeError):
    """Collector must exit instead of accumulating uncertain workers."""


def cleanup(child):
    failure=None
    try:
        if child.poll() is None:
            child.terminate()
            try: child.wait(timeout=.2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=1)
    except (OSError,subprocess.SubprocessError) as error:
        failure=error
    finally:
        if child.stdout is not None:
            try: child.stdout.close()
            except OSError as error: failure=error
    if failure is not None: raise CleanupFailure('owned sampler cleanup incomplete') from failure


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate sample field')
        result[key]=value
    return result


def finite_float(text):
    value=float(text)
    if not math.isfinite(value):raise ValueError('nonfinite sample')
    return value


def bounded_int(text):
    if len(text.lstrip('-'))>20:raise ValueError('oversized sample integer')
    return int(text)


def query_worker(popen=subprocess.Popen,clock=continuous_seconds):
    # An injected popen is only an ordinary test seam; production always supplies
    # this exact command. Workers and their fixed read commands retain the job's
    # process group for launchd's default non-abandoning cleanup on collector exit.
    deadline=clock()+3
    child=None
    try:
        child=popen(list(COMMAND),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,env=ENV,close_fds=True,start_new_session=False)
        if child.stdout is None: raise ValueError('missing sample pipe')
        fd=child.stdout.fileno(); os.set_blocking(fd,False)
        raw=bytearray()
        with selectors.DefaultSelector() as ready:
            ready.register(fd,selectors.EVENT_READ)
            while True:
                remaining=deadline-clock()
                if remaining<=0: return None
                events=ready.select(min(remaining,.2))
                if not events: continue
                try: block=os.read(fd,min(8192,LIMIT+1-len(raw)))
                except BlockingIOError: continue
                if not block: break
                raw.extend(block)
                if len(raw)>LIMIT: return None
        remaining=deadline-clock()
        if remaining<=0: return None
        child.wait(timeout=remaining)
        if child.returncode or clock()>deadline: return None
        result=json.loads(raw,object_pairs_hook=unique,parse_float=finite_float,parse_int=bounded_int,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite sample')))
        required={'server_running','wall','mono','rows','registry_sha256','registry_revision'}
        if clock()>deadline or type(result) is not dict or set(result) not in (required,required|{'unknown_devices'}):
            return None
        return result
    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
        return None
    finally:
        if child is not None: cleanup(child)
