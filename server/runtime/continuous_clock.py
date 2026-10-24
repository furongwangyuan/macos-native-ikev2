"""Read-only Darwin continuous clock, converted in this guardian process."""
import ctypes
import sys


def make_clock():
    if sys.platform != 'darwin':
        raise RuntimeError('Darwin continuous clock required')
    class Timebase(ctypes.Structure):
        _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    lib.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
    lib.mach_timebase_info.restype = ctypes.c_int
    lib.mach_continuous_time.argtypes = []
    lib.mach_continuous_time.restype = ctypes.c_uint64
    base = Timebase()
    if lib.mach_timebase_info(ctypes.byref(base)) or not base.numer or not base.denom:
        raise RuntimeError('Invalid native clock timebase')
    return lambda: lib.mach_continuous_time() * base.numer / base.denom / 1_000_000_000
