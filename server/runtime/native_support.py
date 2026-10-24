"""Fixed native primitives. No work is performed by importing this module."""
import contextlib
import ctypes
import errno
import fcntl
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import stat
import subprocess
import time
from mutation_spec import classification

BASE=Path('/usr/local/family-vpn/production-guardian')
STATE=Path('/private/var/db/family-vpn/production-guardian')
RUN=Path('/private/var/run/family-vpn/production-guardian')
CONF=Path('/usr/local/etc/family-vpn/production-guardian')
PFC=Path('/private/etc/pf.conf')
CHARON=Path('/usr/local/family-vpn/strongswan-6.1.0/libexec/ipsec/charon')
SWAN=CHARON.parents[2]/'sbin/swanctl'
SOCKET=Path('/private/var/run/family-vpn/charon.vici')
URI='unix:///var/run/family-vpn/charon.vici'
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C',
     'STRONGSWAN_CONF':str(RUN/'strongswan.conf'),
     'OPENSSL_MODULES':'/usr/local/family-vpn/openssl-3.5.9/lib/ossl-modules'}
LEGACY=tuple(Path('/private/var/db/family-vpn')/x for x in
    ['lan-full-test','lan-floor-test','lan-floor-lifecycle','wan-full-test','reconnect-test'])
SYS={'net.inet.ip.forwarding':1,'net.inet6.ip6.forwarding':1,
     'net.inet.ip.redirect':0,'net.inet6.ip6.redirect':0}
ESP='net.inet.ipsec.esp_port'


class Refused(RuntimeError):pass


def say(event,**values):
    print(json.dumps(dict(event=event,**values),sort_keys=True),flush=True)


DEADLINE=None
MUTATOR=None


def run(args,timeout=5,check=True):
    if DEADLINE is not None:
        timeout=min(timeout,DEADLINE-time.monotonic())
    if not 0<timeout<=30:raise Refused('command_budget')
    if classification(args)=='mutate':
        if MUTATOR is None:raise Refused('native_mutation_authority_unbound')
        return MUTATOR.run(args,timeout=timeout,check=check)
    # subprocess.run kills AND reaps its exact child on timeout; no detached
    # mutator/future can finish opening after this call has failed.
    p=subprocess.run([str(x) for x in args],stdin=subprocess.DEVNULL,capture_output=True,
        text=True,encoding='utf-8',errors='strict',env=ENV,timeout=timeout,close_fds=True,start_new_session=True)
    if len(p.stdout)>500000 or len(p.stderr)>100000:raise Refused('command_output_limit')
    if check and p.returncode:raise Refused('fixed_command_failed')
    return p


def signature(s):
    return tuple(getattr(s,k) for k in ['st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'])


@lru_cache(maxsize=1)
def _acl_api():
    # Cache function bindings only. Permission results are queried every time.
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_link_np.argtypes=[ctypes.c_char_p,ctypes.c_int]
    lib.acl_get_link_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p]
    lib.acl_free.restype=ctypes.c_int
    return lib


def _no_acl(path):
    # Path API covers Unix sockets too; it does not follow a target symlink.
    # Caller checks object identity/owner/mode around this fresh query.
    lib=_acl_api();ctypes.set_errno(0)
    acl=lib.acl_get_link_np(os.fsencode(path),0x100) # ACL_TYPE_EXTENDED
    error=ctypes.get_errno()
    if acl:
        try:raise Refused('extended_acl_refused')
        finally:
            if lib.acl_free(acl)!=0:raise Refused('acl_release_failed')
    if error!=errno.ENOENT:raise Refused('acl_status_unknown')


def _acl_identity(info):
    # Directory child creation changes its timestamps/link count, not its ACL
    # or trust ownership. Do not turn ordinary directory activity into failure.
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
            None if stat.S_ISDIR(info.st_mode) else info.st_nlink)


def trusted(path,mode=None):
    path=Path(path);first=path.lstat()
    if stat.S_ISLNK(first.st_mode):raise Refused('symlink_refused')
    resolved=path.resolve(strict=True)
    for item in [resolved,*resolved.parents]:
        s=item.lstat()
        run_parent=(item==Path('/private/var/run') and stat.S_ISDIR(s.st_mode)
                    and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,1,0o775))
        if s.st_uid!=0 or (s.st_mode&0o022 and not run_parent):raise Refused('mutable_root_path')
        if stat.S_ISLNK(s.st_mode):raise Refused('symlink_refused')
        _no_acl(item)
        if _acl_identity(item.lstat())!=_acl_identity(s):raise Refused('path_changed_during_acl_read')
    if mode is not None and stat.S_IMODE(first.st_mode)!=mode:raise Refused('path_mode')
    if stat.S_ISREG(first.st_mode) and first.st_nlink!=1:raise Refused('hardlink_refused')
    return first


def read(path,mode=0o600,limit=131072):
    path=Path(path);before=trusted(path,mode)
    if not stat.S_ISREG(before.st_mode) or before.st_size>limit:raise Refused('file_type_or_limit')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        opened=os.fstat(f.fileno());data=f.read(limit+1)
        if (signature(opened)!=signature(before) or signature(os.fstat(f.fileno()))!=signature(opened)
                or signature(path.lstat())!=signature(opened) or len(data)!=opened.st_size or len(data)>limit):
            raise Refused('file_changed_during_read')
    return data


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def directory(path):
    path=Path(path);trusted(path.parent)
    try:path.mkdir(mode=0o700)
    except FileExistsError:pass
    s=trusted(path,0o700)
    if not stat.S_ISDIR(s.st_mode) or s.st_gid not in (0,1):raise Refused('private_directory')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=(s.st_dev,s.st_ino):raise Refused('directory_replaced')
        os.fchown(fd,0,0) # only validated project directory, never system parent
    finally:os.close(fd)
    sync_dir(path.parent)


def atomic(path,data,mode=0o600):
    path=Path(path);trusted(path.parent)
    if path.exists() or path.is_symlink():read(path,mode=mode)
    data=data.encode() if isinstance(data,str) else data
    if len(data)>131072:raise Refused('write_limit')
    temp=path.parent/('.guardian-'+secrets.token_hex(12))
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
        os.replace(temp,path);sync_dir(path.parent)
    finally:
        if temp.exists():temp.unlink()


def json_value(data):
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise Refused('duplicate_json_key')
            out[k]=v
        return out
    def nonfinite(_):raise Refused('nonfinite_json_value')
    return json.loads(data,object_pairs_hook=unique,parse_constant=nonfinite)


def require_local_modules(names):
    """Refuse Python import-cache mixing with any prior native bundle."""
    import sys
    here=Path(__file__).resolve().parent
    for name in names:
        module=sys.modules.get(name)
        filename=getattr(module,'__file__',None)
        if type(filename)is not str or Path(filename).resolve()!=here/(name+'.py'):
            raise Refused('mixed_native_source_closure')


def closed_history(value):
    if (type(value)is not dict or type(value.get('version'))is not int or value['version']!=8
            or value.get('profile')!='production-native-fleet-v1' or value.get('allow_data')is not False
            or type(value.get('baseline'))is not dict or type(value.get('knobs'))is not dict):
        raise Refused('closed_forwarding_history_profile')
    if value.get('phase') in ('WAITING','ACTIVE'):
        raise Refused('closed_phase_contains_data_state')
    if any(key in value for key in ('gate_intent','activation_generation','child_seen')):
        raise Refused('closed_profile_contains_data_ownership')
    network=value.get('network')
    if network is not None and (type(network)is not dict or type(network.get('installed'))is not bool
            or network.get('mode') not in ('new','guarded','restored')):
        raise Refused('closed_profile_network_mode_unknown')
    for key in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding'):
        if type(value['baseline'].get(key))is not int or value['baseline'][key]!=0:
            raise Refused('closed_forwarding_baseline_not_zero')
        record=value['knobs'].get(key)
        if record is not None and (type(record)is not dict or set(record)!={'before','after','phase'}
                or type(record['before'])is not int or record['before']!=0
                or type(record['after'])is not int or record['after']!=0
                or record['phase'] not in ('untouched','apply-intent','applied','restore-intent','restored')):
            raise Refused('closed_forwarding_history_not_zero')


def session_history(value):
    import alf_transaction
    alf_transaction.validate_session(value)
    import probe_owner
    probe_owner.history(value)
    import fleet_session
    fleet_session.history(value)
    if 'production_run' in value:
        import production_source
        production_source.marker(value)
    if value['allow_data'] is False:closed_history(value)


class Store:
    def __init__(self):self.path=STATE/'native-session.json';self.durable=None
    def load(self):
        if not self.path.exists() and not self.path.is_symlink():return None
        value=json_value(read(self.path))
        import alf_transaction
        session_history(value)
        # No v2/v3/v4/v5 handoff: prior recoverers cannot interpret this mode contract.
        if (not isinstance(value,dict) or type(value.get('version'))is not int or value.get('version')!=8 or type(value.get('active')) is not bool
                or not isinstance(value.get('boot'),str) or not value['boot'] or value.get('phase') not in
                ['PREPARING','CLOSED_TEST','WAITING','ACTIVE','CLOSING','ATTENTION','RESTORED']):
            raise Refused('unknown_native_journal')
        if value['allow_data'] is False and value['phase'] in ('WAITING','ACTIVE'):
            raise Refused('closed_phase_contains_data_state')
        if value['active']!=(value['phase']!='RESTORED'):
            raise Refused('native_journal_phase_activity_mismatch')
        if not value['active']:
            mutation=value.get('mutation')
            if mutation is not None:
                # An outer RESTORED flag cannot hide an unfinished writer.
                # The import is delayed until load, after native_support has
                # initialized; record() is pure and never starts a process.
                from mutation_dispatch import Dispatcher
                record=Dispatcher(value,self).record()
                if record['phase']!='settled':raise Refused('restored_journal_has_unsettled_mutator')
            child=value.get('child')
            if child is not None and (not isinstance(child,dict) or child.get('phase')!='exited'):
                raise Refused('restored_journal_has_unsettled_child')
        self.durable=json_value(json.dumps(value));return value
    def save(self,value):
        import alf_transaction
        session_history(value)
        if self.durable is not None and self.durable.get('active') is True:
            session_history(self.durable)
            if (value['allow_data'] is not self.durable['allow_data']
                    or value['probe_mode'] != self.durable['probe_mode']
                    or value.get('fleet') != self.durable.get('fleet')):
                raise Refused('active_session_mode_change')
        raw=json.dumps(value,sort_keys=True,allow_nan=False)+'\n'
        atomic(self.path,raw)
        self.durable=json_value(raw)


@contextlib.contextmanager
def locks(*,check_legacy=True,create=False):
    files=[]
    try:
        for index,root in enumerate([STATE,*LEGACY]):
            path=root/'lock'
            if root.exists() or root.is_symlink():trusted(root,0o700)
            if index and not path.exists() and not path.is_symlink():
                prior=root/'session.json'
                if prior.exists() or prior.is_symlink():raise Refused('legacy_session_without_lock')
                continue
            trusted(root,0o700)
            if path.exists() or path.is_symlink():read(path)
            fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_CREAT if not index and create else 0),0o600)
            files.append(fd);s=trusted(path,0o600)
            if not stat.S_ISREG(s.st_mode) or signature(os.fstat(fd))!=signature(s):raise Refused('lock_changed')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if os.get_inheritable(fd):raise Refused('inherited_lock')
            prior=root/'session.json'
            if index and check_legacy and (prior.exists() or prior.is_symlink()):
                previous=json_value(read(prior))
                if (not isinstance(previous,dict) or type(previous.get('version'))is not int or
                        previous.get('version')!=1 or type(previous.get('active'))is not bool):
                    raise Refused('unknown_legacy_journal')
                if previous['active']:raise Refused('legacy_recovery_required')
        yield
    finally:
        for fd in reversed(files):os.close(fd)


def boot():return run(['/usr/sbin/sysctl','-n','kern.boottime']).stdout.strip()
def values():
    # Read the same four fixed knobs freshly in one process. Names and order
    # bind each value; this is not a cached or atomic kernel snapshot.
    result=run(['/usr/sbin/sysctl',*SYS])
    lines=result.stdout.splitlines()
    if result.stderr or len(lines)!=len(SYS):raise Refused('sysctl_values_output')
    current={}
    for key,line in zip(SYS,lines):
        prefix=key+': '
        if not line.startswith(prefix) or line[len(prefix):] not in ('0','1'):
            raise Refused('sysctl_values_output')
        current[key]=int(line[len(prefix):])
    return current
def digest(data):return hashlib.sha256(data).hexdigest()
def sad_empty():
    p=run(['/usr/sbin/setkey','-D'],check=False)
    return p.returncode==0 and p.stdout.strip()=='No SAD entries.' # never log SAD


class BSDInfo(ctypes.Structure):
    _fields_=[(x,ctypes.c_uint32) for x in ['flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved']]+[
        ('comm',ctypes.c_char*16),('name',ctypes.c_char*32)]+[(x,ctypes.c_uint32) for x in ['nfiles','pgid','jobc','tdev','tpgid']]+[
        ('nice',ctypes.c_int32),('started_sec',ctypes.c_uint64),('started_usec',ctypes.c_uint64)]


def process(pid):
    if type(pid)is not int or pid<=1:raise Refused('pid_format')
    lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    f=lib.proc_pidinfo;f.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int];f.restype=ctypes.c_int
    info=BSDInfo();n=f(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
    if n==0 and ctypes.get_errno() in (errno.ESRCH,errno.ENOENT):return None
    if n!=ctypes.sizeof(info) or info.pid!=pid:raise Refused('process_identity_unavailable')
    path=ctypes.create_string_buffer(4096);q=lib.proc_pidpath
    q.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];q.restype=ctypes.c_int
    if q(pid,path,len(path))<=0:raise Refused('process_path_unavailable')
    return dict(pid=pid,uid=info.uid,pgid=info.pgid,started_sec=info.started_sec,
                started_usec=info.started_usec,path=os.fsdecode(path.value))


def same_birth(current,owned):
    return current is not None and all(current[k]==owned[k] for k in
        ['pid','uid','pgid','started_sec','started_usec'])


def wait_ready(process,timeout=5):
    """Wait until the fixed Python gate has crossed any interpreter shim."""
    end=time.monotonic()+timeout;data=b'';fd=process.stdout.fileno()
    while len(data)<6:
        remaining=end-time.monotonic()
        if remaining<=0 or not select.select([fd],[],[],remaining)[0]:raise Refused('exec_gate_ready_timeout')
        chunk=os.read(fd,6-len(data))
        if not chunk:raise Refused('exec_gate_exited_before_ready')
        data+=chunk
    if data!=b'READY\n':raise Refused('exec_gate_bad_ready')


def group_members(pgid):
    if type(pgid)is not int or pgid<=1:raise Refused('pgid_format')
    lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    call=lib.proc_listpids
    call.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
    call.restype=ctypes.c_int
    # PROC_PGRP_ONLY=2 from the local libproc header. Bound the inventory and
    # refuse unknown/oversized groups rather than signalling a group wholesale.
    buffer=(ctypes.c_int*1024)()
    size=call(2,pgid,buffer,ctypes.sizeof(buffer))
    if size<0 or size>=ctypes.sizeof(buffer) or size%ctypes.sizeof(ctypes.c_int):raise Refused('group_inventory_unavailable')
    return sorted(x for x in list(buffer)[:size//ctypes.sizeof(ctypes.c_int)] if x)


def _forward_value(key,new=None):
    if key not in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding'] or new not in [None,0]:
        raise Refused('close_only_sysctl_scope')
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    call=lib.sysctlbyname
    call.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
    call.restype=ctypes.c_int
    old=ctypes.c_int();size=ctypes.c_size_t(ctypes.sizeof(old));zero=ctypes.c_int(0)
    if call(key.encode('ascii'),ctypes.byref(old),ctypes.byref(size),
            None if new is None else ctypes.byref(zero),0 if new is None else ctypes.sizeof(zero))!=0:
        raise Refused('close_only_sysctl_failed')
    if size.value!=ctypes.sizeof(old) or old.value not in [0,1]:raise Refused('forwarding_value_unknown')
    return old.value


def close_owned_forwarding(key,durable):
    """Synchronous close-only fallback: no child can outlive this writer."""
    if key not in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding']:
        raise Refused('close_only_sysctl_scope')
    session_history(durable)
    if durable['allow_data'] is False:
        # Same reviewed v4 closed behavior: there is no owned forward=1.
        if _forward_value(key)!=0:raise Refused('closed_forwarding_external_change')
        return
    if not isinstance(durable,dict) or durable.get('baseline',{}).get(key)!=0:
        raise Refused('exclusive_durable_forwarding_baseline_required')
    current=_forward_value(key)
    if current==1:
        record=durable.get('knobs',{}).get(key,{})
        if (record.get('before'),record.get('after'))!=(0,1) or record.get('phase') not in [
                'apply-intent','applied','restore-intent']:
            raise Refused('forwarding_not_durably_owned')
        _forward_value(key,0)
    if _forward_value(key)!=0:raise Refused('forwarding_close_unverified')
