#!/usr/bin/python3
"""Fixed, root-only, read-only VICI sample worker; stdout is sanitized JSON only.

The supervisor must enforce a 3-second process deadline. The official library
temporarily disables socket timeouts during partial reads. No control commands
or SAD/key APIs exist in this worker's reachable path.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time

BASE=Path('/usr/local/family-vpn/monitor')
SOCKET=Path('/var/run/family-vpn/charon.vici')
CHARON='/usr/local/family-vpn/strongswan-6.1.0/libexec/ipsec/charon'
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'}

class BoundedSocket:
    """Cap inbound VICI frames without changing the official library.

    It may receive a four-byte frame header in several reads. The body length
    is checked before handing that completed header to Transport, so a huge
    advertised size never becomes a huge recv() request/allocation.
    Limits bound wire input, not a claimed exact Python process-memory ceiling.
    """
    def __init__(self,sock,frame_limit=65536,total_limit=1048576,frame_count=64):
        self.sock=sock;self.frame_limit=frame_limit;self.total_limit=total_limit;self.frame_count=frame_count
        self.header=bytearray();self.remaining=None;self.received=0;self.frames=0
        self.deadline=time.monotonic()+1.5

    def remaining_time(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('VICI sample deadline')
        return remaining

    def recv(self,count):
        if type(count) is not int or count<=0 or self.received>=self.total_limit:raise ValueError('bounded VICI input exhausted')
        section=4-len(self.header) if self.remaining is None else self.remaining
        self.sock.settimeout(self.remaining_time())
        data=self.sock.recv(min(count,section,self.total_limit-self.received))
        self.received+=len(data)
        if self.remaining is None:
            self.header.extend(data)
            if len(self.header)==4:
                length=int.from_bytes(self.header,'big');self.frames+=1
                if not 1<=length<=self.frame_limit or self.frames>self.frame_count:raise ValueError('bounded VICI frame exceeded')
                self.remaining=length;self.header.clear()
        else:
            self.remaining-=len(data)
            if not self.remaining:self.remaining=None
        return data

    def sendall(self,data):
        self.sock.settimeout(self.remaining_time())
        return self.sock.sendall(data)
    def gettimeout(self):return min(self.sock.gettimeout() or self.remaining_time(),self.remaining_time())
    def settimeout(self,value):
        remaining=self.remaining_time()
        return self.sock.settimeout(remaining if value is None else min(value,remaining))

def trusted(path, mode=None):
    path=Path(path);s=path.lstat()
    if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or (mode is not None and stat.S_IMODE(s.st_mode)!=mode):
        raise ValueError('untrusted fixed telemetry path')
    for p in (path.resolve(strict=True),*path.resolve(strict=True).parents):
        s=p.stat()
        system_run=p==Path('/private/var/run') and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,1,0o775)
        if s.st_uid!=0 or (s.st_mode&0o022 and not system_run):raise ValueError('mutable telemetry parent')
    return path

def read_command(args):
    # Call sites below are fixed commands with a single validated numeric PID.
    return subprocess.run(args,capture_output=True,text=True,encoding='ascii',errors='strict',env=ENV,timeout=0.7)

def daemon_identity():
    boot=read_command(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'])
    if boot.returncode or boot.stderr or not re.fullmatch(r'[0-9A-Fa-f-]{36}\s*',boot.stdout):raise ValueError('boot identity unavailable')
    found=read_command(['/usr/bin/pgrep','-x','charon'])
    if found.returncode==1 and found.stdout=='' and found.stderr=='':return None
    if found.returncode or found.stderr or not re.fullmatch(r'[1-9][0-9]*\s*',found.stdout):raise ValueError('daemon inventory ambiguous')
    pid=int(found.stdout.strip())
    proc=read_command(['/bin/ps','-p',str(pid),'-o','uid=,lstart=,comm='])
    if proc.returncode or proc.stderr or not re.fullmatch(r'\s*0\s+.+?\s+'+re.escape(CHARON),proc.stdout.strip()):raise ValueError('daemon identity unavailable')
    # The reviewed daemon creates mode 0660; its root-only parent is the access
    # boundary. Applying a regular-file no-group-write rule to the socket itself
    # would reject that supported mode before querying anything.
    trusted(SOCKET.parent,0o700)
    info=SOCKET.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode) not in (0o600,0o660):raise ValueError('unexpected VICI socket')
    return (boot.stdout.strip().lower(),pid,proc.stdout.strip(),info.st_dev,info.st_ino,info.st_ctime_ns)

def read_events(session_factory):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(0.7);sock.connect(str(SOCKET))
        session=session_factory(BoundedSocket(sock))
        # Query the complete inventory once. Per-name queries could silently
        # miss a registered device during a registry or connection transition.
        events=[]
        for event in session.list_sas({}):
            events.append(event)
            if len(events)>48:raise ValueError('excessive inventory')
        return events


def sample(session_factory, *, identify=daemon_identity, events=read_events,
           read_registry=None, wall=time.time, mono=time.monotonic):
    from source import parse_events
    from registry_source import read_registry as fixed_reader
    reader=fixed_reader if read_registry is None else read_registry
    registered=reader()
    before=identify()
    if before is None:
        if identify() is not None:raise ValueError('daemon appeared during sample')
        now=wall();rows=[];unknown=[];running=False
    else:
        epoch=hashlib.sha256(json.dumps(before,separators=(',',':')).encode('ascii')).hexdigest()
        selected=events(session_factory)
        if identify()!=before:raise ValueError('daemon changed during sample')
        now=wall();running=True
        inventory=parse_events(selected,epoch,now,registered.value,allow_legacy_device01=True,with_unknown=True)
        rows=inventory['rows'];unknown=inventory['unknown_devices']
    after=reader()
    if after.raw!=registered.raw or after.sha256!=registered.sha256:
        raise ValueError('registry changed during sample')
    return dict(server_running=running,wall=now,mono=mono(),rows=rows,unknown_devices=unknown,
                registry_sha256=registered.sha256,registry_revision=registered.value['revision'])


def main():
    if os.geteuid()!=0 or Path(__file__)!=BASE/'worker.py' or len(sys.argv)!=1:
        raise ValueError('fixed root telemetry installation required')
    trusted(BASE,0o700)
    for name in ('source.py','registry.py','registry_source.py','journal_acl.py'):
        trusted(BASE/name,0o600)
    vendor=trusted(BASE/'vendor',0o700)
    manifest=trusted(BASE/'vendor-pins.json',0o600)
    pins=json.loads(manifest.read_text())
    expected={'__init__.py','session.py','protocol.py','command_wrappers.py','event_listener.py','exception.py'}
    if set(pins)!=expected:raise ValueError('unexpected official VICI module set')
    for name,digest in pins.items():
        source=trusted(vendor/'vici'/name,0o600)
        if hashlib.sha256(source.read_bytes()).hexdigest()!=digest:raise ValueError('official VICI source pin differs')
    sys.path.insert(0,str(BASE));sys.path.insert(0,str(vendor))
    import vici
    result=sample(vici.Session)
    output=json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(output)>131072:raise ValueError('sample too large')
    print(output,flush=True)

if __name__=='__main__':
    try:main()
    except Exception:
        # No raw VICI, addresses, command stderr, exception details, or keys.
        sys.exit(1)
