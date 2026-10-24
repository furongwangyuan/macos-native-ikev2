#!/usr/bin/python3
"""Fixed current-boot mutator gate. EOF/no complete bound GO never executes."""
import json,os,select,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import boot_record as r


def frame_read(fd,clock=time.monotonic):
    end=clock()+5;data=b''
    while b'\n' not in data:
        left=end-clock()
        if left<=0 or not select.select([fd],[],[],left)[0]:return None
        chunk=os.read(fd,min(4097-len(data),1024))
        if not chunk:return None
        data+=chunk
        if len(data)>4096:return None
    if data.count(b'\n')!=1 or not data.endswith(b'\n'):return None
    try:frame=r.s.json_value(data)
    except (ValueError,UnicodeError,r.s.Refused):return None
    if (type(frame)is not dict or set(frame)!={'version','profile','go','boot','intent_sha256','argv'}
            or type(frame['version'])is not int or frame['version']!=1 or frame['profile']!=r.PROFILE
            or frame['go'] is not True or type(frame['boot'])is not str or not frame['boot']
            or not r.exact_hash(frame['intent_sha256'])):return None
    try:r.command(frame['argv'])
    except r.Refused:return None
    return frame


def gate(fd,authorize,execute,clock=time.monotonic,ready_fd=None):
    if ready_fd is not None:os.write(ready_fd,b'READY\n')
    frame=frame_read(fd,clock)
    if frame is None:return 2
    try:authorize(frame)
    except Exception:return 2
    execute(frame['argv']);return 2


def authorize_installed(frame):
    import native_support as s
    import boot_native
    import service_supervisor
    record=r.validate(s.json_value(s.read(boot_native.RECORD)))
    raw=[s.read(boot_native.ARCHIVES/(kind+'-'+record[key]+'.json'),limit=262144) for kind,key in
         [('native','native_sha256'),('context','context_sha256')]]
    old=r.bind(record,*raw);intent=record['intent'];mutation=record['mutation']
    installed=boot_native.Native();installed.lease=True # Parent holds same system locks across READY/GO/reap.
    if (record['phase']!='RESTORING' or s.boot()!=record['new_boot'] or frame['boot']!=record['new_boot']
            or service_supervisor.read_configuration().fingerprint!=record['configuration_sha256']
            or installed.implementation()!=record['implementation_sha256']
            or intent is None or intent['effect']!={'kind':'command','argv':frame['argv']}
            or frame['intent_sha256']!=r.sha(r.encode(intent)) or intent['effect']!=r.effect(old,intent['key'])
            or mutation is None or mutation['phase']!='go-intent' or mutation['argv']!=frame['argv']
            or mutation['identity']!=s.process(os.getpid()) or mutation['identity']['uid']!=0):
        raise r.Refused('boot_gate_durable_binding')
    if installed.originals()!=tuple(raw):
        raise r.Refused('boot_gate_originals_changed')


def main():
    import native_support as s
    if os.geteuid()!=0 or Path(__file__)!=s.BASE/'boot_mutation_gate.py' or len(sys.argv)!=1:return 2
    s.trusted(s.BASE,0o700);s.trusted(Path(__file__),0o600)
    if not stat.S_ISFIFO(os.fstat(0).st_mode) or os.getpgrp()!=os.getpid():return 2
    def execute(argv):
        fd=os.open('/dev/null',os.O_RDONLY)
        try:os.dup2(fd,0)
        finally:os.close(fd)
        os.execve(argv[0],argv,{'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'})
    return gate(0,authorize_installed,execute,ready_fd=1)

if __name__=='__main__':sys.exit(main())
