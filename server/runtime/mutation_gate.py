#!/usr/bin/python3
"""Fixed finite mutator exec gate; EOF/no complete GO never executes."""
import json
import os
from pathlib import Path
import select
import stat
import sys
import time

BASE=Path('/usr/local/family-vpn/production-guardian')
sys.path.insert(0,str(Path(__file__).parent))
from mutation_spec import require_for_mode
from alf_transaction import PROFILE


def frame_read(fd,clock=time.monotonic):
    end=clock()+5;data=b''
    while b'\n' not in data:
        remaining=end-clock()
        if remaining<=0 or not select.select([fd],[],[],remaining)[0]:return None
        chunk=os.read(fd,min(4097-len(data),1024))
        if not chunk:return None
        data+=chunk
        if len(data)>4096:return None
    if not data.endswith(b'\n') or data.count(b'\n')!=1:return None
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate')
            value[key]=item
        return value
    try:value=json.loads(data,object_pairs_hook=unique)
    except (UnicodeError,ValueError):return None
    if (not isinstance(value,dict) or set(value)!={'version','profile','allow_data','go','argv'} or
            type(value['version'])is not int or value['version']!=2 or value['profile']!=PROFILE
            or type(value['allow_data'])is not bool or value['go'] is not True):return None
    try:return require_for_mode(value['argv'],value['allow_data'])
    except ValueError:return None


def gate(fd,exec_fixed,clock=time.monotonic,ready_fd=None):
    if ready_fd is not None:os.write(ready_fd,b'READY\n')
    argv=frame_read(fd,clock)
    if argv is None:return 2
    exec_fixed(argv)
    return 2


def main():
    if os.geteuid()!=0 or Path(__file__)!=BASE/'mutation_gate.py' or len(sys.argv)!=1:return 2
    info=BASE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:return 2
    if not stat.S_ISFIFO(os.fstat(0).st_mode) or os.getpgrp()!=os.getpid():return 2
    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C',
         'STRONGSWAN_CONF':'/private/var/run/family-vpn/production-guardian/strongswan.conf',
         'OPENSSL_MODULES':'/usr/local/family-vpn/openssl-3.5.9/lib/ossl-modules'}
    def execute(argv):
        fd=os.open('/dev/null',os.O_RDONLY);os.dup2(fd,0);os.close(fd)
        os.execve(argv[0],list(argv),env)
    return gate(0,execute,ready_fd=1)


if __name__=='__main__':sys.exit(main())
