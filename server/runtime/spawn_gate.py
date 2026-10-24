#!/usr/bin/python3
"""Fixed charon exec gate. EOF/no GO exits without starting the daemon."""
import os
from pathlib import Path
import select
import stat
import sys
import time

BASE=Path('/usr/local/family-vpn/production-guardian')
CHARON='/usr/local/family-vpn/strongswan-6.1.0/libexec/ipsec/charon'


def gate(fd,exec_fixed,clock=time.monotonic,ready_fd=None):
    if ready_fd is not None:os.write(ready_fd,b'READY\n')
    end=clock()+5;data=b''
    while len(data)<3:
        remaining=end-clock()
        if remaining<=0:return 2
        if not select.select([fd],[],[],remaining)[0]:return 2
        chunk=os.read(fd,3-len(data))
        if not chunk:return 2
        data+=chunk
    if data!=b'GO\n':return 2
    exec_fixed()
    return 2


def main():
    if os.geteuid()!=0 or Path(__file__)!=BASE/'spawn_gate.py' or len(sys.argv)!=1:return 2
    st=BASE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o700:return 2
    if not stat.S_ISFIFO(os.fstat(0).st_mode) or os.getpgrp()!=os.getpid():return 2
    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C',
         'STRONGSWAN_CONF':'/private/var/run/family-vpn/production-guardian/strongswan.conf',
         'OPENSSL_MODULES':'/usr/local/family-vpn/openssl-3.5.9/lib/ossl-modules'}
    def launch():
        fd=os.open('/dev/null',os.O_RDONLY);os.dup2(fd,0);os.close(fd)
        fd=os.open('/dev/null',os.O_WRONLY);os.dup2(fd,1);os.close(fd)
        os.execve(CHARON,[CHARON],env)
    return gate(0,launch,ready_fd=1)


if __name__=='__main__':sys.exit(main())
