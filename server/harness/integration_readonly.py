"""Three additional fixed read commands; no generic command execution surface."""
import os
import re
import selectors
import subprocess
import time
from types import SimpleNamespace
from fault_protocol import Refused

SOCKET='/private/var/run/family-vpn/charon.vici'


def allowed(args):
    if type(args)is not list or any(type(x)is not str for x in args):return False
    if args==['/bin/launchctl','print','system/org.familyvpn.guardian-recovery']:return True
    if args==['/usr/sbin/lsof','-nP','-F','p',SOCKET]:return True
    return (len(args)==8 and args[:4]==['/usr/sbin/lsof','-nP','-a','-p']
            and re.fullmatch('[1-9][0-9]{0,9}',args[4]) is not None and int(args[4])>1
            and args[5:]==['-iTCP','-F','pftn'])


def _finish(proc,sel):
    errors=[]
    if proc is not None:
        try:
            if proc.poll() is None:proc.kill()
        except BaseException as error:errors.append(error)
        try:proc.wait(timeout=1)
        except BaseException as error:errors.append(error)
    if sel is not None:
        try:sel.close()
        except BaseException as error:errors.append(error)
    if proc is not None:
        for stream in (proc.stdout,proc.stderr):
            if stream is not None:
                try:stream.close()
                except BaseException as error:errors.append(error)
    if errors:raise Refused('integration_read_cleanup_unverified') from errors[-1]


def run(args):
    args=[str(x) for x in args]
    if not allowed(args):raise Refused('integration_read_command_not_listed')
    proc=None;sel=None;buffers={};end=time.monotonic()+5
    try:
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            close_fds=True,start_new_session=True,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C','LANG':'C'})
        sel=selectors.DefaultSelector()
        for fd in (proc.stdout,proc.stderr):
            os.set_blocking(fd.fileno(),False);sel.register(fd,selectors.EVENT_READ);buffers[fd]=bytearray()
        while sel.get_map():
            left=end-time.monotonic()
            if left<=0:raise Refused('integration_read_deadline')
            events=sel.select(left)
            if not events:raise Refused('integration_read_deadline')
            for key,_ in events:
                more=os.read(key.fileobj.fileno(),8192)
                if not more:sel.unregister(key.fileobj);continue
                buffers[key.fileobj].extend(more)
                if sum(map(len,buffers.values()))>65536:raise Refused('integration_read_limit')
        left=end-time.monotonic()
        if left<=0:raise Refused('integration_read_deadline')
        result=proc.wait(timeout=left)
        if time.monotonic()>=end:raise Refused('integration_read_deadline')
        return SimpleNamespace(returncode=result,stdout=bytes(buffers[proc.stdout]).decode('utf-8'),
                               stderr=bytes(buffers[proc.stderr]).decode('utf-8'))
    finally:_finish(proc,sel)
