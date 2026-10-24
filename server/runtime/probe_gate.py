#!/usr/bin/python3
"""Fixed root READY/GO gate; execs one ordinary non-forking synthetic C child."""
import os,select,stat,sys,time,resource
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import probe_contract as c
import probe_paths

def receive(fd,clock=time.monotonic):
 data=b'';end=clock()+5
 while b'\n' not in data:
  left=end-clock()
  if left<=0 or not select.select([fd],[],[],left)[0]:return None
  more=os.read(fd,min(1025-len(data),1024))
  if not more:return None
  data+=more
  if len(data)>1024:return None
 if data.count(b'\n')!=1 or not data.endswith(b'\n'):return None
 try:return c.frame(c.decode(data))
 except Exception:return None

def gate(fd,execute,clock=time.monotonic,ready_fd=1):
 os.write(ready_fd,b'PROBE_GATE_READY\n');value=receive(fd,clock)
 if value is None:return 2
 # Owner retains sole write pipe through C-ready. EOF/extra bytes visible now
 # are not accepted; after this GO boundary recovery owns parent-death cleanup.
 if select.select([fd],[],[],0)[0]:return 2
 execute(value);return 2

def drop_identity(api=os):
 api.setgroups([]);api.setgid(c.GID);api.setuid(c.UID)
 if (api.getuid()!=c.UID or api.geteuid()!=c.UID or api.getgid()!=c.GID or api.getegid()!=c.GID or not set(api.getgroups())<={c.GID}):raise c.Refused('drop_identity_unverified')

def execute(value):
 c.frame(value);probe_paths.payload()
 limit=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
 if type(limit)is not int or not 3<=limit<=1048576:raise c.Refused('fd_limit_unknown')
 drop_identity()
 fd=os.open('/dev/null',os.O_RDONLY)
 try:os.dup2(fd,0)
 finally:
  if fd!=0:os.close(fd)
 os.closerange(3,limit);os.chdir('/')
 os.execve(str(c.BINARY),[str(c.BINARY),'--vpn-peer',value['peer'],'--seconds',str(value['seconds'])],c.ENV)

def main():
 if len(sys.argv)!=1 or os.geteuid()!=0 or Path(__file__)!=c.GATE:return 2
 if not stat.S_ISFIFO(os.fstat(0).st_mode) or os.getpgrp()!=os.getpid():return 2
 probe_paths.gate_source();probe_paths.payload()
 return gate(0,execute)
if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception:raise SystemExit(2)
