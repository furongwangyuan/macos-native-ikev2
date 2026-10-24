"""Fixed public executable/root source checks; ordinary private test helper only."""
import ctypes,errno,hashlib,os,stat
from pathlib import Path
import probe_contract as c

def no_acl(fd):
 lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
 lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int];lib.acl_get_fd_np.restype=ctypes.c_void_p
 lib.acl_free.argtypes=[ctypes.c_void_p];lib.acl_free.restype=ctypes.c_int;ctypes.set_errno(0)
 value=lib.acl_get_fd_np(fd,0x100);error=ctypes.get_errno()
 if value:
  try:raise c.Refused('extended_acl')
  finally:
   if lib.acl_free(value)!=0:raise c.Refused('acl_free_failed')
 if error!=errno.ENOENT:raise c.Refused('unknown_acl')
def stamp(st):return tuple(getattr(st,k) for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def _read_at(root,parts,uid,mode,limit):
 fds=[];states=[]
 def check(fd,final):
  v=os.fstat(fd)
  if v.st_uid!=uid or v.st_mode&0o7022:raise c.Refused('untrusted_path_metadata')
  if final:
   if not stat.S_ISREG(v.st_mode) or v.st_nlink!=1 or stat.S_IMODE(v.st_mode)!=mode or not 0<v.st_size<=limit:raise c.Refused('untrusted_file')
  elif not stat.S_ISDIR(v.st_mode):raise c.Refused('untrusted_directory')
  no_acl(fd)
  if stamp(os.fstat(fd))!=stamp(v):raise c.Refused('metadata_changed')
  return stamp(v)
 if type(parts)is not tuple or not parts or any(type(x)is not str or not x or x in('.','..') or '/' in x or '\0' in x for x in parts):raise c.Refused('relative_scope')
 try:
  fds.append(os.dup(root));states.append(check(fds[-1],False))
  for i,part in enumerate(parts):
   final=i==len(parts)-1;flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
   if not final:flags|=os.O_DIRECTORY
   fd=os.open(part,flags,dir_fd=fds[-1]);fds.append(fd);states.append(check(fd,final))
  chunks=[];count=0
  while True:
   chunk=os.read(fds[-1],min(65536,limit+1-count))
   if not chunk:break
   count+=len(chunk)
   if count>limit:raise c.Refused('file_bound')
   chunks.append(chunk)
  raw=b''.join(chunks)
  if len(raw)!=os.fstat(fds[-1]).st_size:raise c.Refused('file_size_changed')
  for i,fd in enumerate(fds):
   if check(fd,i==len(fds)-1)!=states[i]:raise c.Refused('path_changed')
  for i,part in enumerate(parts,1):
   if stamp(os.stat(part,dir_fd=fds[i-1],follow_symlinks=False))!=states[i]:raise c.Refused('name_changed')
  return raw
 finally:
  errors=[]
  for fd in reversed(fds):
   try:os.close(fd)
   except OSError as e:errors.append(e)
  if errors:raise c.Refused('path_fd_cleanup_failed') from errors[-1]
def fixed_read(path,mode,limit):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:return _read_at(fd,tuple(path.parts[1:]),0,mode,limit)
 finally:os.close(fd)
def payload():
 raw=fixed_read(c.BINARY,0o755,2*1024*1024)
 if hashlib.sha256(raw).hexdigest()!=c.BINARY_SHA:raise c.Refused('fixed_binary_hash_changed')
 # Every ancestor must be executable by the ordinary target; don't alter it.
 for path in (c.PUBLIC,*c.PUBLIC.parents):
  if stat.S_IMODE(path.lstat().st_mode)&0o005!=0o005:raise c.Refused('ordinary_exec_path_not_searchable')
 return True
def gate_source():
 for name in ('probe_gate.py','probe_contract.py','probe_paths.py'):
  fixed_read(c.BASE/name,0o600,65536)
 if stat.S_IMODE(c.BASE.lstat().st_mode)!=0o700:raise c.Refused('private_gate_directory')
 return True
