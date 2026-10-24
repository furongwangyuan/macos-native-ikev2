"""Small private-file transaction I/O; no production operation on import."""
import contextlib, fcntl, hashlib, json, math, os, secrets, stat
from pathlib import Path
from snapshot_io import _acl_absent

class Refused(RuntimeError): pass
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encode(value): return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def pairs(rows):
    out={}
    for k,v in rows:
        if k in out: raise Refused('duplicate_json')
        out[k]=v
    return out
def number(text):
    value=float(text)
    if not math.isfinite(value): raise Refused('nonfinite_json')
    return value
def decode(raw):
    if type(raw)is not bytes or len(raw)>2097152: raise Refused('json_limit')
    return json.loads(raw,object_pairs_hook=pairs,parse_float=number,
        parse_constant=lambda _:(_ for _ in ()).throw(Refused('nonfinite_json')))
def stamp(st): return (st.st_dev,st.st_ino,st.st_uid,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

class IO:
    def __init__(self,root,uid):
        self.root=Path(root).absolute();self.uid=uid
        self.directory(self.root,create=False)
    def metadata(self,fd,directory=False):
        st=os.fstat(fd)
        if (st.st_uid!=self.uid or stat.S_IMODE(st.st_mode)!=(0o700 if directory else 0o600)
                or not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))
                or (not directory and st.st_nlink!=1)): raise Refused('private_metadata')
        _acl_absent(fd)
        if stamp(os.fstat(fd))!=stamp(st): raise Refused('metadata_changed')
        return st
    def path(self,path):
        path=Path(path).absolute()
        if path!=self.root and self.root not in path.parents: raise Refused('outside_private_root')
        relative=path.relative_to(self.root)
        if '..' in relative.parts: raise Refused('relative_escape')
        return path
    def directory(self,path,create=False):
        path=self.path(path) if hasattr(self,'root') else Path(path)
        if create:
            self.directory(path.parent);path.mkdir(mode=0o700);self.sync(path.parent)
        # Every retained component within this private root has the same owner
        # and no ACL/symlink. Native wrapper separately verifies root ancestors.
        chain=[self.root]+[self.root.joinpath(*path.relative_to(self.root).parts[:i])
            for i in range(1,len(path.relative_to(self.root).parts)+1)]
        for item in chain:
            fd=os.open(item,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:self.metadata(fd,True)
            finally:os.close(fd)
        return path
    def exists(self,path):
        path=self.path(path);self.directory(path.parent)
        try:path.lstat();return True
        except FileNotFoundError:return False
    def read(self,path,limit=1048576):
        path=self.path(path);self.directory(path.parent)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=self.metadata(fd)
            if before.st_size>limit:raise Refused('file_limit')
            out=bytearray()
            while len(out)<=limit:
                data=os.read(fd,min(65536,limit+1-len(out)))
                if not data:break
                out.extend(data)
            if len(out)>limit or len(out)!=before.st_size or stamp(self.metadata(fd))!=stamp(before) or stamp(path.lstat())!=stamp(before):raise Refused('file_changed')
            return bytes(out)
        finally:os.close(fd)
    def sync(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:self.metadata(fd,True);os.fsync(fd)
        finally:os.close(fd)
    def put(self,path,raw,*,before=None):
        path=self.path(path);self.directory(path.parent)
        if type(raw)is not bytes or len(raw)>2097152:raise Refused('write_limit')
        if self.exists(path):
            old=self.read(path,2097152)
            if old==raw:return
            if before is None or old!=before:raise Refused('publication_conflict')
        elif before is not None:raise Refused('publication_missing')
        tmp=path.parent/('.pki-'+secrets.token_hex(12));fd=None
        try:
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            offset=0
            while offset<len(raw):
                n=os.write(fd,raw[offset:])
                if n<=0:raise Refused('short_write')
                offset+=n
            os.fchmod(fd,0o600);os.fsync(fd);os.close(fd);fd=None
            if before is None:
                os.link(tmp,path,follow_symlinks=False);tmp.unlink()
            else:
                if self.read(path,2097152)!=before:raise Refused('publication_race')
                os.replace(tmp,path)
            self.sync(path.parent)
            if self.read(path,2097152)!=raw:raise Refused('publication_readback')
        finally:
            if fd is not None:os.close(fd)
            if tmp.exists():tmp.unlink()
    @contextlib.contextmanager
    def lock(self,path):
        # Never creates a replacement for the original provisioner lock.
        self.read(path,4096);fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
        try:
            before=self.metadata(fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            def held():
                self.metadata(fd)
                if stamp(os.fstat(fd))!=stamp(before) or stamp(Path(path).lstat())!=stamp(before):raise Refused('original_lock_changed')
            held();yield held
        finally:os.close(fd)
