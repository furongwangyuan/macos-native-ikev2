"""Fixed root metadata preservation. No private key/database paths or CLI."""
import os,stat
from pathlib import Path
import native_support as s
import boot_native as native
import boot_record as r

class Store:
    def __init__(self,io):self.io=io;self.previous=None;self.durable=None
    def write_new(self,path,data):
        self.io.held();s.trusted(path.parent,0o700)
        if path.exists() or path.is_symlink():
            if s.read(path,limit=393216)!=data:raise r.Refused('existing_archive_differs')
            return
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb',closefd=False) as f:
                f.write(data);f.flush();os.fchmod(fd,0o600);os.fsync(fd)
        finally:os.close(fd)
        s.sync_dir(path.parent)
        if s.read(path,limit=393216)!=data:raise r.Refused('archive_readback_failed')
    def preserve(self,native_raw,context_raw):
        self.io.held()
        for kind,raw in [('native',native_raw),('context',context_raw)]:
            if type(raw)is not bytes or len(raw)>(131072 if kind=='native' else 393216):raise r.Refused('original_size')
            self.write_new(native.ARCHIVES/(kind+'-'+r.sha(raw)+'.json'),raw)
    def originals(self,record):
        self.io.held();r.validate(record)
        out=[]
        for kind,key in [('native','native_sha256'),('context','context_sha256')]:
            raw=s.read(native.ARCHIVES/(kind+'-'+record[key]+'.json'),limit=393216)
            if r.sha(raw)!=record[key]:raise r.Refused('original_hash_changed')
            out.append(raw)
        return tuple(out)
    def load(self):
        self.io.held()
        if not native.RECORD.exists() and not native.RECORD.is_symlink():self.previous=None;self.durable=None;return None
        raw=s.read(native.RECORD);value=r.validate(s.json_value(raw));self.previous=raw;self.durable=s.json_value(raw);return value
    def save(self,record):
        self.io.held();r.validate(record)
        if self.previous is None:
            self.write_new(native.RECORD,r.encode(record))
        else:
            if s.read(native.RECORD)!=self.previous:raise r.Refused('boot_record_changed')
            s.atomic(native.RECORD,r.encode(record))
        self.previous=s.read(native.RECORD)
        if self.previous!=r.encode(record):raise r.Refused('boot_record_readback')
        self.durable=s.json_value(self.previous)
