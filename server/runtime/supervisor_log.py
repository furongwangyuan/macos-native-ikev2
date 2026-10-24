"""Fixed bounded metadata log; no exception, identity, address or payload text."""
import json
import native_support as s
from supervisor_core import PHASES,REASONS

LIMIT=65536
ARCHIVES=3


class EventLog:
    def __init__(self,path=None,*,read=None,write=None,exists=None):
        self.path=path or s.STATE/'service-events.jsonl'
        self.read=read or (lambda p:s.read(p,limit=LIMIT))
        self.write=write or s.atomic
        self.exists=exists or (lambda p:p.exists() or p.is_symlink())
    def emit(self,phase,reason,attempts,at):
        if phase not in PHASES or reason not in REASONS or type(attempts)is not int or not 0<=attempts<=3:
            raise s.Refused('unknown_service_event')
        line=(json.dumps(dict(phase=phase,reason=reason,attempts=attempts,at=at),sort_keys=True,allow_nan=False)+'\n').encode()
        if len(line)>512:raise s.Refused('oversized_service_event')
        current=self.read(self.path) if self.exists(self.path) else b''
        if len(current)+len(line)>LIMIT:
            # Fixed filenames only, bounded atomic snapshots. An interrupted
            # rotation may duplicate historical entries but never allows an
            # unbounded file, attacker-selected target or partial current write.
            for index in range(ARCHIVES,1,-1):
                source=self.path.with_name(self.path.name+'.'+str(index-1))
                if self.exists(source):self.write(self.path.with_name(self.path.name+'.'+str(index)),self.read(source))
            self.write(self.path.with_name(self.path.name+'.1'),current);current=b''
        self.write(self.path,current+line)
