"""Durably identify and reap the sole in-flight fixed mutator before recovery.

The constructor exposes internal dependency injection for ordinary-process tests,
never a configurable privileged CLI. Production main passes only the fixed gate.
"""
import json
import os
import signal
import subprocess
import time
import native_support as s
from mutation_spec import require_mutation,require_for_mode
import alf_transaction


class Dispatcher:
    def __init__(self,session,store,*,popen=subprocess.Popen,identity=None,members=None,
                 signal_pid=os.kill,clock=time.monotonic,sleep=time.sleep,validate=require_mutation):
        self.session,self.store=session,store
        self.data_mode=session.get('allow_data')
        self.popen=popen;self.identity=identity or s.process;self.members=members or s.group_members
        self.signal=signal_pid;self.clock=clock;self.sleep=sleep;self.validate=validate
        self.child=None
    def mode_scope(self,durable=False):
        s.session_history(self.session)
        if type(self.data_mode)is not bool or self.session['allow_data'] is not self.data_mode:
            raise s.Refused('mutator_session_mode_changed')
        if durable:
            value=self.store.durable;s.session_history(value)
            if value['allow_data'] is not self.data_mode or value.get('active') is not True:
                raise s.Refused('durable_mutator_mode_changed_or_inactive')
        return self.data_mode
    def save(self):self.store.save(self.session)
    def record(self):
        value=self.session.get('mutation')
        if value is None:return None
        if (not isinstance(value,dict) or not {'version','phase','argv','identity'}<=set(value) or
                set(value)-{'version','phase','argv','identity','never_sent_go'} or
                type(value.get('version'))is not int or value.get('version')!=1 or value.get('phase') not in
                ['spawn-intent','go-intent','settled']):raise s.Refused('unknown_mutation_journal')
        self.validate(value.get('argv'))
        require_for_mode(value.get('argv'),self.mode_scope())
        identity=value.get('identity')
        if 'never_sent_go' in value and not(value['never_sent_go'] is True and
                value['phase']=='settled' and identity is None):raise s.Refused('unknown_mutation_receipt_flag')
        if value['phase']=='spawn-intent' and identity is not None:raise s.Refused('unexpected_spawn_identity')
        if identity is None:
            if value['phase']!='spawn-intent' and not(value['phase']=='settled' and value.get('never_sent_go') is True):
                raise s.Refused('mutation_identity_missing')
        elif (not isinstance(identity,dict) or set(identity)!=set(['pid','uid','pgid','started_sec','started_usec','path']) or
              any(type(identity[k])is not int for k in ['pid','uid','pgid','started_sec','started_usec']) or
              identity['pid']<=1 or identity['pgid']!=identity['pid'] or identity['uid']!=os.geteuid() or
              identity['started_sec']<=0 or not 0<=identity['started_usec']<1000000 or not isinstance(identity['path'],str) or
              not identity['path'].startswith('/') or '\0' in identity['path'] or '\n' in identity['path']):
            raise s.Refused('mutation_identity_invalid')
        return value
    def inspect_owned(self,record):
        identity=record['identity']
        until=self.clock()+.5
        while True:
            if self.child is not None:self.child.poll()
            try:current=self.identity(identity['pid'])
            except s.Refused as error:
                if str(error)!='process_path_unavailable':raise
                # BSDInfo and proc_pidpath are separate libproc reads. A
                # process can exit between them. Retry only this exact error,
                # without signalling or inferring absence, while the group
                # contains no unknown PID. A later live read still has to
                # pass the full birth/path check below.
                members=self.members(identity['pgid'])
                if members not in ([],[identity['pid']]):
                    raise s.Refused('mutator_group_has_unattributed_survivor')
                if self.clock()>=until:raise
                self.sleep(.01);continue
            members=self.members(identity['pgid'])
            if current is None:
                if not members:return None
                # libproc's PID and group views can briefly disagree during
                # exit/reaping. Only the exact old numeric PID may receive a
                # bounded, read-only retry; it is never treated as absent. A
                # reappearing process must pass its full birth/path check.
                if members==[identity['pid']] and self.clock()<until:
                    self.sleep(.01);continue
                raise s.Refused('mutator_group_has_unattributed_survivor')
            if (not s.same_birth(current,identity) or current['path'] not in
                    [identity['path'],record['argv'][0]] or members!=[identity['pid']]):
                raise s.Refused('mutator_identity_or_group_changed')
            return current
    def settle(self):
        record=self.record()
        if not record:return
        if record['phase']=='settled':
            # This phase is written only after exact reap + empty group. It is
            # a historical completion receipt; do not signal or reject a later
            # unrelated process that legitimately reused the old numeric PID.
            return
        if record['identity'] is None:
            # Durable spawn-intent precedes Popen; durable identity precedes
            # GO. Parent exit closes the sole writer, so an unidentified gate
            # cannot exec. Do not guess a PID. Allow its fixed EOF deadline.
            if self.child is not None:
                if self.child.stdin and not self.child.stdin.closed:self.child.stdin.close()
                self.child.wait(timeout=6)
            else:self.sleep(6)
            record['never_sent_go']=True
        else:
            current=self.inspect_owned(record)
            if current is not None:
                self.signal(current['pid'],signal.SIGTERM)
                until=self.clock()+2
                while self.inspect_owned(record) is not None and self.clock()<until:self.sleep(.02)
                current=self.inspect_owned(record)
                if current is not None:
                    self.signal(current['pid'],signal.SIGKILL)
                    if self.child is not None:self.child.wait(timeout=3)
                    until=self.clock()+3
                    while self.inspect_owned(record) is not None and self.clock()<until:self.sleep(.02)
                    if self.inspect_owned(record) is not None:raise s.Refused('owned_mutator_did_not_exit')
            if self.child is not None:self.child.wait(timeout=1)
        record['phase']='settled';self.save()
    def run(self,argv,timeout=5,check=True):
        if not 0<timeout<=30:raise s.Refused('mutation_budget')
        end=self.clock()+timeout
        argv=list(self.validate([str(x) for x in argv]))
        require_for_mode(argv,self.mode_scope(durable=True))
        self.settle()
        require_for_mode(argv,self.mode_scope(durable=True))
        import fleet_session
        fleet_session.authorize_state_delete(self.store.durable,argv)
        if argv[0]==alf_transaction.ALF:
            # Grammar is necessary but insufficient: only the last successfully
            # persisted, exact ALF intent grants this owner a single fixed write.
            alf_transaction.authorize(self.store.durable,argv)
        if self.clock()>=end:raise s.Refused('mutation_budget_expired_before_spawn')
        self.session['mutation']=dict(version=1,phase='spawn-intent',argv=argv,identity=None)
        self.save()
        proc=self.popen(['/usr/bin/python3','-I','-B',str(s.BASE/'mutation_gate.py')],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=s.ENV,close_fds=True,start_new_session=True,cwd='/')
        self.child=proc
        try:
            remaining=end-self.clock()
            if remaining<=0:raise s.Refused('mutation_budget_expired_before_ready')
            s.wait_ready(proc,timeout=min(5,remaining))
            identity=self.identity(proc.pid)
            if (identity is None or identity['uid']!=os.geteuid() or identity['pgid']!=proc.pid or
                    self.members(proc.pid)!=[proc.pid] or proc.poll() is not None):
                raise s.Refused('mutation_gate_identity_failed')
            record=self.session['mutation'];record.update(phase='go-intent',identity=identity);self.save()
            remaining=end-self.clock()
            if s.DEADLINE is not None:remaining=min(remaining,s.DEADLINE-time.monotonic())
            if remaining<=0:raise s.Refused('mutation_budget_expired_before_go')
            require_for_mode(argv,self.mode_scope(durable=True))
            fleet_session.authorize_state_delete(self.store.durable,argv)
            if argv[0]==alf_transaction.ALF:alf_transaction.authorize(self.store.durable,argv)
            frame=json.dumps(dict(version=2,profile=alf_transaction.PROFILE,allow_data=self.data_mode,go=True,argv=argv),separators=(',',':')).encode()+b'\n'
            out,err=proc.communicate(input=frame,timeout=remaining)
            # No child/group survivor may race a later close or next command.
            if self.inspect_owned(record) is not None:raise s.Refused('mutator_not_reaped')
            if len(out)>500000 or len(err)>100000:raise s.Refused('mutation_output_limit')
            result=subprocess.CompletedProcess(argv,proc.returncode,out.decode('utf-8'),err.decode('utf-8'))
            record['phase']='settled';self.save()
            if check and result.returncode:raise s.Refused('fixed_mutation_failed')
            return result
        except BaseException:
            if proc.stdin and not proc.stdin.closed:proc.stdin.close()
            # Closing/reaping this precise child is mandatory even when the
            # journal became unwritable. settle persists only AFTER termination.
            self.settle()
            raise
        finally:self.child=None
