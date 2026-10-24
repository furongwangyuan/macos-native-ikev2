"""Sole current-boot close/restore writer; reuses exact owned-child settling.

No old v6 PID/PGID/token is ever handed to Dispatcher. Its inspect_owned/settle
mechanism operates only on this new boot record's fresh mutation receipt.
"""
import json,os,selectors,subprocess,time
import native_support as s
from mutation_dispatch import Dispatcher
import boot_record as r

class Writer(Dispatcher):
    def __init__(self,io,store,**ordinary_test_seams):
        super().__init__({},store,validate=r.command,**ordinary_test_seams)
        self.io=io;self.session=None;self._cleanup_owned=False
    def bind(self,record):
        self.io.held();r.validate(record)
        if self.session is not None:
            for key in ('old_boot','new_boot','native_sha256','context_sha256','configuration_sha256','implementation_sha256'):
                if self.session[key]!=record[key]:raise r.Refused('new_boot_writer_rebinding')
        self.session=record
    def scope(self,durable=False):
        if self.session is None:raise r.Refused('new_boot_writer_not_bound')
        self.io.held();r.validate(self.session)
        original=self.store.originals(self.session);old=r.bind(self.session,*original)
        if (self.session['phase'] not in ('ADMITTED','RESTORING') or self.io.boot()!=self.session['new_boot']
                or self.io.originals()!=original or self.io.configuration()!=self.session['configuration_sha256']
                or self.io.implementation()!=self.session['implementation_sha256']):
            raise r.Refused('new_boot_writer_scope_changed')
        if durable and (self.store.durable is None or r.encode(self.store.durable)!=r.encode(self.session)):
            raise r.Refused('new_boot_writer_not_durable')
        return old
    def record(self):
        if self._cleanup_owned:
            # A failed journal/config read must not abandon this live turn's
            # exact Popen child. This path never reads an old-boot PID and is
            # unavailable after process restart: child must be this Popen.
            r.validate(self.session);value=self.session['mutation']
            if (self.child is None or value is None or value['identity'] is not None
                    and value['identity']['pid']!=self.child.pid):raise r.Refused('cleanup_child_not_this_writer')
        else:self.scope();value=self.session['mutation']
        if value and value['identity'] is not None and value['identity']['uid']!=os.geteuid():
            raise r.Refused('new_boot_mutator_uid')
        return value
    def save(self):self.scope();self.store.save(self.session)
    def settle(self,record=None):
        if record is not None:self.bind(record)
        self.scope(durable=True)
        return super().settle()
    def settle_failed_turn(self):
        self._cleanup_owned=True
        try:return super().settle()
        finally:self._cleanup_owned=False
    def authorize(self,record,effect,old):
        self.bind(record);bound=self.scope(durable=True)
        if (r.encode(old)!=r.encode(bound) or record['intent'] is None
                or record['intent']['effect']!=effect or effect!=r.effect(bound,record['intent']['key'])):
            raise r.Refused('new_boot_effect_authority_missing')
        self.io.closed_kernel()
        mutation=self.record()
        if effect['kind']!='command' and mutation is not None and mutation['phase']!='settled':
            raise r.Refused('file_write_with_unsettled_mutator')
    def exchange(self,proc,frame,end):
        # One bounded GO frame, then bounded streaming output. Never accumulate
        # an unbounded command result before applying the byte limit.
        raw=r.encode(frame)
        if len(raw)>4096 or os.write(proc.stdin.fileno(),raw)!=len(raw):raise r.Refused('boot_go_write')
        proc.stdin.close();output={proc.stdout:bytearray(),proc.stderr:bytearray()}
        with selectors.DefaultSelector() as selector:
            for stream in output:
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ)
            while selector.get_map():
                left=end-self.clock()
                if left<=0:raise r.Refused('boot_mutator_output_deadline')
                events=selector.select(left)
                if not events:raise r.Refused('boot_mutator_output_deadline')
                for key,_ in events:
                    stream=key.fileobj;chunk=os.read(stream.fileno(),32768)
                    if not chunk:selector.unregister(stream);continue
                    output[stream].extend(chunk)
                    if len(output[stream])>65536:raise r.Refused('boot_mutator_output_limit')
        left=end-self.clock()
        if left<=0:raise r.Refused('boot_mutator_reap_deadline')
        proc.wait(timeout=left)
        return bytes(output[proc.stdout]),bytes(output[proc.stderr])
    def run(self,record,effect,old):
        self.authorize(record,effect,old);argv=r.command(effect['argv']);end=self.clock()+5
        self.settle();self.authorize(record,effect,old)
        if self.clock()>=end:raise r.Refused('boot_write_budget_before_spawn')
        self.session['mutation']=dict(version=1,phase='spawn-intent',argv=argv,identity=None);self.save()
        proc=self.popen(['/usr/bin/python3','-I','-B',str(s.BASE/'boot_mutation_gate.py')],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=s.ENV,close_fds=True,start_new_session=True,cwd='/')
        self.child=proc
        try:
            left=end-self.clock()
            if left<=0:raise r.Refused('boot_write_budget_before_ready')
            s.wait_ready(proc,timeout=min(5,left));identity=self.identity(proc.pid)
            if (identity is None or identity['uid']!=os.geteuid() or identity['pgid']!=proc.pid
                    or self.members(proc.pid)!=[proc.pid] or proc.poll() is not None):raise r.Refused('boot_gate_identity')
            self.session['mutation'].update(phase='go-intent',identity=identity);self.save()
            self.authorize(record,effect,old)
            left=end-self.clock()
            if left<=0:raise r.Refused('boot_write_budget_before_go')
            frame=dict(version=1,profile=r.PROFILE,go=True,boot=record['new_boot'],intent_sha256=r.sha(r.encode(record['intent'])),argv=argv)
            out,err=self.exchange(proc,frame,end)
            if self.inspect_owned(self.session['mutation']) is not None:raise r.Refused('boot_mutator_not_reaped')
            if len(out)>65536 or len(err)>65536:raise r.Refused('boot_mutator_output_limit')
            self.session['mutation']['phase']='settled';self.save()
            if self.clock()>=end:raise r.Refused('boot_mutator_late_completion')
            if proc.returncode:raise r.Refused('boot_fixed_command_failed')
            return subprocess.CompletedProcess(argv,proc.returncode,out,err)
        except BaseException:
            if proc.stdin is not None and not proc.stdin.closed:proc.stdin.close()
            self.settle_failed_turn()
            raise
        finally:
            # Even a READY/setup failure or failed settle must close all three
            # parent pipes; failed settling is never converted into success.
            for stream in (proc.stdin,proc.stdout,proc.stderr):
                if stream is not None and not stream.closed:stream.close()
            if self.session['mutation']['phase']=='settled':self.child=None
