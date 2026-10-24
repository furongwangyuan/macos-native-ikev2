"""Owned ordinary probe child. No native/PF/ALF authorization or public CLI.

Journal adapter save/load must persist the one enclosing Owner's child field.
Default launch is fixed; optional ordinary-test seams do not confer permission.
"""
import copy,os,select,selectors,signal,subprocess,time,uuid
import probe_contract as c
import probe_identity as ident
from probe_records import Records

class ProbeChild:
 def __init__(self,journal,*,popen=subprocess.Popen,observe=ident.observe,clock=time.monotonic,boot=ident.boot,reader_factory=Records):
  self.journal=journal;self.popen=popen;self.observe=observe;self.clock=clock;self.boot=boot;self.reader_factory=reader_factory
  self.child=None;self.row=None;self.reader=None;self.selector=None;self.eof=set();self.stderr=bytearray();self.result=None;self.deadline=None;self.cancelled=False
 def save(self):
  c.record(self.row);self.journal.save(copy.deepcopy(self.row))
  if c.encode(self.journal.load())!=c.encode(self.row):raise c.Refused('probe_journal_readback')
 def expected_current(self):
  if self.child is None or self.row['identity'] is None:raise c.Refused('probe_identity_unavailable')
  current,members=self.observe(self.child.pid)
  if current is None:
   if members:raise c.Refused('probe_group_unknown')
   return None
  old=self.row['identity']
  if (not ident.same_birth(current,old) or members!=(old['pid'],)
      or not ((current['path']==old['path'] and current['uid']in(0,c.UID))
              or (current['path']==str(c.BINARY) and current['uid']==c.UID))):raise c.Refused('probe_identity_changed')
  return current
 def wait_gate(self,end):
  out=b'';fd=self.child.stdout.fileno()
  while b'\n' not in out:
   left=end-self.clock()
   if left<=0 or not select.select([fd],[],[],left)[0]:raise c.Refused('gate_ready_timeout')
   more=os.read(fd,64)
   if not more:raise c.Refused('gate_eof_before_ready')
   out+=more
   if len(out)>64:raise c.Refused('gate_ready_bound')
  if out!=b'PROBE_GATE_READY\n':raise c.Refused('gate_ready_unknown')
 def start(self,peer,seconds):
  c.spec(peer,seconds)
  if self.child is not None or self.row is not None or self.journal.load() is not None:raise c.Refused('probe_record_already_exists')
  self.row=dict(version=1,profile=c.PROFILE,boot=self.boot(),run=uuid.uuid4().hex,phase='spawn-intent',peer=peer,seconds=seconds,identity=None,exit=None)
  self.save();gate_end=self.clock()+5
  self.reader=self.reader_factory(c.ready(peer,seconds),c.PAGE_LENGTH)
  self.child=self.popen(['/usr/bin/python3','-I','-B',str(c.GATE)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True,cwd='/',env=c.ENV)
  try:
   self.wait_gate(gate_end);who,members=self.observe(self.child.pid)
   c.identity(who)
   if who['uid']!=0 or who['pgid']!=self.child.pid or members!=(self.child.pid,) or self.child.poll() is not None:raise c.Refused('root_gate_identity_unknown')
   self.row.update(phase='go-intent',identity=who);self.save()
   if self.boot()!=self.row['boot'] or self.clock()>=gate_end:raise c.Refused('gate_budget_or_boot_changed')
   frame=dict(version=1,profile=c.PROFILE,go=True,run=self.row['run'],peer=peer,seconds=seconds)
   raw=c.encode(c.frame(frame));os.set_blocking(self.child.stdin.fileno(),False)
   if os.write(self.child.stdin.fileno(),raw)!=len(raw):raise c.Refused('incomplete_go')
   self.deadline=self.clock()+seconds+5;self.selector=selectors.DefaultSelector()
   for stream in(self.child.stdout,self.child.stderr):
    os.set_blocking(stream.fileno(),False);self.selector.register(stream,selectors.EVENT_READ)
   end=self.clock()+5
   while self.reader.ready is None:
    if self.clock()>=end:raise c.Refused('probe_listener_ready_timeout')
    self.drain(min(.05,max(0,end-self.clock())))
    if self.child.poll() is not None and len(self.eof)==2:raise c.Refused('probe_exited_before_ready')
   current=self.expected_current()
   if current is None or current['uid']!=c.UID or current['path']!=str(c.BINARY):raise c.Refused('ordinary_fixed_exec_not_observed')
   self.deadline=self.clock()+seconds
   self.row['phase']='running';self.save();self.child.stdin.close()
   return dict(ready=True,ordinary_uid_observed=c.UID,fixed_binary_observed=True,authenticated_vpn_verified=False)
  except BaseException as error:
   self.abort(error);raise
 def drain(self,timeout=0):
  if self.selector is None:return
  if type(timeout)not in(int,float) or not 0<=timeout<=.1:raise c.Refused('drain_timeout_bound')
  budget=65536
  for key,_ in self.selector.select(timeout):
   stream=key.fileobj
   while budget>0:
    try:data=os.read(stream.fileno(),min(8192,budget))
    except BlockingIOError:break
    if not data:
     self.selector.unregister(stream);self.eof.add(stream);break
    budget-=len(data)
    if stream is self.child.stdout:self.reader.feed(data)
    else:
     self.stderr.extend(data)
     if len(self.stderr)>4096:raise c.Refused('probe_stderr_limit')
   if budget<=0:break
 def close_pipes(self):
  errors=[]
  if self.selector is not None:
   try:self.selector.close()
   except BaseException as e:errors.append(e)
   self.selector=None
  if self.child is not None:
   for stream in(self.child.stdin,self.child.stdout,self.child.stderr):
    if stream is not None:
     try:stream.close()
     except BaseException as e:errors.append(e)
  if errors:raise c.Refused('probe_pipe_cleanup_failed') from errors[-1]
 def exited(self,*,own_reap):
  self.row['phase']='exited';self.row['exit']=dict(own_reap=own_reap,process_absent=True,group_absent=True,never_sent_go=self.row['identity'] is None)
 def finish(self):
  if self.result is not None:return self.result
  if len(self.eof)!=2 or self.child.poll() is None:raise c.Refused('probe_eof_or_reap_missing')
  current,members=self.observe(self.child.pid)
  if current is not None or members:raise c.Refused('probe_survivor_unknown')
  result=self.reader.finish(exit_code=self.child.returncode,stderr_empty=not self.stderr)
  self.close_pipes();self.exited(own_reap=True);self.save()
  self.result=dict(protocol=result,stdout_eof=True,stderr_eof=True,own_child_reaped=True,cancelled=self.cancelled,
                   authenticated_vpn_verified=False,throughput_computed=False)
  return self.result
 def poll(self):
  if self.child is None:raise c.Refused('probe_not_started')
  if self.result is not None:return self.result
  try:
   self.drain()
   if len(self.eof)==2 and self.child.poll() is not None:return self.finish()
   if self.clock()>=self.deadline:raise c.Refused('probe_window_expired_requires_stop')
   self.expected_current()
   return None
  except BaseException as error:self.abort(error);raise
 def stop_owned(self,*,persist=True):
  """Only this live turn's exact unreaped Popen child, never a supplied PID."""
  if self.child is None:raise c.Refused('no_owned_popen')
  p=self.child;self.cancelled=True;failure=None
  # A broken journal cannot strand this still-owned Popen child. Persist intent
  # if possible, but exact own-child cleanup is attempted even if that fails.
  if persist and self.row['phase']!='exited':
   self.row['phase']='stop-intent' if self.row['identity'] is not None else 'spawn-intent'
   try:self.save()
   except BaseException as e:failure=e
  try:
   if p.stdin and not p.stdin.closed:p.stdin.close()
   if p.poll() is None:
    # Popen's unreaped child PID cannot be reused before wait/poll returns.
    p.terminate()
    try:p.wait(timeout=2)
    except subprocess.TimeoutExpired:
     if p.poll() is None:p.kill()
     p.wait(timeout=3)
   current,members=self.observe(p.pid)
   if current is not None or members:raise c.Refused('owned_probe_group_not_empty')
   # Drain bounded data after confirmed death, preserving protocol completeness
   # separately from cancellation. No further process wait hides invalid logs.
   end=self.clock()+1
   while len(self.eof)<2 and self.selector is not None and self.clock()<end:self.drain(.02)
   if self.selector is not None and len(self.eof)==2 and not self.reader.eof:
    self.result=dict(protocol=self.reader.finish(exit_code=p.returncode,stderr_empty=not self.stderr),stdout_eof=True,stderr_eof=True,own_child_reaped=True,cancelled=True,authenticated_vpn_verified=False,throughput_computed=False)
   self.exited(own_reap=True)
  finally:self.close_pipes()
  if failure is not None:raise failure
  if persist:self.save()
  return self.result
 def abort(self,error):
  try:self.stop_owned(persist=False)
  except BaseException as cleanup:
   try:error.probe_cleanup_error=type(cleanup).__name__+':'+str(cleanup)
   except Exception:pass
   raise c.Refused('probe_owned_cleanup_unverified') from error


def listener_absent():
 """One bounded readonly query; never kill a listener or choose another port."""
 child=None;selector=None;output=bytearray();end=time.monotonic()+3
 try:
  child=subprocess.Popen(['/usr/sbin/lsof','-nP','-iTCP:47729','-sTCP:LISTEN'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,env=c.ENV)
  selector=selectors.DefaultSelector();os.set_blocking(child.stdout.fileno(),False);selector.register(child.stdout,selectors.EVENT_READ)
  while selector.get_map():
   left=end-time.monotonic()
   if left<=0:raise c.Refused('probe_port_observation_timeout')
   for key,_ in selector.select(left):
    data=os.read(key.fd,4096)
    if not data:selector.unregister(key.fileobj);continue
    output.extend(data)
    if len(output)>8192:raise c.Refused('probe_port_observation_limit')
  left=end-time.monotonic()
  if left<=0:raise c.Refused('probe_port_observation_timeout')
  code=child.wait(timeout=left)
  if time.monotonic()>=end:raise c.Refused('probe_port_observation_late')
  if code==1 and not output:return True
  if code==0 and output:return False
  raise c.Refused('probe_port_observation_unknown')
 finally:
  errors=[]
  if child is not None:
   try:
    if child.poll() is None:child.kill()
   except BaseException as e:errors.append(e)
   try:child.wait(timeout=1)
   except BaseException as e:errors.append(e)
  if selector is not None:
   try:selector.close()
   except BaseException as e:errors.append(e)
  if child is not None and child.stdout is not None:
   try:child.stdout.close()
   except BaseException as e:errors.append(e)
  if errors:raise c.Refused('probe_port_observation_cleanup_failed') from errors[-1]


def recover_exact(journal,*,observe=ident.observe,signal_pid=os.kill,clock=time.monotonic,sleep=time.sleep,boot=ident.boot,port_absent=listener_absent):
 """Fixed current-boot receipt recovery, not a native protection assertion.

 A new owner cannot reap a prior owner's child. It requires fresh exact process
 and group absence, and records own_reap=False. No numeric oldboot lookup occurs.
 """
 row=c.record(journal.load())
 if row['boot']!=boot():raise c.Refused('probe_crossboot_requires_fresh_native_reconciliation')
 if row['phase'] in('exited','retired-no-go'):return dict(already_retired=True,own_reap=False,queried_old_pid=False)
 old=row['identity']
 if old is None:
  # No durable identity => the sole authorized writer never sent GO. Do not
  # invent its PID or assert process/group exit. Allow the fixed gate deadline,
  # then independently observe the only possible listener's absence.
  end=clock()+6
  while clock()<end:sleep(min(.1,max(0,end-clock())))
  if boot()!=row['boot'] or c.encode(journal.load())!=c.encode(row):raise c.Refused('pre_go_recovery_scope_changed')
  if port_absent() is not True:raise c.Refused('pre_go_listener_not_proven_absent')
  row['phase']='retired-no-go';row['exit']=dict(own_reap=False,process_absent=None,group_absent=None,never_sent_go=True,listener_absence_verified=True)
  journal.save(copy.deepcopy(row))
  if c.encode(journal.load())!=c.encode(row):raise c.Refused('pre_go_retirement_readback')
  return dict(never_sent_go=True,listener_absence_verified=True,process_absence_unknown=True,own_reap=False,queried_old_pid=False)
 def inspect():
  current,members=observe(old['pid'])
  if current is None:
   if members:raise c.Refused('unknown_probe_group_survivor')
   return None
  if (not ident.same_birth(current,old) or members!=(old['pid'],)
   or not ((current['uid']in(0,c.UID) and current['path']==old['path']) or (current['uid']==c.UID and current['path']==str(c.BINARY)))):
   raise c.Refused('probe_recovery_identity_mismatch')
  return current
 row['phase']='stop-intent';journal.save(copy.deepcopy(row))
 if c.encode(journal.load())!=c.encode(row):raise c.Refused('probe_recovery_intent_readback')
 for sig,duration in ((signal.SIGTERM,2),(signal.SIGKILL,3)):
  current=inspect()
  if current is None:break
  signal_pid(current['pid'],sig) # exact checked leader only, never killpg
  until=clock()+duration
  while inspect() is not None and clock()<until:sleep(.02)
 if inspect() is not None:raise c.Refused('exact_probe_did_not_exit')
 row['phase']='exited';row['exit']=dict(own_reap=False,process_absent=True,group_absent=True,never_sent_go=False)
 journal.save(copy.deepcopy(row))
 if c.encode(journal.load())!=c.encode(row):raise c.Refused('probe_recovery_final_readback')
 return dict(process_absent=True,group_absent=True,own_reap=False,authenticated_vpn_verified=False)
