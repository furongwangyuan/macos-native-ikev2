"""Bounded orchestration around fixed role children and STOP v2 protocol.

Processes accepts a private spawn function solely for offline testing; no CLI or
receipt can supply an executable. Native entry always supplies its two fixed
scripts. Only the coordinator owns child control writers and the outer lock.
"""
import os
import signal
import time
from fault_protocol import Coordinator, Refused, exact, digest
from process_observe import observe
from role_logic import read_line, checked_watch


class Processes:
    def __init__(self,receipts,spawn):
        self.receipts=receipts;self.spawn=spawn;self.no_kill=False
        self.owner_proc=self.observer_proc=None
    def _send(self,proc,raw):proc.stdin.write(raw);proc.stdin.flush()
    def start(self):
        self.coordinator_id=observe(os.getpid()).identity
        exact(observe(os.getpid()),self.coordinator_id,stopped=False)
        self.receipts.write('coordinator.json',self.coordinator_id)
        self.owner_proc=self.spawn('owner');self._ready(self.owner_proc)
        self.owner_id=observe(self.owner_proc.pid).identity;exact(self.owner(),self.owner_id,stopped=False)
        self.receipts.write('owner.json',self.owner_id)
        self.observer_proc=self.spawn('observer');self._ready(self.observer_proc)
        self.observer_id=observe(self.observer_proc.pid).identity;exact(self.observer(),self.observer_id,stopped=False)
        self.receipts.write('observer.json',self.observer_id)
        self._send(self.observer_proc,b'WATCH\n')
        if read_line(self.observer_proc.stdout.fileno(),10)!=b'WATCHING\n':raise Refused('watch_notice')
        intent=self.receipts.read('intent.json')
        roles=dict(owner=self.owner_id,observer=self.observer_id,coordinator=self.coordinator_id)
        checked_watch(self.receipts,intent,roles)
        self._send(self.owner_proc,b'GO\n')
        if read_line(self.owner_proc.stdout.fileno(),90)!=b'PARKED\n':raise Refused('park_notice')
        self.seal=self.receipts.read('checkpoint.json')
        self._send(self.observer_proc,b'ARM\n')
        if read_line(self.observer_proc.stdout.fileno(),10)!=b'ARMED\n':raise Refused('arm_notice')
        return self.seal
    def _ready(self,proc):
        if read_line(proc.stdout.fileno(),10)!=b'READY\n':raise Refused('role_ready')
    def owner(self):
        if self.owner_proc is None:return None
        self.owner_proc.poll();return observe(self.owner_proc.pid)
    def observer(self):
        if self.observer_proc is None:return None
        self.observer_proc.poll();return observe(self.observer_proc.pid)
    def latch_no_kill(self):self.no_kill=True
    def stop_owner(self):
        if self.no_kill:raise Refused('no_kill_latched')
        exact(self.owner(),self.owner_id,stopped=False)
        os.kill(self.owner_id['pid'],signal.SIGSTOP)
    def wait_owner_stopped(self):
        end=time.monotonic()+3
        while time.monotonic()<end:
            found=self.owner();exact(found,self.owner_id)
            if found.stopped:return found
            time.sleep(.01)
        raise Refused('stop_timeout')
    def kill_owner(self):
        if self.no_kill:raise Refused('no_kill_latched')
        exact(self.owner(),self.owner_id,stopped=True)
        exact(self.observer(),self.observer_id,stopped=False)
        os.kill(self.owner_id['pid'],signal.SIGKILL)
    def wait_owner(self):return self.owner_proc.wait(timeout=3)
    def close_owner_control(self):
        if self.owner_proc is not None and not self.owner_proc.stdin.closed:self.owner_proc.stdin.close()
    def continue_owner(self):
        if not self.no_kill:raise Refused('continue_without_abort')
        exact(self.owner(),self.owner_id,stopped=True)
        os.kill(self.owner_id['pid'],signal.SIGCONT)
    def recovery(self,seconds=60):
        # Timeout never signals observer or substitutes a second recovery owner.
        import subprocess
        try:code=self.observer_proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:return None
        value=self.receipts.read('recovery.json')
        return dict(value,returncode=code)
    def close_handles(self):
        for proc in (self.owner_proc,self.observer_proc):
            if proc is not None:
                for fd in (proc.stdin,proc.stdout):
                    if fd is not None and not fd.closed:fd.close()


class Evidence:
    def __init__(self,receipts):self.receipts=receipts
    def observer_armed(self):return self.receipts.read('armed.json')
    def commit(self,value):
        self.receipts.write('injection.json',value)
        if value['phase']=='no-kill':
            self.receipts.write('abort.json',{k:value[k] for k in
                ('run','owner','observer','seal_sha256','no_kill')})


def run(processes,native,receipts):
    core=None
    try:
        seal=processes.start()
        core=Coordinator(processes,Evidence(receipts),native,processes.owner_id,processes.observer_id,seal)
        core.freeze();core.inject()
        result=processes.recovery()
        passed=core.finish(result)
        receipts.write('result.json',dict(run=seal['run'],phase=core.phase,passed=passed,
            native_data_mode_tested=False,observer_reaped=result is not None))
        return 0 if passed else 2
    except BaseException:
        if core is not None:
            if not core.killed:core.abort()
        else:
            processes.latch_no_kill();processes.close_owner_control()
        # No arbitrary kill on an error, including a failed evidence write.
        try:receipts.write('coordinator-attention.json',dict(event='coordinator_incomplete',
                                               run=receipts.read('intent.json')['run']))
        except Exception:pass
        raise
    finally:processes.close_handles()
