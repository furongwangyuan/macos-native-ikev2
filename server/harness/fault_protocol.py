"""Pure closed-checkpoint fault protocol; no root entry point or side effects."""
from dataclasses import dataclass
import copy
import hashlib
import json
import re


class Refused(RuntimeError):pass


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                    allow_nan=False).encode()).hexdigest()


def identity(value):
    fields={'pid','uid','pgid','started_sec','started_usec','path'}
    if (type(value) is not dict or set(value)!=fields
            or any(type(value[k]) is not int for k in fields-{'path'})
            or value['pid']<=1 or value['pgid']!=value['pid'] or value['uid']<0
            or value['started_sec']<=0 or not 0<=value['started_usec']<1000000
            or type(value['path']) is not str or not value['path'].startswith('/')
            or len(value['path'])>4096 or '\0' in value['path'] or '\n' in value['path']):
        raise Refused('identity_schema')
    return copy.deepcopy(value)


@dataclass(frozen=True)
class Observation:
    identity: dict
    stopped: bool
    members: tuple


def exact(observation,expected,*,stopped=None):
    expected=identity(expected)
    if (type(observation) is not Observation or identity(observation.identity)!=expected
            or type(observation.stopped) is not bool or observation.members!=(expected['pid'],)
            or (stopped is not None and observation.stopped is not stopped)):
        raise Refused('owned_process_state_changed')
    return observation


def checkpoint(value):
    from closed_checkpoint import validate, InvalidCheckpoint
    try:return validate(value)
    except InvalidCheckpoint as exc:raise Refused('checkpoint_not_quiescent_production_v5') from exc


class Coordinator:
    """Single-run orchestration with injected internal adapters for offline tests.

    process owns exact Popen bindings; evidence commits are durable in the future
    native adapter; native rechecks a sealed closed checkpoint. No resumed run
    can replay this object's kill permission. Observer final-check/kill is not
    atomic: failure after that check is a separate fault, never automatic PASS.
    """
    def __init__(self,process,evidence,native,owner,observer,seal):
        self.process,self.evidence,self.native=process,evidence,native
        self.owner,self.observer=identity(owner),identity(observer)
        if self.owner['pid']==self.observer['pid']:raise Refused('distinct_roles_required')
        self.seal=checkpoint(seal)
        self.phase='NEW';self.no_kill=False;self.killed=False;self.reaped=False

    def record(self,phase):
        self.evidence.commit(dict(version=1,run=self.seal['run'],phase=phase,
            owner=self.owner,observer=self.observer,seal_sha256=digest(self.seal),
            no_kill=self.no_kill))

    def observer_alive(self):
        exact(self.process.observer(),self.observer,stopped=False)
        arm=self.evidence.observer_armed()
        if (type(arm)is not dict or set(arm)!={'run','observer','seal_sha256'}
                or type(arm['run'])is not str or type(arm['seal_sha256'])is not str
                or identity(arm['observer'])!=self.observer
                or arm!=dict(run=self.seal['run'],observer=self.observer,seal_sha256=digest(self.seal))):
            raise Refused('observer_not_armed_for_checkpoint')

    def freeze(self):
        if self.phase!='NEW' or self.no_kill:raise Refused('freeze_phase')
        try:
            self.observer_alive()
            exact(self.process.owner(),self.owner,stopped=False)
            self.record('stop-intent')
            self.process.stop_owner()      # Adapter rechecks exact own child immediately.
            exact(self.process.wait_owner_stopped(),self.owner,stopped=True)
            self.phase='FROZEN'
            # A timed-out owner may have started finally before SIGSTOP. This
            # fresh seal check must reject CLOSING/unsettled mutations, rather
            # than infer park state from an earlier ACK or deadline margin.
            if checkpoint(self.native.closed_checkpoint())!=self.seal:
                raise Refused('frozen_checkpoint_changed')
            self.record('frozen-verified')
        except BaseException:
            self.abort()
            raise

    def inject(self):
        if self.phase!='FROZEN' or self.no_kill:raise Refused('kill_phase')
        try:
            exact(self.process.owner(),self.owner,stopped=True)
            if checkpoint(self.native.closed_checkpoint())!=self.seal:
                raise Refused('frozen_checkpoint_changed')
            self.observer_alive()
            self.record('kill-intent')      # No signal if this durable write fails.
            # Recheck after the durable write, which can block or fail.
            exact(self.process.owner(),self.owner,stopped=True)
            self.observer_alive()
            if self.no_kill:raise Refused('no_kill_latched')
            self.process.kill_owner()
            self.killed=True;self.phase='KILLED'
            if self.process.wait_owner()!=-9:raise Refused('not_exact_sigkill_exit')
            self.record('owner-sigkill-reaped')
            self.reaped=True
        except BaseException:
            # If injection happened, the independent observer now owns recovery.
            # Do not resume/replace/kill that writer or report normal abort.
            if self.killed:
                self.no_kill=True;self.phase='ATTENTION'
                try:self.record('post-injection-attention')
                except Exception:pass
            else:self.abort()
            raise

    def abort(self):
        self.no_kill=True                 # Irreversible before any unlock action.
        self.process.latch_no_kill()      # Signal adapter independently enforces it.
        if self.killed:
            self.phase='ATTENTION'
            return
        self.phase='ABORTING'
        try:self.record('no-kill')
        except Exception:pass             # A write failure cannot authorize a kill.
        self.process.close_owner_control() # Only coordinator holds this write end.
        observed=self.process.owner()
        if observed is not None:
            exact(observed,self.owner)
            if observed.stopped:self.process.continue_owner()
        self.phase='ABORTED'

    def finish(self,recovery):
        # ATTENTION is terminal for this run. A late completion can be recorded
        # separately, but cannot retrospectively turn an incomplete run PASS.
        if not self.killed or not self.reaped or self.phase!='KILLED':
            raise Refused('no_complete_injected_fault')
        expected=dict(run=self.seal['run'],observer=self.observer,
                      seal_sha256=digest(self.seal),returncode=0,restored=True)
        valid=(type(recovery)is dict and set(recovery)==set(expected)
               and type(recovery['run'])is str and type(recovery['seal_sha256'])is str
               and type(recovery['returncode'])is int and recovery['returncode']==0
               and recovery['restored']is True)
        if valid:
            try:valid=identity(recovery['observer'])==self.observer and recovery==expected
            except Refused:valid=False
        if not valid:
            self.no_kill=True;self.phase='ATTENTION'
            self.record('recovery-incomplete')
            return False                 # Never kill the still-running observer.
        try:restored=self.native.restored_readback()
        except BaseException:
            self.no_kill=True;self.process.latch_no_kill();self.phase='ATTENTION'
            raise
        if restored is not True:
            self.no_kill=True;self.phase='ATTENTION'
            self.record('restoration-unverified')
            return False
        try:self.record('closed-owner-sigkill-passed')
        except BaseException:
            self.no_kill=True;self.process.latch_no_kill();self.phase='ATTENTION'
            raise
        self.phase='PASSED'
        return True


def observer_decision(owner,coordinator,*,owner_expected,coordinator_expected,
                      coordinator_eof,explicit_no_kill=False):
    """Pure observer action; only exact CONT, wait, attention or recover.

    Pipe EOF alone is not independent proof of coordinator death. No timeout
    can resume a stopped owner while a coordinator may still issue SIGKILL.
    explicit_no_kill must come from the bound irreversible abort receipt.
    """
    if type(coordinator_eof) is not bool or type(explicit_no_kill) is not bool:
        raise Refused('observer_flags')
    identity(owner_expected);identity(coordinator_expected)
    if coordinator is not None:exact(coordinator,coordinator_expected)
    if owner is None:return 'RECOVER'
    exact(owner,owner_expected)
    if owner.stopped:
        if explicit_no_kill or (coordinator_eof and coordinator is None):return 'CONTINUE_EXACT_OWNER'
        return 'WAIT_ATTENTION'            # Alive/hung coordinator: no automatic unfreeze.
    return 'WAIT'
