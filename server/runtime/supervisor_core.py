"""Injected sole-owner service lifecycle; no process, socket or native I/O here."""
from dataclasses import dataclass
import math


class Attention(RuntimeError):pass
class OwnedDaemonExit(RuntimeError):pass
class KnownUplinkChange(RuntimeError):pass
class ViciUnavailable(RuntimeError):pass
class GateReadbackUnavailable(RuntimeError):pass
class MaintenanceDue(RuntimeError):pass
class ConfigurationChanged(Attention):pass
class RequestedStop(RuntimeError):pass
class NetworkNotReady(RuntimeError):pass


PHASES={'DISABLED','PREFLIGHT','STARTING','RUNNING','RECOVERING','BACKOFF','STOPPED','ATTENTION'}
REASONS={'initial','disabled','manual_stop','known_daemon_exit','known_uplink_change','scheduled_maintenance','interrupted_owner',
         'unknown_failure','configuration_changed','activation_not_accepted',
         'recovery_not_proven','retry_budget_exhausted','cross_boot_unfinished',
         'latched_attention','running','backoff','preflight','starting','network_not_ready','vici_unavailable',
         'gate_readback_unavailable'}
RETRY_WINDOW=900
RETRY_DELAYS=(5,15,60)
MAX_ATTEMPTS=3
# These exact serve outcomes have already stopped their owner and must complete
# native cleanup/readback before entering BACKOFF. A spent start budget delays
# the next attempt; it does not turn a known, fully recovered stop permanent.
RECOVERY_REASONS=frozenset({'known_daemon_exit','known_uplink_change','scheduled_maintenance',
                            'vici_unavailable','gate_readback_unavailable'})


@dataclass(frozen=True)
class Configuration:
    enabled: bool
    fingerprint: str


def valid_state(value):
    keys={'version','phase','boot','fingerprint','attempts','next_due','reason','updated'}
    if (not isinstance(value,dict) or set(value)!=keys or type(value['version'])is not int or
            value['version']!=1 or value['phase'] not in PHASES or value['reason'] not in REASONS or
            not isinstance(value['boot'],str) or not value['boot'] or
            not isinstance(value['fingerprint'],str) or len(value['fingerprint'])!=64 or
            any(x not in '0123456789abcdef' for x in value['fingerprint']) or
            not isinstance(value['attempts'],list) or len(value['attempts'])>MAX_ATTEMPTS):
        raise Attention('unknown_service_state')
    numbers=[value['next_due'],value['updated'],*value['attempts']]
    if any(type(x) not in [int,float] or not math.isfinite(x) or x<0 for x in numbers):
        raise Attention('unknown_service_clock')
    if value['attempts']!=sorted(value['attempts']):raise Attention('unordered_attempts')
    # ATTENTION may retain attempt timestamps from a quarantined prior boot;
    # these are historical only and can never authorize a subsequent start.
    if value['phase']!='ATTENTION' and any(x>value['updated'] for x in value['attempts']):
        raise Attention('future_attempt')
    if ((value['phase']!='BACKOFF' and value['next_due']!=0) or
            value['next_due']>value['updated']+max(RETRY_DELAYS)):
        raise Attention('unknown_backoff_clock')
    return value


def contains(error,kind):
    seen=set()
    while error is not None and id(error) not in seen:
        if isinstance(error,kind):return True
        seen.add(id(error));error=error.__cause__
    return False


class Supervisor:
    """deps owns native effects; the caller holds the one fixed lock throughout.

    deps: configuration, boot, authorize, recover(expected_owner), preflight,
    prepare(session), setup, serve, cleanup, wait, stopped, event. store: load/save.
    prepare durably writes the native session before returning an Owner. All
    cleanup proofs must include a fresh native journal read and kernel readback.
    """
    def __init__(self,deps,store,clock):
        self.d,self.store,self.clock=deps,store,clock
        self.state=None;self.owner=None;self.close_calls=0;self.state_seen=False
    def failure(self,error):
        # Diagnostics are optional and must never replace phase/cleanup work.
        try:
            hook=getattr(self.d,'failure',None)
            if hook is not None:hook(error)
        except BaseException:pass
    def write(self,phase,reason,**fields):
        self.state.update(phase=phase,reason=reason,updated=self.clock(),**fields)
        valid_state(self.state);self.store.save(self.state)
        self.state_seen=True
        # The durable lifecycle remains mandatory. Its auxiliary event log must
        # not close a healthy owner when only logging is unavailable.
        try:self.d.event(phase,reason,len(self.state['attempts']))
        except Exception as error:self.failure(error)
    def attention(self,reason):
        # Record BEFORE cleanup: neither this loop nor a later invocation may
        # create another owner before complete recovery and fresh authorization.
        self.write('ATTENTION',reason,next_due=0)
        return 0 # The outer loop waits and rechecks; this does not authorize a start.
    def close(self):
        self.close_calls+=1
        # Keep exact process/dispatcher handles until full cleanup AND fresh
        # readback succeed. A False result or exception cannot retire ownership.
        try:
            result=(self.d.recover(expected_owner=False) if self.owner is None
                    else self.d.cleanup(self.owner))
        except Exception as error:
            self.failure(error);return False
        if result is True:self.owner=None
        return result is True
    def reserve_attempt(self):
        now=self.clock()
        if now<self.state['updated']:raise Attention('continuous_clock_regressed')
        attempts=[x for x in self.state['attempts'] if now-x<RETRY_WINDOW]
        if len(attempts)>=MAX_ATTEMPTS:return False
        attempts.append(now)
        self.write('PREFLIGHT','preflight',attempts=attempts,next_due=0)
        return True
    def backoff(self,reason,preserve=False):
        now=self.clock()
        # A long healthy run expires earlier starts before this next wait, not
        # only later when reserve_attempt() is reached. A resumed wait retains
        # its already committed deadline below.
        recent=sum(now-attempt<RETRY_WINDOW for attempt in self.state['attempts'])
        delay=RETRY_DELAYS[min(max(recent-1,0),len(RETRY_DELAYS)-1)]
        if reason in RECOVERY_REASONS and recent>=MAX_ATTEMPTS:
            # Preserve the start rate, but a verified-clean known stop may
            # wait out the budget instead of becoming a permanent latch.
            oldest=min(attempt for attempt in self.state['attempts'] if now-attempt<RETRY_WINDOW)
            delay=min(delay,max(0,oldest+RETRY_WINDOW-now))
        due=self.state['next_due'] if preserve else now+delay
        self.write('BACKOFF',reason,next_due=due)
        while self.clock()<due:
            if self.d.stopped():return False
            self.d.wait(min(.5,due-self.clock()))
            if self.d.configuration().fingerprint!=self.state['fingerprint']:
                raise ConfigurationChanged('configuration_changed')
        return not self.d.stopped()
    def disabled(self):
        try:return self.d.configuration().enabled is False
        except Exception:return False # An unreadable configuration is not an operator stop.
    def retry_wait(self):
        now=self.clock();attempts=[] if self.state is None else self.state['attempts']
        recent=[at for at in attempts if now-at<RETRY_WINDOW]
        delay=RETRY_DELAYS[min(max(len(recent)-1,0),len(RETRY_DELAYS)-1)]
        if len(recent)>=MAX_ATTEMPTS:
            delay=min(delay,max(0,min(recent)+RETRY_WINDOW-now))
        due=now+delay
        while self.clock()<due:
            if self.d.stopped() or self.disabled():return False
            self.d.wait(min(.5,due-self.clock()))
        return not self.d.stopped() and not self.disabled()
    def run(self):
        # ATTENTION describes a closed/unverified owner that needs another
        # observation, not a permanent service exit. Never manufacture a fresh
        # state when the saved one is unreadable, and never open before recovery.
        while True:
            closes=self.close_calls
            try:
                if self.owner is not None and not self.close():
                    self.attention('recovery_not_proven')
                else:
                    result=self._run_cycle()
                    if self.state is not None and self.state['phase'] in ('STOPPED','DISABLED'):
                        return result
            except Exception as error:
                self.failure(error)
                if self.state is not None:
                    try:self.attention('configuration_changed' if isinstance(error,ConfigurationChanged) else 'unknown_failure')
                    except Exception as write_error:self.failure(write_error)
                # Startup/load errors can occur before the cycle reaches its
                # own close path. Try existing recovery once; do not repeat a
                # failed cleanup immediately or replace its retained owner.
                if self.close_calls==closes:
                    try:self.close()
                    except Exception as close_error:self.failure(close_error)
            # SIGTERM/disable must release the lifecycle lock even when an
            # attempted recovery remains unproven. The durable native record
            # stays intact for the stop/recovery entry that obtains this lock.
            if self.d.stopped() or self.disabled():return 0
            # The caller retains this Supervisor if the clock/wait facility
            # itself fails, using its independent STOP.wait before retrying.
            if not self.retry_wait():return 0
    def _run_cycle(self):
        self.state=None
        previous=self.store.load()
        if previous is None and self.state_seen:
            raise Attention('service_state_disappeared')
        if previous is not None:
            self.state_seen=True
            valid_state(previous)
            self.state=dict(previous)
        boot=self.d.boot()
        try:config=self.d.configuration()
        except Exception as error:
            self.failure(error)
            # No valid prior state means there is no configuration fingerprint
            # to bind. Preserve absence; retry after the configuration is readable.
            if previous is None:raise
            self.state=dict(previous)
            expected=self.state['phase'] in ['STARTING','RUNNING','RECOVERING']
            try:self.attention('configuration_changed')
            finally:self.d.recover(expected_owner=expected)
            return 0
        self.state=dict(previous) if previous else dict(version=1,phase='DISABLED',boot=boot,
            fingerprint=config.fingerprint,attempts=[],next_due=0,reason='initial',updated=self.clock())
        phase=self.state['phase'];expected=phase in ['STARTING','RUNNING','RECOVERING']
        # A previous boot's interrupted service remains quarantined even if a
        # separate recovery observer saw no obvious kernel residue. It has no
        # authority to reuse old ownership or silently reset a crash budget.
        if self.state['boot']!=boot and phase not in ['STOPPED','DISABLED']:
            waiting=(phase=='BACKOFF' and self.state['reason']=='network_not_ready'
                     and config.enabled is True and config.fingerprint==self.state['fingerprint'])
            if waiting:
                try:waiting=self.d.resume_network_wait(dict(self.state),boot,config) is True
                except Exception as error:self.failure(error);waiting=False
            if not waiting:
                try:self.attention('cross_boot_unfinished')
                finally:self.d.recover(expected_owner=expected)
                return 0
            # This exact wait had no native owner, now independently proved
            # closed in the new boot. It does not reuse any old native identity.
            self.state.update(boot=boot,attempts=[],updated=self.clock(),next_due=0)
            phase='STOPPED'
        try:restored=self.d.recover(expected_owner=expected)
        except Exception as error:
            self.failure(error);restored=False
        if not restored:return self.attention('recovery_not_proven')
        # A former ATTENTION owner was recovered above; require all current
        # configuration/activation/preflight checks again before any new start.
        if not config.enabled:
            self.write('DISABLED','disabled',boot=boot,fingerprint=config.fingerprint,attempts=[],next_due=0)
            return 0
        if previous and phase not in ['DISABLED','STOPPED'] and config.fingerprint!=self.state['fingerprint']:
            return self.attention('configuration_changed')
        self.state.update(boot=boot,fingerprint=config.fingerprint)
        if previous and previous['boot']!=boot:
            self.state.update(attempts=[],updated=self.clock(),next_due=0)
        try:
            self.d.authorize(config)
        except Exception as error:
            self.failure(error);return self.attention('activation_not_accepted')
        # A completed requested stop has already passed native recovery above.
        # A later authorized start begins a new operator session; failed or
        # interrupted owners and ATTENTION never receive this budget reset.
        if phase=='STOPPED' and self.state['reason']=='manual_stop':
            self.state.update(attempts=[],next_due=0)
        try:
            if phase in ['PREFLIGHT','STARTING','RUNNING','RECOVERING','BACKOFF']:
                reason=(self.state['reason'] if
                        (phase=='BACKOFF' and self.state['reason']=='network_not_ready') or
                        (phase in ('RECOVERING','BACKOFF') and self.state['reason'] in RECOVERY_REASONS)
                        else 'interrupted_owner')
                if not self.backoff(reason,preserve=phase=='BACKOFF'):
                    self.write('STOPPED','manual_stop',next_due=0);return 0
            while not self.d.stopped():
                if self.d.configuration().fingerprint!=self.state['fingerprint']:
                    raise ConfigurationChanged('configuration_changed')
                if (self.owner is None and self.state['phase']=='BACKOFF'
                        and self.state['reason'] in RECOVERY_REASONS
                        and sum(self.clock()-attempt<RETRY_WINDOW for attempt in self.state['attempts'])>=MAX_ATTEMPTS):
                    # Entry is possible only after clean full recovery above,
                    # or after a fresh recovery proof on a resumed BACKOFF.
                    if not self.backoff(self.state['reason']):
                        self.write('STOPPED','manual_stop',next_due=0);return 0
                    continue
                self.write('PREFLIGHT','preflight',next_due=0)
                try:
                    session=self.d.preflight() # fresh baseline/protection prerequisites every time
                except NetworkNotReady as error:
                    if type(error)is not NetworkNotReady or self.owner is not None:
                        raise
                    if not self.close():return self.attention('recovery_not_proven')
                    if not self.backoff('network_not_ready'):
                        self.write('STOPPED','manual_stop',next_due=0);return 0
                    continue
                if self.d.stopped():
                    self.write('STOPPED','manual_stop',next_due=0);return 0
                # Missing connectivity does not spend the actual start budget.
                if not self.reserve_attempt():return self.attention('retry_budget_exhausted')
                self.owner=self.d.prepare(session) # durable native ownership before STARTING
                self.write('STARTING','starting')
                if self.d.stopped():
                    self.write('RECOVERING','manual_stop')
                    if not self.close():return self.attention('recovery_not_proven')
                    self.write('STOPPED','manual_stop',next_due=0);return 0
                self.d.setup(self.owner)
                self.write('RUNNING','running')
                failure=None
                try:self.d.serve(self.owner)
                except Exception as error:failure=error
                if type(failure)is RequestedStop and self.d.stopped():failure=None
                if failure is not None and type(failure) not in (OwnedDaemonExit,KnownUplinkChange,MaintenanceDue,ViciUnavailable,GateReadbackUnavailable):
                    self.failure(failure)
                    self.attention('configuration_changed' if contains(failure,ConfigurationChanged) else 'unknown_failure')
                    self.close();return 0
                if type(failure)in (ViciUnavailable,GateReadbackUnavailable):self.failure(failure)
                reason=('gate_readback_unavailable' if type(failure)is GateReadbackUnavailable else
                        'vici_unavailable' if type(failure)is ViciUnavailable else
                        'scheduled_maintenance' if type(failure)is MaintenanceDue else
                        'known_uplink_change' if type(failure)is KnownUplinkChange else 'known_daemon_exit')
                self.write('RECOVERING','manual_stop' if self.d.stopped() else reason)
                if not self.close():return self.attention('recovery_not_proven')
                if self.d.stopped():
                    self.write('STOPPED','manual_stop',next_due=0);return 0
                # A normal return without stop or a typed owned-child exit is
                # not a license to restart an unexpectedly stopped controller.
                if failure is None:return self.attention('unknown_failure')
                if not self.backoff(reason):
                    self.write('STOPPED','manual_stop',next_due=0);return 0
            self.write('STOPPED','manual_stop',next_due=0);return 0
        except Exception as error:
            if type(error)is RequestedStop and self.d.stopped():
                try:self.write('RECOVERING','manual_stop',next_due=0)
                finally:
                    try:restored=self.close()
                    except Exception as close_error:
                        self.failure(close_error);restored=False
                if not restored:return self.attention('recovery_not_proven')
                self.write('STOPPED','manual_stop',next_due=0);return 0
            self.failure(error)
            reason='configuration_changed' if isinstance(error,ConfigurationChanged) else 'unknown_failure'
            try:self.attention(reason)
            finally:self.close()
            return 0
