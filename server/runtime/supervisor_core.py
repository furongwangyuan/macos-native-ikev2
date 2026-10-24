"""Injected sole-owner service lifecycle; no process, socket or native I/O here."""
from dataclasses import dataclass
import math


class Attention(RuntimeError):pass
class OwnedDaemonExit(RuntimeError):pass
class KnownUplinkChange(RuntimeError):pass
class ViciUnavailable(RuntimeError):pass
class MaintenanceDue(RuntimeError):pass
class ConfigurationChanged(Attention):pass
class RequestedStop(RuntimeError):pass
class NetworkNotReady(RuntimeError):pass


PHASES={'DISABLED','PREFLIGHT','STARTING','RUNNING','RECOVERING','BACKOFF','STOPPED','ATTENTION'}
REASONS={'initial','disabled','manual_stop','known_daemon_exit','known_uplink_change','scheduled_maintenance','interrupted_owner',
         'unknown_failure','configuration_changed','activation_not_accepted',
         'recovery_not_proven','retry_budget_exhausted','cross_boot_unfinished',
         'latched_attention','running','backoff','preflight','starting','network_not_ready','vici_unavailable'}
RETRY_WINDOW=900
RETRY_DELAYS=(5,15,60)
MAX_ATTEMPTS=3


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
        self.state=None;self.owner=None
    def failure(self,error):
        # Diagnostics are optional and must never replace phase/cleanup work.
        try:
            hook=getattr(self.d,'failure',None)
            if hook is not None:hook(error)
        except BaseException:pass
    def write(self,phase,reason,**fields):
        self.state.update(phase=phase,reason=reason,updated=self.clock(),**fields)
        valid_state(self.state);self.store.save(self.state)
        # The durable lifecycle remains mandatory. Its auxiliary event log must
        # not close a healthy owner when only logging is unavailable.
        try:self.d.event(phase,reason,len(self.state['attempts']))
        except Exception as error:self.failure(error)
    def attention(self,reason):
        # Latch BEFORE cleanup: a crash while closing must never turn an unknown
        # failure into an authorized automatic restart on the next invocation.
        self.write('ATTENTION',reason,next_due=0)
        return 0 # Successful exit tells the fixed launchd job not to respawn.
    def close(self):
        if self.owner is None:return self.d.recover(expected_owner=False)
        result=self.d.cleanup(self.owner);self.owner=None
        return result
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
        due=self.state['next_due'] if preserve else now+delay
        self.write('BACKOFF',reason,next_due=due)
        while self.clock()<due:
            if self.d.stopped():return False
            self.d.wait(min(.5,due-self.clock()))
            if self.d.configuration().fingerprint!=self.state['fingerprint']:
                raise ConfigurationChanged('configuration_changed')
        return not self.d.stopped()
    def run(self):
        previous=self.store.load()
        if previous is not None:valid_state(previous)
        boot=self.d.boot()
        try:config=self.d.configuration()
        except Exception as error:
            self.failure(error)
            self.state=dict(previous) if previous else dict(version=1,phase='DISABLED',boot=boot,
                fingerprint='0'*64,attempts=[],next_due=0,reason='initial',updated=self.clock())
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
        if phase=='ATTENTION':return self.attention('latched_attention')
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
                reason=('network_not_ready' if phase=='BACKOFF' and self.state['reason']=='network_not_ready'
                        else 'interrupted_owner')
                if not self.backoff(reason,preserve=phase=='BACKOFF'):
                    self.write('STOPPED','manual_stop',next_due=0);return 0
            while not self.d.stopped():
                if self.d.configuration().fingerprint!=self.state['fingerprint']:
                    raise ConfigurationChanged('configuration_changed')
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
                if failure is not None and type(failure) not in (OwnedDaemonExit,KnownUplinkChange,MaintenanceDue,ViciUnavailable):
                    self.failure(failure)
                    self.attention('configuration_changed' if contains(failure,ConfigurationChanged) else 'unknown_failure')
                    self.close();return 0
                if type(failure)is ViciUnavailable:self.failure(failure)
                reason=('vici_unavailable' if type(failure)is ViciUnavailable else
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
