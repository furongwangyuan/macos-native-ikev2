#!/usr/bin/python3
"""Fixed source-only long-running candidate. Disabled without separate evidence."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

FIXED=Path('/usr/local/family-vpn/production-guardian')
if __name__=='__main__' and (os.geteuid()!=0 or Path(__file__)!=FIXED/'service_supervisor.py'):
    raise SystemExit('Use only a separately reviewed fixed service installation.')
sys.path.insert(0,str(Path(__file__).parent))
import native_support as s
import native_runtime as runtime
import recover_only
import service_recovery_readback
from continuous_clock import make_clock
from supervisor_core import Supervisor,Configuration,Attention,OwnedDaemonExit,KnownUplinkChange,ViciUnavailable,GateReadbackUnavailable,ConfigurationChanged,RequestedStop,NetworkNotReady,valid_state
from supervisor_log import EventLog

RESOURCES=('membership_gate.py','membership_admission.py','enrollment.py','staged_issuer.py',
    'profile_export.py','parent-profile_builder.py','native_quiescent.py','service_pki.py','runtime_resources.py','current_crl.py','renewal.py','pki_io.py','native_closed.py','snapshot_io.py',
    'crypto/public_crl.py','crypto/public_crl_verify.c','crypto/public-crl-verify','crypto/build-manifest.json',
    'boot_record.py','boot_native.py','boot_store.py','boot_reconcile.py','boot_writer.py','boot_mutation_gate.py',
    'boot_finite_source.py','boot_server_source.py','boot_source.py','boot_handoff.py','production_source.py','production_boot.py','production_activation.py','short_admission.py','vici/__init__.py','vici/command_wrappers.py','vici/event_listener.py','vici/exception.py','vici/protocol.py','vici/session.py','fleet_tables.py','fleet_session.py','fleet_gate.py','fleet_native.py','fleet_controller.py',
    'registry.py','fleet_policy.py','fleet_vici.py','fleet_wire.py','fleet_exchange.py','fleet_transport.py',
    'fleet_coordinator.py','family-vpn.fleet.pf',
    'probe_owner.py','probe_policy.py','probe_contract.py','probe_process.py','probe_records.py',
    'probe_identity.py','probe_paths.py','probe_gate.py','native_runtime.py','native_gate.py','native_support.py','native_policy.py',
    'spawn_gate.py','controller.py','reviewed_policy.py','network_readonly.py','alf_readonly.py','alf_transaction.py',
    'crl_gate.py','continuous_clock.py','family-vpn.pf','swanctl.guardian.conf','mutation_spec.py',
    'mutation_gate.py','mutation_dispatch.py','recover_only.py','org.familyvpn.guardian-recovery.plist',
    'supervisor_core.py','supervisor_log.py','service_supervisor.py','service_recovery_readback.py','org.familyvpn.service.plist')
LABEL='org.familyvpn.guardian-recovery'
NATIVE_PREFIX=Path('/usr/local/family-vpn/strongswan-6.1.0')
PLUGINS=('attr','constraints','counters','drbg','kdf','kernel-pfkey','kernel-pfroute','nonce','openssl',
         'pem','pkcs1','pkcs8','pubkey','random','revocation','socket-default','test-vectors','vici','x509')
NATIVE_BINARIES=(s.CHARON,s.SWAN,*tuple(NATIVE_PREFIX/'lib/ipsec'/name for name in
    ['libcharon.0.dylib','libstrongswan.0.dylib','libtls.0.dylib','libvici.0.dylib']),
    *tuple(NATIVE_PREFIX/'lib/ipsec/plugins'/('libstrongswan-'+name+'.so') for name in PLUGINS),
    Path('/usr/local/family-vpn/openssl-3.5.9/lib/ossl-modules/legacy.dylib'))


# Exact reviewed literals only. Shape-compatible exception messages are not codes.
FAILURE_CODES=frozenset({
    'configuration_changed','source_or_native_code_changed','unknown_service_configuration',
    'unknown_native_configuration','native_data_permission_missing','native_ownership_record_missing',
    'recovery_job_plist_differs','recovery_job_readback_unknown','recovery_job_disabled',
    'fixed_command_failed','fixed_mutation_failed','main_pf_changed','root_baseline_changed',
    'guard_readback_failed','enable_token_unknown_preserve_guard','enable_reference_readback',
    'own_pf_reference_disappeared','own_reference_release_unverified','pf_reference_table_unknown',
    'pf_enabled_baseline_not_restored','pf_enabled_state_unknown','ambiguous_pf_reference_requires_review',
    'sysctl_readback','sysctl_external_change','forwarding_restore_incomplete','sysctl_values_output',
    'charon_start_failed','charon_process_absent','restoration_child_not_absent',
    'fleet_registry_changed','fleet_charon_identity','fleet_loaded_config_missing',
    'fleet_loaded_config_changed','fleet_generated_connection_not_loaded','fleet_vici_owner_unverified',
    'fleet_vici_deadline','fleet_controller_stopped','fleet_native_journal_incomplete','fleet_vici_peerpid_unverified',
    'fleet_host_policy_transition','fleet_transition_guard_unverified','fleet_transition_snapshot_unchanged',
    'fleet_transition_native_changed','unknown or multiply attributed host policy',
    'current_crl_changed_during_startup','current_loaded_crl_differs','pki_maintenance_incomplete',
    'alf_changed_preserving_external','crl_expired','crl_changed','active_gate_changed','closed_gate_changed',
    'bounded_exchange_unavailable','vici_unavailable','vici_exchange_timeout','vici_exchange_eof',
    'vici_exchange_io','vici_exchange_capacity','vici_exchange_socket','vici_exchange_protocol','vici_exchange_deadline_invalid',
    'production_source_binding','production_boot_prior_attention',
    'fleet_active_rules_or_tables_readback','fleet_active_postreadback','gate_readback_unavailable'
})
FAILURE_TYPES=frozenset({'Refused','Fault','PolicyTransition','Attention','ConfigurationChanged','RuntimeError',
    'ValueError','TypeError','OSError','PermissionError','FileNotFoundError','BlockingIOError',
    'TimeoutError','TimeoutExpired','JSONDecodeError','UnicodeDecodeError',
    'TransportFault','TransientTransportFault','ExchangeFault','ViciUnavailable','GateReadbackUnavailable'})


def failure_record(error):
    chain=[];seen=set();frames=[];frame_seen=set()
    while isinstance(error,BaseException) and id(error) not in seen and len(chain)<4:
        seen.add(id(error));name=type(error).__name__
        args=error.args
        code=args[0] if len(args)==1 and type(args[0])is str and args[0] in FAILURE_CODES else 'unknown'
        chain.append(dict(type=name if name in FAILURE_TYPES else 'unknown',code=code))
        # Reserve two tail frames per exception layer, so an outer traceback
        # cannot consume the eight-frame budget before its real cause is read.
        tb=error.__traceback__;walked=0;tail=[]
        while tb is not None and walked<4096:
            filename=Path(tb.tb_frame.f_code.co_filename);line=tb.tb_lineno
            if (filename.parent==s.BASE and filename.name in RESOURCES and filename.suffix=='.py'
                    and type(line)is int and 0<line<1000000):
                item=(filename.name,line)
                if not tail or tail[-1]!=item:tail=(tail+[item])[-2:]
            tb=tb.tb_next;walked+=1
        for module,line in tail:
            if (module,line) not in frame_seen:
                frame_seen.add((module,line));frames.append(dict(module=module,line=line))
        # A cleanup exception can implicitly replace the original failure.
        # Follow an explicit cause first, respecting deliberate context suppression.
        error=(error.__cause__ if error.__cause__ is not None else
               None if error.__suppress_context__ else error.__context__)
    return dict(version=1,event='service_failure',errors=chain,frames=frames)



def valid_failure_record(raw):
    """Accept only the existing bounded, non-message diagnostic schema."""
    value=s.json_value(raw)
    if (type(value)is not dict or set(value)!={'version','event','errors','frames'} or
            type(value['version'])is not int or value['version']!=1 or
            value['event']!='service_failure' or type(value['errors'])is not list or
            len(value['errors'])>4 or type(value['frames'])is not list or len(value['frames'])>8):
        raise Attention('unknown_service_failure_record')
    for item in value['errors']:
        if (type(item)is not dict or set(item)!={'type','code'} or
                type(item['type'])is not str or item['type'] not in FAILURE_TYPES|{'unknown'} or
                type(item['code'])is not str or item['code'] not in FAILURE_CODES|{'unknown'}):
            raise Attention('unknown_service_failure_record')
    for item in value['frames']:
        if (type(item)is not dict or set(item)!={'module','line'} or
                type(item['module'])is not str or item['module'] not in RESOURCES or
                Path(item['module']).name!=item['module'] or not item['module'].endswith('.py') or
                type(item['line'])is not int or not 0<item['line']<1000000):
            raise Attention('unknown_service_failure_record')
    return value


def read_configuration():
    raw=s.read(s.CONF/'supervisor-config.json',limit=4096)
    value=s.json_value(raw)
    if (not isinstance(value,dict) or set(value)!={'version','enabled'} or
            type(value['version'])is not int or value['version']!=1 or type(value['enabled'])is not bool):
        raise Attention('unknown_service_configuration')
    native_raw=s.read(s.CONF/'config.json',limit=4096)
    native=s.json_value(native_raw)
    if (not isinstance(native,dict) or set(native)!={'version','allow_data'} or
            type(native['version'])is not int or native['version']!=1 or type(native['allow_data'])is not bool):
        raise Attention('unknown_native_configuration')
    if value['enabled'] and not native['allow_data']:raise Attention('native_data_permission_missing')
    return Configuration(value['enabled'],hashlib.sha256(raw+b'\0'+native_raw).hexdigest())


def code_fingerprint():
    import runtime_resources
    values={'bundle:'+name:s.digest(runtime_resources.read(name)) for name in RESOURCES}
    # A plugin/daemon upgrade invalidates acceptance even if Python sources and
    # OS release stayed unchanged. Fixed actual binary filenames, not symlink
    # aliases or filesystem discovery, define the reviewed execution closure.
    values.update({'native:'+str(path):s.digest(s.read(path,mode=0o755,limit=33554432)) for path in NATIVE_BINARIES})
    return s.digest(json.dumps(values,sort_keys=True,separators=(',',':')).encode())


def recovery_job_gate():
    plist=Path('/Library/LaunchDaemons')/(LABEL+'.plist')
    if s.read(plist,mode=0o644)!=s.read(s.BASE/(LABEL+'.plist')):
        raise Attention('recovery_job_plist_differs')
    def query(args):
        result=subprocess.run(['/bin/launchctl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=s.ENV,timeout=6,close_fds=True)
        if result.returncode or len(result.stdout)>65536 or len(result.stderr)>65536:
            raise Attention('recovery_job_readback_unknown')
        return result.stdout.decode('utf-8','strict')
    text=query(['print','system/'+LABEL])
    if not text.startswith('system/'+LABEL+' = {\n') or not text.endswith('}\n'):
        raise Attention('recovery_job_layout_unknown')
    def one(key):
        values=re.findall(r'^\t'+re.escape(key)+r' = ([^\n]+)$',text,re.M)
        if len(values)!=1:raise Attention('recovery_job_layout_unknown')
        return values[0]
    one('state') # Volatile launchd state is not job identity.
    if (one('path')!=str(plist) or one('program')!='/usr/bin/python3' or
            one('domain')!='system' or one('type')!='LaunchDaemon'):
        raise Attention('recovery_job_identity_unknown')
    args=re.findall(r'^\targuments = \{\n((?:\t\t[^\n]+\n)+)\t\}$',text,re.M)
    if len(args)!=1 or [line[2:] for line in args[0].splitlines()]!=[
            '/usr/bin/python3','-I','-B',str(s.BASE/'recover_only.py')]:
        raise Attention('recovery_job_arguments_unknown')
    text=query(['print-disabled','system'])
    if not re.fullmatch(r'\s*disabled services = \{\n(?:\s*"[^"\n]+" => (?:enabled|disabled)\n)*\s*\}\n?',text):
        raise Attention('recovery_job_override_unknown')
    values=re.findall(r'^\s*"'+re.escape(LABEL)+r'" => (enabled|disabled)$',text,re.M)
    if len(values)>1 or values==['disabled']:raise Attention('recovery_job_disabled')


class ServiceStore:
    def load(self):
        path=s.STATE/'service-state.json'
        if not path.exists() and not path.is_symlink():return None
        return valid_state(s.json_value(s.read(path,limit=16384)))
    def save(self,value):
        valid_state(value);s.atomic(s.STATE/'service-state.json',json.dumps(value,sort_keys=True,allow_nan=False)+'\n')


class ServiceOwner(runtime.Owner):
    def __init__(self,session,store,configuration,clock):
        super().__init__(session,store)
        self.fingerprint=configuration.fingerprint;self.clock=clock;self.config_checked=-math.inf
    def daemon_configuration(self):
        # The parent strongswan.conf is already hash-pinned by native preflight.
        # Its sole familyvpn logger is overridden to a sink; structured bounded
        # metadata below supplies routine lifecycle diagnostics. Upstream
        # daemon.c uses configured loggers, so no default stdout/syslog fallback
        # is selected when this configured logger exists. No copytruncate or
        # raw packet/peer log collector is introduced into the data plane.
        body=super().daemon_configuration()
        old='path = /private/var/db/family-vpn/production-guardian/native-charon.log'
        if body.count(old)!=1:raise Attention('unexpected_daemon_log_template')
        # Use the stdout keyword, not a /dev/null filename: upstream
        # file_logger.open() may fchown filename targets. The reviewed spawn
        # gate already redirects stdout to /dev/null before exec.
        return body.replace(old,'path = stdout').replace('default = 1','default = -1').replace('net = 0','net = -1').replace('enc = 0','enc = -1')
    def known_child_alive(self):
        if self.daemon is not None and self.daemon.poll() is not None:
            raise OwnedDaemonExit('owned_charon_exited')
    def observe(self,timeout):
        self.known_child_alive();return super().observe(timeout)
    def check_local(self,timeout):
        self.known_child_alive()
        if self.clock()-self.config_checked>=5:
            if read_configuration().fingerprint!=self.fingerprint:raise ConfigurationChanged('configuration_changed')
            self.config_checked=self.clock()
        try:return super().check_local(timeout)
        except (runtime.ctl.Fault,s.Refused) as error:
            # The child can exit after known_child_alive() but before libproc's
            # separate identity/path reads. Only the current owned Popen handle
            # can prove that exit; missing metadata alone never does.
            unavailable=(type(error)is runtime.ctl.Fault and error.args==('charon_process_absent',)) or (
                type(error)is s.Refused and error.args in
                (('process_identity_unavailable',),('process_path_unavailable',)))
            if unavailable:self.known_child_alive()
            raise
    def check_uplink(self,local):
        if self.data_mode and runtime.network.known_change(self.session['health'],local):
            # Controller normally audits SPD after check_local. Do not let a
            # typed local change bypass that audit and conceal unrelated native
            # damage. Overlap/incomplete/old-host ambiguity remains ATTENTION.
            snapshot=self.observe(5);proof=self.audit(snapshot,(),5)
            if snapshot.kind=='unique' and proof.ready and proof.generation==snapshot.generations[0]:
                self.check_routes(proof.generation,5)
            elif snapshot.kind!='absent' or proof.hosts:
                raise runtime.ctl.Fault('uplink_change_native_scope_unknown')
            if runtime.network.uplink(external=False)!=local:
                raise runtime.ctl.Fault('uplink_change_not_stable')
            raise KnownUplinkChange('known_en0_dualstack_change')
        return super().check_uplink(local)


class NativeDependencies:
    def __init__(self,clock):
        self.clock=clock;self.store=s.Store();self.log=EventLog();self.config=None;self.code=None;self.assert_held=None
    def failure(self,error):
        try:
            import production_source
            raw=json.dumps(failure_record(error),sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
            if len(raw.encode('utf-8'))>4096:return
            path=s.STATE/'service-error.json'
            if path.exists() or path.is_symlink():
                previous=s.read(path,limit=4096)
                valid_failure_record(previous)
                history=s.STATE/'service-error-history'
                s.directory(history)
                archive=history/(s.digest(previous)+'.json')
                if archive.exists() or archive.is_symlink():
                    if s.read(archive,limit=4096)!=previous:
                        raise Attention('service_failure_history_conflict')
                else:production_source.write_new(archive,previous)
                if s.read(path,limit=4096)!=previous:
                    raise Attention('service_failure_changed_before_archive')
            s.atomic(path,raw)
        except BaseException:pass
    def configuration(self):return read_configuration()
    def boot(self):return s.boot()
    def stopped(self):return runtime.STOP.is_set()
    def wait(self,seconds):runtime.STOP.wait(seconds)
    def event(self,phase,reason,attempts):self.log.emit(phase,reason,attempts,time.time())
    def authorize(self,config):
        import production_activation
        code=code_fingerprint()
        if self.code is not None and self.code!=code:raise ConfigurationChanged('source_or_native_code_changed')
        production_activation.authorize(code,os.uname().release,os.uname().machine)
        recovery_job_gate();self.config=config;self.code=code
    def restored(self,expected):
        try:return service_recovery_readback.verify(self.store,expected)
        except Exception:return False
    def recover(self,expected_owner=False):
        previous=self.store.load()
        if previous is None:
            if expected_owner:raise Attention('native_ownership_record_missing')
            return True
        if previous['active'] and previous['boot']!=s.boot():
            recover_only.new_boot_observation(previous,self.store);return False
        expected=previous
        if previous['active']:
            owner=runtime.Owner(previous,self.store)
            if not owner.cleanup():return False
        saved=self.store.load()
        return (saved is not None and saved['active'] is False and saved['phase']=='RESTORED'
                and service_recovery_readback.digest(saved)==service_recovery_readback.digest(expected)
                and self.restored(saved))
    def resume_network_wait(self,previous,boot,config):
        """Only the exact ownerless network wait may survive another boot."""
        if (previous['phase']!='BACKOFF' or previous['reason']!='network_not_ready'
                or previous['boot']==boot or config.enabled is not True
                or previous['fingerprint']!=config.fingerprint):
            raise Attention('network_wait_boot_scope')
        path=s.STATE/'service-state.json';raw=s.read(path,limit=16384)
        if valid_state(s.json_value(raw))!=previous or self.store.load() is not None or s.boot()!=boot:
            raise Attention('network_wait_boot_source_changed')
        self.authorize(config)
        import native_quiescent
        observed=native_quiescent.verify(self.assert_held)
        if (observed['boot']!=boot or s.boot()!=boot or self.store.load() is not None
                or s.read(path,limit=16384)!=raw or self.configuration()!=config):
            raise Attention('network_wait_boot_source_changed')
        return True
    def preflight(self):
        # Recheck activation evidence/code/job after every abnormal recovery,
        # rather than trusting a previous process's startup verdict.
        current=self.configuration()
        if self.config is None or current.fingerprint!=self.config.fingerprint:
            raise ConfigurationChanged('configuration_changed')
        self.authorize(current)
        if self.stopped():return None
        import service_pki
        service_pki.maintain(current,self.store,self.assert_held)
        if self.stopped():return None
        try:session=runtime.preflight(True)
        except runtime.network.UplinkNotReady as error:
            if (type(error)is not runtime.network.UplinkNotReady or len(error.args)!=1
                    or error.args[0] not in runtime.network.WAIT_CODES):
                raise
            raise NetworkNotReady('network_not_ready') from error
        gate=runtime.native_gate.Gate({},self.store)
        filters,nat=gate.roots();runtime.native_gate.default_root(filters,nat)
        runtime.native_gate.default_auxiliary(gate.auxiliary_roots())
        runtime.native_gate.prepared_main(s.read(s.PFC,mode=None,limit=20000))
        runtime.native_gate.apple_source()
        session['test_action']='service';return session
    def prepare(self,session):
        # RUN paths are normally recreated after boot only after closed fresh
        # baseline/evidence. No recovery action creates missing runtime paths.
        for path in [s.RUN.parent,s.RUN]:s.directory(path)
        if session.get('test_action')=='service':
            import production_source
            production_source.prepare(session,self.config,self.code)
        self.store.save(session)
        from fleet_native import FleetOwner
        return FleetOwner(session,self.store,self.config,self.clock)
    def setup(self,owner):
        try:owner.setup()
        except runtime.ctl.Cancelled as error:
            if (type(error)is runtime.ctl.Cancelled and error.args==('requested_stop',)
                    and runtime.STOP.is_set()):
                raise RequestedStop('requested_stop') from error
            raise
    def serve(self,owner):
        from fleet_controller import Controller
        from fleet_transport import TransientTransportFault
        controller=Controller(owner,math.inf,self.clock)
        try:controller.run()
        except runtime.ctl.Fault as error:
            # Only an exact typed known cause followed by the controller's
            # normal close path may be retried. A close failure or an unknown
            # wrapper is never classified from a loose cause-chain search.
            cause=controller.coordinator.failure
            # Only the controller's exact cancellation wrapper after its finally
            # guard returned successfully is a requested stop. Never search a
            # cleanup failure's context and turn that failure into cancellation.
            if (type(error)is runtime.ctl.Fault and error.args==('fleet_controller_stopped',)
                    and error.__cause__ is cause and type(cause)is runtime.ctl.Cancelled
                    and cause.args==('requested_stop',) and runtime.STOP.is_set()):
                raise RequestedStop('requested_stop') from error
            if type(cause) in (OwnedDaemonExit,KnownUplinkChange) and error.__cause__ is cause:
                raise type(cause)('known_service_transition') from error
            # A known activation readback failure may retry only after the
            # coordinator closed the exact recorded rules/tables and the
            # controller's final guard also returned. Unknown anchor contents
            # fail that guard and cannot reach this original exact wrapper.
            # The supervisor still requires full native cleanup/readback
            # before backoff; this classification never opens any data path.
            closed=getattr(controller.coordinator,'last_result',None)
            if (type(error)is runtime.ctl.Fault and error.args==('fleet_controller_stopped',)
                    and error.__cause__ is cause and type(cause)is s.Refused
                    and cause.args in (('fleet_active_rules_or_tables_readback',),('fleet_active_postreadback',))
                    and closed is not None and closed.state=='STOPPED'
                    and closed.global_guard_confirmed is True):
                raise GateReadbackUnavailable('gate_readback_unavailable') from error
            # A fresh, fully bounded read has already been retried with native
            # protection and ownership checked between attempts. Only these
            # exact I/O failures or bounded event-capacity pressure may use
            # the existing close/readback/backoff
            # lifecycle; protocol, source and identity failures still latch.
            if (type(error)is runtime.ctl.Fault and error.args==('fleet_controller_stopped',)
                    and error.__cause__ is cause and type(cause)is TransientTransportFault
                    and cause.args in (('vici_exchange_timeout',),('vici_exchange_eof',),('vici_exchange_io',),('vici_exchange_capacity',))):
                raise ViciUnavailable('vici_unavailable') from error
            raise
    def cleanup(self,owner):
        if not owner.cleanup():return False
        saved=self.store.load()
        return (saved is not None and saved['active'] is False and saved['phase']=='RESTORED'
                and service_recovery_readback.digest(saved)==service_recovery_readback.digest(owner.session)
                and self.restored(saved))


def main():
    if len(sys.argv)!=1:raise Attention('service_takes_no_arguments')
    os.umask(0o077)
    for path in [s.BASE,s.STATE,s.CONF]:s.trusted(path,0o700)
    for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(sig,lambda *_:runtime.STOP.set())
    clock=make_clock();deps=NativeDependencies(clock)
    try:
        import boot_native
        import production_boot
        boot_native.Native.installed_scope()
        io=boot_native.Native()
        with io.locked():
            deps.assert_held=io.held
            production_boot.recover_locked(io,clock)
            return Supervisor(deps,ServiceStore(),clock).run()
    except BlockingIOError:return 75 # Retry after the independent recovery owner releases the locks.
    except Exception as error:
        deps.failure(error)
        # Do not turn an unknown validation/disk error into a launchd restart
        # loop. The independent recover-only job can close a remaining owner.
        s.say('service_attention',data_activation_not_retried=True);return 0


if __name__=='__main__':sys.exit(main())
