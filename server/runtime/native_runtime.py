#!/usr/bin/python3
"""Bounded sole-writer native candidate; no production launchd installation."""
import contextlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time

FIXED=Path('/usr/local/family-vpn/production-guardian')
if __name__=='__main__' and (os.geteuid()!=0 or Path(__file__)!=FIXED/'native_runtime.py'):
    raise SystemExit('Use the reviewed fixed installation only.')
sys.path.insert(0,str(Path(__file__).parent))
import native_support as s
import native_gate
import native_policy as policies
import network_readonly as network
import alf_readonly as alf
import alf_transaction
import crl_gate
import probe_owner
import probe_policy
import fleet_session,registry,fleet_policy
from mutation_dispatch import Dispatcher
import controller as ctl
import reviewed_policy as policy
from continuous_clock import make_clock

STOP=threading.Event()
FILES={'daemon':s.RUN/'strongswan.conf',
       'connection':Path('/usr/local/etc/family-vpn/swanctl/swanctl.guardian-test.conf')}
CONFIG_SHA='1254799aacb88f7d0ccca5c59e3ff8ea2405a964b890e4594cf075040186a0f9'
ACTIONS=('check','closed-test','closed-charon-term-test','closed-charon-kill-test',
         'closed-suite','data-test','restore')
CLOSED_SIGNALS={'closed-test':None,'closed-charon-term-test':signal.SIGTERM,
                'closed-charon-kill-test':signal.SIGKILL}


def require_closure():
    s.require_local_modules(('native_runtime','native_support','native_gate','native_policy',
        'mutation_dispatch','mutation_spec','alf_readonly','alf_transaction','network_readonly',
        'controller','reviewed_policy','crl_gate','continuous_clock','probe_owner','probe_policy',
        'probe_contract','probe_process','probe_records','probe_identity','probe_paths',
        'fleet_session','registry','fleet_policy'))


@contextlib.contextmanager
def budget(seconds,protect=False):
    old=s.DEADLINE;end=time.monotonic()+seconds
    s.DEADLINE=end if protect or old is None else min(old,end)
    try:yield
    finally:s.DEADLINE=old


def pending_native(session):
    items=session.get('floors',[])+session.get('keepers',[])+([session['floor_gc']] if session.get('floor_gc') else [])
    return any(r.get('status') not in ['deleted','absent'] for r in items)


def configured():
    value=s.json_value(s.read(s.CONF/'config.json',limit=4096))
    if (not isinstance(value,dict) or set(value)!={'version','allow_data'} or
            type(value['version'])is not int or value['version']!=1 or type(value['allow_data'])is not bool):
        raise s.Refused('unknown_activation_configuration')
    return value


def alf_gate(value,data):
    if data:
        # New sessions preserve the host's enabled firewall mode and unrelated
        # app permissions; only VPN-specific allowances are owned.
        alf_transaction.snapshot(value,baseline=True)
    else:
        # A stopped VPN needs its own process blocked, not all host services.
        alf_transaction.snapshot(value,baseline=True)


def native_socket():
    info=s.SOCKET.lstat();s.trusted(s.SOCKET.parent,0o700)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1
            or info.st_gid!=0 or stat.S_IMODE(info.st_mode) not in [0o600,0o660]):
        raise s.Refused('private_vici_socket_required')


class Owner:
    def __init__(self,session,store):
        require_closure();s.session_history(session)
        self.data_mode=session['allow_data']
        self.session,self.store=session,store
        self.dispatcher=Dispatcher(session,store);s.MUTATOR=self.dispatcher
        self.gate=native_gate.Gate(session,store)
        self.alf_transaction=(alf_transaction.Transaction(session,store)
                              if session.get('allow_data') is True else None)
        self.daemon=None;self.sa_text=''
        self.probe_clock=make_clock();self.probe=probe_owner.Adapter(self)
        policies.save=lambda value:self.save()
        policies.say=lambda _:None # no raw SPD/SAD/process or provider data in user log
    def save(self):self.store.save(self.session)
    def same_boot(self):
        s.session_history(self.session)
        if self.session['allow_data'] is not self.data_mode:raise s.Refused('owner_session_mode_changed')
        if self.session['boot']!=s.boot():raise s.Refused('new_boot_needs_separate_reconciliation')
    def bind_file(self,key,body):
        path=FILES[key];data=body.encode() if isinstance(body,str) else body
        exists=path.exists() or path.is_symlink()
        if exists and s.read(path)!=data:raise s.Refused('existing_runtime_configuration_differs')
        rec=dict(phase='apply-intent',created=not exists,sha256=s.digest(data))
        self.session.setdefault('files',{})[key]=rec;self.save()
        if not exists:s.atomic(path,data)
        if s.digest(s.read(path))!=rec['sha256']:raise s.Refused('runtime_file_readback')
        rec['phase']='owned';self.save()
    def restore_files(self):
        for key,rec in self.session.get('files',{}).items():
            if key not in FILES:raise s.Refused('unknown_runtime_file_scope')
            path=FILES[key]
            if rec['phase']=='restored':continue
            exists=path.exists() or path.is_symlink()
            if exists and s.digest(s.read(path))!=rec['sha256']:raise s.Refused('runtime_file_external_change')
            if not exists and not rec['created']:raise s.Refused('preexisting_runtime_file_disappeared')
            rec['phase']='restore-intent';self.save()
            if exists and rec['created']:path.unlink();s.sync_dir(path.parent)
            rec['phase']='restored';self.save()
    def owned_process(self):
        record=self.session.get('child',{})
        identity=record.get('identity')
        if identity is None:
            # An unacknowledged exec gate never receives GO. EOF/5s deadline
            # stops it. No guessed PID or process-name termination is allowed.
            if record and record.get('phase')!='spawn-intent':raise s.Refused('missing_owned_child_identity')
            return None
        current=s.process(identity['pid'])
        if current is None:return None
        if not s.same_birth(current,identity) or current['path'] not in [identity['path'],str(s.CHARON)]:
            raise s.Refused('owned_child_identity_changed')
        return current
    def spawn(self):
        self.session['child']=dict(phase='spawn-intent',identity=None);self.save()
        proc=subprocess.Popen(['/usr/bin/python3','-I','-B',str(s.BASE/'spawn_gate.py')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            env=s.ENV,close_fds=True,start_new_session=True,cwd='/')
        self.daemon=proc
        try:
            s.wait_ready(proc)
            identity=s.process(proc.pid)
            if not identity or identity['uid']!=0 or identity['pgid']!=proc.pid or proc.poll() is not None:
                raise s.Refused('exec_gate_identity_failed')
            self.session['child'].update(phase='go-intent',identity=identity);self.save()
            proc.stdout.close()
            proc.stdin.write(b'GO\n');proc.stdin.flush();proc.stdin.close()
            self.session['child']['phase']='go-sent';self.save()
        except BaseException:
            if proc.stdin and not proc.stdin.closed:proc.stdin.close() # EOF denies exec before GO
            if proc.stdout and not proc.stdout.closed:proc.stdout.close()
            raise
    def stop_child(self):
        rec=self.session.get('child')
        if not rec:return
        # Popen handle is exact for this process, even before journal identity.
        if not rec.get('identity'):
            if self.daemon is not None:
                if self.daemon.stdin and not self.daemon.stdin.closed:self.daemon.stdin.close()
                self.daemon.wait(timeout=6)
            rec['phase']='exited';self.save();return
        # Reap a child which exited between the last audit and cleanup before
        # querying libproc: a zombie can have no readable executable path.
        if self.daemon is not None:self.daemon.poll()
        current=self.owned_process()
        if current is not None:
            rec['phase']='stop-intent'
            try:self.save()
            except Exception:pass # Closing/reaping the exact owned child must not wait for disk.
            os.kill(current['pid'],signal.SIGTERM)
            end=time.monotonic()+5
            while self.owned_process() is not None and time.monotonic()<end:
                if self.daemon is not None:self.daemon.poll()
                time.sleep(0.05)
            current=self.owned_process()
            if current is not None:
                os.kill(current['pid'],signal.SIGKILL)
                if self.daemon is not None:self.daemon.wait(timeout=3)
                end=time.monotonic()+3
                while self.owned_process() is not None and time.monotonic()<end:time.sleep(0.05)
                if self.owned_process() is not None:raise s.Refused('owned_child_did_not_exit')
        if self.daemon is not None:self.daemon.wait(timeout=1)
        rec['phase']='exited';self.save()
    def daemon_configuration(self):
        return '''include /usr/local/etc/family-vpn/strongswan.conf
charon {
    plugins {
        socket-default { use_ipv6 = no }
    }
    filelog {
        familyvpn {
            path = /private/var/db/family-vpn/production-guardian/native-charon.log
            default = 1
            net = 0
            enc = 0
        }
    }
}
'''
    def connection_configuration(self):
        import fleet_session,registry
        fleet_session.history(self.session)
        return registry.render_swanctl(self.session['fleet']['registry']).encode()
    def setup(self):
        self.same_boot();self.gate.prepare()
        policies.install_floors(self.session);policies.add_keeper(self.session,'held-keeper')
        policies.verify_native_protection(self.session)
        if self.alf_transaction is not None:self.alf_transaction.prepare()
        self.gate.set_knob(s.ESP,4500)
        self.bind_file('daemon',self.daemon_configuration())
        self.bind_file('connection',self.connection_configuration())
        if s.SOCKET.exists() or s.SOCKET.is_symlink():
            native_socket()
            if s.run(['/usr/sbin/lsof','-nP',s.SOCKET],check=False).returncode!=1:raise s.Refused('vici_has_owner')
            self.session['stale_socket_unlink_intent']=True;self.save();s.SOCKET.unlink()
        self.spawn()
        end=time.monotonic()+20
        while not s.SOCKET.exists():
            if STOP.is_set():raise ctl.Cancelled('requested_stop')
            if not self.owned_process() or time.monotonic()>=end:raise s.Refused('charon_start_failed')
            time.sleep(0.1)
        native_socket()
        if self.owned_process()['path']!=str(s.CHARON):raise s.Refused('gate_not_execed_expected_charon')
        pid=self.session['child']['identity']['pid']
        sockets=s.run(['/usr/sbin/lsof','-nP','-a','-p',str(pid),'-iUDP','-F','pftn']).stdout
        if re.findall(r'^t(.+)$',sockets,re.M)!=['IPv4','IPv4']:raise s.Refused('outer_not_ipv4_only')
        s.run([s.SWAN,'--load-all','--noprompt','--uri',s.URI,'--file',FILES['connection']],timeout=10)
        crl_gate.loaded_crl_gate(s,self.session['crl'])
        self.session['phase']='WAITING' if self.session['allow_data'] else 'CLOSED_TEST';self.save()
        self.check_local(10)
        if self.alf_transaction is not None:
            if STOP.is_set():raise ctl.Cancelled('requested_stop')
            if not self.gate.closed():raise s.Refused('alf_open_requires_closed_data_gate')
            policies.verify_native_protection(self.session)
            self.alf_transaction.open() # Final setup write; permits IKE only.
            self.check_local(10)
    def guard(self,reason,timeout):
        with budget(timeout,True):
            # Guarding transitions also closes forwarding here; old controller
            # never retains a second write authority and observer hooks are inert.
            # Keep prepared ALF open through WAITING/rekey: closing it here
            # would block the IKE exchanges needed to establish a new CHILD.
            try:
                self.same_boot()
                if not self.gate.protect():raise s.Refused('closed_gate_unverified')
            finally:
                self.probe.stop() # local listener must close even if PF protection failed
    def close_forwarding(self,timeout):
        with budget(timeout,True):self.gate.restore_sysctls()
    def stop_observers(self,timeout):
        with budget(timeout,True):self.probe.stop()
    def observe(self,timeout):
        if STOP.is_set():raise ctl.Cancelled('requested_stop')
        with budget(timeout):
            native_socket();self.sa_text=s.run([s.SWAN,'--list-sas','--uri',s.URI]).stdout
        return ctl.parse_snapshot(self.sa_text)
    def audit(self,snapshot,known,timeout):
        with budget(timeout):
            raw=s.run(['/usr/sbin/setkey','-DP']).stdout;records=policies.parse_spd(raw)
            owned=self.session.get('floors',[])+self.session.get('keepers',[])
            if len(owned)!=3 or any(x.get('status')!='owned' for x in owned):raise ctl.Fault('native_journal_incomplete')
            native=[{k:r[k] for k in ['id','src','dst','direction','kind','requests']} for r in owned]
            active={}
            for r in records:
                kind={'generate':5,'discard':0,'ipsec':2}.get(r['kind'])
                if kind is None:raise ctl.Fault('unknown_spd_kind')
                remaining=s.DEADLINE-time.monotonic()
                if remaining<=0:raise ctl.Fault('spd_audit_budget')
                active[r['id']]=policies.policy_id_active(r['id'],kind,1 if r['direction']=='in' else 2,timeout=min(3,remaining))
            return ctl.audit_inventory(records,active,native,snapshot,known)
    def check_routes(self,generation,timeout):
        with budget(timeout):
            for flag,vip in [('-inet',generation.vip4),('-inet6',generation.vip6)]:
                raw=s.run(['/sbin/route','-n','get',flag,vip]).stdout
                try:policy.verify_route(raw,vip)
                except ValueError as error:raise ctl.RouteTransition('exact_vip_route_changed') from error
            raw=s.run(['/sbin/route','-n','get','-inet',generation.peer4]).stdout
            if not re.search(r'^\s*interface:\s+en0\s*$',raw,re.M):raise ctl.Fault('outer_route_changed')
    def check_local(self,timeout):
        with budget(timeout):
            self.same_boot()
            if self.daemon is not None:self.daemon.poll()
            proc=self.owned_process()
            if proc is None:raise ctl.Fault('charon_process_absent')
            if proc['path']!=str(s.CHARON):raise ctl.Fault('charon_exited_or_changed')
            current_alf=alf.snapshot()
            matches=(alf_transaction.active_matches(self.alf_transaction.record,current_alf)
                     if self.alf_transaction is not None else current_alf==self.session['alf_before'])
            if not matches:raise ctl.Fault('alf_vpn_rule_changed')
            local=network.uplink(external=False)
            if self.session['crl']['next']<=time.time():raise ctl.Fault('crl_expired')
            if s.digest(s.read(crl_gate.CRL))!=self.session['crl']['sha256']:raise ctl.Fault('crl_changed')
            if self.gate.state.get('mode')=='active':
                if not self.gate.verify_active():raise ctl.Fault('active_gate_changed')
            elif not self.gate.closed():raise ctl.Fault('closed_gate_changed')
            if not self.data_mode and self.observe(timeout).kind!='absent':raise ctl.Fault('closed_mode_ike_observed')
            # All unrelated identity/ALF/CRL/PF assertions precede the service
            # subclass's narrowly typed local-uplink change classification.
            self.check_uplink(local)
            self.probe.check()
    def check_uplink(self,local):
        if any(v!=self.session['health'].get(k) for k,v in local.items()):raise ctl.Fault('uplink_changed')
    def activate(self,generation,proof,timeout):
        with budget(timeout):
            if not self.session['allow_data']:raise ctl.Fault('data_not_enabled')
            if STOP.is_set():raise ctl.Cancelled('requested_stop')
            if not proof.ready or proof.generation!=generation:raise ctl.Fault('wrong_generation_proof')
            self.check_local(timeout)
            text=policy.render_pf(s.read(s.BASE/'family-vpn.pf').decode(),generation.info())
            text,count=re.subn(r'^table <familyvpn_home4> persist \{[^\n]*\}$',
                'table <familyvpn_home4> persist { '+self.session['health']['public4']+' }',text,flags=re.M)
            if count!=1:raise ctl.Fault('wan_block_table_layout')
            start_probe=self.probe.want_start()
            if start_probe:
                probe_policy.verified_reply_scope(generation,proof)
                self.check_routes(generation,timeout)
                policies.verify_native_protection(self.session)
                text=probe_policy.rules(text,generation)
            self.session['activation_generation']=generation.info();self.session['phase']='WAITING';self.save()
            self.gate.activate(text)
            if start_probe:self.probe.start(generation,proof)
            self.session.update(child_seen=True,phase='ACTIVE');self.save()
    def request_rekey(self,*args):raise ctl.Fault('no_forced_rekey_in_this_native_stage')
    def wait(self,seconds):STOP.wait(seconds)
    def save_event(self,event):
        # Bounded fixed event name and generation count, not arbitrary exception
        # strings, peer identities, paths or captured process output.
        entry=dict(event=event['event'],at=time.time())
        if type(event.get('generation'))is int:entry['generation']=event['generation']
        self.session.setdefault('events',[]).append(entry)
        self.session['events']=self.session['events'][-32:]
        with budget(5,True):self.save()
        s.say('guardian_event',**entry)
    def cleanup(self):
        s.DEADLINE=None;errors=[]
        try:self.same_boot()
        except Exception:
            # Even a corrupt in-memory journal must not strand our actual child.
            try:self.probe.stop()
            except Exception:pass
            raise
        # An earlier owner may have died with a gated mutator in flight.
        # Reap that exact process BEFORE any recovery command can be issued.
        try:self.dispatcher.settle()
        except Exception:
            for key in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding']:
                try:s.close_owned_forwarding(key,self.store.durable)
                except Exception:pass
            try:self.probe.stop()
            except Exception:pass
            try:self.stop_child()
            except Exception:pass
            self.session.update(phase='ATTENTION',active=True,cleanup_codes=['unsettled_mutator'],
                                recovery_result='protection-unverified')
            try:self.save()
            except Exception:pass
            s.say('native_recovery',complete=False,result='protection-unverified',
                  reason_codes=['unsettled_mutator'],alf_was_never_modified=self.alf_transaction is None,
                  alf_close_verified=False)
            return False
        self.session['phase']='CLOSING'
        alf_closed=False
        if self.alf_transaction is not None:
            try:self.alf_transaction.close();alf_closed=True
            except Exception:errors.append('alf_close')
        # Do NOT make protection conditional on writing a healthy disk.
        pf=self.session.get('pf')
        protected=False
        try:protected=self.gate.protect() if pf and pf.get('phase')!='restored' else False
        except Exception:errors.append('guard')
        try:self.save()
        except Exception:errors.append('journal')
        try:self.probe.stop()
        except Exception:errors.append('probe_child')
        try:self.stop_child()
        except Exception:errors.append('child')
        try:self.gate.restore_sysctls()
        except Exception:errors.append('sysctl')
        stopped=False
        try:stopped=(s.run(['/usr/bin/pgrep','-x','charon'],check=False).returncode==1 and s.sad_empty())
        except Exception:pass
        if not stopped:errors.append('native_daemon_or_sad')
        if self.alf_transaction is not None and stopped and alf_closed and not errors:
            try:self.alf_transaction.restore()
            except Exception:errors.append('alf_restore')
        if stopped and not errors:
            try:
                if pending_native(self.session):
                    if not protected:raise s.Refused('policy_cleanup_requires_guard')
                    policies.wait_dead_host_policies(self.session,self.gate,True)
                    policies.remove_floors(self.session)
                if policies.read_spd()[0]:raise s.Refused('spd_not_baseline')
                if s.ESP in self.session.get('knobs',{}):self.gate.set_knob(s.ESP,self.session['baseline'][s.ESP])
                self.restore_files();self.gate.restore_pf()
            except Exception:errors.append('owned_recovery')
        try:
            current_alf=alf.snapshot()
            self.session['alf_external_changes_preserved']=current_alf!=self.session['alf_before']
            restored=(alf_transaction.restored_matches(self.alf_transaction.record,current_alf)
                      if self.alf_transaction is not None else current_alf==self.session['alf_before'])
            if not restored:
                errors.append('alf_baseline_not_restored' if self.data_mode else 'closed_alf_changed')
        except Exception:errors.append('alf_readback')
        self.session['cleanup_codes']=sorted(set(errors))
        # This distinguishes exact restoration from a retained, independently
        # read-back closed gate. Never equate an ATTENTION journal with proof
        # that the current kernel is protected.
        closed=False
        if errors:
            try:closed=self.gate.closed()
            except Exception:pass
        self.session['recovery_result']=('restored' if not errors else
            'protected-needs-attention' if closed else 'protection-unverified')
        self.session['phase']='ATTENTION' if errors else 'RESTORED';self.session['active']=bool(errors)
        self.save()
        # The durable recovery result and later kernel readback determine
        # success. An unavailable diagnostic output must not replace them.
        try:
            s.say('native_recovery',complete=not errors,reason_codes=self.session['cleanup_codes'],
                  result=self.session['recovery_result'],alf_was_never_modified=self.alf_transaction is None,
                  alf_close_verified=alf_closed,
                  alf_restored_verified=self.alf_transaction is not None and not errors)
        except Exception:pass
        return not errors


def preflight(data, *, probe_mode='off'):
    require_closure()
    import membership_gate
    membership_gate.check()
    if type(data)is not bool:raise s.Refused('strict_preflight_mode_required')
    probe_policy.mode(probe_mode,data)
    if probe_mode!='off':
        probe_owner.probe_paths.payload();probe_owner.probe_paths.gate_source()
        probe_owner.port_absent()
    if probe_mode!='off':raise s.Refused('fleet_probe_mode_unavailable')
    import fleet_session
    fleet=fleet_session.static(s.read(fleet_session.REGISTRY,limit=65536))
    config=configured()
    if data and not config['allow_data']:raise s.Refused('data_activation_default_refused')
    before=alf.snapshot();alf_gate(before,data)
    if s.run(['/usr/bin/pgrep','-x','charon'],check=False).returncode!=1:raise s.Refused('existing_charon_or_inventory_failure')
    if s.run(['/usr/sbin/lsof','-nP','-iUDP:500','-iUDP:4500'],check=False).returncode!=1:raise s.Refused('ike_ports_not_free')
    if not s.sad_empty() or policies.read_spd()[0]:raise s.Refused('native_baseline_not_empty')
    baseline=s.values();baseline[s.ESP]=int(s.run(['/usr/sbin/sysctl','-n',s.ESP]).stdout)
    if any(baseline[k]!=0 for k in ['net.inet.ip.forwarding','net.inet6.ip6.forwarding']) or baseline[s.ESP]!=0:
        raise s.Refused('exclusive_closed_baseline_required')
    if s.digest(s.read(Path('/usr/local/etc/family-vpn/strongswan.conf')))!=CONFIG_SHA:raise s.Refused('daemon_config_pin_changed')
    policies.assert_lifecycle_evidence()
    network.conflict_check(network.read_routes())
    crl=crl_gate.retirement_gate(s)
    health=network.uplink(external=data) # closed tests have zero external HTTP probes
    s.trusted(s.CHARON,0o755);s.trusted(s.SWAN,0o755)
    return dict(version=alf_transaction.VERSION,profile=alf_transaction.PROFILE,
                fleet=fleet,fleet_active=[],active=True,phase='PREPARING',boot=s.boot(),started=time.time(),allow_data=data,probe_mode=probe_mode,
                baseline=baseline,alf_before=before,health=health,crl=crl,files={},knobs={},
                alf_transaction=alf_transaction.new(before,probe_mode=probe_mode) if data else None)


def closed_loop(owner,action,clock):
    """Closed-gate child fault controls, never a guardian-crash claim."""
    requested=CLOSED_SIGNALS[action];start=clock();end=start+15;injected=None
    while clock()<end and not STOP.wait(0.5):
        try:owner.check_local(10)
        except ctl.Fault as error:
            if injected is None or type(error)is not ctl.Fault or error.args!=('charon_process_absent',):raise
            detected=clock()
            owner.guard('owned_charon_fault_detected',10)
            if not owner.gate.closed():raise s.Refused('fault_close_unverified')
            policies.verify_native_protection(owner.session)
            owner.session['fault_control'].update(phase='detected-and-closed',
                detection_seconds=detected-injected,closed_seconds=clock()-injected)
            owner.save()
            s.say('native_child_fault_observed',test=action,
                  detection_seconds=detected-injected,closed_seconds=clock()-injected,
                  gate_was_already_closed=True,guardian_sigkill_tested=False)
            return
        policies.verify_native_protection(owner.session)
        if requested is not None and injected is None and clock()-start>=2:
            identity=owner.owned_process()
            if (identity is None or identity['path']!=str(s.CHARON) or owner.daemon is None or
                    owner.daemon.pid!=identity['pid'] or owner.daemon.poll() is not None):
                raise s.Refused('fault_target_not_exact_owned_child')
            owner.session['fault_control']=dict(phase='signal-intent',test=action,at=time.time(),
                                               identity=identity)
            owner.save() # no signal on a failed write-ahead
            injected=clock();os.kill(identity['pid'],requested)
    if requested is not None:raise s.Refused('requested_fault_not_observed_within_window')
    if STOP.is_set():raise ctl.Cancelled('requested_stop')


def run_session(action,store):
    if STOP.is_set():return 2
    previous=store.load()
    if previous and previous['active']:raise s.Refused('previous_native_recovery_required')
    if action not in (*CLOSED_SIGNALS,'data-test'):raise s.Refused('fixed_session_action_required')
    session=preflight(action=='data-test');session['test_action']=action
    store.save(session);owner=Owner(session,store)
    error=None;restored=False
    try:
        owner.setup()
        clock=make_clock();end=clock()+(900 if session['allow_data'] else 15)
        s.say('native_ready',data_enabled=session['allow_data'],seconds=900 if session['allow_data'] else 15,
              test=action,alf_firewall_unchanged=not session['allow_data'])
        if session['allow_data']:ctl.Controller(owner,end,monotonic=clock).run()
        else:closed_loop(owner,action,clock)
    except BaseException as exc:
        error=exc;s.say('native_test_stopped',test=action,code='validation_or_lifecycle_failure')
    finally:restored=owner.cleanup()
    return 0 if error is None and restored else 2


def read_only_check(store,previous):
    gate=native_gate.Gate(previous or {},store)
    filters,nat=gate.roots();auxiliary=gate.auxiliary_roots()
    pf_ok=False
    try:
        native_gate.prepared_main(s.read(s.PFC,mode=None,limit=20000))
        native_gate.default_root(filters,nat);native_gate.default_auxiliary(auxiliary)
        native_gate.apple_source();pf_ok=True
    except s.Refused:pass
    data=configured()['allow_data'];pending=bool(previous and previous['active'])
    s.say('native_check',installed=True,allow_data=data,
          phase=previous['phase'] if previous else 'NEVER_STARTED',needs_recovery=pending,
          same_boot=not previous or previous['boot']==s.boot(),
          actual_forwarding=s.values(),alf_global_state=alf.snapshot()['global_state'],
          pf_candidate_baseline_layout=pf_ok,
          pf_filter_lines=len(native_gate.rule_lines(filters)),pf_nat_lines=len(native_gate.rule_lines(nat)),
          pf_live_sha256=s.digest(json.dumps([filters,nat,auxiliary],sort_keys=True).encode()),
          live_shape_not_previously_accepted=True)
    return pf_ok and not pending and not data


def run_closed_suite(store):
    if not read_only_check(store,store.load()):raise s.Refused('closed_suite_baseline_check_refused')
    completed=[]
    for step in CLOSED_SIGNALS:
        status=run_session(step,store)
        s.say('native_suite_step',test=step,passed=status==0)
        if status:return status
        completed.append(step)
        # A fresh disk read must agree with the just-finished cleanup; the
        # next step never clears STOP or overwrites unresolved work.
        saved=store.load()
        if saved is None or saved['active'] or saved['phase']!='RESTORED':
            raise s.Refused('suite_restoration_not_durable')
    s.say('native_closed_suite_complete',tests=completed,data_enabled=False,
          guardian_sigkill_tested=False,real_client_traffic_tested=False)
    return 0


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ACTIONS:raise s.Refused('fixed_action_only')
    action=sys.argv[1]
    s.trusted(s.BASE,0o700);s.trusted(s.STATE,0o700);s.trusted(s.CONF,0o700)
    os.umask(0o077)
    if action not in ['check','restore']:
        for path in [s.RUN.parent,s.RUN]:s.directory(path)
    for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(sig,lambda *_:STOP.set())
    with s.locks():
        store=s.Store();previous=store.load()
        if action=='check':
            read_only_check(store,previous)
            return 0
        if action=='restore':
            if previous is None or not previous['active']:
                s.say('already_restored',network_not_modified=True);return 0
            return 0 if Owner(previous,store).cleanup() else 2
        if action=='closed-suite':
            return run_closed_suite(store)
        return run_session(action,store)


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:
        s.say('native_refused',code='fixed_scope_or_recovery_requires_review');sys.exit(2)
