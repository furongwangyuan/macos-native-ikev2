"""Fixed production-v8 closed native integration. Imports are inert; no public root CLI.

Caller owns fixed receipts/identity bindings. setup/restore are the ONLY native
writers and must hold native_support.locks; readbacks never construct Owner.
"""
import contextlib
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
FIXED_BASE=Path('/usr/local/family-vpn/production-owner-fault')
INSTALLED_COMMON=Path('/usr/local/family-vpn/production-guardian')
COMMON=INSTALLED_COMMON if HERE==FIXED_BASE else HERE.parent/'runtime'
sys.path.insert(0,str(COMMON))
import native_support as s
import native_runtime as runtime
import native_policy as policies
import native_gate as ng
import alf_readonly as alf
import recover_only
import integration_readonly as extra
from mutation_dispatch import Dispatcher
from fault_protocol import Refused, checkpoint, digest, exact
from process_observe import observe

CLOSURE_SHA=None # FINAL_BUILD_BINDING
PROFILE='production-native-fleet-v1'
JOB='/Library/LaunchDaemons/org.familyvpn.guardian-recovery.plist'
PREFIX=Path('/usr/local/family-vpn/strongswan-6.1.0')
BINARY_ROOTS=(PREFIX/'sbin',PREFIX/'libexec',PREFIX/'lib',
              Path('/usr/local/family-vpn/openssl-3.5.9/lib'))


def sources():
    """Verify exact frozen source closure; no import-cache mixing."""
    if type(CLOSURE_SHA)is not str or re.fullmatch('[0-9a-f]{64}',CLOSURE_SHA)is None:
        raise Refused('unbuilt_v8_runtime_binding')
    import runtime_resources
    s.require_local_modules(('runtime_resources',))
    raw=runtime_resources.read('candidate-pins.json')
    if hashlib.sha256(raw).hexdigest()!=CLOSURE_SHA:raise Refused('closure_manifest_changed')
    manifest=s.json_value(raw)
    if manifest.get('journal_version')!=8 or manifest.get('profile')!=PROFILE:raise Refused('common_manifest_profile')
    pins=manifest['runtime']
    runtime_resources.inventory(set(pins)|{'candidate-pins.json'})
    for name,expected in pins.items():
        if hashlib.sha256(runtime_resources.read(name)).hexdigest()!=expected:raise Refused('closure_source_changed')
    runtime.require_closure()
    s.require_local_modules(('recover_only',))
    return CLOSURE_SHA


def resource_snapshot():
    """Bind current trusted binary tree (not an independent signature approval).

    The exact same snapshot is compared before setup, at STOP and after recovery.
    Public binaries only: no PKI private keys, passwords, or user traffic read.
    """
    import boot_finite_source
    s.require_local_modules(('boot_finite_source',))
    return boot_finite_source.public_resource_snapshot()


def old_job_absent():
    if Path(JOB).exists() or Path(JOB).is_symlink():raise Refused('old_recovery_job_requires_separate_removal')
    result=extra.run(['/bin/launchctl','print','system/org.familyvpn.guardian-recovery'])
    # Unknown errors do not prove absence. Spelling must be checked on the host
    # by the future read-only inventory; no silent bootout is part of this run.
    lines=(result.stdout+result.stderr).strip().splitlines()
    if (result.returncode!=113 or len(lines)!=2 or lines[0]!='Bad request.' or
            lines[1]!='Could not find service "org.familyvpn.guardian-recovery" in domain for system'):
        raise Refused('old_recovery_job_absence_unverified')


def prior_allowed(store):
    # Production v8 Store refuses old v2/v3/v4/v5/v6/v7 records, including RESTORED. No delete,
    # version rewrite or side effect is an implicit migration.
    previous=store.load()
    if previous is not None and (previous['active'] is not False or previous['phase']!='RESTORED'):
        raise Refused('previous_native_recovery_required')
    return previous


def udp_inventory(text,pid):
    lines=text.splitlines()
    if not lines or lines.pop(0)!='p'+str(pid):raise Refused('charon_udp_pid')
    entries=[];item=None
    for line in lines:
        if line.startswith('f'):
            if not re.fullmatch(r'f[0-9]+',line):raise Refused('charon_udp_fd')
            if item is not None:entries.append(item)
            item={}
        elif line[:1] in ('t','n') and item is not None:
            if line[0] in item:raise Refused('charon_udp_duplicate')
            item[line[0]]=line[1:]
        else:raise Refused('charon_udp_shape')
    if item is not None:entries.append(item)
    if len(entries)!=2 or any(set(x)!={'t','n'} or x['t']!='IPv4' for x in entries):
        raise Refused('charon_udp_count')
    if {x['n'] for x in entries}!={'*:500','*:4500'}:raise Refused('charon_udp_endpoint')


@contextlib.contextmanager
def read_only():
    old=s.MUTATOR;s.MUTATOR=None
    try:yield
    finally:s.MUTATOR=old


class Native:
    def __init__(self,intent,receipts):
        self.intent=intent;self.receipts=receipts;self.owner=None
    def binding(self,value,*,started=True):
        if (value is None or value.get('fault_run')!=self.intent['run']
                or value.get('fault_intent_sha256')!=digest(self.intent)
                or value.get('boot')!=self.intent['boot'] or s.boot()!=self.intent['boot']):
            raise Refused('native_run_boot_binding')
        s.session_history(value);s.closed_history(value)
        if started:
            if not self.receipts.exists('baseline.json'):raise Refused('native_baseline_receipt_missing')
            baseline=self.receipts.read('baseline.json')
            keys=('version','profile','boot','started','allow_data','probe_mode','baseline','alf_before',
                  'health','crl','fleet','fault_run','fault_intent_sha256')
            if (type(baseline)is not dict or any(k not in baseline or k not in value for k in keys)
                    or digest({k:baseline[k] for k in keys})!=digest({k:value[k] for k in keys})):
                raise Refused('native_baseline_receipt_changed')
        return value
    def stable_resources(self):
        if sources()!=self.intent['closure_sha256'] or resource_snapshot()!=self.intent['resources']:
            raise Refused('source_binary_or_configuration_changed')
    def locks(self):return s.locks()
    def prepare(self):
        store=s.Store();previous=prior_allowed(store)
        if (digest(previous) if previous is not None else None)!=self.intent.get('prior_session_sha256'):
            raise Refused('native_admission_changed')
        self.stable_resources();old_job_absent()
        session=runtime.preflight(False)
        session.update(fault_run=self.intent['run'],fault_intent_sha256=digest(self.intent))
        self.binding(session,started=False)
        self.receipts.write('baseline.json',session)
        store.save(session) # Durable run binding BEFORE every native write.
        self.owner=runtime.Owner(session,store)
        self.owner.setup()
        return self.closed_checkpoint()
    def cleanup_owner(self):
        if self.owner is not None:return self.owner.cleanup()
        return True
    def closed_checkpoint(self):
        with read_only(),runtime.budget(25):
            self.stable_resources()
            store=s.Store();before=self.binding(store.load())
            if before['phase']!='CLOSED_TEST' or before['active'] is not True:raise Refused('not_parked_closed')
            record=Dispatcher(copy.deepcopy(before),store).record()
            if record is None or record['phase']!='settled':raise Refused('mutator_not_settled')
            gate=ng.Gate(copy.deepcopy(before),store)
            if gate.closed() is not True:raise Refused('closed_guard_unverified')
            policies.verify_native_protection(before)
            child=before.get('child',{});ident=child.get('identity')
            if child.get('phase')!='go-sent' or type(ident)is not dict:raise Refused('closed_charon_receipt')
            current=observe(ident['pid'])
            expected=dict(ident,path=str(s.CHARON));exact(current,expected,stopped=False)
            runtime.native_socket()
            sockets=s.run(['/usr/sbin/lsof','-nP','-a','-p',str(ident['pid']),'-iUDP','-F','pftn']).stdout
            udp_inventory(sockets,ident['pid'])
            tcp=extra.run(['/usr/sbin/lsof','-nP','-a','-p',str(ident['pid']),'-iTCP','-F','pftn'])
            if tcp.returncode!=1 or tcp.stdout or tcp.stderr:raise Refused('unexpected_owned_tcp_listener')
            vici=extra.run(['/usr/sbin/lsof','-nP','-F','p',s.SOCKET]).stdout
            if vici.splitlines()!=['p'+str(ident['pid'])]:raise Refused('vici_owner_changed')
            if s.run([s.SWAN,'--list-sas','--uri',s.URI]).stdout.strip():raise Refused('closed_ike_not_empty')
            runtime.crl_gate.loaded_crl_gate(s,before['crl'])
            after=self.binding(store.load())
            if digest(after)!=digest(before):raise Refused('checkpoint_journal_changed')
            return checkpoint(dict(version=5,run=self.intent['run'],boot=before['boot'],profile=PROFILE,
                session_sha256=digest(before),closure_sha256=CLOSURE_SHA,allow_data=False,probe_mode='off',
                phase='CLOSED_TEST',mutator='settled',forwarding_zero=True,forwarding_never_opened=True,
                no_state_deletion=True,guard_exact=True,native_only=True,sad_empty=True,no_ike=True,
                alf_blockall_unchanged=True,owned_listener_only=True))
    def recover(self):
        # Caller holds the SAME native and legacy locks after owner absence.
        store=s.Store();previous=store.load()
        if previous is None:
            if self.intent.get('prior_session_sha256') is not None or self.receipts.exists('baseline.json'):
                raise Refused('native_journal_disappeared')
            return True # WATCH-ready before even the baseline/first session save.
        if (previous.get('active') is False and previous.get('phase')=='RESTORED'
                and digest(previous)==self.intent.get('prior_session_sha256')
                and not self.receipts.exists('baseline.json')):
            return True # Untouched prior production-v8 receipt; this run never began setup.
        self.binding(previous);self.stable_resources()
        if previous['phase']=='CLOSED_TEST' and self.receipts.exists('checkpoint.json'):
            seal=checkpoint(self.receipts.read('checkpoint.json'))
            if (seal['run']!=self.intent['run'] or seal['session_sha256']!=digest(previous)
                    or seal['closure_sha256']!=CLOSURE_SHA):
                raise Refused('quiescent_recovery_checkpoint_changed')
        return recover_only.recover(store)==0
    def restored_readback(self):
        with read_only(),runtime.budget(25):
            self.stable_resources();store=s.Store();before=self.binding(store.load())
            if before['active']is not False or before['phase']!='RESTORED' or before.get('cleanup_codes')!=[]:
                raise Refused('restoration_record_incomplete')
            if before.get('recovery_result')!='restored':raise Refused('restoration_result')
            actual=s.values();expected={k:before['baseline'][k] for k in s.SYS}
            if actual!=expected:raise Refused('restoration_sysctl')
            if int(s.run(['/usr/sbin/sysctl','-n',s.ESP]).stdout)!=before['baseline'][s.ESP]:raise Refused('restoration_esp')
            if alf.snapshot()!=before['alf_before'] or not s.sad_empty() or policies.read_spd()[0]:
                raise Refused('restoration_native_or_alf')
            if s.run(['/usr/bin/pgrep','-x','charon'],check=False).returncode!=1:raise Refused('restoration_charon')
            if s.run(['/usr/sbin/lsof','-nP','-iUDP:500','-iUDP:4500'],check=False).returncode!=1:
                raise Refused('restoration_ike_ports')
            child=before.get('child',{})
            if child and (child.get('phase')!='exited' or observe(child['identity']['pid']) is not None):
                raise Refused('restoration_child_not_absent')
            if s.SOCKET.exists() and s.run(['/usr/sbin/lsof','-nP',s.SOCKET],check=False).returncode!=1:
                raise Refused('restoration_vici_owned')
            gate=ng.Gate(copy.deepcopy(before),store);pf=before.get('pf')
            if pf is None or pf.get('phase')!='restored':raise Refused('restoration_pf_receipt')
            if s.digest(s.read(s.PFC,mode=pf['mode']))!=pf['before_sha']:raise Refused('restoration_pf_file')
            filters,nat=gate.roots()
            if dict(filters=ng.rule_lines(filters),nat=ng.rule_lines(nat))!=pf['root_before']:
                raise Refused('restoration_pf_roots')
            gate.auxiliary_intact()
            if not gate.rules_equal(dict(filters=[],nat=[])):raise Refused('restoration_anchor')
            refs=gate.refs();enabled=gate.enabled()
            reference=before.get('pf_reference')
            if reference and (reference.get('phase')!='released' or gate.token_present()):raise Refused('restoration_owned_pf_reference')
            if refs==pf['references_before'] and enabled!=pf['enabled_before']:
                raise Refused('restoration_pf_refs')
            for key,rec in before.get('files',{}).items():
                path=runtime.FILES[key]
                if rec['phase']!='restored':raise Refused('restoration_file_phase')
                if rec['created']:
                    if path.exists() or path.is_symlink():raise Refused('restoration_created_file')
                elif s.digest(s.read(path))!=rec['sha256']:raise Refused('restoration_preexisting_file')
            if digest(store.load())!=digest(before):raise Refused('restoration_journal_changed')
            return True
