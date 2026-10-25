"""Actual fixed native observations/persistent file operations; inert on import.

This source is not installed. The default instance has NO write authority;
attach_writer binds the sole same-lock, current-boot journaled writer.
"""
import contextlib,copy,os,stat,subprocess,sys
from pathlib import Path
import native_support as s
import native_runtime as runtime
import native_gate as pf
import service_supervisor as service
import runtime_resources
from boot_record import Refused

ROOT=s.STATE/'boot-recovery'
ARCHIVES=ROOT/'originals'
RECORD=ROOT/'boot-reconcile.json'
BOOT_RESOURCES=('boot_record.py','boot_native.py','boot_store.py','boot_reconcile.py','boot_writer.py','boot_mutation_gate.py','boot_finite_source.py','boot_server_source.py','boot_source.py','boot_handoff.py','production_source.py','production_boot.py')
RUNTIME_RESOURCES=tuple(sorted(set((*service.RESOURCES,'config.json','supervisor-config.json',*BOOT_RESOURCES))))
PARENT_MANIFEST_SHA256='31c50e9feb8cec31d4799eafd2bb14f32a1c89d7a8b992f0064717ba0312c92c'

class WriterUnavailable(Refused):pass

class Native:
    def __init__(self):self.lease=False;self.writer=None
    @contextlib.contextmanager
    def locked(self):
        if os.geteuid()!=0:raise Refused('native_boot_requires_fixed_root_owner')
        for path in (s.BASE,s.STATE,s.CONF,ROOT,ARCHIVES):s.trusted(path,0o700)
        with s.locks():
            self.lease=True
            try:yield self
            finally:self.lease=False
    def held(self):
        if not self.lease:raise Refused('same_system_locks_required')
    def attach_writer(self,store):
        self.held()
        if self.writer is not None or store.io is not self:raise Refused('boot_writer_already_bound_or_wrong_store')
        from boot_writer import Writer
        self.writer=Writer(self,store)
    @staticmethod
    def installed_scope():
        if Path(__file__).resolve()!=s.BASE/'boot_native.py':raise Refused('boot_source_not_fixed_installation')
        for name in RUNTIME_RESOURCES:
            if not name.endswith('.py'):continue
            module_name=name[:-3].replace('/','.')
            if module_name.endswith('.__init__'):module_name=module_name[:-9]
            module=sys.modules.get(module_name)
            if module is not None and Path(getattr(module,'__file__','')).resolve()!=s.BASE/name:
                raise Refused('mixed_boot_native_source_closure')
    def boot(self):self.held();return s.boot()
    def configuration(self):self.held();return service.read_configuration().fingerprint
    def implementation(self):
        self.held()
        from boot_record import exact_hash,PROFILE
        raw=s.read(s.BASE/'boot-runtime-pins.json');manifest=s.json_value(raw)
        if (type(manifest)is not dict or set(manifest)!={'version','profile','parent_manifest_sha256','runtime'}
                or type(manifest['version'])is not int or manifest['version']!=1 or manifest['profile']!=PROFILE
                or manifest['parent_manifest_sha256']!=PARENT_MANIFEST_SHA256 or type(manifest['runtime'])is not dict
                or set(manifest['runtime'])!=set(RUNTIME_RESOURCES)
                or any(not exact_hash(value) for value in manifest['runtime'].values())):raise Refused('boot_implementation_manifest')
        for name,expected in manifest['runtime'].items():
            if s.digest(runtime_resources.read(name))!=expected:raise Refused('boot_implementation_changed')
        return s.digest(raw)
    def originals(self):
        self.held()
        import boot_source as source
        raw=s.read(s.STATE/'native-session.json');value=s.json_value(raw)
        context=source.snapshot(value)
        if s.read(s.STATE/'native-session.json')!=raw:raise Refused('bounded_original_changed')
        return raw,context
    def context_admission(self,context_raw):
        self.held()
        import boot_source as source
        value=s.json_value(s.read(s.STATE/'native-session.json'))
        source.validate(value,context_raw)
        if value.get('boot')==self.boot():raise Refused('boot_admission_requires_new_kernel')
        self.closed_kernel()
        source.verify_current_resources(value,context_raw,recovery=True)
    def closed_kernel(self):
        self.held();values=s.values()
        if any(values[k]!=0 for k in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding')):
            raise Refused('new_boot_forwarding_not_zero')
        if any(type(x)is not int or x not in (0,1) for x in values.values()):raise Refused('new_boot_sysctl_unknown')
        if int(s.run(['/usr/sbin/sysctl','-n',s.ESP]).stdout)!=0:raise Refused('new_boot_esp_not_zero')
        if not s.sad_empty() or runtime.policies.read_spd()[0]:raise Refused('new_boot_native_not_empty')
        if s.run(['/usr/bin/pgrep','-x','charon'],check=False).returncode!=1:raise Refused('new_boot_charon_not_absent')
        if s.run(['/usr/sbin/lsof','-nP','-iUDP:500','-iUDP:4500'],check=False).returncode!=1:
            raise Refused('new_boot_ike_ports_not_free')
        if s.SOCKET.exists() or s.SOCKET.is_symlink():
            runtime.native_socket()
            if s.run(['/usr/sbin/lsof','-nP',s.SOCKET],check=False).returncode!=1:raise Refused('new_boot_vici_owned')
        port=subprocess.run(['/usr/sbin/lsof','-nP','-iTCP:47729','-F','pftn'],
            stdin=subprocess.DEVNULL,capture_output=True,env=s.ENV,timeout=5,close_fds=True,start_new_session=True)
        if port.returncode!=1 or port.stdout or port.stderr:raise Refused('new_boot_probe_port_not_free')
        return values
    def alf(self):self.held();return runtime.alf.snapshot()
    def pf(self,old):
        self.held();info=s.trusted(s.PFC,0o644);raw=s.read(s.PFC,mode=0o644,limit=20000)
        guard=s.read(s.CONF/'guard.pf')
        if guard!=pf.GUARD.encode():raise Refused('persistent_guard_not_fixed_source')
        # This sole extra command is syntax-only against exact fixed public
        # guard bytes, never a load/reload or caller-selected pathname.
        result=subprocess.run(['/sbin/pfctl','-n','-v','-a',pf.ANCHOR,'-f',str(s.CONF/'guard.pf')],
            stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding='utf-8',errors='strict',
            env=s.ENV,timeout=5,close_fds=True,start_new_session=True)
        if result.returncode or len(result.stdout)>65536 or len(result.stderr)>65536:raise Refused('fixed_guard_compile_unknown')
        compiled=pf.classify(result.stdout)
        gate=pf.Gate(copy.deepcopy(old),None);filters,nat=gate.roots()
        roots=dict(filters=pf.rule_lines(filters),nat=pf.rule_lines(nat))
        kind='baseline'
        if roots!=old['pf']['root_before']:
            gate.own_root(filters,nat);kind='owned'
        anchor=dict(filters=pf.rule_lines(s.run([pf.PF,'-a',pf.ANCHOR,'-sr']).stdout),
                    nat=pf.rule_lines(s.run([pf.PF,'-a',pf.ANCHOR,'-sn']).stdout))
        auxiliary=gate.auxiliary_roots();pf.default_auxiliary(auxiliary)
        if pf.apple_source()!=old['pf']['apple_source_sha']:raise Refused('apple_source_changed')
        if (compiled!=old['pf']['guard'] or anchor not in (dict(filters=[],nat=[]),compiled)
                or auxiliary!=old['pf']['auxiliary_before']):raise Refused('new_boot_pf_unknown_scope')
        if s.digest(raw) not in (old['pf']['before_sha'],old['pf']['after_sha']):raise Refused('persistent_pf_source_changed')
        return dict(sha256=s.digest(raw),mode=stat.S_IMODE(info.st_mode),root=kind,anchor=anchor,
                    references=gate.refs(),enabled=gate.enabled())
    def file(self,key):
        self.held()
        if key not in runtime.FILES:raise Refused('fixed_file_key_required')
        path=runtime.FILES[key]
        if key=='daemon' and not path.parent.exists() and not path.parent.is_symlink():
            parent=path.parent.parent
            if not parent.exists() and not parent.is_symlink():parent=parent.parent
            info=s.trusted(parent)
            if not stat.S_ISDIR(info.st_mode):raise Refused('runtime_parent_type')
            return None # Known volatile subtree absent; never create it for cleanup.
        info=s.trusted(path.parent,0o700)
        if not stat.S_ISDIR(info.st_mode):raise Refused('fixed_file_parent_type')
        if not path.exists() and not path.is_symlink():return None
        return s.digest(s.read(path))
    def settle(self,record):
        self.held()
        if self.writer is None:raise WriterUnavailable('new_boot_sole_writer_not_integrated')
        return self.writer.settle(record)
    def apply(self,record,effect,old):
        self.held()
        if self.writer is None:raise WriterUnavailable('new_boot_sole_writer_not_integrated')
        self.writer.authorize(record,effect,old)
        if effect['kind']=='command':return self.writer.run(record,effect,old)
        if effect['kind']=='replace-pf':
            import base64
            if s.digest(s.read(s.PFC,mode=old['pf']['mode'])) not in (old['pf']['before_sha'],old['pf']['after_sha']):
                raise Refused('pf_changed_before_replace')
            s.atomic(s.PFC,base64.b64decode(old['pf']['before'],validate=True),old['pf']['mode'])
        elif effect['kind']=='delete-created':
            path=runtime.FILES[effect['file']]
            if self.file(effect['file'])!=effect['sha256']:raise Refused('created_file_changed_before_unlink')
            path.unlink();s.sync_dir(path.parent)
        else:raise Refused('unknown_boot_effect')
