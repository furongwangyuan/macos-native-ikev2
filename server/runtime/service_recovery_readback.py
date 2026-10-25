"""Fresh read-only restored verification for the sole-lock service owner.

Reuses the common owner-fault adapter's actual restoration assertions without
fault-protocol receipts. No authority schema, writer, subprocess grammar or CLI.
Caller holds the same native/legacy locks and supplies the expected durable
session; successful cleanup's boolean or RESTORED flag alone is insufficient.
"""
import contextlib
import copy
import json
import native_support as s
import native_runtime as runtime


def digest(value):
    return s.digest(json.dumps(value,sort_keys=True,allow_nan=False,separators=(',',':')).encode())


@contextlib.contextmanager
def read_only():
    old=s.MUTATOR;s.MUTATOR=None
    try:yield
    finally:s.MUTATOR=old


def verify(store,expected):
    s.require_local_modules(('service_recovery_readback',))
    runtime.require_closure()
    with read_only(),runtime.budget(25):
        before=store.load()
        if before is None or digest(before)!=digest(expected):raise s.Refused('restoration_journal_changed')
        s.session_history(before)
        if (before['boot']!=s.boot() or before['active']is not False or before['phase']!='RESTORED'
                or before.get('cleanup_codes')!=[] or before.get('recovery_result')!='restored'):
            raise s.Refused('restoration_record_incomplete')
        if s.values()!={k:before['baseline'][k] for k in s.SYS}:raise s.Refused('restoration_sysctl')
        if int(s.run(['/usr/sbin/sysctl','-n',s.ESP]).stdout)!=before['baseline'][s.ESP]:raise s.Refused('restoration_esp')
        current_alf = runtime.alf.snapshot()
        alf_restored = (runtime.alf_transaction.restored_matches(before['alf_transaction'], current_alf)
                        if before.get('alf_transaction') is not None else current_alf == before['alf_before'])
        if (not alf_restored or not s.sad_empty()
                or runtime.policies.read_spd()[0]):raise s.Refused('restoration_native_or_alf')
        if s.run(['/usr/bin/pgrep','-x','charon'],check=False).returncode!=1:raise s.Refused('restoration_charon')
        if s.run(['/usr/sbin/lsof','-nP','-iUDP:500','-iUDP:4500'],check=False).returncode!=1:
            raise s.Refused('restoration_ike_ports')
        runtime.probe_owner.port_absent()
        child=before.get('child')
        if child:
            if child.get('phase')!='exited' or type(child.get('identity'))is not dict:
                raise s.Refused('restoration_child_not_absent')
            identity=child['identity'];pid=identity.get('pid')
            if type(pid)is not int or pid<=1:raise s.Refused('restoration_child_not_absent')
            current=s.process(pid)
            if current is not None:
                # A completed old child may have its PID reused while the VPN
                # stays disabled. Only a strictly newer birth proves that this
                # is another process; uid/pgid changes alone do not prove exit.
                if type(current)is not dict or type(current.get('pid'))is not int or current['pid']!=pid:
                    raise s.Refused('restoration_child_not_absent')
                def birth(value):
                    sec,usec=value.get('started_sec'),value.get('started_usec')
                    if type(sec)is not int or sec<=0 or type(usec)is not int or not 0<=usec<1000000:
                        raise s.Refused('restoration_child_not_absent')
                    return sec,usec
                if birth(current)<=birth(identity):raise s.Refused('restoration_child_not_absent')
        if s.SOCKET.exists() and s.run(['/usr/sbin/lsof','-nP',s.SOCKET],check=False).returncode!=1:
            raise s.Refused('restoration_vici_owned')
        gate=runtime.native_gate.Gate(copy.deepcopy(before),store);pf=before.get('pf')
        if pf is None or pf.get('phase')!='restored':raise s.Refused('restoration_pf_receipt')
        if s.digest(s.read(s.PFC,mode=pf['mode']))!=pf['before_sha']:raise s.Refused('restoration_pf_file')
        filters,nat=gate.roots()
        if dict(filters=runtime.native_gate.rule_lines(filters),nat=runtime.native_gate.rule_lines(nat))!=pf['root_before']:
            raise s.Refused('restoration_pf_roots')
        gate.auxiliary_intact()
        if not gate.rules_equal(dict(filters=[],nat=[])):raise s.Refused('restoration_anchor')
        reference=before.get('pf_reference')
        if reference and (reference.get('phase')!='released' or reference.get('token') is None
                          or gate.token_present()):raise s.Refused('restoration_owned_pf_reference')
        refs=gate.refs();enabled=gate.enabled()
        # Same contract as Gate.restore_pf: other users' later references are
        # preserved. Never disable PF or require deleting an external token.
        if (runtime.native_gate.reference_tokens(refs)==runtime.native_gate.reference_tokens(pf['references_before'])
                and enabled!=pf['enabled_before']):
            raise s.Refused('restoration_pf_refs')
        for key,rec in before.get('files',{}).items():
            path=runtime.FILES[key]
            if rec['phase']!='restored':raise s.Refused('restoration_file_phase')
            if rec['created']:
                if path.exists() or path.is_symlink():raise s.Refused('restoration_created_file')
            elif s.digest(s.read(path))!=rec['sha256']:raise s.Refused('restoration_preexisting_file')
        if digest(store.load())!=digest(before):raise s.Refused('restoration_journal_changed')
        return True
