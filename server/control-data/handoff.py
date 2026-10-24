"""Only same-version actual closed-baseline readback; no legacy migration."""
import copy,re
import install_io as io

def fixed_roles_gone(native, value):
    for row in (value.get('child'), value.get('mutation')):
        if row is None or row.get('identity') is None:
            continue
        ident = row['identity']
        keys = {'pid','uid','pgid','started_sec','started_usec','path'}
        if (type(ident) is not dict or set(ident) != keys
                or any(type(ident[k]) is not int for k in keys-{'path'})
                or ident['pid'] <= 1 or ident['pgid'] != ident['pid'] or ident['uid'] != 0
                or ident['started_sec'] <= 0 or not 0 <= ident['started_usec'] < 1000000
                or type(ident['path']) is not str or not ident['path'].startswith('/')
                or '\0' in ident['path'] or '\n' in ident['path']):
            raise io.Failure('predecessor_process_identity_unknown')
        current = native.s.process(ident['pid'])
        if current is not None and native.s.same_birth(current, ident):
            raise io.Failure('predecessor_process_still_alive')


def fresh_closed_baseline(native, value):
    """Real fixed read path, before any journal is archived or new mode starts."""
    s, runtime, ng = native.s, native.runtime, native.runtime.native_gate
    if s.MUTATOR is not None:
        raise io.Failure('handoff_requires_no_writer_bound')
    fixed_roles_gone(native, value)
    current = runtime.preflight(False)  # Own native code: ALF, SAD/SPD, sockets, knobs, CRL/uplink.
    gate = ng.Gate(copy.deepcopy(current), s.Store())
    filters, nat = gate.roots()
    ng.default_root(filters, nat)
    auxiliary = gate.auxiliary_roots()
    ng.default_auxiliary(auxiliary)
    raw = s.read(s.PFC, mode=None, limit=20000)
    ng.prepared_main(raw)
    apple = ng.apple_source()
    if not gate.rules_equal(dict(filters=[],nat=[])):
        raise io.Failure('handoff_has_live_owned_anchor')
    refs, enabled = gate.refs(), gate.enabled()
    tokens=ng.reference_tokens(refs)
    # An implicit Apple -e reference can keep PF enabled without a listed Token.
    # Capture that baseline; only a later exact owned token may be released.
    if current['baseline'] != value['baseline'] or current['alf_before'] != value.get('alf_before'):
        raise io.Failure('predecessor_baseline_differs')
    pf = value.get('pf')
    if pf is not None and (s.digest(raw) != pf.get('before_sha')
            or dict(filters=ng.rule_lines(filters),nat=ng.rule_lines(nat)) != pf.get('root_before')
            or auxiliary != pf.get('auxiliary_before')):
        raise io.Failure('predecessor_pf_baseline_differs')
    # Later external PF references are preserved by the old recovery code.
    # They become this run's fresh baseline, never an excuse to release them.
    ref = value.get('pf_reference')
    if ref is not None:
        token = ref.get('token')
        if (type(token) is not str or not re.fullmatch('[0-9]{1,20}', token)
                or token in tokens):
            raise io.Failure('predecessor_pf_token_not_released')
    if (pf is not None and tokens==ng.reference_tokens(pf.get('references_before'))
            and enabled is not pf.get('enabled_before')):
        raise io.Failure('unchanged_pf_references_enabled_state_differs')
    for name, record in value['files'].items():
        path = runtime.FILES[name]
        present = path.exists() or path.is_symlink()
        if record['created']:
            if present:raise io.Failure('predecessor_created_file_remains')
        elif not present or s.digest(s.read(path)) != record['sha256']:
            raise io.Failure('predecessor_original_file_changed')
    return dict(boot=current['boot'], baseline=current['baseline'], alf_before=current['alf_before'],
        pf_sha256=s.digest(raw), pf_roots=dict(filters=ng.rule_lines(filters),nat=ng.rule_lines(nat)),
        pf_auxiliary=auxiliary, apple_source_sha256=apple, pf_references=refs, pf_enabled=enabled)

