"""Fresh closed native facts without CRL, registry or a fabricated session.

The fixed manager/service caller retains the original native and legacy locks.
This read-only helper does not authorize publication, signal processes, settle
writers, change settings, or turn an absent journal into a recovery receipt.
"""
import native_support as s
import native_runtime as runtime


def _held(assert_held):
    if assert_held() is not None:
        raise s.Refused('quiescent_lock_callback_contract')
    if s.MUTATOR is not None:
        raise s.Refused('quiescent_mutator_still_bound')


def _absent(argv, code):
    observed = s.run(argv, check=False)
    if observed.returncode != 1 or observed.stdout or observed.stderr:
        raise s.Refused(code)


def verify(assert_held):
    """Return actual closed facts; only callable under the caller's held locks."""
    s.require_local_modules(('native_quiescent',))
    runtime.require_closure()
    _held(assert_held)
    with runtime.budget(25):
        values = s.values()
        if (set(values) != set(s.SYS) or any(type(v) is not int or v not in (0, 1) for v in values.values())
                or any(values[k] != 0 for k in ('net.inet.ip.forwarding', 'net.inet6.ip6.forwarding'))):
            raise s.Refused('quiescent_forwarding_not_closed')
        esp = s.run(['/usr/sbin/sysctl', '-n', s.ESP]).stdout.strip()
        if esp != '0':
            raise s.Refused('quiescent_esp_not_zero')
        if not s.sad_empty() or runtime.policies.read_spd()[0]:
            raise s.Refused('quiescent_native_policy_not_empty')
        _absent(['/usr/bin/pgrep', '-x', 'charon'], 'quiescent_charon_not_absent')
        _absent(['/usr/sbin/lsof', '-nP', '-iUDP:500', '-iUDP:4500'], 'quiescent_ike_ports_not_absent')
        _absent(['/usr/sbin/lsof', '-nP', '-iTCP:47729', '-F', 'pftn'], 'quiescent_probe_port_not_absent')
        if s.SOCKET.exists() or s.SOCKET.is_symlink():
            runtime.native_socket()
            _absent(['/usr/sbin/lsof', '-nP', s.SOCKET], 'quiescent_vici_not_absent')
        alf = runtime.alf.snapshot()
        runtime.alf_gate(alf, False)
        probe = '/usr/local/libexec/family-vpn-probe/native-probe'
        if probe in alf['apps'] and alf['apps'][probe] is not False:
            raise s.Refused('quiescent_probe_alf_not_blocked')
        pf = runtime.native_gate
        gate = pf.Gate({}, None)  # Read methods only, never a native owner.
        raw = s.read(s.PFC, mode=0o644, limit=20000)
        pf.prepared_main(raw)
        filters, nat = gate.roots()
        pf.default_root(filters, nat)
        auxiliary = gate.auxiliary_roots()
        pf.default_auxiliary(auxiliary)
        if not gate.rules_equal(dict(filters=[], nat=[])):
            raise s.Refused('quiescent_owned_anchor_not_empty')
        apple = pf.apple_source()
        enabled = gate.enabled()
        if s.read(s.PFC, mode=0o644, limit=20000) != raw:
            raise s.Refused('quiescent_pf_source_changed')
        _held(assert_held)
        return dict(version=1, boot=s.boot(), sysctl=dict(values, **{s.ESP: 0}),
                    alf=alf, pf=dict(source_sha256=s.digest(raw), apple_sha256=apple,
                    filters=pf.rule_lines(filters), nat=pf.rule_lines(nat), auxiliary=auxiliary,
                    enabled=enabled, owned_anchor_empty=True),
                    sad_empty=True, spd_empty=True, charon_absent=True,
                    ike_ports_absent=True, probe_port_absent=True, vici_unowned=True)
