"""Same-owner CRL upkeep after complete native closure, before fresh setup.

No timer, external job, CLI or live credential reload. The production supervisor
already holds all native/legacy locks throughout this call. Only the existing
provisioner lock is acquired by Renewal. A partial signer is never replayed.
"""
import math
import time
import native_support as s
import native_runtime as runtime
import service_recovery_readback as restoration
from pki_io import IO, Refused, encode, sha, decode
from renewal import Renewal, ROOT, STATE_NAME, pending_run, completed
from native_closed import legacy_writers_absent
import current_crl

RENEW_BEFORE = 7 * 86400

def due(session, now=None):
    now = time.time() if now is None else now
    value = session.get('crl')
    if (type(now) not in (int, float) or not math.isfinite(now)
            or type(value) is not dict or type(value.get('next')) not in (int, float)
            or not math.isfinite(value['next']) or value['next'] <= 0):
        raise Refused('service_crl_deadline_missing')
    return now >= value['next'] - RENEW_BEFORE

def maintain(configuration, store, assert_held):
    """Actual caller is NativeDependencies.preflight under Native.locked()."""
    import service_supervisor as service
    from supervisor_core import valid_state
    runtime.require_closure()
    expected_config = configuration.fingerprint
    def service_bound():
        if not callable(assert_held) or assert_held() is not None:
            raise Refused('service_pki_actual_native_locks_required')
        if configuration.enabled is not True or service.read_configuration() != configuration:
            raise Refused('service_pki_configuration_changed')
        state = valid_state(decode(s.read(s.STATE / 'service-state.json', limit=16384)))
        if (state['phase'] != 'PREFLIGHT' or state['boot'] != s.boot()
                or state['fingerprint'] != expected_config):
            raise Refused('service_pki_not_actual_preflight')
    service_bound()
    import membership_gate
    membership_gate.check()
    saved = store.load()
    io = IO(ROOT, 0)
    state = ROOT / STATE_NAME
    ca = io.read(ROOT / 'swanctl/x509ca/ca.pem')
    public = io.read(ROOT / 'swanctl/x509crl/ca.crl.pem')
    run = pending_run(io, state)
    incomplete = run is not None and not io.exists(run / 'complete.json')
    if run is not None and not incomplete:
        completed(io, state, run)
    if not incomplete:
        _, evidence = current_crl.inspect(io, state, ca, public, current=False)
        if time.time() >= evidence.ca_not_after - RENEW_BEFORE:
            # A new CRL cannot extend the installed CA or iPhone trust profile.
            # Refuse before reserving a number/signing instead of restart loops.
            raise Refused('ca_near_expiry_requires_trust_profile_renewal')
        if time.time() < min(evidence.next_update, evidence.ca_not_after) - RENEW_BEFORE:
            return {'renewed': False, 'recovered': False}
    # The production boot handoff can retire the old native journal. In that
    # case check actual current kernel/PF/ALF facts again; never fabricate an
    # empty RESTORED journal to make signing look eligible.
    prior = sha(encode(saved)) if saved is not None else None
    def closed():
        service_bound()
        legacy_writers_absent()
        observed = store.load()
        if saved is None:
            import native_quiescent
            if observed is not None:
                raise Refused('service_pki_native_appeared')
            native_quiescent.verify(assert_held)
            if store.load() is not None:
                raise Refused('service_pki_native_appeared')
        elif sha(encode(observed)) != prior or restoration.verify(store, saved) is not True:
            raise Refused('service_pki_native_not_closed')
        values = s.values()
        if any(values[key] != 0 for key in ('net.inet.ip.forwarding', 'net.inet6.ip6.forwarding')):
            raise Refused('service_pki_forwarding_not_closed')
    closed()
    worker = Renewal(io, closed)
    if not incomplete and runtime.STOP.is_set():
        return {'renewed': False, 'recovered': False, 'stopped': True}
    result = worker.recover_locked() if incomplete else worker.renew_locked()
    closed()
    if result.get('data_started') is not False or result.get('loaded_verified') is not False:
        raise Refused('service_pki_unexpected_open_claim')
    _, evidence = current_crl.inspect(io, state, ca, io.read(ROOT / 'swanctl/x509crl/ca.crl.pem'))
    if time.time() >= evidence.ca_not_after - RENEW_BEFORE:
        raise Refused('ca_near_expiry_requires_trust_profile_renewal')
    # The subsequent normal Owner must perform a new loaded-CRL comparison.
    return {'renewed': not incomplete, 'recovered': incomplete}

if __name__ == '__main__':
    raise SystemExit('Only the fixed same-lock service preflight calls this module.')
