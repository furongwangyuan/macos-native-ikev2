"""Fixed 900-second ServiceOwner call used by the verified installed batch.

Standalone execution refuses; only the source-checked fixed root entry supplies
same-version native admission and an actual previous journal digest.
"""
import hashlib
import json
import math
import re
import sys
import uuid
if __name__ != '__main__':
    import diagnostics as diag

SECONDS = 900
COMMON_MANIFEST_SHA256=None # FINAL_BUILD_BINDING



class Refused(Exception):
    pass


def _configuration(service):
    value = service.read_configuration()
    if value.enabled is not False:
        raise Refused('production_must_remain_disabled')
    if service.runtime.configured()['allow_data'] is not True:
        raise Refused('separate_finite_data_permission_missing')
    return value


def _time(clock):
    value = clock()
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise Refused('continuous_clock_invalid')
    return value


def _check_same_configuration(service, original):
    if _configuration(service).fingerprint != original.fingerprint:
        raise Refused('configuration_changed')


def _run_after_external_native_admission(service, clock, *, run_id=None, previous_session_sha256=None):
    progress = dict(stage='data_admission', initial=None, cleanup=None, cleanup_codes=[])
    if run_id is None: run_id = uuid.uuid4().hex
    try:
        return _run_observed(service, clock, run_id=run_id, progress=progress, previous_session_sha256=previous_session_sha256)
    except BaseException as error:
        if progress['initial'] is None:
            progress['initial'] = diag.diagnostic_failure(progress['stage'], error)
        # Bounded metadata only; never replace the exception/control semantics.
        try:
            error.familyvpn_diagnostic = diag.diagnostic_record(run_id, progress['initial'],
                progress['cleanup'], progress['cleanup_codes'])
        except BaseException:
            pass
        raise


def _run_observed(service, clock, *, run_id, progress, previous_session_sha256=None):
    """Concrete, single-attempt path called by the verified installed batch.

    Caller supplies the exact admitted, fixed installed service module and a
    Darwin continuous clock. The batch obtains closed-test evidence
    before this first unaccepted data window; it does not require the window
    to already have produced data-fault or 24-hour evidence. No public token,
    bool, callback or CLI switch claims to supply those facts.
    Tests patch native effects around the real ServiceOwner/Controller classes.
    """
    if run_id is not None and (type(run_id) is not str or not re.fullmatch('[a-f0-9]{32}', run_id)):
        raise Refused('fixed_run_identity_required')
    s, runtime = service.s, service.runtime
    with s.locks():
        if runtime.STOP.is_set():
            raise Refused('stop_already_requested')
        configuration = _configuration(service)
        store = s.Store()
        previous = store.load()  # v8 Store rejects older/unknown schemas.
        if previous is not None and previous['active'] is not False:
            raise Refused('prior_owner_requires_separate_recovery')
        if previous_session_sha256 is not None:
            raw=(json.dumps(previous,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
            if (type(previous_session_sha256)is not str or re.fullmatch('[a-f0-9]{64}',previous_session_sha256)is None
                    or hashlib.sha256(raw).hexdigest()!=previous_session_sha256):
                raise Refused('finite_previous_changed_under_lock')
        # A loaded matching job is necessary but not evidence that recovery or
        # its timing works. The fixed batch records actual test outcomes separately.
        service.recovery_job_gate()
        progress['stage'] = 'data_preflight'
        session = runtime.preflight(True, probe_mode='off')
        if (type(session.get('version')) is not int or session['version'] != 8
                or session.get('profile') != 'production-native-fleet-v1' or session.get('allow_data') is not True or session.get('probe_mode')!='off'):
            raise Refused('unexpected_data_session')
        gate = runtime.native_gate.Gate(session, store)
        filters, nat = gate.roots()
        runtime.native_gate.default_root(filters, nat)
        runtime.native_gate.default_auxiliary(gate.auxiliary_roots())
        runtime.native_gate.prepared_main(s.read(s.PFC, mode=None, limit=20000))
        runtime.native_gate.apple_source()
        _check_same_configuration(service, configuration)
        if runtime.STOP.is_set():
            raise Refused('stop_before_prepare')

        start = _time(clock)
        deadline = start + SECONDS
        run_id = uuid.uuid4().hex if run_id is None else run_id
        marker = dict(version=1, run_id=run_id, seconds=SECONDS,
                      continuous_start=start, continuous_deadline=deadline)
        session.update(test_action='finite-service-900', finite_window=marker)
        owner = None
        preparation_attempted = False
        controller = None
        failure = None
        cleaned = False
        journal_restored = False
        cleanup_failure = None
        window_end = None
        deps = service.NativeDependencies(clock)
        deps.store, deps.config = store, configuration
        try:
            progress['stage'] = 'data_prepare'
            preparation_attempted = True
            owner = deps.prepare(session)  # same ServiceOwner, not old run_session
            _check_same_configuration(service, configuration)
            if runtime.STOP.is_set() or _time(clock) >= deadline:
                raise runtime.ctl.Cancelled('finite_window_cancelled_before_setup')
            progress['stage'] = 'data_setup'
            owner.setup()  # includes v8 ALF intent/dispatcher and native protection
            _check_same_configuration(service, configuration)
            if runtime.STOP.is_set() or _time(clock) >= deadline:
                raise runtime.ctl.Cancelled('finite_window_cancelled_after_setup')
            # WAITING is written before ALF.open in the common setup. Publish
            # readiness only AFTER setup and the final config/stop/time gates.
            owner.session['finite_ready'] = dict(version=1, run_id=run_id, setup_completed=True)
            owner.save()
            # This is the existing ServiceOwner's existing production controller;
            # only deadline differs. No retry/soak/production acceptance is used.
            progress['stage'] = 'data_controller'
            from fleet_controller import Controller
            controller = Controller(owner, deadline, clock)
            controller.run()
        except BaseException as error:
            failure = error
            progress['initial'] = diag.diagnostic_failure(progress['stage'], error,
                controller_cause=progress['stage']=='data_controller')
        finally:
            try:
                window_end = _time(clock)
                if window_end < start:
                    raise Refused('continuous_clock_regressed')
            except BaseException as error:
                # A failed timing observation cannot skip exact owner cleanup.
                # Preserve process-control exceptions for rethrow AFTER cleanup.
                if progress['initial'] is None:
                    progress['initial'] = diag.diagnostic_failure(progress['stage'], error)
                if failure is None or not isinstance(error, Exception):
                    failure = error
            try:
                progress['stage'] = 'data_cleanup'
                if owner is not None:
                    cleaned = owner.cleanup() is True
                elif preparation_attempted:
                    # prepare can durably save then fail before returning Owner.
                    # Recover ONLY this exact saved session under the same lock.
                    current = store.load()
                    if (current is None or current.get('finite_window') != marker
                            or current.get('boot') != session['boot']):
                        raise Refused('failed_prepare_has_no_exact_owned_journal')
                    recovery_code = service.recover_only.recover(store)
                    cleaned = type(recovery_code) is int and recovery_code == 0
                saved = store.load()
                progress['cleanup_codes'] = diag.diagnostic_cleanup_codes(saved.get('cleanup_codes', [])) if type(saved) is dict else []
                journal_restored = bool(saved is not None
                    and saved.get('finite_window') == marker
                    and saved.get('boot') == session['boot']
                    and saved.get('active') is False and saved.get('phase') == 'RESTORED')
            except Exception as error:
                progress['cleanup'] = diag.diagnostic_failure('data_cleanup', error)
                cleanup_failure = 'cleanup_or_durable_readback_failed'
        end = _time(clock)
        if end < start:
            raise Refused('continuous_clock_regressed')
        if failure is not None and not isinstance(failure, Exception):
            raise failure
        stop_requested = runtime.STOP.is_set()
        if stop_requested and progress['initial'] is None:
            progress['initial'] = dict(stage='data_controller', reason='requested_stop', action=None)
        if (not cleaned or not journal_restored) and progress['cleanup'] is None:
            progress['cleanup'] = dict(stage='data_cleanup', reason=(
                'probe_cleanup_unverified' if 'probe_child' in progress['cleanup_codes']
                else 'native_protection_unverified'), action=None)
        failed = failure is not None or stop_requested or not cleaned or not journal_restored or cleanup_failure is not None
        return dict(run_id=run_id, seconds=SECONDS,
            diagnostic=diag.diagnostic_record(run_id, progress['initial'], progress['cleanup'], progress['cleanup_codes']),
            execution='failed_or_incomplete' if failed else 'cooperative_window_returned',
            controller_entered=controller is not None, stop_requested=stop_requested,
            generations=0 if controller is None else controller.generation_count,
            expiry_observed=window_end is not None and window_end >= deadline,
            service_phase_elapsed_seconds=None if window_end is None else window_end-start,
            continuous_elapsed_seconds=end-start,
            failure=None if failure is None else 'finite_execution_failed',
            cleanup_failure=cleanup_failure, owner_cleanup_returned_true=cleaned,
            same_run_restored_journal=journal_restored,
            independent_restoration_verified=False, native_acceptance=False,
            production_enabled=False)


def main():
    # Static refusal before loading native modules, reading private state, taking
    # locks or issuing system/network commands. This is intentionally NOT usable
    # as an acceptance launcher. No --force, --pass, duration or source argument.
    print(json.dumps(dict(status='fixed_installed_entry_required', native_started=False,
        fixed_seconds=SECONDS, production_enabled=False, arguments_accepted=False)))
    return 2


if __name__ == '__main__':
    sys.exit(main())
