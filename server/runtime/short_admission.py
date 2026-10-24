"""Actual short-run receipt admission; no native/production facts synthesized."""
import math


class Refused(RuntimeError):pass


def successful_short_result(result,run,variant):
    keys={'run_id','seconds','execution','controller_entered','stop_requested','generations','expiry_observed',
          'service_phase_elapsed_seconds','continuous_elapsed_seconds','failure','cleanup_failure',
          'owner_cleanup_returned_true','same_run_restored_journal','independent_restoration_verified',
          'native_acceptance','production_enabled'}
    if variant!='diagnostic':raise Refused('unified_diagnostic_parent_only')
    if variant=='diagnostic':keys=keys|{'diagnostic'}
    if type(result)is not dict or set(result)!=keys:raise Refused('short_result_schema')
    if variant=='diagnostic':
        value=result['diagnostic']
        if (type(value)is not dict or set(value)!={'version','run','initial','cleanup','cleanup_codes'}
                or type(value['version'])is not int or value['version']!=1 or value['run']!=run
                or value['initial']is not None or value['cleanup']is not None or value['cleanup_codes']!=[]):
            raise Refused('short_diagnostic_not_clean')
    if (result['run_id']!=run or type(result['seconds'])is not int or result['seconds']!=900
            or result['execution']!='cooperative_window_returned'
            or any(result[k]is not True for k in ('controller_entered','expiry_observed','owner_cleanup_returned_true','same_run_restored_journal'))
            or any(result[k]is not False for k in ('stop_requested','independent_restoration_verified','native_acceptance','production_enabled'))
            or result['failure']is not None or result['cleanup_failure']is not None
            or type(result['generations'])is not int or result['generations']<1):
        raise Refused('short_window_not_successfully_used')
    phase=result['service_phase_elapsed_seconds'];total=result['continuous_elapsed_seconds']
    if any(type(v)not in(int,float) or not math.isfinite(v) for v in (phase,total)) or not 900<=phase<=total:
        raise Refused('short_window_timing_unknown')
    return result


def short_run(b,n,variant):
    """data_readback takes the native lock; caller rechecks before a new session."""
    io=b.io
    b.verify_closed(n,restoring=True)
    run,root=b.current_data();b.data_binding(n,run,root,restoring=True)
    result=successful_short_result(io.decode(io.read(root/'result.json',installed=True)),run,variant)
    receipt=io.decode(io.read(root/'restoration.json',installed=True))
    if (type(receipt)is not dict or set(receipt)!={'version','run','restored','session_sha256','baseline'}
            or type(receipt['version'])is not int or receipt['version']!=1 or receipt['run']!=run
            or receipt['restored']is not True):raise Refused('short_restoration_receipt_unknown')
    final=io.read(root/'final-session.json',installed=True)
    if io.digest(final)!=receipt['session_sha256']:raise Refused('short_final_session_changed')
    # Must be exactly this latest successfully completed short run, not a later
    # unrelated inactive journal. This v1 is one long run, no automatic retries.
    if io.encode(n.s.Store().load())!=final:raise Refused('short_run_no_longer_current')
    tested,saved,baseline=b.data_readback(n,run,root)
    if tested is not True or io.encode(saved)!=final:raise Refused('short_current_native_readback_failed')
    return dict(short_run=run,short_result_sha256=io.digest(io.encode(result)),
                short_restoration_sha256=io.digest(io.encode(receipt)),previous_session_sha256=io.digest(final),
                fresh_baseline=baseline)
