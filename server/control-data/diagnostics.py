"""Bounded public diagnostics only. No native operation or admission decision."""
import json
import re
import subprocess

STAGES = frozenset(('installation', 'history_handoff', 'closed_suite', 'owner_fault',
    'data_admission', 'data_preflight', 'data_prepare', 'data_setup', 'data_controller',
    'data_cleanup', 'restoration_readback', 'permission_restore', 'production_control'))
ACTIONS = frozenset(('closed-test', 'closed-charon-term-test', 'closed-charon-kill-test'))
REASONS = frozenset(('uplink_ipv4_unavailable', 'uplink_ipv6_unavailable',
    'uplink_route_or_address_changed', 'existing_vpn_or_port_busy', 'native_baseline_not_empty',
    'daemon_start_failed', 'loaded_crl_not_current', 'alf_state_changed', 'owned_writer_unsettled',
    'native_protection_unverified', 'configuration_changed', 'command_failed', 'command_timeout',
    'io_failed', 'requested_stop', 'unknown_validation_failure', 'diagnostic_unavailable',
    'diagnostic_write_failed', 'closed_control_failed', 'probe_port_unverified',
    'probe_start_or_identity_failed', 'probe_cleanup_unverified'))
CLEANUP_CODES = frozenset(('unsettled_mutator', 'alf_close', 'guard', 'journal', 'child', 'sysctl',
    'native_daemon_or_sad', 'alf_restore', 'owned_recovery', 'alf_baseline_not_restored',
    'closed_alf_changed', 'alf_readback', 'probe_child'))
EXACT = {
    'probe_tcp_endpoint_not_absent': 'probe_port_unverified',
    'fixed_command_failed': 'command_failed',
    'fixed_mutation_failed': 'command_failed',
    'uplink_changed': 'uplink_route_or_address_changed',
    'outer_route_changed': 'uplink_route_or_address_changed',
    'exact_vip_route_changed': 'uplink_route_or_address_changed',
    'existing_charon_or_inventory_failure': 'existing_vpn_or_port_busy',
    'ike_ports_not_free': 'existing_vpn_or_port_busy',
    'native_baseline_not_empty': 'native_baseline_not_empty',
    'charon_start_failed': 'daemon_start_failed',
    'owned_charon_exited': 'daemon_start_failed',
    'charon_exited_or_changed': 'daemon_start_failed',
    'VICI has not loaded the retired-retired01 CRL': 'loaded_crl_not_current',
    'CRL changed during startup': 'loaded_crl_not_current',
    'crl_changed': 'loaded_crl_not_current', 'crl_expired': 'loaded_crl_not_current',
    'alf_changed_preserving_external': 'alf_state_changed',
    'alf_baseline_changed': 'alf_state_changed', 'alf_prepared_state_changed': 'alf_state_changed',
    'alf_open_readback_failed': 'alf_state_changed', 'alf_close_unverified': 'alf_state_changed',
    'alf_external_changes_preserved_not_restored': 'alf_state_changed',
    'writer_not_settled': 'owned_writer_unsettled',
    'native_restoration_incomplete': 'native_protection_unverified',
    'closed_gate_unverified': 'native_protection_unverified',
    'closed_gate_changed': 'native_protection_unverified',
    'active_gate_changed': 'native_protection_unverified',
    'configuration_changed': 'configuration_changed', 'data_resources_changed': 'configuration_changed',
    'daemon_config_pin_changed': 'configuration_changed',
    'requested_stop': 'requested_stop', 'stop_already_requested': 'requested_stop',
    'stop_before_prepare': 'requested_stop',
    'finite_window_cancelled_before_setup': 'requested_stop',
    'finite_window_cancelled_after_setup': 'requested_stop',
    'closed_control_failed': 'closed_control_failed', 'closed_suite_failed': 'closed_control_failed',
}

# Fixed literal codes only; unknown messages stay private and unclassified.
EXACT.update({code:'probe_start_or_identity_failed' for code in (
    'probe_identity_unavailable','probe_group_unknown','probe_identity_changed',
    'gate_ready_timeout','gate_eof_before_ready','gate_ready_bound','gate_ready_unknown',
    'root_gate_identity_unknown','gate_budget_or_boot_changed','incomplete_go',
    'probe_listener_ready_timeout','probe_exited_before_ready','ordinary_fixed_exec_not_observed',
    'fixed_binary_hash_changed','ordinary_exec_path_not_searchable','private_gate_directory',
    'probe_ended_before_owner_window')})
EXACT.update({code:'probe_cleanup_unverified' for code in (
    'probe_pipe_cleanup_failed','probe_eof_or_reap_missing','probe_survivor_unknown',
    'owned_probe_group_not_empty','probe_owned_cleanup_unverified','probe_port_observation_timeout',
    'probe_port_observation_limit','probe_port_observation_late','probe_port_observation_unknown',
    'probe_port_observation_cleanup_failed','pre_go_listener_not_proven_absent',
    'unknown_probe_group_survivor','probe_recovery_identity_mismatch','exact_probe_did_not_exit',
    'probe_recovery_final_readback','restored_probe_not_retired')})


def diagnostic_reason(error):
    """Only exact literals, fixed prefixes and types; never returns error text."""
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return 'requested_stop'
    if isinstance(error, subprocess.TimeoutExpired):
        return 'command_timeout'
    if isinstance(error, subprocess.CalledProcessError):
        return 'command_failed'
    if isinstance(error, OSError):
        return 'io_failed'
    # args is inspected, not __str__; custom formatting is never invoked.
    args = getattr(error, 'args', ())
    value = args[0] if type(args) is tuple and len(args) == 1 and type(args[0]) is str else None
    if value in EXACT:
        return EXACT[value]
    if value is not None:
        for family in (4, 6):
            if value.startswith('Uplink IPv%d preflight failed after 2 bounded attempts: ' % family):
                return 'uplink_ipv%d_unavailable' % family
    return 'unknown_validation_failure'


def diagnostic_failure(stage, error, *, action=None, controller_cause=False):
    try:
        reason = diagnostic_reason(error)
        # The real Controller wraps its sole failure in this specific Fault.
        # Inspect at most its direct cause, only on the concrete controller path.
        args = getattr(error, 'args', ())
        if (controller_cause and type(error).__module__ == 'controller' and type(error).__name__ == 'Fault'
                and len(args) == 1 and type(args[0]) is str
                and args[0].startswith('Reconnect validation failed: ')
                and isinstance(error.__cause__, BaseException)):
            reason = diagnostic_reason(error.__cause__)
        return diagnostic_validate_failure(dict(stage=stage, reason=reason, action=action))
    except BaseException:
        return dict(stage=stage if stage in STAGES else 'data_admission',
                    reason='diagnostic_unavailable', action=None)


def diagnostic_validate_failure(value):
    if (type(value) is not dict or set(value) != {'stage','reason','action'}
            or type(value['stage']) is not str or value['stage'] not in STAGES
            or type(value['reason']) is not str or value['reason'] not in REASONS
            or not (value['action'] is None or type(value['action']) is str and value['action'] in ACTIONS)
            or value['action'] is not None and value['stage'] != 'closed_suite'):
        raise ValueError('invalid_diagnostic')
    return dict(value)


def diagnostic_cleanup_codes(value):
    if type(value) is not list or len(value) > len(CLEANUP_CODES):
        return []
    return sorted(set(x for x in value if type(x) is str and x in CLEANUP_CODES))


def diagnostic_record(run, initial=None, cleanup=None, codes=()):
    return diagnostic_validate_record(dict(version=1, run=run, initial=initial, cleanup=cleanup,
                                          cleanup_codes=list(codes)), run)


def diagnostic_validate_record(value, run):
    if (type(run) is not str or re.fullmatch('[a-f0-9]{32}', run) is None
            or type(value) is not dict or set(value) != {'version','run','initial','cleanup','cleanup_codes'}
            or type(value['version']) is not int or value['version'] != 1 or value['run'] != run
            or type(value['cleanup_codes']) is not list
            or value['cleanup_codes'] != diagnostic_cleanup_codes(value['cleanup_codes'])):
        raise ValueError('invalid_diagnostic_receipt')
    return dict(version=1, run=run,
                initial=None if value['initial'] is None else diagnostic_validate_failure(value['initial']),
                cleanup=None if value['cleanup'] is None else diagnostic_validate_failure(value['cleanup']),
                cleanup_codes=list(value['cleanup_codes']))


def diagnostic_emit(failure, *, restoration='not_attempted', codes=()):
    """Public output exceptions do not replace cleanup; synchronous I/O is not a hard timeout."""
    try:
        fact = diagnostic_validate_failure(failure)
        if restoration not in ('not_attempted', 'verified', 'unverified'):
            raise ValueError('invalid_restoration_status')
        print(json.dumps(dict(version=1, event='failure_diagnostic', **fact,
            restoration_status=restoration, cleanup_codes=diagnostic_cleanup_codes(list(codes)),
            production_ready=False), sort_keys=True), flush=True)
    except BaseException:
        pass
