"""Production fleet closed-only seal v5. Pure schema; not a native collector or activation receipt."""
import copy
import re

PROFILE='production-native-fleet-v1'


class InvalidCheckpoint(ValueError):pass


def validate(value):
    fields={'version','run','boot','profile','session_sha256','closure_sha256','allow_data','probe_mode',
            'phase','mutator','forwarding_zero','forwarding_never_opened','no_state_deletion',
            'guard_exact','native_only','sad_empty','no_ike','alf_blockall_unchanged','owned_listener_only'}
    if (type(value)is not dict or set(value)!=fields or type(value['version'])is not int or value['version']!=5
            or type(value['run'])is not str or not re.fullmatch('[0-9a-f]{32}',value['run'])
            or type(value['boot'])is not str or not 1<=len(value['boot'])<=256
            or value['profile']!=PROFILE or value['allow_data']is not False or value['probe_mode']!='off'
            or value['phase']!='CLOSED_TEST' or value['mutator']!='settled'
            or any(type(value[k])is not str or not re.fullmatch('[0-9a-f]{64}',value[k])
                   for k in ('session_sha256','closure_sha256'))
            or any(value[k]is not True for k in ('forwarding_zero','forwarding_never_opened','no_state_deletion',
                'guard_exact','native_only','sad_empty','no_ike','alf_blockall_unchanged','owned_listener_only'))):
        raise InvalidCheckpoint('production_fleet_closed_v5_checkpoint_required')
    return copy.deepcopy(value)
