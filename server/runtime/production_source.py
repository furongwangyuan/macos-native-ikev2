"""Actual durable service start, separate from finite phone/server windows.

The sole service owner writes an immutable start before native preparation.
Recovery reads that same run, the real service state and current configuration.
No caller supplies an old PID to inspect/kill and no finite marker is invented.
"""
import base64
import json
import os
import re
import uuid
import native_support as s
from supervisor_core import valid_state

KIND = 'production-service-v1'
NAMES = {'intent', 'service-state', 'native-config', 'supervisor-config'}


class Refused(RuntimeError):
    pass


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return s.digest(raw)


def exact_hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def run_id(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{32}', value) is not None


def root():
    return s.STATE / 'production' / 'runs'


def marker(native):
    value = native.get('production_run')
    if (type(value) is not dict or set(value) != {'version', 'run_id', 'intent_sha256'}
            or type(value['version']) is not int or value['version'] != 1
            or not run_id(value['run_id']) or not exact_hash(value['intent_sha256'])
            or native.get('probe_mode') != 'off' or native.get('test_action') != 'service'
            or any(k in native for k in ('finite_window', 'finite_ready', 'server_window', 'server_ready'))):
        raise Refused('production_native_marker')
    return value


def intent(value):
    keys = {'version', 'profile', 'run', 'boot', 'configuration_sha256', 'code_sha256',
            'kernel_release', 'machine', 'owner'}
    if (type(value) is not dict or set(value) != keys or type(value['version']) is not int
            or value['version'] != 1 or value['profile'] != KIND or not run_id(value['run'])
            or any(type(value[k]) is not str or not value[k] or len(value[k]) > 256
                   for k in ('boot', 'kernel_release', 'machine'))
            or any(not exact_hash(value[k]) for k in ('configuration_sha256', 'code_sha256'))):
        raise Refused('production_start_intent')
    owner = value['owner']
    if (type(owner) is not dict or set(owner) != {'pid', 'uid', 'pgid', 'started_sec', 'started_usec', 'path'}
            or any(type(owner[k]) is not int for k in ('pid', 'uid', 'pgid', 'started_sec', 'started_usec'))
            or owner['pid'] <= 1 or owner['uid'] != 0 or owner['pgid'] <= 0 or owner['started_sec'] <= 0
            or not 0 <= owner['started_usec'] < 1000000 or type(owner['path']) is not str
            or not owner['path'].startswith('/') or any(c in owner['path'] for c in ('\0', '\n', '\r'))):
        raise Refused('production_actual_owner_receipt')
    return value


def write_new(path, raw):
    """Fixed private regular file, no replacement of a prior start."""
    s.trusted(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(raw)
            out.flush()
            os.fchmod(fd, 0o600)
            os.fsync(fd)
    finally:
        os.close(fd)
    s.sync_dir(path.parent)
    if s.read(path) != raw:
        raise Refused('production_start_readback')


def prepare(session, configuration, code):
    """NativeDependencies.prepare calls this under the existing native locks.

    This writes metadata only. A crash before Store.save leaves an orphan run,
    which is never selected by recovery; an existing native journal is intact.
    """
    if (session.get('test_action') != 'service' or session.get('probe_mode') != 'off'
            or session.get('active') is not True or session.get('phase') != 'PREPARING'
            or session.get('boot') != s.boot() or configuration.enabled is not True
            or not exact_hash(configuration.fingerprint) or not exact_hash(code)
            or 'production_run' in session):
        raise Refused('production_prepare_scope')
    state = valid_state(s.json_value(s.read(s.STATE / 'service-state.json', limit=16384)))
    if (state['boot'] != session['boot'] or state['fingerprint'] != configuration.fingerprint
            or state['phase'] != 'PREFLIGHT'):
        raise Refused('production_prepare_requires_actual_service_preflight')
    parent = s.STATE / 'production'
    s.directory(parent)
    s.directory(root())
    run = uuid.uuid4().hex
    directory = root() / run
    directory.mkdir(mode=0o700)
    s.sync_dir(root())
    value = intent(dict(version=1, profile=KIND, run=run, boot=session['boot'],
        configuration_sha256=configuration.fingerprint, code_sha256=code,
        kernel_release=os.uname().release, machine=os.uname().machine,
        owner=s.process(os.getpid())))
    raw = encode(value)
    write_new(directory / 'intent.json', raw)
    session['production_run'] = dict(version=1, run_id=run, intent_sha256=digest(raw))
    marker(session)


def snapshot(native):
    mark = marker(native)
    path = root() / mark['run_id']
    s.trusted(path, 0o700)
    paths = {'intent': path / 'intent.json', 'service-state': s.STATE / 'service-state.json',
             'native-config': s.CONF / 'config.json', 'supervisor-config': s.CONF / 'supervisor-config.json'}
    files = {key: s.read(value, limit=16384) for key, value in paths.items()}
    if any(s.read(value, limit=16384) != files[key] for key, value in paths.items()):
        raise Refused('production_context_changed')
    return encode(dict(version=1, kind=KIND, files={k: base64.b64encode(v).decode() for k, v in files.items()}))


def unpack(raw):
    if type(raw) is not bytes or len(raw) > 98304:
        raise Refused('production_context_limit')
    value = s.json_value(raw)
    if (type(value) is not dict or set(value) != {'version', 'kind', 'files'}
            or type(value['version']) is not int or value['version'] != 1 or value['kind'] != KIND
            or type(value['files']) is not dict or set(value['files']) != NAMES):
        raise Refused('production_context_shape')
    files = {}
    for key, encoded in value['files'].items():
        if type(encoded) is not str:
            raise Refused('production_context_file_type')
        files[key] = base64.b64decode(encoded, validate=True)
        if len(files[key]) > 16384:
            raise Refused('production_context_file_limit')
    return files


def validate(native, raw, *, permission_closed=False):
    if permission_closed is not False:
        raise Refused('production_recovery_does_not_reenable_permission')
    mark = marker(native)
    files = unpack(raw)
    start = intent(s.json_value(files['intent']))
    state = valid_state(s.json_value(files['service-state']))
    config = s.json_value(files['native-config'])
    supervisor = s.json_value(files['supervisor-config'])
    # An explicit operator disable is never overwritten to complete a reboot.
    if (config != dict(version=1, allow_data=True) or type(config.get('version')) is not int
            or config.get('allow_data') is not True
            or supervisor != dict(version=1, enabled=True) or type(supervisor.get('version')) is not int
            or supervisor.get('enabled') is not True):
        raise Refused('production_permission_changed')
    configuration = digest(files['supervisor-config'] + b'\0' + files['native-config'])
    if (start['run'] != mark['run_id'] or digest(files['intent']) != mark['intent_sha256']
            or start['boot'] != native.get('boot') or state['boot'] != start['boot']
            or start['configuration_sha256'] != configuration or state['fingerprint'] != configuration
            or state['phase'] not in ('PREFLIGHT', 'STARTING', 'RUNNING', 'RECOVERING', 'STOPPED', 'BACKOFF')):
        raise Refused('production_source_binding')
    return dict(kind=KIND, boot=start['boot'], configuration_sha256=configuration, run=start['run'])


def verify_current_resources(raw):
    import service_supervisor as service
    files = unpack(raw)
    start = intent(s.json_value(files['intent']))
    if (start['code_sha256'] != service.code_fingerprint()
            or start['kernel_release'] != os.uname().release or start['machine'] != os.uname().machine):
        raise Refused('production_runtime_changed_since_start')

