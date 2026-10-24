#!/usr/bin/python3
"""Fixed VPN maintenance capability. Installed root-owned; JSON on stdin only."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import time

INSTALL = Path('/Library/PrivilegedHelperTools/org.familyvpn.maintenance.py')
STATE = Path('/private/var/db/family-vpn-maintenance')
VPN = Path('/private/var/db/family-vpn/production-guardian')
ENTRY = Path('/usr/local/family-vpn/production-acceptance/root_entry.py')
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/var/root'}
LOGS = {
    'service-state': VPN / 'service-state.json',
    'service-events': VPN / 'service-events.jsonl',
    'service-error': VPN / 'service-error.json',
    'native-session': VPN / 'native-session.json',
    'native-charon': VPN / 'native-charon.log',
    'service-control': VPN / 'production/service-control.json',
    'ddns-status': Path('/private/var/db/family-vpn/ddns-production/status.json'),
    'maintenance-audit': STATE / 'audit.jsonl',
}
for _i in range(1, 4):
    LOGS['service-events.' + str(_i)] = VPN / ('service-events.jsonl.' + str(_i))
JOBS = {
    'vpn': ('org.familyvpn.service', ['/usr/bin/python3', '-I', '-B', '/usr/local/family-vpn/production-guardian/service_supervisor.py']),
    'monitor': ('org.familyvpn.monitor', ['/usr/bin/python3', '-I', '-B', '/usr/local/family-vpn/monitor-service/service.py']),
}


class Refused(Exception):
    pass


def trusted(path, directory=False):
    path = Path(path)
    for p in (path, *path.parents):
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise Refused('untrusted_root_path')
        if p != path and not stat.S_ISDIR(s.st_mode):
            raise Refused('untrusted_parent')
        # Reject inherited ACL grants as well as ordinary writable modes.
        acl = subprocess.run(['/bin/ls', '-lde', str(p)], env=ENV, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=3)
        if acl.returncode or len(acl.stdout.splitlines()) != 1:
            raise Refused('acl_refused')
    s = path.lstat()
    if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise Refused('wrong_file_type')
    if not directory and s.st_nlink != 1:
        raise Refused('hardlink_refused')
    return s


def read(path, limit=1048576):
    before = trusted(path)
    if before.st_size > limit:
        raise Refused('read_limit')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise Refused('file_changed')
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if len(data) > limit or (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise Refused('file_changed')
        return data
    finally:
        os.close(fd)


def value(path):
    return json.loads(read(path))


def command(args, timeout=20):
    p = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, env=ENV,
                       timeout=timeout, close_fds=True, cwd='/', start_new_session=True)
    return {'exit_code': p.returncode, 'stdout': p.stdout.decode('utf-8', 'replace')[:65536],
            'stderr': p.stderr.decode('utf-8', 'replace')[:4096]}


def job(key):
    label, _ = JOBS[key]
    r = command(['/bin/launchctl', 'print', 'system/' + label])
    if r['exit_code']:
        if 'Could not find service' not in r['stderr'] and 'Could not find service' not in r['stdout']:
            raise Refused('launchd_status_unavailable')
        return {'loaded': False, 'pid': None, 'state': None}
    pid = re.search(r'^\s*pid = (\d+)\s*$', r['stdout'], re.M)
    state = re.search(r'^\s*state = (.+)$', r['stdout'], re.M)
    return {'loaded': True, 'pid': int(pid[1]) if pid else None, 'state': state[1] if state else None}


def resolve_log(identifier):
    if identifier in LOGS:
        return LOGS[identifier]
    if re.fullmatch(r'error-history/[0-9a-f]{64}', identifier):
        return VPN / 'service-error-history' / (identifier.split('/')[1] + '.json')
    raise Refused('log_not_allowed')


def inventory():
    logs = dict(LOGS)
    history = VPN / 'service-error-history'
    if history.exists():
        trusted(history, directory=True)
        for p in history.iterdir():
            if re.fullmatch(r'[0-9a-f]{64}\.json', p.name):
                logs['error-history/' + p.stem] = p
    result = []
    for identifier, p in sorted(logs.items()):
        try:
            s = trusted(p)
            result.append({'id': identifier, 'bytes': s.st_size, 'mtime_ns': s.st_mtime_ns,
                           'device': s.st_dev, 'inode': s.st_ino})
        except FileNotFoundError:
            result.append({'id': identifier, 'missing': True})
    return result


def read_log(req):
    path = resolve_log(req['id'])
    before = trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if (s.st_dev, s.st_ino) != (before.st_dev, before.st_ino):
            raise Refused('file_changed')
        if req['offset'] > s.st_size:
            raise Refused('offset_past_end')
        os.lseek(fd, req['offset'], os.SEEK_SET)
        data = os.read(fd, min(262144, s.st_size - req['offset']))
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns) != (s.st_size, s.st_mtime_ns):
            raise Refused('file_changed_retry')
        # UTF-8 bytes are preserved across chunk boundaries.
        import base64
        return {'id': req['id'], 'offset': req['offset'], 'next_offset': req['offset'] + len(data),
                'eof': req['offset'] + len(data) == s.st_size, 'bytes': s.st_size,
                'inode': s.st_ino, 'mtime_ns': s.st_mtime_ns,
                'sha256_chunk': hashlib.sha256(data).hexdigest(), 'base64': base64.b64encode(data).decode()}
    finally:
        os.close(fd)


def snapshot():
    result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'logs': inventory(),
              'jobs': {k: job(k) for k in JOBS}}
    for key in ('service-state', 'service-control', 'service-error', 'ddns-status'):
        try:
            result[key] = value(LOGS[key])
        except FileNotFoundError:
            result[key] = None
    try:
        n = value(LOGS['native-session'])
        result['native-summary'] = {k: n.get(k) for k in ('phase', 'active', 'boot', 'cleanup_codes', 'recovery_result')}
    except FileNotFoundError:
        result['native-summary'] = None
    return result


def atomic(path, data):
    trusted(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        trusted(path)
    tmp = path.with_name(path.name + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if tmp.exists():
            tmp.unlink()


def audit(record):
    p = STATE / 'audit.jsonl'
    old = read(p, 2097152) if p.exists() else b''
    if len(old) > 1048576:
        atomic(STATE / 'audit.previous.jsonl', old)
        old = b''
    record = dict(record, at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    atomic(p, old + (json.dumps(record, sort_keys=True) + '\n').encode())


def status_verified():
    trusted(ENTRY)
    r = command(['/usr/bin/python3', '-I', '-B', str(ENTRY), 'service-status'], timeout=45)
    if r['exit_code']:
        raise Refused('installed_service_validation_failed')
    for line in reversed(r['stdout'].splitlines()):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get('action') == 'service-status':
            return d
    raise Refused('service_status_missing')


def service_decision(s, n, c, verified, live, boot):
    if verified.get('service_enabled') is not True or verified.get('data_permission') is not True:
        return 'disabled_preserved'
    if c.get('phase') != 'LOADED':
        return 'maintenance_or_manual_state_preserved'
    if s.get('phase') not in ('PREFLIGHT', 'STARTING', 'RUNNING', 'RECOVERING', 'BACKOFF'):
        return 'latched_or_stopped_state_preserved'
    if s.get('reason') not in ('initial', 'preflight', 'starting', 'running', 'known_daemon_exit',
                              'known_uplink_change', 'scheduled_maintenance', 'interrupted_owner',
                              'backoff', 'network_not_ready', 'vici_unavailable', 'gate_readback_unavailable'):
        return 'failure_requires_diagnosis'
    if s.get('boot') != boot or n.get('boot') != boot or n.get('phase') == 'ATTENTION':
        return 'boot_or_native_state_requires_diagnosis'
    return 'already_running' if live['pid'] else 'restore_supervisor'


def disabled_override(text, label):
    """Read the complete launchctl override table; absent target means no override."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if (len(lines) < 2 or lines[0] not in ('disabled services = {', '{')
            or lines[-1] != '}'):
        raise Refused('disabled_status_unverified')
    values = []
    for line in lines[1:-1]:
        row = re.fullmatch(r'"([^"\r\n]+)"\s*=>\s*(\S+)', line)
        if row is None:
            raise Refused('disabled_status_unverified')
        if row[1] == label:
            if values or row[2] not in ('true', 'false', 'disabled', 'enabled'):
                raise Refused('disabled_status_unverified')
            values.append(row[2] in ('true', 'disabled'))
    return bool(values and values[0])


def repair(key):
    label, expected_args = JOBS[key]
    plist = Path('/Library/LaunchDaemons') / (label + '.plist')
    p = plistlib.loads(read(plist))
    if p.get('Label') != label or p.get('ProgramArguments') != expected_args or p.get('UserName', 'root') != 'root':
        raise Refused('job_definition_changed')
    trusted(Path(expected_args[-1]))
    disabled = command(['/bin/launchctl', 'print-disabled', 'system'])
    if disabled['exit_code'] or disabled_override(disabled['stdout'], label):
        raise Refused('disabled_job_preserved')
    live = job(key)
    kill = False
    if key == 'vpn':
        v = status_verified()
        s, n, c = (value(LOGS[k]) for k in ('service-state', 'native-session', 'service-control'))
        b = command(['/usr/sbin/sysctl', '-n', 'kern.boottime'])
        if b['exit_code']:
            raise Refused('boot_unknown')
        decision = service_decision(s, n, c, v, live, b['stdout'].strip())
        if decision != 'restore_supervisor':
            return {'action': 'none', 'reason': decision, 'job': key}
    elif live['pid']:
        # The root collector has no VPN control authority; only restart it when
        # its public sample is stale on two observations, never on empty traffic.
        import urllib.request
        def fresh():
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open('http://127.0.0.1:8767/api/status', timeout=3) as f:
                    d = json.loads(f.read(1048576))
                at = datetime.datetime.fromisoformat(d['observed_at'].replace('Z', '+00:00')).timestamp()
                return 0 <= time.time() - at < 60 and d.get('collector', {}).get('state') == 'ok'
            except Exception:
                return None
        one = fresh()
        if one is not False:
            return {'action': 'none', 'reason': 'collector_fresh_or_endpoint_unavailable', 'job': key}
        time.sleep(2)
        if fresh() is not False:
            return {'action': 'none', 'reason': 'collector_recovered_or_unconfirmed', 'job': key}
        kill = True
    cooldown = STATE / 'attempts.json'
    attempts = value(cooldown) if cooldown.exists() else {}
    now = time.time()
    if now - attempts.get(key, 0) < 900:
        return {'action': 'none', 'reason': 'repair_cooldown', 'job': key}
    # Record intent before the one permitted action; a crash cannot cause a retry loop.
    attempts[key] = now
    atomic(cooldown, (json.dumps(attempts) + '\n').encode())
    audit({'event': 'repair_intent', 'job': key, 'previous': live, 'force_collector_only': kill})
    # Recheck immediately before launchd. Configuration/state may have changed
    # while the audit was committed; never undo an operator's stop.
    again = command(['/bin/launchctl', 'print-disabled', 'system'])
    if again['exit_code'] or disabled_override(again['stdout'], label):
        raise Refused('disabled_during_repair')
    if plistlib.loads(read(plist)) != p:
        raise Refused('job_changed_during_repair')
    latest = job(key)
    if key == 'vpn':
        verified = status_verified()
        s, n, c = (value(LOGS[k]) for k in ('service-state', 'native-session', 'service-control'))
        decision = service_decision(s, n, c, verified, latest, b['stdout'].strip())
        if decision != 'restore_supervisor':
            audit({'event': 'repair_cancelled', 'job': key, 'reason': decision})
            return {'action': 'none', 'reason': decision, 'job': key}
    elif latest['pid'] and (not kill or latest['pid'] != live['pid'] or fresh() is not False):
        audit({'event': 'repair_cancelled', 'job': key, 'reason': 'collector_changed_or_recovered'})
        return {'action': 'none', 'reason': 'collector_changed_or_recovered', 'job': key}
    live = latest
    if live['loaded']:
        args = ['/bin/launchctl', 'kickstart'] + (['-k'] if kill else []) + ['system/' + label]
    else:
        args = ['/bin/launchctl', 'bootstrap', 'system', str(plist)]
    r = command(args)
    time.sleep(2)
    after = job(key)
    audit({'event': 'repair_result', 'job': key, 'exit_code': r['exit_code'], 'after': after})
    return {'action': args[1], 'job': key, 'command_result': r, 'after': after,
            'recovery_verified': False, 'next_step': 'Recheck fresh service/native/monitor and host networking; spawning is not recovery proof.'}


def validate(req):
    if type(req) is not dict:
        raise Refused('request_type')
    a = req.get('action')
    fields = {'snapshot': {'action'}, 'read-log': {'action', 'id', 'offset'},
              'repair': {'action', 'job'}, 'network': {'action'}}
    if type(a) is not str or a not in fields or set(req) != fields[a]:
        raise Refused('request_not_allowed')
    if a == 'read-log':
        if type(req['id']) is not str or type(req['offset']) is not int or not 0 <= req['offset'] <= 2**63 - 1:
            raise Refused('log_request_invalid')
        resolve_log(req['id'])
    if a == 'repair' and (type(req['job']) is not str or req['job'] not in JOBS):
        raise Refused('repair_target_not_allowed')
    return a


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1 or Path(__file__) != INSTALL:
        raise Refused('installed_root_entry_only')
    trusted(INSTALL)
    trusted(STATE, directory=True)
    os.umask(0o077)
    raw = sys.stdin.buffer.readline(8193)
    if len(raw) > 8192:
        raise Refused('request_too_large')
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise Refused('duplicate_key')
            d[k] = v
        return d
    req = json.loads(raw, object_pairs_hook=unique)
    action = validate(req)
    lock = STATE / 'maintenance.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        trusted(lock)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'snapshot':
            result = snapshot()
        elif action == 'read-log':
            result = read_log(req)
        elif action == 'repair':
            result = repair(req['job'])
        else:
            result = {name: command(args) for name, args in {
                'forwarding': ['/usr/sbin/sysctl', 'net.inet.ip.forwarding', 'net.inet6.ip6.forwarding'],
                'ipv4-route': ['/sbin/route', '-n', 'get', '-inet', 'default'],
                'ipv6-route': ['/sbin/route', '-n', 'get', '-inet6', 'default'],
                'pf-status': ['/sbin/pfctl', '-s', 'info'],
            }.items()}
        print(json.dumps({'ok': True, 'action': action, 'result': result}, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'ok': False, 'error': str(e) if isinstance(e, Refused) else type(e).__name__}))
        raise SystemExit(1)
