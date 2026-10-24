#!/usr/bin/python3
"""Work-only launchd scheduler candidate. Importing this module does nothing.

The unchanged, pinned v4 helper owns credentials, Ethernet-bound observation,
DNS validation, fixed update scope and its original nonblocking update lock.
"""
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import time

BASE = Path('/usr/local/family-vpn/ddns-production')
HELPER = Path('/usr/local/family-vpn/dynadot-ddns/update.py')
HELPER_SHA = 'ab3969b6ed62626c98be639e548c3ded7e803464ca155f1f23732e8908b1a0b7'
CONFIG = Path('/usr/local/etc/family-vpn/dynadot-ddns.json')
STATE = Path('/private/var/db/family-vpn/ddns-production')
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'}
LIMIT = 100000
RUN_SECONDS = 140


class Failure(Exception):
    pass


class Stopped(BaseException):
    pass


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid',
        'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def trusted(path, *, directory=False, mode=None):
    path = Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Failure('untrusted_path')
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise Failure('untrusted_ancestor')
        result = subprocess.run(['/bin/ls', '-lde', str(item)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, timeout=3)
        if result.returncode or len(result.stdout.splitlines()) != 1:
            raise Failure('extended_acl_or_metadata_failure')
    info = path.lstat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise Failure('unexpected_path_type')
    if not directory and info.st_nlink != 1:
        raise Failure('multiply_linked_file')
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise Failure('unexpected_mode')


def read(path, limit=LIMIT):
    trusted(path, mode=0o600)
    before = path.lstat()
    if before.st_size > limit:
        raise Failure('file_limit')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        opened = os.fstat(f.fileno())
        if identity(opened) != identity(before):
            raise Failure('changed_before_read')
        data = f.read(limit + 1)
        if (len(data) > limit or len(data) != opened.st_size or
                identity(os.fstat(f.fileno())) != identity(opened) or
                identity(path.lstat()) != identity(opened)):
            raise Failure('changed_during_read')
    return data


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_metadata(name, value):
    if name not in ('status.json', 'process.json'):
        raise Failure('unexpected_metadata_file')
    trusted(STATE, directory=True, mode=0o700)
    path = STATE / name
    if path.exists() or path.is_symlink():
        trusted(path, mode=0o600)
    data = (json.dumps(value, sort_keys=True) + '\n').encode('ascii')
    if len(data) > 4096:
        raise Failure('status_limit')
    temp = STATE / ('.status-' + secrets.token_hex(12))
    try:
        with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        sync_dir(STATE)
    finally:
        if temp.exists():
            temp.unlink()


def atomic_status(value):
    atomic_metadata('status.json', value)


@contextlib.contextmanager
def locked_path(path, *, create=False):
    trusted(path.parent, directory=True, mode=0o700)
    if path.exists() or path.is_symlink():
        trusted(path, mode=0o600)
    fd = os.open(path, os.O_RDWR | (os.O_CREAT if create else 0) | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        trusted(path, mode=0o600)
        if identity(os.fstat(fd)) != identity(path.lstat()):
            raise Failure('lock_replaced')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def load_status():
    path = STATE / 'status.json'
    if not path.exists() and not path.is_symlink():
        return None
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Failure('duplicate_status_key')
            value[key] = item
        return value
    try:
        value = json.loads(read(path, 4096), object_pairs_hook=unique)
    except (ValueError, TypeError, UnicodeError):
        raise Failure('invalid_status') from None
    return validate_status(value)


def validate_status(value):
    keys = {'version', 'last_started', 'last_finished', 'next_due', 'failures', 'outcome'}
    if not isinstance(value, dict) or set(value) != keys or type(value['version']) is not int or value['version'] != 1:
        raise Failure('invalid_status')
    if type(value['failures']) is not int or not 0 <= value['failures'] <= 5:
        raise Failure('invalid_status')
    for key in ('last_started', 'last_finished', 'next_due'):
        number = value[key]
        if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
            raise Failure('invalid_status')
    if value['outcome'] not in ('scheduled', 'running', 'success', 'failed', 'timeout', 'interrupted', 'clock_reset'):
        raise Failure('invalid_status')
    if value['next_due'] > max(value['last_started'], value['last_finished']) + 3630:
        raise Failure('invalid_status')
    return value


def delay(failures, jitter):
    if type(failures) is not int or not 0 <= failures <= 5 or type(jitter) is not int or not 0 <= jitter <= 30:
        raise Failure('invalid_schedule_input')
    return min(3600, 300 * 2 ** max(0, failures - 1)) + jitter


def record(now, failures, outcome, *, started=None, jitter=0):
    return dict(version=1, last_started=now if started is None else started,
        last_finished=now, next_due=now + delay(failures, jitter),
        failures=failures, outcome=outcome)


def execute_helper():
    # Same process group: launchd's default group cleanup is intentionally kept.
    # stdout/stderr are discarded, including unexpected Python traceback text.
    # Only the fixed result classification is persisted by this scheduler.
    proc = subprocess.Popen(['/usr/bin/python3', '-I', str(HELPER), 'update'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=ENV, close_fds=True, start_new_session=False, cwd='/')
    try:
        code = proc.wait(timeout=RUN_SECONDS)
        return 'success' if code == 0 else 'failed'
    except subprocess.TimeoutExpired:
        return 'timeout'
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)


def tick(previous, *, now=time.time, jitter=lambda: secrets.randbelow(31),
         save=atomic_status, execute=execute_helper):
    moment = now()
    if previous is None:
        # Installation/first boot schedules a later run; it is never a hidden
        # immediate update during the installation transaction.
        save(record(moment, 0, 'scheduled', jitter=jitter()))
        return 'scheduled'
    validate_status(previous)
    if moment < max(previous['last_started'], previous['last_finished']) - 5:
        save(record(moment, previous['failures'], 'clock_reset', jitter=jitter()))
        return 'clock_reset'
    if moment < previous['next_due']:
        return 'not_due'
    count = min(5, previous['failures'] + 1)
    pending = record(moment, count, 'running', jitter=jitter())
    save(pending)  # Crash/ambiguous request has a persisted backoff before spawn.
    try:
        outcome = execute()
        if outcome not in ('success', 'failed', 'timeout'):
            raise Failure('invalid_execution_result')
    except Stopped:
        save(record(now(), count, 'interrupted', started=moment, jitter=jitter()))
        raise
    except Exception:
        outcome = 'failed'
    finished = now()
    save(record(finished, 0 if outcome == 'success' else count, outcome,
                started=moment, jitter=jitter()))
    return outcome


def main():
    if os.geteuid() != 0 or Path(__file__).absolute() != BASE / 'scheduler.py' or len(sys.argv) != 1:
        raise Failure('fixed_root_installation_required')
    os.umask(0o077)
    trusted(BASE, directory=True, mode=0o700)
    trusted(BASE / 'scheduler.py', mode=0o600)
    # Metadata only. The scheduler never opens/prints the credential file.
    trusted(CONFIG, mode=0o600)
    def stop(_signum, _frame):
        raise Stopped()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with locked_path(STATE / 'scheduler.lock', create=True):
        pid, pgid = os.getpid(), os.getpgrp()
        if pid != pgid:
            raise Failure('dedicated_launchd_process_group_required')
        # Only used to prove group absence after bootout, never as kill authority.
        atomic_metadata('process.json', dict(version=1, pid=pid, pgid=pgid, started=time.time()))
        # The existing import/upgrade tool takes this lock before replacing the
        # helper. Hold it through execution; never replace that old lock inode.
        with locked_path(HELPER.parent / '.installer.lock'):
            if hashlib.sha256(read(HELPER)).hexdigest() != HELPER_SHA:
                raise Failure('helper_version_changed')
            tick(load_status())


if __name__ == '__main__':
    try:
        main()
    except BlockingIOError:
        sys.exit(0)  # Another scheduler owns its lock; no duplicate work.
    except Stopped:
        sys.exit(0)
    except Exception:
        # The job exposes no arbitrary exception, path, response or secret text.
        sys.exit(1)
