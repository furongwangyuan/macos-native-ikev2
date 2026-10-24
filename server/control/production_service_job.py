"""Fixed production launchd operations. No arbitrary target, argv or CLI."""
import os
from pathlib import Path
import plistlib
import re
import secrets
import selectors
import subprocess
import time

LABEL = 'org.familyvpn.service'
TARGET = 'system/' + LABEL
PLIST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
PROGRAM = '/usr/local/family-vpn/production-guardian/service_supervisor.py'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
COMMANDS = {
    'query': ['/bin/launchctl', 'print', TARGET],
    'overrides': ['/bin/launchctl', 'print-disabled', 'system'],
    'enable': ['/bin/launchctl', 'enable', TARGET],
    'disable': ['/bin/launchctl', 'disable', TARGET],
    'load': ['/bin/launchctl', 'bootstrap', 'system', str(PLIST)],
    'terminate': ['/bin/launchctl', 'kill', 'SIGTERM', TARGET],
    'unload': ['/bin/launchctl', 'bootout', TARGET],
}


class Refused(RuntimeError):
    pass


def command(action):
    if action not in COMMANDS:
        raise Refused('production_job_fixed_command_only')
    child = subprocess.Popen(COMMANDS[action], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, cwd='/',
        close_fds=True, start_new_session=True)
    selector = None
    outputs = {child.stdout: bytearray(), child.stderr: bytearray()}
    try:
        selector = selectors.DefaultSelector()
        for stream in outputs:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + (180 if action == 'unload' else 8)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused('production_job_command_deadline')
            for key, _ in selector.select(min(remaining, .1)):
                raw = os.read(key.fd, 8192)
                if not raw:
                    selector.unregister(key.fileobj)
                else:
                    outputs[key.fileobj].extend(raw)
                    if sum(map(len, outputs.values())) > 131072:
                        raise Refused('production_job_output_limit')
        child.wait(timeout=max(.001, deadline - time.monotonic()))
        if time.monotonic() > deadline:
            raise Refused('production_job_command_late_completion')
        return subprocess.CompletedProcess(COMMANDS[action], child.returncode,
            bytes(outputs[child.stdout]), bytes(outputs[child.stderr]))
    finally:
        try:
            if child.poll() is None:
                child.kill()  # exact still-owned Popen child, never PID/group search
            child.wait(timeout=2)
        finally:
            try:
                if selector is not None:
                    selector.close()
            finally:
                for stream in outputs:
                    stream.close()


def observe():
    """One registered identity and its current process, never a saved PID."""
    reply = command('query')
    absent = b'Bad request.\nCould not find service "org.familyvpn.service" in domain for system'
    if reply.returncode == 113 and (reply.stdout + reply.stderr).strip() == absent:
        return None
    if reply.returncode or reply.stderr:
        raise Refused('production_job_query_unknown')
    lines = reply.stdout.decode('utf8', 'strict').splitlines()
    if (len(lines) < 3 or lines[0] != TARGET + ' = {' or lines[-1] != '}'
            or any(line and not line.startswith('\t') for line in lines[1:-1])):
        raise Refused('production_job_layout')
    wanted = dict(path=str(PLIST), program='/usr/bin/python3', domain='system',
                  type='LaunchDaemon', arguments='{')
    fields, positions = {}, {}
    for index, line in enumerate(lines[1:-1], 1):
        if not line.startswith('\t') or line.startswith('\t\t'):
            continue
        key, sep, value = line[1:].partition(' = ')
        if key in set(wanted) | {'state', 'pid'}:
            if not sep or key in fields:
                raise Refused('production_job_duplicate_field')
            fields[key], positions[key] = value, index
    # Scheduler state changes during bootstrap/bootout (observed: xpcproxy,
    # SIGTERMed). It is not the identity of this registered launchd job.
    if any(fields.get(key) != value for key, value in wanted.items()):
        raise Refused('production_job_identity')
    block = ['\targuments = {', '\t\t/usr/bin/python3', '\t\t-I', '\t\t-B', '\t\t' + PROGRAM, '\t}']
    at = positions['arguments']
    if lines[at:at + len(block)] != block:
        raise Refused('production_job_arguments')
    state, pid = fields.get('state'), fields.get('pid')
    if not state or (pid is not None and
            (not re.fullmatch('[1-9][0-9]*', pid) or int(pid) <= 1)):
        raise Refused('production_job_process_layout')
    return dict(state=state, pid=None if pid is None else int(pid))


def loaded():
    return observe() is not None


def stop_and_unload(held):
    """Finish the existing disable request without bootout killing recovery.

    A loaded but idle job is removed only after its process has exited. The
    ordinary close/fresh native readback remains the caller's responsibility.
    """
    def idle(value):
        return value is None or (value['pid'] is None and
            value['state'] in ('not running', 'waiting', 'exited'))

    held()
    if override() is not True:
        raise Refused('production_stop_not_disabled')
    current = observe()
    if current is None:
        return
    if not idle(current):
        reply = command('terminate')  # fixed label; never signal a remembered PID
        current = observe()
        if reply.returncode and not idle(current):
            raise Refused('production_job_term_failed')
        deadline = time.monotonic() + 90
        while not idle(current):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused('production_job_process_still_running')
            time.sleep(min(.5, remaining))
            held()
            current = observe()
    held()
    if override() is not True:
        raise Refused('production_stop_not_disabled')
    current = observe()
    if current is None:
        return
    if not idle(current):
        raise Refused('production_job_restarted_during_stop')
    try:
        command('unload')
    except Refused as error:
        if str(error) not in ('production_job_command_deadline',
                              'production_job_command_late_completion'):
            raise
    except subprocess.TimeoutExpired:
        # A bootout subprocess timing out does not establish job absence.
        pass
    deadline = time.monotonic() + 30
    while True:
        held()
        current = observe()
        if current is None:
            return
        if current['pid'] is not None:
            raise Refused('production_job_restarted_during_stop')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused('production_job_still_loaded')
        time.sleep(min(.5, remaining))


def override():
    reply = command('overrides')
    if reply.returncode or reply.stderr:
        raise Refused('production_override_query')
    text = reply.stdout.decode('ascii', 'strict')
    if not re.fullmatch(r'\s*disabled services = \{\n(?:\s*"[^"\n]+" => (?:enabled|disabled)\n)*\s*\}\n?', text):
        raise Refused('production_override_layout')
    values = re.findall(r'^\s*"' + re.escape(LABEL) + r'" => (enabled|disabled)$', text, re.M)
    if len(values) > 1:
        raise Refused('production_override_duplicate')
    return None if not values else values[0] == 'disabled'


def set_override(disabled):
    if type(disabled) is not bool:
        raise Refused('production_override_type')
    command('disable' if disabled else 'enable')
    if override() is not disabled:
        raise Refused('production_override_not_confirmed')


def expected(s):
    raw = s.read(s.BASE / (LABEL + '.plist'))
    value = plistlib.loads(raw)
    wanted = dict(Label=LABEL, ProgramArguments=['/usr/bin/python3', '-I', '-B', PROGRAM],
        UserName='root', RunAtLoad=True, KeepAlive={'SuccessfulExit': False}, ThrottleInterval=15,
        ProcessType='Background', StandardOutPath='/dev/null', StandardErrorPath='/dev/null')
    if value != wanted or type(value.get('ThrottleInterval')) is not int:
        raise Refused('production_plist_not_fixed')
    return raw


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def check_file(s, raw, *, absent=False):
    if not present(PLIST):
        if absent:
            return False
        raise Refused('production_plist_missing')
    if s.read(PLIST, mode=0o644) != raw:
        raise Refused('production_plist_unknown_preserved')
    return True


def publish(s, raw):
    if check_file(s, raw, absent=True):
        return
    s.trusted(PLIST.parent, 0o755)
    temp = PLIST.parent / ('.familyvpn-service-' + secrets.token_hex(12))
    fd = None
    stamp = None
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        stamp = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        offset = 0
        while offset < len(raw):
            amount = os.write(fd, raw[offset:])
            if amount <= 0:
                raise Refused('production_plist_short_write')
            offset += amount
        os.fchmod(fd, 0o644)
        os.fsync(fd)
        if (temp.lstat().st_dev, temp.lstat().st_ino) != stamp:
            raise Refused('production_plist_temp_changed')
        os.link(temp, PLIST, follow_symlinks=False)
        temp.unlink()
        s.sync_dir(PLIST.parent)
        check_file(s, raw)
    finally:
        if fd is not None:
            os.close(fd)
        if present(temp) and stamp == (temp.lstat().st_dev, temp.lstat().st_ino):
            temp.unlink()


def remove(s, raw):
    if check_file(s, raw, absent=True):
        PLIST.unlink()
        s.sync_dir(PLIST.parent)
    if present(PLIST):
        raise Refused('production_plist_removal_not_confirmed')
