"""Ordinary-user hidden input -> anonymous pipe -> pinned root installer.

No credential is placed in arguments, environment, files, or bridge diagnostics.
sudo input logging must be independently excluded BEFORE collecting a credential.
Only a strict, read-only standard local sudoers check passes the policy gate.
"""
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import selectors
import time
import subprocess
import sys
import termios
import warnings

INSTALLER_SHA = '__INSTALLER_SHA__'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
HANDOFF_SECONDS = 120

# This code never reads stdin. The installer's execve must preserve the FIFO at fd 0.
BOOTSTRAP = r'''
from pathlib import Path
import hashlib, os, stat, sys
path = Path(sys.argv[1]) / 'install-root.py'
try:
    if not stat.S_ISFIFO(os.fstat(0).st_mode):
        raise ValueError()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 100000:
            raise ValueError()
        data = handle.read(100001)
    if len(data) > 100000 or hashlib.sha256(data).hexdigest() != '__INSTALLER_SHA__':
        raise ValueError()
except (OSError, ValueError):
    sys.exit('DDNS installer verification failed; no code executed')
exec(compile(data, str(path), 'exec'), {'__name__': '__main__', '__file__': str(path)})
'''


class BridgeFailure(Exception):
    def __init__(self, stage, error_number=None):
        self.stage = stage
        self.error_number = error_number if type(error_number) is int else None
        super().__init__(stage)


class Cancelled(BaseException):
    pass


def root_command(here):
    """Exact command after sudo's explicit root target and -- delimiter."""
    return ['/usr/bin/python3', '-I', '-c', BOOTSTRAP, str(here)]


"""Embedded bridge-side gate. ROOT_POLICY_PROBE is inserted from reviewed source."""
POLICY_LIMIT = 32768
POLICY_SECONDS = 12
ROOT_POLICY_PROBE = '"""Fixed, read-only root preflight; no credentials, writes or network access.\n\nThis file is embedded verbatim in the pinned ordinary-user bridge. Its strict\nsubset follows Apple\'s public files/sudoers sample and the installed manuals.\nUnknown configurations stop before a DDNS credential is collected.\n"""\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport signal\nimport stat\nimport subprocess\nimport sys\n\nENV = {\'PATH\': \'/usr/bin:/bin:/usr/sbin:/sbin\', \'LANG\': \'C\', \'LC_ALL\': \'C\'}\nLIMIT = 32768\n\n\nclass Rejected(Exception):\n    def __init__(self, code, line=None, digest=None):\n        self.code, self.line, self.digest = code, line, digest\n\n\ndef identity(info):\n    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,\n            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n\n\ndef no_acl(path):\n    try:\n        result = subprocess.run([\'/bin/ls\', \'-lde\', str(path)], stdin=subprocess.DEVNULL,\n            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, timeout=2, check=False)\n    except (OSError, subprocess.SubprocessError):\n        raise Rejected(\'metadata_unavailable\') from None\n    lines = result.stdout.splitlines()\n    if (result.returncode != 0 or result.stderr or len(result.stdout) > 2048\n            or len(lines) != 1 or not lines[0].split()\n            or b\'+\' in lines[0].split()[0]):\n        raise Rejected(\'acl_or_unknown_metadata\')\n\n\ndef safe(path, directory=False):\n    info = os.lstat(path)\n    expected_type = stat.S_ISDIR if directory else stat.S_ISREG\n    if (not expected_type(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022\n            or (not directory and info.st_nlink != 1)):\n        raise Rejected(\'unsafe_policy_metadata\')\n    no_acl(path)\n    if identity(os.lstat(path)) != identity(info):\n        raise Rejected(\'policy_changed_during_check\')\n    return info\n\n\ndef read_safe(path, optional=False):\n    try:\n        before = safe(path)\n    except FileNotFoundError:\n        if optional:\n            return None\n        raise\n    if before.st_size > LIMIT:\n        raise Rejected(\'policy_size_limit\')\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    with os.fdopen(fd, \'rb\') as handle:\n        if identity(os.fstat(handle.fileno())) != identity(before):\n            raise Rejected(\'policy_changed_during_check\')\n        data = handle.read(LIMIT + 1)\n        if (len(data) > LIMIT or identity(os.fstat(handle.fileno())) != identity(before)\n                or identity(os.lstat(path)) != identity(before)):\n            raise Rejected(\'policy_changed_during_check\')\n    try:\n        return data.decode(\'ascii\')\n    except UnicodeError:\n        raise Rejected(\'unknown_policy_encoding\') from None\n\n\nENV_NAMES = frozenset((\'BLOCKSIZE COLORFGBG COLORTERM __CF_USER_TEXT_ENCODING \'\n    \'CHARSET LANG LANGUAGE LC_ALL LC_COLLATE LC_CTYPE LC_MESSAGES LC_MONETARY \'\n    \'LC_NUMERIC LC_TIME LINES COLUMNS LSCOLORS SSH_AUTH_SOCK TZ DISPLAY \'\n    \'XAUTHORIZATION XAUTHORITY EDITOR VISUAL HOME MAIL\').split())\n\n\ndef policy_lines(text):\n    if len(text) > LIMIT or any(ord(c) < 32 and c not in \'\\n\\t\\r\' for c in text):\n        raise Rejected(\'unknown_policy_text\')\n    for number, raw in enumerate(text.splitlines(), 1):\n        line = raw.strip()\n        if not line:\n            continue\n        # These two hash-prefixed directives are NOT comments in sudoers.\n        # In a sudoers user position # followed by digits is a UID, not a\n        # comment. Never hide a numeric-user grant (or its LOG_INPUT tag).\n        if line.startswith((\'#include\', \'@include\')) or re.match(r\'#[+-]?[0-9]\', line):\n            yield number, line\n        elif not line.startswith(\'#\'):\n            yield number, line\n\n\ndef unknown(code, number, line):\n    raise Rejected(code, number, hashlib.sha256(line.encode(\'ascii\')).hexdigest())\n\n\ndef parse_sudoers(text):\n    grants, included, reset = set(), False, False\n    for number, line in policy_lines(text):\n        if re.search(r\'log[_-]?(?:input|stdin|ttyin)\', line, re.I):\n            unknown(\'input_logging_mentioned\', number, line)\n        if re.fullmatch(r\'(?:#|@)includedir\\s+/private/etc/sudoers\\.d\', line):\n            if included:\n                unknown(\'duplicate_policy_include\', number, line)\n            included = True\n            continue\n        grant = re.fullmatch(r\'(root|%admin)\\s+ALL\\s*=\\s*\\(ALL(?::ALL)?\\)\\s+ALL\', line)\n        if grant:\n            if grant[1] in grants:\n                unknown(\'duplicate_policy_grant\', number, line)\n            grants.add(grant[1])\n            continue\n        if re.fullmatch(r\'Defaults\\s+env_reset\', line):\n            reset = True\n            continue\n        if re.fullmatch(r\'Defaults\\s+!log_allowed\', line):\n            continue\n        if re.fullmatch(r\'Defaults\\s+lecture_file\\s*=\\s*"/etc/sudo_lecture"\', line):\n            continue\n        keep = re.fullmatch(r\'Defaults\\s+env_keep\\s*\\+=\\s*"([A-Za-z0-9_ ]+)"\', line)\n        if keep and set(keep[1].split()) and set(keep[1].split()) <= ENV_NAMES:\n            continue\n        if re.fullmatch(r\'Defaults\\s+secure_path\\s*=\\s*"/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"\', line):\n            continue\n        unknown(\'unsupported_sudoers_statement\', number, line)\n    if grants != {\'root\', \'%admin\'} or not reset:\n        raise Rejected(\'standard_admin_policy_not_confirmed\')\n    return {\'admin_all_rule\': True, \'dropin_directive\': included}\n\n\ndef parse_sudo_conf(text):\n    if text is None:\n        return \'absent_default_plugins\'\n    lines = list(policy_lines(text))\n    if not lines:\n        return \'empty_default_plugins\'\n    expected = {\'Plugin sudoers_policy sudoers.so\', \'Plugin sudoers_io sudoers.so\',\n                \'Plugin sudoers_audit sudoers.so\'}\n    actual = []\n    for number, line in lines:\n        canonical = \' \'.join(line.split())\n        if canonical not in expected or canonical in actual:\n            unknown(\'custom_sudo_configuration\', number, line)\n        actual.append(canonical)\n    if set(actual) != expected:\n        raise Rejected(\'incomplete_standard_plugins\')\n    return \'explicit_standard_plugins\'\n\n\ndef snapshot():\n    if os.geteuid() != 0 or sys.platform != \'darwin\':\n        raise Rejected(\'root_macos_required\')\n    for path in (\'/private\', \'/private/etc\'):\n        safe(path, directory=True)\n    # Default local sources only. Their presence requires a separate review;\n    # no LDAP/SSSD secret files or arbitrary configuration trees are opened.\n    for path in (\'/private/etc/nsswitch.conf\', \'/private/etc/ldap.conf\',\n                 \'/private/etc/sudo-ldap.conf\', \'/private/etc/sssd\'):\n        try:\n            os.lstat(path)\n        except FileNotFoundError:\n            pass\n        else:\n            raise Rejected(\'alternate_policy_source_present\')\n    sudoers = read_safe(\'/private/etc/sudoers\')\n    conf = read_safe(\'/private/etc/sudo.conf\', optional=True)\n    metadata = parse_sudoers(sudoers)\n    plugin_mode = parse_sudo_conf(conf)\n    dropin = \'/private/etc/sudoers.d\'\n    before = safe(dropin, directory=True)\n    if os.listdir(dropin):\n        raise Rejected(\'policy_dropin_directory_not_empty\')\n    if identity(os.lstat(dropin)) != identity(before):\n        raise Rejected(\'policy_changed_during_check\')\n    # Re-read the same fixed, bounded files to reject an observed concurrent edit.\n    if sudoers != read_safe(\'/private/etc/sudoers\') or conf != read_safe(\'/private/etc/sudo.conf\', optional=True):\n        raise Rejected(\'policy_changed_during_check\')\n    return {\'probe\': \'FAMILYVPN_SUDO_POLICY_V2\', \'safe\': True,\n        \'sudoers_sha256\': hashlib.sha256(sudoers.encode(\'ascii\')).hexdigest(),\n        \'sudo_conf_sha256\': None if conf is None else hashlib.sha256(conf.encode(\'ascii\')).hexdigest(),\n        \'plugin_mode\': plugin_mode, \'empty_dropin\': True,\n        \'source\': \'standard_local_files\', **metadata}\n\n\ndef deadline(_number, _frame):\n    raise Rejected(\'policy_probe_deadline\')\n\n\ndef main():\n    signal.signal(signal.SIGALRM, deadline)\n    signal.alarm(8)\n    try:\n        result = snapshot()\n    except Rejected as error:\n        result = {\'probe\': \'FAMILYVPN_SUDO_POLICY_V2\', \'safe\': False,\n                  \'reason\': error.code, \'line\': error.line, \'line_sha256\': error.digest}\n    except BaseException:\n        # Never output exception strings, file contents or command arguments.\n        result = {\'probe\': \'FAMILYVPN_SUDO_POLICY_V2\', \'safe\': False,\n                  \'reason\': \'policy_probe_unavailable\', \'line\': None, \'line_sha256\': None}\n    print(json.dumps(result, separators=(\',\', \':\')), flush=True)\n    return 0 if result.get(\'safe\') is True else 1\n\n\nif __name__ == \'__main__\':\n    raise SystemExit(main())\n'


class PolicyFailure(RuntimeError):
    def __init__(self, code, diagnostic):
        super().__init__(code)
        self.diagnostic = diagnostic


def version_known(text):
    lines = text.strip().splitlines()
    if len(lines) != 5:
        return False
    match = re.fullmatch(r'Sudo version (1\.9\.[0-9]+(?:p[0-9]+)?)', lines[0])
    if not match:
        return False
    version = match[1]
    return (lines[1] == 'Sudoers policy plugin version ' + version
        and re.fullmatch(r'Sudoers file grammar version [0-9]+', lines[2]) is not None
        and lines[3] == 'Sudoers I/O plugin version ' + version
        and lines[4] == 'Sudoers audit plugin version ' + version)


def bounded_policy_command(command, timeout=POLICY_SECONDS, popen=None):
    """Capture fixed no-secret checks with a byte cap and a monotonic deadline."""
    process, selector = None, selectors.DefaultSelector()
    output = [bytearray(), bytearray()]
    end = time.monotonic() + timeout
    try:
        process = (popen or subprocess.Popen)(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
        for number, stream in enumerate((process.stdout, process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, number)
        while selector.get_map():
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise PolicyFailure('policy_query_deadline', {})
            for key, _ in selector.select(min(remaining, 0.2)):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(block)
                if sum(map(len, output)) > POLICY_LIMIT:
                    raise PolicyFailure('policy_query_output_limit', {})
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise PolicyFailure('policy_query_deadline', {})
        process.wait(timeout=remaining)
        return process.returncode, bytes(output[0]), bytes(output[1])
    except (OSError, subprocess.SubprocessError):
        raise PolicyFailure('policy_query_unavailable', {}) from None
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
            # We do not assert that an interrupted privileged process was killed.
            # It has no credential and the fixed root probe has its own alarm.


def parse_root_policy(stdout):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    try:
        result = json.loads(stdout.decode('ascii'), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError):
        raise PolicyFailure('root_policy_response_unknown', {}) from None
    if not isinstance(result, dict) or result.get('probe') != 'FAMILYVPN_SUDO_POLICY_V2':
        raise PolicyFailure('root_policy_response_unknown', {})
    if result.get('safe') is False:
        if (set(result) != {'probe', 'safe', 'reason', 'line', 'line_sha256'}
                or not isinstance(result['reason'], str)
                or not re.fullmatch(r'[a-z_]{1,64}', result['reason'])
                or (result['line'] is not None and (type(result['line']) is not int or not 1 <= result['line'] <= 32768))
                or (result['line_sha256'] is not None and not re.fullmatch(r'[0-9a-f]{64}', str(result['line_sha256'])))):
            raise PolicyFailure('root_policy_response_unknown', {})
        raise PolicyFailure('root_policy_preflight_rejected', {'root_check': result})
    if (set(result) != {'probe', 'safe', 'sudoers_sha256', 'sudo_conf_sha256',
            'plugin_mode', 'empty_dropin', 'source', 'admin_all_rule', 'dropin_directive'}
            or result['safe'] is not True or result['empty_dropin'] is not True
            or result['admin_all_rule'] is not True or type(result['dropin_directive']) is not bool
            or result['source'] != 'standard_local_files'
            or result['plugin_mode'] not in {'absent_default_plugins', 'empty_default_plugins', 'explicit_standard_plugins'}
            or not re.fullmatch(r'[0-9a-f]{64}', str(result['sudoers_sha256']))
            or (result['sudo_conf_sha256'] is not None and not re.fullmatch(r'[0-9a-f]{64}', str(result['sudo_conf_sha256'])))):
        raise PolicyFailure('root_policy_response_unknown', {})
    return result


def policy_check(target_argv, *, runner=bounded_policy_command):
    target = list(target_argv)
    if (len(target) != 5 or target[:3] != ['/usr/bin/python3', '-I', '-c']
            or not all(isinstance(v, str) for v in target)
            or not 1 <= len(target[3]) <= 100000 or '\0' in ''.join(target)
            or not os.path.isabs(target[4]) or '\n' in target[4] or '\r' in target[4]):
        raise PolicyFailure('invalid_fixed_policy_target', {})
    # No credential has been collected. The target code is only hashed here;
    # actual authorization follows from root/%admin ALL with no other rules.
    diagnostic = {'stage': 'before_credential_input', 'target_code_sha256':
                  hashlib.sha256(target[3].encode('utf-8')).hexdigest(), 'queries': []}
    queries = [('version', ['/usr/bin/sudo', '-V']),
        ('root_local_policy', ['/usr/bin/sudo', '-n', '-u', 'root', '--',
                              '/usr/bin/python3', '-I', '-c', ROOT_POLICY_PROBE])]
    checked = None
    for kind, command in queries:
        try:
            status, stdout, stderr = runner(command)
        except PolicyFailure as error:
            raise PolicyFailure(str(error), diagnostic) from None
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes) or len(stdout) + len(stderr) > POLICY_LIMIT:
            raise PolicyFailure('policy_query_output_limit', diagnostic)
        diagnostic['queries'].append({'kind': kind, 'returncode': status,
            'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'stdout_bytes': len(stdout),
            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'stderr_bytes': len(stderr)})
        if stderr:
            raise PolicyFailure('policy_query_not_confirmed', diagnostic)
        if kind == 'version':
            try:
                valid = version_known(stdout.decode('ascii'))
            except UnicodeError:
                valid = False
            if status != 0 or not valid:
                raise PolicyFailure('ordinary_sudoers_plugin_not_confirmed', diagnostic)
        else:
            try:
                checked = parse_root_policy(stdout)
            except PolicyFailure as error:
                raise PolicyFailure(str(error), {**diagnostic, **error.diagnostic}) from None
            if status != 0:
                raise PolicyFailure('policy_query_not_confirmed', diagnostic)
    return {'result': 'standard_local_sudoers_no_input_logging', 'root_check': checked,
        'scope': 'Strict local sudoers subset at check time; excludes configured sudo input logging. '
                 'Does not exclude independent system auditing or later administrator changes.'}


def check_sudo_input_policy():
    try:
        result = policy_check(root_command(Path(__file__).resolve().parent))
    except PolicyFailure as error:
        print(json.dumps({'event': 'sudo_policy_check_failed',
            'diagnostic': error.diagnostic}, separators=(',', ':')), flush=True)
        raise BridgeFailure(str(error)) from None
    print(json.dumps({'event': 'sudo_policy_check_passed', **result}, separators=(',', ':')), flush=True)
    return result


PIPE_MARKER = b'FAMILYVPN_PIPE_PROBE_V1\n'
PIPE_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
PIPE_SECONDS = 10
PIPE_STAGE_TWO = r'''
import json,os,stat,sys
marker=b'FAMILYVPN_PIPE_PROBE_V1\n'
fifo=stat.S_ISFIFO(os.fstat(0).st_mode)
data=sys.stdin.buffer.read(len(marker)+1) if fifo else b''
print(json.dumps({'probe':'FAMILYVPN_PIPE_PROBE_V1','fifo':fifo,'marker_match':data==marker},separators=(',',':')),flush=True)
'''
# A real execve in the privileged chain, with fd 0 inherited unchanged. No shell.
PIPE_STAGE_ONE = (
    "import os\n"
    "os.execve('/usr/bin/python3', ['/usr/bin/python3','-I','-c', "
    + repr(PIPE_STAGE_TWO) + "], " + repr(PIPE_ENV) + ")\n"
)
PIPE_COMMAND = ['/usr/bin/sudo', '-n', '-u', 'root', '--',
                '/usr/bin/python3', '-I', '-c', PIPE_STAGE_ONE]
PIPE_EXPECTED = b'{"probe":"FAMILYVPN_PIPE_PROBE_V1","fifo":true,"marker_match":true}\n'


class PipeProbeFailure(Exception):
    def __init__(self, stage, error_number=None):
        self.stage = stage
        self.error_number = error_number if type(error_number) is int else None
        super().__init__(stage)


def _probe_close(process):
    if process is None:
        return
    for stream in (process.stdin, process.stdout, process.stderr):
        try:
            if stream is not None:
                stream.close()
        except (OSError, ValueError):
            pass


def admin_pipe_probe(popen=None):
    """Return a verified fixed result. No retries, credentials or raw output logs.

    A timeout closes our pipe endpoints and fails before password input. It does
    not assert that a privileged descendant was killed or finished.
    """
    process = None
    started = time.monotonic()
    try:
        process = (popen or subprocess.Popen)(list(PIPE_COMMAND), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=PIPE_ENV)
        remaining = PIPE_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(PIPE_COMMAND, PIPE_SECONDS)
        stdout, stderr = process.communicate(input=PIPE_MARKER, timeout=remaining)
    except subprocess.TimeoutExpired:
        _probe_close(process)
        raise PipeProbeFailure('administrator_pipe_probe_timeout') from None
    except OSError as error:
        _probe_close(process)
        raise PipeProbeFailure('administrator_pipe_probe_unavailable', error.errno) from None
    except BaseException:
        # Includes the enclosing bridge's signal exception; never log its value.
        _probe_close(process)
        raise
    if process.returncode != 0 or stderr != b'' or stdout != PIPE_EXPECTED:
        raise PipeProbeFailure('administrator_pipe_probe_not_confirmed')
    return {'probe': 'FAMILYVPN_PIPE_PROBE_V1', 'fifo': True, 'marker_match': True}


def check_admin_pipe():
    try:
        result = admin_pipe_probe()
    except PipeProbeFailure as error:
        raise BridgeFailure(error.stage, error.error_number) from None
    print(json.dumps({'event': 'administrator_pipe_probe_passed', **result},
                     separators=(',', ':')), flush=True)
    return result


def tty_available():
    try:
        return os.isatty(0)
    except OSError:
        return False


def valid_password(value):
    return isinstance(value, str) and 1 <= len(value) <= 1024 and all(
        32 <= ord(char) <= 126 for char in value)


def collect_password():
    # A pipe must never become an echoing fallback input stream.
    if not tty_available():
        raise BridgeFailure('stdin_not_tty')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            first = getpass.getpass('New Dynadot DDNS password (hidden): ')
            second = getpass.getpass('Repeat new Dynadot DDNS password (hidden): ')
    except (OSError, EOFError, getpass.GetPassWarning, termios.error) as error:
        raise BridgeFailure('hidden_input_unavailable', getattr(error, 'errno', None)) from None
    if first != second:
        raise BridgeFailure('password_confirmation_mismatch')
    if not valid_password(first):
        raise BridgeFailure('password_format_rejected')
    return first


def close_input(process):
    # This closes only our pipe endpoint. It does not claim to stop root work.
    try:
        if process.stdin is not None:
            process.stdin.close()
    except (OSError, ValueError):
        pass


def handoff(password, here, popen=None):
    if not valid_password(password):
        raise BridgeFailure('password_format_rejected')
    if not re.fullmatch(r'[0-9a-f]{64}', INSTALLER_SHA):
        raise BridgeFailure('unbuilt_template')
    payload = json.dumps({'password': password}, ensure_ascii=True,
                         separators=(',', ':')).encode('ascii') + b'\n'
    command = ['/usr/bin/sudo', '-n', '-u', 'root', '--'] + root_command(here)
    process = None
    try:
        process = (popen or subprocess.Popen)(command, stdin=subprocess.PIPE, env=ENV)
        process.communicate(input=payload, timeout=HANDOFF_SECONDS)
    except (subprocess.TimeoutExpired, KeyboardInterrupt, Cancelled):
        if process is not None:
            close_input(process)
        raise BridgeFailure('administrator_completion_unconfirmed') from None
    except OSError as error:
        if process is not None:
            close_input(process)
        stage = 'administrator_start_failed' if process is None else 'administrator_completion_unconfirmed'
        raise BridgeFailure(stage, error.errno) from None
    if process.returncode != 0:
        raise BridgeFailure('administrator_reported_failure')


def diagnostic(error):
    # Never print an exception string, subprocess arguments, input, or credential.
    print(json.dumps({'stage': error.stage, 'isatty': tty_available(),
                      'errno': error.error_number}, separators=(',', ':')), flush=True)


def cancel_signal(_number, _frame):
    raise Cancelled()


def main():
    try:
        if len(sys.argv) != 1:
            raise BridgeFailure('unexpected_arguments')
        if os.geteuid() == 0:
            raise BridgeFailure('ordinary_user_required')
        if not tty_available():
            raise BridgeFailure('stdin_not_tty')
        if not re.fullmatch(r'[0-9a-f]{64}', INSTALLER_SHA):
            raise BridgeFailure('unbuilt_template')
        check_sudo_input_policy()
        check_admin_pipe()
        password = collect_password()
        try:
            handoff(password, Path(__file__).resolve().parent)
        finally:
            # Python strings are not promised to be securely erased from memory.
            password = None
        return 0
    except (KeyboardInterrupt, Cancelled):
        diagnostic(BridgeFailure('input_cancelled'))
        return 130
    except BridgeFailure as error:
        diagnostic(error)
        return 1


if __name__ == '__main__':
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, cancel_signal)
    sys.exit(main())
