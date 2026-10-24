#!/usr/bin/python3
"""Fixed vpn.example.com IPv4 DDNS candidate; no installation on import."""
import argparse
import contextlib
import datetime as dt
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode

BASE = Path('/usr/local/family-vpn/dynadot-ddns')
CONFIG = Path('/usr/local/etc/family-vpn/dynadot-ddns.json')
STATE = Path('/private/var/db/family-vpn/dynadot-ddns')
DOMAIN, HOST, FQDN = 'example.com', 'vpn', 'vpn.example.com.'
NAMESERVERS = ('ns1.dyna-ns.net', 'ns2.dyna-ns.net')
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'}


class Failure(Exception):
    """Only fixed safe codes; never embed command arguments or responses."""


class Budget:
    def __init__(self, seconds=100):
        self.end = time.monotonic() + seconds

    def run(self, args, *, input_bytes=None, timeout=8, discard_error=False):
        left = self.end - time.monotonic()
        if left <= 0:
            raise Failure('run_deadline')
        try:
            p = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL if discard_error else subprocess.PIPE,
                env=ENV, timeout=min(timeout, left))
        except (OSError, subprocess.SubprocessError):
            raise Failure('command_unavailable_or_timeout') from None
        if len(p.stdout) > 65536 or (p.stderr and len(p.stderr) > 65536):
            raise Failure('response_limit')
        return p


def say(event, **metadata):
    print(json.dumps(dict(time=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
                         event=event, **metadata), sort_keys=True), flush=True)


def public4(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise Failure('invalid_public_ipv4') from None
    if (ip.version != 4 or not ip.is_global or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or ip.is_loopback or ip.is_link_local):
        raise Failure('invalid_public_ipv4')
    return str(ip)


def trusted(path, *, directory=False, private=False):
    path = Path(path)
    for item in (path, *path.parents):
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise Failure('untrusted_privileged_path')
        if item != path and not stat.S_ISDIR(s.st_mode):
            raise Failure('invalid_path_ancestor')
        p = Budget(4).run(['/bin/ls', '-lde', str(item)], timeout=3)
        if p.returncode or len(p.stdout.splitlines()) != 1:
            raise Failure('privileged_path_acl')
    s = path.lstat()
    if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise Failure('invalid_path_type')
    if private and stat.S_IMODE(s.st_mode) != (0o700 if directory else 0o600):
        raise Failure('private_path_mode')


def read_json(path):
    trusted(path, private=True)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        raw = f.read(8193)
    if len(raw) > 8192:
        raise Failure('metadata_limit')
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Failure('invalid_metadata') from None
    if not isinstance(result, dict):
        raise Failure('invalid_metadata')
    return result


def atomic(path, data):
    trusted(path.parent, directory=True, private=True)
    if path.exists() or path.is_symlink():
        trusted(path, private=True)
    temp = path.with_name(path.name + '.new.' + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temp.exists():
            temp.unlink()


def password_valid(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(not 32 <= ord(c) <= 126 for c in value):
        raise Failure('invalid_ddns_password_format')
    return value


def load_password():
    cfg = read_json(CONFIG)
    if set(cfg) != {'version', 'domain', 'subdomain', 'password'} or cfg['version'] != 1 or cfg['domain'] != DOMAIN or cfg['subdomain'] != HOST:
        raise Failure('unexpected_fixed_configuration')
    return password_valid(cfg['password'])


def ask_password():
    # The ordinary-user credential bridge owns hidden TTY input. Privileged
    # code only consumes a bounded JSON message from its inherited pipe.
    fd = sys.stdin.fileno()
    if not stat.S_ISFIFO(os.fstat(fd).st_mode):
        raise Failure('credential_pipe_required')
    deadline = time.monotonic() + 10
    raw = bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise Failure('credential_pipe_timeout')
        chunk = os.read(fd, min(1024, 4097 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > 4096:
            raise Failure('credential_pipe_limit')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Failure('credential_pipe_schema')
            result[key] = value
        return result
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError):
        raise Failure('credential_pipe_schema') from None
    finally:
        for index in range(len(raw)):
            raw[index] = 0
    if not isinstance(data, dict) or set(data) != {'password'}:
        raise Failure('credential_pipe_schema')
    return password_valid(data['password'])


def curl(budget, url, *, discard_body=False):
    # Every URL travels only in an anonymous stdin pipe. No URL/password in argv,
    # environment, disk config, diagnostics, shell, redirect or proxy request.
    if not url.startswith('https://') or any(c in url for c in '\r\n"\\'):
        raise Failure('unsafe_internal_url')
    args = ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--ipv4',
        '--interface', 'en0', '--noproxy', '*', '--proxy', '', '--proto', '=https',
        '--proto-redir', '=https', '--max-redirs', '0', '--tlsv1.2',
        '--connect-timeout', '4', '--max-time', '7', '--max-filesize', '16384',
        '--request', 'GET', '--write-out', '\n%{http_code}', '--config', '-']
    if discard_body:
        args += ['--output', '/dev/null']
    p = budget.run(args, input_bytes=('url = "' + url + '"\n').encode('ascii'),
                   timeout=8, discard_error=True)
    body, separator, status = p.stdout.rpartition(b'\n')
    if not separator or not re.fullmatch(rb'[0-9]{3}', status):
        raise Failure('invalid_http_status')
    return p.returncode, int(status), b'' if discard_body else body


def ethernet_address(budget):
    p = budget.run(['/sbin/ifconfig', 'en0'], timeout=3)
    try:
        text = p.stdout.decode('ascii')
    except UnicodeError:
        raise Failure('ethernet_inventory') from None
    values = re.findall(r'^\s+inet ([0-9.]+) netmask ', text, re.M)
    if p.returncode or len(values) != 1 or not re.search(r'^\s+status: active$', text, re.M):
        raise Failure('ethernet_not_active_single_ipv4')
    try:
        ip = ipaddress.IPv4Address(values[0])
    except ValueError:
        raise Failure('ethernet_invalid_ipv4') from None
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise Failure('ethernet_invalid_ipv4')
    return str(ip)


def observed_ipv4(budget):
    cloudflare = None
    for url in ('https://www.cloudflare.com/cdn-cgi/trace', 'https://1.1.1.1/cdn-cgi/trace'):
        try:
            code, status, body = curl(budget, url)
            if code or status != 200:
                continue
            values = re.findall(r'^ip=([^\r\n]+)$', body.decode('ascii'), re.M)
            if len(values) == 1:
                cloudflare = public4(values[0])
                break
        except (Failure, UnicodeError):
            continue
    if cloudflare is None:
        raise Failure('public_ipv4_cloudflare_unverified')
    code, status, body = curl(budget, 'https://checkip.amazonaws.com/')
    if code or status != 200:
        raise Failure('public_ipv4_aws_unverified')
    try:
        aws = public4(body.decode('ascii').strip())
    except UnicodeError:
        raise Failure('public_ipv4_aws_unverified') from None
    if aws != cloudflare:
        raise Failure('public_ipv4_sources_disagree')
    return cloudflare


def parse_dns(text, name, kind, authoritative=True):
    statuses = re.findall(r'^;; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+), id: [0-9]+$', text, re.M)
    flags = re.findall(r'^;; flags: ([a-z ]+); QUERY: ([0-9]+), ANSWER: ([0-9]+), AUTHORITY: [0-9]+, ADDITIONAL: [0-9]+$', text, re.M)
    if statuses != ['NOERROR'] or len(flags) != 1 or flags[0][1] != '1':
        raise Failure('dns_invalid_response')
    flagset = set(flags[0][0].split())
    if 'qr' not in flagset or 'tc' in flagset:
        raise Failure('dns_invalid_response')
    if authoritative and 'aa' not in flagset:
        raise Failure('dns_not_authoritative')
    records = []
    for line in text.splitlines():
        if not line or line.startswith(';'):
            continue
        parts = line.split()
        if len(parts) != 5 or parts[0].lower() != name or not parts[1].isdigit() or parts[2] != 'IN' or parts[3] != kind:
            raise Failure('dns_unexpected_record_or_alias')
        records.append((int(parts[1]), parts[4].lower()))
    if len(records) != int(flags[0][2]):
        raise Failure('dns_answer_count')
    return records


def query(budget, local, name, kind, server=None):
    args = ['/usr/bin/dig', '-4', '-b', local, '+time=2', '+tries=1', '+noall', '+comments', '+answer']
    if server:
        # Resolve fixed NS names separately; dig must not perform an implicit
        # hostname lookup with its own unbound/default resolver path.
        args += ['+norecurse', '@' + public4(server)]
    args += [name, kind]
    p = budget.run(args, timeout=4)
    if p.returncode:
        raise Failure('dns_query_failed')
    try:
        return parse_dns(p.stdout.decode('ascii'), name, kind, bool(server))
    except UnicodeError:
        raise Failure('dns_invalid_response') from None


def doh_records(budget, name, kind):
    if (name, kind) not in {(DOMAIN + '.', 'NS'), *((ns + '.', 'A') for ns in NAMESERVERS)}:
        raise Failure('unexpected_dns_resolution_target')
    url = 'https://dns.google/resolve?' + urlencode(dict(name=name, type=kind,
        edns_client_subnet='0.0.0.0/0'))
    code, status, body = curl(budget, url)
    if code or status != 200:
        raise Failure('dns_https_resolution_failed')
    try:
        obj = json.loads(body)
        number = {'A': 1, 'NS': 2}[kind]
        if (not isinstance(obj, dict) or type(obj.get('Status')) is not int or obj['Status'] != 0
                or obj.get('TC') is not False or obj.get('CD') is not False
                or obj.get('Question') != [dict(name=name, type=number)]
                or not isinstance(obj.get('Answer'), list) or not 1 <= len(obj['Answer']) <= 4):
            raise ValueError()
        records = []
        for row in obj['Answer']:
            if (not isinstance(row, dict) or row.get('name', '').lower() != name
                    or type(row.get('type')) is not int or row['type'] != number
                    or type(row.get('TTL')) is not int or not 0 <= row['TTL'] < 2**31
                    or not isinstance(row.get('data'), str)):
                raise ValueError()
            records.append((row['TTL'], row['data'].lower()))
        return records
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
        raise Failure('dns_https_resolution_invalid') from None


def recursive_records(budget, local, name, kind):
    try:
        return query(budget, local, name, kind)
    except Failure as error:
        # Semantic DNS errors/aliases are not silently replaced with a more
        # convenient answer; only the unavailable resolver path may fall back.
        if str(error) not in ('dns_query_failed', 'command_unavailable_or_timeout'):
            raise
        return doh_records(budget, name, kind)


def dns_state(budget, local):
    delegation = recursive_records(budget, local, DOMAIN + '.', 'NS')
    if len(delegation) != 2 or {r[1] for r in delegation} != {n + '.' for n in NAMESERVERS}:
        raise Failure('dns_provider_changed')
    results = []
    for ns in NAMESERVERS:
        addresses = recursive_records(budget, local, ns + '.', 'A')
        if not 1 <= len(addresses) <= 4:
            raise Failure('dns_nameserver_addresses_invalid')
        addresses = sorted({public4(value) for ttl, value in addresses})
        result = None
        for address in addresses[:2]:
            try:
                a = query(budget, local, FQDN, 'A', address)
                aaaa = query(budget, local, FQDN, 'AAAA', address)
            except Failure as error:
                if str(error) in ('dns_query_failed', 'command_unavailable_or_timeout'):
                    continue
                raise
            if len(a) != 1 or aaaa:
                raise Failure('dns_requires_exact_existing_a_and_empty_aaaa')
            result = (public4(a[0][1]), a[0][0])
            break
        if result is None:
            raise Failure('dns_nameserver_unreachable')
        results.append(result)
    if results[0] != results[1]:
        raise Failure('authoritative_servers_disagree')
    return results[0]


def update_url(ip, password):
    return 'https://www.dynadot.com/set_ddns?' + urlencode(dict(domain=DOMAIN,
        subDomain=HOST, containRoot='false', type='A', ttl='300', ip=public4(ip),
        pwd=password_valid(password)))


API_JSON_MAX_DEPTH = 32


def api_json_depth_ok(value):
    """Bound container nesting independently of Python's JSON recursion limit.

    The caller also bounds response length. Use an explicit stack so neither
    this check nor its result depends on the interpreter's recursion threshold.
    Strings (including escaped brackets) are scalar values, not containers.
    """
    pending = [(value, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if type(item) not in (dict, list):
            continue
        depth = parent_depth + 1
        if depth > API_JSON_MAX_DEPTH:
            return False
        children = item.values() if type(item) is dict else item
        pending.extend((child, depth) for child in children
                       if type(child) in (dict, list))
    return True


def api_response_shape(body):
    """Fixed metadata only, independent of acknowledgement/credential decisions.

    Response text, unknown key names and arbitrary values may reflect a secret.
    Never export them, their lengths, hashes, snippets or exception messages.
    """
    result = {'parse': 'unavailable', 'root_type': 'unavailable',
              'known_fields_complete': None, 'extra_fields_present': None,
              'status_present': None, 'status_type': 'unavailable', 'status_class': 'unavailable',
              'error_code_present': None, 'error_code_type': 'unavailable', 'error_code_class': 'unavailable',
              'content_present': None, 'content_type': 'unavailable', 'content_strings_only': None}
    if not isinstance(body, (bytes, str)):
        result['parse'] = 'input_type_rejected'
        return result
    if len(body) > 16384:
        result['parse'] = 'body_limit'
        return result
    class DuplicateKey(Exception):
        pass
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise DuplicateKey()
            value[key] = item
        return value
    def reject_constant(_value):
        raise ValueError()
    def typename(value):
        return {type(None): 'null', bool: 'boolean', int: 'integer', float: 'number',
                str: 'string', list: 'array', dict: 'object'}.get(type(value), 'unknown')
    try:
        obj = json.loads(body, object_pairs_hook=unique, parse_constant=reject_constant)
        if not api_json_depth_ok(obj):
            raise ValueError()
    except DuplicateKey:
        result['parse'] = 'duplicate_keys'
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError):
        result['parse'] = 'invalid_json'
        return result
    result['parse'], result['root_type'] = 'parsed', typename(obj)
    if not isinstance(obj, dict):
        return result
    known = {'status', 'error_code', 'content'}
    result['known_fields_complete'] = known <= set(obj)
    result['extra_fields_present'] = bool(set(obj) - known)
    for name in ('status', 'error_code', 'content'):
        result[name + '_present'] = name in obj
        result[name + '_type'] = typename(obj[name]) if name in obj else 'missing'
    status = obj.get('status')
    result['status_class'] = ('missing' if 'status' not in obj else
        {'success': 'success_literal', 'error': 'error_literal'}.get(status, 'other_string')
        if type(status) is str else 'non_string')
    code = obj.get('error_code')
    if 'error_code' not in obj:
        result['error_code_class'] = 'missing'
    elif type(code) is int:
        result['error_code_class'] = {-1: 'minus_one', 0: 'zero'}.get(code, 'other_integer')
    elif type(code) is str:
        result['error_code_class'] = {'-1': 'string_minus_one', '0': 'string_zero'}.get(code, 'other_string')
    else:
        result['error_code_class'] = 'non_integer'
    if type(obj.get('content')) is list:
        result['content_strings_only'] = all(type(item) is str for item in obj['content'])
    return result


def api_result(body):
    # A direct success report for /set_ddns contains only {"status":"success"}:
    # https://github.com/ddclient/ddclient/issues/970 (2026-09-06).
    # Accept only that exact object or the known three-field response with
    # explicit success and integer zero. Neither partial/extra fields nor plain
    # text are acknowledgements. This is still followed by authoritative DNS.
    # The potentially sensitive status/content text never leaves this function.
    if not isinstance(body, (bytes, str)) or len(body) > 16384:
        return 'unknown'
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate')
            result[key] = value
        return result
    try:
        obj = json.loads(body, object_pairs_hook=unique)
        if not api_json_depth_ok(obj):
            return 'unknown'
        if isinstance(obj, dict) and set(obj) == {'status'}:
            return 'acknowledged' if obj['status'] == 'success' else 'unknown'
        if (not isinstance(obj, dict) or set(obj) != {'status', 'error_code', 'content'}
                or not isinstance(obj['status'], str)
                or type(obj['error_code']) is not int
                or not isinstance(obj['content'], list)
                or any(not isinstance(item, str) for item in obj['content'])):
            return 'unknown'
        if obj['error_code'] == -1:
            return 'rejected'
        return 'acknowledged' if obj['status'] == 'success' and obj['error_code'] == 0 else 'unknown'
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return 'unknown'


def update_once(budget, password, *, read_state, save_state, pause=time.sleep, configure=False):
    local = ethernet_address(budget)
    target = observed_ipv4(budget)
    before = dns_state(budget, local)
    if ethernet_address(budget) != local:
        raise Failure('ethernet_address_changed')
    if configure and before != (target, 300):
        raise Failure('initial_dns_not_already_ready')
    if not configure and before == (target, 300):
        say('already_current', hostname=FQDN[:-1], ipv4=target, aaaa='empty')
        return
    previous = read_state()
    if previous and (set(previous) != {'version', 'last_attempt', 'ipv4', 'outcome'} or previous['version'] != 1
                     or type(previous['last_attempt']) not in (int, float)
                     or not math.isfinite(previous['last_attempt']) or previous['last_attempt'] < 0
                     or previous['outcome'] not in ('attempted', 'verified', 'unconfirmed')):
        raise Failure('invalid_attempt_state')
    if previous:
        public4(previous['ipv4'])
    moment = time.time()
    if previous:
        elapsed = moment - previous['last_attempt']
        if elapsed < -5:
            # The outer scheduler also rebases after a wall-clock rollback,
            # but its status cannot reset this helper's separate cooldown.
            # Retain the address but do not present the rebased clock as a
            # successful request. Require a full new 300-second cooldown before
            # another request; the original four-field format stays readable.
            save_state(dict(previous, last_attempt=moment, outcome='unconfirmed'))
            raise Failure('update_retry_clock_reset')
        if elapsed < 300:
            raise Failure('update_retry_cooldown')
    record = dict(version=1, last_attempt=moment, ipv4=target, outcome='attempted')
    save_state(record)  # Write-ahead timestamp; prevents immediate retry after ambiguity.
    http_code, transport_code, response = None, None, 'unknown'
    try:
        transport_code, http_code, body = curl(budget, update_url(target, password))
        if transport_code == 0 and http_code == 200:
            say('api_response_shape', **api_response_shape(body))
            response = api_result(body)
    except Failure:
        pass  # A timed-out request may have reached Dynadot; only DNS can confirm.
    for attempt in range(3):
        if attempt:
            pause(2)
        try:
            if ethernet_address(budget) != local:
                break
            after = dns_state(budget, local)
            if after == (target, 300):
                if response != 'acknowledged':
                    record['outcome'] = 'unconfirmed'
                    save_state(record)
                    say('dns_correct_api_not_verified', api_result=response,
                        http_status=http_code, curl_code=transport_code)
                    raise Failure('api_not_verified_no_credential_saved' if configure else 'api_not_verified')
                record['outcome'] = 'verified'
                save_state(record)
                say('dns_update_verified', hostname=FQDN[:-1], ipv4=target, ttl=300,
                    aaaa='empty', http_status=http_code, curl_code=transport_code)
                return
        except Failure as error:
            if str(error) in ('api_not_verified_no_credential_saved', 'api_not_verified'):
                raise
            continue
    record['outcome'] = 'unconfirmed'
    save_state(record)
    raise Failure('dns_update_unconfirmed_no_rollback')


@contextlib.contextmanager
def locked():
    trusted(STATE.parent, directory=True, private=True)
    try:
        STATE.mkdir(mode=0o700)
    except FileExistsError:
        pass
    trusted(STATE, directory=True, private=True)
    path = STATE / 'lock'
    if path.exists() or path.is_symlink():
        trusted(path, private=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        trusted(path, private=True)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['update', 'configure-once'])
    args = p.parse_args()
    if os.geteuid() != 0 or Path(__file__).absolute() != BASE / 'update.py':
        raise Failure('fixed_root_installation_required')
    os.umask(0o077)
    trusted(BASE, directory=True, private=True)
    trusted(Path(__file__), private=True)
    trusted(CONFIG.parent, directory=True, private=True)
    with locked():
        password = ask_password() if args.action == 'configure-once' else load_password()
        state = STATE / 'attempt.json'
        update_once(Budget(), password,
            read_state=lambda: read_json(state) if state.exists() else {},
            save_state=lambda data: atomic(state, data), configure=args.action == 'configure-once')
        if args.action == 'configure-once':
            atomic(CONFIG, dict(version=1, domain=DOMAIN, subdomain=HOST, password=password))
            say('credential_verified_and_saved_scheduler_not_installed')


if __name__ == '__main__':
    try:
        main()
    except Failure as error:
        say('failed', code=str(error))
        sys.exit(1)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        say('failed', code='local_configuration_or_io_failure')
        sys.exit(1)
    except KeyboardInterrupt:
        say('cancelled', code='operator_interrupt')
        sys.exit(130)
