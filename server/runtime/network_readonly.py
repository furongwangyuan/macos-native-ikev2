"""Extracted reviewed functions; import performs no native operation."""
import concurrent.futures
import ipaddress
import re
import subprocess
from native_support import run as command, Refused as Failure, say
WAN='en0'
POOL4='10.77.26.0/24'
POOL6='fd6d:fe83:ab27:2600::/64'
LOCAL_KEYS={'inet_gateway','inet6_gateway','lan4','stable6'}
class UplinkNotReady(Failure):
    """Only identified absence/transient transport failure, never invalid scope."""
    pass

WAIT_CODES=frozenset({'uplink_local_not_ready','uplink_external_not_ready'})
def log(_): say('uplink_preflight_progress')


def local_parameters(value):
    """Fixed, unambiguous en0 dual-stack scope; metadata is not liveness proof."""
    if type(value)is not dict or set(value)!=LOCAL_KEYS or any(type(x)is not str for x in value.values()):
        raise Failure('Unknown local uplink shape')
    try:
        lan=ipaddress.IPv4Address(value['lan4']);gw4=ipaddress.IPv4Address(value['inet_gateway'])
        stable=ipaddress.IPv6Address(value['stable6'])
        gateway,sep,zone=value['inet6_gateway'].partition('%');gw6=ipaddress.IPv6Address(gateway)
    except ValueError as error:raise Failure('Unknown local uplink address') from error
    if (str(lan)!=value['lan4'] or str(gw4)!=value['inet_gateway'] or str(lan)!='192.0.2.8'
            or str(stable)!=value['stable6'] or not stable.is_global or stable.is_multicast
            or stable.scope_id is not None or str(gw6)!=gateway or gw6.scope_id is not None
            or (gw6.is_link_local and (not sep or zone!=WAN))
            or (not gw6.is_link_local and (sep or not gw6.is_global))
            or any(a.is_multicast or a.is_unspecified or a.is_loopback or a.is_reserved for a in (gw4,gw6))):
        raise Failure('Local uplink outside fixed valid scope')
    return dict(value)


def known_change(before,after):
    """Only a change between an established external-verified data baseline
    and a newly read complete valid local sample. No external network I/O.
    """
    if type(before)is not dict or set(before)!=LOCAL_KEYS|{'public4','public6_probe'}:
        raise Failure('Established dual-stack baseline missing')
    previous=local_parameters({k:before[k] for k in LOCAL_KEYS});current=local_parameters(after)
    for key,version in [('public4',4),('public6_probe',6)]:
        if type(before[key])is not str:raise Failure('Invalid established probe address')
        try:addr=ipaddress.ip_address(before[key])
        except ValueError as error:raise Failure('Invalid established probe address') from error
        if (str(addr)!=before[key] or addr.version!=version or not addr.is_global or addr.is_multicast
                or getattr(addr,'scope_id',None) is not None):
            raise Failure('Invalid established probe address')
    if ipaddress.ip_address(before['public6_probe']) not in ipaddress.ip_network(previous['stable6']+'/64',strict=False):
        raise Failure('Established probe prefix differs')
    return previous!=current


def read_routes():
    return {family: command(['/usr/sbin/netstat', '-rn', '-f', family]).stdout
            for family in ['inet', 'inet6']}

def conflict_check(routes):
    pools = [ipaddress.ip_network(POOL4), ipaddress.ip_network(POOL6)]
    for family, text in routes.items():
        for line in text.splitlines():
            cols = line.split()
            if not cols or cols[0] in ['default', 'Destination']:
                continue
            value = cols[0].split('%')[0]
            try:
                if family == 'inet':
                    a, sep, prefix = value.partition('/')
                    parts = a.split('.')
                    if len(parts) < 4:
                        value = '.'.join(parts + ['0'] * (4 - len(parts))) + '/' + (prefix if sep else str(8 * len(parts)))
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            for pool in pools:
                if net.version == pool.version and net.overlaps(pool):
                    raise Failure('Existing non-default route overlaps VPN pool: ' + line)

def trace(family):
    if type(family) is not int or family not in (4, 6):
        raise Failure('Uplink probe requires IPv4 or IPv6')
    # Startup only: two fixed, independently TLS-verified endpoints. A transient
    # resolver/edge failure must not cause an opaque failure, but neither family
    # may be skipped. No proxies, redirects, curl config, or raw response logging.
    numeric = '1.1.1.1' if family == 4 else '[2606:4700:4700::1111]'
    endpoints = [('domain', 'https://www.cloudflare.com/cdn-cgi/trace'),
                 ('numeric', 'https://' + numeric + '/cdn-cgi/trace')]
    failures = []
    transient = True
    reasons = {6: 'name_resolution', 7: 'connect', 22: 'http_status',
               28: 'timeout', 35: 'tls_handshake', 51: 'tls_identity',
               60: 'tls_certificate', 77: 'tls_trust_store'}
    for attempt, (label, url) in enumerate(endpoints, 1):
        log(f'Uplink IPv{family} preflight attempt {attempt}/2 ({label})')
        try:
            p = command(['/usr/bin/curl', '--disable', '--fail', '--silent', '--show-error',
                         '--noproxy', '*', '--connect-timeout', '4', '--max-time', '7',
                         '--interface', WAN, '-' + str(family), url], check=False, timeout=8)
        except subprocess.TimeoutExpired:
            reason = 'process_timeout'
            transient = False
        except (OSError, UnicodeError):
            reason = 'execution_or_encoding_error'
            transient = False
        else:
            if p.returncode:
                reason = f'curl_exit_{p.returncode}_{reasons.get(p.returncode, "curl_error")}'
                transient = transient and p.returncode in (6, 7, 28)
            else:
                values = [line[3:] for line in p.stdout.splitlines() if line.startswith('ip=')]
                try:
                    addr = ipaddress.ip_address(values[0]) if len(values) == 1 else None
                except ValueError:
                    addr = None
                if (addr is not None and addr.version == family and addr.is_global
                        and not addr.is_multicast and not addr.is_reserved
                        and not addr.is_unspecified and getattr(addr, 'scope_id', None) is None):
                    log(f'Uplink IPv{family} preflight passed on attempt {attempt}/2 ({label})')
                    return str(addr)
                reason = 'invalid_public_address_response'
                transient = False
        failures.append(f'{label}:{reason}')
        log(f'Uplink IPv{family} preflight attempt {attempt}/2 failed: {reason}')
    if transient:
        raise UplinkNotReady('uplink_external_not_ready')
    raise Failure(f'Uplink IPv{family} preflight failed after 2 bounded attempts: ' + ', '.join(failures))

def uplink(external=True):
    details = {}
    missing = False
    for family, flag in [('inet', '-inet'), ('inet6', '-inet6')]:
        observed = command(['/sbin/route', '-n', 'get', flag, 'default'], check=False)
        # Apple route's GET path exits 0 even for ESRCH. Accept only this exact
        # empty-stdout diagnostic; command failure alone is never temporary.
        if (observed.returncode == 0 and observed.stdout == '' and
                observed.stderr == 'route: writing to routing socket: not in table\n'):
            missing = True
            continue
        if observed.returncode or observed.stderr:
            raise Failure('uplink_route_query_failed')
        text = observed.stdout
        match = re.findall(r'^\s*interface:\s*(\S+)\s*$', text, re.M)
        gateway = re.findall(r'^\s*gateway:\s*(\S+)\s*$', text, re.M)
        if match != [WAN] or len(gateway)!=1:
            raise Failure(f'{family} default route is not the Ethernet uplink')
        value, sep, zone = gateway[0].partition('%')
        address = ipaddress.ip_address(value)
        if (address.version != (4 if family == 'inet' else 6) or str(address) != value
                or address.is_multicast or address.is_unspecified or address.is_loopback or address.is_reserved
                or (family == 'inet' and sep)
                or (family == 'inet6' and ((address.is_link_local and (not sep or zone != WAN))
                    or (not address.is_link_local and (sep or not address.is_global))))):
            raise Failure('Local uplink outside fixed valid scope')
        details[family + '_gateway'] = gateway[0]
    info = command(['/sbin/ifconfig', WAN]).stdout
    status = re.findall(r'^\s*status:\s*(\S+)\s*$',info,re.M)
    if status == ['inactive']:
        missing = True
    elif status != ['active']:
        raise Failure('uplink_interface_status_unknown')
    v4 = re.findall(r'^\s*inet (\S+)', info, re.M)
    v6 = []
    unusable6 = False
    for line in info.splitlines():
        if re.search(r'\binet6\b', line) and re.search(r'\b(duplicated|detached)\b', line):
            unusable6 = True
        if re.search(r'\binet6\b', line) and not re.search(r'\b(temporary|deprecated|tentative|duplicated|detached)\b', line):
            candidate = line.split()[1]
            address = ipaddress.ip_address(candidate)
            if address.is_global:
                if (address.version != 6 or str(address) != candidate or address.is_multicast
                        or address.scope_id is not None):
                    raise Failure('Unknown local uplink address')
                if re.findall(r'\bprefixlen (\d+)\b',line)!=['64']:
                    raise Failure('Stable Ethernet IPv6 prefix length unknown')
                v6.append(candidate)
    if len(v4) > 1 or len(v6) > 1:
        raise Failure('Both a single Ethernet IPv4 and a usable stable IPv6 are required')
    if v4 and v4[0] != '192.0.2.8':
        raise Failure('Ethernet IPv4 changed; router UDP forwarding/DHCP reservation must be reconciled')
    if not v4 or not v6 or missing:
        # Extra shape evidence is only needed to classify an absent address;
        # do not reject an otherwise valid sample due to an ignored old address.
        if not re.match(r'^en0: flags=[0-9a-fA-F]+<[^>\n]+> mtu [1-9][0-9]*(?:[ \t][^\n]*)?\n', info):
            raise Failure('uplink_interface_layout')
        if not v6 and unusable6:
            raise Failure('uplink_ipv6_address_unusable')
        raise UplinkNotReady('uplink_local_not_ready')
    details['lan4'] = v4[0]
    details['stable6'] = v6[0]
    local_parameters(details)
    if not external:
        return details
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f4, f6 = pool.submit(trace, 4), pool.submit(trace, 6)
        waiting = []
        for key, result in [('public4', f4), ('public6_probe', f6)]:
            try:
                details[key] = result.result()
            except UplinkNotReady as error:
                if type(error) is not UplinkNotReady or len(error.args) != 1 or error.args[0] not in WAIT_CODES:
                    raise
                waiting.append(error)
        # A pending IPv4 result must not hide a serious IPv6 failure.
        if waiting:
            raise waiting[0]
    if ipaddress.ip_address(details['public6_probe']) not in ipaddress.ip_network(details['stable6'] + '/64', strict=False):
        raise Failure('IPv6 probe address is outside the expected Ethernet prefix')
    return details
