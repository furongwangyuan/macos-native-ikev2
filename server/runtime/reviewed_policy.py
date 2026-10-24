#!/usr/bin/env python3
"""Review-only pure WAN adaptation; no subprocess, sockets or system mutations.

No runnable WAN start action exists. Native floor/keeper lifecycle is deliberately
not copied here and must be integrated after its actual host validation.
"""
import copy
import ipaddress
import re

DEVICE_ID = 'device01.family.home.arpa'
SERVER_ID = 'vpn.family.home.arpa'
LOCAL4 = '192.0.2.8'
CHARON = '/usr/local/family-vpn/strongswan-6.1.0/libexec/ipsec/charon'


def assert_runtime_ready():
    raise RuntimeError('WAN activation is not wired: active native floor + held keeper + verified cleanup are mandatory.')


def _one(pattern, text, label):
    matches = re.findall(pattern, text, re.M)
    if len(matches) != 1:
        raise ValueError('expected exactly one ' + label)
    return matches[0]


def _peer4(value):
    value = ipaddress.IPv4Address(value)
    if value.is_unspecified or value.is_loopback or value.is_link_local or value.is_multicast or str(value) == LOCAL4:
        raise ValueError('unexpected IPv4 outer peer')
    return str(value)


def _vip_pair(networks):
    if len(networks) != 2 or sorted(n.version for n in networks) != [4, 6] or any(n.num_addresses != 1 for n in networks):
        raise ValueError('exactly one host VIP per family is required')
    v4, v6 = [next(n.network_address for n in networks if n.version == family) for family in [4, 6]]
    if not ipaddress.ip_address('10.77.26.10') <= v4 <= ipaddress.ip_address('10.77.26.100'):
        raise ValueError('IPv4 VIP outside the reviewed allocation range')
    if not ipaddress.ip_address('fd6d:fe83:ab27:2600::10') <= v6 <= ipaddress.ip_address('fd6d:fe83:ab27:2600::100'):
        raise ValueError('IPv6 VIP outside the reviewed allocation range')
    return str(v4), str(v6)


def sa_info(text):
    """Input must come from the already-verified private VICI socket.

    Returns None only when no established/installed connection is available.
    Multiple or unexpected established identities are rejected; callers guard.
    This parser cannot itself prove CRL checks; the loaded connection must require
    remote.id=device01 and revocation=strict and acceptance must inspect auth logs.
    """
    if not text.strip() or 'ESTABLISHED' not in text:
        return None
    headers = re.findall(r'^(\S+): #([0-9]+), ESTABLISHED, IKEv2,', text, re.M)
    if len(headers) != 1 or headers[0][0] != 'family-vpn':
        raise ValueError('expected exactly one established family-vpn IKE SA')
    local_id, local_ip, local_port = _one(r"^  local  '([^']+)' @ ([0-9.]+)\[([0-9]+)\]$", text, 'local IKE endpoint')
    remote_id, peer, peer_port, leases = _one(
        r"^  remote '([^']+)' @ ([0-9.]+)\[([0-9]+)\] \[([^\]]+)\]$", text, 'remote IKE endpoint and leases')
    if local_id != SERVER_ID or local_ip != LOCAL4 or remote_id != DEVICE_ID:
        raise ValueError('only the reviewed server and device01 identity are accepted')
    peer = _peer4(peer)
    if int(local_port) != 4500 or not 1 <= int(peer_port) <= 65535:
        raise ValueError('unexpected NAT-T endpoint port')
    if 'INSTALLED' not in text:
        return None
    child_id, reqid = _one(
        r'^  internet: #([0-9]+), reqid ([0-9]+), INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-256$',
        text, 'installed GCM256 tunnel CHILD')
    if len(re.findall(r'^  \S+: #[0-9]+, reqid ', text, re.M)) != 1:
        raise ValueError('CHILD overlap is not yet stable; keep the bounded test guarded')
    _one(r'^  AES_GCM_16-256/PRF_HMAC_SHA2_256/ECP_256$', text, 'reviewed IKE proposal')
    full = _one(r'^    local  (.+)$', text, 'local CHILD selectors').split()
    if len(full) != 2 or set(full) != {'0.0.0.0/0', '::/0'}:
        raise ValueError('both full traffic selectors are required')
    remote = _one(r'^    remote (.+)$', text, 'remote CHILD selectors').split()
    vip4, vip6 = _vip_pair([ipaddress.ip_network(x, strict=True) for x in remote])
    if set(leases.split()) != {vip4, vip6} or len(leases.split()) != 2:
        raise ValueError('IKE virtual leases differ from host CHILD selectors')
    result = dict(ike_id=int(headers[0][1]), child_id=int(child_id), reqid=int(reqid),
                  peer4=peer, peer_port=int(peer_port), local4=local_ip, local_port=int(local_port),
                  vip4=vip4, vip6=vip6, remote_id=remote_id)
    if min(result['ike_id'], result['child_id'], result['reqid']) < 1:
        raise ValueError('invalid SA identifier')
    return result


def fingerprint(info):
    return tuple(info[key] for key in ('ike_id', 'child_id', 'reqid', 'remote_id', 'peer4',
                                       'peer_port', 'local4', 'local_port', 'vip4', 'vip6'))


def transition(previous, current):
    if current is None:
        return {'guard_required': True, 'revalidate_required': False, 'action': 'wait-within-original-deadline'}
    changed = previous is None or fingerprint(previous) != fingerprint(current)
    return {'guard_required': changed, 'revalidate_required': True,
            'action': 'guard-then-revalidate' if changed else 'revalidate-current'}


def verify_spd(records, info):
    """Validate parsed metadata; lifecycle separately proves policy IDs are active.

    Non-IPsec floors/keeper are verified by their owning lifecycle, not trusted by
    this function. Exact CHILD reqid and current outer endpoints must match.
    """
    ipsec = [entry for entry in records if entry['kind'] == 'ipsec']
    expected = {}
    for family, vip in [(4, info['vip4']), (6, info['vip6'])]:
        host = str(ipaddress.ip_network(vip))
        anynet = '0.0.0.0/0' if family == 4 else '::/0'
        for direction in ('in', 'out'):
            selectors = (host, anynet) if direction == 'in' else (anynet, host)
            endpoints = (info['peer4'], info['local4']) if direction == 'in' else (info['local4'], info['peer4'])
            expected[(direction, *selectors)] = 'esp/tunnel/' + '-'.join(endpoints) + '/unique'
    if len(ipsec) != 4:
        raise ValueError('expected four current host CHILD policies; overlap/unknown policies remain guarded')
    ids = []
    for entry in ipsec:
        key = entry['direction'], entry['src'], entry['dst']
        prefix = expected.pop(key, None)
        if prefix is None or len(entry['requests']) != 1:
            raise ValueError('unexpected CHILD SPD selectors/direction')
        if entry['requests'][0] not in (prefix + ':' + str(info['reqid']), prefix + '#' + str(info['reqid'])):
            raise ValueError('CHILD SPD outer peer/reqid differs; MOBIKE must be revalidated')
        if not isinstance(entry['id'], int) or entry['id'] <= 0 or entry['id'] in ids:
            raise ValueError('invalid/duplicate CHILD SPD ID')
        ids.append(entry['id'])
    if expected:
        raise ValueError('missing CHILD host policy')
    return tuple(sorted(ids))


def verify_route(text, vip):
    interface = _one(r'^\s*interface:\s*(\S+)\s*$', text, 'route interface')
    destination = _one(r'^\s*destination:\s*(\S+)\s*$', text, 'route destination')
    flags = set(_one(r'^\s*flags:\s*<([^>]+)>\s*$', text, 'route flags').split(','))
    if interface != 'en0' or destination.split('%')[0] != vip or not {'UP', 'HOST'} <= flags:
        raise ValueError('active exact VIP route must be UP/HOST on Ethernet')
    # WAN gateway may be the home router; never require it to equal remote peer.


def render_pf(template, info):
    marker = '# ACTIVE_IPV4_RETURN_RULE'
    if template.count(marker) != 1 or template.count('table <familyvpn_home4>') != 1:
        raise ValueError('PF template markers differ')
    text = template.replace(marker, 'pass out quick on $wan inet from any to <familyvpn_active4> '
                            'tagged FAMILYVPN_EGRESS4 no state label "familyvpn_return4"')
    text = text.replace('table <familyvpn_home4>',
                        f'table <familyvpn_active4> const {{ {info["vip4"]}/32 }}\n'
                        f'table <familyvpn_active6> const {{ {info["vip6"]}/128 }}\ntable <familyvpn_home4>', 1)
    for version in (4, 6):
        family = 'inet' if version == 4 else 'inet6'
        for old, new in [
            (f'nat on $wan {family} from <familyvpn_v{version}> to !',
             f'nat on $wan {family} from <familyvpn_active{version}> to !'),
            (f'pass in quick on $wan {family} from <familyvpn_v{version}> to any no state',
             f'pass in quick on $wan {family} from <familyvpn_active{version}> to any no state')]:
            if text.count(old) != 1:
                raise ValueError('PF source-scope rule differs')
            text = text.replace(old, new)
    old_ike = 'pass in quick on $wan inet proto udp to ($wan) port { 500, 4500 }'
    if text.count(old_ike) != 1:
        raise ValueError('PF IKE rule differs')
    # IPv4 %any applies only to IKE/NAT-T outer packets, never inner pool NAT.
    text = text.replace(old_ike, 'pass in quick on $wan inet proto udp from any to ' + LOCAL4 + ' port { 500, 4500 }')
    if '192.168.0.5' in text:
        raise ValueError('LAN-only peer unexpectedly survived WAN rendering')
    return text


def alf_plan(before):
    """Return a journal plan only. Caller must apply/verify using root lifecycle."""
    required = {'global_state', 'blockall', 'stealth', 'apps', 'builtin', 'downloaded'}
    if set(before) != required or (before['global_state'], before['blockall']) != (2, True):
        raise ValueError('first bounded WAN test requires the restored block-all baseline')
    if before['apps'].get(CHARON) is not False:
        raise ValueError('expected existing charon rule to be blocked before the window')
    if not all(isinstance(value, bool) for value in [before['builtin'], before['downloaded'], *before['apps'].values()]):
        raise ValueError('unexpected ALF flags/app state')
    expected = copy.deepcopy(before)
    changes = [('flag', key, True, False) for key in ('builtin', 'downloaded') if before[key]]
    changes.extend(('app', path, True, False) for path, allowed in before['apps'].items() if allowed)
    changes.extend([('app', CHARON, False, True), ('blockall', None, True, False)])
    expected.update(builtin=False, downloaded=False, global_state=1, blockall=False)
    expected['apps'] = {path: path == CHARON for path in before['apps']}
    return {'expected': expected, 'changes_in_order': changes,
            'rollback_scope': 'block-all safety override first, conditional reverse of our app/autoallow writes'}



if __name__ == '__main__':
    assert_runtime_ready()
