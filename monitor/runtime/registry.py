"""Pure candidate metadata validation/generation. No file, network or root effects.

This does not register certificates or enable multi-device forwarding. Runtime
inventory and the monitor journal still require their separate migrations.
"""
import copy
import ipaddress
import json
import re
import unicodedata

ZONE = 'Asia/Kuala_Lumpur'
DEVICE = re.compile(r'[a-z][a-z0-9-]{0,30}[a-z0-9]', re.ASCII)
LOW4 = int(ipaddress.IPv4Address('10.77.26.10'))
HIGH4 = int(ipaddress.IPv4Address('10.77.26.100'))
LOW6 = int(ipaddress.IPv6Address('fd6d:fe83:ab27:2600::10'))
HIGH6 = int(ipaddress.IPv6Address('fd6d:fe83:ab27:2600::100'))


class Invalid(ValueError):
    pass


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Invalid('duplicate JSON field')
        value[key] = item
    return value


def loads(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise Invalid('registry size or input type')
    def invalid_constant(_):
        raise Invalid('nonfinite JSON constant')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                          parse_constant=invalid_constant)
        return normalize(data)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid('invalid registry encoding or JSON') from exc


def normalize(raw):
    if type(raw) is not dict or set(raw) != {'version', 'revision', 'usage_timezone', 'devices'}:
        raise Invalid('registry fields')
    if type(raw['version']) is not int or raw['version'] != 1:
        raise Invalid('registry version')
    if type(raw['revision']) is not int or not 1 <= raw['revision'] < 2**53:
        raise Invalid('registry revision')
    if raw['usage_timezone'] != ZONE:
        raise Invalid('registry timezone')
    if type(raw['devices']) is not list or not 1 <= len(raw['devices']) <= 16:
        raise Invalid('registry device bound')
    unique = {key: set() for key in ('device_id', 'ike_identity', 'vip4', 'vip6')}
    devices = []
    for item in raw['devices']:
        keys = {'device_id', 'display_name', 'ike_identity', 'state', 'vip4', 'vip6'}
        if type(item) is not dict or set(item) != keys:
            raise Invalid('device fields')
        if any(type(item[k]) is not str for k in keys):
            raise Invalid('device field types')
        ident = item['device_id']
        if not DEVICE.fullmatch(ident) or item['ike_identity'] != ident + '.family.home.arpa':
            raise Invalid('exact device identity required')
        name = item['display_name']
        if not 1 <= len(name) <= 80 or name != name.strip() or any(unicodedata.category(c)[0] == 'C' for c in name):
            raise Invalid('display name')
        if any(c in '\u2028\u2029' for c in name):
            raise Invalid('display separator')
        if item['state'] not in ('enabled', 'disabled', 'revoked'):
            raise Invalid('device state')
        try:
            v4 = ipaddress.IPv4Address(item['vip4'])
            v6 = ipaddress.IPv6Address(item['vip6'])
        except ipaddress.AddressValueError as exc:
            raise Invalid('device address syntax') from exc
        if v6.scope_id is not None:
            raise Invalid('scoped address not allowed')
        if not LOW4 <= int(v4) <= HIGH4 or not LOW6 <= int(v6) <= HIGH6:
            raise Invalid('device address outside fixed pools')
        row = dict(item, vip4=str(v4), vip6=str(v6))
        for key, seen in unique.items():
            if row[key] in seen:
                raise Invalid('duplicate device identity or address')
            seen.add(row[key])
        devices.append(row)
    return dict(version=1, revision=raw['revision'], usage_timezone=ZONE,
                devices=sorted(devices, key=lambda d: d['device_id']))


def check_update(previous, proposed):
    """Keep permanent accounting keys and addresses; no implicit reassignment.

    Re-enabling a revoked identity needs a separate certificate reissue flow,
    which this metadata-only candidate intentionally cannot authorize.
    """
    old, new = normalize(previous), normalize(proposed)
    if new == old:
        return copy.deepcopy(new)
    if new['revision'] <= old['revision']:
        raise Invalid('changed registry needs a newer revision')
    after = {row['device_id']: row for row in new['devices']}
    for row in old['devices']:
        current = after.get(row['device_id'])
        if current is None:
            raise Invalid('permanent device cannot be removed')
        if any(current[k] != row[k] for k in ('ike_identity', 'vip4', 'vip6')):
            raise Invalid('permanent identity or address changed')
        if row['state'] == 'revoked' and current['state'] != 'revoked':
            raise Invalid('certificate reissue proof required')
    return new


def monitor_maps(registry):
    registry = normalize(registry)
    return dict(revision=registry['revision'],
                devices={d['device_id']: d['display_name'] for d in registry['devices']},
                identities={d['ike_identity']: d['device_id'] for d in registry['devices']},
                states={d['device_id']: d['state'] for d in registry['devices']})


CONNECTION = '''    family-vpn-@ID@ {
        version = 2
        local_addrs = 192.0.2.8
        remote_addrs = %any
        pools = family4-@ID@, family6-@ID@
        proposals = aes256gcm16-prfsha256-ecp256,aes256-sha256-prfsha256-modp2048
        fragmentation = yes
        mobike = no
        encap = yes
        send_cert = always
        unique = replace
        dpd_delay = 30s
        rekey_time = 23h
        reauth_time = 0s
        local {
            auth = pubkey
            id = vpn.family.home.arpa
            certs = server.pem
        }
        remote {
            auth = pubkey
            id = @AUTH@
            cacerts = ca.pem
            revocation = strict
        }
        children {
            internet {
                local_ts = 0.0.0.0/0, ::/0
                remote_ts = dynamic
                esp_proposals = aes256gcm16-ecp256,aes256-sha256-modp2048
                rekey_time = 50m
                life_time = 60m
                rand_time = 5m
                start_action = none
                dpd_action = clear
                close_action = none
                mode = tunnel
            }
        }
    }
'''


def render_swanctl(registry):
    registry = normalize(registry)
    connections, pools = [], []
    for row in registry['devices']:
        if row['state'] != 'enabled':
            continue
        name = row['device_id']
        connections.append(CONNECTION.replace('@ID@', name).replace('@AUTH@', row['ike_identity']))
        pools.append('    family4-' + name + ' {\n        addrs = ' + row['vip4'] +
                     '\n        dns = 202.188.18.188, 1.9.1.9\n    }\n    family6-' + name +
                     ' {\n        addrs = ' + row['vip6'] + '\n    }\n')
    return ('# GENERATED CANDIDATE ONLY; not registered or loaded. Registry revision ' +
            str(registry['revision']) + '\nconnections {\n' + ''.join(connections) +
            '}\npools {\n' + ''.join(pools) + '}\n')
