"""Extracted reviewed functions; import performs no native operation."""
import errno
import ipaddress
import os
from pathlib import Path
import re
import socket
import struct
import time
from native_support import run,atomic,trusted,read,json_value,sad_empty,STATE
PROBE4='10.77.26.254'
PROBE6='fd6d:fe83:ab27:2600::fffe'
# Bound by the sole runtime owner after its private lock and versioned journal.
def save(_):raise RuntimeError('Native owner not bound')
def say(_):pass


def parse_spd(text):
    """Normalize only supported policy semantics, excluding volatile dump fields."""
    if text.strip() in ['', 'No SPD entries.']:
        return []
    blocks = re.split(r'(?=^\S+\s+\S+\s+any\s*$)', text, flags=re.M)
    result = []
    for block in blocks:
        if not block.strip():
            continue
        lines = block.splitlines()
        header = re.fullmatch(r'(\S+)\[any\]\s+(\S+)\[any\]\s+any', lines[0])
        if not header:
            raise RuntimeError('Unknown SPD header layout')
        src, dst = [str(ipaddress.ip_network(x, strict=False)) for x in header.groups()]
        policy = re.fullmatch(r'\s+(in|out) (ipsec|generate|discard|none)\s*', lines[1]) if len(lines) > 1 else None
        ids = re.findall(r'\bspid=([0-9]+)\b', block)
        if not policy or len(ids) != 1 or int(ids[0]) <= 0:
            raise RuntimeError('Unknown SPD policy or ID layout')
        requests = []
        for line in lines[2:]:
            value = line.strip()
            if not value:
                continue
            if value.startswith('esp/'):
                requests.append(value)
            elif not re.match(r'^(spid=|refcnt=|created:|lastused:|lifetime:|validtime:)', value):
                raise RuntimeError('Unknown SPD metadata line')
        if policy[2] != 'ipsec' and requests:
            raise RuntimeError('Unexpected request on non-IPsec policy')
        result.append(dict(src=src, dst=dst, direction=policy[1], kind=policy[2], id=int(ids[0]), requests=requests))
    if len({x['id'] for x in result}) != len(result):
        raise RuntimeError('Duplicate SPD IDs')
    return result

def floor_specs():
    return [dict(src='0.0.0.0/0', dst='10.77.26.0/24', direction='out', kind='generate', requests=[]),
            dict(src='::/0', dst='fd6d:fe83:ab27:2600::/64', direction='out', kind='generate', requests=[])]

def read_spd():
    text = run(['/usr/sbin/setkey', '-DP']).stdout
    say('Current SPD metadata:\n' + text[-20000:])
    return parse_spd(text), text

def expected_floors(session):
    result = []
    for rec in session.get('floors', []):
        spec = {k: rec[k] for k in ['src', 'dst', 'direction', 'kind', 'requests']}
        if spec not in floor_specs():
            raise RuntimeError('Unrecognized saved floor scope')
        if rec['status'] in ['owned', 'delete-intent']:
            if not isinstance(rec.get('id'), int) or not 0 < rec['id'] <= 0xffffffff:
                raise RuntimeError('Invalid saved floor ID')
            result.append(dict(spec, id=rec['id']))
        elif rec['status'] not in ['intent', 'deleted', 'absent']:
            raise RuntimeError('Unknown floor ownership state')
    return result

def install_floors(session):
    records, _ = read_spd()
    if records:
        raise RuntimeError('Native preflight requires an empty SPD baseline')
    session['floors'] = []
    save(session)
    for number, spec in enumerate(floor_specs()):
        rec = dict(spec, status='intent')
        session['floors'].append(rec)
        save(session)
        path = STATE / ('floor-add-' + str(number) + '.conf')
        atomic(path, 'spdadd ' + spec['src'] + ' ' + spec['dst'] + ' any -P out generate;\n')
        run(['/usr/sbin/setkey', '-n', '-f', path])
        run(['/usr/sbin/setkey', '-f', path])
        current, _ = read_spd()
        already = expected_floors(session)
        added = [r for r in current if r not in already]
        if len(added) != 1 or {k:v for k,v in added[0].items() if k != 'id'} != spec:
            raise RuntimeError('Cannot attribute newly added floor; preserving unknown policies')
        rec.update(id=added[0]['id'], status='owned')
        save(session)
        check_cleanup_spd(session)
    say('Both individually owned native GENERATE floors installed; keeper must be added before service use')

def delete_floor_message(policy_id, seq, pid, policy_kind=5, message_kind=22, direction=2):
    # Current SDK net/pfkeyv2.h: PF_KEY_V2=2, SPDDELETE2=22, EXT_POLICY=18.
    # Native-endian fields; both C structures are exactly16 bytes.
    if message_kind not in [16, 22] or direction not in [1, 2] or policy_kind not in ([0, 2, 5] if message_kind == 16 else [0, 5]):
        raise RuntimeError('Unsupported exact-ID policy operation')
    if message_kind == 22 and direction != 2:
        raise RuntimeError('This helper deletes only its owned OUT policies')
    header = struct.pack('=BBBBHHII', 2, message_kind, 0, 0, 4, 0, seq, pid)
    policy = struct.pack('=HHHBBII', 2, 18, policy_kind, direction, 0, policy_id, 0)
    return header + policy

def delete_floor_id(policy_id, policy_kind=5):
    seq = (time.monotonic_ns() & 0xffffffff) or 1
    pid = os.getpid()
    message = delete_floor_message(policy_id, seq, pid, policy_kind)
    # Never register or dump SAD; discard unrelated PF_KEY messages in memory.
    with socket.socket(29, socket.SOCK_RAW, 2) as key:
        key.settimeout(3)
        if key.send(message) != len(message):
            raise RuntimeError('Incomplete exact-ID SPD delete request')
        until = time.monotonic() + 3
        while time.monotonic() < until:
            key.settimeout(max(0.05, until - time.monotonic()))
            data = key.recv(65536)
            if len(data) < 16:
                continue
            version, kind, error, satype, units, reserved, got_seq, got_pid = struct.unpack('=BBBBHHII', data[:16])
            if (version, kind, got_seq, got_pid) != (2, 22, seq, pid):
                continue
            if error:
                raise RuntimeError('Exact-ID SPD delete returned errno ' + str(error))
            if units * 8 != len(data) or len(data) != 32:
                raise RuntimeError('Unexpected exact-ID SPD delete acknowledgment length')
            length, ext, echoed_kind, direction, _, echoed_id, _ = struct.unpack('=HHHBBII', data[16:32])
            if (length, ext, echoed_kind, direction, echoed_id) != (2, 18, policy_kind, 2, policy_id):
                raise RuntimeError('Exact-ID SPD delete acknowledgment did not match')
            return
        raise RuntimeError('Exact-ID SPD delete acknowledgment timed out')

def policy_id_active(policy_id, policy_kind=5, direction=2, timeout=3):
    """SPDGET ignores DEAD entries; SPDDUMP does not. No SAD data requested."""
    seq = (time.monotonic_ns() & 0xffffffff) or 1
    pid = os.getpid()
    message = delete_floor_message(policy_id, seq, pid, policy_kind, 16, direction)
    if not 0 < timeout <= 3:
        raise RuntimeError('Invalid bounded exact-ID query timeout')
    until = time.monotonic() + timeout
    with socket.socket(29, socket.SOCK_RAW, 2) as key:
        key.settimeout(timeout)
        if key.send(message) != len(message):
            raise RuntimeError('Incomplete exact-ID SPD query')
        while True:
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            key.settimeout(remaining)
            data = key.recv(65536)
            if time.monotonic() >= until:
                raise RuntimeError('Exact-ID SPD query timed out')
            if len(data) < 16:
                continue
            version, kind, error, satype, units, _, got_seq, got_pid = struct.unpack('=BBBBHHII', data[:16])
            # Apple key_spdget emits sequence0 for a successful dump response;
            # key_senderror echoes the request sequence on ENOENT.
            if (version, kind, got_pid) != (2, 16, pid) or got_seq not in [0, seq]:
                continue
            if satype != 0 or units * 8 != len(data):
                raise RuntimeError('Unexpected exact-ID SPD query response')
            if error:
                if error == errno.ENOENT and got_seq == seq:
                    expected = bytearray(message)
                    expected[2] = errno.ENOENT
                    if data != bytes(expected):
                        raise RuntimeError('Inactive-policy reply did not echo the exact query')
                    return False
                raise RuntimeError('Exact-ID SPD query returned errno ' + str(error))
            policies, offset = [], 16
            while offset < len(data):
                if offset + 4 > len(data):
                    raise RuntimeError('Truncated SPD query extension')
                length, extension = struct.unpack('=HH', data[offset:offset + 4])
                length *= 8
                if length < 8 or offset + length > len(data):
                    raise RuntimeError('Invalid SPD query extension length')
                if extension == 18:
                    if (policy_kind != 2 and length != 16) or (policy_kind == 2 and length <= 16):
                        raise RuntimeError('Unexpected request on queried cleanup policy')
                    fields = struct.unpack('=HHHBBII', data[offset:offset + 16])
                    policies.append((fields[2], fields[3], fields[5]))
                offset += length
            if policies != [(policy_kind, direction, policy_id)]:
                raise RuntimeError('Queried policy ID/type/direction differs')
            return True
        raise RuntimeError('Exact-ID SPD query timed out')

def gc_spec():
    # This unassigned project-only target was already used by the UDP controls.
    return dict(src='0.0.0.0/0', dst=PROBE4 + '/32', direction='out', kind='discard', requests=[])

def keeper_spec():
    # Deliberately distinct from BOTH probe targets and from cleanup's GC host.
    return dict(src='0.0.0.0/0', dst='10.77.26.253/32', direction='out', kind='discard', requests=[])

def cleanup_records(session):
    """Validate the journal independently of active-floor requirements."""
    records = session.get('floors', []) + session.get('keepers', []) + ([session['floor_gc']] if session.get('floor_gc') else [])
    result = []
    for rec in records:
        spec = {k: rec[k] for k in ['src', 'dst', 'direction', 'kind', 'requests']}
        allowed = [gc_spec()] if rec is session.get('floor_gc') else ([keeper_spec()] if any(rec is k for k in session.get('keepers', [])) else floor_specs())
        if spec not in allowed or rec.get('status') not in ['intent', 'owned', 'delete-intent', 'delete-acked', 'deleted', 'absent']:
            raise RuntimeError('Unknown cleanup ownership record')
        if rec['status'] not in ['intent', 'absent']:
            if not isinstance(rec.get('id'), int) or not 0 < rec['id'] <= 0xffffffff:
                raise RuntimeError('Invalid cleanup policy ID')
        if rec['status'] in ['owned', 'delete-intent', 'delete-acked']:
            result.append(dict(spec, id=rec['id']))
    if len({x['id'] for x in result}) != len(result):
        raise RuntimeError('Duplicate cleanup ownership IDs')
    return records, result

def check_cleanup_spd(session):
    journal, expected = cleanup_records(session)
    records, _ = read_spd()
    if any(x not in expected for x in records):
        raise RuntimeError('Unowned or replaced SPD entries; preserving all unknown policies')
    for rec in journal:
        if rec['status'] == 'owned' and not any(x['id'] == rec['id'] for x in records):
            raise RuntimeError('Owned cleanup policy unexpectedly disappeared')
    return records

def wait_dead_host_policies(session, net, guard_confirmed):
    """Read-only grace period for stopped charon's DEAD IPsec dump records.

    No extra ID becomes owned, no host policy is deleted, and strict cleanup
    remains unchanged. A live/unknown non-IPsec record is never waited away.
    """
    if not guard_confirmed or not net.state.get('installed') or net.state.get('mode') != 'guarded':
        raise RuntimeError('DEAD-policy wait requires the just-confirmed PF guard')
    if run(['/usr/bin/pgrep', '-x', 'charon'], check=False).returncode != 1:
        raise RuntimeError('DEAD-policy wait requires no charon process')
    if not sad_empty() or any(net.sys_values()[name] != 0 for name in
                             ['net.inet.ip.forwarding', 'net.inet6.ip6.forwarding']):
        raise RuntimeError('DEAD-policy wait requires empty SAD and both forwarding knobs0')
    journal, expected = cleanup_records(session)
    expected_ids = {r['id'] for r in expected}
    until = time.monotonic() + 8
    logged = None
    while True:
        remaining = until - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Inactive host IPsec dump records did not reclaim within 8 seconds; preserving guard')
        records = parse_spd(run(['/usr/sbin/setkey', '-DP'], timeout=min(3, remaining)).stdout)
        extras = [r for r in records if r not in expected]
        if any(r['id'] in expected_ids or r['kind'] != 'ipsec' for r in extras):
            raise RuntimeError('Unowned non-IPsec or replaced native policy; no grace deletion permitted')
        if any(r['status'] == 'owned' and not any(x['id'] == r['id'] for x in records) for r in journal):
            raise RuntimeError('Owned native policy disappeared before host-policy reclamation')
        if not extras:
            if logged:
                say('Inactive host IPsec dump records reclaimed naturally; strict native cleanup resumes')
            return
        for rec in extras:
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('Host policy inactivity query exceeded 8-second grace budget')
            if policy_id_active(rec['id'], 2, 1 if rec['direction'] == 'in' else 2,
                                timeout=min(3, remaining)):
                raise RuntimeError('Unowned host IPsec policy is still active; preserving it and guard')
        ids = sorted(r['id'] for r in extras)
        if ids != logged:
            say('Waiting only for naturally reclaimed inactive IPsec IDs: ' + str(ids))
            logged = ids
        time.sleep(min(0.2, max(0, until - time.monotonic())))

def wait_policy_reclamation(session, ids):
    limit = time.monotonic() + 8
    while True:
        current = check_cleanup_spd(session)
        if not any(x['id'] in ids for x in current):
            return
        if time.monotonic() >= limit:
            raise RuntimeError('Inactive owned policy remains in SPD dump after bounded garbage-collection wait')
        time.sleep(0.2)

def request_cleanup_delete(session, rec):
    current = check_cleanup_spd(session)
    exists = any(x['id'] == rec['id'] for x in current)
    policy_kind = 0 if rec['kind'] == 'discard' else 5
    if not exists:
        if rec['status'] not in ['delete-intent', 'delete-acked']:
            raise RuntimeError('Policy vanished without a recorded deletion intent')
        rec['status'] = 'delete-acked'
        save(session)
        return
    active = policy_id_active(rec['id'], policy_kind)
    if not active:
        if rec['status'] not in ['delete-intent', 'delete-acked']:
            raise RuntimeError('Owned policy became inactive without our deletion intent')
        rec['status'] = 'delete-acked'
        save(session)
        say('Recorded policy ID ' + str(rec['id']) + ' is inactive; dump record awaits garbage collection')
        return
    if rec['status'] == 'delete-acked':
        raise RuntimeError('Acknowledged deletion now resolves to an active policy; preserving it')
    rec['status'] = 'delete-intent'
    save(session)
    delete_floor_id(rec['id'], policy_kind)
    if policy_id_active(rec['id'], policy_kind):
        raise RuntimeError('Deleted policy is still active by exact-ID query')
    rec['status'] = 'delete-acked'
    save(session)
    say('Exact-ID delete acknowledged and inactive confirmed: ID ' + str(rec['id']))

def ensure_gc_policy(session):
    if session.get('floor_gc'):
        rec = session['floor_gc']
        # A crash/failure before ADD may leave only intent. Strict inventory
        # proves no unowned object exists before allowing this intent to retry.
        if rec['status'] in ['intent', 'absent']:
            check_cleanup_spd(session)
            rec['status'] = 'absent'
            save(session)
        elif rec['status'] != 'owned' or not policy_id_active(rec['id'], 0):
            raise RuntimeError('Existing cleanup GC policy cannot safely be reused')
        else:
            check_cleanup_spd(session)
            return
    known = check_cleanup_spd(session)
    rec = dict(gc_spec(), status='intent')
    session['floor_gc'] = rec
    save(session)
    path = STATE / 'floor-gc-add.conf'
    atomic(path, 'spdadd 0.0.0.0/0 ' + PROBE4 + '/32 any -P out discard;\n')
    run(['/usr/sbin/setkey', '-n', '-f', path])
    run(['/usr/sbin/setkey', '-f', path])
    current, _ = read_spd()
    added = [x for x in current if x not in known]
    if len(added) != 1 or {k: v for k, v in added[0].items() if k != 'id'} != gc_spec():
        raise RuntimeError('Cannot attribute temporary GC policy; preserving unknown entries and guard')
    rec.update(id=added[0]['id'], status='owned')
    save(session)
    check_cleanup_spd(session)
    if not policy_id_active(rec['id'], 0):
        raise RuntimeError('Temporary GC policy is not active')
    say('Recorded temporary project-target DISCARD policy to wake native reclamation: ID ' + str(rec['id']))

def remove_floors(session):
    if not session.get('floors'):
        return
    # Caller has guarded both pools, stopped its daemon and restored forwarding.
    # Unlike SPDDUMP, SPDGET excludes DEAD policies. Apple defers physical unlink
    # to key_timehandler, which GENERATE alone deliberately does not keep alive.
    if not sad_empty() or any(int(run(['/usr/sbin/sysctl', '-n', name]).stdout) != 0 for name in
                             ['net.inet.ip.forwarding', 'net.inet6.ip6.forwarding']):
        raise RuntimeError('Policy reclamation requires empty SAD and both forwarding knobs0')
    records = check_cleanup_spd(session)
    if not session.get('floor_removal_started'):
        session['floor_removal_started'] = True
        if session.get('child_seen') and len([r for r in records if r['kind'] == 'generate']) == 2 and all(x['status'] == 'owned' for x in session['floors']):
            session['floor_survived_child'] = True
            say('Both recorded native floors remain after the real CHILD and owned daemon stopped')
        save(session)
    pending = [r for r in session['floors'] if r['status'] in ['owned', 'delete-intent', 'delete-acked']]
    # First distinguish a previous successful deletion from an active policy,
    # without repeatedly attempting to delete a DEAD object.
    for rec in pending:
        active = policy_id_active(rec['id'])
        if rec['status'] == 'owned' and not active:
            raise RuntimeError('Owned floor became inactive without our deletion intent')
        if rec['status'] == 'delete-acked' and active:
            raise RuntimeError('Deleted floor is unexpectedly active; preserving it')
        if rec['status'] in ['delete-intent', 'delete-acked'] and not active:
            rec['status'] = 'delete-acked'
            save(session)
    if any(x['id'] in {r['id'] for r in pending} for x in records):
        ensure_gc_policy(session)
    for rec in session['floors']:
        if rec['status'] == 'intent':
            # The strict inventory already rejected unattributed installations.
            rec['status'] = 'absent'
            save(session)
        elif rec['status'] in ['owned', 'delete-intent', 'delete-acked']:
            request_cleanup_delete(session, rec)
    wait_policy_reclamation(session, {r['id'] for r in pending})
    for rec in pending:
        rec['status'] = 'deleted'
    save(session)
    # Keep a normal policy alive while floors are reclaimed. Only after that
    # stage may lifecycle keepers be removed, before cleanup's last GC policy.
    for rec in session.get('keepers', []):
        if rec['status'] in ['owned', 'delete-intent', 'delete-acked']:
            request_cleanup_delete(session, rec)
            wait_policy_reclamation(session, {rec['id']})
            rec['status'] = 'deleted'
            save(session)
        elif rec['status'] == 'intent':
            check_cleanup_spd(session)
            rec['status'] = 'absent'
            save(session)
    gc = session.get('floor_gc')
    if gc and gc['status'] in ['owned', 'delete-intent', 'delete-acked']:
        request_cleanup_delete(session, gc)
        wait_policy_reclamation(session, {gc['id']})
        gc['status'] = 'deleted'
        save(session)
    elif gc and gc['status'] == 'intent':
        if check_cleanup_spd(session):
            raise RuntimeError('Unresolved GC installation intent')
        gc['status'] = 'absent'
        save(session)
    if check_cleanup_spd(session):
        raise RuntimeError('SPD is not empty after precise cleanup')
    say('Recorded floor IDs and temporary GC ID reclaimed; empty SPD baseline verified without global flush')

def add_keeper(session, role):
    if role not in ['timer-trigger', 'held-keeper']:
        raise RuntimeError('Unknown normal-policy role')
    target = ipaddress.ip_network(keeper_spec()['dst'])
    if any(ipaddress.ip_address(v) in target for v in [PROBE4, PROBE6]):
        raise RuntimeError('Keeper overlaps a probe target')
    before = check_cleanup_spd(session)
    if session.get('floor_gc'):
        raise RuntimeError('Cleanup GC must never coexist with lifecycle probes')
    rec = dict(keeper_spec(), status='intent', role=role)
    session.setdefault('keepers', []).append(rec)
    save(session)
    path = STATE / ('keeper-' + role + '.conf')
    atomic(path, 'spdadd 0.0.0.0/0 10.77.26.253/32 any -P out discard;\n')
    run(['/usr/sbin/setkey', '-n', '-f', path])
    run(['/usr/sbin/setkey', '-f', path])
    current, _ = read_spd()
    added = [x for x in current if x not in before]
    if len(added) != 1 or {k: v for k, v in added[0].items() if k != 'id'} != keeper_spec():
        raise RuntimeError('Cannot attribute normal policy; guard and recovery record retained')
    rec.update(id=added[0]['id'], status='owned')
    save(session)
    check_cleanup_spd(session)
    if not policy_id_active(rec['id'], 0):
        raise RuntimeError('New normal policy is not active')
    say(role + ' recorded active ID ' + str(rec['id']) + ', destination10.77.26.253/32 excludes both probes')
    return rec

def verify_native_protection(session):
    records, text = read_spd()
    expected = expected_floors(session)
    keepers = session.get('keepers', [])
    if len(expected) != 2 or len(keepers) != 1 or keepers[0].get('status') != 'owned':
        raise RuntimeError('Both native floors and the held keeper must remain owned')
    keeper = keepers[0]
    if {k: keeper[k] for k in ['src', 'dst', 'direction', 'kind', 'requests']} != keeper_spec():
        raise RuntimeError('Keeper scope changed')
    expected.append({k: keeper[k] for k in ['src', 'dst', 'direction', 'kind', 'requests', 'id']})
    if type(session.get('allow_data')) is not bool:raise RuntimeError('Strict native protection mode required')
    inventory = [r for r in records if r['kind'] != 'ipsec'] if session['allow_data'] else records
    if sorted(inventory, key=lambda r:r['id']) != sorted(expected, key=lambda r:r['id']):
        raise RuntimeError('Native protection SPD ownership changed or an unknown policy appeared')
    for rec in expected:
        if not policy_id_active(rec['id'], 0 if rec['kind'] == 'discard' else 5):
            raise RuntimeError('A required native floor/keeper is inactive')
    return records, text

def assert_lifecycle_evidence():
    path = Path('/var/db/family-vpn/lan-floor-lifecycle/session.json')
    record = json_value(read(path))
    if (not isinstance(record,dict) or type(record.get('version'))is not int or record.get('version') != 1 or
            record.get('active') is not False or record.get('lifecycle_completed') is not True or record.get('cleanup_errors')):
        raise RuntimeError('Prior native lifecycle must have completed and fully restored')
    for family in [4, 6]:
        matches = [p for p in record.get('probe_results', []) if p.get('phase') == 'keeper-held-generate-v' + str(family)]
        if len(matches) != 1 or matches[0].get('verdict') != 'protected' or matches[0].get('policy_drop_delta') != 3 or matches[0].get('observed_ports') != [] or matches[0].get('capture_kernel_drops') != 0:
            raise RuntimeError('Prior keeper evidence is incomplete for one address family')
    if any(r.get('status') != 'deleted' for r in [*record.get('floors', []), *record.get('keepers', []), record.get('floor_gc', {})]):
        raise RuntimeError('Prior lifecycle ownership did not finish exact cleanup')
    say('Prior root-owned lifecycle evidence accepted; this lifecycle-only candidate sends no native control traffic')
