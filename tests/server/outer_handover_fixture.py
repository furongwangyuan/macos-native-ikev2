"""Synthetic two-device handover frames; no operating-system operations."""
from dataclasses import replace
from fleet_coordinator import Coordinator, FakeAdapter, Observation, Route, Routes
from fleet_policy import Generation, Snapshot, PolicyTransition
from fleet_vici import ParseResult
from fleet_native import NativeFleetAdapter
from outer_fixture import OUTER

REGISTRY = dict(version=1, revision=1, usage_timezone='Asia/Kuala_Lumpur', devices=[
    dict(device_id='device01', display_name='Phone A', state='enabled',
         ike_identity='device01.family.home.arpa', vip4='10.77.26.10',
         vip6='fd6d:fe83:ab27:2600::10'),
    dict(device_id='device02', display_name='Phone B', state='enabled',
         ike_identity='device02.family.home.arpa', vip4='10.77.26.11',
         vip6='fd6d:fe83:ab27:2600::11')])
OLD = Generation(1, 1, 1, 'device01.family.home.arpa', '203.0.113.101', 45000,
    '192.0.2.8', 4500, '10.77.26.10', 'fd6d:fe83:ab27:2600::10', '10000001', '20000001')
MAPPED = replace(OLD, peer4='198.51.100.101', peer_port=45001)
NEW = replace(MAPPED, child_id=2, spi_in='10000002', spi_out='20000002')
OTHER = Generation(10, 10, 10, 'device02.family.home.arpa', '203.0.113.102', 45002,
    '192.0.2.8', 4500, '10.77.26.11', 'fd6d:fe83:ab27:2600::11', '10000010', '20000010')


def record(ident, src, dst, direction, kind, requests=()):
    return dict(id=ident, src=src, dst=dst, direction=direction, kind=kind,
                requests=list(requests))


def hosts(g, offset):
    rows = []
    for vip, suffix, anynet in ((g.vip4, '/32', '0.0.0.0/0'), (g.vip6, '/128', '::/0')):
        for direction in ('in', 'out'):
            src, dst = (vip + suffix, anynet) if direction == 'in' else (anynet, vip + suffix)
            outer = (g.peer4, g.local4) if direction == 'in' else (g.local4, g.peer4)
            rows.append(record(offset + len(rows), src, dst, direction, 'ipsec',
                ['esp/tunnel/' + '-'.join(outer) + '/unique:' + str(g.reqid)]))
    return rows


def frame(g=OLD, *, snapshot=None, policy=None, offset=20, extra=()):
    native = [record(1, '0.0.0.0/0', '10.77.26.0/24', 'out', 'generate'),
              record(2, '::/0', 'fd6d:fe83:ab27:2600::/64', 'out', 'generate'),
              record(3, '0.0.0.0/0', '10.77.26.253/32', 'out', 'discard')]
    records = native + hosts(g if policy is None else policy, offset) + hosts(OTHER, 100) + list(extra)
    snapshots = {'device01': snapshot or Snapshot('unique', (g,)),
                 'device02': Snapshot('unique', (OTHER,))}
    routes = {ident: Routes(gen, Route(gen.vip4, 'en0', True, True),
        Route(gen.vip6, 'en0', True, True), Route(gen.peer4, 'en0', True, False))
        for ident, gen in (('device01', g), ('device02', OTHER))}
    return Observation(REGISTRY, ParseResult(snapshots, 0), records,
        {r['id']: True for r in records}, native, routes, 'a' * 32)


def fixture(frames):
    fake = FakeAdapter(frames)
    adapter = object.__new__(NativeFleetAdapter)
    for name in ('observe', 'inventory', 'route', 'narrow', 'publish', 'guard_all'):
        setattr(adapter, name, getattr(fake, name))
    return Coordinator(REGISTRY, adapter, outer_endpoints=OUTER), fake


