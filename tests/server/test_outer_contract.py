"""Outer endpoint scope, codec, persistence and generated rules: offline only."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import outer_endpoints as outer
import fleet_session as fs
import fleet_policy as policy
import fleet_vici as vici
import registry
import native_runtime
import native_policy
import service_supervisor
import outer_fixture as fixture
import test_outer_routes as routes
from outer_fixture import LOCAL6, PEER6, OUTER as SCOPE
HERE = Path(__file__).resolve().parent
R = HERE.parents[1]/'server/runtime'


def ipv6_event():
    result = fixture.event()
    fields = fixture.inner(result)
    fields['local-host'] = LOCAL6.encode()
    fields['remote-host'] = PEER6.encode()
    return result

def socket_inventory(entries):
    return 'p111\n' + ''.join('f%d\nt%s\nn*:%d\n' % (i+3, family, port)
                            for i, (family, port) in enumerate(entries))

class OuterContract(unittest.TestCase):
    def tearDown(self):
        routes.h.s.MUTATOR = None
        routes.h.s.DEADLINE = None
        native_runtime.STOP.clear()

    def test_old_render_is_byte_identical_and_dual_render_changes_only_local_addrs(self):
        # Digest of this synthetic fixture rendered by the pre-IPv6 revision.
        legacy = json.loads((HERE/'registry.example.json').read_text())
        self.assertEqual(hashlib.sha256(registry.render_swanctl(legacy).encode()).hexdigest(),
            'ea92381abe09477e664b966b310e4c52f714baa457c243d77a411dbc3853bc7e')
        reg = fixture.registry_many(16)
        old = registry.render_swanctl(reg)
        dual = registry.render_swanctl(reg, SCOPE)
        self.assertEqual(dual, old.replace('local_addrs = 192.0.2.8',
            'local_addrs = 192.0.2.8, ' + LOCAL6))
        self.assertIn('revocation = strict', dual)

    def test_scope_is_explicit_canonical_and_not_any_global_local_address(self):
        self.assertEqual(outer.from_health({'lan4': SCOPE[0], 'stable6': LOCAL6}), SCOPE)
        for bad in [('192.0.2.9', LOCAL6), (SCOPE[0], '::1'), (SCOPE[0], 'fe80::8%en0'),
                    (SCOPE[0], '::ffff:192.0.2.8'), (SCOPE[0], '2001:4860:1234:5678:0:0:0:8')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                outer.normalize(bad)
        for local, peer in [(LOCAL6, '203.0.113.1'), ('2001:4860:1234:5678::9', PEER6),
                            (LOCAL6, '::1'), (LOCAL6, 'fe80::1%en0'), (LOCAL6, LOCAL6)]:
            with self.subTest(local=local, peer=peer), self.assertRaises(ValueError):
                outer.pair(local, peer, SCOPE)

    def test_mixed_vici_codec_canonical_local_peer_and_endpoint_spi_scope(self):
        reg = fixture.registry_many()
        first = ipv6_event()
        second = fixture.event(reg['devices'][1], 2, 2)
        result = vici.parse_events(fixture.decoded([first, second]), reg, SCOPE)
        self.assertEqual(result.snapshots['device01'].generations[0].local4, LOCAL6)
        self.assertEqual(result.snapshots['device01'].generations[0].peer4, PEER6)
        self.assertEqual(result.snapshots['device02'].generations[0].local4, SCOPE[0])
        # Two different receiving IP addresses may use the same inbound SPI.
        fixture.child(second)['spi-in'] = fixture.child(first)['spi-in']
        vici.parse_events([first, second], reg, SCOPE)
        fixture.inner(second)['local-host'] = LOCAL6.encode()
        fixture.inner(second)['remote-host'] = b'2001:4860:abcd::102'
        with self.assertRaises(policy.Fault):
            vici.parse_events([first, second], reg, SCOPE)

    def test_ipv6_requires_scope_and_rejects_wrong_local_family_and_scope_id(self):
        with self.assertRaises(policy.Fault):
            vici.parse_events([ipv6_event()], fixture.REG)
        for field, value in [('local-host', '2001:4860:1234:5678::9'),
                             ('remote-host', '203.0.113.1'),
                             ('remote-host', '2001:4860:abcd:0:0:0:0:101'),
                             ('remote-host', 'fe80::123%en0')]:
            event = ipv6_event()
            fixture.inner(event)[field] = value.encode()
            with self.subTest(field=field, value=value), self.assertRaises(policy.Fault):
                vici.parse_events([event], fixture.REG, SCOPE)

    def test_binding_v1_recovery_unchanged_v2_commits_scope_and_hash(self):
        raw = json.dumps(fixture.REG).encode()
        old = fs.static(raw)
        self.assertEqual(old, dict(version=1, registry_sha256=fs.sha(raw),
            registry=registry.loads(raw), connection_sha256=fs.sha(registry.render_swanctl(fixture.REG).encode())))
        new = fs.static(raw, SCOPE)
        self.assertEqual(new['version'], 2)
        self.assertEqual(fs.endpoints(new), SCOPE)
        self.assertNotEqual(new['connection_sha256'], old['connection_sha256'])
        fs.validate_static(new)
        bad = copy.deepcopy(new)
        bad['outer_endpoints'][1] = '2001:4860:1234:5678::9'
        with self.assertRaises(fs.Invalid):
            fs.validate_static(bad)
        session = dict(version=8, profile=fs.PROFILE, probe_mode='off', fleet=old,
                       fleet_active=[], allow_data=True, phase='WAITING')
        fs.history(session)  # No new health field is required for old sessions.
        session['fleet'] = new
        session['health'] = dict(lan4=SCOPE[0], stable6=LOCAL6)
        fs.history(session)
        session['health']['stable6'] = '2001:4860:1234:5678::9'
        with self.assertRaises(fs.Invalid):
            fs.history(session)

    def test_ipv6_spd_text_and_durable_active_round_trip(self):
        _, owner, proof, _, records, _, _ = fixture.native_fixture()
        scope = fs.endpoints(owner.session['fleet'])
        registry_value = owner.session['fleet']['registry']
        for d in proof.devices:
            for key in d.hosts:
                record = policy.record_from_key(key)
                self.assertEqual(policy.host_request_reqid(record, scope), d.generation.reqid)
                self.assertTrue(policy.host_matches(record, d.generation))
                text = record['src']+'[any] '+record['dst']+'[any] any\n'
                text += '\t'+record['direction']+' ipsec\n\t'+record['requests'][0]+'\n\tspid='+str(record['id'])+' refcnt=1\n'
                self.assertEqual(native_policy.parse_spd(text), [record])
        encoded = [fs.encode_device(d) for d in proof.devices]
        self.assertEqual(fs.decode_active(encoded, registry_value, scope), proof.devices)
        with self.assertRaises(policy.Fault):
            fs.decode_active(encoded, registry_value)
        owner.session['fleet_active'] = encoded
        fs.history(owner.session)
        policy.validate_proof(proof, registry_value, scope)
        with self.assertRaises(policy.Fault):
            policy.validate_proof(proof, registry_value, outer.IPV4)

    def test_existing_uplink_reader_receives_scoped_ipv6_proof(self):
        _, owner, proof, snapshots, records, activity, native = fixture.native_fixture()
        owner.session['fleet_active'] = [fs.encode_device(d) for d in proof.devices]
        adapter = owner.fleet_adapter
        def route(device):
            g = device.generation
            return routes.h.fc.Routes(g, routes.h.fc.Route(g.vip4, 'en0', True, True),
                routes.h.fc.Route(g.vip6, 'en0', True, True),
                routes.h.fc.Route(g.peer4, 'en0', True, False))
        with patch.object(owner, 'uplink_protection_readback', return_value='same-context'), \
             patch.object(adapter, 'read_fleet', return_value=vici.ParseResult(snapshots, 0)), \
             patch.object(adapter, '_inventory', return_value=(records, activity, native)), \
             patch.object(adapter, 'route', side_effect=route):
            _, result, _, _, _ = adapter.uplink_change_frame()
        self.assertEqual(result.outer_endpoints, fs.endpoints(owner.session['fleet']))
        self.assertEqual(result.devices, proof.devices)

    def test_generated_pf_preserves_v4_line_and_adds_only_exact_ipv6_entry(self):
        _, owner, proof, *_ = fixture.native_fixture()
        reg = owner.session['fleet']['registry']
        template = (R/'family-vpn.fleet.pf').read_text()
        text = policy.render(template, reg, proof)
        original4 = 'pass in quick on $wan inet proto udp from any to 192.0.2.8 port { 500, 4500 } keep state (if-bound) label "familyvpn_ike"'
        expected6 = 'pass in quick on $wan inet6 proto udp from any to '+routes.LOCAL6+' port { 500, 4500 } keep state (if-bound) label "familyvpn_ike6"'
        self.assertIn('\n'+original4+'\n'+expected6+'\n', text)
        self.assertNotIn('inet6 proto udp from any to any', text)
        self.assertEqual([line for line in text.splitlines() if 'proto udp' in line], [original4, expected6])
        # Initial empty active set still admits IPv6 IKE; admission does not
        # depend on a CHILD that has not yet negotiated.
        owner.session['fleet_active'] = []
        with patch.object(native_runtime.s, 'read', return_value=template.encode()):
            self.assertIn(expected6, owner.fleet_adapter.gate.rules(()))

    def test_daemon_socket_family_inventory_exact_and_order_independent(self):
        v4 = [('IPv4', 500), ('IPv4', 4500)]
        dual = v4+[('IPv6', 500), ('IPv6', 4500)]
        self.assertTrue(outer.ike_sockets(socket_inventory(v4)))
        self.assertTrue(outer.ike_sockets(socket_inventory(list(reversed(dual))), SCOPE))
        for entries in (v4, dual+[('IPv4',4500)], dual[:-1], [('IPv4',500)]*4):
            self.assertFalse(outer.ike_sockets(socket_inventory(entries), SCOPE))
        self.assertFalse(outer.ike_sockets(socket_inventory(dual), outer.IPV4))
        self.assertFalse(outer.ike_sockets(socket_inventory(dual).replace('n*:500', 'n[::1]:500', 1), SCOPE))

    def test_daemon_setting_and_manifest_include_new_module(self):
        self.assertIn('outer_endpoints.py', service_supervisor.RESOURCES)
        _, owner, *_ = fixture.native_fixture()
        with patch.object(native_runtime.s, 'read', return_value=b'charon {\n plugins { socket-default { use_ipv6 = no } }\n}\n'):
            # The real method uses the pinned original template; inspect its
            # exact output independent of host installed configuration.
            value = owner.daemon_configuration()
        self.assertIn('use_ipv6 = yes', value)
        owner.session['fleet'] = fs.static(owner.registry_bytes)
        value = owner.daemon_configuration()
        self.assertIn('use_ipv6 = no', value)

