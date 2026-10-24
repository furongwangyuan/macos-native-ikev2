"""Current parser, complete-exchange bounds, and cross-device isolation tests."""
import copy
import unittest
import fleet_exchange
import fleet_policy as policy
import fleet_vici as parser
from vici.protocol import Message, FiniteStream
import vici_fixture as fixture


def complete(events):
    exchange = fleet_exchange.Exchange(0)
    def feed(payload):
        raw = len(payload).to_bytes(4, 'big') + payload
        while raw:
            size = exchange.receive_limit(.1)
            exchange.feed(raw[:size], .1)
            raw = raw[size:]
    exchange.outbound(.1); feed(b'\x05'); exchange.outbound(.1)
    for event in events:
        feed(b'\x07\x07list-sa' + Message.serialize(event))
    feed(b'\x01'); exchange.outbound(.1); feed(b'\x05')
    return exchange.result(.1)


def pending(number):
    event = fixture.event(0, 1000 + number, state='CONNECTING', children=False, vips=False)
    ike = fixture.inner(event)
    ike['remote-id'] = b'%any'
    return {'(unnamed)': ike}


class ProtocolPolicy(unittest.TestCase):
    def test_two_devices_have_distinct_authenticated_ownership(self):
        events = [fixture.event(0, 1, 1), fixture.event(1, 2, 2)]
        parsed = parser.parse_events(fixture.decode(events), fixture.REG)
        self.assertEqual(set(parsed.snapshots), {'device01', 'device02'})
        generations = [x.generations[0] for x in parsed.snapshots.values()]
        self.assertEqual(len({x.remote_id for x in generations}), 2)
        self.assertEqual(len({x.vip4 for x in generations}), 2)

    def test_46_pending_and_two_devices_fit_complete_48_event_budget(self):
        events = [fixture.event(0, 1, 1), fixture.event(1, 2, 2)] + [pending(i) for i in range(46)]
        result = complete(events)
        decoded = [Message.deserialize(FiniteStream(x)) for x in result.event_messages]
        parsed = parser.parse_events(decoded, fixture.REG)
        self.assertEqual(parsed.unattributed_pending_count, 46)
        self.assertTrue(all(len(x.generations) == 1 for x in parsed.snapshots.values()))

    def test_49_events_are_not_a_partial_complete_inventory(self):
        with self.assertRaisesRegex(fleet_exchange.ExchangeFault, '^event_count$'):
            complete([pending(i) for i in range(49)])

    def test_unauthenticated_claim_does_not_get_device_ownership(self):
        event = pending(1)
        fixture.inner(event)['remote-id'] = b'device01.family.home.arpa'
        parsed = parser.parse_events(fixture.decode([event]), fixture.REG)
        self.assertEqual(parsed.unattributed_pending_count, 1)
        self.assertTrue(all(not x.generations for x in parsed.snapshots.values()))

    def test_pending_policy_for_new_device_does_not_close_other_device(self):
        first = parser.parse_events(fixture.decode([fixture.event(0, 1, 1)]), fixture.REG)
        both = parser.parse_events(fixture.decode([fixture.event(0, 1, 1), fixture.event(1, 2, 2)]), fixture.REG)
        rows = copy.deepcopy(fixture.NATIVE)
        for index, snap in enumerate(both.snapshots.values()):
            rows += fixture.hosts(snap.generations[0], 20 + 4 * index)
        proof = policy.audit(fixture.REG, first.snapshots, rows, {x['id']: True for x in rows}, fixture.NATIVE)
        by_id = {d.device_id: d for d in proof.devices}
        self.assertTrue(by_id['device01'].ready)
        self.assertFalse(by_id['device02'].ready)

    def test_active_reqid_collision_is_rejected(self):
        events = [fixture.event(0, 1, 1), fixture.event(1, 2, 2)]
        fixture.inner(events[1])['child-sas']['internet-2']['reqid'] = b'1'
        with self.assertRaises(policy.Fault):
            parser.parse_events(fixture.decode(events), fixture.REG)

    def test_normal_rekey_preserves_second_device(self):
        retired = fixture.event(state='REKEYED', children=False, vips=False)
        result = fixture.simulate(parser, [retired, fixture.event(ikeid=2)])
        self.assertEqual(set(result['active']), {'device01', 'device02'})

    def test_unknown_selector_does_not_acquire_device_authority(self):
        parsed = parser.parse_events(fixture.decode([fixture.event(0, 1, 1)]), fixture.REG)
        rows = copy.deepcopy(fixture.NATIVE)
        rows += fixture.hosts(parsed.snapshots['device01'].generations[0], 20)
        rows.append(fixture.record(99, '10.77.26.99/32', '0.0.0.0/0', 'in', 'ipsec',
            ['esp/tunnel/203.0.113.101-192.0.2.8/unique:99']))
        with self.assertRaises(policy.Fault):
            policy.audit(fixture.REG, parsed.snapshots, rows, {x['id']: True for x in rows}, fixture.NATIVE)
