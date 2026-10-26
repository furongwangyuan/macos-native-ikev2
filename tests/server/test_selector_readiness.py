"""Synthetic selector readiness; concrete coordinator with mocked native edges."""
import copy
import socket
import subprocess
import unittest
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
from unittest.mock import patch
import test_native_fleet as h
from outer_fixture import OUTER, PEER6, event, inner, child
import fleet_vici as v

def events_for(reg, snaps):
    events = []
    for d in reg['devices']:
        g = snaps[d['device_id']].generations[0]
        e = event(d, g.ike_id, g.child_id); fields = inner(e); c = child(e)
        fields.update({'local-host':g.local4.encode(), 'remote-host':g.peer4.encode(),
                       'remote-port':str(g.peer_port).encode()})
        c.update({'reqid':str(g.reqid).encode(), 'spi-in':g.spi_in.encode(), 'spi-out':g.spi_out.encode()})
        events.append(e)
    return events

@contextmanager
def environment():
    _, owner, proof, snaps, records, active, native = h.fixture(outer_endpoints=OUTER, peer6=PEER6)
    a = owner.fleet_adapter; k = h.Kernel(owner); reg = owner.session['fleet']['registry']
    e = SimpleNamespace(owner=owner, a=a, k=k, reg=reg, records=records, active=active,
                        events=events_for(reg, snaps), expected=snaps, reads=0, sequence=[])
    with ExitStack() as stack:
        # A missed mock must fail, never access a network or launch native tools.
        stack.enter_context(patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')))
        stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')))
        k.bind(stack)
        def read(_=10):
            e.reads += 1; a.last_context = 'a'*32
            events = e.sequence.pop(0) if e.sequence else e.events
            return v.parse_events(copy.deepcopy(events), reg, OUTER)
        stack.enter_context(patch.object(a, 'read_fleet', side_effect=read))
        stack.enter_context(patch.object(h.runtime.policies, 'parse_spd', side_effect=lambda _:copy.deepcopy(records)))
        stack.enter_context(patch.object(h.runtime.policies, 'policy_id_active', side_effect=lambda ident,*args,**kwargs:active[ident]))
        e.c = h.fc.Coordinator(reg, a, outer_endpoints=OUTER)
        yield e

class SelectorReadiness(unittest.TestCase):
    def tearDown(self): h.s.MUTATOR = None; h.s.DEADLINE = None; h.runtime.STOP.clear()
    def parse(self, e, events=None): return v.parse_events(e.events if events is None else events, e.reg, OUTER)
    def assert_b_only(self, e):
        self.assertEqual(e.c.last_result.state, 'ACTIVE')
        self.assertEqual(e.c.last_result.active, ('device02',))
        self.assertIsNone(e.c.failure)
        self.assertEqual(e.k.guard_count, 1)
        self.assertEqual(tuple(d.device_id for d in e.a.gate.current()), ('device02',))
        self.assertEqual(e.k.tables, {'active4':['10.77.26.11'], 'active6':['fd6d:fe83:ab27:2600::11']})

    def test_normal_full_scope_unchanged_and_order_independent(self):
        with environment() as e:
            expected = e.expected
            for reverse in (False, True):
                if reverse: child(e.events[0])['local-ts'].reverse()
                got = self.parse(e)
                self.assertEqual(got.snapshots, expected)
                self.assertEqual(got.unattributed_pending_count, 0)
            self.assertEqual(e.c.step().active, ('device01','device02'))
            self.assertEqual(e.reads, 3)

    def test_structured_mismatch_pending_keeps_generation_and_healthy_sibling(self):
        cases = ([], [b'0.0.0.0/0'], [b'::/0'], [b'::/0', b'::/0'],
                 [b'0.0.0.0/1', b'::/0'], [b'0.0.0.0/0', b'0:0:0:0:0:0:0:0/0'],
                 [b'0.0.0.0/0',b'::/0',b'192.0.2.0/24'], [b'192.0.2.0/24']*16)
        with environment() as e:
            before = self.parse(e)
            for ts in cases:
                with self.subTest(ts=ts):
                    child(e.events[0])['local-ts'] = ts
                    got = self.parse(e)
                    self.assertEqual(got.snapshots['device01'].kind, 'pending')
                    self.assertEqual(got.snapshots['device01'].generations, before.snapshots['device01'].generations)
                    self.assertEqual(got.snapshots['device02'], before.snapshots['device02'])

    def test_malformed_local_scope_still_faults(self):
        for ts in (b'::/0', ['::/0'], [b'\xff'], [b''], [b'::/0\n'], [b'::/0']*17):
            with self.subTest(ts=ts), environment() as e:
                child(e.events[0])['local-ts'] = ts
                with self.assertRaises(v.Fault): self.parse(e)

    def test_multi_child_keeps_bad_sibling_no_winner_both_orders(self):
        for state in sorted(v.COMPLETE_CHILD):
            for reverse in (False, True):
                with self.subTest(state=state,reverse=reverse), environment() as e:
                    c = child(event(e.reg['devices'][0], 1, 3)); c['state'] = state.encode(); c['local-ts'] = []
                    children = inner(e.events[0])['child-sas']; children['internet-3'] = c
                    if reverse: inner(e.events[0])['child-sas'] = dict(reversed(list(children.items())))
                    got = self.parse(e).snapshots['device01']
                    self.assertEqual(got.kind, 'overlap'); self.assertEqual(len(got.generations), 2)
                    self.assertEqual(len(got.deleted), int(state == 'DELETED'))
                    raw_state, generation, ready = v.parse_child('internet-3', c, inner(e.events[0]), e.reg['devices'][0],
                        (got.generations[0].peer4,45000,got.generations[0].local4,4500), set(), {}, OUTER)
                    self.assertEqual(raw_state, state); self.assertIsNotNone(generation); self.assertFalse(ready)

    def test_bad_scope_does_not_hide_other_child_violations(self):
        changes = [('remote-ts',[b'10.77.26.11/32', b'fd6d:fe83:ab27:2600::10/128']),
                   ('mode',b'TRANSPORT'), ('protocol',b'AH'), ('encap',b'no'),
                   ('encr-alg',b'AES_CBC'), ('encr-keysize',b'128'), ('dh-group',b'MODP_2048'),
                   ('spi-in',b'00000000'), ('spi-out',b'NOTHEX00'), ('reqid',b'0'),
                   ('bytes-in',b'-1'), ('install-time',b'-1')]
        for key, val in changes:
            for sibling in (False, True):
                with self.subTest(key=key,sibling=sibling), environment() as e:
                    c = child(e.events[0]); c['local-ts'] = []; c[key] = val
                    if sibling: inner(e.events[0])['child-sas']['internet-3'] = child(event(e.reg['devices'][0],1,3))
                    with self.assertRaises(v.Fault): self.parse(e)

    def test_bad_scope_does_not_hide_ike_vip_or_identity_violations(self):
        for key, val in [('remote-vips',[b'10.77.26.11',b'fd6d:fe83:ab27:2600::10']),
                         ('remote-id',b'other.family.home.arpa'), ('local-id',b'other.family.home.arpa')]:
            with self.subTest(key=key), environment() as e:
                child(e.events[0])['local-ts'] = []; inner(e.events[0])[key] = val
                with self.assertRaises(v.Fault): self.parse(e)

    def test_bad_scope_cannot_skip_invalid_sibling_either_order(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse), environment() as e:
                child(e.events[0])['local-ts'] = []
                bad = child(event(e.reg['devices'][0],1,3)); bad['remote-ts'] = [b'0.0.0.0/0',b'::/0']
                children = inner(e.events[0])['child-sas']; children['internet-3'] = bad
                if reverse: inner(e.events[0])['child-sas'] = dict(reversed(list(children.items())))
                with self.assertRaises(v.Fault): self.parse(e)

    def test_bad_scope_cannot_erase_cross_device_reqid_spi_ownership(self):
        for key in ('reqid','spi-in','spi-out'):
            for reverse in (False, True):
                with self.subTest(key=key,reverse=reverse), environment() as e:
                    # Same outer endpoints so identical SPI keys really collide.
                    for field in ('local-host','remote-host'): inner(e.events[0])[field] = inner(e.events[1])[field]
                    child(e.events[0])['local-ts'] = []; child(e.events[0])[key] = child(e.events[1])[key]
                    with self.assertRaises(v.Fault): self.parse(e, list(reversed(e.events)) if reverse else e.events)

    def test_cold_start_bad_a_keeps_b_eligible(self):
        with environment() as e:
            child(e.events[0])['local-ts'] = []
            e.c.step(); self.assert_b_only(e)

    def test_active_a_narrows_only_a_then_ordinary_readmission(self):
        with environment() as e:
            self.assertEqual(e.c.step().active, ('device01','device02'))
            saved_b = e.c.active['device02']; start = len(e.k.trace)
            child(e.events[0])['local-ts'] = []
            e.c.step(); self.assert_b_only(e); self.assertEqual(e.c.active['device02'], saved_b)
            self.assertEqual([row[-1] for row in e.k.trace[start:] if '-k' in row],
                             ['10.77.26.10']*2 + ['fd6d:fe83:ab27:2600::10']*2)
            self.assertEqual(e.owner.session['fleet_closing']['phase'], 'verified')
            bad = copy.deepcopy(e.events); child(e.events[0])['local-ts'] = [b'0.0.0.0/0',b'::/0']
            # One full-scope observation must not override a later bad frame.
            e.sequence = [copy.deepcopy(e.events), bad, copy.deepcopy(e.events)]
            before = e.reads; e.c.step(); self.assert_b_only(e); self.assertEqual(e.reads-before,3)
            before = e.reads; e.c.step(); self.assertEqual(e.reads-before,3)
            self.assertEqual(e.c.last_result.active, ('device01','device02'))
            self.assertEqual(e.c.active['device02'], saved_b); self.assertEqual(e.k.guard_count,1)

    def test_multi_child_bad_scope_keeps_healthy_device_active(self):
        with environment() as e:
            e.c.step()
            c = child(event(e.reg['devices'][0],1,3)); c['local-ts'] = []
            inner(e.events[0])['child-sas']['internet-3'] = c
            e.c.step(); self.assert_b_only(e)

    def test_non_authorized_native_selector_still_stops(self):
        with environment() as e:
            e.c.step(); child(e.events[0])['local-ts'] = []
            e.records[-1]['src'] = '2001:db8::/64'
            result = e.c.step()
            self.assertEqual(result.state,'STOPPED'); self.assertIsNotNone(e.c.failure)
            self.assertFalse(e.c.active)

if __name__ == '__main__':
    unittest.main(verbosity=2)
