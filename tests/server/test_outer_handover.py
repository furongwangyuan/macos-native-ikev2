"""Cross-family handover preserves the unrelated IPv4 device."""
from dataclasses import replace
import unittest
import outer_handover_fixture as h
from outer_fixture import LOCAL6, PEER6, OUTER
V4 = h.OLD
V6 = replace(V4, peer4=PEER6, peer_port=45001, local4=LOCAL6)
REPORT = {}


class OuterHandover(unittest.TestCase):
    def active(self, old, frames):
        coordinator, fake = h.fixture([h.frame(old)] * 3 + frames)
        self.assertEqual(coordinator.step().active, ('device01', 'device02'))
        self.assertEqual(fake.calls['guard_all'], 1)
        fake.trace.clear()
        return coordinator, fake

    def other_unchanged(self, coordinator, fake):
        self.assertIsNone(coordinator.failure)
        self.assertEqual(coordinator.active['device02'].generation, h.OTHER)
        self.assertEqual(fake.calls['guard_all'], 1)
        # Every transition must narrow the VPN user being moved, not the
        # unrelated IPv4 device. Real adapter/gate route tests check VIP kills.
        for name, value in fake.trace:
            if name == 'narrow':
                remaining, requests = value
                self.assertEqual(tuple(d.device_id for d in remaining), ('device02',))
                self.assertEqual(tuple(r.device_id for r in requests), ('device01',))

    def mapped_then_new(self, old, mapped, policy_at_new_endpoint):
        new = replace(mapped, child_id=2, spi_in='10000002', spi_out='20000002')
        policy = mapped if policy_at_new_endpoint else old
        moving = h.frame(mapped, policy=policy, offset=40)
        coordinator, fake = self.active(old, [moving] * 6 + [h.frame(new)] * 3)
        self.assertEqual(coordinator.step().active, ('device02',))
        self.assertEqual(coordinator.handovers['device01'].old, old)
        self.assertEqual(coordinator.handovers['device01'].mapped_old(), mapped)
        self.assertEqual(coordinator.step().active, ('device02',))
        self.assertEqual(fake.calls['publish'], 1)
        names = [name for name, _ in fake.trace]
        self.assertLess(names.index('narrow'), names.index('inventory'))
        self.other_unchanged(coordinator, fake)
        self.assertEqual(coordinator.step().active, ('device01', 'device02'))
        self.assertEqual(coordinator.active['device01'].generation, new)
        self.assertEqual(fake.calls['publish'], 2)
        self.other_unchanged(coordinator, fake)
        key = ('v6_to_v4' if ':' in old.local4 else 'v4_to_v6')
        key += '_new_spd' if policy_at_new_endpoint else '_old_spd'
        REPORT[key] = {'old_child_stayed_closed': True, 'new_child_resumed': True,
            'other_ipv4_device_retained': True, 'global_guards_after_initial': 0}

    def test_ipv4_to_ipv6_old_child_waits_for_new_child(self):
        for already_mapped in (False, True):
            with self.subTest(spd_already_mapped=already_mapped):
                self.mapped_then_new(V4, V6, already_mapped)

    def test_ipv6_to_ipv4_old_child_waits_for_new_child(self):
        for already_mapped in (False, True):
            with self.subTest(spd_already_mapped=already_mapped):
                self.mapped_then_new(V6, V4, already_mapped)

    def fresh_ike_overlap(self, old, endpoint, during_handover=False):
        fresh = replace(endpoint, ike_id=2, child_id=3, reqid=3,
            spi_in='10000003', spi_out='20000003')
        overlap = h.Snapshot('overlap', (old, fresh))
        # VICI can show both IKEs while just one set of SPD rows is installed.
        # Both choices remain closed until a unique fresh-CHILD snapshot.
        for installed in (old, fresh):
            with self.subTest(installed_local=installed.local4, during_handover=during_handover):
                frames = []
                if during_handover:
                    frames += [h.frame(endpoint, policy=old, offset=40)] * 3
                frames += [h.frame(fresh, snapshot=overlap, policy=installed)] * 3
                frames += [h.frame(fresh)] * 3
                coordinator, fake = self.active(old, frames)
                if during_handover:
                    self.assertEqual(coordinator.step().active, ('device02',))
                    self.assertIn('device01', coordinator.handovers)
                self.assertEqual(coordinator.step().active, ('device02',))
                self.assertNotIn('device01', coordinator.handovers)
                self.other_unchanged(coordinator, fake)
                self.assertEqual(coordinator.step().active, ('device01', 'device02'))
                self.assertEqual(coordinator.active['device01'].generation, fresh)
                self.other_unchanged(coordinator, fake)
        key = ('fresh_ike_v6_to_v4' if ':' in old.local4 else 'fresh_ike_v4_to_v6')
        if during_handover:
            key += '_during_handover'
        REPORT[key] = {'mixed_local_families_only_closed_own_device': True,
            'unique_fresh_ike_resumed': True, 'global_guards_after_initial': 0}

    def test_fresh_ike_ipv4_ipv6_overlap_only_closes_same_device(self):
        self.fresh_ike_overlap(V4, V6)

    def test_fresh_ike_ipv6_ipv4_overlap_only_closes_same_device(self):
        self.fresh_ike_overlap(V6, V4)

    def test_fresh_ike_cross_family_overlap_clears_prior_handover_only_for_device(self):
        self.fresh_ike_overlap(V4, V6, during_handover=True)

    def test_quick_cross_family_return_uses_exact_original_child(self):
        coordinator, fake = self.active(V4,
            [h.frame(V6, policy=V4, offset=40)] * 3 + [h.frame(V4)] * 3)
        self.assertEqual(coordinator.step().active, ('device02',))
        self.assertEqual(coordinator.step().active, ('device01', 'device02'))
        self.assertEqual(coordinator.active['device01'].generation, V4)
        self.assertNotIn('device01', coordinator.handovers)
        self.other_unchanged(coordinator, fake)


