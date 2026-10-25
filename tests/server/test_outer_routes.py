"""Mixed outer-family route checks with real adapters and mocked OS boundaries."""
import copy
import subprocess
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch
import test_native_fleet as h
from outer_fixture import LOCAL6, PEER6, OUTER
REPORT = {}


def route_result(destination, interface='en0', flags='UP,HOST', code=0):
    return SimpleNamespace(
        stdout='destination: ' + destination + '\ninterface: ' + interface
               + '\nflags: <' + flags + '>\n',
        stderr='', returncode=code)


class OuterRoutes(unittest.TestCase):
    def tearDown(self):
        h.s.MUTATOR = None
        h.s.DEADLINE = None
        h.runtime.STOP.clear()

    def direct_device(self, peer):
        generation = h.policy.Generation(1, 1, 1, 'device01.family.home.arpa',
            peer, 45000, LOCAL6 if ':' in peer else '192.0.2.8', 4500,
            '10.77.26.10', 'fd6d:fe83:ab27:2600::10', '10000001', '20000001')
        return SimpleNamespace(generation=generation)

    def direct_adapter(self):
        # route() requires no daemon/owner: only its bounded route reader.
        return object.__new__(h.fn.NativeFleetAdapter)

    def test_outer_family_selects_route_flag_and_inner_dual_stack_is_unchanged(self):
        for peer, flag in ((PEER6, '-inet6'), ('203.0.113.101', '-inet')):
            with self.subTest(peer=peer):
                device = self.direct_device(peer)
                g = device.generation
                calls = []

                def run(args, **kwargs):
                    calls.append((list(args), kwargs))
                    return route_result(args[-1])

                with patch.object(h.s, 'run', side_effect=run):
                    result = self.direct_adapter().route(device)
                self.assertEqual([x[0] for x in calls], [
                    ['/sbin/route', '-n', 'get', '-inet', g.vip4],
                    ['/sbin/route', '-n', 'get', '-inet6', g.vip6],
                    ['/sbin/route', '-n', 'get', flag, peer]])
                self.assertTrue(all(kw.get('check') is False for _, kw in calls))
                self.assertEqual(result, h.fc.Routes(g,
                    h.fc.Route(g.vip4, 'en0', True, True),
                    h.fc.Route(g.vip6, 'en0', True, True),
                    h.fc.Route(peer, 'en0', True, True)))
                REPORT['family_' + flag] = {'correct_outer_flag': True,
                    'inner_ipv4_and_ipv6_unchanged': True}

    def test_ipv6_peer_default_or_on_link_route_does_not_require_host_flag(self):
        device = self.direct_device(PEER6)

        def run(args, **kwargs):
            return route_result(args[-1], flags='UP,GATEWAY'
                if args[-1] == PEER6 else 'UP,HOST')

        with patch.object(h.s, 'run', side_effect=run):
            result = self.direct_adapter().route(device)
        self.assertEqual(result.peer, h.fc.Route(PEER6, 'en0', True, False))

    def scenario(self, mode):
        _, owner, proof, snaps, records, activity, _ = h.fixture(OUTER, PEER6)
        kernel = h.Kernel(owner)
        adapter = owner.fleet_adapter
        a = next(d for d in proof.devices if d.device_id == 'device01')
        b = next(d for d in proof.devices if d.device_id == 'device02')
        self.assertEqual(a.generation.peer4, PEER6)
        self.assertNotIn(':', b.generation.peer4)
        self.assertEqual(h.fs.endpoints(owner.session['fleet']), OUTER)
        fault = {'enabled': False}
        queries = []

        def run(args, **kwargs):
            args = list(map(str, args))
            if args[:3] == ['/sbin/route', '-n', 'get']:
                self.assertIs(kwargs.get('check'), False)
                queries.append(args)
                if fault['enabled'] and args[-1] == PEER6:
                    self.assertEqual(args[-2], '-inet6')
                    kernel.trace.append(args)
                    if mode == 'timeout':
                        raise subprocess.TimeoutExpired(args, 5)
                    if mode == 'exit':
                        return route_result(PEER6, code=1)
                    if mode == 'wrong_interface':
                        return route_result(PEER6, interface='utun8')
                    raise AssertionError('unknown failure mode')
            return kernel.run(args, **kwargs)

        with ExitStack() as stack:
            kernel.bind(stack)
            stack.enter_context(patch.object(h.s, 'run', side_effect=run))

            def read(_=10):
                adapter.last_context = 'a' * 32
                return h.ParseResult(copy.deepcopy(snaps), 0)

            stack.enter_context(patch.object(adapter, 'read_fleet', side_effect=read))
            stack.enter_context(patch.object(h.runtime.policies, 'parse_spd',
                side_effect=lambda _: copy.deepcopy(records)))
            stack.enter_context(patch.object(h.runtime.policies, 'policy_id_active',
                side_effect=lambda ident, *a, **k: activity[ident]))
            coordinator = h.fc.Coordinator(owner.session['fleet']['registry'],
                adapter, outer_endpoints=OUTER)
            self.assertEqual(coordinator.step().active, ('device01', 'device02'))
            self.assertEqual(kernel.guard_count, 1)
            before = len(kernel.trace)
            queries.clear()
            fault['enabled'] = True
            result = coordinator.step()
            self.assertEqual((result.state, result.active), ('ACTIVE', ('device02',)))
            self.assertIsNone(coordinator.failure)
            self.assertEqual(kernel.guard_count, 1)
            self.assertEqual(kernel.values, h.s.SYS)
            for destination, flag in ((b.generation.vip4, '-inet'),
                    (b.generation.vip6, '-inet6'), (b.generation.peer4, '-inet')):
                self.assertEqual(queries.count(['/sbin/route', '-n', 'get', flag, destination]), 3)
            kills = [args for args in kernel.trace[before:] if '-k' in args]
            self.assertEqual([args[-1] for args in kills],
                [a.generation.vip4] * 2 + [a.generation.vip6] * 2)
            self.assertTrue(all(b.generation.vip4 not in args
                and b.generation.vip6 not in args for args in kills))
            self.assertEqual(kernel.tables, {'active4': [b.generation.vip4],
                'active6': [b.generation.vip6]})
            self.assertFalse(any(args[0] in ('/bin/kill', '/usr/bin/kill', '/usr/bin/pkill')
                for args in kernel.trace))
            fault['enabled'] = False
            self.assertEqual(coordinator.step().active, ('device01', 'device02'))
            self.assertEqual(kernel.guard_count, 1)
        REPORT['ipv6_peer_' + mode] = {'ipv4_device_retained': True,
            'other_device_fresh_route_frames': 3, 'global_guards_after_initial': 0,
            'only_affected_device_states_cleared': True, 'ipv6_device_resumed': True}

    def test_ipv6_peer_timeout_only_narrows_affected_device(self):
        self.scenario('timeout')

    def test_ipv6_peer_nonzero_exit_only_narrows_affected_device(self):
        self.scenario('exit')

    def test_ipv6_peer_non_en0_route_only_narrows_affected_device(self):
        self.scenario('wrong_interface')

    def test_timeout_classification_keeps_unrelated_errors_visible(self):
        device = self.direct_device(PEER6)
        args = ['/sbin/route', '-n', 'get', '-inet6', PEER6]
        wrong = ['/sbin/route', '-n', 'get', '-inet', PEER6]

        class Derived(subprocess.TimeoutExpired):
            pass

        for error in (subprocess.TimeoutExpired(wrong, 5),
                subprocess.TimeoutExpired(args, 6), Derived(args, 5), OSError('unrelated')):
            with self.subTest(error=type(error).__name__):
                def run(command, **kwargs):
                    if command[-1] == PEER6:
                        raise error
                    return route_result(command[-1])

                with patch.object(h.s, 'run', side_effect=run), self.assertRaises(type(error)):
                    self.direct_adapter().route(device)


