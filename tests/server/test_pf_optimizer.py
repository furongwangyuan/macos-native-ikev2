"""PF source and receipt regressions with all operating-system IO mocked."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fleet_gate
import native_gate


RULES = 'block drop quick inet6 to 2001:db8::1 tagged FAMILYVPN_EGRESS6\n'


class PFOptimizerRegression(unittest.TestCase):
    def test_source_directive_is_idempotent_and_guard_bytes_stay_unchanged(self):
        stable = native_gate.stable_rules_source(RULES)
        self.assertEqual(stable, 'set ruleset-optimization none\n' + RULES)
        self.assertEqual(native_gate.stable_rules_source(stable), stable)
        self.assertFalse(native_gate.GUARD.startswith('set ruleset-optimization'))

    def test_compile_uses_the_exact_persisted_source(self):
        gate = object.__new__(native_gate.Gate)
        with tempfile.TemporaryDirectory() as directory:
            def run(args):
                self.assertEqual(args[:6], [native_gate.PF, '-n', '-v', '-a', native_gate.ANCHOR, '-f'])
                self.assertEqual(Path(args[6]).read_text(), native_gate.stable_rules_source(RULES))
                return SimpleNamespace(stdout='block drop quick inet6 from any to 2001:db8::1\n')
            with patch.object(native_gate.s, 'RUN', Path(directory)), \
                    patch.object(native_gate.s, 'atomic', lambda p, text: Path(p).write_text(text)), \
                    patch.object(native_gate.s, 'run', run):
                path, expected = gate.compile_rules(RULES, 'active.pf')
                self.assertEqual(path.read_text(), native_gate.stable_rules_source(RULES))
                self.assertEqual(expected['filters'], ['block drop quick inet6 from any to 2001:db8::1'])

    def test_anonymous_table_name_mismatch_still_fails_exact_readback(self):
        gate = object.__new__(native_gate.Gate)
        expected = {'filters': ['block drop quick inet6 from any to <__automatic_1>'], 'nat': []}
        def run(args):
            return SimpleNamespace(stdout=('block drop quick inet6 from any to <__automatic_2>\n'
                                           if args[-1] == '-sr' else ''))
        with patch.object(native_gate.s, 'run', run):
            self.assertFalse(gate.rules_equal(expected))

    def test_single_gate_receipt_covers_the_saved_compilation_input(self):
        gate = object.__new__(native_gate.Gate)
        gate.session = {}
        gate.state = {}
        for name in ('guard', 'restore_sysctls', 'set_knob', 'save'):
            setattr(gate, name, lambda *args: None)
        gate.mode = lambda: True
        gate.rules_equal = lambda expected: True
        saved = native_gate.stable_rules_source(RULES).encode()
        gate.compile_rules = lambda text, name: (Path('/fixture/active.pf'), {'filters': ['x'], 'nat': []})
        with patch.object(native_gate.s, 'read', lambda p: saved), \
                patch.object(native_gate.s, 'values', lambda: native_gate.s.SYS), \
                patch.object(native_gate.s, 'run', lambda args: None):
            gate.activate(RULES)
        self.assertEqual(gate.session['gate_intent']['sha256'], hashlib.sha256(saved).hexdigest())
        self.assertNotEqual(gate.session['gate_intent']['sha256'], hashlib.sha256(RULES.encode()).hexdigest())

    def test_fleet_gate_receipt_covers_the_saved_compilation_input(self):
        state = {'allow_data': True, 'probe_mode': 'off', 'pf': {'guard': {'filters': ['guard'], 'nat': []}}}
        saved = native_gate.stable_rules_source(RULES).encode()
        gate = SimpleNamespace(state={'mode': 'guarded'}, closed=lambda: True,
            compile_rules=lambda text, name: (Path('/fixture/active.pf'), {'filters': ['x'], 'nat': []}),
            set_knob=lambda *args: None, rules_equal=lambda value: True, verify_active=lambda: True)
        owner = SimpleNamespace(session=state, gate=gate, check_local=lambda seconds: None,
                                registry_current=lambda: None, save=lambda: None)
        worker = fleet_gate.FleetGate(owner)
        worker.current = lambda: ()
        worker.rules = lambda proposed: RULES
        with patch.object(native_gate.s, 'read', lambda p: saved), \
                patch.object(native_gate.s, 'values', lambda: native_gate.s.SYS), \
                patch.object(native_gate.s, 'run', lambda args: None), \
                patch.object(fleet_gate.fleet_tables, 'read', lambda: {'active4': [], 'active6': []}):
            worker.replace((), ())
        self.assertEqual(state['gate_intent']['sha256'], hashlib.sha256(saved).hexdigest())
        self.assertEqual(state['gate_intent']['phase'], 'applied')
