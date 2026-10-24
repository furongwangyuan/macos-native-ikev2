#!/usr/bin/env python3
"""macOS PF compiler checks: every pfctl invocation includes syntax-only -n."""
import importlib
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'server/runtime'))
native = importlib.import_module('native_gate')
ADDRESSES = ['2001:db8::' + str(i) for i in range(1, 13)]
MANY = ('block drop quick inet6 to { ' + ', '.join(ADDRESSES)
        + ' } tagged FAMILYVPN_EGRESS6\n')


def compile_only(text):
    result = subprocess.run(['/sbin/pfctl', '-n', '-v', '-a', native.ANCHOR, '-f', '-'],
                            input=text, text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout


@unittest.skipUnless(sys.platform == 'darwin', 'Requires the macOS PF compiler')
class NativePFCompilerRegression(unittest.TestCase):
    def test_legacy_expansion_demonstrates_anonymous_table_generation(self):
        result = compile_only(MANY)
        self.assertIn('table <__automatic_', result)
        self.assertIn('to <__automatic_', result)

    def test_fixed_expansion_retains_all_explicit_ipv6_targets(self):
        result = compile_only(native.stable_rules_source(MANY))
        self.assertNotIn('__automatic_', result)
        self.assertEqual(native.classify(result)['filters'], [
            'block drop quick inet6 from any to ' + ip + ' tagged FAMILYVPN_EGRESS6'
            for ip in ADDRESSES])

    def test_prior_guard_semantics_are_unchanged(self):
        self.assertEqual(native.classify(compile_only(native.GUARD)),
                         native.classify(compile_only(native.stable_rules_source(native.GUARD))))


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Run as an ordinary user. No administrator access is needed.')
    unittest.main(verbosity=2)
