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

    def test_generated_dual_outer_rules_compile_for_empty_and_mixed_fleet(self):
        # Only synthetic fixtures enter the real syntax-only compiler.
        here = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(here/'server'))
        import outer_fixture as fixture
        import vici_fixture as v
        import fleet_policy as policy
        import fleet_vici
        events = [v.event(0,1,1),v.event(1,2,2)]
        v.inner(events[0])['local-host'] = fixture.LOCAL6.encode()
        v.inner(events[0])['remote-host'] = fixture.PEER6.encode()
        parsed = fleet_vici.parse_events(v.decode(events),v.REG,fixture.OUTER)
        rows = list(v.NATIVE)
        for i,snapshot in enumerate(parsed.snapshots.values()):
            rows += v.hosts(snapshot.generations[0],20+4*i)
        template = (here.parent/'server/runtime/family-vpn.fleet.pf').read_text()
        for active in (False,True):
            with self.subTest(active=active):
                snapshots = parsed.snapshots if active else {
                    d['device_id']:policy.Snapshot('absent') for d in v.REG['devices']}
                inventory = rows if active else v.NATIVE
                proof = policy.audit(v.REG,snapshots,inventory,
                    {r['id']:True for r in inventory},v.NATIVE,outer_endpoints=fixture.OUTER)
                text = policy.render(template,v.REG,proof)
                compiled = native.classify(compile_only(native.stable_rules_source(text)))
                ike6 = [line for line in compiled['filters'] if 'familyvpn_ike6' in line]
                self.assertEqual(len(ike6),2)  # UDP 500 and UDP 4500
                self.assertTrue(all('to '+fixture.LOCAL6 in line for line in ike6))


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Run as an ordinary user. No administrator access is needed.')
    unittest.main(verbosity=2)
