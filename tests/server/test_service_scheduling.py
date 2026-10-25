"""The service template and fixed installer validator agree on scheduling."""
import importlib.util
from pathlib import Path
import plistlib
from types import SimpleNamespace
import unittest

SERVER = Path(__file__).resolve().parents[2] / 'server'
SPEC = importlib.util.spec_from_file_location(
    'scheduling_job_fixture', SERVER / 'control/production_service_job.py')
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)


class ServiceScheduling(unittest.TestCase):
    def test_fixed_validator_accepts_shipped_standard_template(self):
        raw = (SERVER / 'runtime/org.familyvpn.service.plist').read_bytes()
        self.assertEqual(plistlib.loads(raw)['ProcessType'], 'Standard')
        source = SimpleNamespace(BASE=SERVER / 'runtime', read=lambda path: raw)
        self.assertEqual(job.expected(source), raw)

    def test_changed_scheduling_or_lifecycle_is_not_silently_accepted(self):
        value = plistlib.loads(
            (SERVER / 'runtime/org.familyvpn.service.plist').read_bytes())
        for field, changed in (('ProcessType', 'Background'),
                               ('ProcessType', 'Interactive'),
                               ('ThrottleInterval', 0),
                               ('KeepAlive', True)):
            with self.subTest(field=field, value=changed):
                raw = plistlib.dumps(dict(value, **{field: changed}))
                source = SimpleNamespace(BASE=SERVER / 'runtime', read=lambda path: raw)
                with self.assertRaisesRegex(job.Refused, 'production_plist_not_fixed'):
                    job.expected(source)
