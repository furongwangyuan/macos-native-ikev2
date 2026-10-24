"""Offline API-shape privacy/decision checks. No root, network or real credential."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ddns_shape_candidate', HERE / 'update.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CANARY = 'SYNTHETIC_REFLECTED_SECRET_NEVER_LOG_9264'
ACK = b'{"status":"success","error_code":0,"content":["synthetic"]}'


class ShapeTests(unittest.TestCase):
    def setUp(self):
        self.block = patch.object(m.subprocess, 'run', side_effect=AssertionError('no real processes'))
        self.block.start()
        self.addCleanup(self.block.stop)

    def test_complete_known_schema_and_known_literal_classes(self):
        shape = m.api_response_shape(ACK)
        self.assertEqual(shape, {
            'parse': 'parsed', 'root_type': 'object', 'known_fields_complete': True,
            'extra_fields_present': False, 'status_present': True, 'status_type': 'string',
            'status_class': 'success_literal', 'error_code_present': True,
            'error_code_type': 'integer', 'error_code_class': 'zero',
            'content_present': True, 'content_type': 'array', 'content_strings_only': True})
        error = m.api_response_shape(b'{"status":"error","error_code":-1,"content":[]}')
        self.assertEqual(error['status_class'], 'error_literal')
        self.assertEqual(error['error_code_class'], 'minus_one')

    def test_missing_fields_extra_keys_and_string_code_are_distinguished(self):
        shape = m.api_response_shape(json.dumps({'status': 'success', 'error_code': '0', CANARY: CANARY}))
        self.assertTrue(shape['extra_fields_present'])
        self.assertFalse(shape['known_fields_complete'])
        self.assertFalse(shape['content_present'])
        self.assertEqual(shape['content_type'], 'missing')
        self.assertEqual(shape['error_code_type'], 'string')
        self.assertEqual(shape['error_code_class'], 'string_zero')
        self.assertNotIn(CANARY, json.dumps(shape))

    def test_content_string_null_nested_and_mixed_arrays_have_only_type_flags(self):
        for content, kind, strings in [(CANARY, 'string', None), (None, 'null', None),
                ({CANARY: CANARY}, 'object', None), ([CANARY, 3], 'array', False),
                ([CANARY], 'array', True)]:
            shape = m.api_response_shape(json.dumps({'status': 'success', 'error_code': 0, 'content': content}))
            self.assertEqual(shape['content_type'], kind)
            self.assertIs(shape['content_strings_only'], strings)
            self.assertNotIn(CANARY, json.dumps(shape))

    def test_reflected_fields_unknown_keys_and_numeric_values_never_escape(self):
        url = 'https://synthetic.invalid/?pwd=' + CANARY
        for status in (CANARY, url, {'nested': CANARY}, [CANARY], True):
            for code in (CANARY, url, 92647777777777777, -92647777777777, 1.5, False, None):
                raw = json.dumps({'status': status, 'error_code': code, 'content': [url], CANARY: url})
                shape = m.api_response_shape(raw)
                rendered = json.dumps(shape)
                for disallowed in (CANARY, url, '92647777777777', 'pwd=', 'synthetic.invalid'):
                    self.assertNotIn(disallowed, rendered)
                self.assertTrue(all(value is None or type(value) in (str, bool) for value in shape.values()))
                self.assertEqual(shape['status_class'], 'other_string' if type(status) is str else 'non_string')

    def test_invalid_duplicate_deep_nonfinite_oversized_and_nonobject_safe(self):
        cases = [(b'{', 'invalid_json'), (b'\xff', 'invalid_json'),
                 (b'{"status":"success","status":"error"}', 'duplicate_keys'),
                 (b'{"content":{"same":1,"same":2}}', 'duplicate_keys'),
                 (b'{"status":NaN}', 'invalid_json'),
                 (('[' * 1200 + ']' * 1200).encode(), 'invalid_json'),
                 (b'x' * 16385, 'body_limit'), (None, 'input_type_rejected')]
        for body, parse in cases:
            shape = m.api_response_shape(body)
            self.assertEqual(shape['parse'], parse)
            self.assertIsNone(shape['status_present'])
        for body, kind in [(b'[]', 'array'), (b'null', 'null'), (b'0', 'integer'),
                           (b'true', 'boolean'), (json.dumps(CANARY), 'string')]:
            shape = m.api_response_shape(body)
            self.assertEqual(shape['root_type'], kind)
            self.assertIsNone(shape['known_fields_complete'])
            self.assertNotIn(CANARY, json.dumps(shape))

    def test_acknowledgement_accepts_exact_minimal_success_and_no_ambiguous_shapes(self):
        self.assertEqual(m.api_result(ACK), 'acknowledged')
        minimal = b'{"status":"success"}'
        self.assertEqual(m.api_result(minimal), 'acknowledged')
        self.assertFalse(m.api_response_shape(minimal)['known_fields_complete'])
        self.assertEqual(m.api_response_shape(minimal)['status_class'], 'success_literal')
        for obj in [dict(status='success', error_code='0', content=[]),
                    dict(status='success', error_code=0, content=CANARY),
                    dict(status='success', error_code=0, content=[], extra=CANARY),
                    dict(status='success', error_code=False, content=[])]:
            body = json.dumps(obj).encode()
            self.assertEqual(m.api_response_shape(body)['parse'], 'parsed')
            self.assertEqual(m.api_result(body), 'unknown')

    def test_explicit_depth_boundary_for_arrays_objects_and_scalar_brackets(self):
        # Root containers count as depth one; malformed/deep data must not be
        # accepted merely because a newer interpreter allows deeper JSON trees.
        limit = m.API_JSON_MAX_DEPTH
        for opening, closing in [('[', ']'), ('{"child":', '}')]:
            allowed = opening * limit + 'null' + closing * limit
            rejected = opening * (limit + 1) + 'null' + closing * (limit + 1)
            for encode in (lambda value: value, lambda value: value.encode()):
                self.assertEqual(m.api_response_shape(encode(allowed))['parse'], 'parsed')
                self.assertEqual(m.api_response_shape(encode(rejected))['parse'], 'invalid_json')
                self.assertEqual(m.api_result(encode(rejected)), 'unknown')
        quoted = json.dumps({'status': 'success', 'error_code': 0,
                             'content': ['[{}]\\"' * 100]})
        self.assertEqual(m.api_response_shape(quoted)['parse'], 'parsed')
        self.assertEqual(m.api_result(quoted), 'acknowledged')
        # Size bounds apply to the decision parser as well as shape metadata.
        padded = '{"status":"success"}' + ' ' * 16384
        self.assertEqual(m.api_result(padded), 'unknown')

    def test_once_only_shape_event_and_unknown_still_never_verifies_credential(self):
        raw = json.dumps({'status': CANARY, 'error_code': '0', 'content': CANARY, CANARY: CANARY}).encode()
        saved, output = [], io.StringIO()
        with patch.object(m, 'ethernet_address', return_value='192.0.2.8'), \
                patch.object(m, 'observed_ipv4', return_value='8.8.8.8'), \
                patch.object(m, 'dns_state', return_value=('8.8.8.8', 300)), \
                patch.object(m, 'curl', return_value=(0, 200, raw)) as request, \
                contextlib.redirect_stdout(output):
            with self.assertRaises(m.Failure) as caught:
                m.update_once(Mock(), CANARY, read_state=lambda: {},
                    save_state=lambda value: saved.append(dict(value)), pause=lambda _: None, configure=True)
        self.assertEqual(str(caught.exception), 'api_not_verified_no_credential_saved')
        self.assertEqual(request.call_count, 1)
        self.assertEqual(saved[-1]['outcome'], 'unconfirmed')
        self.assertEqual(output.getvalue().count('api_response_shape'), 1)
        self.assertNotIn(CANARY, output.getvalue())
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(events[0]['event'], 'api_response_shape')
        self.assertEqual(events[0]['error_code_class'], 'string_zero')


if __name__ == '__main__':
    unittest.main(verbosity=2)
