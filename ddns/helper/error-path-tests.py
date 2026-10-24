"""No root, credentials or network: actual CLI error and UTF-8 shell output regressions."""
import importlib.util
import io
import json
import contextlib
import subprocess
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent

class Regression(unittest.TestCase):
    def test_failure_metadata_has_no_argument_collision(self):
        spec=importlib.util.spec_from_file_location('ddns_error_test',HERE/'update.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):module.say('failed',code='synthetic_fixed_error')
        result=json.loads(stream.getvalue())
        self.assertEqual(result['event'],'failed');self.assertEqual(result['code'],'synthetic_fixed_error')

    def test_ordinary_user_cli_error_is_safe_json(self):
        import os
        self.assertNotEqual(os.geteuid(),0)
        p=subprocess.run(['/usr/bin/python3','-I',str(HERE/'update.py'),'configure-once'],capture_output=True,timeout=5)
        self.assertEqual(p.returncode,1)
        self.assertEqual(p.stderr,b'')
        result=json.loads(p.stdout)
        self.assertEqual(result['event'],'failed')
        self.assertEqual(result['code'],'fixed_root_installation_required')

    def test_actual_generated_echo_works_in_utf8_locales(self):
        line=next(line for line in (HERE/'import-DDNS-password.command').read_text().splitlines() if '返回状态 ' in line)
        self.assertIn('${result}',line)
        for locale in ('C','en_US.UTF-8','zh_CN.UTF-8'):
            p=subprocess.run(['/bin/bash','-c','set -u\nresult=7\n'+line],capture_output=True,env={'PATH':'/usr/bin:/bin','LC_ALL':locale},timeout=3)
            self.assertEqual(p.returncode,0)
            self.assertIn('返回状态 7；'.encode(),p.stdout)

    def test_bootstrap_code_is_separate_from_terminal_input(self):
        source=(HERE/'import-DDNS-password.command').read_text()
        self.assertIn('-I -c "$BOOTSTRAP" "$HERE" </dev/tty',source)
        self.assertNotIn('-I - "$HERE"',source)
        self.assertIn('os.O_NOFOLLOW | os.O_NONBLOCK',source)
        self.assertIn('stat.S_ISREG',source)
        self.assertIn('/usr/bin/tee -i',source)

if __name__=='__main__': unittest.main(verbosity=2)
