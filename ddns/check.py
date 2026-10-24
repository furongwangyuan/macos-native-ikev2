#!/usr/bin/env python3
"""Offline DDNS parser/scheduler checks with fake processes and no credentials."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
if os.geteuid()==0: raise SystemExit('Run checks as an ordinary user.')
subprocess.run([sys.executable,'-I','-B',str(HERE/'build.py')],check=True)
for name in ('helper/api-shape-tests.py','helper/error-path-tests.py','scheduler/review-tests.py','scheduler/watch-review-tests.py','scheduler/package-review-tests.py'):
    subprocess.run([sys.executable,'-I','-B',str(HERE/'build'/name)],check=True)
for rel,wanted in json.loads((HERE/'build/manifest.json').read_text()).items():
    assert hashlib.sha256((HERE/'build'/rel).read_bytes()).hexdigest()==wanted,rel
print(json.dumps({'passed':True,'network_or_credentials':False,'installed':False}))
