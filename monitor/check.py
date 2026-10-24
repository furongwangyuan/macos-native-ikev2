#!/usr/bin/env python3
"""Offline syntax, manifest, concurrent-device accounting and loopback-reader checks."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
if os.geteuid()==0: raise SystemExit('Run offline checks as an ordinary user.')
for root in ('runtime','ui'):
    for p in (HERE/root).rglob('*.py'): compile(p.read_bytes(),str(p),'exec')
for command in ([sys.executable,'-I','-B',str(HERE/'build.py')],
                [sys.executable,'-I','-B',str(HERE/'tests/test_concurrency.py')]):
    subprocess.run(command,check=True,cwd=HERE)
# This regression imports the server from its own directory and mocks its reader.
subprocess.run([sys.executable,'-B',str(HERE/'ui/test_read.py')],check=True,cwd=HERE/'ui')
manifest=json.loads((HERE/'build/manifest.json').read_text())
for name,wanted in manifest.items():
    assert hashlib.sha256((HERE/'build'/name).read_bytes()).hexdigest()==wanted,name
print(json.dumps({'passed':True,'scope':'offline modules and synthetic inputs; no VICI, credentials, or service changes'}))
