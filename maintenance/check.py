#!/usr/bin/env python3
"""Build a synthetic-user installer then test requests/repair with all IO mocked."""
import os
from pathlib import Path
import subprocess
import sys
HERE=Path(__file__).resolve().parent
if os.geteuid()==0: raise SystemExit('Run checks as an ordinary user.')
for name in ('build-install.py','review-tests.py','review-repair-tests.py'):
    subprocess.run([sys.executable,'-I','-B',str(HERE/name)],check=True)
