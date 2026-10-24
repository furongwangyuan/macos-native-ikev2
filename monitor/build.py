#!/usr/bin/env python3
"""Build locally pinned monitor sources. Never installs, starts, or reads a service."""
import ast
import hashlib
import json
from pathlib import Path
import re
import plistlib
import shutil

HERE = Path(__file__).resolve().parent
OUT = HERE / 'build'
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def files(root):
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}

def pin_entry(source, destination, expected):
    text = source.read_text()
    text, count = re.subn(r'^EXPECTED\s*=.*$', 'EXPECTED='+repr(expected), text, count=1, flags=re.M)
    assert count == 1
    ast.parse(text)
    destination.write_text(text)

def build():
    OUT.mkdir(exist_ok=True)
    for name in ('runtime', 'ui'):
        target = OUT/name
        if target.exists(): shutil.rmtree(target)
        shutil.copytree(HERE/name,target,ignore=shutil.ignore_patterns('__pycache__','*.pyc','test_*.py'))
    runtime = files(OUT/'runtime')
    (OUT/'runtime/installed-manifest.json').write_text(json.dumps(runtime,indent=2)+'\n')
    pin_entry(HERE/'service.py',OUT/'service.py',runtime)
    ui = files(OUT/'ui'); ui.pop('ui.py')
    pin_entry(HERE/'ui/ui.py',OUT/'ui/ui.py',ui)
    launchd=OUT/'launchd'; launchd.mkdir(exist_ok=True)
    for p in (HERE/'launchd').glob('*.plist'):
        plistlib.loads(p.read_bytes()); shutil.copyfile(p,launchd/p.name)
    manifest = files(OUT); manifest.pop('manifest.json',None)
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'built':True,'runtime_files':len(runtime),'ui_files':len(ui)+1,'installed':False}))

if __name__ == '__main__': build()
