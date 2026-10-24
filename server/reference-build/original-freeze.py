# Historical build implementation; not a configured deployment entry.
"""Ordinary source inventory builder; does not install or execute native work."""
import ast
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE/'runtime'
PARENT='31c50e9feb8cec31d4799eafd2bb14f32a1c89d7a8b992f0064717ba0312c92c'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def main():
    if os.geteuid()==0 or sys.argv[1:] not in ([],['--check']):
        raise ValueError('ordinary source freeze or check only')
    parent=HERE.parent/'family-vpn-production-v8/runtime'
    parent_raw=(parent/'candidate-pins.json').read_bytes()
    if sha(parent_raw)!=PARENT:raise ValueError('frozen v8 parent manifest changed')
    for name,expected in json.loads(parent_raw)['runtime'].items():
        if sha((parent/name).read_bytes())!=expected:raise ValueError('frozen v8 parent resource changed')
    sys.path.insert(0,str(ROOT))
    service=importlib.import_module('service_supervisor')
    boot=importlib.import_module('boot_native')
    record=importlib.import_module('boot_record')
    files=set(boot.RUNTIME_RESOURCES)
    if len(service.RESOURCES)!=len(set(service.RESOURCES)):
        raise ValueError('duplicate execution closure')
    paths={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}
    expected=files|{'boot-runtime-pins.json','candidate-pins.json'}
    if paths!=expected:
        raise ValueError('source inventory differs: '+repr(sorted(paths^expected)))
    # Require isolated sources, no executable imports from a different candidate.
    for name in files:
        path=ROOT/name
        if path.is_symlink() or not path.is_file():raise ValueError('nonregular source')
        if path.suffix=='.py':ast.parse(path.read_bytes(),filename=name)
    bootpins=dict(version=1,profile=record.PROFILE,parent_manifest_sha256=PARENT,
        runtime={name:sha((ROOT/name).read_bytes()) for name in sorted(files)})
    bootraw=encoded(bootpins)
    runtime=dict(bootpins['runtime'],**{'boot-runtime-pins.json':sha(bootraw)})
    candidate=dict(version=1,journal_version=8,profile='production-native-fleet-v1',
        boot_profile=record.PROFILE,parent_manifest_sha256=PARENT,runtime=runtime,
        native_installed=False,phone_trial_verified=False,production_24h_verified=False)
    targets={'boot-runtime-pins.json':bootraw,'candidate-pins.json':encoded(candidate)}
    for name,raw in targets.items():
        if sys.argv[1:]==['--check']:
            if (ROOT/name).read_bytes()!=raw:raise ValueError('source pins stale: '+name)
        else:(ROOT/name).write_bytes(raw)
    print(json.dumps(dict(runtime_files=len(runtime),common_sha256=sha(targets['candidate-pins.json']),
        mode='check' if sys.argv[1:] else 'freeze',installed=False)))

if __name__=='__main__':
    raise SystemExit('Historical build source only. See reference-build/README.md; use tools/build_reference.py for the self-contained source package.')
