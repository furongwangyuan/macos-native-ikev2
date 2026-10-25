#!/usr/bin/env python3
"""Build a source reference only. No runtime imports or system modifications."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil

SERVER = Path(__file__).resolve().parents[1]
REPOSITORY = SERVER.parent


def inventory():
    records = {}
    for path in sorted(SERVER.rglob('*')):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('Source symlinks are not accepted: ' + str(path))
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if path.suffix == '.py':
            ast.parse(raw, filename=str(path.relative_to(SERVER)))
        if path.suffix in {'.mobileconfig', '.p12', '.pfx', '.pem', '.key'}:
            raise ValueError('Credential artifact in source tree')
        if raw[:4] in {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\x7fELF'}:
            raise ValueError('Compiled binary in source tree')
        records[path.relative_to(SERVER).as_posix()] = {
            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    required = ('runtime/fleet_coordinator.py', 'runtime/fleet_policy.py',
                'runtime/fleet_vici.py', 'runtime/outer_endpoints.py', 'runtime/service_supervisor.py',
                'runtime/crypto/public_crl_verify.c', 'runtime/vici/LICENSE',
                'control/production_service.py', 'harness/native_adapter.py')
    for name in required:
        if name not in records:
            raise ValueError('Missing source resource: ' + name)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run as an ordinary user; root is neither needed nor accepted.')
    if args.check == bool(args.output):
        parser.error('Choose exactly one of --check or --output.')
    files = inventory()
    manifest = dict(format_version=1, purpose='source-reference', files=files,
        deployable=False, privileged_installer_generated=False,
        missing_deployment_material=['fresh native build and build bindings',
            'site-specific network configuration', 'local CA and device identities',
            'reviewed installation and recovery receipts'])
    if args.output:
        output = args.output.absolute()
        build = REPOSITORY / 'build'
        if output == build or build not in output.parents:
            parser.error('Output must be a new directory below this checkout/build/.')
        for ancestor in [output, *output.parents]:
            if ancestor.is_symlink():
                parser.error('Output path must not contain a symlink.')
        if output.exists():
            parser.error('Output already exists; choose a new directory.')
        output.mkdir(parents=True)
        for name in files:
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SERVER / name, target)
        (output / 'REFERENCE-MANIFEST.json').write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        for name, item in files.items():
            if hashlib.sha256((output / name).read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('Reference copy readback failed: ' + name)
    print(json.dumps({'source_files': len(files), 'syntax_checked': True,
        'self_contained_source': True, 'deployable': False,
        'output': str(args.output) if args.output else None}, sort_keys=True))


if __name__ == '__main__':
    main()
