#!/usr/bin/env python3
"""Read-only repository hygiene/syntax check. Never installs or runs VPN code."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', 'node_modules', '__pycache__', '.venv', '.next', '.wrangler',
        '.sites-runtime', '.vinext',
        'build', 'dist', 'downloads', 'generated', '.pytest_cache'}
PRIVATE_SUFFIXES = {'.p12', '.pfx', '.mobileconfig', '.key', '.pem', '.pcap',
                    '.pcapng', '.sqlite', '.sqlite3', '.db'}
SECRET_PATTERNS = (
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b'),
)


def main() -> int:
    failures: list[str] = []
    count = 0
    for path in sorted(ROOT.rglob('*')):
        rel = path.relative_to(ROOT)
        if set(rel.parts) & SKIP:
            continue
        if path.is_symlink():
            failures.append(f'{rel}: symlink is not a portable source file')
            continue
        if not path.is_file():
            continue
        count += 1
        if path.suffix.lower() in PRIVATE_SUFFIXES:
            failures.append(f'{rel}: private/runtime artifact suffix')
        try:
            source = path.read_text('utf-8')
        except UnicodeError:
            failures.append(f'{rel}: binary content is not allowed in this source release')
            continue
        if any(pattern.search(source) for pattern in SECRET_PATTERNS):
            failures.append(f'{rel}: possible credential content (not printed)')
        for username in re.findall(r'/Users/([A-Za-z0-9_-]+)/', source):
            if username not in {'example', 'YOUR_USER', '${USER}', '$USER'}:
                failures.append(f'{rel}: non-example home directory')
        if path.suffix == '.json':
            try:
                json.loads(source)
            except ValueError as error:
                failures.append(f'{rel}: invalid JSON: {error}')
        if path.suffix == '.py' and 'template' not in path.stem:
            try:
                ast.parse(source, filename=str(rel))
            except SyntaxError as error:
                failures.append(f'{rel}: Python syntax at line {error.lineno}')
        if path.suffix == '.md':
            # Plain relative file links, not anchors/URLs or code examples.
            for target in re.findall(r'\]\(([^\s()]+)\)', source):
                if '://' in target or target.startswith(('#', 'mailto:')):
                    continue
                target = unquote(target.split('#', 1)[0])
                if target and not (path.parent / target).exists():
                    failures.append(f'{rel}: missing linked file {target}')
    for item in failures:
        print('FAIL:', item)
    print(json.dumps({'source_files': count, 'failures': len(failures),
                      'system_configuration_changed': False}))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
