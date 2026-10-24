#!/usr/bin/env python3
"""Download fixed upstream source archives and verify their SHA256 digests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    args = p.parse_args()
    if os.geteuid() == 0:
        p.error('Run as the ordinary build user.')
    args.directory.mkdir(parents=True, exist_ok=True)
    for item in json.loads((HERE / 'sources.lock.json').read_text())['sources']:
        target = args.directory / item['file']
        if target.exists():
            if not target.is_file() or target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('Existing archive differs: ' + item['file'])
            print('verified ' + item['file'])
            continue
        fd, name = tempfile.mkstemp(prefix='.download-', dir=args.directory)
        temporary = Path(name)
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, 'wb') as out, urllib.request.urlopen(item['url'], timeout=60) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    out.write(chunk)
            if digest.hexdigest() != item['sha256']:
                raise ValueError('Downloaded archive digest differs: ' + item['file'])
            os.link(temporary, target)
            print('downloaded and verified ' + item['file'])
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
