#!/usr/bin/env python3
"""Build the CRL verifier from source without installing it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-prefix', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--minimum-macos', default='26.0')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Ordinary build user required.')
    cc = Path(subprocess.check_output(['/usr/bin/xcrun', '--find', 'clang'], text=True).strip())
    sdk = args.sdk or Path(subprocess.check_output(
        ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip())
    source = HERE / 'public_crl_verify.c'
    library = args.openssl_prefix / 'lib/libcrypto.a'
    if not library.is_file() or not sdk.is_dir():
        parser.error('A built static OpenSSL library and a valid SDK are required.')
    if args.output.exists():
        parser.error('Choose a new output directory.')
    args.output.mkdir(parents=True)
    binary = args.output / 'public-crl-verify'
    argv = [str(cc), '-arch', 'arm64', '-std=c11', '-O2', '-Wall', '-Wextra',
        '-Werror', '-isysroot', str(sdk), '-mmacosx-version-min=' + args.minimum_macos,
        '-I' + str(args.openssl_prefix / 'include'), str(source), str(library), '-o', str(binary)]
    subprocess.run(argv, check=True, timeout=120)
    libraries = subprocess.check_output(['/usr/bin/otool', '-L', str(binary)], text=True)
    manifest = dict(version=1, source_sha256=sha(source), helper_sha256=sha(binary),
        static_library_sha256=sha(library), compiler_sha256=sha(cc),
        minimum_macos=args.minimum_macos, linked_libraries=libraries,
        deployment_bindings_created=False, installed=False)
    (args.output / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'built': str(binary), 'installed': False}))


if __name__ == '__main__':
    main()
