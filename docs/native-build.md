# Native dependency build

The deployment uses strongSwan 6.1.0, OpenSSL 3.5.9, and pkgconf 3.0.10.
[`native/sources.lock.json`](../native/sources.lock.json) records the exact
upstream source archives and SHA256 values used by the reference build.

Upstream sources: [strongSwan downloads](https://download.strongswan.org/),
[OpenSSL 3.5.9 release](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9),
and [pkgconf releases](https://distfiles.ariadne.space/pkgconf/).

## Build without installing

Requires an Apple Silicon Mac, Apple Command Line Tools, Python 3, make, and Perl.
Run from the repository root as an ordinary user:

```sh
python3 -I -B native/download.py build/downloads
bash native/build-native.sh "$PWD/build/downloads" "$PWD/build/native"
```

The script checks all archive hashes, creates a new scratch directory, builds
pkgconf, builds static OpenSSL, runs the selected OpenSSL test suites, builds
strongSwan, runs `make check`, and stages the installation using `DESTDIR`.
It does not run `sudo`, change PF/IPsec, install launchd jobs, or copy into system
directories. The staged formal prefixes are:

```text
/usr/local/family-vpn/openssl-3.5.9
/usr/local/family-vpn/strongswan-6.1.0
/usr/local/etc/family-vpn
```

Enabled networking plugins include `kernel-pfkey`, `kernel-pfroute`,
`socket-default`, and `vici`. `kernel-libipsec` is not enabled. OpenSSL provides
crypto algorithms; ESP processing uses macOS kernel IPsec.

## SDK selection

The original tested recipe used SDK 26.5 with a macOS 26.0 deployment target.
The build script prefers that SDK when present, otherwise uses `xcrun`'s current
macOS SDK. Override explicitly when needed:

```sh
FAMILYVPN_SDKROOT="/path/to/MacOSX.sdk" \
FAMILYVPN_MACOS_TARGET=26.0 \
bash native/build-native.sh "$PWD/build/downloads" "$PWD/build/native"
```

The original machine's linker rejected an architecture entry in its SDK 27
libSystem stub; selecting SDK 26.5 avoided that toolchain mismatch. This is a
build observation, not a promise that every SDK or macOS update is compatible.
Record and review the compiler/SDK used for each rebuilt deployment.

## CRL helper

After building OpenSSL, use its staged prefix:

```sh
python3 -I -B native/build_crl_helper.py \
  --openssl-prefix "$PWD/build/native/native-rebuild.EXAMPLE/stage/usr/local/family-vpn/openssl-3.5.9" \
  --sdk "/path/to/MacOSX.sdk" \
  --output build/crl-helper
```

Replace the scratch directory and SDK path with actual paths. The output is a
local binary and a build manifest; neither is installed or committed. The
deployment's runtime bindings must be regenerated and independently verified
for the actual helper and compiler. Old binary hashes are not portable build
identities.

## Patch and license scope

The published recipe uses the unmodified upstream strongSwan source. No
experimental Apple PF_KEY/SADB_UPDATE/MIGRATE patch is enabled or shipped.
The installed plugin inspected during export matched the unpatched staged
build. Python control-plane fixes are separate from native strongSwan patches.

Preserve the upstream licenses in [`native/licenses`](../native/licenses),
the MIT license under `server/runtime/vici`, and individual source notices.
This repository ships sources and recipes, not prebuilt strongSwan/OpenSSL
binaries or Apple SDK contents.

The export validates script syntax and source digests. A full native rebuild
is an explicit separate operation; repository checks do not imply a fresh
native build, iPhone acceptance, cross-border latency, or 200 Mbps throughput.
