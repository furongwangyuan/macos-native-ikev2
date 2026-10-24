#!/bin/bash
# Reproduce the unpatched native build in a NEW scratch directory.
# Usage: bash native/build-native.sh /absolute/archive-dir /absolute/build-parent
# Requires the archives listed in sources.lock.json; all installs use DESTDIR.
# No sudo, signature override, package manager, source patches, or system writes.
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo 'Run this build as the ordinary user.' >&2; exit 1; }
[[ $# -eq 2 ]] || { echo 'Usage: build-native.sh /absolute/archive-directory /absolute/build-parent' >&2; exit 2; }
vpn_archives=$1
vpn_build_parent=$2
[[ "$vpn_archives" = /* && -d "$vpn_archives" && "$vpn_build_parent" = /* ]] || exit 2
mkdir -p "$vpn_build_parent"
(
    cd "$vpn_archives"
    shasum -a 256 -c <<'CHECKSUMS'
603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  openssl-3.5.9.tar.gz
fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4  strongswan-6.1.0.tar.bz2
9371b2f6372da574d4c6dc96fe9b1463037bcf6afcb6671c1555afde7b17e2de  pkgconf-3.0.10.tar.xz
CHECKSUMS
)
vpn_build=$(mktemp -d "$vpn_build_parent/native-rebuild.XXXXXX")
vpn_stage="$vpn_build/stage"
vpn_logs="$vpn_build/logs"
mkdir -p "$vpn_build/src" "$vpn_stage" "$vpn_logs"
tar -xzf "$vpn_archives/openssl-3.5.9.tar.gz" -C "$vpn_build/src"
tar -xjf "$vpn_archives/strongswan-6.1.0.tar.bz2" -C "$vpn_build/src"
tar -xJf "$vpn_archives/pkgconf-3.0.10.tar.xz" -C "$vpn_build/src"
if [[ -n "${FAMILYVPN_SDKROOT:-}" ]]; then
    export SDKROOT="$FAMILYVPN_SDKROOT"
elif [[ -d /Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk ]]; then
    export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
else
    export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
fi
export MACOSX_DEPLOYMENT_TARGET="${FAMILYVPN_MACOS_TARGET:-26.0}"
[[ -d "$SDKROOT" ]] || { echo 'Selected SDK is unavailable.' >&2; exit 1; }

cd "$vpn_build/src/pkgconf-3.0.10"
CFLAGS="-O2 -isysroot $SDKROOT -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" \
    ./configure --prefix="$vpn_build/build-tools" --disable-shared \
    --enable-static --disable-dependency-tracking > "$vpn_logs/pkgconf-configure.log" 2>&1
make -j6 > "$vpn_logs/pkgconf-build.log" 2>&1
make install > "$vpn_logs/pkgconf-install.log" 2>&1

cd "$vpn_build/src/openssl-3.5.9"
./Configure darwin64-arm64-cc --prefix=/usr/local/family-vpn/openssl-3.5.9 \
    --openssldir=/usr/local/etc/family-vpn/openssl no-shared \
    -isysroot "$SDKROOT" -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET > "$vpn_logs/openssl-configure.log" 2>&1
make -j6 build_sw > "$vpn_logs/openssl-build.log" 2>&1
make -j6 test TESTS='test_rsa test_ecdsa test_pkcs12 test_aesgcm test_rand test_evp test_x509 test_evp_kdf test_kdf' \
    > "$vpn_logs/openssl-tests.log" 2>&1
make install_sw DESTDIR="$vpn_stage" > "$vpn_logs/openssl-install.log" 2>&1

vpn_openssl="$vpn_stage/usr/local/family-vpn/openssl-3.5.9"
export PKG_CONFIG="$vpn_build/build-tools/bin/pkgconf"
export PKG_CONFIG_LIBDIR="$vpn_openssl/lib/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$vpn_stage"
export CFLAGS="-O2 -g -arch arm64 -isysroot $SDKROOT -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
export CPPFLAGS="-I$vpn_openssl/include"
export LDFLAGS="-L$vpn_openssl/lib -isysroot $SDKROOT -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
cd "$vpn_build/src/strongswan-6.1.0"
./configure --prefix=/usr/local/family-vpn/strongswan-6.1.0 \
    --sysconfdir=/usr/local/etc/family-vpn --localstatedir=/var \
    --with-piddir=/var/run/family-vpn --disable-defaults \
    --enable-charon --enable-ikev2 --enable-swanctl --enable-pki \
    --enable-openssl --enable-nonce --enable-random --enable-drbg \
    --enable-pem --enable-x509 --enable-pkcs1 --enable-pkcs8 \
    --enable-pubkey --enable-constraints --enable-revocation \
    --enable-socket-default --enable-kernel-pfkey --enable-kernel-pfroute \
    --enable-vici --enable-attr --enable-counters --enable-kdf \
    --enable-test-vectors > "$vpn_logs/strongswan-configure.log" 2>&1
make -j6 > "$vpn_logs/strongswan-build.log" 2>&1
printf '# Native unit-test configuration.\n' > "$vpn_build/tests.conf"
OPENSSL_MODULES="$vpn_openssl/lib/ossl-modules" \
    TESTS_STRONGSWAN_CONF="$vpn_build/tests.conf" \
    make -j6 check > "$vpn_logs/strongswan-tests.log" 2>&1
make install DESTDIR="$vpn_stage" > "$vpn_logs/strongswan-install.log" 2>&1

vpn_swan="$vpn_stage/usr/local/family-vpn/strongswan-6.1.0"
file "$vpn_openssl/bin/openssl" "$vpn_swan/libexec/ipsec/charon" "$vpn_swan/sbin/swanctl" \
    > "$vpn_logs/architecture.log"
otool -hv "$vpn_swan/lib/ipsec/libstrongswan.0.dylib" "$vpn_swan/lib/ipsec/libvici.0.dylib" \
    > "$vpn_logs/macho-headers.log"
DYLD_LIBRARY_PATH="$vpn_swan/lib/ipsec" STRONGSWAN_CONF="$vpn_build/tests.conf" \
    "$vpn_swan/libexec/ipsec/charon" --version > "$vpn_logs/charon-version.log"
printf 'Build and tests passed. Staged files: %s\nLogs: %s\n' "$vpn_stage" "$vpn_logs"
