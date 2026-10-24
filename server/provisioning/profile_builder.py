#!/usr/bin/env python3
"""Build an UNVERIFIED iOS IKEv2 candidate profile from existing credentials.

This tool creates no keys or certificates, does not install a profile, and makes
no network/compatibility claims. It never accepts or embeds the PKCS#12 password.
The encrypted PKCS#12 is nevertheless sensitive; output is created mode 0600.
See ios-design.txt for sources, server prerequisites and acceptance tests.
"""

import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import plistlib
import re
import sys
import uuid


SUITES = {
    "gcm256-ecp256": ("AES-256-GCM", 19),
    "cbc256-modp2048": ("AES-256", 14),
}
NOTICE = (
    "候选配置，尚未通过 iPhone 安装、认证、IPv4/IPv6、DNS、断线保护及跨境性能验收。"
    "安装时需要输入此设备 PKCS#12 的独立密码。请勿将此文件分享给其他设备。"
)


def nonempty(value):
    if not value.strip() or any(ord(c) < 32 for c in value):
        raise argparse.ArgumentTypeError("must be nonempty and contain no control characters")
    return value


def server_address(value):
    value = nonempty(value)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", value):
        raise argparse.ArgumentTypeError("use an ASCII DNS hostname or IP, without scheme/port/path")
    labels = value.rstrip(".").split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise argparse.ArgumentTypeError("invalid DNS hostname")
    return value


def dns_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("DNS server must be an IPv4/IPv6 address") from exc
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise argparse.ArgumentTypeError("DNS server must be a usable address reachable through the tunnel")
    return str(address)


def read_der(path):
    """Reject PEM/empty/truncated containers, without claiming X.509/P12 validation."""
    data = Path(path).read_bytes()
    if len(data) < 16 or len(data) > 2 * 1024 * 1024 or data[0] != 0x30:
        raise ValueError(f"{path}: expected a DER SEQUENCE, not PEM or an empty file")
    length_byte = data[1]
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if not 1 <= count <= 4 or len(data) < 2 + count:
            raise ValueError(f"{path}: invalid DER length")
        length = int.from_bytes(data[2:2 + count], "big")
        offset = 2 + count
    else:
        length, offset = length_byte, 2
    if offset + length != len(data):
        raise ValueError(f"{path}: truncated DER or unexpected trailing bytes")
    return data


def build_profile(args, ca_der, device_p12):
    # Stable per-server/device identifiers permit a deliberate later replacement.
    scope = uuid.uuid5(uuid.NAMESPACE_URL, args.remote_id + "\0" + args.device_id)
    prefix = "local.familyvpn.ikev2." + scope.hex

    def payload(kind, suffix, name):
        return {
            "PayloadType": kind,
            "PayloadVersion": 1,
            "PayloadIdentifier": prefix + "." + suffix,
            "PayloadUUID": str(uuid.uuid5(scope, suffix)).upper(),
            "PayloadDisplayName": name,
        }

    ca = payload("com.apple.security.root", "ca", "家庭 VPN CA")
    ca.update(PayloadCertificateFileName=Path(args.ca_der).name, PayloadContent=ca_der)
    identity = payload("com.apple.security.pkcs12", "identity", "家庭 VPN 设备身份")
    identity.update(PayloadCertificateFileName=Path(args.device_p12).name, PayloadContent=device_p12)
    encryption, group = SUITES[args.cipher_suite]
    ike_sa = {
        "EncryptionAlgorithm": encryption,
        "IntegrityAlgorithm": "SHA2-256",
        "DiffieHellmanGroup": group,
        "LifeTimeInMinutes": 1440,
    }
    child_sa = dict(ike_sa, LifeTimeInMinutes=60)
    ike = {
        "RemoteAddress": args.server,
        "RemoteIdentifier": args.remote_id,
        "LocalIdentifier": args.device_id,
        "AuthenticationMethod": "Certificate",
        "ExtendedAuthEnabled": 0,
        "CertificateType": args.certificate_type,
        "PayloadCertificateUUID": identity["PayloadUUID"],
        "ServerCertificateIssuerCommonName": args.ca_cn,
        "IncludeAllNetworks": 1,
        "ExcludeLocalNetworks": 0,
        "ExcludeAPNs": 0,
        "ExcludeCellularServices": 0,
        "ExcludeDeviceCommunication": 0,
        "OnDemandEnabled": 0,
        "OnDemandUserOverrideDisabled": 0,
        "DisconnectOnIdle": 0,
        "DisableMOBIKE": 0,
        "DeadPeerDetectionRate": "High",
        "EnablePFS": 1,
        "MTU": args.mtu,
        "IKESecurityAssociationParameters": ike_sa,
        "ChildSecurityAssociationParameters": child_sa,
    }
    vpn = payload("com.apple.vpn.managed", "vpn", args.name + "（待验收）")
    vpn.update({
        "UserDefinedName": args.name + "（待验收）",
        "PayloadDescription": NOTICE,
        "VPNType": "IKEv2",
        "IKEv2": ike,
        "DNS": {
            "DNSProtocol": "Cleartext",
            "ServerAddresses": list(dict.fromkeys(args.dns)),
            "SupplementalMatchDomains": [""],
            "SupplementalMatchDomainsNoSearch": 1,
        },
    })
    profile = payload("Configuration", "profile", args.name + "（候选配置，待验收）")
    profile.update({
        "PayloadDescription": NOTICE,
        "PayloadContent": [ca, identity, vpn],
        "PayloadRemovalDisallowed": False,
    })
    return profile


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-p12", required=True, help="existing password-protected per-device PKCS#12")
    parser.add_argument("--ca-der", required=True, help="existing root CA certificate in DER format")
    parser.add_argument("--server", required=True, type=server_address)
    parser.add_argument("--remote-id", required=True, type=nonempty, help="server IKE identity matching certificate SAN")
    parser.add_argument("--device-id", required=True, type=nonempty, help="unique IKE identity matching this device certificate SAN")
    parser.add_argument("--ca-cn", required=True, type=nonempty, help="Common Name of the server certificate issuer")
    parser.add_argument("--dns", required=True, action="append", type=dns_address, help="VPN-reachable DNS IP; repeat for multiple servers")
    parser.add_argument("--certificate-type", choices=("RSA", "ECDSA256", "ECDSA384", "ECDSA521", "RSA-PSS"), default="RSA")
    parser.add_argument("--cipher-suite", required=True, choices=tuple(SUITES), help="must match the validated server IKE/ESP proposals")
    parser.add_argument("--mtu", type=int, choices=range(1280, 1401), default=1280, metavar="1280..1400")
    parser.add_argument("--name", type=nonempty, default="家庭 VPN · 马来西亚")
    parser.add_argument("--candidate-output", required=True, help="new .mobileconfig file; existing files are never overwritten")
    return parser.parse_args()


def main():
    args = parse_args()
    output = Path(args.candidate_output)
    if output.suffix != ".mobileconfig":
        raise ValueError("candidate output must have the .mobileconfig suffix")
    ca_der = read_der(args.ca_der)
    device_p12 = read_der(args.device_p12)
    profile = build_profile(args, ca_der, device_p12)
    data = plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)
    # Round-trip encoding check only; not an iOS or network acceptance test.
    if plistlib.loads(data) != profile:
        raise ValueError("plist round-trip failed")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(output, flags, 0o600), "wb") as handle:
        handle.write(data)
    print(f"Created unverified candidate: {output.resolve()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
    print("PKCS#12 password was not read or embedded. No keys/certificates were created.")
    print("Credential contents, iPhone installation, routes, DNS, fail-closed behavior and performance remain unverified.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
