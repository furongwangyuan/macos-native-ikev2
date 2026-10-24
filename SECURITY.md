# Security and deployment boundaries

This repository contains source and configuration examples. A repository clone
is not a running VPN and does not contain the original deployment's identities,
credentials, installed state, private monitoring data, or personal profiles.

## Credentials and device enrollment

Generate a separate client identity for each device. Keep the CA signing key,
server and client private keys, DDNS credentials, monitor upload credentials,
and generated `.mobileconfig` files outside the repository. The profile may
contain a private client identity even when installation does not ask for a
certificate password. Treat possession of that file as possession of the
device's VPN credential, and revoke a lost or shared identity.

Do not paste credentials into issues, pull requests, screenshots, shell command
arguments, or diagnostic reports. The `.gitignore` file is a guard against
accidental additions; it cannot remove material already committed to Git.

## Network and administrative scope

The native server configures IPsec policies, packet filtering, routing and
forwarding. Read the installation and recovery instructions before applying
machine-specific configuration. Use a dedicated backup of the original settings
and keep a local way to stop the service and restore networking.

Public IKEv2 endpoints normally expose UDP 500 and 4500. Do not expose the VICI
socket, CA signing interface, local control commands or local monitor directly
to the Internet. A remotely hosted monitor needs its own authenticated access
and upload credentials; a difficult-to-guess URL is not authentication.

The project aims to limit device-local failures to that device. Some incomplete
or inconsistent global kernel-state observations can still require a wider
recovery action. A successful build, an idle health check or mocked tests do not
prove all concurrent-device, roaming or failure cases are covered.

An ordinary iOS IKEv2 profile has platform-specific behavior for traffic capture,
connection attempts and system traffic. Do not infer a universal kill switch,
permanent Always On behavior, or immediate reconnection solely from profile
keys. Verify the configured device and OS version. A VPN does not hide GPS,
cellular-network metadata or application-level location permissions.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on the repository's Security tab
when it is available. If it is unavailable, open a minimal issue asking for a
private contact route; do not include credentials, private network details, or
an exploit against a live deployment in the public issue.

Include the affected source revision, OS and dependency versions, the smallest
reproduction, expected and observed behavior, and a sanitized trace. Remove
device names, domains, public IP addresses, certificate fingerprints, private
profiles and credentials before sharing diagnostics.

No response deadline or commercial support is promised. Review upstream
strongSwan, OpenSSL and Apple security updates as well as this repository.
