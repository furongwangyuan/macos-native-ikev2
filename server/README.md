# Server maintenance source

This directory contains the native macOS VPN control plane, device enrollment,
PKI lifecycle, and release templates exported from the maintained deployment.
It is a **source reference**, not an installer for a new Mac.

```sh
python3 -I -B server/tools/build_reference.py --check
python3 -I -B tests/server/run.py
python3 -I -B server/tools/build_reference.py --output build/reference-server
```

The builder needs only this checkout. It checks Python syntax and creates a
reference package with hashes of the actual exported files. It never creates
deployment receipts, changes the Mac network, installs launchd jobs, signs
certificates, or produces a privileged installer.

Deployment examples use `vpn.example.com`, `192.0.2.8`, and synthetic device
identities. `192.0.2.8` is a documentation address and cannot be used as the LAN
address of a real server. The original CA/profile hashes have been removed.
The original lifecycle checks remain in the source; they must not be bypassed
to force installation. See [source and configuration boundaries](../docs/server-source.md).

## Layout

- `runtime/`: session coordination, IPsec/SPD observation, per-device PF access,
  recovery, CRL verification, and profile creation.
- `control/`, `control-data/`: managed install/start/stop/device operations.
- `harness/`: owner/recovery observation and lifecycle integration.
- `release/`: unbound installer templates retained for review.
- `provisioning/`: initial CA/device tooling; credential generation is explicit.
- `compat/`: non-secret historical manifest metadata used to explain old guards.
- `tools/`: self-contained source validation/reference packaging.

The `runtime/vici` dependency retains its upstream MIT license. Native dependency
licenses are in [`native/licenses`](../native/licenses).
