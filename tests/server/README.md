# Offline core regression tests

From the repository root:

```sh
python3 -I -B tests/server/run.py
```

The runner imports the **exported current server modules**. Fixtures contain
only synthetic identities, RFC 5737 peer addresses,
policy metadata, and in-memory state. No private keys or packet captures are
used. Actual sockets and subprocess creation are explicitly denied by the
runner, in addition to mocking the native adapters.

Coverage includes two-device admission/removal, preserving the unaffected
device, narrow state cleanup, interrupted publication/recovery, registry drift,
untrusted state output, IKE rekey, policy-install/read interleaving, duplicate
reqids, unauthenticated identity claims, and the complete 48-event VICI budget.

`test_gate_readback_retry.py` covers known PF activation-readback failures:
the controller must confirm its closed guard, complete native cleanup, and
verify recovery before a retry. Three starts per rolling 15-minute window
remain the limit; persistent known failures wait for that budget to expire.
Interrupted cooldown, manual stop, failed recovery, unknown rules and changed
exception wrappers are exercised separately. Other failure types keep their
existing retry policy.

These tests verify Python control-plane behavior. They do not validate real
macOS PF/IPsec behavior, actual concurrent iPhones, leak prevention on a physical
iPhone, China–Malaysia paths, native build compatibility, or throughput.

`vici_fixture.py` and `registry.example.json` are reusable synthetic fixtures.
`test_native_fleet.py` additionally contains the in-memory native boundary used
by its integration tests. Original workspace paths and historical candidate
hash assertions were removed; all imports resolve inside this checkout.
