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
exception wrappers are exercised separately.

`test_known_recovery.py` extends that cooldown to the five exact known,
fully recovered service outcomes. It also exercises owned-child exit races
and distinguishes optional diagnostic output from required durable recovery.
`test_route_isolation.py` verifies that one device's route lookup failure or
timeout leaves the other device forwarding through fresh checks.
`test_soft_pause.py` exercises bounded same-process VICI recovery: data gates
close, the existing daemon and IKE sessions remain, and a full fresh admission
is required before reopening. Persistent failures fall back to full recovery.

`test_persistent_recovery.py` checks that unknown errors, failed startup,
configuration/state read failures and incomplete cleanup leave recovery alive.
It exercises exact owner retention, bounded starts, recovery after a condition
clears, and interruptible manual stop. `ATTENTION` is a retry state, not a
permanent shutdown. Required durable-state failure still prevents data admission.
`test_entry_recovery.py` checks fresh boot writer instances, retained supervisor
instances under the same lock, diagnostic failures, manual stop, and complete
read-only native checks when no journal exists.

These tests verify Python control-plane behavior. They do not validate real
macOS PF/IPsec behavior, actual concurrent iPhones, leak prevention on a physical
iPhone, China–Malaysia paths, native build compatibility, or throughput.

`vici_fixture.py` and `registry.example.json` are reusable synthetic fixtures.
`test_native_fleet.py` additionally contains the in-memory native boundary used
by its integration tests. Original workspace paths and historical candidate
hash assertions were removed; all imports resolve inside this checkout.

`test_outer_contract.py`, `test_outer_routes.py`, and `test_outer_handover.py`
cover explicit IPv6 outer endpoints, legacy IPv4 session recovery, exact dual
socket inventories, IPv6 SPD text, scoped PF ingress, mixed-family route failures,
and both directions of IPv4/IPv6 generation handover. A failed IPv6 peer route
must leave the unrelated IPv4 device forwarding. Their fixtures contain invented
addresses and remain inside the same socket/subprocess-denying runner; they do
not reproduce or publish any private packet capture or installation receipt.

`test_pf_nat_chain.py` covers the actual three-endpoint, two-arrow NAT display
with sanitized IPv4/IPv6 endpoints, every endpoint position, reverse direction,
legacy parentheses, and malformed-line rejection. Its concrete adapter test
retires device A while preserving B, then rejoins A without a shared guard.
`test_pf_retirement_defer.py` covers persistent unknown state output, bounded
read failures, residual states, deferred A rejoining, once-per-tick scoped
retries and recovery. Rule/table changes, delete failures, ownership changes,
and malformed receipts must remain visible. The existing residual-state test
now requires a truthful deferred receipt instead of a false cleanup success.

`test_selector_readiness.py` keeps a device with a bounded, nonmatching local
selector list pending/overlapping while its healthy peer remains active. It
retains every CHILD and its original state, rejects other invalid fields and
cross-device ownership collisions, and verifies normal multi-read readmission.
Malformed/oversized lists and unauthorized native selectors still fail closed.
