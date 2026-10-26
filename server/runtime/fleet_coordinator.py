"""Native-bound copy of the reviewed bounded three-frame fleet coordinator.

The in-memory fixture class remains for source comparison only; the Coordinator
accepts only the concrete NativeFleetAdapter. No original frozen file is changed.
"""
import copy
import outer_endpoints as endpoints
from dataclasses import dataclass, replace
import re

from registry import normalize
from fleet_policy import (DeviceProof, FleetProof, Generation, Snapshot, Fault,
                          PolicyTransition, audit, native_keys, registry_digest, checked_snapshot, checked_generation, MAX_IKE_EVENTS)
from fleet_vici import ParseResult
from fleet_transport import TransientTransportFault
from fleet_policy import continuation_target, same_device_authority


@dataclass(frozen=True)
class Route:
    destination: str
    interface: str
    up: bool
    host: bool


@dataclass(frozen=True)
class Routes:
    generation: Generation
    ipv4: Route
    ipv6: Route
    peer: Route


@dataclass(frozen=True)
class Observation:
    """One fake read frame; observe exposes only registry, parsed and context.

    context_token represents externally authenticated boot/daemon/config/local
    continuity. A string is not proof of any of those properties. Each subsequent
    inventory/route call is separately traced, preserving ordering assertions.
    """
    registry: dict
    parsed: ParseResult
    records: list
    activity: dict
    owned_native: list
    routes: dict
    context_token: str


@dataclass(frozen=True)
class View:
    registry: dict
    parsed: ParseResult
    context_token: str


@dataclass(frozen=True)
class CloseRequest:
    """Exact previously activated generation; never a delete-all request.

    policy_keys identify audited ownership metadata only. This contract does not
    authorize SPD deletion. The future adapter must first narrow the active VIP
    set, then clear all states for this exclusive device address pair (all generations),
    retain unrelated device addresses, and read back absence. This is NOT an
    SA/anchor-specific deletion receipt or an instantaneous packet-close proof.
    """
    device_id: str
    generation: Generation
    vip4: str
    vip6: str
    policy_keys: tuple


@dataclass(frozen=True)
class NarrowReceipt:
    remaining: tuple
    cleared: tuple
    # Removal from the active tables is confirmed, but address-state absence
    # is not. These requests cannot grant a new generation admission.
    deferred: tuple = ()


@dataclass(frozen=True)
class Result:
    state: str
    active: tuple
    unattributed_pending_count: int
    reason: str = ''
    global_guard_confirmed: bool = False


def _ordered(values):
    return tuple(sorted(values, key=lambda d: d.device_id))


def _request(device):
    g = device.generation
    return CloseRequest(device.device_id, g, g.vip4, g.vip6, device.hosts)


def _endpoint(g):
    return g.peer4, g.peer_port, g.local4, g.local_port


def _same_ike(g, old):
    return (g.ike_id, g.remote_id, g.vip4, g.vip6) == (
        old.ike_id, old.remote_id, old.vip4, old.vip6)


def _same_child(g, old):
    # VICI reports the current IKE endpoint for even the retained old CHILD.
    return _same_ike(g, old) and (g.child_id, g.reqid, g.spi_in, g.spi_out) == (
        old.child_id, old.reqid, old.spi_in, old.spi_out)


@dataclass(frozen=True)
class Handover:
    old: Generation
    peer4: str
    peer_port: int
    replacement: object = None
    retired: tuple = ()
    local4: object = None
    local_port: object = None

    def old_children(self):
        return (self.old,) + self.retired

    def historical_child(self, g):
        return any(_same_child(g, old) for old in self.old_children())

    def endpoint(self):
        return (self.peer4,self.peer_port,self.old.local4 if self.local4 is None else self.local4,
                self.old.local_port if self.local_port is None else self.local_port)

    def mapped_old(self):
        peer,port,local,local_port=self.endpoint()
        return replace(self.old,peer4=peer,peer_port=port,local4=local,local_port=local_port)

    def fresh_child(self, g):
        return (_same_ike(g, self.old)
                and _endpoint(g) == self.endpoint()
                and all(g.child_id != old.child_id and g.spi_in != old.spi_in
                        and g.spi_out != old.spi_out for old in self.old_children()))


class FakeAdapter:
    """Ordinary in-memory simulation only; no callbacks or native fallbacks.

    failures maps fixed operation names to one-based call numbers that raise.
    bad_receipts maps narrow/publish/guard_all to call numbers with wrong replies.
    observe frames must be Observation objects, or Fault objects for read failure.
    The trace and simulated gates are evidence of order, not kernel evidence.
    """
    def __init__(self, frames, *, failures=None, bad_receipts=None):
        self.frames = list(copy.deepcopy(frames))
        self.failures = copy.deepcopy(failures or {})
        self.bad_receipts = copy.deepcopy(bad_receipts or {})
        allowed = {'observe', 'inventory', 'route', 'narrow', 'narrow_after',
                   'publish', 'publish_after', 'guard_all'}
        for mapping in (self.failures, self.bad_receipts):
            if (type(mapping) is not dict or not set(mapping) <= allowed
                    or any(type(v) is not tuple or any(type(i) is not int or i < 1 for i in v)
                           for v in mapping.values())):
                raise Fault('invalid fake failure script')
        self.calls = {}
        self.trace = []
        self.gates = ()
        self.frame = None

    def _call(self, name, detail=()):
        self.calls[name] = self.calls.get(name, 0) + 1
        self.trace.append((name, copy.deepcopy(detail)))
        if self.calls[name] in self.failures.get(name, ()):
            raise Fault('fake injected ' + name + ' failure')

    def _bad(self, name):
        return self.calls[name] in self.bad_receipts.get(name, ())

    def observe(self):
        self._call('observe')
        if not self.frames:
            raise Fault('fake observation script exhausted')
        self.frame = self.frames.pop(0)
        if isinstance(self.frame, Exception):
            raise self.frame
        if type(self.frame) is not Observation:
            raise Fault('malformed fake frame')
        return copy.deepcopy(View(self.frame.registry, self.frame.parsed,
                                  self.frame.context_token))

    def inventory(self):
        self._call('inventory')
        return copy.deepcopy((self.frame.records, self.frame.activity, self.frame.owned_native))

    def route(self, device):
        self._call('route', device.device_id)
        if type(self.frame.routes) is not dict:
            raise Fault('route inventory is malformed')
        if not set(self.frame.routes) <= {d['device_id'] for d in self.frame.registry['devices']}:
            raise Fault('unknown route identity')
        return copy.deepcopy(self.frame.routes.get(device.device_id))

    def narrow(self, expected, remaining, requests):
        self._call('narrow', (remaining, requests))
        before = {d.device_id: d for d in expected}
        after = {d.device_id: d for d in remaining}
        removed = _ordered(before[i] for i in set(before) - set(after))
        if (self.gates != expected or not set(after) <= set(before)
                or any(before[i] != d for i, d in after.items())
                or requests != tuple(_request(d) for d in removed)):
            raise Fault('fake narrowing contract differs')
        self.gates = remaining
        self._call('narrow_after')
        return NarrowReceipt(remaining, ()) if self._bad('narrow') else NarrowReceipt(remaining, requests)

    def publish(self, expected, proposed, proof):
        self._call('publish', proposed)
        ready = {d.device_id: d for d in proof.devices if d.ready}
        if (self.gates != expected or any(ready.get(d.device_id) != d for d in proposed)
                or any(d not in proposed for d in expected)):
            raise Fault('fake publication contract differs')
        self.gates = proposed
        self._call('publish_after')
        return None if self._bad('publish') else proposed

    def guard_all(self, reason):
        self._call('guard_all', reason)
        self.gates = ()
        return False if self._bad('guard_all') else True


class Coordinator:
    """Bounded three-observation tick with independently gated device state.

    An unsupported changed snapshot narrows before SPD or route reads. Only an
    exact same-authority CHILD continuation may retain an already open VIP set
    while independently reading every proof again. Missing evidence never waits.
    The two preactivation frames must agree per device;
    publication has a third postcheck that can only remove devices. Ordinary
    absence/overlap/readiness/route loss narrows only identified devices. Unknown
    inventory, native/context/registry changes or unsupported provenance stops
    globally. No stopped instance can resume or accept a new registry in place.
    """
    def __init__(self, registry, adapter, outer_endpoints=endpoints.IPV4):
        from fleet_native import NativeFleetAdapter
        if type(adapter) is not NativeFleetAdapter:
            raise Fault('concrete NativeFleetAdapter required')
        self.outer_endpoints = endpoints.normalize(outer_endpoints)
        self.registry = normalize(registry)
        self.registry_sha256 = registry_digest(self.registry)
        self.adapter = adapter
        self.active = {}
        # A postcheck can observe teardown immediately after publication. Keep
        # the exact twice-verified, published-and-read-back generation even when
        # narrowing removes it from active before the following SPD audit.
        # This is distinct from last_verified, which also passed final postcheck.
        self.last_activated = {}
        self.last_verified = {}
        # Strictly audited metadata retained while closed, never activation or
        # deletion ownership. Mirrors the old reconnect controller's known_hosts.
        self.guarded_proofs = {}
        # Exact latest full SPD inventory, separate from ready CHILD provenance.
        # Closed overlap may disappear before this tick reaches publication;
        # its already-audited host keys still identify asynchronous teardown.
        self.audited_hosts = {}
        # At most two old/mapped CHILD pairs per device. This records closed
        # migration provenance, never deletion rights or readiness by itself.
        # Retain it after publication for the old CHILD's delayed DELETED row.
        self.handovers = {}
        self.native = None
        self.context = None
        self.state = 'NEW'
        self.pending_count = 0
        self.last_result = None
        self.failure = None
        self.transient_pauses = 0
        self.pending_retirements = {}
        self.continuities = {}  # at most 16 devices: fixed (published old, exact new)

    def _continuation(self, ident, snapshot, current):
        if ident in self.pending_retirements or ident in self.handovers:return None
        previous = self.continuities.get(ident)
        if previous is not None:
            old, new = previous
            if current not in (old,new):return None
            target = continuation_target(snapshot, old)
            if target != new or (snapshot.rekey_pair and snapshot.rekey_pair != (old,new)):return None
            return new
        target = continuation_target(snapshot, current)
        if target is None or target == current:return target
        if snapshot.rekey_pair and snapshot.rekey_pair[0] != current:return None
        self.continuities[ident] = (current,target)
        return target

    def _retirement_receipt(self, remaining, requests, receipt):
        if (type(receipt)is not NarrowReceipt or receipt.remaining!=remaining
                or type(receipt.cleared)is not tuple or type(receipt.deferred)is not tuple
                or any(type(r)is not CloseRequest for r in receipt.cleared+receipt.deferred)
                or any(r not in requests for r in receipt.cleared+receipt.deferred)
                or len(receipt.cleared)+len(receipt.deferred)!=len(requests)
                or len({r.device_id for r in receipt.cleared+receipt.deferred})!=len(requests)):
            raise Fault('narrowing or exclusive-address state-cleanup readback not confirmed')
        self.active = {d.device_id:d for d in remaining}
        for request in receipt.cleared:self.pending_retirements.pop(request.device_id,None)
        for request in receipt.deferred:self.pending_retirements[request.device_id]=request

    def _retry_retirements(self):
        if not self.pending_retirements:return
        expected=_ordered(self.active.values())
        requests=tuple(self.pending_retirements[i] for i in sorted(self.pending_retirements))
        receipt=self.adapter.retry_retirement(expected,requests)
        self._retirement_receipt(expected,requests,receipt)

    def _narrow(self, identifiers, reason):
        identifiers = set(identifiers) & set(self.active)
        if not identifiers:
            return
        for ident in identifiers:self.continuities.pop(ident,None)
        expected = _ordered(self.active.values())
        remaining = _ordered(d for i, d in self.active.items() if i not in identifiers)
        requests = tuple(_request(self.active[i]) for i in sorted(identifiers))
        receipt = self.adapter.narrow(expected, remaining, requests)
        self._retirement_receipt(remaining,requests,receipt)

    def _stop(self, reason):
        confirmed = False
        try:
            confirmed = self.adapter.guard_all(reason) is True
        except Exception:
            pass
        # Empty is the requested set, not a claim that failed closure succeeded.
        self.active = {}
        self.continuities.clear()
        self.state = 'STOPPED'
        self.last_result = Result('STOPPED', (), self.pending_count, reason, confirmed)
        return self.last_result

    def _retarget_handover(self, ident, handover, peer4, peer_port, local4, local_port):
        proof = self.guarded_proofs.get(ident)
        # A new CHILD may pass its first complete SPD/route frame and then
        # move again before publication. It is now old for the next target;
        # comparing only with the first admitted CHILD would reopen it there.
        if proof is not None and proof.ready and handover.fresh_child(proof.generation):
            return Handover(proof.generation, peer4, peer_port, retired=(handover.old,),local4=local4,local_port=local_port)
        return replace(handover, peer4=peer4, peer_port=peer_port,local4=local4,local_port=local_port)

    def _view(self):
        view = self.adapter.observe()
        if type(view) is not View or registry_digest(view.registry) != self.registry_sha256:
            raise Fault('registry scope changed; separate globally guarded transaction required')
        if (type(view.context_token) is not str
                or not re.fullmatch('[0-9a-f]{32}', view.context_token)):
            raise Fault('unknown authenticated-context evidence')
        if self.context is None:
            self.context = view.context_token
        elif self.context != view.context_token:
            raise Fault('global authenticated context changed')
        parsed = view.parsed
        devices = {d['device_id']:d for d in self.registry['devices']}
        ids = set(devices)
        if (type(parsed) is not ParseResult or type(parsed.snapshots) is not dict
                or set(parsed.snapshots) != ids
                or type(parsed.unattributed_pending_count) is not int
                or not 0 <= parsed.unattributed_pending_count <= MAX_IKE_EVENTS):
            raise Fault('incomplete or malformed parsed inventory')
        if any(type(s) is not Snapshot for s in parsed.snapshots.values()):
            raise Fault('unknown normalized snapshot')
        self.pending_count = parsed.unattributed_pending_count
        changed = []
        for i,d in self.active.items():
            snapshot=parsed.snapshots[i]
            if snapshot==Snapshot('unique',(d.generation,)) and i not in self.continuities:continue
            if self._continuation(i,snapshot,d.generation) is None:changed.append(i)
        self._narrow(changed, 'observed generation transition')
        visible_ikes = set()
        for ident, snapshot in parsed.snapshots.items():
            if (type(snapshot.generations) is not tuple or type(snapshot.deleted) is not tuple
                    or any(type(g) is not Generation for g in snapshot.generations)):
                raise Fault('unknown generation metadata')
            # Retirement is closed metadata, including a cold first read.
            # It cannot select a winner; real MOBIKE admission below still
            # requires exact historical or fresh CHILD/endpoint evidence.
            checked_snapshot(snapshot)
            for generation in snapshot.generations:
                checked_generation(generation,devices[ident],self.outer_endpoints)
            visible_ikes.update(g.ike_id for g in snapshot.generations)
            previous = self.last_activated.get(ident)
            if previous is None:
                # A complete first admission frame can be followed by a move
                # before publication. Its proof is closed provenance only.
                previous = self.guarded_proofs.get(ident)
            last = None if previous is None else previous.generation
            handover = self.handovers.get(ident)
            if handover is not None and snapshot.generations and any(
                    g.ike_id != handover.old.ike_id for g in snapshot.generations):
                # A fresh IKE uses the ordinary reconnect path. Mixed IKE
                # overlap stays closed under the exact-scope checks below.
                del self.handovers[ident]
                handover = None
            if (handover is not None and handover.replacement is None
                    and snapshot == Snapshot('unique', (handover.old,))):
                # A quick return to the exact original CHILD/endpoint can use
                # the ordinary full audit again; this does not itself reopen.
                del self.handovers[ident]
                handover = None
            # A new IKE from another network can coexist with the old IKE
            # while its authenticated DELETE awaits a reply. This is a closed
            # per-device replacement, not a MOBIKE update of the old CHILD.
            replacing_ike = snapshot.kind == 'overlap' and len({
                g.ike_id for g in snapshot.generations}) > 1
            moved = [] if last is None or replacing_ike else [g for g in snapshot.generations
                if g.ike_id == last.ike_id and _endpoint(g) != _endpoint(last)]
            if moved:
                if any(not _same_ike(g, last) for g in moved):
                    raise Fault('handover changed authenticated identity or local scope')
                current_endpoints = {_endpoint(g) for g in snapshot.generations}
                if len(current_endpoints) != 1:
                    raise Fault('handover has multiple current endpoints')
                peer4, peer_port, local4, local_port = next(iter(current_endpoints))
                if handover is None or (handover.replacement is not None
                                         and last == handover.replacement):
                    retired = () if handover is None else (handover.old,)
                    # Use the same retargeting path after a published move:
                    # a later ordinary rekey may already have passed a full
                    # frame without publication. It is old at the next port.
                    handover = Handover(last, last.peer4, last.peer_port, retired=retired)
                    handover = self._retarget_handover(ident, handover, peer4, peer_port, local4, local_port)
                    self.handovers[ident] = handover
                elif (peer4, peer_port, local4, local_port) != handover.endpoint():
                    handover = self._retarget_handover(ident, handover, peer4, peer_port, local4, local_port)
                    self.handovers[ident] = handover
            if handover is not None and handover.replacement is None and snapshot.generations:
                current_endpoints = {_endpoint(g) for g in snapshot.generations}
                if len(current_endpoints) != 1 or any(not _same_ike(g, handover.old) for g in snapshot.generations):
                    raise Fault('handover has ambiguous authenticated endpoint')
                peer4, peer_port, local4, local_port = next(iter(current_endpoints))
                if (peer4, peer_port, local4, local_port) != handover.endpoint():
                    handover = self._retarget_handover(ident, handover, peer4, peer_port, local4, local_port)
                    self.handovers[ident] = handover
            old_present = handover is not None and any(
                handover.historical_child(g) for g in snapshot.generations)
            if handover is not None and (handover.replacement is None or old_present):
                for g in snapshot.generations:
                    if (not _same_ike(g, handover.old)
                            or _endpoint(g) != handover.endpoint()
                            or not (handover.historical_child(g) or handover.fresh_child(g))):
                        raise Fault('handover CHILD provenance differs')
                continue
            if snapshot.kind == 'overlap':
                # CHILD rekey uses one current IKE endpoint. Separate IKEs
                # may have different remote endpoints during a reconnect;
                # both must retain this exact registered local/identity scope.
                # Neither generation wins: the full audit keeps this device
                # closed until unique admission passes its ordinary two reads.
                current = snapshot.generations[0]
                for g in snapshot.generations:
                    if (g.vip4, g.vip6, g.remote_id) != (
                            current.vip4, current.vip6, current.remote_id):
                        raise Fault('overlap changed authenticated identity or local scope')
                    if not replacing_ike and _endpoint(g) != _endpoint(current):
                        raise Fault('overlap is not one fixed-endpoint CHILD transition')
        # Direct normalized inputs retain the same whole-inventory IKE budget
        # as the complete VICI event exchange. Pending counts grant no owner.
        if len(visible_ikes) + parsed.unattributed_pending_count > MAX_IKE_EVENTS:
            raise Fault('parsed fleet IKE budget exceeded')
        return view

    def _handover_history(self):
        return {ident: tuple(g for old in h.old_children() for g in
                    (old, replace(old, peer4=h.endpoint()[0], peer_port=h.endpoint()[1],
                                  local4=h.endpoint()[2],local_port=h.endpoint()[3])))
                for ident, h in self.handovers.items()}

    def _remembered(self):
        # One complete inventory supersedes the previous one. These bounded
        # exact keys provide closed attribution only, never readiness or
        # deletion rights. A later empty inventory removes stale provenance.
        return dict(self.audited_hosts)

    def _recheck_transition(self, previous, original_native):
        """One closed recheck; never treat a failed read as normal teardown.

        Close before a full fresh audit. VICI can return the same normalized
        snapshot after a short-lived CHILD's policies disappear, so snapshot
        equality alone is not a persistent policy fault. This recheck cannot
        publish an active set; unresolved policy mismatches still fail audit.
        """
        if self.adapter.guard_all('fleet_host_policy_transition') is not True:
            raise Fault('fleet_transition_guard_unverified')
        self.active = {}
        self.pending_retirements.clear()
        self.continuities.clear()
        self.state = 'GUARDED'
        # A MOBIKE update briefly uses outbound DROP policies and can reinstall
        # old SPD entries with new IDs before its replacement CHILD is ready.
        # No unknown row is admitted: allow only three closed fresh audits,
        # then retain the existing hard failure if attribution never settles.
        for attempt in range(3):
            latest = self._view()
            records, activity, native = self.adapter.inventory()
            try:
                fresh = audit(self.registry, latest.parsed.snapshots, records, activity,
                              native, remembered=self._remembered(),
                              handovers=self._handover_history(),outer_endpoints=self.outer_endpoints)
                break
            except PolicyTransition as error:
                if attempt == 2 or (not self.handovers
                        and str(error) != 'fleet_handover_drop_transition'):
                    raise
        if (fresh.native != original_native or
                (self.native is not None and fresh.native != self.native)):
            raise Fault('fleet_transition_native_changed')
        self.native = fresh.native
        self.audited_hosts = {d.device_id: d.hosts for d in fresh.devices}
        self.guarded_proofs = {d.device_id: d for d in fresh.devices if d.hosts}
        self.last_result = Result('GUARDED', (), self.pending_count,
                                  'fleet_guarded_policy_transition')

    def _route_valid(self, device):
        evidence = self.adapter.route(device)
        if evidence is None:
            return False, None
        if type(evidence) is not Routes or type(evidence.generation) is not Generation:
            raise Fault('unknown route evidence shape')
        for r in (evidence.ipv4, evidence.ipv6, evidence.peer):
            if (type(r) is not Route or type(r.destination) is not str
                    or type(r.interface) is not str or type(r.up) is not bool or type(r.host) is not bool):
                raise Fault('unknown route record shape')
        g = device.generation
        valid = (evidence.generation == g
                 and evidence.ipv4 == Route(g.vip4, 'en0', True, True)
                 and evidence.ipv6 == Route(g.vip6, 'en0', True, True)
                 and evidence.peer.destination == g.peer4
                 and evidence.peer.interface == 'en0' and evidence.peer.up)
        return valid, evidence

    def _round(self):
        view = self._view()
        records, activity, native = self.adapter.inventory()
        try:
            proof = audit(self.registry, view.parsed.snapshots, records, activity, native,
                          remembered=self._remembered(), handovers=self._handover_history(),outer_endpoints=self.outer_endpoints,
                          continuing={i:d for i,d in self.active.items() if i in self.continuities})
        except PolicyTransition:
            self._recheck_transition(view, native_keys(native))
            return None
        if self.native is None:
            self.native = proof.native
        elif self.native != proof.native:
            raise Fault('native floor ownership changed')
        self.audited_hosts = {d.device_id: d.hosts for d in proof.devices}
        byid = {d.device_id: d for d in proof.devices}
        self._narrow([i for i, d in self.active.items() if byid.get(i) != d
                     and not (i in self.continuities and same_device_authority(d,byid.get(i)))],
                     'device policy proof changed')
        eligible, routes = {}, {}
        for ident in sorted(byid):
            d = byid[ident]
            if not d.ready or ident in self.pending_retirements:
                continue
            handover = self.handovers.get(ident)
            if handover is not None and not handover.fresh_child(d.generation):
                continue
            valid, evidence = self._route_valid(d)
            if not valid:
                self._narrow([ident], 'device exact route proof unavailable')
            elif ident not in self.pending_retirements:
                if ident not in self.active:
                    self.guarded_proofs[ident] = d
                eligible[ident] = d
                routes[ident] = evidence
        return view, proof, eligible, routes

    def _same_device(self, ident, first, second):
        same_snapshot=first[0].parsed.snapshots[ident] == second[0].parsed.snapshots[ident]
        transition=self.continuities.get(ident)
        if transition is None and any(frame[0].parsed.snapshots[ident].kind!='unique' for frame in (first,second)):
            return False
        if transition is not None:
            old,new=transition
            same_snapshot=all(continuation_target(frame[0].parsed.snapshots[ident],old)==new for frame in (first,second))
        return (ident in first[2] and ident in second[2]
                and same_snapshot
                and first[2][ident] == second[2][ident] and first[3][ident] == second[3][ident])

    def step(self):
        if self.state == 'STOPPED':
            return self.last_result
        try:
            if self.state == 'NEW':
                if self.adapter.guard_all('initial closed baseline') is not True:
                    raise Fault('initial global closure not confirmed')
                self.state = 'GUARDED'
            self._retry_retirements()
            first = self._round()
            if first is None:
                return self.last_result
            idle = (not self.active and not first[2]
                    and first[0].parsed.unattributed_pending_count == 0
                    and all(snapshot == Snapshot('absent')
                            for snapshot in first[0].parsed.snapshots.values())
                    and all(not device.hosts for device in first[1].devices))
            if idle:
                # The complete first round found no active, pending or retained
                # device scope. This tick cannot admit any device: admission
                # still requires two independently read eligible frames. Reuse
                # only this closed result for normal bookkeeping, never opening.
                second = post = first
            else:
                second = self._round()
                if second is None:
                    return self.last_result
                # If replacement first appeared in read two, one bounded extra
                # complete read supplies its second proof. Never publish from
                # one read or keep a device missing any complete evidence.
                crossing=[i for i in self.active if i in self.continuities
                          and i in first[2] and i in second[2]
                          and first[2][i] != second[2][i]
                          and same_device_authority(first[2][i],second[2][i])]
                if crossing:
                    first=second
                    second=self._round()
                    if second is None:return self.last_result
                stable = {i: d for i, d in second[2].items() if self._same_device(i, first, second)}
                # Route evidence itself must be consistent, even if each individual
                # read was structurally valid. Do not retain by mere device name.
                self._narrow(set(self.active) - set(stable), 'preactivation evidence differs')
                expected = _ordered(self.active.values())
                proposed = _ordered(stable.values())
                if proposed != expected:
                    receipt = self.adapter.publish(expected, proposed, second[1])
                    if receipt != proposed:
                        raise Fault('active-set publication readback not confirmed')
                    self.active = dict(stable)
                    self.last_activated.update(stable)
                    for ident, device in stable.items():
                        handover = self.handovers.get(ident)
                        if handover is not None and handover.fresh_child(device.generation):
                            self.handovers[ident] = replace(handover, replacement=device.generation)
                post = self._round()
                if post is None:
                    return self.last_result
            changed = [i for i in self.active if not self._same_device(i, second, post)]
            self._narrow(changed, 'postcheck changed; no new activation permitted')
            for ident, device in self.active.items():
                self.last_verified[ident] = device
                if post[0].parsed.snapshots[ident]==Snapshot('unique',(device.generation,)):
                    self.continuities.pop(ident,None)
            self.guarded_proofs = {d.device_id: d for d in post[1].devices
                if d.device_id in self.guarded_proofs and d.device_id not in self.active and d.hosts}
            self.state = 'ACTIVE' if self.active else 'GUARDED'
            self.last_result = Result(self.state, tuple(sorted(self.active)), self.pending_count,
                                      'fleet_retirement_pending' if self.pending_retirements else '')
            self.transient_pauses = 0
            return self.last_result
        except Exception as error:
            # An unavailable complete VICI observation never retains an open
            # data gate. Close the recorded active set, retain only its closed
            # provenance, and allow a fresh three-frame tick without restarting
            # charon/IKE. A third consecutive failure uses the existing full
            # service recovery path; no partial observation is reused.
            if (type(error)is TransientTransportFault and error.args in
                    (('vici_exchange_timeout',),('vici_exchange_eof',),
                     ('vici_exchange_io',),('vici_exchange_capacity',))
                    and self.transient_pauses<2):
                try:closed=self.adapter.guard_all('fleet_transient_observation') is True
                except Exception:closed=False
                if closed:
                    self.active={};self.pending_retirements.clear()
                    self.continuities.clear()
                    self.state='GUARDED';self.transient_pauses+=1
                    self.last_result=Result('GUARDED',(),self.pending_count,
                                            'fleet_transient_observation',True)
                    return self.last_result
            self.failure = error
            return self._stop(str(error) or type(error).__name__)
