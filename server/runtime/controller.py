"""Bounded reconnect controller with an explicit injected native adapter.

The separate reviewed owner retains setup, floor/keeper ownership and cleanup.
This module has no standalone service entry point.
"""
from dataclasses import dataclass
import ipaddress
import re
import time
from typing import Optional, Tuple

import reviewed_policy as policy


class Fault(RuntimeError):
    pass


class Cancelled(RuntimeError):
    """Ordinary deadline or explicit user cancellation; still requires cleanup."""


class RouteTransition(Fault):
    """Only an exact VIP route's semantic proof changed after a VICI read."""


class PolicyTransition(Fault):
    """Native floors were verified, but a host policy differs from the snapshot."""
    pass


@dataclass(frozen=True)
class Generation:
    ike_id: int
    child_id: int
    reqid: int
    remote_id: str
    peer4: str
    peer_port: int
    local4: str
    local_port: int
    vip4: str
    vip6: str
    spi_in: str
    spi_out: str

    def info(self):
        return dict(self.__dict__)

    def endpoint(self):
        return self.peer4, self.peer_port, self.local4, self.local_port


@dataclass(frozen=True)
class Snapshot:
    kind: str  # absent / pending / unique / overlap
    generations: Tuple[Generation, ...] = ()
    # Retain DELETED provenance: it is never an activation candidate and must
    # be exactly the complete generation previously verified by the controller.
    deleted: Tuple[Generation, ...] = ()

    def __post_init__(self):
        expected = {'absent': (0,), 'pending': (0, 1), 'unique': (1,), 'overlap': (2,)}
        if self.kind not in expected or len(self.generations) not in expected[self.kind]:
            raise Fault('Invalid normalized snapshot')
        if (len(self.deleted) > 1 or any(g not in self.generations for g in self.deleted) or
                (self.deleted and self.kind not in ['pending', 'overlap'])):
            raise Fault('Invalid deleted CHILD provenance')


def parse_snapshot(text):
    """Trusted VICI metadata only; this does not authenticate an arbitrary string.

    An overlap is syntactically recognizable, but only the controller may decide
    whether its old CHILD is one it previously verified. No "largest ID wins".
    """
    if not text.strip():
        return Snapshot('absent')
    headers = re.findall(r'^(\S+): #([0-9]+), ([A-Z_]+), IKEv2,', text, re.M)
    if len(headers) != 1:
        raise Fault('Ambiguous IKE inventory; no replacement winner is guessed')
    name, _, ike_state = headers[0]
    if ike_state in ['CONNECTING', 'CREATED'] and 'INSTALLED' not in text:
        return Snapshot('pending')
    if name != 'family-vpn' or ike_state != 'ESTABLISHED':
        raise Fault('Unexpected IKE name/state')
    matches = list(re.finditer(r'^  (\S+): #([0-9]+), reqid ([0-9]+), ([A-Z_]+),', text, re.M))
    if not matches:
        # The reviewed parser still validates the established IKE identity and
        # endpoint before returning None for no installed CHILD.
        policy.sa_info(text)
        return Snapshot('pending')
    if len(matches) > 2:
        raise Fault('More than one attributable rekey overlap')
    prefix = text[:matches[0].start()]
    generations, states = [], []
    for i, match in enumerate(matches):
        state = match[4]
        if match[1] != 'internet' or state not in ['INSTALLED', 'REKEYING', 'REKEYED', 'DELETING', 'DELETED']:
            raise Fault('Unknown/partial CHILD layout needs real fixture review')
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        child = text[match.start():end]
        # Preserve state separately. Normalize only for reuse of the reviewed
        # full identity/proposal/TS/host-VIP checks; pending never opens traffic.
        normalized = re.sub(r'^(  internet: #[0-9]+, reqid [0-9]+), ' + state + ',',
                            r'\1, INSTALLED,', child, count=1, flags=re.M)
        # swanctl list_sas.c prints CHILD DH on rekey (unlike the initial
        # IKE_AUTH CHILD). Accept only our configured GCM256/ECP256 suffix,
        # leaving all other proposals/ESN/additional exchanges rejected.
        normalized = re.sub(r'^(  internet: [^\n]+, ESP:AES_GCM_16-256)/ECP_256$',
                            r'\1', normalized, count=1, flags=re.M)
        info = policy.sa_info(prefix + normalized)
        if info is None:
            raise Fault('Incomplete authenticated CHILD metadata')
        spis = []
        for direction in ['in', 'out']:
            values = re.findall(r'^    ' + direction + r'\s+([0-9a-fA-F]{8}),', child, re.M)
            if len(values) != 1 or int(values[0], 16) == 0:
                raise Fault('Missing/ambiguous ESP SPI metadata')
            spis.append(values[0].lower())
        generations.append(Generation(**info, spi_in=spis[0], spi_out=spis[1]))
        states.append(state)
    if len(set(generations)) != len(generations) or len({x.child_id for x in generations}) != len(generations):
        raise Fault('Duplicate CHILD generation')
    # strongSwan 6.1.0 child_delete.c retains an old DELETED inbound SA for
    # delete_rekeyed_delay (5s here). VICI intentionally still exports its full
    # metadata. Preserve that state while waiting for a unique INSTALLED child.
    deleted = tuple(g for g, state in zip(generations, states) if state == 'DELETED')
    if len(generations) == 2:
        return Snapshot('overlap', tuple(generations), deleted)
    return Snapshot('unique' if states[0] == 'INSTALLED' else 'pending', tuple(generations), deleted)


def record_key(record):
    return (record['id'], record['src'], record['dst'], record['direction'],
            record['kind'], tuple(record['requests']))


def expected_native(records):
    specs = [('0.0.0.0/0', '10.77.26.0/24', 'generate'),
             ('::/0', 'fd6d:fe83:ab27:2600::/64', 'generate'),
             ('0.0.0.0/0', '10.77.26.253/32', 'discard')]
    if len(records) != 3 or len({r['id'] for r in records}) != 3:
        raise Fault('Exactly two journaled floors plus one held keeper required')
    for src, dst, kind in specs:
        found = [r for r in records if (r['src'], r['dst'], r['kind']) == (src, dst, kind)]
        if len(found) != 1 or found[0]['direction'] != 'out' or found[0]['requests'] or found[0]['id'] <= 0:
            raise Fault('Native ownership/keeper scope differs')
    return tuple(sorted(record_key(r) for r in records))


def host_matches(record, generation):
    """Single policy semantics: never infer protection from an arbitrary VIP tag."""
    info = generation.info()
    for family, vip in [(4, generation.vip4), (6, generation.vip6)]:
        host = str(ipaddress.ip_network(vip))
        anynet = '0.0.0.0/0' if family == 4 else '::/0'
        for direction in ['in', 'out']:
            src, dst = (host, anynet) if direction == 'in' else (anynet, host)
            outer = (generation.peer4, generation.local4) if direction == 'in' else (generation.local4, generation.peer4)
            req = 'esp/tunnel/' + '-'.join(outer) + '/unique'
            if (record['src'], record['dst'], record['direction'], record['kind']) == (src, dst, direction, 'ipsec'):
                return record['requests'] in [[req + ':' + str(info['reqid'])], [req + '#' + str(info['reqid'])]]
    return False


@dataclass(frozen=True)
class Proof:
    ready: bool
    generation: Optional[Generation]
    native: tuple
    hosts: tuple
    policy_ids: tuple


def audit_inventory(records, active, owned_native, snapshot, remembered_hosts=()):
    """No mutations. active is exact-ID/type/direction SPDGET results supplied
    by the future trusted adapter; dump-visible DEAD entries are not active.
    """
    native = expected_native(owned_native)
    if len({r['id'] for r in records}) != len(records) or set(active) != {r['id'] for r in records}:
        raise Fault('Incomplete/duplicate exact-ID policy inventory')
    if any(type(v) is not bool for v in active.values()):
        raise Fault('Unknown policy activity response')
    nonipsec = [r for r in records if r['kind'] != 'ipsec']
    if tuple(sorted(record_key(r) for r in nonipsec)) != native or not all(active[r['id']] for r in nonipsec):
        raise Fault('Required floor/keeper missing, inactive, replaced, or extra policy')
    hosts = [r for r in records if r['kind'] == 'ipsec']
    known = set(remembered_hosts)
    for r in hosts:
        matches = any(host_matches(r, g) for g in snapshot.generations)
        if not matches and record_key(r) not in known:
            raise PolicyTransition('Host policy no longer matches the observed generation')
    # Multiple active policies with the same selector are ambiguous even when
    # their reqids differ. Do not choose one based on ID or dump order.
    selectors = [(r['direction'], r['src'], r['dst']) for r in hosts if active[r['id']]]
    if len(selectors) != len(set(selectors)):
        raise Fault('Ambiguous duplicate active host selectors')
    generation = snapshot.generations[0] if snapshot.kind == 'unique' else None
    keys = tuple(sorted(record_key(r) for r in hosts))
    if generation is None or len(hosts) != 4 or not all(active[r['id']] for r in hosts):
        return Proof(False, generation, native, keys, ())
    try:
        ids = policy.verify_spd(hosts, generation.info())
    except ValueError:
        return Proof(False, generation, native, keys, ())
    return Proof(True, generation, native, keys, ids)


class Controller:
    """Injected runtime contract, not an installed daemon or crash watchdog.

    Runtime methods: guard(reason,timeout), close_forwarding(timeout),
    stop_observers(timeout), observe(timeout)->Snapshot, audit(snapshot,known,
    timeout)->Proof, check_routes(generation,timeout), check_local(timeout),
    activate(generation,proof,timeout), wait(seconds), save_event(event).
    audit must use original journaled native records + current exact SPDGET;
    check_local verifies daemon identity, VICI, PF reference, ALF and uplink.
    activate must use exact VIP NAT/return4 and the original held native records.
    """
    def __init__(self, runtime, deadline, monotonic=time.monotonic, transition_seconds=30, rekey_after_seconds=None,
                 generation_limit=32):
        if generation_limit is not None and (type(generation_limit)is not int or generation_limit<=0):
            raise ValueError('Invalid generation limit')
        self.generation_limit=generation_limit
        self.r = runtime
        self.deadline, self.clock = deadline, monotonic
        self.transition_seconds = transition_seconds
        self.state = 'NEW'
        self.active = self.last = None
        self.native = None
        self.known_hosts = ()
        self.transition_start = None
        self.generation_count = 0
        self.failure = None
        self.stop_reason = None
        self.active_since = None
        self.rekey_after = rekey_after_seconds
        self.rekey_attempted = False
        self.rekey_target = None
        self.rekey_observed = False

    def budget(self):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise Cancelled('Window deadline reached')
        return min(5, remaining)

    def close(self, reason):
        # guard and its precise pool-state clear precede observer work/reporting.
        try:
            self.r.guard(reason, 5)
        except Exception:
            try:
                self.r.close_forwarding(5)
            finally:
                self.state = 'STOPPED'
            raise
        self.active = None
        self.r.stop_observers(5)

    def stop(self, reason):
        self.stop_reason = reason
        try:
            self.close(reason)
        finally:
            self.state = 'STOPPED'
        self.r.save_event({'event': 'stopped', 'reason': reason, 'full_cleanup_required': True})

    def waiting(self, reason):
        if self.state not in ['WAITING', 'VERIFYING']:
            self.close(reason)
        self.state = 'WAITING'
        if self.transition_start is None:
            self.transition_start = self.clock()

    def validate_change(self, snapshot):
        if any(g != self.last for g in snapshot.deleted):
            raise Fault('Deleted CHILD is not the previously verified full generation')
        if snapshot.kind == 'overlap':
            if self.last is None or self.last not in snapshot.generations:
                raise Fault('Rekey overlap has no previously verified old CHILD')
            for g in snapshot.generations:
                if (g.ike_id, g.endpoint(), g.vip4, g.vip6, g.remote_id) != (
                        self.last.ike_id, self.last.endpoint(), self.last.vip4,
                        self.last.vip6, self.last.remote_id):
                    raise Fault('Overlap cannot be attributed to one fixed-endpoint CHILD rekey')
        for g in snapshot.generations:
            if self.last is not None and g.ike_id == self.last.ike_id and g.endpoint() != self.last.endpoint():
                raise Fault('Same-IKE endpoint/port change is outside this mobike=no test')
        if len(snapshot.generations) == 1 and self.last is not None:
            g = snapshot.generations[0]
            if g.ike_id == self.last.ike_id and (g.vip4, g.vip6) != (self.last.vip4, self.last.vip6):
                raise Fault('Same-IKE VIP mutation is outside controlled CHILD rekey')

    def recheck_transition(self, previous, proof, reason):
        """A narrow inconsistent read is not itself proof of normal teardown.

        Close first, then require a different trusted VICI snapshot AND a new
        complete native/local audit. Same-generation route/policy damage,
        unknown objects, native changes and endpoint mutations still stop.
        Nothing here activates a replacement; the next tick uses all gates.
        """
        self.close(reason)
        self.state = 'WAITING'
        if self.transition_start is None:
            self.transition_start = self.clock()
        latest = self.r.observe(self.budget())
        if latest == previous:
            raise Fault('Route/policy proof failed without an attributable generation transition')
        self.validate_change(latest)
        self.r.check_local(self.budget())
        known = set(self.known_hosts)
        # A fully verified earlier SPD proof may become DEAD before activation.
        # Remember exact metadata only; never grant policy deletion ownership.
        if proof is not None and proof.ready:
            known.update(proof.hosts)
        fresh = self.r.audit(latest, tuple(sorted(known)), self.budget())
        if self.native is None:
            self.native = fresh.native
        if fresh.native != self.native:
            raise Fault('Held native policy ownership changed during guarded transition')
        if latest.kind == 'absent' and not fresh.hosts:
            self.transition_start = None
            self.known_hosts = ()
            if self.rekey_target is not None:
                self.r.save_event({'event': 'rekey-interrupted-by-disconnect'})
                self.rekey_target = None
        else:
            if self.clock() - self.transition_start > self.transition_seconds:
                raise Fault('Guarded route/policy transition did not settle')
            self.known_hosts = tuple(sorted(known | set(fresh.hosts)))
        self.r.save_event({'event': 'guarded-read-transition', 'reason': reason,
                          'next_snapshot': latest.kind})

    def routes_current(self, generation, snapshot, proof):
        try:
            self.r.check_routes(generation, self.budget())
            return True
        except RouteTransition:
            self.recheck_transition(snapshot, proof, 'exact VIP route changed during generation read')
            return False

    def tick(self):
        if self.state == 'STOPPED':
            return False
        try:
            self.budget()
            if self.state == 'NEW':
                self.close('initial reconnect waiting guard')
                self.state = 'WAITING'
            snapshot = self.r.observe(self.budget())
            if self.active is not None and (snapshot.kind != 'unique' or snapshot.generations[0] != self.active):
                self.waiting('authenticated generation disappeared or changed')
            self.validate_change(snapshot)
            self.r.check_local(self.budget())
            try:
                proof = self.r.audit(snapshot, self.known_hosts, self.budget())
            except PolicyTransition:
                self.recheck_transition(snapshot, None, 'host SPD changed during generation read')
                return True
            if self.native is None:
                self.native = proof.native
            if proof.native != self.native:
                raise Fault('Held native policy ownership changed between generations')
            if (self.state in ['WAITING', 'VERIFYING'] and self.transition_start is not None and
                    not (snapshot.kind == 'absent' and not proof.hosts) and
                    self.clock() - self.transition_start > self.transition_seconds):
                raise Fault('Generation verification did not settle before transition deadline')
            if snapshot.kind != 'unique' or not proof.ready:
                self.waiting('waiting for a complete unique authenticated dual-stack generation')
                if snapshot.kind == 'absent' and not proof.hosts:
                    if self.rekey_target is not None:
                        self.r.save_event({'event': 'rekey-interrupted-by-disconnect'})
                        self.rekey_target = None
                    # Explicit DELETE and unobserved disappearance have identical
                    # server semantics: stay waiting within the original window.
                    self.transition_start = None
                    self.known_hosts = ()
                elif self.clock() - self.transition_start > self.transition_seconds:
                    raise Fault('Incomplete policy/CHILD transition did not settle')
                return True
            generation = snapshot.generations[0]
            if proof.generation != generation or len(proof.policy_ids) != 4:
                raise Fault('Verification proof belongs to another generation')
            if self.rekey_target == generation:
                self.waiting('waiting for requested CHILD replacement; old CHILD cannot reopen')
                if self.clock() - self.transition_start > self.transition_seconds:
                    raise Fault('Requested CHILD rekey did not settle')
                return True
            if self.active == generation:
                if not self.routes_current(generation, snapshot, proof):
                    return True
                if (self.rekey_after is not None and not self.rekey_attempted and
                        self.clock() - self.active_since >= self.rekey_after):
                    self.waiting('closing before one explicitly enabled exact-CHILD rekey')
                    # Identity was just audited; recheck after closing the gate.
                    if self.r.observe(self.budget()) != snapshot:
                        return True
                    self.rekey_attempted = True
                    self.rekey_target = generation
                    self.r.request_rekey(generation, self.budget())
                    self.r.save_event({'event': 'rekey-queued', 'ike_id': generation.ike_id,
                                      'child_id': generation.child_id})
                return True
            self.waiting('verifying new authenticated generation')
            self.state = 'VERIFYING'
            if not self.routes_current(generation, snapshot, proof):
                return True
            latest = self.r.observe(self.budget())
            if latest != snapshot:
                self.state = 'WAITING'
                return True
            try:
                again = self.r.audit(latest, self.known_hosts, self.budget())
            except PolicyTransition:
                self.recheck_transition(latest, proof, 'host SPD changed during final activation audit')
                return True
            if not again.ready or again.generation != generation or again.native != self.native or again.hosts != proof.hosts:
                self.state = 'WAITING'
                return True
            self.r.activate(generation, again, self.budget())
            # This postcheck detects, but cannot erase, a command-level race.
            # The held native floor/keeper must cover any no-SA interval.
            if self.r.observe(self.budget()) != snapshot:
                self.close('generation changed during PF activation')
                self.state = 'WAITING'
                return True
            if self.rekey_target is not None:
                old = self.rekey_target
                self.rekey_observed = (generation.ike_id == old.ike_id and generation.child_id != old.child_id and
                                       generation.spi_in != old.spi_in and generation.spi_out != old.spi_out)
                self.rekey_target = None
            self.active = self.last = generation
            self.active_since = self.clock()
            self.known_hosts = again.hosts
            self.transition_start = None
            self.generation_count += 1
            if self.generation_limit is not None and self.generation_count > self.generation_limit:
                raise Fault('Bounded generation limit exceeded')
            self.state = 'ACTIVE'
            self.r.save_event({'event': 'active', 'generation': self.generation_count,
                              'info': generation.info(), 'spd_ids': again.policy_ids})
            return True
        except Exception as error:
            if not isinstance(error, Cancelled):
                self.failure = error
            try:
                self.stop(type(error).__name__ + ': ' + str(error))
            except Exception as close_error:
                raise Fault('Protection close failed; immediate owner cleanup required') from close_error
            return False

    def run(self):
        try:
            while self.tick():
                self.r.wait(min(0.5, max(0, self.deadline - self.clock())))
        except BaseException:
            self.stop('controller interrupted')
            raise
        finally:
            if self.state != 'STOPPED':
                self.stop('controller leaving bounded loop')
        # Only the owner can confirm charon/SAD/floors/PF/ALF cleanup.
        if self.failure is not None:
            raise Fault('Reconnect validation failed: ' + str(self.failure)) from self.failure
        return {'generations': self.generation_count, 'reason': self.stop_reason,
                'rekey_attempted': self.rekey_attempted, 'rekey_observed': self.rekey_observed,
                'full_cleanup_required': True}


if __name__ == '__main__':
    raise SystemExit('Use only the reviewed installed owner after packaging; this pure module starts no service.')
