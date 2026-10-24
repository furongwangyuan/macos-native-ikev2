"""Offline-only stable-device accounting migration candidate.

No file or system operations. A caller must separately authenticate the old
registry binding for a v2 migration: v2 journals contain names/IDs, not certificate
or address ownership. This module never authorizes or disconnects a VPN client.
"""
import copy
import json
import math

from ledger_core_v3 import Ledger
from registry import Invalid, check_update, monitor_maps, normalize, unique_pairs


def _accounting(previous, current, raw, epoch, wall):
    """Validate the complete old scope before adding IDs or changing labels."""
    previous = normalize(previous)
    current = check_update(previous, current)
    old_names = monitor_maps(previous)['devices']
    saved = Ledger(old_names, epoch, wall, persisted=raw).to_journal()
    names = monitor_maps(current)['devices']
    saved['names'] = names
    for ident in names:
        if ident not in saved['devices']:
            saved['devices'][ident] = dict(up=0, down=0, seen=False, since=None)
    return current, Ledger(names, epoch, wall, persisted=saved)


def migrate_v2(raw, *, previous_registry, registry, epoch, wall):
    """Return a v3 envelope; never infer or reassign an old device identity."""
    current, accounting = _accounting(previous_registry, registry, raw, epoch, wall)
    return dict(version=3, registry=copy.deepcopy(current), accounting=accounting.to_journal())


def loads(raw):
    """Decode bounded JSON without accepting duplicate or nonfinite values.

    Semantic validation requires RegistryLedger and its current wall clock.
    This decoder is deliberately not a trusted-file reader.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= 8 * 1024 * 1024:
        raise Invalid('journal input type or size')
    def reject(_):
        raise Invalid('nonfinite journal number')
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise Invalid('nonfinite journal number')
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                          parse_constant=reject, parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid('invalid journal encoding or JSON') from exc


class RegistryLedger:
    def __init__(self, registry, epoch, wall, persisted=None):
        current = normalize(registry)
        if persisted is None:
            accounting = Ledger(monitor_maps(current)['devices'], epoch, wall)
        else:
            if (type(persisted) is not dict or set(persisted) != {'version', 'registry', 'accounting'}
                    or type(persisted['version']) is not int or persisted['version'] != 3):
                raise Invalid('v3 journal envelope required')
            current, accounting = _accounting(persisted['registry'], current,
                                              persisted['accounting'], epoch, wall)
        self._registry = current
        self._ledger = accounting

    def to_journal(self):
        return dict(version=3, registry=copy.deepcopy(self._registry),
                    accounting=self._ledger.to_journal())

    def matches_registry(self, value):
        """Compare metadata without copying or exposing the private journal."""
        return self._registry == value

    def _decorate(self, snapshot):
        # Registration status does not replace the actual observed online state.
        result = copy.deepcopy(snapshot)
        result['schema_version'] = 3
        result['registry_revision'] = self._registry['revision']
        states = monitor_maps(self._registry)['states']
        for row in result['devices']:
            row['registration_state'] = states[row['id']]
        return result

    def observe(self, rows, *, wall, mono, server_running, unknown_devices=()):
        return self._decorate(self._ledger.observe(rows, wall=wall, mono=mono,
                                                   server_running=server_running,unknown_devices=unknown_devices))

    def unavailable(self):
        return self._decorate(self._ledger.unavailable())
