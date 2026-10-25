"""Real service reboot closure, archival and a fresh service lifecycle.

Reuses the fixed native reconciliation effects under its actual locks. Old
process/policy identities remain history. Permissions stay exactly as configured;
only a subsequent normal preflight may create a new owner or open forwarding.
"""
import copy
import os
import boot_native as native
import boot_record as r
import boot_reconcile as close
import boot_source as source
import boot_store
import native_support as s
import production_source as production
from supervisor_core import valid_state


def receipts():
    return s.STATE / 'production' / 'boot'


def receipt_path(record):
    return receipts() / (r.sha(record['new_boot'].encode()) + '-' + record['native_sha256'] + '.json')


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def record_receipt(value, record):
    keys = {'version', 'profile', 'boot_record_sha256', 'boot', 'native_sha256', 'context_sha256',
            'old_service_sha256', 'new_service', 'completed', 'intent', 'phase'}
    if (type(value) is not dict or set(value) != keys or type(value['version']) is not int
            or value['version'] != 1 or value['profile'] != 'production-boot-handoff-v1'
            or value['boot'] != record['new_boot'] or value['native_sha256'] != record['native_sha256']
            or value['context_sha256'] != record['context_sha256']
            or any(not r.exact_hash(value[k]) for k in ('boot_record_sha256', 'old_service_sha256'))
            or value['phase'] not in ('RETIRING', 'COMPLETE')
            or value['completed'] not in ([], ['native'], ['native', 'service'])
            or value['intent'] not in (None, 'native', 'service')):
        raise r.Refused('production_boot_handoff_shape')
    new = valid_state(value['new_service'])
    if (new['boot'] != record['new_boot'] or new['fingerprint'] != record['configuration_sha256']
            or new['phase'] != 'STOPPED' or new['reason'] != 'initial' or new['attempts'] != []
            or new['next_due'] != 0):
        raise r.Refused('production_boot_requires_new_stopped_state')
    next_key = ('native', 'service')[len(value['completed'])] if len(value['completed']) < 2 else None
    if value['intent'] is not None and value['intent'] != next_key:
        raise r.Refused('production_boot_handoff_order')
    if value['phase'] == 'COMPLETE' and (value['completed'] != ['native', 'service'] or value['intent'] is not None):
        raise r.Refused('production_boot_handoff_incomplete')
    return value


def closed_readback(io, store, record):
    io.held()
    if record['phase'] != 'RESTORED' or record['intent'] is not None:
        raise r.Refused('production_boot_close_not_complete')
    original, context = store.originals(record)
    old = r.bind(record, original, context)
    if source.kind(old) != 'production':
        raise r.Refused('production_boot_source_required')
    if (io.boot() != record['new_boot'] or io.implementation() != record['implementation_sha256']
            or io.configuration() != record['configuration_sha256']):
        raise r.Refused('production_boot_configuration_changed')
    production.verify_current_resources(context)
    io.closed_kernel()
    r.alf_scope(old, io.alf(), record['completed'])
    if io.alf() != old['alf_before']:
        raise r.Refused('production_boot_alf_not_restored')
    pf = io.pf(old)
    if (pf['sha256'] != old['pf']['before_sha'] or pf['root'] != 'baseline'
            or pf['anchor'] != dict(filters=[], nat=[])):
        raise r.Refused('production_boot_pf_not_restored')
    close.files_scope(io, old, record['completed'])
    return original, context


def finish(io, store, record, clock):
    original, context = closed_readback(io, store, record)
    files = production.unpack(context)
    old_service = files['service-state']
    # A previous service error is historical after the exact native state has
    # been restored and re-read above. It must not permanently veto recovery.
    valid_state(s.json_value(old_service))
    raw_record = s.read(native.RECORD)
    if r.validate(s.json_value(raw_record)) != record:
        raise r.Refused('production_boot_record_changed')
    path = receipt_path(record)
    s.directory(receipts())
    if present(path):
        raw = s.read(path)
        value = record_receipt(s.json_value(raw), record)
    else:
        if io.originals() != (original, context):
            raise r.Refused('production_boot_originals_changed_before_retirement')
        value = dict(version=1, profile='production-boot-handoff-v1', boot_record_sha256=r.sha(raw_record),
            boot=record['new_boot'], native_sha256=record['native_sha256'], context_sha256=record['context_sha256'],
            old_service_sha256=r.sha(old_service),
            new_service=dict(version=1, phase='STOPPED', boot=record['new_boot'],
                fingerprint=record['configuration_sha256'], attempts=[], next_due=0, reason='initial', updated=clock()),
            completed=[], intent=None, phase='RETIRING')
        record_receipt(value, record)
        store.write_new(native.ARCHIVES / ('service-' + r.sha(old_service) + '.json'), old_service)
        raw = r.encode(value)
        store.write_new(path, raw)
    if value['boot_record_sha256'] != r.sha(raw_record) or value['old_service_sha256'] != r.sha(old_service):
        raise r.Refused('production_boot_receipt_binding')
    targets = {'native': s.STATE / 'native-session.json', 'service': s.STATE / 'service-state.json'}
    before = {'native': original, 'service': old_service}
    after = {'native': None, 'service': r.encode(value['new_service'])}

    def scope():
        closed_readback(io, store, record)
        if s.read(path) != raw:
            raise r.Refused('production_boot_receipt_changed')
        for key, target in targets.items():
            observed = s.read(target) if present(target) else None
            allowed = (after[key],) if key in value['completed'] else (
                (before[key], after[key]) if value['intent'] == key else (before[key],))
            if observed not in allowed:
                raise r.Refused('production_boot_target_changed')

    def save():
        nonlocal raw
        record_receipt(value, record)
        if s.read(path) != raw:
            raise r.Refused('production_boot_receipt_cas')
        new_raw = r.encode(value)
        s.atomic(path, new_raw)
        if s.read(path) != new_raw:
            raise r.Refused('production_boot_receipt_readback')
        raw = new_raw

    scope()
    for key in ('native', 'service'):
        if key in value['completed']:
            continue
        value['intent'] = key
        save()
        scope()
        target = targets[key]
        if key == 'native':
            if present(target):
                if s.read(target) != original or s.read(native.ARCHIVES / ('native-' + r.sha(original) + '.json')) != original:
                    raise r.Refused('production_boot_native_archive_changed')
                target.unlink()
                s.sync_dir(target.parent)
        elif s.read(target) != after[key]:
            s.atomic(target, after[key])
        value['completed'].append(key)
        value['intent'] = None
        save()
    scope()
    value['phase'] = 'COMPLETE'
    save()
    return dict(result='production_prior_boot_closed_and_retired', new_boot=record['new_boot'],
                new_owner_created=False, data_started=False, configuration_preserved=True)


def retire_completed_record(io, store, record):
    """Archive only a completed prior boot record; never reapply its effects."""
    io.held()
    path = receipt_path(record)
    value = record_receipt(s.json_value(s.read(path)), record)
    raw = s.read(native.RECORD)
    if (record['phase'] != 'RESTORED' or value['phase'] != 'COMPLETE'
            or r.sha(raw) != value['boot_record_sha256'] or r.validate(s.json_value(raw)) != record):
        raise r.Refused('production_prior_boot_record_not_complete')
    store.write_new(native.ARCHIVES / ('reconcile-' + r.sha(raw) + '.json'), raw)
    if s.read(native.RECORD) != raw:
        raise r.Refused('production_old_record_changed')
    native.RECORD.unlink()
    s.sync_dir(native.RECORD.parent)
    store.previous = None
    store.durable = None


def recover_locked(io, clock):
    """Called by fixed service/recover entry while it holds Native.locked()."""
    io.held()
    store = boot_store.Store(io)
    record = store.load()
    if record is not None:
        if record['new_boot'] != io.boot():
            retire_completed_record(io, store, record)
            record = None
        else:
            # Resume an interrupted metadata handoff even after journal unlink.
            path = receipt_path(record)
            if present(path) and record_receipt(s.json_value(s.read(path)), record)['phase'] == 'COMPLETE':
                # A new owner may already have run. This is historical completion,
                # not permission to close/reuse that old session again.
                retire_completed_record(io, store, record)
                record = None
            else:
                if record['phase'] != 'RESTORED':
                    io.attach_writer(store)
                    close.restore_locked(io, store)
                    record = store.load()
                return finish(io, store, record, clock)
    current = s.Store().load()
    if current is None or current['boot'] == io.boot():
        return dict(result='no_previous_boot_production_session', data_started=False)
    if source.kind(current) != 'production':
        raise r.Refused('production_start_requires_separate_bounded_handoff')
    record = close.admit(io, store)
    io.attach_writer(store)
    close.restore_locked(io, store)
    return finish(io, store, store.load(), clock)

