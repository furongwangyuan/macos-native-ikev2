"""Fixed explicit production install/disable/remove, called by verified manager.

No CLI, installer, generic workflow, arbitrary path or subprocess argument.
Caller holds the fixed manager and acceptance-state locks (lease callback).
Native lock is acquired here only at the necessary closed/readback boundaries.
"""
import base64
import contextlib
import errno
import time
import json
import os
import re
import production_service_job as job

ACTIONS = ('service-install', 'service-start', 'service-disable', 'service-remove','service-status')
PHASES = ('PREPARED', 'PUBLISHING', 'PUBLISHED', 'CONFIGURING', 'CONFIGURED',
          'STARTING', 'LOADED', 'DISABLING', 'UNLOADED', 'CLOSED', 'DISABLED', 'REMOVING', 'REMOVED',
          'ENABLE_PREPARED', 'ENABLING', 'ENABLE_CONFIGURED', 'ENABLE_STARTING')


class Refused(RuntimeError):
    pass


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def exact_hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def config(raw, name):
    import native_support as s
    value = s.json_value(raw)
    key = 'enabled' if name == 'supervisor-config.json' else 'allow_data'
    if (type(value) is not dict or set(value) != {'version', key}
            or type(value['version']) is not int or value['version'] != 1 or type(value[key]) is not bool):
        raise Refused('production_config_unknown')
    return value[key]


def on(name, enabled):
    return encode(dict(version=1, **{('enabled' if name == 'supervisor-config.json' else 'allow_data'): enabled}))


def native_io():
    import boot_native
    boot_native.Native.installed_scope()
    return boot_native.Native()


@contextlib.contextmanager
def native_locked():
    """Explicit operation waits only for ordinary native-lock contention.

    No action is retried. A failed enter releases every partial legacy lease;
    service and recovery owners keep their existing nonblocking behavior.
    """
    deadline=time.monotonic()+20
    with contextlib.ExitStack() as stack:
        while True:
            try:
                io=stack.enter_context(native_io().locked())
                break
            except BlockingIOError as error:
                if error.errno!=errno.EAGAIN:raise
                remaining=deadline-time.monotonic()
                if remaining<=0:raise Refused('production_native_lock_busy') from error
                time.sleep(min(.1,remaining))
        yield io


def fresh_locked(service, io):
    """Actual fresh closed readback; successful cleanup return is insufficient."""
    import boot_store
    import boot_record
    import boot_reconcile
    import production_boot
    import production_source
    s = service.s
    io.held()
    current = s.Store().load()
    if current is not None:
        service.service_recovery_readback.verify(s.Store(), current)
        return dict(kind='same-boot-native', sha256=s.digest(encode(current)))
    # Cross-boot production handoff deliberately retires the native journal.
    # Its exact archived original is still the readback baseline, never old PID,
    # policy ID or PF token authority. Configuration can now be deliberately off.
    store = boot_store.Store(io)
    record = store.load()
    if record is None:
        # First installation has no old owner to restore. Read actual closed
        # kernel/firewall/process facts; absence is not called RESTORED.
        state=service.ServiceStore().load()
        if state is not None and state['phase'] not in ('DISABLED','STOPPED','PREFLIGHT','ATTENTION'):
            raise Refused('missing_native_record_for_started_service')
        import native_quiescent
        observed=native_quiescent.verify(io.held)
        baseline=service.runtime.preflight(False)
        if s.Store().load() is not None or boot_store.Store(io).load() is not None:
            raise Refused('fresh_native_owner_appeared')
        # started/time fields are not part of this stable read-only observation.
        checked={key:baseline[key] for key in ('version','profile','boot','baseline','alf_before','health','crl','fleet')}
        io.held()
        return dict(kind='fresh-no-owner',sha256=s.digest(encode(dict(native=observed,preflight=checked))))
    if record['phase'] != 'RESTORED' or record['new_boot'] != io.boot():
        raise Refused('production_closed_baseline_missing')
    receipt = production_boot.record_receipt(s.json_value(s.read(production_boot.receipt_path(record))), record)
    if receipt['phase'] != 'COMPLETE' or receipt['boot_record_sha256'] != s.digest(s.read(production_boot.native.RECORD)):
        raise Refused('production_boot_handoff_not_complete')
    original, context = store.originals(record)
    old = boot_record.bind(record, original, context)
    if s.json_value(context).get('kind') != 'production-service-v1' or io.implementation() != record['implementation_sha256']:
        raise Refused('production_boot_closed_source_changed')
    production_source.verify_current_resources(context)
    io.closed_kernel()
    if io.alf() != old['alf_before']:
        raise Refused('production_boot_alf_not_restored')
    pf = io.pf(old)
    if pf['sha256'] != old['pf']['before_sha'] or pf['root'] != 'baseline' or pf['anchor'] != dict(filters=[], nat=[]):
        raise Refused('production_boot_pf_not_restored')
    boot_reconcile.files_scope(io, old, record['completed'])
    if store.load() != record or s.Store().load() is not None:
        raise Refused('production_boot_closed_source_raced')
    return dict(kind='retired-production-boot', sha256=s.digest(s.read(production_boot.native.RECORD)))


def close_locked(service, io):
    import boot_store
    import production_boot
    import continuous_clock
    s = service.s
    io.held()
    current = s.Store().load()
    pending = boot_store.Store(io).load()
    # Preserve a completed handoff until the final disable readback; do not
    # retire the last usable baseline merely to create a new metadata answer.
    if current is None and pending is not None and pending['phase'] == 'RESTORED':
        return fresh_locked(service, io)
    if pending is not None or (current is not None and current['boot'] != io.boot()):
        production_boot.recover_locked(io, continuous_clock.make_clock())
    if service.recover_only.recover(s.Store()) != 0:
        raise Refused('production_native_restore_incomplete')
    return fresh_locked(service, io)


class Control:
    def __init__(self, batch, native, service, held):
        self.batch, self.native, self.service, self.held = batch, native, service, held
        self.s = service.s
        self.path = self.s.STATE / 'production' / 'service-control.json'
        self.raw = None
        self.value = None
        self.plist = job.expected(self.s)
        self.code = service.code_fingerprint()
        if not exact_hash(self.code):
            raise Refused('production_code_fingerprint')

    def scope(self):
        self.held()
        if self.service.code_fingerprint() != self.code or job.expected(self.s) != self.plist:
            raise Refused('production_source_changed')
        if self.raw is not None and self.s.read(self.path) != self.raw:
            raise Refused('production_control_record_changed')

    def validate(self, value):
        keys = {'version', 'phase', 'code_sha256', 'plist_sha256', 'created_boot', 'before', 'closed', 'start_boot'}
        if (type(value) is not dict or set(value) != keys or type(value['version']) is not int
                or value['version'] != 1 or value['phase'] not in PHASES
                or value['code_sha256'] != self.code or value['plist_sha256'] != self.s.digest(self.plist)
                or type(value['created_boot']) is not str or not value['created_boot']
                or type(value['before']) is not dict or set(value['before']) != {'config.json', 'supervisor-config.json'}):
            raise Refused('production_control_unknown_preserved')
        if value['start_boot'] is not None and (type(value['start_boot']) is not str or not value['start_boot']):
            raise Refused('production_start_boot_shape')
        if value['phase'].startswith('ENABLE') and value['start_boot'] is None:
            raise Refused('production_start_boot_missing')
        for name, encoded in value['before'].items():
            if type(encoded) is not str or len(encoded) > 8192:
                raise Refused('production_original_config_shape')
            raw = base64.b64decode(encoded, validate=True)
            if config(raw, name) is not False:
                raise Refused('production_original_config_not_disabled')
        closed = value['closed']
        if closed is not None and (type(closed) is not dict or set(closed) != {'kind', 'sha256'}
                or closed['kind'] not in ('fresh-no-owner','same-boot-native', 'retired-production-boot') or not exact_hash(closed['sha256'])):
            raise Refused('production_closed_receipt_shape')
        if value['phase'] in ('CLOSED', 'DISABLED', 'REMOVING', 'REMOVED') and closed is None:
            raise Refused('production_closed_receipt_missing')
        return value

    def load(self):
        self.scope()
        if not job.present(self.path):
            return None
        self.raw = self.s.read(self.path)
        self.value = self.validate(self.s.json_value(self.raw))
        return self.value

    def save(self, phase, *, closed=None, start_boot=None):
        self.scope()
        value = dict(self.value, phase=phase)
        if closed is not None:
            value['closed'] = closed
        if start_boot is not None:
            value['start_boot'] = start_boot
        self.validate(value)
        raw = encode(value)
        self.s.atomic(self.path, raw)
        if self.s.read(self.path) != raw:
            raise Refused('production_control_write_readback')
        self.raw, self.value = raw, value

    def set_config(self, name, enabled):
        self.scope()
        path = self.s.CONF / name
        raw = self.s.read(path, limit=4096)
        before = base64.b64decode(self.value['before'][name], validate=True)
        target = on(name, enabled)
        if raw not in (before, on(name, True), on(name, False)):
            raise Refused('production_configuration_changed_preserved')
        config(raw, name)
        if raw != target:
            self.s.atomic(path, target)
        if self.s.read(path) != target:
            raise Refused('production_config_write_readback')

    def disabled_configs(self):
        for name in ('supervisor-config.json', 'config.json'):
            if config(self.s.read(self.s.CONF / name, limit=4096), name) is not False:
                raise Refused('production_permission_not_disabled')

    def authorize(self):
        import production_activation
        return production_activation.authorize(self.code, os.uname().release, os.uname().machine)

    def install(self):
        import activation_install
        import production_source
        if self.load() is None:
            if job.present(job.PLIST) or job.loaded() or job.override() is not None:
                raise Refused('production_existing_job_or_override_preserved')
            self.disabled_configs()
            if job.present(self.s.CONF / 'service-activation.json'):
                self.authorize()
            else:
                activation_install.capture_enable(self.batch, self.native, self.service)
            with native_locked() as io:
                self.scope()
                fresh_locked(self.service, io)
                before = {name: self.s.read(self.s.CONF / name, limit=4096)
                          for name in ('config.json', 'supervisor-config.json')}
                if any(config(raw, name) for name, raw in before.items()):
                    raise Refused('production_initial_permission_changed')
                value = dict(version=1, phase='PREPARED', code_sha256=self.code,
                    plist_sha256=self.s.digest(self.plist), created_boot=self.s.boot(),
                    before={name: base64.b64encode(raw).decode() for name, raw in before.items()}, closed=None, start_boot=None)
                self.validate(value)
                production_source.write_new(self.path, encode(value))
                self.raw, self.value = encode(value), value
        if self.value['phase'] not in PHASES[:6]:
            raise Refused('production_install_phase_preserved')
        if self.value['created_boot'] != self.s.boot():
            raise Refused('production_install_crossboot_requires_inspection')
        self.authorize()
        if self.value['phase'] in ('PREPARED', 'PUBLISHING'):
            if job.loaded():
                raise Refused('production_unowned_loaded_job')
            self.save('PUBLISHING')
            job.publish(self.s, self.plist)
            self.save('PUBLISHED')
        job.check_file(self.s, self.plist)
        if self.value['phase'] in ('PUBLISHED', 'CONFIGURING'):
            if job.loaded():
                raise Refused('production_job_loaded_before_permission_commit')
            with native_locked() as io:
                self.scope()
                fresh_locked(self.service, io)
                self.service.recovery_job_gate()
                self.save('CONFIGURING')
                self.set_config('config.json', True)
                self.set_config('supervisor-config.json', True)
                self.save('CONFIGURED')
        if self.value['phase'] == 'CONFIGURED':
            self.save('STARTING')
        self.scope()
        for name in ('config.json', 'supervisor-config.json'):
            if self.s.read(self.s.CONF / name) != on(name, True):
                raise Refused('production_start_permission_changed')
        job.set_override(False)
        if not job.loaded():
            job.command('load')
        if not job.loaded():
            raise Refused('production_job_not_loaded')
        self.save('LOADED')
        return dict(action='service-install', job_loaded=True, service_enabled=True,
                    service_health_verified=False, all_project_requirements_verified=False)

    def start(self):
        """Explicit same-installed-version enable after a proven disable."""
        import production_source
        if self.load() is None or self.value['phase'] not in (
                'DISABLED', 'ENABLE_PREPARED', 'ENABLING', 'ENABLE_CONFIGURED', 'ENABLE_STARTING'):
            raise Refused('production_start_requires_own_disabled_record')
        self.authorize()
        job.check_file(self.s, self.plist)
        if self.value['phase'] == 'DISABLED':
            with native_locked() as io:
                self.scope()
                self.disabled_configs()
                if job.loaded() or job.override() is not True:
                    raise Refused('production_start_job_not_disabled')
                state = self.service.ServiceStore().load()
                if state is not None and state['phase'] not in ('DISABLED', 'STOPPED'):
                    raise Refused('production_start_preserves_attention_or_unfinished_lifecycle')
                self.retire_disabled_prior_boot(io)
                fresh_locked(self.service, io)
                # Preserve the previous completed stop receipt verbatim before
                # beginning this explicit enable, never rewrite its original boot.
                archive = self.path.parent / ('service-control-history-' + self.s.digest(self.raw) + '.json')
                if job.present(archive):
                    if self.s.read(archive) != self.raw:
                        raise Refused('production_start_history_conflict_preserved')
                else:
                    production_source.write_new(archive, self.raw)
                self.save('ENABLE_PREPARED', start_boot=self.s.boot())
        if self.value['start_boot'] != self.s.boot():
            raise Refused('production_start_crossboot_requires_inspection')
        if self.value['phase'] in ('ENABLE_PREPARED', 'ENABLING'):
            with native_locked() as io:
                self.scope()
                if job.loaded() or job.override() is not True:
                    raise Refused('production_start_early_job_change')
                state = self.service.ServiceStore().load()
                if state is not None and state['phase'] not in ('DISABLED', 'STOPPED'):
                    raise Refused('production_start_preserves_attention_or_unfinished_lifecycle')
                fresh_locked(self.service, io)
                self.service.recovery_job_gate()
                self.save('ENABLING')
                self.set_config('config.json', True)
                self.set_config('supervisor-config.json', True)
                self.save('ENABLE_CONFIGURED')
        if self.value['phase'] == 'ENABLE_CONFIGURED':
            self.save('ENABLE_STARTING')
        self.scope()
        for name in ('config.json', 'supervisor-config.json'):
            if self.s.read(self.s.CONF / name) != on(name, True):
                raise Refused('production_start_permission_changed')
        job.set_override(False)
        if not job.loaded():
            job.command('load')
        if not job.loaded():
            raise Refused('production_start_job_not_loaded')
        self.save('LOADED')
        return dict(action='service-start', job_loaded=True, service_enabled=True,
                    service_health_verified=False, prior_stop_history_preserved=True)

    def retire_disabled_prior_boot(self, io):
        """Explicit start may retire its own already-closed prior-boot journal.

        No recovery or permission change occurs here. Archive-before-unlink is
        restartable while the control record and both permissions stay DISABLED;
        a crash after unlink returns through the existing fresh-no-owner path.
        Old process IDs, policy IDs and PF tokens are never reused as authority.
        """
        import boot_store
        import boot_reconcile
        import native_quiescent
        import production_source
        s = self.s
        io.held()
        current_boot = s.boot()
        old = s.Store().load()
        if old is None or old['boot'] == current_boot:
            return
        self.scope()
        self.disabled_configs()
        if (self.value['phase'] != 'DISABLED' or job.loaded() or job.override() is not True
                or boot_store.Store(io).load() is not None):
            raise Refused('production_disabled_retirement_scope')
        if (old['phase'] != 'RESTORED' or old['active'] is not False
                or old.get('cleanup_codes') != [] or old.get('recovery_result') != 'restored'
                or self.value['closed'] != dict(kind='same-boot-native', sha256=s.digest(encode(old)))):
            raise Refused('production_disabled_retirement_receipt')
        path = s.STATE / 'native-session.json'
        original = s.read(path)
        if s.json_value(original) != old:
            raise Refused('production_disabled_retirement_journal_changed')
        context = production_source.snapshot(old)
        files = production_source.unpack(context)
        mark = production_source.marker(old)
        intent = production_source.intent(s.json_value(files['intent']))
        state = production_source.valid_state(s.json_value(files['service-state']))
        # The completed stop belongs to the actual enabled run. Current config
        # stays false; do not relax generic cross-boot permission validation.
        fingerprint = s.digest(on('supervisor-config.json', True) + b'\0' + on('config.json', True))
        if (intent['run'] != mark['run_id'] or s.digest(files['intent']) != mark['intent_sha256']
                or intent['boot'] != old['boot'] or state['boot'] != old['boot']
                or intent['configuration_sha256'] != fingerprint or state['fingerprint'] != fingerprint
                or intent['code_sha256'] != self.code
                or state['phase'] != 'STOPPED' or state['reason'] != 'manual_stop'
                or self.service.ServiceStore().load() != state):
            raise Refused('production_disabled_retirement_source')
        production_source.verify_current_resources(context)

        def scope():
            io.held()
            self.scope()
            self.disabled_configs()
            if (s.boot() != current_boot or job.loaded() or job.override() is not True
                    or s.read(path) != original or s.Store().load() != old
                    or production_source.snapshot(old) != context or boot_store.Store(io).load() is not None):
                raise Refused('production_disabled_retirement_changed')

        scope()
        native_quiescent.verify(io.held)
        if io.alf() != old['alf_before']:
            raise Refused('production_disabled_retirement_alf')
        pf = io.pf(old)
        if (pf['sha256'] != old['pf']['before_sha'] or pf['root'] != 'baseline'
                or pf['anchor'] != dict(filters=[], nat=[])):
            raise Refused('production_disabled_retirement_pf')
        boot_reconcile.files_scope(io, old, [])
        archives = (
            ('disabled-native-' + s.digest(original) + '.json', original),
            ('disabled-service-' + s.digest(files['service-state']) + '.json', files['service-state']),
            ('disabled-context-' + s.digest(context) + '.json', context),
            ('service-control-history-' + s.digest(self.raw) + '.json', self.raw),
        )
        for name, raw in archives:
            archive = self.path.parent / name
            if job.present(archive):
                if s.read(archive) != raw:
                    raise Refused('production_disabled_retirement_archive_conflict')
            else:
                production_source.write_new(archive, raw)
        scope()
        for name, raw in archives:
            if s.read(self.path.parent / name) != raw:
                raise Refused('production_disabled_retirement_archive_changed')
        path.unlink()
        s.sync_dir(path.parent)

    def disable(self):
        if self.value is None and self.load() is None:
            raise Refused('production_job_ownership_missing')
        if self.value['phase'] == 'REMOVED':
            raise Refused('production_removed_record_preserved')
        job.check_file(self.s, self.plist, absent=True)
        self.scope()
        if self.value['phase'] not in ('DISABLING', 'UNLOADED', 'CLOSED', 'DISABLED', 'REMOVING'):
            self.save('DISABLING')
        # This is a persistent, explicit requested disable, not a temporary
        # native effect: it prevents startup after a crash/reboot during stop.
        if job.override() is not True:
            job.set_override(True)
        job.stop_and_unload(self.held)
        if self.value['phase'] == 'DISABLING':
            self.save('UNLOADED')
        with native_locked() as io:
            self.scope()
            if job.loaded() or job.override() is not True:
                raise Refused('production_job_changed_during_stop')
            if self.value['phase'] == 'UNLOADED':
                closed = close_locked(self.service, io)
                self.save('CLOSED', closed=closed)
            else:
                fresh_locked(self.service, io)
            # Change source permissions only after original-source restoration.
            self.set_config('supervisor-config.json', False)
            self.set_config('config.json', False)
            self.disabled_configs()
            fresh_locked(self.service, io)
            if self.value['phase'] != 'REMOVING':
                self.save('DISABLED')
        return dict(action='service-disable', job_loaded=False, service_enabled=False,
                    fresh_closed_readback=True, persistent_launchd_disable=True)

    def status(self):
        # Read-only observations, not readiness or end-to-end verification.
        value=self.load();state=self.service.ServiceStore().load();native=self.s.Store().load()
        return dict(action='service-status',job_loaded=job.loaded(),
            service_control_phase=None if value is None else value['phase'],
            service_phase=None if state is None else state['phase'],
            native_phase=None if native is None else native['phase'],
            service_enabled=config(self.s.read(self.s.CONF/'supervisor-config.json'),'supervisor-config.json'),
            data_permission=config(self.s.read(self.s.CONF/'config.json'),'config.json'),
            service_health_verified=False)

    def remove(self):
        self.disable()
        self.save('REMOVING')
        with native_locked() as io:
            self.scope()
            if job.loaded() or job.override() is not True:
                raise Refused('production_job_changed_before_remove')
            self.disabled_configs()
            fresh_locked(self.service, io)
            job.remove(self.s, self.plist)
            self.save('REMOVED')
        return dict(action='service-remove', job_plist_removed=True, service_enabled=False,
                    persistent_launchd_disable=True, original_records_preserved=True)


def dispatch(action, batch, native, service, manager_and_state_held):
    if action not in ACTIONS:
        raise Refused('production_service_fixed_action_only')
    # No caller-provided argv/path/PID is accepted. The enclosing fixed root
    # entry verifies module closure and holds its existing two metadata leases.
    manager_and_state_held()
    control = Control(batch, native, service, manager_and_state_held)
    return {'service-install': control.install, 'service-start': control.start, 'service-disable': control.disable,
            'service-remove': control.remove,'service-status':control.status}[action]()


if __name__ == '__main__':
    raise SystemExit('Only the fixed reviewed root manager may dispatch this source module.')
