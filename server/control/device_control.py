"""Fixed device maintenance through the existing verified service manager.

The parent entry holds manager/acceptance locks and verifies all installed code.
Membership mutation temporarily stops an owned service, holds original native
locks throughout, and only restarts after a complete closed transaction.
"""
import re
import unicodedata
import production_service as production
import production_service_job as job

ACTIONS={'device-add':2,'device-revoke':2,'device-recover':0,'device-list':0,'device-report':0,'device-export':1,'device-password':1}
REASONS={'unspecified','keyCompromise','affiliationChanged','superseded','cessationOfOperation'}

class Refused(RuntimeError):pass

def arguments(action,values):
    if action not in ACTIONS or type(values) is not list or len(values)!=ACTIONS[action]:
        raise Refused('device_action_arguments')
    if any(type(x)is not str or not x or '\0' in x for x in values):raise Refused('device_argument_type')
    if action in ('device-add','device-revoke','device-export','device-password'):
        if re.fullmatch('[a-z][a-z0-9-]{0,30}[a-z0-9]',values[0]) is None:raise Refused('device_id')
        if action=='device-revoke' and values[1] not in REASONS:raise Refused('device_revocation_reason')
        if action=='device-add':
            name=values[1]
            if not 1<=len(name)<=80 or name!=name.strip() or any(unicodedata.category(c)[0]=='C' or c in '\u2028\u2029' for c in name):
                raise Refused('device_display_name')
    return tuple(values)

def public_result(value):
    expected={'version','run','action','device','phase','serial','registry_revision',
              'current_authority_sha256','loaded_verified','data_started'}
    if (type(value)is not dict or set(value)!=expected or type(value['version'])is not int or value['version']!=1
            or value['phase']!='COMMITTED_CLOSED' or value['action'] not in ('enroll','revoke')
            or value['loaded_verified']is not False or value['data_started']is not False
            or type(value['run'])is not str or re.fullmatch('[a-f0-9]{32}',value['run'])is None
            or type(value['serial'])is not int or value['serial']<=0
            or type(value['registry_revision'])is not int or value['registry_revision']<1
            or type(value['current_authority_sha256'])is not str
            or re.fullmatch('[a-f0-9]{64}',value['current_authority_sha256'])is None
            or type(value['device'])is not str or re.fullmatch('[a-z][a-z0-9-]{0,30}[a-z0-9]',value['device'])is None):
        raise Refused('device_transaction_result_unknown')
    return dict(device_id=value['device'],action=value['action'],serial_hex=format(value['serial'],'X'),
        registry_revision=value['registry_revision'],transaction_complete=True,
        loaded_crl_verified=False,phone_verified=False)

def readonly(action,io):
    import registry
    import membership_admission as membership
    if action=='device-list':
        reg=registry.loads(io.read(io.root/'devices.json',65536))
        return dict(action=action,registry_revision=reg['revision'],devices=[
            {key:row[key] for key in ('device_id','display_name','state')} for row in reg['devices']])
    run=membership.pending(io)
    if run is None:return dict(action=action,pending=False,service_health_verified=False)
    path=io.root/membership.NAME/run;io.directory(path)
    # Presence is not a successful commit/crypto/native proof. No stored payload,
    # secret or arbitrary exception text is copied into a public report.
    return dict(action=action,pending=True,run=run,prepared_present=io.exists(path/'prepared.json'),
                complete_present=io.exists(path/'complete.json'),admission_blocked=True)

def dispatch(action,values,batch,native,service,manager_held):
    values=arguments(action,values);manager_held()
    from pki_io import IO,encode,sha
    import renewal
    import enrollment
    import native_quiescent
    import native_closed
    s=service.s
    s.trusted(renewal.ROOT,0o700)
    io=IO(renewal.ROOT,0)
    if action in ('device-list','device-report'):return readonly(action,io)
    if action=='device-recover':
        import membership_admission
        if membership_admission.pending(io) is None:
            return dict(action=action,pending=False,previous_completion_verified=False,
                        service_operation_performed=False)
    control=production.Control(batch,native,service,manager_held)
    record=control.load()
    was_enabled=False
    if record is not None:
        # Only a normal loaded owned service is automatically resumed. An old
        # incomplete stop remains off after maintenance, for explicit recovery.
        was_enabled=record['phase']=='LOADED' and service.read_configuration().enabled is True
        control.disable()
    else:
        if job.loaded() or job.present(job.PLIST) or job.present(s.STATE/'service-state.json'):
            raise Refused('device_unowned_service_state_preserved')
        if (service.read_configuration().enabled is not False
                or production.config(s.read(s.CONF/'config.json'),'config.json')is not False):
            raise Refused('device_requires_disabled_native_configuration')
    source=service.code_fingerprint()
    with production.native_io().locked() as native_io:
        saved=s.Store().load();prior=sha(encode(saved)) if saved is not None else None
        def closed():
            if manager_held()is not None or native_io.held()is not None:
                raise Refused('device_actual_original_locks_required')
            if service.code_fingerprint()!=source:raise Refused('device_source_changed')
            if job.loaded() or service.read_configuration().enabled is not False:
                raise Refused('device_service_no_longer_disabled')
            if production.config(s.read(s.CONF/'config.json'),'config.json')is not False:
                raise Refused('device_native_permission_not_closed')
            if record is not None:
                control.scope()
                if job.override()is not True:raise Refused('device_persistent_stop_changed')
            native_closed.legacy_writers_absent()
            current=s.Store().load()
            if (sha(encode(current)) if current is not None else None)!=prior:
                raise Refused('device_original_native_record_changed')
            if saved is None:native_quiescent.verify(native_io.held)
            elif service.service_recovery_readback.verify(s.Store(),saved)is not True:
                raise Refused('device_native_closed_readback_failed')
        closed()
        worker=enrollment.Enrollment(io,closed)
        if action=='device-add':result=worker.enroll_locked(*values)
        elif action=='device-revoke':result=worker.revoke_locked(*values)
        elif action=='device-export':
            import profile_export,device_delivery
            result=profile_export.export_locked(worker,*values)
            summary=dict(action=action,result=result,delivery=device_delivery.encode_profile(io,result))
        elif action=='device-password':
            import profile_export,device_password
            result=profile_export.export_locked(worker,*values)
            summary=dict(action=action,device_id=values[0],**device_password.reveal(io,result,closed))
        else:result=worker.recover_locked()
        closed()
        if action not in ('device-export','device-password'):summary=public_result(result)
    # A failed/pending transaction never reaches this point; it leaves the
    # persistent service disable intact. Restart has its own real readbacks.
    if was_enabled:
        try:
            result=control.start()
            if type(result)is not dict or result.get('job_loaded')is not True or result.get('service_enabled')is not True:
                raise Refused('device_post_maintenance_start_unverified')
        except BaseException as original:
            from diagnostics import diagnostic_emit,diagnostic_failure
            try:
                # Reload durable state: start may have changed launchd/config
                # before its last write or readback failed.
                cleanup=production.Control(batch,native,service,manager_held)
                cleanup.disable()
            except BaseException as cleanup_error:
                diagnostic_emit(diagnostic_failure('production_control',original),restoration='unverified')
                diagnostic_emit(diagnostic_failure('production_control',cleanup_error),restoration='unverified')
                raise Refused('device_restart_failed_closure_unverified') from cleanup_error
            diagnostic_emit(diagnostic_failure('production_control',original),restoration='verified')
            raise
    if action=='device-export':
        return dict(summary,service=dict(restart_requested=was_enabled,left_disabled=not was_enabled,health_verified=False))
    return dict(summary,service_restart_requested=was_enabled,service_health_verified=False,
                service_left_disabled=not was_enabled)

if __name__=='__main__':raise SystemExit('Only the fixed verified root manager calls this module.')
