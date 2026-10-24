"""One fixed, authorized first trial; no arbitrary command or admission bypass."""
import production_service as service_control
import production_service_job as job
import time


class Refused(RuntimeError):
    pass


def before_enable(batch, native, service, held):
    """Refuse any existing service before changing finite-test permission."""
    held()
    control = service_control.Control(batch, native, service, held)
    if control.load() is not None or job.present(job.PLIST) or job.loaded() or job.override() is not None:
        raise Refused('first_trial_preserves_existing_service')
    control.disabled_configs()
    state = service.ServiceStore().load()
    if state is not None:
        raise Refused('first_trial_preserves_existing_service_lifecycle')


def wait_ready(service,held,*,clock=time.monotonic,pause=time.sleep):
    """Observe existing real service/owner records; no traffic or test PASS."""
    import production_source
    deadline=clock()+90
    pending=dict(native_ready_observed=False,startup_pending=True,phone_confirmation_pending=True,
                 service_health_verified=False,tests_claimed=False)
    while True:
        held()
        state=service.ServiceStore().load()
        current=service.s.Store().load()
        if state is not None and state['phase']=='ATTENTION':
            raise Refused('service_start_attention')
        if current is not None and current.get('phase')=='ATTENTION':
            raise Refused('service_start_native_attention')
        if (state is not None and state['phase']=='RUNNING' and state['boot']==service.s.boot()
                and current is not None and current['active'] is True
                and current['phase'] in ('WAITING','ACTIVE') and current['boot']==state['boot']
                and current.get('alf_transaction',{}).get('phase')=='open'):
            production_source.marker(current)
            raw=production_source.snapshot(current)
            production_source.validate(current,raw)
            if (service.s.Store().load()!=current or service.ServiceStore().load()!=state):
                if clock()>=deadline:return dict(pending)
                continue
            return dict(native_ready_observed=True,startup_pending=False,phone_confirmation_pending=True,
                        service_health_verified=False,tests_claimed=False)
        if clock()>=deadline:return dict(pending)
        pause(.5)


def observe_ready(service,held):
    """Read-only observation cannot stop the independently protected service."""
    try:return wait_ready(service,held)
    except Exception as error:
        args=error.args
        code=args[0] if len(args)==1 and type(args[0])is str and args[0] in {
            'file_changed_during_read','service_start_attention','service_start_native_attention'} else 'startup_observation_unavailable'
        return dict(native_ready_observed=False,startup_pending=False,phone_confirmation_pending=True,
                    service_health_verified=False,tests_claimed=False,startup_observation_error=code)


def enable(batch, native, service, held):
    """Explicit installation/start; phone and fault results are not permissions.

    Actual install/start errors retain their original disable/readback. Later
    observation errors report unverified status without issuing a stop.
    """
    held()
    control = service_control.Control(batch, native, service, held)
    current=control.load()
    if current is not None and current['phase']=='LOADED':
        control.authorize();job.check_file(service.s,control.plist)
        if not job.loaded() or job.override() is True:
            raise Refused('enabled_service_job_not_verified')
        for name in ('config.json','supervisor-config.json'):
            if service_control.config(service.s.read(service.s.CONF/name),name)is not True:
                raise Refused('enabled_service_configuration_changed')
        ready=observe_ready(service,held)
        return dict(ready,action='already-enabled',job_loaded=True,service_enabled=True)
    try:
        if current is None:
            before_enable(batch,native,service,held)
            # Installing the exact closed-only recovery job grants no data.
            with service_control.native_locked() as io:
                service_control.fresh_locked(service,io)
                held();batch.ins.install_current_job();service.recovery_job_gate()
            result=control.install()
        elif current['phase'] in ('DISABLED','ENABLE_PREPARED','ENABLING','ENABLE_CONFIGURED','ENABLE_STARTING'):
            result=control.start()
        elif current['phase'] in service_control.PHASES[:6]:
            result=control.install()
        else:
            raise Refused('explicit_enable_preserves_unfinished_service_state')
    except BaseException as original:
        # Reload after an after-effect storage failure; never operate from a
        # stale in-memory phase or infer that a missing record means no effect.
        try:
            cleanup = service_control.Control(batch, native, service, held)
            if cleanup.load() is None:
                if job.present(job.PLIST) or job.loaded() or job.override() is not None:
                    raise Refused('trial_unrecorded_service_effect_preserved')
                cleanup.disabled_configs()
            else:
                cleanup.disable()
        except BaseException as cleanup_error:
            raise Refused('trial_install_failed_closure_unverified') from cleanup_error
        raise original
    ready=observe_ready(service,held)
    return dict(result,**{key:value for key,value in ready.items() if key not in result},explicit_enable=True)
