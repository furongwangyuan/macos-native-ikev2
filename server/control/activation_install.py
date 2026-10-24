"""Capture explicit enablement only after current native closure, under its lock."""
import os

class Refused(RuntimeError):pass

def capture_enable(batch,native,service):
    import production_activation as activation
    import production_service as control
    import production_source as files
    s=service.s
    with control.native_locked() as io:
        io.held()
        for name in ('config.json','supervisor-config.json'):
            if control.config(s.read(s.CONF/name,limit=4096),name)is not False:
                raise Refused('explicit_enable_requires_disabled_configuration')
        if service.ServiceStore().load() is not None:
            raise Refused('explicit_enable_preserves_existing_service_history')
        closed=control.fresh_locked(service,io)
        code=service.code_fingerprint()
        record=dict(version=2,stage='explicit-enable',explicit_enable=True,code_sha256=code,
            kernel_release=os.uname().release,machine=os.uname().machine,
            common_sha256=s.digest(s.read(s.BASE/'candidate-pins.json')),enabled_boot=s.boot(),
            closed_observation=closed,fault_tests_performed=False,phone_test_performed=False)
        activation.validate(record,code,os.uname().release,os.uname().machine)
        io.held()
        # Recheck real closure, but never manufacture a RESTORED native session.
        again=control.fresh_locked(service,io)
        if again!=closed or service.code_fingerprint()!=code:
            raise Refused('explicit_enable_source_or_baseline_changed')
        path=s.CONF/'service-activation.json';raw=activation.encode(record)
        if path.exists() or path.is_symlink():
            existing=s.read(path)
            # A retry may reuse only the exact same already-owned record.
            if existing!=raw:raise Refused('explicit_enable_existing_record_preserved')
        else:files.write_new(path,raw)
        activation.authorize(code,os.uname().release,os.uname().machine)
        return dict(explicit_enable=True,tests_claimed=False,service_enabled=False)
