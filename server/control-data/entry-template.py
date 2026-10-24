#!/usr/bin/python3
"""Fixed installed finite-test entry; no path/PID/duration/credential arguments."""
# IO_PRIMITIVES
# DIAGNOSTIC_PRIMITIVES
# ARGUMENT_PRIMITIVES
DIAGNOSTIC_STAGE = 'data_admission'
CONTRACT = {} # ENTRY_CONTRACT
PUBLIC_CODES=frozenset() # PUBLIC_ERROR_CODES
ROOTS={'control':Path('/usr/local/family-vpn/production-acceptance'),
       'common':Path('/usr/local/family-vpn/production-guardian'),
       'harness':Path('/usr/local/family-vpn/production-owner-fault')}
ENTRY=ROOTS['control']/'root_entry.py'
FIXED_ACTIONS=dict.fromkeys(('install-trial','batch','data-test','recover','report','suite','data-window','service-install','service-start','service-disable','service-remove','service-status'),0)
FIXED_ACTIONS.update(DEVICE_ARITY)


def verified():
    # Verification precedes imports of any executable installed payload. The
    # entry itself is root-owned and pinned by the outer installer contract.
    if os.geteuid()!=0 or Path(__file__)!=ENTRY or len(sys.argv)<2:
        raise Failure('fixed_installed_root_entry_only')
    validate_request(sys.argv[1],sys.argv[2:],FIXED_ACTIONS)
    if set(CONTRACT)!=set(ROOTS):raise Failure('unbuilt_entry')
    for group,root in ROOTS.items():
        trusted(root,directory=True,mode=0o700)
        extra={'root_entry.py'} if group=='control' else set()
        expected_names=set(CONTRACT[group])|extra
        directories={name.split('/')[0] for name in expected_names if '/' in name}
        if directories-{'crypto','vici'} or group!='common' and directories:raise Failure('entry_nested_scope')
        actual=set()
        for path in root.iterdir():
            if path.name in directories:
                trusted(path,directory=True,mode=0o700)
                for child in path.iterdir():actual.add(path.name+'/'+child.name)
            else:actual.add(path.name)
        if actual!=expected_names:raise Failure('entry_inventory')
        for name,expected in CONTRACT[group].items():
            if not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?',name) or any(x in ('.','..') for x in name.split('/')):
                raise Failure('entry_resource_name')
            path=root/name
            binary=group=='common' and name=='crypto/public-crl-verify'
            info=trusted(path,mode=0o755 if binary else 0o600)
            raw=read(path,limit=16*1024*1024 if binary else LIMIT)
            if stamp(path.lstat())!=stamp(info) or digest(raw)!=expected:raise Failure('entry_source_changed')
    trusted(ENTRY,mode=0o600)
    record=decode(read(MANAGER/'installed.json',installed=True))
    if (type(record)is not dict or set(record)!={'version','resources'} or type(record['version'])is not int
            or record['version']!=1 or type(record['resources'])is not dict or set(record['resources'])!=set(ROOTS)):
        raise Failure('installed_record_unknown')
    for group in ROOTS:
        expected=dict(CONTRACT[group])
        if group=='control':expected['root_entry.py']=digest(read(ENTRY,installed=True))
        if encode(record['resources'][group])!=encode(expected):raise Failure('installed_record_differs')
    sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOTS['control']))
    import batch,installation
    return batch,installation


def close_permission_if_restored(b,ins):
    n,_,_=b.native()
    with n.s.locks():
        had_session=n.s.Store().load() is not None
        if not had_session:
            with n.read_only():
                baseline=n.runtime.preflight(False)
                b.handoff.fresh_closed_baseline(n,baseline)
        else:b.fresh(n)
        ins.close_test_config()
        return had_session


def restore(b,ins):
    n,f,_=b.native()
    if exists(b.CURRENT):
        run,root=b.current_data()
        tested,saved,baseline=b.data_readback(n,run,root,recover=True)
        write_new(root/'final-session.json',encode(saved))
        write_new(root/'restoration.json',encode(dict(version=1,run=run,restored=True,
            session_sha256=digest(encode(saved)),baseline=baseline)))
    elif exists(ins.HARNESS_STATE/'current.json'):
        b.owner_fault_result(n,f,recover=True)
    else:
        with n.s.locks():
            current=n.s.Store().load()
            if current is not None:
                if n.recover_only.recover(n.s.Store())!=0:raise Failure('recovery_incomplete')
                b.fresh(n)
            else:
                with n.read_only():n.runtime.preflight(False)
    close_permission_if_restored(b,ins)
    b.public('manual_recovery',restored=True,manual_recovery=True,complete=True)
    return 0


def cross_boot_pending(b):
    n,_,_=b.native()
    # Fixed metadata branch only. The actual recovery obtains the native lock
    # and rechecks boot/context/current ownership inside the same closure.
    raw=read(NATIVE/'native-session.json',installed=True) if exists(NATIVE/'native-session.json') else None
    if raw is None:return exists(NATIVE/'boot-recovery'/'boot-reconcile.json')
    value=decode(raw)
    if type(value)is not dict or type(value.get('boot'))is not str:raise Failure('boot_journal_unknown')
    return value['boot']!=n.s.boot()


def boot_recover(b):
    n,_,_=b.native()
    code=b.wait_fixed(n.s.BASE/'recover_only.py',180)
    if type(code)is not int or code!=0:raise Failure('boot_recovery_incomplete')
    # Recover-only may legitimately retire the old journal. Never call absence
    # a passed phone/production test or fabricate a new closed proof here.
    b.public('boot_recovery_returned',complete=False,incomplete=True,manual_recovery=True)
    return 0


def main():
    global DIAGNOSTIC_STAGE
    b,ins=verified();action=sys.argv[1];os.umask(0o077)
    if action=='suite':return b.suite()
    if action=='data-window':return b.data_window()
    with lock(MANAGER/'lock') as manager_held,lock(STATE/'lock') as state_held:
        def held():manager_held();state_held()
        if action in DEVICE_ARITY:
            DIAGNOSTIC_STAGE='production_control'
            import device_control
            n,_,service=b.native()
            result=device_control.dispatch(action,sys.argv[2:],b,n,service,held)
            print(encode(dict(version=1,stage='production_control',**result)).decode().strip(),flush=True)
            return 0
        if action in ('service-install','service-start','service-disable','service-remove','service-status'):
            import production_service
            n,_,service=b.native()
            result=production_service.dispatch(action,b,n,service,held)
            print(encode(dict(version=1,stage='production_control',**result)).decode().strip(),flush=True)
            return 0
        if action=='recover':
            if cross_boot_pending(b):return boot_recover(b)
            return restore(b,ins)
        if action=='report':
            n,_,_=b.native()
            with n.s.locks():
                if n.s.Store().load() is None:
                    b.public('status',complete=False,incomplete=True);return 2
                b.fresh(n)
            b.public('status',restored=True,complete=True);return 0
        n,_,service=b.native()
        if action=='install-trial':
            DIAGNOSTIC_STAGE='production_control'
            import trial_install
            print(encode(dict(version=1,event='installation_progress',stage='enable_service')).decode().strip(),flush=True)
            result=trial_install.enable(b,n,service,held)
            print(encode(dict(version=1,stage='production_control',**result)).decode().strip(),flush=True)
            if result.get('native_ready_observed') is True:
                print('VPN 服务已就绪，可以用 iPhone 连接；安装窗口可以关闭。',flush=True)
            elif result.get('startup_observation_error'):
                print('暂未确认服务就绪，已保留服务当前状态；请稍后查看状态。',flush=True)
                return 2
            else:
                print('服务仍在启动，后台会继续；窗口可以关闭。手机连接尚未确认。',flush=True)
            return 0
        if service.read_configuration().enabled is not False:
            raise Failure('finite_requires_disabled_production')
        with n.s.locks():
            if n.s.Store().load() is not None:b.fresh(n)
            ins.test_config()
        result=2
        try:
            if action=='batch':
                DIAGNOSTIC_STAGE='closed_suite';b.closed_batch()
            else:b.verify_closed(n)
            DIAGNOSTIC_STAGE='data_admission'
            result=b.start_data(retry=action=='data-test')
        except BaseException as error:
            diagnostic_emit(diagnostic_failure(DIAGNOSTIC_STAGE,error))
            raise
        finally:
            try:
                restored=close_permission_if_restored(b,ins)
                b.public('restoration',restored=restored,complete=True)
            except Exception as error:
                diagnostic_emit(diagnostic_failure('permission_restore',error),restoration='unverified')
                result=2
                b.public('permission_restore',restored=False,incomplete=True,failure_class='validation_or_io')
        return result


if __name__=='__main__':
    try:result=main()
    except BaseException as error:
        code=str(error)
        print(encode(dict(version=1,event='operation_failed',stage=DIAGNOSTIC_STAGE,
            code=code if code in PUBLIC_CODES else 'unclassified_error',
            errno=error.errno if isinstance(error,OSError) else None,service_health_verified=False)).decode().strip(),flush=True)
        result=2
    sys.exit(result)
