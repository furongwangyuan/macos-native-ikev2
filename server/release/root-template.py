#!/usr/bin/python3
"""Fixed fresh/v9-resume release; does not adopt uninstalled old candidates."""
# IO_PRIMITIVES
# ASSET_PRIMITIVES
# DIAGNOSTIC_PRIMITIVES
# ARGUMENT_PRIMITIVES
DIAGNOSTIC_STAGE='installation'
PAYLOAD={} # RELEASE_PAYLOAD
OLD_PAYLOAD={} # PREVIOUS_V9_PAYLOAD
PRIOR_CONTROL={} # PREVIOUS_CONTROL_PAYLOAD
PUBLIC_CODES=frozenset() # PUBLIC_ERROR_CODES
INSTALL_STEP="entry"
ROOTS={'control':Path('/usr/local/family-vpn/production-acceptance'),
       'common':Path('/usr/local/family-vpn/production-guardian'),
       'harness':Path('/usr/local/family-vpn/production-owner-fault')}
HARNESS_STATE=Path('/private/var/db/family-vpn/production-owner-fault')
RELEASE_ACTIONS=dict.fromkeys(('inspect','install-trial','data-test','recover','report',
         'service-install','service-start','service-disable','service-remove','service-status'),0)
RELEASE_ACTIONS.update(DEVICE_ARITY)


def progress(step):
    global INSTALL_STEP
    INSTALL_STEP=step
    print(encode(dict(version=1,event='installation_progress',stage=step)).decode().strip(),flush=True)

def public_failure(step,error):
    code=str(error)
    known=code if code in PUBLIC_CODES else 'unclassified_error'
    value=dict(version=1,event='operation_failed',stage=step,code=known,
               errno=error.errno if isinstance(error,OSError) else None,
               service_health_verified=False)
    print(encode(value).decode().strip(),flush=True)

def no_running_history():
    # This is ONLY the observed v9 half-install, never an installed-service upgrade.
    forbidden=(MANAGER/'installed.json',NATIVE/'native-session.json',NATIVE/'service-state.json',
        NATIVE/'boot-recovery/boot-reconcile.json',NATIVE/'production/service-control.json',
        STATE/'current-data.json',STATE/'closed-proof.json',STATE/'closed-suite.json',
        STATE/'server/current.json',HARNESS_STATE/'current.json',CONF/'service-activation.json',
        MANAGER/'test-config-intent.json')
    if any(exists(path) for path in forbidden):raise Failure('known_partial_upgrade_has_execution_history')
    for name,key in (('config.json','allow_data'),('supervisor-config.json','enabled')):
        value=decode(read(CONF/name,installed=True))
        if (type(value)is not dict or set(value)!={'version',key}
                or type(value['version'])is not int or value['version']!=1 or value[key]is not False):
            raise Failure('known_partial_upgrade_configuration_not_closed')
    for label in ('org.familyvpn.guardian-recovery','org.familyvpn.service','org.familyvpn.crl-refresh','org.familyvpn.server'):
        if exists(Path('/Library/LaunchDaemons')/(label+'.plist')):
            raise Failure('known_partial_upgrade_existing_job_file')
        result=subprocess.run(['/bin/launchctl','print','system/'+label],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,close_fds=True,start_new_session=True,timeout=5)
        expected=('Bad request.\nCould not find service "'+label+'" in domain for system\n').encode()
        if result.returncode!=113 or result.stdout or result.stderr!=expected:
            raise Failure('known_partial_upgrade_job_not_absent')

def replace_exact(path,before,after,mode=0o600):
    info=trusted(path,mode=mode)
    if read(path,limit=16*1024*1024)!=before:raise Failure('known_partial_upgrade_before_changed')
    temporary=path.parent/('.simple-update-'+secrets.token_hex(12));fd=None
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb',closefd=False) as out:
            out.write(after);out.flush();os.fchmod(fd,mode);os.fsync(fd)
        os.close(fd);fd=None
        if stamp(path.lstat())!=stamp(info) or read(path,limit=16*1024*1024)!=before:
            raise Failure('known_partial_upgrade_before_changed')
        os.replace(temporary,path);sync_dir(path.parent)
        if read(path,limit=16*1024*1024)!=after:raise Failure('known_partial_upgrade_readback_failed')
    finally:
        if fd is not None:os.close(fd)
        if exists(temporary):temporary.unlink()

def update_known_partial(source,held):
    """Only the exact observed v9 no-receipt/no-owner tree; no broad migration."""
    held();no_running_history();data=all_resources(source)
    if set(OLD_PAYLOAD)!=set(PAYLOAD):raise Failure('previous_v9_map_not_built')
    record=encode(dict(version=1,old=OLD_PAYLOAD,new=PAYLOAD))
    intent=MANAGER/'simple-start-update.json'
    resuming=exists(intent)
    if resuming and read(intent,installed=True)!=record:raise Failure('known_partial_upgrade_intent_unknown')
    for group,folder in ROOTS.items():
        if set(OLD_PAYLOAD[group])!=set(PAYLOAD[group]):raise Failure('known_partial_upgrade_inventory_scope')
        actual=asset_inventory(folder,OLD_PAYLOAD[group],installed=True)
        for name in actual:
            observed=digest(asset_read(folder,name,True))
            allowed={OLD_PAYLOAD[group][name],PAYLOAD[group][name]} if resuming else {OLD_PAYLOAD[group][name]}
            if observed not in allowed:raise Failure('known_partial_upgrade_unknown_source_preserved')
        old=encode(dict(version=1,path=str(folder),inventory=OLD_PAYLOAD[group]))
        new=encode(dict(version=1,path=str(folder),inventory=PAYLOAD[group]))
        if read(MANAGER/('publish-'+folder.name+'.json'),installed=True) not in ((old,new) if resuming else (old,)):
            raise Failure('known_partial_upgrade_original_intent_changed')
    if not resuming:write_new(intent,record)
    backup=MANAGER/'simple-start-previous';directory(backup)
    for group,folder in ROOTS.items():
        directory(backup/group)
        for name,after in data[group].items():
            held();before=asset_read(folder,name,True)
            if digest(before)==PAYLOAD[group][name]:continue
            if digest(before)!=OLD_PAYLOAD[group][name]:raise Failure('known_partial_upgrade_unknown_source_preserved')
            asset_write_new(backup/group,name,before)
            no_running_history();held();replace_exact(folder/name,before,after,asset_mode(name))
        old=encode(dict(version=1,path=str(folder),inventory=OLD_PAYLOAD[group]))
        new=encode(dict(version=1,path=str(folder),inventory=PAYLOAD[group]))
        target=MANAGER/('publish-'+folder.name+'.json')
        write_new(backup/group/'original-publication.json',old)
        current=read(target,installed=True)
        if current!=new:replace_exact(target,old,new)
    held();no_running_history();all_resources()
    write_new(MANAGER/'simple-start-update-complete.json',record)


def update_closed_control(source,manager_and_state_held):
    """One exact same-runtime control update; no runtime/activation changes."""
    import types
    data=all_resources(source)
    if (set(PRIOR_CONTROL)!=set(PAYLOAD) or
            any(PRIOR_CONTROL[g]!=PAYLOAD[g] for g in ('common','harness')) or
            set(PRIOR_CONTROL['control'])!=set(PAYLOAD['control'])):
        raise Failure('control_update_runtime_or_inventory_changed')
    changed={n for n in PAYLOAD['control'] if PAYLOAD['control'][n]!=PRIOR_CONTROL['control'][n]}
    if changed!={'production_service_job.py','root_entry.py'}:
        raise Failure('control_update_scope_changed')
    receipt=MANAGER/'installed.json';old_receipt=encode(dict(version=1,resources=PRIOR_CONTROL))
    if read(receipt,installed=True)!=old_receipt:raise Failure('control_update_old_receipt_changed')
    intent=MANAGER/'launchd-state-update.json'
    record=encode(dict(version=1,old=PRIOR_CONTROL,new=PAYLOAD))
    resume=exists(intent)
    if resume and read(intent,installed=True)!=record:raise Failure('control_update_intent_changed')
    def inventory():
        manager_and_state_held()
        for group,folder in ROOTS.items():
            asset_inventory(folder,PAYLOAD[group],installed=True)
            for name in PAYLOAD[group]:
                allowed={PRIOR_CONTROL[group][name]}
                if resume and group=='control':allowed.add(PAYLOAD[group][name])
                if digest(asset_read(folder,name,True)) not in allowed:
                    raise Failure('control_update_unknown_code_preserved')
    inventory()
    # Runtime is unchanged. The original job helper is valid for the required
    # absent/disabled state; only the new job reader and entry will be replaced.
    sys.path[:0]=[str(ROOTS['common']),str(ROOTS['control'])]
    import service_supervisor as service
    import production_service_job as job
    if Path(service.__file__).resolve()!=ROOTS['common']/'service_supervisor.py' or Path(job.__file__).resolve()!=ROOTS['control']/'production_service_job.py':
        raise Failure('control_update_mixed_source')
    module=types.ModuleType('fixed_control_update_validation')
    exec(compile(data['control']['production_service.py'],'fixed_control_update_validation','exec'),module.__dict__)
    with module.native_locked() as io:
        def held():manager_and_state_held();io.held()
        c=module.Control(None,None,service,held)
        value=c.load()
        if value is None or value['phase']!='DISABLED':raise Failure('control_update_requires_disabled_service')
        state=service.ServiceStore().load()
        if state is None or state['phase'] not in ('STOPPED','DISABLED') or state['boot']!=service.s.boot():
            raise Failure('control_update_service_history_not_stopped')
        original_state=read(NATIVE/'service-state.json',installed=True)
        c.disabled_configs();job.check_file(service.s,c.plist)
        if job.loaded() or job.override()is not True:raise Failure('control_update_job_not_disabled')
        service.recovery_job_gate()
        if service.s.Store().load()is not None or exists(NATIVE/'boot-recovery/boot-reconcile.json'):
            raise Failure('control_update_native_history_preserved')
        module.fresh_locked(service,io)
        publication=MANAGER/('publish-'+ROOTS['control'].name+'.json')
        old_pub=encode(dict(version=1,path=str(ROOTS['control']),inventory=PRIOR_CONTROL['control']))
        new_pub=encode(dict(version=1,path=str(ROOTS['control']),inventory=PAYLOAD['control']))
        if read(publication,installed=True) not in ((old_pub,new_pub) if resume else (old_pub,)):
            raise Failure('control_update_publication_changed')
        def unchanged():
            held();c.scope();c.disabled_configs()
            if read(NATIVE/'service-state.json',installed=True)!=original_state or service.s.Store().load()is not None:
                raise Failure('control_update_history_changed')
        unchanged()
        if not resume:write_new(intent,record)
        resume=True
        backup=MANAGER/'launchd-state-update-originals';directory(backup)
        write_new(backup/'installed.json',old_receipt);write_new(backup/'publication.json',old_pub)
        for name in sorted(changed):
            unchanged();before=asset_read(ROOTS['control'],name,True)
            if digest(before)==PAYLOAD['control'][name]:continue
            if digest(before)!=PRIOR_CONTROL['control'][name]:raise Failure('control_update_unknown_code_preserved')
            write_new(backup/name,before)
            replace_exact(ROOTS['control']/name,before,data['control'][name])
        unchanged();all_resources()
        if read(publication,installed=True)!=new_pub:replace_exact(publication,old_pub,new_pub)
        replace_exact(receipt,old_receipt,encode(dict(version=1,resources=PAYLOAD)))


def all_resources(source=None):
    if set(PAYLOAD)!=set(ROOTS):raise Failure('release_not_built')
    out={}
    for group,pins in PAYLOAD.items():
        root=ROOTS[group] if source is None else source/group
        if group!='common' and any('/' in name for name in pins):raise Failure('release_group_scope')
        asset_inventory(root,pins,installed=source is None)
        out[group]={}
        for name,wanted in pins.items():
            if type(wanted)is not str or not re.fullmatch('[a-f0-9]{64}',wanted):raise Failure('release_digest')
            raw=asset_read(root,name,source is None)
            if digest(raw)!=wanted:raise Failure('release_source_changed')
            if name.endswith('.py'):compile(raw,name,'exec')
            out[group][name]=raw
    return out

def initial_state():
    if exists(MANAGER/'installed.json'):
        actual=read(MANAGER/'installed.json',installed=True)
        if actual!=encode(dict(version=1,resources=PAYLOAD)):
            raise Failure('existing_release_receipt_unknown')
    if exists(NATIVE/'service-state.json'):
        raise Failure('production_already_used_choose_service_action')
    for path in (NATIVE/'boot-recovery'/'boot-reconcile.json',NATIVE/'production'/'service-control.json'):
        if exists(path):raise Failure('existing_service_history_preserved')
    if exists(NATIVE/'native-session.json'):
        read(NATIVE/'lock',installed=True,limit=4096)
        value=decode(read(NATIVE/'native-session.json',installed=True))
        if (type(value)is not dict or type(value.get('version'))is not int or value['version']!=8
                or value.get('profile')!='production-native-fleet-v1'
                or value.get('active')is not False or value.get('phase')!='RESTORED'):
            raise Failure('existing_native_history_requires_inspection')
    # This release intentionally does not adopt any historical source tree.
    if exists(ROOTS['common']) and not exists(MANAGER/'installed.json'):
        expected=encode(dict(version=1,path=str(ROOTS['common']),inventory=PAYLOAD['common']))
        if not exists(MANAGER/'publish-production-guardian.json') or read(MANAGER/'publish-production-guardian.json',installed=True)!=expected:
            raise Failure('existing_unowned_runtime_preserved')

def original_or_first_lock(path):
    """Only an empty new state directory may receive its first lock inode."""
    trusted(path.parent,directory=True,mode=0o700)
    if exists(path):
        read(path,installed=True,limit=4096)
        return
    if any(path.parent.iterdir()):raise Failure('history_without_original_lock')
    write_new(path,b'')

def installed_modules():
    root=ROOTS['control']
    asset_inventory(root,PAYLOAD['control'],installed=True)
    for name,wanted in PAYLOAD['control'].items():
        if digest(asset_read(root,name,True))!=wanted:raise Failure('installed_control_changed')
    sys.dont_write_bytecode=True;sys.path.insert(0,str(root))
    import batch,installation,pki_registry_setup
    for module in (batch,installation,pki_registry_setup):
        if Path(module.__file__).resolve()!=root/(module.__name__+'.py'):
            raise Failure('mixed_release_control')
    return batch,installation,pki_registry_setup

def install(source,manager_held):
    progress("verify_payload");data=all_resources(source);initial_state()
    for path in (NATIVE,STATE,CONF,RUN.parent,RUN):directory(path)
    original_or_first_lock(NATIVE/'lock')
    original_or_first_lock(STATE/'lock')
    with lock(STATE/'lock') as state_held,install_native_locks() as native_held:
        def held():manager_held();state_held();native_held()
        held();initial_state()
        # New payload imports are only possible after complete fixed publication.
        progress('publish_code')
        for group in ('common','harness','control'):asset_publish(ROOTS[group],data[group])
        for path in (HARNESS_STATE,NATIVE/'production',NATIVE/'boot-recovery',NATIVE/'boot-recovery'/'originals'):directory(path)
        original_or_first_lock(HARNESS_STATE/'lock')
        for name in ('config.json','supervisor-config.json'):
            write_new(CONF/name,data['common'][name])
        # Bind runtime path before importing setup; it shares the exact source
        # closure and cannot fall back to workspace or an older installed tree.
        sys.path.insert(0,str(ROOTS['common']))
        batch,ins,setup=installed_modules()
        n,_,service=batch.native()
        if ins.COMMON_SHA!=digest(data['common']['candidate-pins.json']):raise Failure('release_common_binding')
        if ins.job() is not None or exists(ins.PLIST):
            raise Failure('recovery_job_already_present_before_closed_trial')
        import production_service_job
        if (Path(production_service_job.__file__).resolve()!=ROOTS['control']/'production_service_job.py'
                or production_service_job.loaded()):
            raise Failure('production_job_not_absent_before_closed_trial')
        for name in ('org.familyvpn.service.plist','org.familyvpn.crl-refresh.plist','org.familyvpn.server.plist'):
            if exists(Path('/Library/LaunchDaemons')/name):raise Failure('existing_writer_job_preserved')
        journal=NATIVE/'native-session.json'
        prior=read(journal,installed=True) if exists(journal) else None
        if prior is not None:
            saved=n.s.Store().load()
            if (saved['active']is not False or saved['phase']!='RESTORED'
                    or saved.get('cleanup_codes')!=[] or saved.get('recovery_result')!='restored'):
                raise Failure('existing_v8_native_not_restored')
            batch.handoff.fixed_roles_gone(n,saved)
        def unchanged_closed_source():
            held()
            if (read(journal,installed=True) if exists(journal) else None)!=prior:
                raise Failure('initial_native_source_changed')
            if prior is not None:batch.handoff.fixed_roles_gone(n,n.s.Store().load())
            all_resources()
        # This performs fresh native closure without CRL/registry prerequisites;
        # it never changes the old native journal or regenerates credentials.
        progress('initialize_public_identity')
        setup.initialize_locked(held,unchanged_closed_source)
        progress('verify_closed_baseline')
        with n.read_only():
            if prior is None:
                fresh=n.runtime.preflight(False)
                batch.handoff.fresh_closed_baseline(n,fresh)
            else:batch.fresh(n)
        held();all_resources()
        write_new(MANAGER/'installed.json',encode(dict(version=1,resources=PAYLOAD)))
        progress('installation_complete')

def run_entry(action,values=()):
    if action not in RELEASE_ACTIONS or action=='inspect':raise Failure('release_entry_action')
    validate_request(action,list(values),RELEASE_ACTIONS)
    all_resources()
    actual=decode(read(MANAGER/'installed.json',installed=True))
    if encode(actual)!=encode(dict(version=1,resources=PAYLOAD)):raise Failure('release_installed_record')
    # Existing manager descriptor is close-on-exec; fixed entry reacquires it.
    os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(ROOTS['control']/'root_entry.py'),action,*values],ENV)

def main():
    if os.geteuid()!=0 or len(sys.argv)<2:
        raise Failure('fixed_release_action')
    action,values=validate_request(sys.argv[1],sys.argv[2:],RELEASE_ACTIONS)
    os.umask(0o077)
    if action=='inspect':
        value=dict(version=1,stage='metadata_only',native_runtime_present=exists(ROOTS['common']),
            installed_receipt_present=exists(MANAGER/'installed.json'),production_ready=False)
        print(encode(value).decode().strip());return 0
    if action=='install-trial':
        source=Path(__file__).resolve().parent/'payload'
        progress('verify_source');all_resources(source)
        directory(MANAGER);original_or_first_lock(MANAGER/'lock')
        with lock(MANAGER/'lock') as manager_held:
            if exists(MANAGER/'installed.json'):
                # Only this exact stopped same-runtime predecessor can update.
                current=read(MANAGER/'installed.json',installed=True)
                if current!=encode(dict(version=1,resources=PAYLOAD)):
                    progress('update_closed_control')
                    with lock(STATE/'lock') as state_held:
                        def held():manager_held();state_held()
                        update_closed_control(source,held)
                run_entry('install-trial')
            if exists(ROOTS['common']) and not exists(MANAGER/'installed.json'):
                # Exact new publication may simply resume. Only a mismatch goes
                # through the one pinned old-v9 transition below.
                wanted=encode(dict(version=1,path=str(ROOTS['common']),inventory=PAYLOAD['common']))
                if (exists(MANAGER/'simple-start-update.json') or
                        read(MANAGER/'publish-production-guardian.json',installed=True)!=wanted):
                    progress('update_known_partial_installation')
                    with lock(STATE/'lock') as state_held,install_native_locks() as native_held,lock(HARNESS_STATE/'lock') as harness_held:
                        def held():manager_held();state_held();native_held();harness_held()
                        update_known_partial(source,held)
            initial_state();install(source,manager_held);run_entry('install-trial')
    with lock(MANAGER/'lock'):run_entry(action,values)
    return 2

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:
        public_failure(INSTALL_STEP,error)
        print(encode(dict(version=1,stage='release_stopped',incomplete=True,
            installed_state_requires_readback=True,production_ready=False)).decode().strip(),flush=True)
        sys.exit(2)
