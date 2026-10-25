"""Fixed actual persistent restoration functions for the finite boot successor.

Functions require an explicitly locked Native and fixed Store; ordinary tests
supply a fake native boundary. No general tasks, arbitrary path or shell API.
"""
import boot_record as r


def files_scope(io,old,completed):
    for name in sorted(r.FILE_KEYS):
        actual=io.file(name);row=old['files'].get(name)
        if row is None:
            if actual is not None:raise r.Refused('unrecorded_runtime_file')
        elif row['created']:
            released=row['phase']=='restored' or 'file-'+name in completed
            if actual is not None and (released or actual!=row['sha256']):raise r.Refused('created_file_scope_lost')
        elif actual!=row['sha256']:raise r.Refused('preexisting_file_missing_or_changed')


def admit(io,store):
    io.held()
    if store.load() is not None:raise r.Refused('existing_boot_record_requires_resume')
    native_raw,context_raw=io.originals();current_boot=io.boot()
    store.preserve(native_raw,context_raw) # Original bytes survive even rejected admission.
    old,context=r.sources(native_raw,context_raw,current_boot)
    configuration=io.configuration();implementation=io.implementation()
    if configuration!=context['configuration_sha256']:raise r.Refused('configuration_changed_since_finite_source')
    io.closed_kernel()
    io.context_admission(context_raw)
    r.alf_scope(old,io.alf(),[]);io.pf(old);files_scope(io,old,[])
    if (io.originals()!=(native_raw,context_raw) or io.boot()!=current_boot or io.configuration()!=configuration
            or io.implementation()!=implementation):
        raise r.Refused('admission_changed_during_observation')
    record=r.new(native_raw,context_raw,current_boot,configuration,implementation);store.save(record)
    return record


def stable(io,store,record):
    io.held();raw=store.originals(record);old=r.bind(record,*raw)
    if record['phase'] in ('ATTENTION','RESTORED'):raise r.Refused('boot_record_not_mutable')
    if (io.boot()!=record['new_boot'] or io.configuration()!=record['configuration_sha256']
            or io.originals()!=raw or io.implementation()!=record['implementation_sha256']):raise r.Refused('boot_configuration_or_originals_changed')
    io.closed_kernel();return old


def done(store,record,key):
    if record['intent'] is not None and record['intent']['key']!=key:raise r.Refused('other_pending_boot_effect')
    if key not in record['completed']:record['completed'].append(key)
    record['intent']=None;record['phase']='RESTORING';store.save(record)


def issue(io,store,record,old,key):
    effect=r.effect(old,key);intent={'key':key,'effect':effect}
    if record['intent'] is not None and record['intent']!=intent:raise r.Refused('unsettled_prior_boot_effect')
    record['intent']=intent;record['phase']='RESTORING';store.save(record)
    io.apply(record,effect,old)


def restore_alf(io,store,record):
    old=stable(io,store,record);current=r.alf_scope(old,io.alf(),record['completed'])
    if 'production_run' in old:
        # Reboot already closed the native data plane. Never set system-wide
        # block-all here: SSH/Tailscale may be the only maintenance path.
        if 'alf-close' not in record['completed']:done(store,record,'alf-close')
        for index in reversed(range(len(old['alf_transaction']['changes']))):
            key='alf-'+str(index);row=old['alf_transaction']['changes'][index]
            old=stable(io,store,record);current=r.alf_scope(old,io.alf(),record['completed'])
            if key in record['completed']:continue
            actual=current['apps'].get(row['key']) if row['kind']=='app' else current[row['key']]
            if row['phase'] in ('pending','restored','conflict') or actual is None:
                done(store,record,key);continue
            if actual is row['after']:
                issue(io,store,record,old,key)
                current=r.alf_scope(old,io.alf(),record['completed'])
                after=current['apps'].get(row['key']) if row['kind']=='app' else current[row['key']]
                if after is not row['before']:raise r.Refused('boot_alf_rule_readback')
            done(store,record,key)
        r.alf_finished(old,io.alf(),record['completed'])
        return
    if 'alf-close' not in record['completed']:
        if current['global_state']!=2:
            issue(io,store,record,old,'alf-close')
            current=r.alf_scope(old,io.alf(),record['completed'])
            if (current['global_state'],current['blockall'])!=(2,True):raise r.Refused('boot_alf_close_unverified')
        done(store,record,'alf-close')
    for index in reversed(range(len(old['alf_transaction']['changes']))):
        key='alf-'+str(index);row=old['alf_transaction']['changes'][index]
        old=stable(io,store,record);current=r.alf_scope(old,io.alf(),record['completed'])
        if key in record['completed']:continue
        actual=current['apps'][row['key']] if row['kind']=='app' else current[row['key']]
        if actual is not row['before']:
            issue(io,store,record,old,key)
            current=r.alf_scope(old,io.alf(),record['completed'])
            after=current['apps'][row['key']] if row['kind']=='app' else current[row['key']]
            if after is not row['before']:raise r.Refused('boot_alf_rule_readback')
        done(store,record,key)
    r.alf_finished(old,io.alf(),record['completed'])


def restore_pf(io,store,record):
    old=stable(io,store,record)
    r.alf_finished(old,io.alf(),record['completed'])
    current=io.pf(old)
    if 'pf-source' in record['completed'] and current['sha256']!=old['pf']['before_sha']:
        raise r.Refused('released_pf_source_changed')
    if 'pf-source' not in record['completed']:
        if current['sha256']!=old['pf']['before_sha']:
            issue(io,store,record,old,'pf-source')
            if io.pf(old)['sha256']!=old['pf']['before_sha']:raise r.Refused('boot_pf_source_readback')
        done(store,record,'pf-source')
    old=stable(io,store,record);current=io.pf(old)
    if 'pf-load' in record['completed'] and current['root']!='baseline':raise r.Refused('released_pf_root_changed')
    if 'pf-load' not in record['completed']:
        if current['root']!='baseline':
            issue(io,store,record,old,'pf-load')
            if io.pf(old)['root']!='baseline':raise r.Refused('boot_pf_root_readback')
        done(store,record,'pf-load')
    old=stable(io,store,record);current=io.pf(old);empty={'filters':[],'nat':[]}
    if 'pf-clear' in record['completed'] and current['anchor']!=empty:raise r.Refused('released_pf_anchor_changed')
    if 'pf-clear' not in record['completed']:
        if current['anchor']!=empty:
            issue(io,store,record,old,'pf-clear')
            if io.pf(old)['anchor']!=empty:raise r.Refused('boot_pf_anchor_readback')
        done(store,record,'pf-clear')


def restore_files(io,store,record):
    old=stable(io,store,record);files_scope(io,old,record['completed'])
    for name in sorted(r.FILE_KEYS):
        key='file-'+name
        if key in record['completed']:continue
        old=stable(io,store,record);files_scope(io,old,record['completed']);row=old['files'].get(name)
        if row and row['created'] and io.file(name) is not None:
            issue(io,store,record,old,key)
            if io.file(name) is not None:raise r.Refused('boot_created_file_not_removed')
        done(store,record,key)


def finish(io,store,record):
    old=stable(io,store,record);r.alf_scope(old,io.alf(),record['completed'])
    required={'alf-close','pf-source','pf-load','pf-clear'}|{'alf-'+str(i) for i in range(len(old['alf_transaction']['changes']))}|{'file-'+k for k in r.FILE_KEYS}
    if set(record['completed'])!=required or record['intent'] is not None:raise r.Refused('boot_steps_incomplete')
    r.alf_finished(old,io.alf(),record['completed'])
    current=io.pf(old)
    if current['sha256']!=old['pf']['before_sha'] or current['root']!='baseline' or current['anchor']!={'filters':[],'nat':[]}:
        raise r.Refused('boot_final_pf')
    files_scope(io,old,record['completed']);stable(io,store,record)
    record['phase']='RESTORED';store.save(record)
    # Only this new reconciliation record completes. Original native/context
    # bytes remain archived; retiring the native journal is a later handoff.
    return True


def restore_locked(io,store):
    record=store.load()
    if record is None:raise r.Refused('boot_admission_required')
    stable(io,store,record)
    io.context_admission(store.originals(record)[1])
    io.settle(record) # Settle only this new boot's owned writer before any effect.
    restore_alf(io,store,record);restore_pf(io,store,record);restore_files(io,store,record)
    return finish(io,store,record)


def recover_bounded_locked(io):
    """Only fixed recover_only.main calls this while owning Native.locked()."""
    from boot_native import Native
    from boot_store import Store
    import boot_handoff
    Native.installed_scope();io.held();store=Store(io)
    record=store.load()
    if record is None:record=admit(io,store)
    if record['phase']!='RESTORED':
        io.attach_writer(store);Native.installed_scope();restore_locked(io,store)
    result=boot_handoff.run_locked(io,store)
    return result


def reconcile_native():
    """Fixed no-argument native call; no arbitrary boot, path, PID or command."""
    from boot_native import Native
    Native.installed_scope();io=Native()
    with io.locked():return recover_bounded_locked(io)


def main():
    raise r.Refused('source_candidate_native_entry_disabled_pending_independent_review_and_packaging')

if __name__=='__main__':main()
