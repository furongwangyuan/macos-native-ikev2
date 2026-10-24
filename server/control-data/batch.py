"""Fixed installed sequence: common closed controls -> owner fault -> finite data.

This module has no CLI; the verified fixed root entry selects a finite action.
No production acceptance is written. Every native truth comes from current code.
"""
import contextlib
import copy
import importlib
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid
import install_io as io
import installation as ins
import handoff
import finite_service
import diagnostics as diag

STATE=io.STATE
PROOF=STATE/'closed-proof.json'
DATA=STATE/'data'
CURRENT=STATE/'current-data.json'
SUITE=STATE/'closed-suite.json'
DIAG_CURRENT=STATE/'closed-diagnostic-current.json'
DIAG_ROOT=STATE/'diagnostics'


def native():
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(ins.HARNESS));sys.path.insert(0,str(ins.COMMON))
    n=importlib.import_module('native_adapter')
    f=importlib.import_module('fixed_entries')
    service=importlib.import_module('service_supervisor')
    for module,root in ((n,ins.HARNESS),(f,ins.HARNESS),(service,ins.COMMON)):
        if Path(module.__file__).resolve()!=root/(module.__name__+'.py'):raise io.Failure('mixed_installed_module')
    n.sources();n.runtime.require_closure()
    return n,f,service


def public(stage,**facts):
    allowed={'complete','restored','ready','incomplete','data_mode_tested','native_owner_sigkill','native_closed_suite',
             'new_same_version_rekey_observed','production_ready','deadline_seconds','manual_recovery','failure_class'}
    if set(facts)-allowed:raise io.Failure('public_report_fields')
    if 'failure_class' in facts and facts['failure_class'] not in ('validation_or_io','preflight_or_window','child_timeout','roles_not_gone','uplink_ipv4_unavailable','uplink_ipv6_unavailable'):
        raise io.Failure('public_report_code')
    print(io.encode(dict(version=1,stage=stage,production_ready=False,**facts)).decode().strip(),flush=True)


def restored_record(n):
    value=n.s.Store().load()
    if (value is None or value.get('active')is not False or value.get('phase')!='RESTORED'
            or value.get('cleanup_codes')!=[] or value.get('recovery_result')!='restored'
            or value.get('boot')!=n.s.boot()):raise io.Failure('native_restoration_incomplete')
    if value.get('child') is not None and value['child'].get('phase')!='exited':raise io.Failure('child_not_settled')
    if value.get('mutation') is not None and value['mutation'].get('phase')!='settled':raise io.Failure('writer_not_settled')
    return value


def fresh(n):
    """Actual fresh closed native reads after the sole owner is gone/settled."""
    before=restored_record(n)
    with n.read_only():
        baseline=handoff.fresh_closed_baseline(n,before)
    if io.encode(n.s.Store().load())!=io.encode(before):raise io.Failure('fresh_journal_changed')
    return before,baseline


def save_diagnostic(root, run, initial=None, cleanup=None, codes=(), *, name='diagnostic.json'):
    try:
        value=diag.diagnostic_record(run,initial,cleanup,codes)
        io.write_new(root/name,io.encode(value))
        return True
    except Exception:
        diag.diagnostic_emit(dict(stage='data_cleanup',reason='diagnostic_write_failed',action=None))
        return False


def read_diagnostic(root,run,*,name='diagnostic.json',stage='data_admission'):
    try:
        value=io.decode(io.read(root/name,installed=True,limit=8192))
        return diag.diagnostic_validate_record(value,run)
    except Exception:
        return diag.diagnostic_record(run,dict(stage=stage,reason='diagnostic_unavailable',action=None))


def emit_diagnostic(value, *, restoration='not_attempted'):
    for part in ('initial','cleanup'):
        if value[part] is not None:
            diag.diagnostic_emit(value[part],restoration=restoration,codes=value['cleanup_codes'])


def closed_diagnostic_binding():
    value=io.decode(io.read(DIAG_CURRENT,installed=True,limit=1024))
    if (type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int
            or value['version']!=1 or type(value['run'])is not str or not re.fullmatch('[a-f0-9]{32}',value['run'])):
        raise io.Failure('closed_diagnostic_binding_unknown')
    root=DIAG_ROOT/value['run'];io.trusted(root,directory=True,mode=0o700)
    return value['run'],root


def suite():
    n,_,_=native()
    run,diagnostic_root=closed_diagnostic_binding()
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
        signal.signal(sig,lambda *_:n.runtime.STOP.set())
    with n.s.locks():
        if io.exists(SUITE):raise io.Failure('closed_suite_receipt_preserved')
        previous=n.s.Store().load()
        if previous is not None and previous['active']:raise io.Failure('old_owner_requires_recovery')
        n.old_job_absent()
        steps=[]
        for action in ('closed-test','closed-charon-term-test','closed-charon-kill-test'):
            initial=None
            try:
                code=n.runtime.run_session(action,n.s.Store())
                if type(code)is not int or code!=0:
                    initial=dict(stage='closed_suite',reason='closed_control_failed',action=action)
            except BaseException as error:
                initial=diag.diagnostic_failure('closed_suite',error,action=action)
                save_diagnostic(diagnostic_root,run,initial,name=action+'.json')
                raise
            # The common routine swallows its original native exception. Never
            # infer it from the last command or the subsequently RESTORED phase.
            if initial is not None:
                codes=[]
                try:
                    current=n.s.Store().load()
                    codes=diag.diagnostic_cleanup_codes(current.get('cleanup_codes',[]))
                except Exception:pass
                save_diagnostic(diagnostic_root,run,initial,codes=codes,name=action+'.json')
            try:
                saved,baseline=fresh(n)
            except BaseException as error:
                save_diagnostic(diagnostic_root,run,None,
                    diag.diagnostic_failure('restoration_readback',error),name=action+'-restore.json')
                raise
            io.write_new(STATE/('session-'+action+'.json'),io.encode(saved))
            if initial is not None:raise io.Failure('closed_control_failed')
            steps.append(action)
        io.write_new(SUITE,io.encode(dict(version=1,common_sha256=ins.COMMON_SHA,boot=n.s.boot(),
            steps=steps,restored=True,resources=n.resource_snapshot(),baseline=baseline)))
    return 0


def owner_fault_result(n,f,*,recover=False):
    with io.lock(ins.HARNESS_STATE/'lock'),n.s.locks():
        receipts=f.current('coordinator');intent=receipts.read('intent.json')
        from fault_protocol import identity
        from process_observe import observe
        for role in ('coordinator','owner','observer'):
            ident=identity(receipts.read(role+'.json'))
            if observe(ident['pid']) is not None:raise io.Failure('fault_role_not_gone')
        adapter=n.Native(intent,receipts)
        if recover and adapter.recover()is not True:raise io.Failure('fault_recovery_incomplete')
        if adapter.restored_readback()is not True:raise io.Failure('fault_fresh_readback_failed')
        result=receipts.read('result.json') if receipts.exists('result.json') else None
        passed=(type(result)is dict and set(result)=={'run','phase','passed','native_data_mode_tested','observer_reaped'}
                and result['run']==intent['run'] and result['phase']=='PASSED' and result['passed']is True
                and result['native_data_mode_tested']is False and result['observer_reaped']is True)
        saved,baseline=fresh(n)
        return passed,saved,baseline,intent


def wait_fixed(path,seconds):
    if path not in (ins.CONTROL/'root_entry.py',ins.HARNESS/'coordinator_entry.py',ins.COMMON/'recover_only.py'):
        raise io.Failure('fixed_child_entry')
    # Actual argv for the control entry is fixed by the only caller below.
    args=['/usr/bin/python3','-I','-B',str(path)]
    if path==ins.CONTROL/'root_entry.py':args.append('suite')
    child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        env=io.ENV,close_fds=True,start_new_session=True,cwd='/')
    try:return child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        # No signal, second writer or false hard cutoff. Existing owner/observer
        # retains its exact ownership and recovery responsibilities.
        raise io.Failure('child_still_running_incomplete')


def closed_batch():
    n,f,_=native()
    if io.exists(PROOF):return verify_closed(n)
    if io.exists(ins.HARNESS_STATE/'current.json'):
        raise io.Failure('old_fault_attempt_preserved_requires_inspect')
    public('closed_controls',complete=False)
    if not io.exists(SUITE):
        diagnostic_run=uuid.uuid4().hex;io.directory(DIAG_ROOT);diagnostic_root=DIAG_ROOT/diagnostic_run
        io.directory(diagnostic_root)
        raw=io.encode(dict(version=1,run=diagnostic_run))
        if io.exists(DIAG_CURRENT):ins.replace_owned(DIAG_CURRENT,io.read(DIAG_CURRENT,installed=True),raw)
        else:io.write_new(DIAG_CURRENT,raw)
        code=wait_fixed(ins.CONTROL/'root_entry.py',180)
        if code!=0:
            seen=False
            for action in ('closed-test','closed-charon-term-test','closed-charon-kill-test'):
                for name in (action+'.json',action+'-restore.json'):
                    if io.exists(diagnostic_root/name):
                        emit_diagnostic(read_diagnostic(diagnostic_root,diagnostic_run,name=name,stage='closed_suite'))
                        seen=True
            if not seen:
                diag.diagnostic_emit(dict(stage='closed_suite',reason='diagnostic_unavailable',action=None))
            raise io.Failure('closed_suite_failed')
    value=io.decode(io.read(SUITE,installed=True))
    if (type(value)is not dict or type(value.get('version'))is not int or value['version']!=1
            or value.get('common_sha256')!=ins.COMMON_SHA or value.get('boot')!=n.s.boot()
            or value.get('steps')!=['closed-test','closed-charon-term-test','closed-charon-kill-test']
            or value.get('restored')is not True or value.get('resources')!=n.resource_snapshot()):
        raise io.Failure('closed_suite_receipt_not_current')
    with n.s.locks():fresh(n)
    try:
        code=wait_fixed(ins.HARNESS/'coordinator_entry.py',180)
        passed,saved,baseline,intent=owner_fault_result(n,f)
        if type(code)is not int or code!=0 or not passed:raise io.Failure('owner_fault_sequence_failed_restored')
    except BaseException as error:
        diag.diagnostic_emit(diag.diagnostic_failure('owner_fault',error));raise
    io.write_new(STATE/'closed-final-session.json',io.encode(saved))
    proof=dict(version=1,profile='production-native-fleet-v1',common_sha256=ins.COMMON_SHA,boot=n.s.boot(),
        resources=n.resource_snapshot(),baseline=baseline,fault_run=intent['run'],
        session_sha256=io.digest(io.encode(saved)),native_closed_suite=True,native_owner_sigkill=True,
        native_mutator_ownerkill=False,native_data_faults=False)
    io.write_new(PROOF,io.encode(proof))
    public('closed_faults',complete=True,restored=True,native_closed_suite=True,native_owner_sigkill=True)
    return proof


def resources_match(expected,actual,*,restoring=False):
    if actual==expected:return True
    if type(expected)is not dict or type(actual)is not dict or not restoring:return False
    key=str(io.CONF/'config.json')
    on=io.encode(dict(version=1,allow_data=True));off=io.encode(dict(version=1,allow_data=False))
    changed=dict(expected);changed[key]={'sha256':io.digest(off)}
    owned=io.encode(dict(version=1,before_sha256=io.digest(off),after_sha256=io.digest(on)))
    return (expected.get(key)=={'sha256':io.digest(on)} and actual==changed
            and io.read(io.MANAGER/'test-config-intent.json',installed=True)==owned)


def verify_closed(n,*,restoring=False):
    value=io.decode(io.read(PROOF,installed=True))
    keys={'version','profile','common_sha256','boot','resources','baseline','fault_run','session_sha256',
          'native_closed_suite','native_owner_sigkill','native_mutator_ownerkill','native_data_faults'}
    if (type(value)is not dict or set(value)!=keys or type(value['version'])is not int or value['version']!=1
            or value['profile']!='production-native-fleet-v1' or value['common_sha256']!=ins.COMMON_SHA
            or value['boot']!=n.s.boot() or not resources_match(value['resources'],n.resource_snapshot(),restoring=restoring)
            or value['native_closed_suite']is not True or value['native_owner_sigkill']is not True
            or value['native_mutator_ownerkill']is not False or value['native_data_faults']is not False
            or io.digest(io.read(STATE/'closed-final-session.json',installed=True))!=value['session_sha256']):
        raise io.Failure('closed_proof_not_same_version_and_boot')
    return value


def current_data():
    value=io.decode(io.read(CURRENT,installed=True))
    if (type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int
            or value['version']!=1 or type(value['run'])is not str or not re.fullmatch('[a-f0-9]{32}',value['run'])):
        raise io.Failure('data_pointer_unknown')
    root=DATA/value['run'];io.trusted(root,directory=True,mode=0o700)
    return value['run'],root


def data_binding(n,run,root,*,restoring=False):
    intent=io.decode(io.read(root/'intent.json',installed=True))
    if (type(intent)is not dict or set(intent)!={'version','run','boot','resources','common_sha256','seconds','previous_session_sha256'}
            or type(intent['version'])is not int or intent['version']!=1 or intent['run']!=run
            or intent['boot']!=n.s.boot() or intent['common_sha256']!=ins.COMMON_SHA
            or type(intent['seconds'])is not int or intent['seconds']!=900
            or type(intent['resources'])is not dict or type(intent['previous_session_sha256'])is not str
            or not re.fullmatch('[a-f0-9]{64}',intent['previous_session_sha256'])):
        raise io.Failure('data_intent_not_current')
    if not resources_match(intent['resources'],n.resource_snapshot(),restoring=restoring):
        raise io.Failure('data_resources_changed')

    return intent


def data_window():
    n,_,service=native();run,root=current_data()
    verify_closed(n);intent=data_binding(n,run,root)
    if io.exists(root/'owner.json') or io.exists(root/'result.json'):raise io.Failure('data_run_already_started')
    from process_observe import observe
    observed=observe(os.getpid())
    ident=None if observed is None else observed.identity
    if ident is None or observed.members!=(os.getpid(),) or ident['pgid']!=os.getpid() or ident['uid']!=0:raise io.Failure('data_owner_identity')
    io.write_new(root/'owner.json',io.encode(ident))
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
        signal.signal(sig,lambda *_:n.runtime.STOP.set())
    try:
        result=finite_service._run_after_external_native_admission(service,service.make_clock(),run_id=run,previous_session_sha256=intent['previous_session_sha256'])
    except BaseException as error:
        try:
            value=diag.diagnostic_validate_record(getattr(error,'familyvpn_diagnostic',None),run)
        except Exception:
            value=diag.diagnostic_record(run,diag.diagnostic_failure('data_admission',error))
        save_diagnostic(root,run,value['initial'],value['cleanup'],value['cleanup_codes'])
        raise
    value=diag.diagnostic_validate_record(result['diagnostic'],run)
    save_diagnostic(root,run,value['initial'],value['cleanup'],value['cleanup_codes'])
    io.write_new(root/'result.json',io.encode(result))
    return 0 if result['execution']=='cooperative_window_returned' else 2


def data_readback(n,run,root,*,recover=False):
    from process_observe import observe
    from fault_protocol import identity
    if io.exists(root/'owner.json'):
        ident=identity(io.decode(io.read(root/'owner.json',installed=True)))
        if observe(ident['pid']) is not None:raise io.Failure('data_owner_not_gone')
    with n.s.locks():
        current=n.s.Store().load()
        if current is None:raise io.Failure('data_journal_missing')
        intent=data_binding(n,run,root,restoring=True)
        if io.digest(io.encode(current))==intent['previous_session_sha256']:
            if io.exists(root/'result.json'):raise io.Failure('result_without_new_data_journal')
            saved,baseline=fresh(n);return False,saved,baseline
        marker=current.get('finite_window')
        if marker is None:raise io.Failure('data_journal_has_no_matching_run')
        if (type(marker)is not dict or marker.get('run_id')!=run or marker.get('seconds')!=900
                or current.get('boot')!=n.s.boot()):raise io.Failure('data_journal_other_run')
        if not io.exists(root/'owner.json'):raise io.Failure('data_owner_receipt_missing')
        if recover:
            code=n.recover_only.recover(n.s.Store())
            if type(code)is not int or code!=0:raise io.Failure('data_recovery_incomplete')
        saved,baseline=fresh(n)
        return True,saved,baseline


def phone_ready(current,run):
    return bool(type(current)is dict and current.get('finite_window',{}).get('run_id')==run
        and current.get('phase') in ('WAITING','ACTIVE')
        and current.get('finite_ready')==dict(version=1,run_id=run,setup_completed=True)
        and type(current['finite_ready'].get('version'))is int
        and current['finite_ready'].get('setup_completed')is True
        and current.get('alf_transaction',{}).get('phase')=='open')


def cancel_owned_data_child(child,run,root):
    """Only this parent's unreaped Popen child; never a supplied PID or group.

    waitpid-based poll must still report it alive. A direct child PID cannot be
    reused before the parent reaps it. There is no KILL escalation or recovery
    writer while this process still lives. The same closure handles SIGTERM.
    """
    io.write_new(root/'cancel-request.json',io.encode(dict(version=1,run=run,requested=True)))
    if child.poll() is None:child.terminate()
    try:child.wait(timeout=60)
    except subprocess.TimeoutExpired:return False
    return True


def prepare_data_run(n,service,*,retry=False):
    """One explicit action, original locks, preserved source bytes, new window.

    Failure before the last pointer publication leaves the original run current.
    Incomplete new directories are retained; no automatic cleanup/retry loop.
    """
    if type(retry)is not bool:raise io.Failure('fixed_retry_action')
    if io.exists(STATE/'server/current.json'):raise io.Failure('server_attempt_preserved_no_short_retry')
    prior=None;old_pointer=None;old_root=None
    if io.exists(CURRENT):
        if not retry:raise io.Failure('short_attempt_preserved_use_explicit_data_test')
        old_pointer=io.read(CURRENT,installed=True);old_run,old_root=current_data()
        if not io.exists(old_root/'owner.json'):raise io.Failure('retry_old_owner_identity_missing')
        _,prior,_=data_readback(n,old_run,old_root)
    with n.s.locks():
        saved,baseline=fresh(n);previous=io.encode(saved)
        if prior is not None and previous!=io.encode(prior):raise io.Failure('retry_previous_changed')
        if old_pointer is not None and io.read(CURRENT,installed=True)!=old_pointer:
            raise io.Failure('retry_pointer_changed')
        if old_pointer is None and io.exists(CURRENT):raise io.Failure('data_pointer_appeared')
        if io.exists(STATE/'server/current.json'):raise io.Failure('server_attempt_preserved_no_short_retry')
        verify_closed(n);ins.install_current_job();service.recovery_job_gate()
        history={}
        if old_root is not None:
            io.write_new(old_root/'final-session.json',previous)
            if not io.exists(old_root/'restoration.json'):
                io.write_new(old_root/'restoration.json',io.encode(dict(version=1,run=old_run,restored=True,
                    session_sha256=io.digest(previous),baseline=baseline)))
            restored=io.read(old_root/'restoration.json',installed=True);receipt=io.decode(restored)
            if (type(receipt)is not dict or set(receipt)!={'version','run','restored','session_sha256','baseline'}
                    or type(receipt['version'])is not int or receipt['version']!=1 or receipt['run']!=old_run
                    or receipt['restored']is not True or receipt['session_sha256']!=io.digest(previous)
                    or type(receipt['baseline'])is not dict):raise io.Failure('retry_restoration_unknown')
            history={'prior-pointer.json':old_pointer,'prior-restoration.json':restored}
        run=uuid.uuid4().hex;io.directory(DATA);root=DATA/run;io.directory(root)
        # This exact previous journal is saved for EVERY run, including the first
        # closed predecessor. It is independent of the unchanged closed proof.
        io.write_new(root/'previous-session.json',previous)
        for name,raw in history.items():io.write_new(root/name,raw)
        io.write_new(root/'intent.json',io.encode(dict(version=1,run=run,boot=n.s.boot(),resources=n.resource_snapshot(),
            common_sha256=ins.COMMON_SHA,seconds=900,previous_session_sha256=io.digest(previous))))
        pointer=io.encode(dict(version=1,run=run))
        if old_pointer is not None:ins.replace_owned(CURRENT,old_pointer,pointer)
        else:io.write_new(CURRENT,pointer)
        return run,root


def start_data(*,retry=False):
    n,_,service=native();verify_closed(n)
    run,root=prepare_data_run(n,service,retry=retry)
    child=None
    try:
        child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(ins.CONTROL/'root_entry.py'),'data-window'],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            env=io.ENV,close_fds=True,start_new_session=True,cwd='/')
        public('data_preparing',ready=False,deadline_seconds=900)
        until=time.monotonic()+1200;announced=False
        while child.poll() is None:
            if time.monotonic()>=until:
                public('data_window',incomplete=True,failure_class='child_timeout');return 2
            if not announced:
                try:
                    current=n.s.Store().load()
                    if phone_ready(current,run):
                        announced=True
                        remaining=max(0,int(current['finite_window']['continuous_deadline']-n.runtime.make_clock()()))
                        if remaining>0:
                            public('phone_window',ready=True,deadline_seconds=remaining)
                            print('READY: 本轮可连接手机并做双栈和测速检查。本轮原生全局VPN短窗口约 '+str(remaining)+' 秒后关闭；关闭恢复核验后可显式开启同版常驻试运行；本轮无需单设备C探针或另一轮26小时前置测试。请先不要重启 Mac。',flush=True)
                except Exception:pass # Readiness-only race; never turns failure into PASS.
            time.sleep(.5)
    except KeyboardInterrupt:
        if child is None:raise
        if not cancel_owned_data_child(child,run,root):
            public('data_cancel',incomplete=True,failure_class='child_timeout');return 2
    code=child.wait()
    # Publish initial/cleanup diagnostics BEFORE the independent fresh readback.
    # If readback also fails, the first failure remains in the ordinary tee report.
    value=read_diagnostic(root,run)
    emit_diagnostic(value)
    try:
        tested,saved,baseline=data_readback(n,run,root)
        io.write_new(root/'final-session.json',io.encode(saved))
        io.write_new(root/'restoration.json',io.encode(dict(version=1,run=run,restored=True,
            session_sha256=io.digest(io.encode(saved)),baseline=baseline)))
    except BaseException as error:
        diag.diagnostic_emit(diag.diagnostic_failure('restoration_readback',error),restoration='unverified')
        raise
    result=io.decode(io.read(root/'result.json',installed=True)) if io.exists(root/'result.json') else None
    complete=(code==0 and type(result)is dict and result.get('run_id')==run and
              result.get('execution')=='cooperative_window_returned' and result.get('same_run_restored_journal')is True)
    extra={}
    if not complete:
        reason=(value['initial'] or {}).get('reason')
        extra['failure_class']=reason if reason in ('uplink_ipv4_unavailable','uplink_ipv6_unavailable') else 'preflight_or_window'
    public('data_window',complete=complete,restored=True,incomplete=not complete,data_mode_tested=tested,
           new_same_version_rekey_observed=False,**extra)
    return 0 if complete else 2
