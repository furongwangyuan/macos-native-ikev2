#!/usr/bin/python3
"""Human root installation/check/removal only. No DDNS request or secret read."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

EXPECTED = __EXPECTED__
LABEL = 'org.familyvpn.ddns'
TARGET = 'system/' + LABEL
BASE = Path('/usr/local/family-vpn/ddns-production')
STATE = Path('/private/var/db/family-vpn/ddns-production')
PLIST = Path('/Library/LaunchDaemons/org.familyvpn.ddns.plist')
HELPER_STATE = Path('/private/var/db/family-vpn/dynadot-ddns')
ENV = {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}


class Failure(Exception):
    pass


def say(event, **fields):
    print(json.dumps(dict(event=event, **fields),sort_keys=True),flush=True)


def raw_read(path, *, root_metadata=False, limit=100000):
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:
        raise Failure('source_file_type_or_limit')
    if root_metadata and (before.st_uid!=0 or stat.S_IMODE(before.st_mode)!=0o600):
        raise Failure('untrusted_status_metadata')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        opened=os.fstat(f.fileno())
        signature=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        data=f.read(limit+1)
        if (signature(before)!=signature(opened) or signature(os.fstat(f.fileno()))!=signature(opened)
                or signature(path.lstat())!=signature(opened) or len(data)!=opened.st_size or len(data)>limit):
            raise Failure('source_changed_during_read')
    return data


def resources(here):
    result={}
    for name,digest in EXPECTED.items():
        value=raw_read(here/name)
        if hashlib.sha256(value).hexdigest()!=digest:
            raise Failure('reviewed_resource_hash_changed')
        result[name]=value
    library={'__name__':'reviewed_scheduler_library','__file__':str(BASE/'scheduler.py')}
    exec(compile(result['scheduler.py'],'reviewed_scheduler.py','exec'),library)
    return result,library


def exists(path):
    try:path.lstat();return True
    except FileNotFoundError:return False


def run(args,timeout=6):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,env=ENV,timeout=timeout)
    if len(result.stdout)>65536 or len(result.stderr)>65536:
        raise Failure('command_output_limit')
    return result


def parse_job(result):
    if result.returncode==113 and (result.stdout+result.stderr).decode('ascii','strict').strip()==(
            'Bad request.\nCould not find service "'+LABEL+'" in domain for system'):
        return None
    if result.returncode:
        raise Failure('launchd_status_unknown')
    text=result.stdout.decode('utf-8','strict')
    if not text.startswith(TARGET+' = {\n') or not text.endswith('}\n'):
        raise Failure('launchd_layout_unknown')
    def one(key):
        values=re.findall(r'^\t'+re.escape(key)+r' = ([^\n]+)$',text,re.M)
        if len(values)!=1:raise Failure('launchd_layout_unknown')
        return values[0]
    if (one('path')!=str(PLIST) or one('program')!='/usr/bin/python3' or
            one('domain')!='system' or one('type')!='LaunchDaemon'):
        raise Failure('loaded_job_identity_differs')
    arguments=re.findall(r'^\targuments = \{\n((?:\t\t[^\n]+\n)+)\t\}$',text,re.M)
    expected=['/usr/bin/python3','-I',str(BASE/'scheduler.py')]
    if len(arguments)!=1 or [line[2:] for line in arguments[0].splitlines()]!=expected:
        raise Failure('loaded_job_arguments_differ')
    pid=re.findall(r'^\tpid = ([0-9]+)$',text,re.M)
    if len(pid)>1 or (pid and int(pid[0])<=1):raise Failure('launchd_pid_unknown')
    state=one('state')
    state=state if state in ('running','not running','waiting','spawn scheduled','exited') else 'unknown'
    exit_values=re.findall(r'^\tlast exit code = (-?[0-9]+|\(never exited\))$',text,re.M)
    exit_code=int(exit_values[0]) if len(exit_values)==1 and exit_values[0]!='(never exited)' else None
    runs=re.findall(r'^\truns = ([0-9]+)$',text,re.M)
    return dict(loaded=True,pid=int(pid[0]) if pid else None,state=state,last_exit_code=exit_code,
        runs=int(runs[0]) if len(runs)==1 else None)


def job(timeout=6):
    return parse_job(run(['/bin/launchctl','print',TARGET],timeout=timeout))


def disabled_gate():
    result=run(['/bin/launchctl','print-disabled','system'])
    text=result.stdout.decode('ascii','strict')
    if result.returncode or not re.fullmatch(r'\s*disabled services = \{\n(?:\s*"[^"\n]+" => (?:enabled|disabled)\n)*\s*\}\n?',text):
        raise Failure('disabled_state_unknown')
    values=re.findall(r'^\s*"'+re.escape(LABEL)+r'" => (enabled|disabled)$',text,re.M)
    if len(values)>1 or values==['disabled']:
        raise Failure('persistent_disabled_override_requires_review')


def protected_read(lib,path,mode=0o600):
    lib['trusted'](path,mode=mode)
    return raw_read(path)


def json_read(lib,path):
    def pairs(items):
        obj={}
        for key,value in items:
            if key in obj:raise Failure('duplicate_metadata_key')
            obj[key]=value
        return obj
    return json.loads(protected_read(lib,path),object_pairs_hook=pairs)


def ensure_directory(lib,path):
    lib['trusted'](path.parent,directory=True)
    try:path.mkdir(mode=0o700)
    except FileExistsError:pass
    else:lib['sync_dir'](path.parent)
    lib['trusted'](path,directory=True,mode=0o700)


def publish(lib,path,data,mode):
    lib['trusted'](path.parent,directory=True)
    if exists(path):
        if protected_read(lib,path,mode)!=data:raise Failure('existing_owned_file_differs')
        return
    temp=path.parent/('.ddns-install-'+secrets.token_hex(12))
    try:
        with os.fdopen(os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode),'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        # umask077 must not silently leave the reviewed LaunchDaemon at0600.
        os.chmod(temp,mode,follow_symlinks=False)
        os.link(temp,path,follow_symlinks=False)
        temp.unlink();lib['sync_dir'](path.parent)
    finally:
        if exists(temp):temp.unlink()


def journal(lib,phase):
    path=STATE/'install.json'
    if exists(path):protected_read(lib,path)
    value=dict(version=1,phase=phase,expected=EXPECTED)
    data=(json.dumps(value,sort_keys=True)+'\n').encode('ascii')
    temp=STATE/('.journal-'+secrets.token_hex(12))
    try:
        with os.fdopen(os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(temp,path);lib['sync_dir'](STATE)
    finally:
        if exists(temp):temp.unlink()


def read_journal(lib):
    if not exists(STATE/'install.json'):return None
    value=json_read(lib,STATE/'install.json')
    if (not isinstance(value,dict) or set(value)!= {'version','phase','expected'} or
            type(value['version'])is not int or value['version']!=1 or value['expected']!=EXPECTED or
            value['phase'] not in ('installing','bootstrap-intent','installed','removing','removed')):
        raise Failure('installation_journal_unknown')
    return value


def owned_files(lib,content,*,partial=False):
    for name,path,mode in [('scheduler.py',BASE/'scheduler.py',0o600),
                           ('org.familyvpn.ddns.plist',PLIST,0o644)]:
        if not exists(path):
            if partial or path==PLIST:continue
            raise Failure('owned_source_missing')
        if protected_read(lib,path,mode)!=content[name]:raise Failure('owned_file_changed')
    manifest=BASE/'manifest.json'
    if exists(manifest):
        if json_read(lib,manifest)!=EXPECTED:raise Failure('installed_manifest_changed')
    elif not partial:raise Failure('installed_manifest_missing')


def helper_gate(lib):
    # CONFIG is deliberately not read, copied, hashed, or included in reports.
    lib['trusted'](lib['CONFIG'],mode=0o600)
    if hashlib.sha256(lib['read'](lib['HELPER'])).hexdigest()!=lib['HELPER_SHA']:
        raise Failure('installed_helper_version_changed')


def process_record(lib):
    path=STATE/'process.json'
    if not exists(path):return None
    value=json_read(lib,path)
    if (not isinstance(value,dict) or set(value)!= {'version','pid','pgid','started'} or
            type(value['version'])is not int or value['version']!=1 or
            type(value['pid'])is not int or value['pid']<=1 or value['pgid']!=value['pid'] or
            type(value['started'])not in (int,float) or not 0<value['started']<1e11):
        raise Failure('process_record_unknown')
    return value


def group_absent(groups):
    if not groups:return True
    result=run(['/bin/ps','-axo','pgid='])
    lines=result.stdout.decode('ascii','strict').splitlines()
    if result.returncode or not lines or any(not re.fullmatch(r'\s*[0-9]+\s*',line) for line in lines):
        raise Failure('process_group_inventory_unknown')
    return not (groups & {int(line) for line in lines})


def install(lib,content):
    helper_gate(lib);disabled_gate()
    loaded=job()
    previous=read_journal(lib)
    if previous is None:
        if loaded is not None or exists(PLIST) or exists(BASE/'scheduler.py') or exists(BASE/'manifest.json'):
            raise Failure('unknown_preexisting_installation')
    owned_files(lib,content,partial=True)
    journal(lib,'installing')
    publish(lib,BASE/'scheduler.py',content['scheduler.py'],0o600)
    publish(lib,BASE/'manifest.json',(json.dumps(EXPECTED,sort_keys=True)+'\n').encode('ascii'),0o600)
    publish(lib,PLIST,content['org.familyvpn.ddns.plist'],0o644)
    owned_files(lib,content)
    if loaded is None:
        old_process=process_record(lib)
        if old_process and not group_absent({old_process['pgid']}):
            raise Failure('previous_job_group_remains_before_bootstrap')
        # Manual re-enable is also delayed. No due status from a previous
        # installation can trigger an API during this installation transaction.
        with lib['locked_path'](STATE/'scheduler.lock',create=True):
            with lib['locked_path'](lib['HELPER'].parent/'.installer.lock'):
                with lib['locked_path'](HELPER_STATE/'lock'):
                    helper_gate(lib)
                    lib['atomic_status'](lib['record'](time.time(),0,'scheduled',jitter=secrets.randbelow(31)))
        journal(lib,'bootstrap-intent')
        try:result=run(['/bin/launchctl','bootstrap','system',str(PLIST)],timeout=12)
        except subprocess.TimeoutExpired:result=None
        # Even a failing/timeout bootstrap can have loaded the job. Converge
        # only through the exact identity check; do not delete uncertain state.
        loaded=job()
        if loaded is None:raise Failure('bootstrap_not_confirmed_recovery_record_preserved')
    journal(lib,'installed')
    say('scheduler_installed',loaded=True,first_new_state_only_schedules=True,
        helper_sha=lib['HELPER_SHA'],dns_update_not_run_by_installer=True)


def remove(lib,content):
    previous=read_journal(lib)
    if previous is None:raise Failure('no_owned_installation_journal')
    owned_files(lib,content,partial=previous['phase']=='installing')
    loaded=job();groups=set()
    if loaded and loaded['pid']:
        try:
            pgid=os.getpgid(loaded['pid'])
            if pgid!=loaded['pid']:raise Failure('loaded_job_group_not_dedicated')
            groups.add(pgid)
        except ProcessLookupError:pass
    saved=process_record(lib)
    if saved:groups.add(saved['pgid'])
    journal(lib,'removing')
    if loaded is not None:
        try:run(['/bin/launchctl','bootout',TARGET],timeout=12)
        except subprocess.TimeoutExpired:pass
    deadline=time.monotonic()+16
    while True:
        saved=process_record(lib)
        if saved:groups.add(saved['pgid'])
        if job() is None and group_absent(groups):break
        if time.monotonic()>=deadline:raise Failure('job_or_group_remains_no_files_removed')
        time.sleep(0.5)
    # No unlinking locks, no unknown PID signals, and never hold scheduler.lock
    # while trying to stop its owner. Lock busy preserves files for retry.
    with lib['locked_path'](STATE/'scheduler.lock',create=True):
        with lib['locked_path'](lib['HELPER'].parent/'.installer.lock'):
            with lib['locked_path'](HELPER_STATE/'lock'):
                if job() is not None or not group_absent(groups):
                    raise Failure('service_reappeared_during_removal')
                if exists(PLIST):
                    if protected_read(lib,PLIST,0o644)!=content['org.familyvpn.ddns.plist']:
                        raise Failure('plist_changed_before_removal')
                    PLIST.unlink();lib['sync_dir'](PLIST.parent)
                journal(lib,'removed')
    say('scheduler_removed',job_absent=True,recorded_groups_absent=True,
        credentials_preserved=True,helper_preserved=True,dns_records_unchanged=True)


def check(lib,content):
    if not exists(BASE) and not exists(STATE) and not exists(PLIST):
        if job() is not None:raise Failure('loaded_job_without_owned_files')
        say('not_installed');return
    lib['trusted'](BASE,directory=True,mode=0o700)
    lib['trusted'](STATE,directory=True,mode=0o700)
    previous=read_journal(lib)
    if previous is None:raise Failure('no_owned_installation_journal')
    owned_files(lib,content,partial=previous['phase']=='installing')
    loaded=job();disabled_gate();helper_gate(lib)
    status=lib['load_status']()
    fields=dict(phase=previous['phase'],loaded=loaded is not None,
        job_state=loaded['state'] if loaded else 'absent',helper_sha=lib['HELPER_SHA'],
        job_last_exit_code=loaded['last_exit_code'] if loaded else None,
        job_invocations=loaded.get('runs') if loaded else None,process_record=process_record(lib),
        credential_metadata_verified=True,credential_content_not_read=True,
        live_dns_not_queried=True,status=status,
        status_overdue=None if status is None else time.time()>status['next_due']+120)
    say('read_only_status',**fields)



WATCH_SECONDS=480
WATCH_INTERVAL=5


def directory_identity(path):
    info=path.lstat()
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)


def watch_status(lib, expected_directory):
    # Installation already verified this root-owned ancestry. Keep its identity;
    # do not repeat external ls calls in the bounded polling loop. The scheduler
    # legitimately replaces status.json, so compare the file within each read.
    if directory_identity(STATE)!=expected_directory:
        raise Failure('watch_state_directory_changed')
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise Failure('duplicate_status_key')
            value[key]=item
        return value
    raw=raw_read(STATE/'status.json',root_metadata=True,limit=4096)
    value=lib['validate_status'](json.loads(raw,object_pairs_hook=unique))
    if directory_identity(STATE)!=expected_directory:
        raise Failure('watch_state_directory_changed')
    return value


def watch(lib):
    """Read-only fixed 480-second observation; no locks, writes or update calls."""
    started=time.monotonic();deadline=started+WATCH_SECONDS
    baseline=None;last=None;last_report=-60.0;last_job=-60.0
    loaded=None
    def report(event, **fields):
        say(event,elapsed_seconds=round(max(0,time.monotonic()-started),2),
            scheduler_kept_installed=True,live_dns_not_queried=True,
            helper_not_invoked_by_watcher=True,**fields)
    try:
        anchor=directory_identity(STATE)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:
                report('watch_final',result='inconclusive',code='no_new_completed_run_before_deadline',status=last)
                return 2
            current=watch_status(lib,anchor)
            elapsed=time.monotonic()-started
            if baseline is None:baseline=current
            terminal=current['outcome'] in ('success','failed','timeout','interrupted')
            fresh=(current['last_started']>baseline['last_started'] or
                (baseline['outcome']=='running' and current['last_started']==baseline['last_started']))
            completed=terminal and fresh and current['last_finished']>=current['last_started']
            if elapsed-last_job>=60 or completed:
                remaining=deadline-time.monotonic()
                if remaining<=0:continue
                loaded=job(timeout=min(6,remaining));last_job=time.monotonic()-started
                if loaded is None:
                    report('watch_final',result='inconclusive',code='scheduler_no_longer_loaded',status=current)
                    return 2
            if last is None or current!=last or elapsed-last_report>=60:
                report('watch_initial' if last is None else 'watch_check',status=current,
                    job_state=loaded['state'],job_invocations=loaded.get('runs'),
                    job_last_exit_code=loaded['last_exit_code'])
                last_report=elapsed
            last=current
            if time.monotonic()>=deadline:continue
            if completed:
                result='success' if current['outcome']=='success' else 'failed'
                report('watch_final',result=result,code='new_automatic_helper_completion',status=current,
                    success_means_helper_exit_zero_not_necessarily_dns_write=True)
                return 0 if result=='success' else 1
            time.sleep(min(WATCH_INTERVAL,max(0,deadline-time.monotonic())))
    except KeyboardInterrupt:
        report('watch_final',result='inconclusive',code='observation_cancelled',status=last)
        return 2
    except Exception:
        # Never emit arbitrary launchctl, filesystem, provider or JSON content.
        report('watch_final',result='inconclusive',code='read_only_metadata_unavailable',status=last)
        return 2


def main():
    if os.geteuid()!=0 or len(sys.argv)!=3 or sys.argv[1] not in ('install','install-and-watch','remove','check'):
        raise Failure('fixed_human_root_launcher_required')
    action,here=sys.argv[1],Path(sys.argv[2])
    content,lib=resources(here);os.umask(0o077)
    if action=='check':check(lib,content);return
    if action in ('install','install-and-watch'):
        for parent in (BASE.parent,STATE.parent,PLIST.parent):lib['trusted'](parent,directory=True)
        # Verify existing helper before any directory/file mutation.
        helper_gate(lib);disabled_gate()
        ensure_directory(lib,BASE);ensure_directory(lib,STATE)
    else:
        lib['trusted'](BASE,directory=True,mode=0o700)
        lib['trusted'](STATE,directory=True,mode=0o700)
    with lib['locked_path'](BASE/'.installer.lock',create=True):
        if action in ('install','install-and-watch'):install(lib,content)
        else:remove(lib,content)
    # Do not block scheduler/helper/update or uninstall locks while observing.
    if action=='install-and-watch':return watch(lib)


if __name__=='__main__':
    try:sys.exit(main() or 0)
    except Exception as error:
        # No arbitrary OS/provider strings or source paths in human reports.
        code=str(error) if type(error)is Failure else 'local_or_command_failure'
        say('stopped',code=code,recovery_record_preserved=True)
        sys.exit(1)
