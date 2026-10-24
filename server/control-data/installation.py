"""Only fixed same-v8 finite permission/recover-job functions; no code installer."""
import os,re,subprocess
from pathlib import Path
import install_io as io
COMMON=io.BASE
HARNESS=Path('/usr/local/family-vpn/production-owner-fault')
HARNESS_STATE=Path('/private/var/db/family-vpn/production-owner-fault')
CONTROL=Path('/usr/local/family-vpn/production-acceptance')
COMMON_SHA=None # FINAL_BUILD_BINDING
LABEL='org.familyvpn.guardian-recovery'
TARGET='system/'+LABEL
PLIST=io.OLD_JOB

def fixed_command(argv):
    if argv not in (["/bin/launchctl","print",TARGET], ["/bin/launchctl","bootout",TARGET],
                    ["/bin/launchctl","bootstrap","system",str(PLIST)],
                    ["/bin/launchctl","print-disabled","system"]):
        raise io.Failure('unlisted_installer_command')
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=io.ENV,timeout=6,close_fds=True,start_new_session=True)
    if len(result.stdout)>65536 or len(result.stderr)>65536:raise io.Failure('job_output_limit')
    return result


def job():
    result=fixed_command(['/bin/launchctl','print',TARGET])
    absent=b'Bad request.\nCould not find service "org.familyvpn.guardian-recovery" in domain for system'
    if result.returncode==113 and (result.stdout+result.stderr).strip()==absent:return None
    if result.returncode:raise io.Failure('job_status_unknown')
    text=result.stdout.decode('utf8','strict');lines=text.splitlines()
    if (len(lines)<3 or lines[0]!=TARGET+' = {' or lines[-1]!='}'
            or any(line and not line.startswith('\t') for line in lines[1:-1])):
        raise io.Failure('job_shape')
    wanted={'path':str(PLIST),'program':'/usr/bin/python3','domain':'system',
            'type':'LaunchDaemon','arguments':'{'}
    fields={};positions={}
    for index,line in enumerate(lines[1:-1],1):
        if not line.startswith('\t') or line.startswith('\t\t'):continue
        key,sep,value=line[1:].partition(' = ')
        if key in set(wanted)|{'state'}:
            if not sep or key in fields:raise io.Failure('job_duplicate_field')
            fields[key]=value;positions[key]=index
    if (any(fields.get(k)!=v for k,v in wanted.items()) or
            not fields.get('state')):
        raise io.Failure('job_identity')
    block=['\targuments = {','\t\t/usr/bin/python3','\t\t-I','\t\t-B',
           '\t\t'+str(COMMON/'recover_only.py'),'\t}']
    at=positions['arguments']
    if lines[at:at+len(block)]!=block:raise io.Failure('job_arguments')
    return {'state':fields['state']}


def replace_owned(path,before,after):
    """One fixed config/plist caller; root-only single writer, exact old bytes."""
    if io.read(path,installed=True)!=before:raise io.Failure('configuration_before_changed')
    temp=path.parent/('.common-config-'+io.secrets.token_hex(12))
    try:
        io.write_new(temp,after)
        if io.read(path,installed=True)!=before:raise io.Failure('configuration_changed_before_replace')
        os.replace(temp,path);io.sync_dir(path.parent)
        if io.read(path,installed=True)!=after:raise io.Failure('configuration_readback')
    finally:
        if io.exists(temp):temp.unlink()


def test_config():
    path=io.CONF/'config.json';before=io.read(path,installed=True)
    value=io.decode(before)
    if (type(value)is not dict or set(value)!={'version','allow_data'} or type(value['version'])is not int
            or value['version']!=1 or type(value['allow_data'])is not bool):raise io.Failure('configuration_unknown')
    after=io.encode({'version':1,'allow_data':True})
    if value['allow_data'] is True:
        intent=io.decode(io.read(io.MANAGER/'test-config-intent.json',installed=True))
        if io.encode(intent)!=io.encode(dict(version=1,before_sha256=io.digest(io.encode({'version':1,'allow_data':False})),after_sha256=io.digest(after))):
            raise io.Failure('test_config_not_owned')
        if before!=after:raise io.Failure('test_config_bytes_changed')
        return
    # Keep initial arbitrary whitespace as an immutable archived original, but
    # the fixed off value is the restoration target for this new installation.
    initial=io.MANAGER/'initial-config.json'
    if not io.exists(initial):io.write_new(initial,before)
    else:
        original=io.decode(io.read(initial,installed=True))
        if (type(original)is not dict or set(original)!={'version','allow_data'} or
                type(original['version'])is not int or original['version']!=1 or original['allow_data']is not False):
            raise io.Failure('initial_configuration_unknown')
    off=io.encode({'version':1,'allow_data':False})
    intent_path=io.MANAGER/'test-config-intent.json'
    intent=io.encode(dict(version=1,before_sha256=io.digest(off),after_sha256=io.digest(after)))
    if io.exists(intent_path):
        if io.read(intent_path,installed=True)!=intent:raise io.Failure('test_config_intent_changed')
    else:io.write_new(intent_path,intent)
    replace_owned(path,before,after)


def close_test_config():
    path=io.CONF/'config.json'
    off=io.encode({'version':1,'allow_data':False});on=io.encode({'version':1,'allow_data':True})
    raw=io.read(path,installed=True)
    if raw==off:return
    if raw!=on:raise io.Failure('test_config_changed_preserved')
    record=io.read(io.MANAGER/'test-config-intent.json',installed=True)
    expected=io.encode(dict(version=1,before_sha256=io.digest(off),after_sha256=io.digest(on)))
    if record!=expected:raise io.Failure('test_config_not_owned')
    original=io.decode(io.read(io.MANAGER/'initial-config.json',installed=True))
    if (type(original)is not dict or set(original)!={'version','allow_data'} or
            type(original['version'])is not int or original['version']!=1 or original['allow_data']is not False):
        raise io.Failure('initial_configuration_unknown')
    # Caller first proves no active native owner; this only removes future data
    # permission, and is not described as kernel recovery.
    replace_owned(path,on,off)


def install_current_job():
    """Install ONLY common recover-only, after closed fault readback succeeded."""
    expected=io.read(COMMON/(LABEL+'.plist'),installed=True)
    record=io.MANAGER/'common-job-intent.json'
    io.write_new(record,io.encode(dict(version=1,common_sha256=COMMON_SHA,plist_sha256=io.digest(expected))))
    result=fixed_command(['/bin/launchctl','print-disabled','system'])
    text=result.stdout.decode('ascii','strict')
    if result.returncode or not re.fullmatch(r'\s*disabled services = \{\n(?:\s*"[^"\n]+" => (?:enabled|disabled)\n)*\s*\}\n?',text):
        raise io.Failure('job_disabled_state_unknown')
    values=re.findall(r'^\s*"'+re.escape(LABEL)+r'" => (enabled|disabled)$',text,re.M)
    if len(values)>1 or values==['disabled']:raise io.Failure('job_disabled_override')
    loaded=job()
    if io.exists(PLIST):
        io.trusted(PLIST,mode=0o644)
        if io.read(PLIST)!=expected:raise io.Failure('foreign_job_preserved')
    else:
        if loaded is not None:raise io.Failure('loaded_job_without_plist')
        io.trusted(PLIST.parent,directory=True)
        temp=PLIST.parent/('.common-recovery-'+io.secrets.token_hex(12))
        fd=None
        try:
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
            os.fchmod(fd,0o644)
            with os.fdopen(fd,'wb') as stream:
                fd=None;stream.write(expected);stream.flush();os.fsync(stream.fileno())
            os.link(temp,PLIST,follow_symlinks=False);temp.unlink();io.sync_dir(PLIST.parent)
        finally:
            if fd is not None:os.close(fd)
            if io.exists(temp):temp.unlink()
        io.trusted(PLIST,mode=0o644)
        if io.read(PLIST)!=expected:raise io.Failure('job_publish_readback')
    if loaded is None:
        try:fixed_command(['/bin/launchctl','bootstrap','system',str(PLIST)])
        except subprocess.TimeoutExpired:pass
    if job() is None:raise io.Failure('common_recovery_job_not_loaded')
    io.write_new(io.MANAGER/'common-job-installed.json',io.encode(dict(version=1,common_sha256=COMMON_SHA,loaded=True)))

