"""Display an already verified enrollment password only on a foreground TTY.

The fixed caller holds manager/native locks, has disabled the service, and has
just called profile_export.export_locked. This module acquires the original
provision lock itself. It never reads a private key, writes an export/file, or
returns a password. Terminal scrollback/recording cannot be reliably erased.
"""
import os
import re
import stat

from pki_io import Refused, decode, encode, sha
import enrollment as membership
import membership_admission
import profile_export
import registry
import staged_issuer

RESULT_KEYS={'event','device','registry_revision','profile_sha256','private_relative_path',
             'encrypted_identity_included','password_exported','iphone_installation_verified','data_started'}
ORIGIN_KEYS={'version','run','device','registry_row','certificate_sha256','metadata_sha256','p12_sha256'}


def _digest(value):
    if type(value)is not str or re.fullmatch('[0-9a-f]{64}',value)is None:
        raise Refused('device_password_digest')
    return value


def _scope(held,assert_closed):
    held()
    if not callable(assert_closed) or assert_closed() is not None:
        raise Refused('device_password_actual_closed_required')
    held()


def _foreground(fd):
    group=os.getpgrp()
    if (not all(os.isatty(value) for value in (0,1,fd))
            or any(os.tcgetpgrp(value)!=group for value in (0,1,fd))):
        raise Refused('device_password_foreground_terminal_required')


def _terminal():
    # A pipe/tee or background shell must fail before reading any password.
    if not os.isatty(0) or not os.isatty(1):
        raise Refused('device_password_foreground_terminal_required')
    group=os.getpgrp()
    if os.tcgetpgrp(0)!=group or os.tcgetpgrp(1)!=group:
        raise Refused('device_password_foreground_terminal_required')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOFOLLOW|os.O_NOCTTY|os.O_CLOEXEC)
    try:
        if (not stat.S_ISCHR(os.fstat(fd).st_mode) or not os.isatty(fd)
                or os.tcgetpgrp(fd)!=group):
            raise Refused('device_password_foreground_terminal_required')
        _foreground(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write(fd,value):
    offset=0
    while offset<len(value):
        written=os.write(fd,value[offset:])
        if written<=0:raise Refused('device_password_terminal_write_failed')
        offset+=written


def _bound_password(io,result):
    if (type(result)is not dict or set(result)!=RESULT_KEYS
            or result['event']!='membership_private_profile_exported'
            or type(result['registry_revision'])is not int or not 1<=result['registry_revision']<2**53
            or result['encrypted_identity_included']is not True or result['password_exported']is not False
            or result['iphone_installation_verified']is not False or result['data_started']is not False):
        raise Refused('device_password_export_result')
    device=membership.exact_id(result['device']);_digest(result['profile_sha256'])
    client=io.root/'clients'/device
    origin_raw=io.read(client/'enrollment.json');origin=decode(origin_raw)
    if (type(origin)is not dict or set(origin)!=ORIGIN_KEYS
            or type(origin['version'])is not int or origin['version']!=1 or origin['device']!=device
            or type(origin['run'])is not str or re.fullmatch('[a-f0-9]{32}',origin['run'])is None):
        raise Refused('device_password_enrollment_origin')
    run=io.root/membership_admission.NAME/origin['run']
    expected='clients/'+device+'/exports/enrollment-'+run.name+'-r'+str(result['registry_revision'])+'.mobileconfig'
    if type(result['private_relative_path'])is not str or result['private_relative_path']!=expected:
        raise Refused('device_password_export_path')
    if sha(io.read(io.root/expected,2097152))!=result['profile_sha256']:
        raise Refused('device_password_export_changed')
    live=registry.loads(io.read(io.root/'devices.json',65536))
    row=next((r for r in live['devices']if r['device_id']==device),None)
    if row is None or row['state']!='enabled' or live['revision']!=result['registry_revision']:
        raise Refused('device_password_registry_changed')
    prior=registry.normalize(dict(version=1,revision=1,usage_timezone=registry.ZONE,devices=[origin['registry_row']]))['devices'][0]
    if prior['state']!='enabled' or any(row[k]!=prior[k] for k in ('device_id','ike_identity','vip4','vip6')):
        raise Refused('device_password_permanent_mapping_changed')
    intent_raw=io.read(run/'intent.json');intent=decode(intent_raw);prepared=decode(io.read(run/'prepared.json'))
    if (type(intent)is not dict or set(intent)!=membership.INTENT
            or type(intent['version'])is not int or intent['version']!=1
            or intent['run']!=run.name or intent['action']!='enroll' or intent['device']!=device
            or intent['identity']!=row['ike_identity'] or type(intent['serial'])is not int
            or not 1<=intent['serial']<2**159
            or type(prepared)is not dict or set(prepared)!=membership.PREPARED
            or type(prepared['version'])is not int or prepared['version']!=1
            or prepared['intent_sha256']!=sha(intent_raw)
            or type(prepared['artifact_hashes'])is not dict
            or set(prepared['artifact_hashes'])!=set(staged_issuer.FILES)|{'enrollment.json'}):
        raise Refused('device_password_prepared_origin')
    for value in prepared['artifact_hashes'].values():_digest(value)
    if (io.read(run/'enrollment.json')!=origin_raw
            or prepared['artifact_hashes']['enrollment.json']!=sha(origin_raw)
            or io.read(run/'retired-current.json')!=encode(dict(version=1,run=run.name))):
        raise Refused('device_password_origin_not_retired')
    newreg_raw=io.read(run/'new-registry.json');newreg=registry.loads(newreg_raw)
    if (sha(newreg_raw)!=prepared['new_registry_sha256']
            or next((r for r in newreg['devices']if r['device_id']==device),None)!=prior):
        raise Refused('device_password_registry_origin')
    authority_raw=io.read(run/'new-authority.json')
    if sha(authority_raw)!=prepared['new_authority_sha256']:
        raise Refused('device_password_authority_origin')
    profile_export._complete(io.read(run/'complete.json'),run,device,intent['serial'],sha(authority_raw),newreg['revision'])
    public={}
    for name,key in (('cert.pem','certificate_sha256'),('metadata.json','metadata_sha256'),('identity.p12','p12_sha256')):
        raw=io.read(client/name)
        if (raw!=io.read(run/'identity'/name) or sha(raw)!=_digest(origin[key])
                or sha(raw)!=prepared['artifact_hashes'][name]):
            raise Refused('device_password_live_identity_changed')
        public[name]=raw
    meta=membership.metadata(public['metadata.json'],row['ike_identity'],public['cert.pem'])
    if int(meta['serial_hex'],16)!=intent['serial']:
        raise Refused('device_password_serial_changed')
    password=io.read(client/'p12-password.txt',256)
    if (re.fullmatch(rb'[A-Za-z0-9_-]{43}\n',password)is None
            or password!=io.read(run/'identity/p12-password.txt',256)
            or sha(password)!=prepared['artifact_hashes']['p12-password.txt']):
        raise Refused('device_password_password_origin')
    return password


def reveal(io,export_result,assert_closed):
    """No stdout/stderr/file password output; requires direct interactive entry.

    export_result must be the immediately preceding real export_locked result.
    The value is retained only in memory and explicitly shown on /dev/tty. No
    attempt is made to promise removal from recording or terminal scrollback.
    """
    fd=None;password=None;failed=False
    try:
        fd=_terminal()
        with io.lock(io.root/'.provision.lock') as held:
            _scope(held,assert_closed);membership_admission.admission(io)
            password=_bound_password(io,export_result)
            _scope(held,assert_closed);membership_admission.admission(io)
            _foreground(fd)
            _write(fd,'仅在本机终端显示；录屏和终端滚动历史可能保留此密码。\n安装密码：'.encode())
            _write(fd,password)
            password=None
            _write(fd,'输入到 iPhone 后，按回车结束本次查看。'.encode())
            received=0
            while True:
                raw=os.read(fd,1024)
                if not raw:raise Refused('device_password_terminal_input_closed')
                received+=len(raw)
                if received>1024:raise Refused('device_password_terminal_input_limit')
                if b'\n' in raw or b'\r' in raw:break
            _scope(held,assert_closed);membership_admission.admission(io)
            _foreground(fd)
            _write(fd,'\n本次查看结束。请自行关闭此终端窗口。\n'.encode())
    except (KeyboardInterrupt,SystemExit):
        raise
    except Exception:
        failed=True
    finally:
        password=None
        if fd is not None:
            try:os.close(fd)
            except Exception:failed=True
    # Raise outside the handler so even the exception context cannot retain a
    # failed native/custom operation's diagnostic string or password bytes.
    if failed:raise Refused('device_password_display_failed_no_secret_details') from None
    return {'password_displayed_on_local_terminal':True}

if __name__=='__main__':
    raise SystemExit('Only the fixed verified interactive device-password action may call reveal.')
