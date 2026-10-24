"""Fixed read-only public PKI observation candidate. No installation or authority.

Native main has no arguments, fixed paths, requires root and a future fixed
root-owned deployment. Offline tests call private mechanics with a temp-dir FD
and the actual ordinary UID. Those library calls are not privilege boundaries.
"""
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time

FIXED_BASE = '/usr/local/family-vpn/public-pki-snapshot-v1'
FIXED_CA = ('usr','local','etc','family-vpn','swanctl','x509ca','ca.pem')
FIXED_CRL = ('usr','local','etc','family-vpn','swanctl','x509crl','ca.crl.pem')
MAX_CA_PEM = 32768
MAX_CRL_PEM = 524288
MAX_RESULT = 1024*1024
CRYPTO_PINS = {
    'public_crl.py':'b6312b2bdd93ec7ff5daca2e949239b6f198f7abbeef3b3b9721cbfffe1adf7f',
    'public_crl_verify.c':'5b45a7913cc8dc661db87118bf186dfae86d7b88b24c03c1464cccb036114774',
    'public-crl-verify':'3a951597703bceac13886236973577eb19d19b2292503698925671b07cd8ef0b',
    'build-manifest.json':'f43663fda58e60ca8a9b3f2b721ed7d17475d9a3ed5a155cb50c339791e8fced',
}

class Refused(ValueError):
    pass

def _sha(data): return hashlib.sha256(data).hexdigest()

def _stamp(st):
    return dict(dev=st.st_dev,ino=st.st_ino,uid=st.st_uid,gid=st.st_gid,
                mode=stat.S_IMODE(st.st_mode),nlink=st.st_nlink,size=st.st_size,
                mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)

def _acl_absent(fd):
    # Darwin API, bound to the already-open object. NULL+ENOENT is the documented
    # absent FILESEC_ACL property; all other errors and any ACL object are refused.
    # In particular EINVAL/ENOTSUP and an allocated empty ACL are NOT called absent.
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int]
    lib.acl_get_fd_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p]
    lib.acl_free.restype=ctypes.c_int
    ctypes.set_errno(0)
    acl=lib.acl_get_fd_np(fd,0x100)  # SDK ACL_TYPE_EXTENDED
    error=ctypes.get_errno()
    if acl:
        try: raise Refused('extended_acl_present')
        finally:
            if lib.acl_free(acl)!=0: raise Refused('acl_free_failed')
    if error!=errno.ENOENT: raise Refused('acl_status_unknown')

def _metadata(fd,uid,directory,maximum=None,allow_exec=False):
    st=os.fstat(fd)
    if st.st_uid!=uid: raise Refused('unexpected_owner')
    if st.st_mode&0o022 or st.st_mode&0o7000: raise Refused('unsafe_mode')
    if directory:
        if not stat.S_ISDIR(st.st_mode): raise Refused('not_directory')
    else:
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1: raise Refused('not_single_regular_file')
        modes=(0o700,0o755) if allow_exec else (0o600,0o644)
        if stat.S_IMODE(st.st_mode) not in modes: raise Refused('file_mode_scope')
        if not 0<st.st_size<=maximum: raise Refused('file_size_scope')
    _acl_absent(fd)
    if _stamp(os.fstat(fd))!=_stamp(st): raise Refused('metadata_changed_during_acl')
    return _stamp(st)

def _path_parts(parts):
    if type(parts) is not tuple or not parts or any(type(p) is not str or not p or
            p in ('.','..') or '/' in p or '\x00' in p for p in parts):
        raise Refused('internal_path_scope')

def _read_one(root_fd,parts,uid,maximum,allow_exec=False):
    """Return bytes and complete stable FD chain; never resolve a symbolic link."""
    _path_parts(parts)
    fds=[];states=[]
    try:
        fds.append(os.dup(root_fd));states.append(_metadata(fds[-1],uid,True))
        for component in parts[:-1]:
            fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                       dir_fd=fds[-1]);fds.append(fd);states.append(_metadata(fd,uid,True))
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                   dir_fd=fds[-1]);fds.append(fd);states.append(_metadata(fd,uid,False,maximum,allow_exec))
        chunks=[];size=0
        while True:
            block=os.read(fd,min(65536,maximum+1-size))
            if not block: break
            chunks.append(block);size+=len(block)
            if size>maximum: raise Refused('read_bound')
        raw=b''.join(chunks)
        if len(raw)!=states[-1]['size']: raise Refused('read_size_changed')
        for i,handle in enumerate(fds):
            if _metadata(handle,uid,i<len(fds)-1,maximum,allow_exec)!=states[i]:
                raise Refused('object_changed_during_read')
        # Verify the retained chain still denotes each name in its retained parent.
        for i,component in enumerate(parts,1):
            current=os.stat(component,dir_fd=fds[i-1],follow_symlinks=False)
            if _stamp(current)!=states[i]: raise Refused('name_replaced_during_read')
        return {'bytes':raw,'chain':states,'sha256':_sha(raw)}
    finally:
        failure=None
        for fd in reversed(fds):
            try: os.close(fd)
            except OSError as error: failure=error
        if failure: raise Refused('descriptor_cleanup_failed') from failure

def _pair(root_fd,ca_parts,crl_parts,uid):
    return {'ca':_read_one(root_fd,ca_parts,uid,MAX_CA_PEM),
            'crl':_read_one(root_fd,crl_parts,uid,MAX_CRL_PEM)}

def _observed_crypto(ca_pem,crl_pem,now,verifier):
    """Inspect unapproved material; never call verify_current or invent trust.

    Direct frozen helper historical inspection proves only signatures, issue-time
    constraints and input binding. It deliberately creates neither CurrentEvidence
    nor a lifecycle Authority and does not call its external-authority API with a
    self-computed CA digest.
    """
    verifier._integer(now)
    ca=verifier._pem(ca_pem,'CERTIFICATE',verifier.MAX_CA)
    crl=verifier._pem(crl_pem,'X509 CRL',verifier.MAX_CRL)
    data=struct.pack('!8sIIQB',b'FVPNCRL1',len(ca),len(crl),now,True)+ca+crl
    result=json.loads(verifier._execute(data),object_pairs_hook=verifier._unique)
    fields={'version','openssl','ca_sha256','der_sha256','number','this_update',
            'next_update','ca_not_before','ca_not_after','historical','revocations'}
    if type(result) is not dict or set(result)!=fields or type(result['version']) is not int or \
       result['version']!=1 or result['openssl']!='3.5.9' or result['historical'] is not True or \
       result['ca_sha256']!=_sha(ca) or result['der_sha256']!=_sha(crl):
        raise Refused('observed_crypto_binding')
    verifier._integer(result['number'],1,2**159-1)
    start,end,ca_start,ca_end=(verifier._integer(result[n]) for n in
        ('this_update','next_update','ca_not_before','ca_not_after'))
    if not ca_start<=start<ca_end or start>now or not 29*86400<=end-start<=31*86400:
        raise Refused('observed_crypto_time_scope')
    rows=result['revocations']
    if type(rows) is not list or len(rows)>4096: raise Refused('observed_revocations_scope')
    previous=0
    for row in rows:
        if type(row) is not dict or set(row)!={'serial','reason','revoked_at'}: raise Refused('observed_revocation_shape')
        serial=verifier._integer(row['serial'],1,2**159-1)
        when=verifier._integer(row['revoked_at'])
        if serial<=previous or when>start or type(row['reason']) is not str or row['reason'] not in verifier.REASONS:
            raise Refused('observed_revocation_scope')
        previous=serial
    result.update(ca_der_base64=base64.b64encode(ca).decode(),crl_der_base64=base64.b64encode(crl).decode(),
                  ca_pem_sha256=_sha(ca_pem),crl_pem_sha256=_sha(crl_pem),
                  current_time_window_at_observation=ca_start<=now<ca_end and now<end)
    return result

def _capture(root_fd,ca_parts,crl_parts,uid,verifier,clock=time.time):
    # Two observations detect ordinary concurrent replacement. They are NOT a
    # common CA-state commit record: existing sync_public has no such public record.
    before=int(clock());first=_pair(root_fd,ca_parts,crl_parts,uid)
    crypto=_observed_crypto(first['ca']['bytes'],first['crl']['bytes'],before,verifier)
    second=_pair(root_fd,ca_parts,crl_parts,uid);after=int(clock())
    if after<before: raise Refused('clock_went_backwards')
    if first!=second: raise Refused('public_pair_changed')
    crypto['current_time_window_at_observation'] = (
        crypto['ca_not_before']<=after<crypto['ca_not_after'] and
        crypto['this_update']<=after<crypto['next_update'])
    result={'version':1,'classification':'observed_installed_public_material',
        'authority_approved':False,'creates_current_authority':False,
        'transaction_commit_proven':False,'stable_pair_observed_twice':True,
        'inspection_mode':'historical_signature_and_issue_time',
        'observed_start':before,'observed_end':after,'crypto':crypto,
        'sources':{k:{'path':'/'+ '/'.join(ca_parts if k=='ca' else crl_parts),
                      'chain':v['chain'],'pem_sha256':v['sha256']} for k,v in first.items()}}
    if len(json.dumps(result,separators=(',',':')).encode())>MAX_RESULT: raise Refused('output_bound')
    return result

def _native_verifier(root_fd):
    # No code is imported from writable workspace roots. All four deployed
    # resources and every directory component must first pass the same FD gates.
    prefix=tuple(FIXED_BASE.strip('/').split('/'))+('crypto',)
    raw=None
    for name,digest in CRYPTO_PINS.items():
        maximum=16*1024*1024 if name=='public-crl-verify' else 256*1024
        value=_read_one(root_fd,prefix+(name,),0,maximum,name=='public-crl-verify')
        if value['sha256']!=digest: raise Refused('fixed_crypto_resource_changed')
        if name=='public_crl.py': raw=value['bytes']
    module=type(sys)('_fixed_public_pki_observer_verifier')
    module.__file__=FIXED_BASE+'/crypto/public_crl.py'
    sys.modules[module.__name__]=module
    try: exec(compile(raw,module.__file__,'exec'),module.__dict__)
    except BaseException:
        sys.modules.pop(module.__name__,None);raise
    return module

def main():
    if len(sys.argv)!=1 or os.geteuid()!=0: raise Refused('fixed_root_entry_only')
    if str(Path(__file__).absolute())!=FIXED_BASE+'/public_snapshot.py':
        raise Refused('fixed_installation_required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        _metadata(fd,0,True)
        own=_read_one(fd,tuple(FIXED_BASE.strip('/').split('/'))+('public_snapshot.py',),0,256*1024)
        if own['bytes']!=Path(__file__).read_bytes(): raise Refused('running_source_changed')
        verifier=_native_verifier(fd)
        result=_capture(fd,FIXED_CA,FIXED_CRL,0,verifier)
    finally: os.close(fd)
    print(json.dumps(result,sort_keys=True,separators=(',',':')))

if __name__=='__main__':
    try: main()
    except BaseException as error:
        if isinstance(error,KeyboardInterrupt): code='interrupted'
        elif isinstance(error,Refused): code=str(error)
        else: code='read_or_validation_failed'
        print('public_snapshot_refused:'+code,file=sys.stderr)
        raise SystemExit(2)
