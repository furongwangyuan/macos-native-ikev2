"""Actual stopped-service CRL signer and restartable exact-byte publisher.

No CLI and no auto-restart. The caller retains native/legacy locks and supplies
the real closed verifier. Only original provision lock is acquired here. A crash
before signed bytes are validated/reaped stays incomplete, never re-signs.
"""
import base64, os, re, subprocess, time, uuid
from pathlib import Path
from pki_io import IO,Refused,encode,decode,sha
import current_crl as current

ROOT=Path('/usr/local/etc/family-vpn')
OPENSSL=Path('/usr/local/family-vpn/openssl-3.5.9/bin/openssl')
OPENSSL_SHA='a1416548fece955c86e1255e5429107ad12e2b4c52d78bb107fbf028930e28e0'
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/var/empty',
    'OPENSSL_CONF':'/dev/null','OPENSSL_MODULES':'/var/empty'}
STATE_NAME='.crl-maintenance'
def pending_run(io,state):
    pointer=state/'current.json'
    if not io.exists(pointer):return None
    value=decode(io.read(pointer))
    if type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int or value['version']!=1 or type(value['run'])is not str or re.fullmatch('[a-f0-9]{32}',value['run'])is None:raise Refused('maintenance_pointer')
    run=state/value['run'];io.directory(run);return run
def completed(io,state,run):
    value=decode(io.read(run/'complete.json'))
    authority=current.check_authority(decode(io.read(state/current.AUTHORITY)))
    if (type(value)is not dict or set(value)!={'version','run','phase','number','current_authority_sha256','loaded_verified','data_started'}
            or type(value['version'])is not int or value['version']!=1 or value['run']!=run.name
            or value['phase']!='COMMITTED_CLOSED' or type(value['number'])is not int
            or value['number']!=authority['crl']['number'] or value['loaded_verified']is not False
            or value['data_started']is not False or value['current_authority_sha256']!=sha(io.read(state/current.AUTHORITY))):raise Refused('completed_renewal_binding')
    return value
def unhex(raw):
    if not re.fullmatch(rb'[0-9A-Fa-f]{1,40}\n',raw):raise Refused('counter_shape')
    value=int(raw,16)
    if not 1<=value<2**159-1:raise Refused('counter_range')
    return value
def hexbytes(n):
    v=format(n,'X');return (('0'if len(v)%2 else '')+v+'\n').encode()
def q(path):
    v=str(path)
    if any(c in v for c in ('\n','\r','\0')):raise Refused('config_path')
    return '"'+v.replace('\\','\\\\').replace('"','\\"').replace('$','\\$')+'"'
def signing_config(ca,stage):
    return ('[ca]\ndefault_ca=local_ca\n[local_ca]\n'+
        'database='+q(stage/'index.txt')+'\nnew_certs_dir='+q(stage/'newcerts')+
        '\ncertificate='+q(ca/'ca.cert.pem')+'\nprivate_key='+q(ca/'private/ca.key.pem')+
        '\nserial='+q(stage/'serial')+'\ncrlnumber='+q(stage/'crlnumber')+
        '\ndefault_md=sha256\ndefault_crl_days=30\npolicy=identity\nunique_subject=no\n'+
        'crl_extensions=crl_extensions\n[identity]\ncommonName=supplied\n'+
        '[crl_extensions]\nauthorityKeyIdentifier=keyid:always\n').encode()
def sign(openssl,config,output):
    # Fixed ca/gencrl only. No issued identity, secret stdin, stdout or logs.
    p=subprocess.Popen([str(openssl),'ca','-batch','-config',str(config),'-gencrl','-out',str(output)],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        env=ENV,close_fds=True,start_new_session=True,umask=0o077)
    try:
        if p.wait(timeout=20)!=0:raise Refused('fixed_crl_signer_failed')
    finally:
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=2)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
        if p.poll() is None:raise Refused('signer_cleanup_unverified')

class Renewal:
    def __init__(self,io,assert_closed,*,openssl=OPENSSL,openssl_sha=OPENSSL_SHA,clock=time.time):
        self.io=io;self.root=io.root;self.state=self.root/STATE_NAME
        self.assert_closed=assert_closed;self.openssl=Path(openssl);self.openssl_sha=openssl_sha;self.clock=clock
    def scope(self,held):
        held()
        if self.assert_closed() is not None:raise Refused('closed_verifier_must_raise_or_return_none')
        held()
    def inventory(self,path):
        self.io.directory(path);out={};total=0
        for entry in sorted(path.rglob('*')):
            rel=entry.relative_to(path).as_posix()
            if rel=='newcerts':self.io.directory(entry);continue
            if (not re.fullmatch(r'(?:index\.txt(?:\.attr)?|serial|crlnumber)(?:\.old)?|crl\.pem',rel)
                    and not re.fullmatch(r'newcerts/[0-9A-Fa-f]+\.pem',rel)):raise Refused('unknown_ca_state_file')
            raw=self.io.read(entry);total+=len(raw)
            if len(out)>=4096 or total>16*1024*1024:raise Refused('ca_state_inventory_bound')
            out[rel]=raw
        if not {'index.txt','index.txt.attr','serial','crlnumber','crl.pem'}<=set(out):raise Refused('ca_state_missing')
        return out
    def pending(self):
        return pending_run(self.io,self.state)
    def bootstrap_locked(self,record_raw,expected_ca_sha256):
        # Actual locks, actual public bytes; no secret/key bytes are read here.
        with self.io.lock(self.root/'.provision.lock') as held:
            from membership_admission import admission
            admission(self.io)
            self.scope(held)
            if not self.io.exists(self.state):self.io.directory(self.state,create=True)
            ca=self.io.read(self.root/'swanctl/x509ca/ca.pem');crl=self.io.read(self.root/'swanctl/x509crl/ca.crl.pem')
            if self.io.read(self.root/'ca/ca.cert.pem')!=ca:raise Refused('ca_public_installation_differs')
            value=current.bootstrap(self.io,self.state,ca,crl,record_raw,expected_ca_sha256=expected_ca_sha256,now=int(self.clock()))
            self.scope(held);return value
    def renew_locked(self):
        with self.io.lock(self.root/'.provision.lock') as held:
            from membership_admission import admission
            admission(self.io)
            self.scope(held);self.io.directory(self.state)
            oldrun=self.pending()
            if oldrun is not None and not self.io.exists(oldrun/'complete.json'):raise Refused('prior_renewal_incomplete_use_recover')
            if oldrun is not None:completed(self.io,self.state,oldrun)
            # Never replay the old provisioner's independent pending transaction.
            self.io.directory(self.root/'.transactions')
            if list((self.root/'.transactions').iterdir()):raise Refused('legacy_pki_transaction_present')
            ca=self.io.read(self.root/'ca/ca.cert.pem');public=self.io.read(self.root/'swanctl/x509crl/ca.crl.pem')
            if self.io.read(self.root/'swanctl/x509ca/ca.pem')!=ca:raise Refused('ca_public_installation_differs')
            authority,_=current.inspect(self.io,self.state,ca,public,now=int(self.clock()),current=False)
            pointer=self.io.read(self.root/'ca/current-state')
            if not re.fullmatch(rb'state-[a-f0-9]{32}\n',pointer):raise Refused('ca_pointer')
            oldstate=self.root/'ca/states'/pointer.decode().strip();contents=self.inventory(oldstate)
            if contents['crl.pem']!=public:raise Refused('ca_state_public_differs')
            counter=self.io.read(self.root/'ca/next-crlnumber');number=unhex(counter)
            if number<=authority['crl']['number']:raise Refused('crl_number_not_reserved_forward')
            # Code and executable metadata checked before creating any intent.
            st=self.openssl.lstat()
            import stat
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=self.io.uid or st.st_nlink!=1 or st.st_mode&0o7022 or sha(self.openssl.read_bytes())!=self.openssl_sha:raise Refused('signer_binary_changed')
            # Validate the original key file's descriptor metadata only. Python
            # never reads/copies/logs its contents; the fixed OpenSSL child signs.
            self.io.directory(self.root/'ca/private')
            fd=os.open(self.root/'ca/private/ca.key.pem',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:self.io.metadata(fd)
            finally:os.close(fd)
            runid=uuid.uuid4().hex;run=self.state/runid;stage=self.root/'ca/states'/('state-'+runid)
            self.io.directory(run,create=True)
            for name,raw in [('old-public.pem',public),('old-authority.json',encode(authority)),('old-ca.pem',ca)]:self.io.put(run/name,raw)
            intent=dict(version=1,run=runid,old_pointer=pointer.decode(),old_counter=counter.decode(),reserved=number,
                old_inventory={name:sha(raw) for name,raw in contents.items()},old_ca_sha256=sha(ca),old_public_sha256=sha(public),
                old_authority_sha256=sha(encode(authority)),stage=stage.name)
            self.io.put(run/'intent.json',encode(intent))
            p=self.state/'current.json';before=self.io.read(p) if self.io.exists(p) else None
            self.io.put(p,encode(dict(version=1,run=runid)),before=before)
            self.scope(held)
            # Reserve before signing; never roll back a possibly used number.
            self.io.put(self.root/'ca/next-crlnumber',hexbytes(number+1),before=counter)
            self.io.directory(stage,create=True);self.io.directory(stage/'newcerts',create=True)
            for name,raw in contents.items():self.io.put(stage/name,raw)
            self.io.put(stage/'crlnumber',hexbytes(number),before=contents['crlnumber'])
            config=run/'signing.cnf';self.io.put(config,signing_config(self.root/'ca',stage))
            self.scope(held);sign(self.openssl,config,stage/'crl.pem');self.scope(held)
            new=self.io.read(stage/'crl.pem')
            verified=current.crypto.verify_current(ca,new,expected_ca_sha256=authority['ca_sha256'],now=int(self.clock()))
            if verified.number!=number:raise Refused('signed_number_not_reserved')
            proposed=current.successor(authority,verified)
            after=self.inventory(stage)
            if (unhex(after['crlnumber'])!=number+1 or set(after)-set(contents)-{'crlnumber.old'}
                    or any(after.get(name)!=raw for name,raw in contents.items() if name not in ('crl.pem','crlnumber','crlnumber.old'))):raise Refused('signer_changed_identity_database')
            self.io.put(run/'new-public.pem',new);self.io.put(run/'new-authority.json',encode(proposed))
            # Durable commit intent exists ONLY after the exact child was reaped
            # and the actual new CRL passed signature/current/revocation checks.
            prepared=dict(version=1,intent_sha256=sha(self.io.read(run/'intent.json')),
                new_inventory={name:sha(raw) for name,raw in after.items()},new_public_sha256=sha(new),new_authority_sha256=sha(encode(proposed)))
            self.io.put(run/'prepared.json',encode(prepared))
            return self._commit(run,held)
    def recover_locked(self):
        with self.io.lock(self.root/'.provision.lock') as held:
            from membership_admission import admission
            admission(self.io)
            self.scope(held);run=self.pending()
            if run is None:raise Refused('no_renewal_to_recover')
            if not self.io.exists(run/'prepared.json'):raise Refused('signing_incomplete_no_replay_or_publication')
            return self._commit(run,held)
    def _commit(self,run,held):
        self.scope(held)
        intent=decode(self.io.read(run/'intent.json'));prepared=decode(self.io.read(run/'prepared.json'))
        # Fixed destination names; a stored manifest cannot select a new path.
        if (type(intent)is not dict or set(intent)!={'version','run','old_pointer','old_counter','reserved','old_inventory','old_ca_sha256','old_public_sha256','old_authority_sha256','stage'}
                or type(intent['version'])is not int or intent['version']!=1 or intent['run']!=run.name
                or intent['stage']!='state-'+run.name or type(intent['old_pointer'])is not str
                or type(intent['reserved'])is not int or not 1<=intent['reserved']<2**159-1
                or type(intent['old_counter'])is not str or unhex(intent['old_counter'].encode())!=intent['reserved']
                or re.fullmatch(r'state-[a-f0-9]{32}\n',intent['old_pointer'])is None
                or type(prepared)is not dict or set(prepared)!={'version','intent_sha256','new_inventory','new_public_sha256','new_authority_sha256'}
                or type(prepared['version'])is not int or prepared['version']!=1
                or prepared['intent_sha256']!=sha(self.io.read(run/'intent.json'))):raise Refused('renewal_intent_invalid')
        oldca=self.io.read(run/'old-ca.pem');oldpublic=self.io.read(run/'old-public.pem');oldauth=self.io.read(run/'old-authority.json')
        new=self.io.read(run/'new-public.pem');newauth=self.io.read(run/'new-authority.json')
        for raw,expected in ((oldca,intent['old_ca_sha256']),(oldpublic,intent['old_public_sha256']),(oldauth,intent['old_authority_sha256']),
                (new,prepared['new_public_sha256']),(newauth,prepared['new_authority_sha256'])):
            if sha(raw)!=expected:raise Refused('renewal_bytes_changed')
        if (self.io.read(self.root/'ca/ca.cert.pem')!=oldca or self.io.read(self.root/'swanctl/x509ca/ca.pem')!=oldca
                or self.io.read(self.root/'ca/next-crlnumber')!=hexbytes(intent['reserved']+1)):raise Refused('ca_or_reservation_changed')
        before=self.root/'ca/states'/intent['old_pointer'].strip();stage=self.root/'ca/states'/intent['stage']
        if ({k:sha(v) for k,v in self.inventory(before).items()}!=intent['old_inventory']
                or {k:sha(v) for k,v in self.inventory(stage).items()}!=prepared['new_inventory']):raise Refused('ca_state_changed')
        authority=current.check_authority(decode(oldauth))
        history=self.io.read(self.state/'retirement.json')
        if sha(history)!=authority['history_sha256'] or self.io.read(self.state/'retirement-ca.pem')!=oldca:raise Refused('retirement_anchor_changed')
        current.history_binding(history,oldca,self.io.read(self.state/'retirement-crl.pem'),authority['ca_sha256'],int(self.clock()))
        evidence=current.crypto.verify_current(oldca,new,expected_ca_sha256=authority['ca_sha256'],now=int(self.clock()))
        if encode(current.successor(authority,evidence))!=newauth:raise Refused('new_authority_does_not_match_signed_bytes')
        # Complete forward only; all sources retained, old or exact new accepted.
        targets=[(self.root/'ca/current-state',intent['old_pointer'].encode(),(intent['stage']+'\n').encode()),
                (self.root/'swanctl/x509crl/ca.crl.pem',oldpublic,new),(self.state/current.AUTHORITY,oldauth,newauth)]
        statuses=[]
        for path,old,updated in targets:
            observed=self.io.read(path)
            if observed not in (old,updated):raise Refused('publication_conflict')
            statuses.append(observed==updated)
        if statuses not in ([False,False,False],[True,False,False],[True,True,False],[True,True,True]):raise Refused('publication_order_unknown')
        for path,old,updated in targets:
            self.scope(held);self.io.put(path,updated,before=old)
        self.scope(held)
        current.inspect(self.io,self.state,oldca,self.io.read(self.root/'swanctl/x509crl/ca.crl.pem'),now=int(self.clock()))
        result=dict(version=1,run=run.name,phase='COMMITTED_CLOSED',number=evidence.number,
            current_authority_sha256=sha(newauth),loaded_verified=False,data_started=False)
        self.io.put(run/'complete.json',encode(result));return result
