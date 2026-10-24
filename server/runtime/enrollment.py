"""Actual fixed membership transaction candidate. No installation or CLI effects.

Original provision lock + caller's actual closed/native lease. Fixed staged
signing, strict database delta, prepared-only forward publication and retained
history. This module does not enable a VPN or hot-reload credentials.
"""
import datetime as dt,ipaddress,os,re,time,uuid
from pathlib import Path
from pki_io import IO,Refused,encode,decode,sha,stamp
import registry,current_crl as current,renewal,staged_issuer as issuer
from membership_admission import NAME,pending,admission
REASONS=frozenset(('unspecified','keyCompromise','affiliationChanged','superseded','cessationOfOperation'))
META={'identity','kind','serial_hex','issued_utc','validity_days','algorithm','revoked','certificate_sha256'}
INTENT={'version','run','action','device','identity','reason','stage','serial','crl_number','time_before','old_pointer','old_inventory','old_registry_sha256','old_authority_sha256','old_ca_sha256','old_public_sha256','old_serial_counter','old_crl_counter','old_renewal_pointer','old_renewal_complete_sha256'}
PREPARED={'version','intent_sha256','new_inventory','artifact_hashes','new_registry_sha256','new_authority_sha256','new_public_sha256','time_after'}

def exact_id(value):
    if type(value)is not str or not registry.DEVICE.fullmatch(value):raise Refused('membership_device_id')
    return value

def pointer(raw):
    value=decode(raw)
    if (type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int or value['version']!=1
            or type(value['run'])is not str or not re.fullmatch('[a-f0-9]{32}',value['run'])):raise Refused('membership_run_pointer')
    return value['run']

def index(raw):
    if type(raw)is not bytes or len(raw)>1048576 or raw and not raw.endswith(b'\n'):raise Refused('membership_index_format')
    rows={}
    for line in raw.splitlines():
        fields=line.split(b'\t')
        if (len(fields)!=6 or fields[0]not in (b'V',b'R',b'E') or not re.fullmatch(rb'(?:[0-9]{12}|[0-9]{14})Z',fields[1])
                or not re.fullmatch(rb'[0-9A-Fa-f]{1,40}',fields[3]) or fields[4]!=b'unknown'
                or not fields[5].startswith(b'/CN=') or any(c<32 or c==127 for c in fields[5])):raise Refused('membership_index_row')
        serial=int(fields[3],16)
        if serial in rows:raise Refused('membership_index_duplicate')
        if fields[0]!=b'R' and fields[2]:raise Refused('membership_index_unexpected_revocation')
        rows[serial]=fields
    return rows

def revocation(field):
    parts=field.decode('ascii').split(',')
    if len(parts)not in (1,2):raise Refused('membership_revocation_field')
    text=parts[0];fmt='%y%m%d%H%M%SZ' if len(text)==13 else '%Y%m%d%H%M%SZ'
    try:when=int(dt.datetime.strptime(text,fmt).replace(tzinfo=dt.timezone.utc).timestamp())
    except ValueError:raise Refused('membership_revocation_time')from None
    reason=parts[1] if len(parts)==2 else 'unspecified'
    if reason not in REASONS:raise Refused('membership_revocation_reason')
    return when,reason

def metadata(raw,identity,cert,revoked=False):
    v=decode(raw);keys=META|({'revoked_utc','revocation_reason'}if revoked else set())
    if (type(v)is not dict or set(v)!=keys or v['identity']!=identity or v['kind']!='client'
            or type(v['serial_hex'])is not str or not re.fullmatch('[0-9A-Fa-f]{1,40}',v['serial_hex'])
            or v['revoked']is not revoked or type(v['validity_days'])is not int or v['validity_days']!=365
            or v['algorithm']!='RSA3072/SHA256' or v['certificate_sha256']!=sha(cert)):
        raise Refused('membership_certificate_metadata')
    for key in ('issued_utc',)+(('revoked_utc',)if revoked else ()):
        if type(v[key])is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00',v[key]):raise Refused('membership_metadata_time')
        dt.datetime.fromisoformat(v[key])
    if revoked and v['revocation_reason']not in REASONS:raise Refused('membership_metadata_reason')
    return v

def database_delta(before,after,intent):
    action,serial,number=intent['action'],intent['serial'],intent['crl_number']
    old,new=index(before['index.txt']),index(after['index.txt']);identity=intent['identity'].encode()
    if action=='enroll':
        if serial in old or set(new)!=set(old)|{serial} or any(new[k]!=v for k,v in old.items()):raise Refused('membership_issued_database_delta')
        row=new[serial]
        if row[0]!=b'V' or row[2] or row[5]!=b'/CN='+identity:raise Refused('membership_issued_database_row')
    else:
        if set(new)!=set(old) or serial not in old or old[serial][0]!=b'V' or any(new[k]!=v for k,v in old.items() if k!=serial):raise Refused('membership_revoke_database_delta')
        row=new[serial]
        if row[0]!=b'R' or row[1]!=old[serial][1] or row[3:]!=old[serial][3:] or row[5]!=b'/CN='+identity:raise Refused('membership_revoked_database_row')
        when,reason=revocation(row[2])
        if reason!=intent['reason'] or not intent['time_before']<=when<=intent['time_after']:raise Refused('membership_revoked_database_time_reason')
    changed={'index.txt','index.txt.old','index.txt.attr.old','crl.pem','crlnumber','crlnumber.old'}
    if action=='enroll':changed|={'serial','serial.old','newcerts/'+renewal.hexbytes(serial).decode().strip()+'.pem'}
    if set(after)-set(before)-changed or any(after.get(k)!=v for k,v in before.items() if k not in changed):raise Refused('membership_unrelated_database_change')
    if (after.get('index.txt.old')!=before['index.txt'] or after.get('index.txt.attr.old')!=before['index.txt.attr']
            or after['crlnumber']!=renewal.hexbytes(number+1) or after.get('crlnumber.old')!=renewal.hexbytes(number)):
        raise Refused('membership_database_backup_or_counter')
    if action=='enroll' and (after['serial']!=renewal.hexbytes(serial+1) or after.get('serial.old')!=renewal.hexbytes(serial)):
        raise Refused('membership_serial_counter')
    return row

def historical_identity_absent(io,binary,state,contents,identity):
    """All historical states count; a differently named client may have this SAN.
    The fixed old issuer used CN == its one DNS SAN. Verify actual archived
    certificates and directory metadata rather than assuming folder == SAN.
    """
    rows=index(contents['index.txt']);certs={};identities=set()
    if len(rows)>64:raise Refused('membership_history_inventory_bound')
    for name,raw in contents.items():
        if not name.startswith('newcerts/'):continue
        serial=int(Path(name).stem,16)
        if serial in certs or serial not in rows:raise Refused('membership_history_certificate_inventory')
        observed=issuer.run(binary,['x509','-in',state/name,'-noout','-serial','-subject','-nameopt','RFC2253','-ext','subjectAltName'],output=True)
        match=re.fullmatch(rb'serial=([0-9A-Fa-f]+)\nsubject=CN=([a-z0-9.-]+)\nX509v3 Subject Alternative Name: \n    DNS:([a-z0-9.-]+)\n',observed)
        if (match is None or int(match[1],16)!=serial or match[2]!=match[3]
                or rows[serial][5]!=b'/CN='+match[2]):raise Refused('membership_history_identity_contract')
        issuer.run(binary,['verify','-no_check_time','-CAfile',io.root/'ca/ca.cert.pem',state/name])
        certs[serial]=raw;identities.add(match[2].decode())
    if set(certs)!=set(rows):raise Refused('membership_history_certificate_missing')
    clientroot=io.root/'clients';io.directory(clientroot);children=list(clientroot.iterdir())
    if len(children)>64:raise Refused('membership_client_inventory_bound')
    for client in children:
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}',client.name):raise Refused('membership_client_directory_unknown')
        io.directory(client);cert=io.read(client/'cert.pem');raw=io.read(client/'metadata.json');v=decode(raw)
        if type(v)is not dict or type(v.get('identity'))is not str or type(v.get('revoked'))is not bool:raise Refused('membership_client_metadata_unknown')
        value=metadata(raw,v['identity'],cert,v['revoked']);serial=int(value['serial_hex'],16)
        if certs.get(serial)!=cert or rows[serial][5]!=('/CN='+value['identity']).encode():raise Refused('membership_client_index_alias_differs')
        identities.add(value['identity'])
    if identity in identities or any(row[5]==('/CN='+identity).encode()for row in rows.values()):raise Refused('membership_identity_previously_issued')


def successor(authority,evidence,intent):
    current.check_authority(authority);new=current.metadata(evidence);old=authority['crl']
    if (type(evidence)is not current.crypto.CurrentEvidence or evidence.ca_sha256!=authority['ca_sha256']
            or new['number']!=intent['crl_number'] or new['number']<=old['number'] or new['this_update']<old['this_update']
            or new['der_sha256']==old['der_sha256']):raise Refused('membership_authority_monotonicity')
    if intent['action']=='enroll':
        if new['revocations']!=old['revocations']:raise Refused('membership_enroll_changed_revocations')
    else:
        extra=[r for r in new['revocations'] if r not in old['revocations']]
        if (len(extra)!=1 or any(r not in new['revocations'] for r in old['revocations'])
                or extra[0]['serial']!=intent['serial'] or extra[0]['reason']!=intent['reason']
                or not intent['time_before']<=extra[0]['revoked_at']<=intent['time_after']):raise Refused('membership_revocation_delta')
    return dict(authority,revision=authority['revision']+1,crl=new)

class Enrollment:
    def __init__(self,io,assert_closed,*,openssl=renewal.OPENSSL,clock=time.time):
        self.io=io;self.root=io.root;self.state=self.root/NAME;self.maintenance=self.root/renewal.STATE_NAME
        self.assert_closed=assert_closed;self.openssl=Path(openssl);self.clock=clock
    def scope(self,held):
        held()
        if self.assert_closed()is not None:raise Refused('membership_actual_closed_callback_required')
        held()
    def snapshot(self):
        io=self.io
        ca=io.read(self.root/'ca/ca.cert.pem');public=io.read(self.root/'swanctl/x509crl/ca.crl.pem')
        if io.read(self.root/'swanctl/x509ca/ca.pem')!=ca:raise Refused('membership_public_ca_changed')
        authority,evidence=current.inspect(io,self.maintenance,ca,public,now=int(self.clock()))
        raw=io.read(self.root/'devices.json',65536);reg=registry.loads(raw)
        p=io.read(self.root/'ca/current-state')
        if not re.fullmatch(rb'state-[a-f0-9]{32}\n',p):raise Refused('membership_ca_pointer')
        contents=renewal.Renewal(io,self.assert_closed).inventory(self.root/'ca/states'/p.decode().strip())
        if contents['crl.pem']!=public:raise Refused('membership_state_crl_changed')
        return ca,public,authority,raw,reg,p,contents
    def _new_registry(self,reg,action,device,display):
        rows=[dict(row) for row in reg['devices']];match=next((r for r in rows if r['device_id']==device),None)
        if action=='enroll':
            if match is not None or len(rows)>=16:raise Refused('membership_id_exists_or_registry_full')
            if type(display)is not str:raise Refused('membership_display_name')
            used4={int(ipaddress.IPv4Address(r['vip4']))for r in rows};used6={int(ipaddress.IPv6Address(r['vip6']))for r in rows}
            v4=next((n for n in range(registry.LOW4,registry.HIGH4+1)if n not in used4),None)
            v6=next((n for n in range(registry.LOW6,registry.HIGH6+1)if n not in used6),None)
            if v4 is None or v6 is None:raise Refused('membership_pool_exhausted')
            rows.append(dict(device_id=device,display_name=display,ike_identity=device+'.family.home.arpa',state='enabled',vip4=str(ipaddress.IPv4Address(v4)),vip6=str(ipaddress.IPv6Address(v6))))
        else:
            if match is None or match['state']=='revoked':raise Refused('membership_device_absent_or_already_revoked')
            match['state']='revoked'
        return registry.check_update(reg,dict(reg,revision=reg['revision']+1,devices=rows))
    def enroll_locked(self,device_id,display_name):return self._start('enroll',exact_id(device_id),display_name,None)
    def revoke_locked(self,device_id,reason='cessationOfOperation'):
        if type(reason)is not str or reason not in REASONS:raise Refused('membership_reason')
        return self._start('revoke',exact_id(device_id),None,reason)
    def _start(self,action,device,display,reason):
        io=self.io
        with io.lock(self.root/'.provision.lock')as held:
            self.scope(held);admission(io)
            io.directory(self.root/'.transactions')
            if list((self.root/'.transactions').iterdir()):raise Refused('legacy_membership_transaction_present')
            ca,public,authority,regraw,reg,oldpointer,before=self.snapshot()
            proposed=self._new_registry(reg,action,device,display)
            oldrun=renewal.pending_run(io,self.maintenance);renewptr=None;renewcomplete=None
            if oldrun is not None:
                renewcomplete=io.read(oldrun/'complete.json');renewal.completed(io,self.maintenance,oldrun)
                renewptr=io.read(self.maintenance/'current.json')
            binary=issuer.binary(io,self.openssl)
            io.directory(self.root/'ca/private');fd=os.open(self.root/'ca/private/ca.key.pem',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:io.metadata(fd)
            finally:os.close(fd)
            client=self.root/'clients'/device;identity=device+'.family.home.arpa'
            if action=='enroll':
                historical_identity_absent(io,binary,self.root/'ca/states'/oldpointer.decode().strip(),before,identity)
                if io.exists(client):raise Refused('membership_client_material_exists')
                serial_counter=io.read(self.root/'ca/next-serial');serial=renewal.unhex(serial_counter)
                if serial in index(before['index.txt']):raise Refused('membership_serial_reuse')
                oldmeta=None;cert=None
            else:
                serial_counter=None;cert=io.read(client/'cert.pem');oldmeta=io.read(client/'metadata.json')
                meta=metadata(oldmeta,identity,cert);serial=int(meta['serial_hex'],16)
                issuer.verify_cert(binary,client/'cert.pem',self.root/'ca/ca.cert.pem',identity,serial,self.root/'swanctl/x509crl/ca.crl.pem')
            counter=io.read(self.root/'ca/next-crlnumber');number=renewal.unhex(counter)
            if number<=authority['crl']['number']:raise Refused('membership_crl_counter_not_forward')
            if not io.exists(self.state):io.directory(self.state,create=True)
            runid=uuid.uuid4().hex;run=self.state/runid;io.directory(run,create=True)
            intent=dict(version=1,run=runid,action=action,device=device,identity=identity,reason=reason,stage='state-'+runid,
                serial=serial,crl_number=number,time_before=int(self.clock()),old_pointer=oldpointer.decode(),
                old_inventory={k:sha(v)for k,v in before.items()},old_registry_sha256=sha(regraw),old_authority_sha256=sha(encode(authority)),
                old_ca_sha256=sha(ca),old_public_sha256=sha(public),old_serial_counter=None if serial_counter is None else serial_counter.decode(),
                old_crl_counter=counter.decode(),old_renewal_pointer=None if renewptr is None else renewptr.decode(),
                old_renewal_complete_sha256=None if renewcomplete is None else sha(renewcomplete))
            for name,raw in [('old-ca.pem',ca),('old-public.pem',public),('old-authority.json',encode(authority)),('old-registry.json',regraw),('new-registry.json',encode(proposed))]:io.put(run/name,raw)
            if oldmeta is not None:io.put(run/'old-metadata.json',oldmeta);io.put(run/'old-certificate.pem',cert)
            if renewptr is not None:io.put(run/'old-renewal-pointer.json',renewptr);io.put(run/'old-renewal-complete.json',renewcomplete)
            io.put(run/'intent.json',encode(intent));io.put(self.state/'current.json',encode(dict(version=1,run=runid)))
            self.scope(held)
            # Reserve the whole operation before any signer, never from inside
            # the old issuer and never repeat/reuse numbers after failure.
            if serial_counter is not None:io.put(self.root/'ca/next-serial',renewal.hexbytes(serial+1),before=serial_counter)
            io.put(self.root/'ca/next-crlnumber',renewal.hexbytes(number+1),before=counter)
            stage=self.root/'ca/states'/intent['stage'];io.directory(stage,create=True);io.directory(stage/'newcerts',create=True)
            for name,raw in before.items():io.put(stage/name,raw)
            if action=='enroll':io.put(stage/'serial',renewal.hexbytes(serial),before=before['serial'])
            io.put(stage/'crlnumber',renewal.hexbytes(number),before=before['crlnumber'])
            self.scope(held)
            conf=issuer.issue(io,run,stage,identity,serial,openssl=binary)if action=='enroll'else issuer.revoke(io,run,stage,identity,client/'cert.pem',reason,openssl=binary)
            issuer.gencrl(binary,conf,stage);self.scope(held)
            after=renewal.Renewal(io,self.assert_closed).inventory(stage);end=int(self.clock())
            observed=dict(intent,time_after=end);database_delta(before,after,observed)
            evidence=current.crypto.verify_current(ca,after['crl.pem'],expected_ca_sha256=authority['ca_sha256'],now=end)
            newauth=successor(authority,evidence,observed)
            if action=='enroll':
                cert=io.read(run/'identity/cert.pem');metadata(io.read(run/'identity/metadata.json'),identity,cert)
                issuer.verify_cert(binary,run/'identity/cert.pem',self.root/'ca/ca.cert.pem',identity,serial,stage/'crl.pem')
                if io.read(stage/('newcerts/'+renewal.hexbytes(serial).decode().strip()+'.pem'))!=cert:raise Refused('membership_newcerts_differs')
            else:
                value=decode(oldmeta);revoked_at,_=revocation(index(after['index.txt'])[serial][2]);value.update(revoked=True,revoked_utc=dt.datetime.fromtimestamp(revoked_at,dt.timezone.utc).isoformat(timespec='seconds'),revocation_reason=reason)
                io.put(run/'revoked-metadata.json',encode(value))
            io.put(run/'new-public.pem',after['crl.pem']);io.put(run/'new-authority.json',encode(newauth))
            if action=='enroll':
                regrow=next(r for r in proposed['devices']if r['device_id']==device)
                receipt=dict(version=1,run=runid,device=device,registry_row=regrow,certificate_sha256=sha(cert),metadata_sha256=sha(io.read(run/'identity/metadata.json')),p12_sha256=sha(io.read(run/'identity/identity.p12')))
                io.put(run/'enrollment.json',encode(receipt))
            artifacts=self.artifacts(run,intent)
            prepared=dict(version=1,intent_sha256=sha(io.read(run/'intent.json')),new_inventory={k:sha(v)for k,v in after.items()},
                artifact_hashes={n:sha(raw)for n,raw in artifacts.items()},new_registry_sha256=sha(encode(proposed)),new_authority_sha256=sha(encode(newauth)),new_public_sha256=sha(after['crl.pem']),time_after=end)
            io.put(run/'prepared.json',encode(prepared));return self._commit(run,held)
    def artifacts(self,run,intent):
        if intent['action']=='enroll':return {name:self.io.read(run/'identity'/name)for name in issuer.FILES}|{'enrollment.json':self.io.read(run/'enrollment.json')}
        return {'metadata.json':self.io.read(run/'revoked-metadata.json')}
    def _read(self,run):
        io=self.io;intent=decode(io.read(run/'intent.json'));prepared=decode(io.read(run/'prepared.json'))
        if (type(intent)is not dict or set(intent)!=INTENT or type(intent['version'])is not int or intent['version']!=1
                or intent['run']!=run.name or not re.fullmatch('[a-f0-9]{32}',run.name)or intent['action']not in ('enroll','revoke')
                or intent['identity']!=exact_id(intent['device'])+'.family.home.arpa' or intent['stage']!='state-'+run.name
                or type(intent['serial'])is not int or not 1<=intent['serial']<2**159-1 or type(intent['crl_number'])is not int
                or not 1<=intent['crl_number']<2**159-1 or type(intent['time_before'])is not int
                or not re.fullmatch(r'state-[a-f0-9]{32}\n',intent['old_pointer'])
                or type(prepared)is not dict or set(prepared)!=PREPARED or type(prepared['version'])is not int or prepared['version']!=1
                or prepared['intent_sha256']!=sha(io.read(run/'intent.json')) or type(prepared['time_after'])is not int
                or not intent['time_before']<=prepared['time_after']<=int(self.clock())):raise Refused('membership_prepared_contract')
        if (intent['action']=='enroll' and (intent['reason']is not None or renewal.unhex(intent['old_serial_counter'].encode())!=intent['serial'])
                or intent['action']=='revoke' and (intent['reason']not in REASONS or intent['old_serial_counter']is not None)
                or renewal.unhex(intent['old_crl_counter'].encode())!=intent['crl_number']):raise Refused('membership_intent_reservations')
        for name,expected in [('old-ca.pem',intent['old_ca_sha256']),('old-public.pem',intent['old_public_sha256']),('old-authority.json',intent['old_authority_sha256']),('old-registry.json',intent['old_registry_sha256']),
                ('new-public.pem',prepared['new_public_sha256']),('new-authority.json',prepared['new_authority_sha256']),('new-registry.json',prepared['new_registry_sha256'])]:
            if sha(io.read(run/name))!=expected:raise Refused('membership_retained_source_changed')
        before=renewal.Renewal(io,self.assert_closed).inventory(self.root/'ca/states'/intent['old_pointer'].strip())
        after=renewal.Renewal(io,self.assert_closed).inventory(self.root/'ca/states'/intent['stage'])
        if {k:sha(v)for k,v in before.items()}!=intent['old_inventory']or {k:sha(v)for k,v in after.items()}!=prepared['new_inventory']:raise Refused('membership_database_source_changed')
        observed=dict(intent,time_after=prepared['time_after']);database_delta(before,after,observed)
        ca=io.read(run/'old-ca.pem');oldauth=current.check_authority(decode(io.read(run/'old-authority.json')))
        if io.read(self.root/'ca/ca.cert.pem')!=ca or io.read(self.root/'swanctl/x509ca/ca.pem')!=ca:raise Refused('membership_ca_changed')
        # Validate retained original historical anchor independently of whichever
        # prefix of public publication is currently present.
        history=io.read(self.maintenance/'retirement.json')
        if sha(history)!=oldauth['history_sha256']or io.read(self.maintenance/'retirement-ca.pem')!=ca:raise Refused('membership_history_changed')
        historical=current.history_binding(history,ca,io.read(self.maintenance/'retirement-crl.pem'),oldauth['ca_sha256'],int(self.clock()))
        oldproof=current.crypto.verify_historical(ca,io.read(run/'old-public.pem'),expected_ca_sha256=oldauth['ca_sha256'],now=int(self.clock()))
        if current.metadata(oldproof)!=oldauth['crl'] or any(r not in oldproof.revocations for r in historical.revocations):raise Refused('membership_retained_old_authority_not_proven')
        evidence=current.crypto.verify_current(ca,io.read(run/'new-public.pem'),expected_ca_sha256=oldauth['ca_sha256'],now=int(self.clock()))
        if encode(successor(oldauth,evidence,observed))!=io.read(run/'new-authority.json'):raise Refused('membership_proposed_authority_differs')
        oldreg=registry.loads(io.read(run/'old-registry.json'));newreg=registry.loads(io.read(run/'new-registry.json'))
        expected=self._new_registry(oldreg,intent['action'],intent['device'],next((r['display_name']for r in newreg['devices']if r['device_id']==intent['device']),None))
        if newreg!=expected:raise Refused('membership_registry_delta')
        if io.read(self.root/'ca/next-crlnumber')!=renewal.hexbytes(intent['crl_number']+1):raise Refused('membership_reserved_crl_changed')
        if intent['action']=='enroll'and io.read(self.root/'ca/next-serial')!=renewal.hexbytes(intent['serial']+1):raise Refused('membership_reserved_serial_changed')
        artifacts=self.artifacts(run,intent)
        if {n:sha(v)for n,v in artifacts.items()}!=prepared['artifact_hashes']:raise Refused('membership_staged_artifact_changed')
        if intent['action']=='enroll':
            metadata(artifacts['metadata.json'],intent['identity'],artifacts['cert.pem'])
            issuer.verify_cert(issuer.binary(io,self.openssl),run/'identity/cert.pem',self.root/'ca/ca.cert.pem',intent['identity'],intent['serial'],self.root/'ca/states'/intent['stage']/'crl.pem')
        else:
            beforemeta=metadata(io.read(run/'old-metadata.json'),intent['identity'],io.read(run/'old-certificate.pem'))
            aftermeta=metadata(artifacts['metadata.json'],intent['identity'],io.read(run/'old-certificate.pem'),True)
            if {k:aftermeta[k]for k in META-{'revoked'}}!={k:beforemeta[k]for k in META-{'revoked'}}or aftermeta['revocation_reason']!=intent['reason']or aftermeta['revoked_utc']!=dt.datetime.fromtimestamp(revocation(index(after['index.txt'])[intent['serial']][2])[0],dt.timezone.utc).isoformat(timespec='seconds'):raise Refused('membership_revoked_metadata_delta')
        return intent,prepared,artifacts
    def _retire(self,path,raw,archive):
        io=self.io
        if not io.exists(path):
            if not io.exists(archive)or io.read(archive)!=raw:raise Refused('membership_missing_pointer_without_retirement')
            return
        if io.read(path)!=raw:raise Refused('membership_pointer_changed')
        io.put(archive,raw)
        st=path.lstat()
        if io.read(path)!=raw or stamp(path.lstat())!=stamp(st):raise Refused('membership_pointer_replaced')
        path.unlink();io.sync(path.parent)
    def _commit(self,run,held):
        io=self.io;self.scope(held);intent,prepared,artifacts=self._read(run)
        # No signer runs on recovery. Retirement is prepared-only and preserves
        # the original renewal completion unchanged before any authority update.
        oldrenew=intent['old_renewal_pointer']
        if oldrenew is not None:
            raw=io.read(run/'old-renewal-pointer.json')
            if raw.decode()!=oldrenew:raise Refused('membership_renewal_pointer_retention')
            prior=self.maintenance/pointer(raw);completion=io.read(prior/'complete.json')
            if completion!=io.read(run/'old-renewal-complete.json')or sha(completion)!=intent['old_renewal_complete_sha256']:raise Refused('membership_renewal_completion_changed')
            value=decode(completion);oldauth=decode(io.read(run/'old-authority.json'))
            if (type(value)is not dict or set(value)!={'version','run','phase','number','current_authority_sha256','loaded_verified','data_started'}
                    or type(value['version'])is not int or value['version']!=1 or value['run']!=prior.name
                    or value['phase']!='COMMITTED_CLOSED' or type(value['number'])is not int or value['number']!=oldauth['crl']['number']
                    or value['current_authority_sha256']!=intent['old_authority_sha256'] or value['loaded_verified']is not False or value['data_started']is not False):raise Refused('membership_retained_renewal_completion_contract')
            renewal_raw=raw
        elif io.exists(self.maintenance/'current.json'):raise Refused('membership_unexpected_renewal_pointer')
        client=self.root/'clients'/intent['device']
        if not io.exists(client):io.directory(client,create=True)
        targets=[(self.root/'ca/current-state',intent['old_pointer'].encode(),(intent['stage']+'\n').encode())]
        for name,raw in artifacts.items():
            before=io.read(run/'old-metadata.json')if intent['action']=='revoke'else None
            targets.append((client/name,before,raw))
        targets.extend([(self.root/'swanctl/x509crl/ca.crl.pem',io.read(run/'old-public.pem'),io.read(run/'new-public.pem')),
            (self.maintenance/current.AUTHORITY,io.read(run/'old-authority.json'),io.read(run/'new-authority.json')),
            (self.root/'devices.json',io.read(run/'old-registry.json'),io.read(run/'new-registry.json'))])
        statuses=[]
        for path,before,raw in targets:
            actual=io.read(path)if io.exists(path)else None
            if actual not in (before,raw):raise Refused('membership_publication_conflict')
            statuses.append(actual==raw)
        if statuses!=sorted(statuses,reverse=True):raise Refused('membership_publication_order_unknown')
        if oldrenew is not None:
            if any(statuses)and io.exists(self.maintenance/'current.json'):raise Refused('membership_renewal_pointer_not_retired_first')
            self.scope(held);self._retire(self.maintenance/'current.json',renewal_raw,run/'retired-renewal-pointer.json')
        for path,before,raw in targets:self.scope(held);io.put(path,raw,before=before)
        self.scope(held)
        self.snapshot()
        if io.read(self.root/'devices.json')!=io.read(run/'new-registry.json'):raise Refused('membership_registry_final_readback')
        result=dict(version=1,run=run.name,action=intent['action'],device=intent['device'],phase='COMMITTED_CLOSED',serial=intent['serial'],
            registry_revision=registry.loads(io.read(run/'new-registry.json'))['revision'],current_authority_sha256=prepared['new_authority_sha256'],loaded_verified=False,data_started=False)
        io.put(run/'complete.json',encode(result));self.scope(held)
        self._retire(self.state/'current.json',encode(dict(version=1,run=run.name)),run/'retired-current.json')
        return result
    def recover_locked(self):
        with self.io.lock(self.root/'.provision.lock')as held:
            self.scope(held);runid=pending(self.io)
            if runid is None:raise Refused('no_membership_pending')
            run=self.state/runid;self.io.directory(run)
            if not self.io.exists(run/'prepared.json'):raise Refused('membership_signing_incomplete_no_replay')
            return self._commit(run,held)
