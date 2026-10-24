"""Second-step private encrypted profile export for one completed enrollment.

No signing, new identity, registry change, public export or service operation.
Actual manager holds native lease; method additionally holds original PKI lock.
"""
import hashlib,importlib.util,plistlib,re,types
from pathlib import Path
from pki_io import Refused,encode,decode,sha
import enrollment as e,current_crl as current,staged_issuer as issuer
from membership_admission import admission
BUILDER=Path(__file__).resolve().parent/'parent-profile_builder.py'
BUILDER_SHA='83ff70ed52cff719f5c2e820953069e252c87b2a576f59767176beed0bedf237'

def _complete(raw,run,device,serial,authority_sha,revision):
    value=decode(raw)
    if (type(value)is not dict or set(value)!={'version','run','action','device','phase','serial','registry_revision','current_authority_sha256','loaded_verified','data_started'}
            or type(value['version'])is not int or value['version']!=1 or value['run']!=run.name
            or value['action']!='enroll' or value['device']!=device or value['phase']!='COMMITTED_CLOSED'
            or type(value['serial'])is not int or value['serial']!=serial or type(value['registry_revision'])is not int or value['registry_revision']!=revision
            or value['current_authority_sha256']!=authority_sha or value['loaded_verified']is not False or value['data_started']is not False):raise Refused('membership_export_not_completed')

def export_locked(worker,device_id):
    device=e.exact_id(device_id);io=worker.io;root=worker.root
    with io.lock(root/'.provision.lock')as held:
        worker.scope(held);admission(io)
        ca,public,authority,registry_raw,reg,_,_=worker.snapshot()
        row=next((v for v in reg['devices']if v['device_id']==device),None)
        if row is None or row['state']!='enabled':raise Refused('membership_export_device_not_enabled')
        client=root/'clients'/device;record_raw=io.read(client/'enrollment.json');record=decode(record_raw)
        keys={'version','run','device','registry_row','certificate_sha256','metadata_sha256','p12_sha256'}
        if (type(record)is not dict or set(record)!=keys or type(record['version'])is not int or record['version']!=1 or record['device']!=device
                or type(record['run'])is not str or not re.fullmatch('[a-f0-9]{32}',record['run']) or type(record['registry_row'])is not dict):raise Refused('membership_export_origin')
        previous=e.registry.normalize(dict(version=1,revision=1,usage_timezone=e.registry.ZONE,devices=[record['registry_row']]))['devices'][0]
        if any(row[k]!=previous[k]for k in ('device_id','ike_identity','vip4','vip6'))or previous['state']!='enabled':raise Refused('membership_export_permanent_mapping_changed')
        run=worker.state/record['run'];intent_raw=io.read(run/'intent.json');intent=decode(intent_raw);prepared=decode(io.read(run/'prepared.json'))
        if (type(intent)is not dict or set(intent)!=e.INTENT or type(intent['version'])is not int or intent['version']!=1
                or intent['run']!=run.name or intent['action']!='enroll' or intent['device']!=device or intent['identity']!=row['ike_identity']
                or type(intent['serial'])is not int or type(prepared)is not dict or set(prepared)!=e.PREPARED
                or type(prepared['version'])is not int or prepared['version']!=1 or prepared['intent_sha256']!=sha(intent_raw)):
            raise Refused('membership_export_prepared_origin')
        if io.read(run/'enrollment.json')!=record_raw or io.read(run/'retired-current.json')!=encode(dict(version=1,run=run.name)):
            raise Refused('membership_export_origin_not_retired')
        newreg_raw=io.read(run/'new-registry.json');newreg=e.registry.loads(newreg_raw)
        if sha(newreg_raw)!=prepared['new_registry_sha256']or next((r for r in newreg['devices']if r['device_id']==device),None)!=previous:
            raise Refused('membership_export_registry_origin_changed')
        newauth=io.read(run/'new-authority.json')
        if sha(newauth)!=prepared['new_authority_sha256']:raise Refused('membership_export_authority_origin_changed')
        _complete(io.read(run/'complete.json'),run,device,intent['serial'],sha(newauth),newreg['revision'])
        cert=io.read(client/'cert.pem');meta_raw=io.read(client/'metadata.json');p12=io.read(client/'identity.p12')
        if (sha(cert)!=record['certificate_sha256']or sha(meta_raw)!=record['metadata_sha256']or sha(p12)!=record['p12_sha256']
                or any(io.read(client/name)!=io.read(run/'identity'/name)for name in ('cert.pem','metadata.json','identity.p12'))):raise Refused('membership_export_live_artifact_changed')
        meta=e.metadata(meta_raw,row['ike_identity'],cert)
        if int(meta['serial_hex'],16)!=intent['serial']:raise Refused('membership_export_serial_changed')
        binary=issuer.binary(io,worker.openssl)
        issuer.verify_cert(binary,client/'cert.pem',root/'ca/ca.cert.pem',row['ike_identity'],intent['serial'],root/'swanctl/x509crl/ca.crl.pem')
        # Verify the existing encrypted container/password again. Password goes
        # only to this fixed child private stdin, never profile/report/argv.
        password=io.read(client/'p12-password.txt')
        if password!=io.read(run/'identity/p12-password.txt')or sha(password)!=prepared['artifact_hashes']['p12-password.txt']:raise Refused('membership_export_password_origin_changed')
        issuer.run(binary,['pkcs12','-in',client/'identity.p12','-passin','fd:0','-noout'],input_bytes=password)
        raw=BUILDER.read_bytes()
        if sha(raw)!=BUILDER_SHA:raise Refused('membership_profile_builder_changed')
        scope={'__name__':'fixed_membership_profile_builder','__file__':str(BUILDER)};exec(compile(raw,str(BUILDER),'exec'),scope)
        args=types.SimpleNamespace(remote_id='vpn.family.home.arpa',device_id=row['ike_identity'],ca_der='ca.cert.der',device_p12='identity.p12',
            server='vpn.example.com',ca_cn='Family VPN Root CA',certificate_type='RSA',cipher_suite='gcm256-ecp256',mtu=1280,
            name='家庭 VPN · '+row['display_name'],dns=['202.188.18.188','1.9.1.9'])
        der=current.crypto._pem(ca,'CERTIFICATE',current.crypto.MAX_CA)
        profile=scope['build_profile'](args,der,p12);out=plistlib.dumps(profile,fmt=plistlib.FMT_XML,sort_keys=False)
        if plistlib.loads(out)!=profile:raise Refused('membership_profile_roundtrip')
        worker.scope(held);admission(io)
        if worker.snapshot()[:5]!=(ca,public,authority,registry_raw,reg):raise Refused('membership_export_source_changed')
        if io.read(client/'enrollment.json')!=record_raw or io.read(client/'cert.pem')!=cert or io.read(client/'metadata.json')!=meta_raw or io.read(client/'identity.p12')!=p12:raise Refused('membership_export_identity_changed')
        directory=client/'exports'
        if not io.exists(directory):io.directory(directory,create=True)
        path=directory/('enrollment-'+run.name+'-r'+str(reg['revision'])+'.mobileconfig');io.put(path,out)
        worker.scope(held)
        return dict(event='membership_private_profile_exported',device=device,registry_revision=reg['revision'],profile_sha256=sha(out),
            private_relative_path=str(path.relative_to(root)),encrypted_identity_included=True,password_exported=False,iphone_installation_verified=False,data_started=False)
