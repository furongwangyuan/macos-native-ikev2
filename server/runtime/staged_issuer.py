"""Narrow adapted old issuer staging, never its lock/commit/sync_public.

All destinations are the caller's immutable fixed transaction paths. Number
reservation belongs solely to the outer transaction. No public live writes.
"""
import datetime as dt,os,secrets,stat,subprocess,time
from pathlib import Path
from pki_io import Refused,encode,decode,sha
from renewal import ENV,OPENSSL,OPENSSL_SHA,hexbytes,q

FILES=('key.pem','cert.pem','request.csr.pem','identity.p12','p12-password.txt','metadata.json')

def run(binary,args,*,input_bytes=None,output=False):
    # Internal fixed call sites below; this function is not an external command
    # dispatcher. No raw child diagnostics/secret arguments are exported.
    p=subprocess.Popen([str(binary),*map(str,args)],stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE if output else subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        env=ENV,close_fds=True,start_new_session=True,umask=0o077)
    try:
        raw,_=p.communicate(input_bytes,timeout=30)
        if p.returncode!=0:raise Refused('fixed_membership_crypto_failed')
        raw=raw or b''
        if len(raw)>65536:raise Refused('fixed_membership_crypto_output_limit')
        return raw
    finally:
        try:
            if p.poll()is None:
                p.terminate()
                try:p.wait(timeout=2)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
        finally:
            for stream in (p.stdin,p.stdout):
                if stream is not None:stream.close()

def binary(io,path=OPENSSL):
    path=Path(path);info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=io.uid or info.st_nlink!=1
            or info.st_mode&0o7022 or sha(path.read_bytes())!=OPENSSL_SHA):raise Refused('membership_signer_changed')
    return path

def config(ca,state,identity):
    # Same explicit extensions and crypto parameters as reviewed old issuer;
    # no arbitrary config text or caller-controlled path makes this boundary.
    return ('[ca]\ndefault_ca=local_ca\n[local_ca]\n'+
        'database='+q(state/'index.txt')+'\nnew_certs_dir='+q(state/'newcerts')+
        '\ncertificate='+q(ca/'ca.cert.pem')+'\nprivate_key='+q(ca/'private/ca.key.pem')+
        '\nserial='+q(state/'serial')+'\ncrlnumber='+q(state/'crlnumber')+
        '\ndefault_md=sha256\ndefault_days=365\ndefault_crl_days=30\npolicy=identity_policy\nunique_subject=no\ncopy_extensions=none\nemail_in_dn=no\ncrl_extensions=crl_extensions\n'+
        '[identity_policy]\ncommonName=supplied\n[crl_extensions]\nauthorityKeyIdentifier=keyid:always\n'+
        '[client_cert]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:'+identity+'\n').encode()

def issue(io,runroot,state,identity,serial,*,openssl):
    out=runroot/'identity';io.directory(out,create=True)
    key,cert,csr=(out/name for name in ('key.pem','cert.pem','request.csr.pem'))
    req=runroot/'request.cnf';io.put(req,('[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN='+identity+'\n').encode())
    conf=runroot/'signing.cnf';io.put(conf,config(io.root/'ca',state,identity))
    run(openssl,['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',key])
    run(openssl,['req','-new','-sha256','-key',key,'-config',req,'-out',csr])
    run(openssl,['ca','-batch','-notext','-config',conf,'-extensions','client_cert','-days','365','-md','sha256','-in',csr,'-out',cert])
    verify_cert(openssl,cert,io.root/'ca/ca.cert.pem',identity,serial)
    metadata=dict(identity=identity,kind='client',serial_hex=hexbytes(serial).decode().strip(),issued_utc=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        validity_days=365,algorithm='RSA3072/SHA256',revoked=False,certificate_sha256=sha(io.read(cert)))
    io.put(out/'metadata.json',encode(metadata))
    password=secrets.token_urlsafe(32)+'\n';io.put(out/'p12-password.txt',password.encode())
    run(openssl,['pkcs12','-export','-inkey',key,'-in',cert,'-certfile',io.root/'ca/ca.cert.pem','-name',identity,
        '-keypbe','PBE-SHA1-3DES','-certpbe','PBE-SHA1-3DES','-macalg','sha1','-iter','2048','-passout','fd:0','-out',out/'identity.p12'],input_bytes=password.encode())
    run(openssl,['pkcs12','-in',out/'identity.p12','-passin','fd:0','-noout'],input_bytes=password.encode())
    # Public key consistency without printing or exporting private bytes.
    left=run(openssl,['pkey','-in',key,'-pubout'],output=True)
    right=run(openssl,['x509','-in',cert,'-pubkey','-noout'],output=True)
    if left!=right:raise Refused('membership_new_key_certificate_mismatch')
    return conf

def revoke(io,runroot,state,identity,cert,reason,*,openssl):
    conf=runroot/'signing.cnf';io.put(conf,config(io.root/'ca',state,identity))
    run(openssl,['ca','-batch','-config',conf,'-revoke',cert,'-crl_reason',reason]);return conf

def gencrl(openssl,config,state):
    run(openssl,['ca','-batch','-config',config,'-gencrl','-out',state/'crl.pem'])

def verify_cert(openssl,cert,ca,identity,serial,crl=None):
    raw=run(openssl,['x509','-in',cert,'-noout','-serial','-ext','subjectAltName'],output=True)
    expected=('serial='+hexbytes(serial).decode().strip()+'\nX509v3 Subject Alternative Name: \n    DNS:'+identity+'\n').encode()
    if raw!=expected:raise Refused('membership_certificate_identity_or_serial')
    args=['verify','-CAfile',ca,'-purpose','sslclient','-verify_hostname',identity]
    if crl is not None:args+=['-CRLfile',crl,'-crl_check']
    run(openssl,args+[cert])
