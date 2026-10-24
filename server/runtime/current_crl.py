"""Real byte verification for a maintained current CRL; never opens the VPN.

Bootstrap expected_ca_sha256 comes from the existing installed/profile trust
chain checked by the installing caller. It is not a new user approval prompt
and must not be replaced by a digest calculated from an arbitrary input.
"""
from dataclasses import asdict
import importlib.util, re, sys, time
from pathlib import Path
from pki_io import Refused,encode,decode,sha

BASE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_maintained_public_crl',BASE/'crypto/public_crl.py')
crypto=importlib.util.module_from_spec(spec);sys.modules[spec.name]=crypto;spec.loader.exec_module(crypto)
AUTHORITY='current-authority.json'
PROFILE='closed-crl-renewal-v1'

def digest(value):
    if type(value)is not str or re.fullmatch('[0-9a-f]{64}',value)is None:raise Refused('digest_required')
    return value
def metadata(evidence):
    value=asdict(evidence);value.pop('verified_at')
    return decode(encode(value))
def check_authority(value):
    if (type(value)is not dict or set(value)!={'version','profile','revision','ca_sha256','history_sha256','crl'}
            or type(value['version'])is not int or value['version']!=1 or value['profile']!=PROFILE
            or type(value['revision'])is not int or not 1<=value['revision']<2**53
            or type(value['crl'])is not dict):raise Refused('authority_schema')
    digest(value['ca_sha256']);digest(value['history_sha256'])
    return value
def history_binding(record_raw,ca,crl,ca_sha,now):
    record=decode(record_raw);e=crypto.verify_historical(ca,crl,expected_ca_sha256=ca_sha,now=now)
    if (type(record)is not dict or record.get('version')!=1 or type(record.get('version'))is not int
            or record.get('device')!='retired01' or record.get('stage')!='complete'):raise Refused('retirement_not_complete')
    after=record.get('after',{});item=after.get('retired01',{});proof=after.get('crl',{})
    serial=item.get('serial_hex')
    if (type(serial)is not str or re.fullmatch('[0-9A-Fa-f]{1,40}',serial)is None
            or item.get('identity')!='retired01.family.home.arpa' or item.get('revoked')is not True
            or item.get('revocation_reason')!='superseded'):raise Refused('retired_identity_binding')
    rows=[r for r in e.revocations if r.serial==int(serial,16) and r.reason=='superseded']
    if (len(rows)!=1 or proof.get('sha256')!=sha(crl) or type(proof.get('number'))is not int
            or proof['number']!=e.number or proof.get('last')!=e.this_update or proof.get('next')!=e.next_update
            or proof.get('revoked')!=[r.serial for r in e.revocations]):raise Refused('retirement_public_bytes_differ')
    return e
def bootstrap(io,state,ca,crl,record_raw,*,expected_ca_sha256,now):
    """Caller owns native + provision locks and has proved closed before calling."""
    digest(expected_ca_sha256)
    old=history_binding(record_raw,ca,crl,expected_ca_sha256,now)
    value=dict(version=1,profile=PROFILE,revision=1,ca_sha256=expected_ca_sha256,
        history_sha256=sha(record_raw),crl=metadata(old))
    for name,raw in [('retirement.json',record_raw),('retirement-ca.pem',ca),('retirement-crl.pem',crl)]:io.put(state/name,raw)
    # Last publication creates authority only after retained historical bytes.
    io.put(state/AUTHORITY,encode(value));return value
def inspect(io,state,ca,crl,*,now=None,current=True):
    now=int(time.time()) if now is None else now
    value=check_authority(decode(io.read(state/AUTHORITY)))
    history=io.read(state/'retirement.json');original=io.read(state/'retirement-crl.pem')
    oldca=io.read(state/'retirement-ca.pem')
    if sha(history)!=value['history_sha256'] or ca!=oldca:raise Refused('retirement_anchor_changed')
    old=history_binding(history,oldca,original,value['ca_sha256'],now)
    verify=crypto.verify_current if current else crypto.verify_historical
    observed=verify(ca,crl,expected_ca_sha256=value['ca_sha256'],now=now)
    if metadata(observed)!=value['crl']:raise Refused('current_authority_public_mismatch')
    if (observed.number<old.number or observed.this_update<old.this_update
            or any(r not in observed.revocations for r in old.revocations)):raise Refused('retirement_lost')
    return value,observed
def successor(old,evidence):
    check_authority(old)
    new=metadata(evidence);prior=old['crl']
    if (type(evidence)is not crypto.CurrentEvidence or evidence.ca_sha256!=old['ca_sha256']
            or new['number']<=prior['number'] or new['this_update']<prior['this_update']
            or new['der_sha256']==prior['der_sha256'] or new['revocations']!=prior['revocations']):
        raise Refused('renewal_changes_identity_or_revocations')
    return dict(old,revision=old['revision']+1,crl=new)
def loaded_der_gate(ca,loaded_pem,authority,*,now=None):
    """Called by the same authenticated Owner after actual swanctl --list-certs.
    Exact one CRL, actual signatures/current interval; no exit-code-only success.
    """
    check_authority(authority)
    proof=crypto.verify_current(ca,loaded_pem,expected_ca_sha256=authority['ca_sha256'],
        now=int(time.time()) if now is None else now)
    if proof.der_sha256!=authority['crl']['der_sha256']:raise Refused('loaded_current_crl_differs')
    return proof
