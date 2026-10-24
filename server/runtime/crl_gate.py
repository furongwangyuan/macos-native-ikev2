"""Candidate drop-in gate for the next common Owner; frozen unified unchanged."""
import time
from pathlib import Path
from pki_io import IO,Refused,sha
import current_crl as current
ROOT=Path('/usr/local/etc/family-vpn')
CRL=ROOT/'swanctl/x509crl/ca.crl.pem'
CA=ROOT/'swanctl/x509ca/ca.pem'

def retirement_gate(h):
    io=IO(ROOT,0);state=ROOT/'.crl-maintenance'
    run=state/'current.json'
    if io.exists(run):
        from renewal import pending_run,completed
        pending=pending_run(io,state)
        # No opening while a signer or multi-file commit could still be active.
        if pending is None or not io.exists(pending/'complete.json'):raise Refused('pki_maintenance_incomplete')
        completed(io,state,pending)
    ca=h.read(CA);raw=h.read(CRL)
    authority,evidence=current.inspect(io,state,ca,raw,now=int(time.time()))
    return dict(number=evidence.number,sha256=evidence.pem_sha256,der_sha256=evidence.der_sha256,
        next=min(evidence.next_update,evidence.ca_not_after),authority_sha256=sha(io.read(state/current.AUTHORITY)))

def loaded_crl_gate(h,proof):
    if retirement_gate(h)!=proof:raise Refused('current_crl_changed_during_startup')
    io=IO(ROOT,0);state=ROOT/'.crl-maintenance'
    from pki_io import decode
    authority=decode(io.read(state/current.AUTHORITY))
    text=h.run([h.SWAN,'--list-certs','--type','x509_crl','--pem','--uri',h.URI]).stdout
    loaded=current.loaded_der_gate(h.read(CA),text.encode('ascii'),authority)
    if loaded.der_sha256!=proof['der_sha256']:raise Refused('current_loaded_crl_differs')
    if retirement_gate(h)!=proof:raise Refused('current_crl_changed_after_loaded_readback')
    h.say('Current verified CRL loaded; historical revocations retained.')
