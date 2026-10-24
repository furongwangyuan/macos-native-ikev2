"""Read-only pending-membership gate; imports only reviewed private JSON I/O.

Called under actual native/provision maintenance locks by ALL new Owners and
PKI writers. No issuer import, signing, recovery, or implicit pointer retirement.
"""
from pki_io import Refused,decode
import re
NAME='.device-enrollment'
def pending(io):
    state=io.root/NAME
    if not io.exists(state):return None
    io.directory(state)
    path=state/'current.json'
    if not io.exists(path):return None
    value=decode(io.read(path,4096))
    if (type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int
            or value['version']!=1 or type(value['run'])is not str or not re.fullmatch('[0-9a-f]{32}',value['run'])):
        raise Refused('membership_pending_pointer_unknown')
    return value['run']
def admission(io):
    if pending(io)is not None:raise Refused('membership_pending_recover_before_owner_or_pki')
    return None
