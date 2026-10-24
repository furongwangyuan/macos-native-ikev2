"""Fixed read-only registry inputs for telemetry, never VPN authorization.

The runtime's committed registry path is shared with the device configuration
publisher. This reader grants no certificate/network permissions. A v2 migration
requires a separately installed exact old-ledger/public-registry binding; it is
never synthesized from display names or directory emptiness.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from journal_acl import trusted_path, absent
import registry

ROOT=Path('/usr/local/etc/family-vpn')
REGISTRY=ROOT/'devices.json'
LEGACY=ROOT/'monitor-legacy-registry.json'
LIMIT=65536

@dataclass(frozen=True)
class Snapshot:
    raw: bytes
    sha256: str
    value: dict


def read_public(path):
    if path not in (REGISTRY,LEGACY):raise ValueError('fixed registry source required')
    trusted_path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or
                stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=LIMIT):
            raise ValueError('registry input metadata')
        absent(fd)
        data=bytearray()
        while len(data)<=LIMIT:
            block=os.read(fd,min(8192,LIMIT+1-len(data)))
            if not block:break
            data.extend(block)
        if len(data)!=before.st_size or len(data)>LIMIT or os.fstat(fd)!=before or path.lstat()!=before:
            raise ValueError('registry source changed')
        trusted_path(path)
        if path.lstat()!=before:raise ValueError('registry source replaced')
        return bytes(data)
    finally:os.close(fd)


def read_registry():
    raw=read_public(REGISTRY)
    return Snapshot(raw,hashlib.sha256(raw).hexdigest(),registry.loads(raw))


def legacy_registry(ledger_raw):
    raw=read_public(LEGACY)
    value=json.loads(raw,object_pairs_hook=registry.unique_pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite migration input')))
    if (type(value)is not dict or set(value)!={'version','ledger_sha256','previous_registry'} or
            type(value['version'])is not int or value['version']!=1 or
            type(value['ledger_sha256'])is not str or not re.fullmatch('[a-f0-9]{64}',value['ledger_sha256']) or
            value['ledger_sha256']!=hashlib.sha256(ledger_raw).hexdigest()):
        raise ValueError('explicit legacy ledger binding required')
    return registry.normalize(value['previous_registry'])
