"""Public byte verification only; no signing, installation or native authority.

The externally trusted expected CA DER SHA256 is mandatory. It must NOT merely
be computed from the untrusted input by the caller and mistaken for authority.
HistoricalEvidence deliberately has no current lifecycle conversion method.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import time

BASE = Path(__file__).resolve().parent
HELPER = BASE / 'public-crl-verify'
MAX_CA = 16384
MAX_CRL = 262144
MAX_OUTPUT = 1024 * 1024
MAX_ERROR = 4096
TIMEOUT = 8.0
MAX_TIME = 253402300799
REASONS = frozenset(('unspecified', 'keyCompromise', 'CACompromise',
    'affiliationChanged', 'superseded', 'cessationOfOperation',
    'privilegeWithdrawn', 'AACompromise'))
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/var/empty',
       'OPENSSL_CONF': '/dev/null', 'OPENSSL_MODULES': '/var/empty'}

class Refused(ValueError):
    pass

@dataclass(frozen=True)
class PublicRevocation:
    serial: int
    reason: str
    revoked_at: int

@dataclass(frozen=True)
class _Evidence:
    ca_sha256: str
    pem_sha256: str
    der_sha256: str
    number: int
    this_update: int
    next_update: int
    revocations: tuple
    ca_not_before: int
    ca_not_after: int
    verified_at: int

@dataclass(frozen=True)
class CurrentEvidence(_Evidence):
    def lifecycle_fields(self):
        """Strict structured fields; caller builds lifecycle.Revocation objects.

        This does not commit a CRL or authorize publishing. The frozen lifecycle
        plan must still validate history, monotonicity and guarded transaction.
        """
        return {k: getattr(self, k) for k in ('ca_sha256', 'pem_sha256',
            'der_sha256', 'number', 'this_update', 'next_update', 'revocations')}

@dataclass(frozen=True)
class HistoricalEvidence(_Evidence):
    """Signature/issue-time evidence only, never current publication evidence."""

def _integer(n, low=0, high=MAX_TIME):
    if type(n) is not int or not low <= n <= high:
        raise Refused('bounded integer required')
    return n

def _sha(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise Refused('exact external CA DER digest required')
    return value

def _digest(data):
    return hashlib.sha256(data).hexdigest()

def _pem(data, label, maximum):
    if type(data) is not bytes or len(data) > 2 * maximum:
        raise Refused('bounded public PEM bytes required')
    marker = label.encode('ascii')
    match = re.fullmatch(rb'[\x09\x0a\x0d\x20]*-----BEGIN ' + marker +
        rb'-----[\x0a\x0d]+([A-Za-z0-9+/=\x09\x0a\x0d\x20]+)-----END ' +
        marker + rb'-----[\x09\x0a\x0d\x20]*', data)
    if not match:
        raise Refused('exact one public PEM object required')
    compact = re.sub(rb'[\x09\x0a\x0d\x20]', b'', match[1])
    try:
        der = base64.b64decode(compact, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Refused('invalid base64') from None
    if not 0 < len(der) <= maximum or base64.b64encode(der) != compact:
        raise Refused('noncanonical or oversized base64')
    return der

def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Refused('duplicate JSON key')
        out[key] = value
    return out

def _pinned_helper():
    # Candidate files are trusted source inputs, not a root ownership boundary.
    # Neither manifest nor ordinary-user files constitute tamper resistance.
    try:
        manifest = json.loads((BASE / 'build-manifest.json').read_bytes(), object_pairs_hook=_unique)
        st = HELPER.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o022:
            raise Refused('helper metadata')
        if _digest(HELPER.read_bytes()) != manifest['helper_sha256'] or \
           _digest((BASE / 'public_crl_verify.c').read_bytes()) != manifest['source_sha256'] or \
           manifest['openssl_version'] != '3.5.9':
            raise Refused('candidate build pins changed')
    except (OSError, KeyError, ValueError) as error:
        raise Refused('fixed helper unavailable or changed') from error

def _execute(payload):
    _pinned_helper()
    proc = subprocess.Popen([str(HELPER)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, close_fds=True)
    selector = None
    try:
        started = time.monotonic()
        out, err = bytearray(), bytearray()
        position = 0
        selector = selectors.DefaultSelector()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE, 'in')
        selector.register(proc.stdout, selectors.EVENT_READ, 'out')
        selector.register(proc.stderr, selectors.EVENT_READ, 'err')
        while selector.get_map():
            remaining = TIMEOUT - (time.monotonic() - started)
            if remaining <= 0:
                raise Refused('verification timeout')
            for key, _ in selector.select(remaining):
                stream, kind = key.fileobj, key.data
                if kind == 'in':
                    try:
                        position += os.write(stream.fileno(), payload[position:position+16384])
                    except BrokenPipeError:
                        position = len(payload)
                    if position == len(payload):
                        selector.unregister(stream)
                        stream.close()
                else:
                    block = os.read(stream.fileno(), 16384)
                    if not block:
                        selector.unregister(stream)
                        stream.close()
                    else:
                        destination, bound = (out, MAX_OUTPUT) if kind == 'out' else (err, MAX_ERROR)
                        destination.extend(block)
                        if len(destination) > bound:
                            raise Refused('verification output bound')
        remaining = TIMEOUT - (time.monotonic() - started)
        if remaining <= 0:
            raise Refused('verification timeout')
        status = proc.wait(timeout=remaining)
        if status != 0 or err:
            # Fixed bounded diagnosis only; never echo arbitrary helper bytes.
            code = bytes(err).decode('ascii', errors='replace').strip()
            if re.fullmatch('public_crl_rejected:[a-z0-9_]+', code) is None:
                code = 'helper_failed'
            raise Refused(code)
        return bytes(out)
    except subprocess.TimeoutExpired:
        raise Refused('verification timeout') from None
    finally:
        # Cleanup also covers selector/descriptor SETUP failures. Cleanup failure
        # is propagated, never converted into a successful verification result.
        try:
            if selector is not None:
                selector.close()
        finally:
            try:
                if proc.poll() is None:
                    proc.kill()  # This Popen's still-unreaped child only.
            finally:
                try:
                    proc.wait(timeout=2)
                finally:
                    errors = []
                    for stream in (proc.stdin, proc.stdout, proc.stderr):
                        try:
                            stream.close()
                        except BaseException as error:
                            errors.append(error)
                    if errors:
                        raise Refused('verification stream cleanup failed') from errors[0]

def _verify(ca_pem, crl_pem, expected_ca_sha256, now, historical):
    _integer(now)
    _sha(expected_ca_sha256)
    ca_der, crl_der = _pem(ca_pem, 'CERTIFICATE', MAX_CA), _pem(crl_pem, 'X509 CRL', MAX_CRL)
    if _digest(ca_der) != expected_ca_sha256:
        raise Refused('external CA authority mismatch')
    payload = struct.pack('!8sIIQB', b'FVPNCRL1', len(ca_der), len(crl_der), now, historical) + ca_der + crl_der
    try:
        result = json.loads(_execute(payload), object_pairs_hook=_unique)
    except Refused:
        raise
    except (UnicodeError, ValueError) as error:
        raise Refused('invalid verification result') from error
    required = {'version', 'openssl', 'ca_sha256', 'der_sha256', 'number',
                'this_update', 'next_update', 'ca_not_before', 'ca_not_after',
                'historical', 'revocations'}
    if type(result) is not dict or set(result) != required or \
       type(result['version']) is not int or result['version'] != 1 or result['openssl'] != '3.5.9' or \
       type(result['historical']) is not bool or result['historical'] != historical or \
       result['ca_sha256'] != expected_ca_sha256 or result['der_sha256'] != _digest(crl_der):
        raise Refused('verification result binding')
    number = _integer(result['number'], 1, 2**159 - 1)
    start, end, ca_start, ca_end = (_integer(result[k]) for k in
        ('this_update', 'next_update', 'ca_not_before', 'ca_not_after'))
    if not (ca_start <= start < ca_end and start <= now and 29*86400 <= end-start <= 31*86400):
        raise Refused('verification result time scope')
    if not historical and not (ca_start <= now < ca_end and now < end):
        raise Refused('verification result expired')
    rows = result['revocations']
    if type(rows) is not list or len(rows) > 4096:
        raise Refused('verification result revocations')
    revocations, previous = [], 0
    for row in rows:
        if type(row) is not dict or set(row) != {'serial', 'reason', 'revoked_at'}:
            raise Refused('verification result entry')
        serial, when = _integer(row['serial'], 1, 2**159-1), _integer(row['revoked_at'])
        if serial <= previous or when > start or type(row['reason']) is not str or row['reason'] not in REASONS:
            raise Refused('verification result entry scope')
        previous = serial
        revocations.append(PublicRevocation(serial, row['reason'], when))
    cls = HistoricalEvidence if historical else CurrentEvidence
    return cls(expected_ca_sha256, _digest(crl_pem), _digest(crl_der), number,
               start, end, tuple(revocations), ca_start, ca_end, now)

def verify_current(ca_pem, crl_pem, *, expected_ca_sha256, now):
    return _verify(ca_pem, crl_pem, expected_ca_sha256, now, False)

def verify_historical(ca_pem, crl_pem, *, expected_ca_sha256, now):
    return _verify(ca_pem, crl_pem, expected_ca_sha256, now, True)
