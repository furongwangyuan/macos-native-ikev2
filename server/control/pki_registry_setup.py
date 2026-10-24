"""Fixed initial current-CRL authority and permanent device01 registration.

No CLI, signing, secret reads, service start, credential regeneration or caller
selected paths. The verified manager holds its original manager/native/legacy
locks and supplies lease + old-owner/source readback callbacks. Native closure
is checked independently here, without calling the CRL-dependent preflight.
"""
import re
import subprocess
import time
from pathlib import Path

import current_crl as current
import native_closed
import native_quiescent
import native_runtime as runtime
import native_support as s
import registry
import renewal
from pki_io import IO, Refused, decode, encode, sha

ROOT = Path('/usr/local/etc/family-vpn')
RETIREMENT = Path('/private/var/db/family-vpn/retired01-retirement')
CA_DER_SHA256 = '0000000000000000000000000000000000000000000000000000000000000000'
# Observed in the already saved domain mobileconfig; a reference to the fixed
# public trust anchor, not a hash derived from arbitrary new CA input.
PROFILE_SHA256 = '0000000000000000000000000000000000000000000000000000000000000000'
IDENTITY = 'device01.family.home.arpa'
SERIAL = 0x1002
INITIAL_REGISTRY = dict(version=1, revision=1, usage_timezone='Asia/Kuala_Lumpur', devices=[
    dict(device_id='device01', display_name='家庭 iPhone', ike_identity=IDENTITY,
         state='enabled', vip4='10.77.26.10', vip6='fd6d:fe83:ab27:2600::10')])
PUBLIC = ('ca/ca.cert.pem', 'swanctl/x509ca/ca.pem', 'swanctl/x509crl/ca.crl.pem',
          'clients/device01/cert.pem', 'clients/device01/metadata.json')


def _callback(callback, code):
    if callback() is not None:
        raise Refused(code)


def metadata_binding(record_raw, meta_raw, cert):
    record, meta = decode(record_raw), decode(meta_raw)
    if (type(record) is not dict or type(record.get('version')) is not int or record['version'] != 1
            or record.get('device') != 'retired01' or record.get('stage') != 'complete'
            or type(record.get('after')) is not dict or type(record['after'].get('immutable')) is not dict):
        raise Refused('setup_retirement_history_missing')
    immutable = record['after']['immutable']
    if (immutable.get('clients/device01/cert.pem') != sha(cert)
            or immutable.get('clients/device01/metadata.json') != sha(meta_raw)):
        raise Refused('setup_device01_historical_bytes_changed')
    keys = {'identity', 'kind', 'serial_hex', 'issued_utc', 'validity_days', 'algorithm', 'revoked', 'certificate_sha256'}
    if (type(meta) is not dict or set(meta) != keys or meta['identity'] != IDENTITY
            or meta['kind'] != 'client' or meta['revoked'] is not False
            or type(meta['serial_hex']) is not str or re.fullmatch('[0-9A-Fa-f]{1,40}', meta['serial_hex']) is None
            or int(meta['serial_hex'], 16) != SERIAL or meta['certificate_sha256'] != sha(cert)
            or type(meta['validity_days']) is not int or meta['validity_days'] != 365
            or meta['algorithm'] != 'RSA3072/SHA256' or type(meta['issued_utc']) is not str
            or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|\+00:00)', meta['issued_utc']) is None):
        raise Refused('setup_device01_metadata_invalid')
    return meta


def _openssl(tail):
    # The exact fixed trusted binary and fixed public-only argument sets are
    # selected below. No arbitrary command is passed from the manager or CLI.
    if sha(s.read(renewal.OPENSSL, mode=0o755, limit=32 * 1024 * 1024)) != renewal.OPENSSL_SHA:
        raise Refused('setup_public_verifier_binary_changed')
    p = subprocess.run([str(renewal.OPENSSL), *map(str, tail)], stdin=subprocess.DEVNULL,
        capture_output=True, env=renewal.ENV, close_fds=True, start_new_session=True, timeout=8)
    if len(p.stdout) > 65536 or len(p.stderr) > 8192:
        raise Refused('setup_public_verifier_output_bound')
    return p


def verify_device01_public():
    cert = ROOT / 'clients/device01/cert.pem'
    p = _openssl(['x509', '-in', cert, '-noout', '-serial', '-ext', 'subjectAltName'])
    if (p.returncode or p.stderr or re.fullmatch(
            rb'serial=1002\r?\nX509v3 Subject Alternative Name:\s*\r?\n[ \t]*DNS:device01\.family\.home\.arpa\r?\n', p.stdout) is None):
        raise Refused('setup_device01_public_serial_or_san')
    p = _openssl(['verify', '-CAfile', ROOT / 'swanctl/x509ca/ca.pem',
        '-CRLfile', ROOT / 'swanctl/x509crl/ca.crl.pem', '-crl_check',
        '-purpose', 'sslclient', '-verify_hostname', IDENTITY, cert])
    if p.returncode or p.stderr or p.stdout != (str(cert) + ': OK\n').encode():
        raise Refused('setup_device01_current_certificate_verification')


class _Setup:
    def __init__(self, io, history_io, assert_held, assert_closed):
        self.io, self.history = io, history_io
        self.root, self.state = io.root, io.root / renewal.STATE_NAME
        self.assert_held, self.assert_closed = assert_held, assert_closed
        self.baseline = None
        self.prior_journal = None
        self.journal_observed = False

    def scope(self):
        _callback(self.assert_held, 'setup_lock_callback_contract')
        _callback(self.assert_closed, 'setup_closed_callback_contract')
        native_closed.legacy_writers_absent()
        if runtime.configured()['allow_data'] is not False:
            raise Refused('setup_data_permission_not_closed')
        config = s.json_value(s.read(s.CONF / 'supervisor-config.json', limit=4096))
        if (type(config) is not dict or set(config) != {'version', 'enabled'}
                or type(config['version']) is not int or config['version'] != 1 or config['enabled'] is not False):
            raise Refused('setup_production_permission_not_closed')
        path = s.STATE / 'native-session.json'
        raw = s.read(path) if path.exists() or path.is_symlink() else None
        if raw is not None:
            previous = s.json_value(raw)
            if (type(previous) is not dict or type(previous.get('version')) is not int
                    or previous['version'] not in range(2, 9) or previous.get('active') is not False
                    or previous.get('phase') != 'RESTORED'):
                raise Refused('setup_existing_native_owner_not_restored')
            if previous['version'] == 8:
                # Detailed prior-version completion/role ownership is checked by
                # the fixed manager's assert_closed, before archive. Do not feed
                # v2..v7 to the v8 reader or relabel their original bytes.
                s.Store().load()
            if s.read(path) != raw:
                raise Refused('setup_previous_native_journal_changed')
        if self.journal_observed and raw != self.prior_journal:
            raise Refused('setup_previous_native_journal_changed')
        self.prior_journal, self.journal_observed = raw, True
        observed = native_quiescent.verify(self.assert_held)
        if self.baseline is None:
            self.baseline = observed
        elif observed != self.baseline:
            raise Refused('setup_closed_baseline_changed')
        _callback(self.assert_held, 'setup_lock_callback_contract')

    def materials(self):
        record = self.history.read(self.history.root / 'retirement.json')
        public = {name: self.io.read(self.root / name) for name in PUBLIC}
        if public['ca/ca.cert.pem'] != public['swanctl/x509ca/ca.pem']:
            raise Refused('setup_ca_public_copies_differ')
        metadata_binding(record, public['clients/device01/metadata.json'], public['clients/device01/cert.pem'])
        return record, public

    def transaction_absent(self):
        self.io.directory(self.root / '.transactions')
        if list((self.root / '.transactions').iterdir()):
            raise Refused('setup_legacy_pki_transaction_present')
        if self.io.exists(self.state):
            pending = renewal.pending_run(self.io, self.state)
            if pending is not None:
                # Completed renewals are inspectable. An unfinished signer or
                # publisher must use its original recovery; never bootstrap over it.
                renewal.completed(self.io, self.state, pending)

    def authority(self, record, public):
        authority, evidence = current.inspect(self.io, self.state, public['swanctl/x509ca/ca.pem'],
            public['swanctl/x509crl/ca.crl.pem'], now=int(time.time()))
        if (authority['ca_sha256'] != CA_DER_SHA256 or authority['history_sha256'] != sha(record)
                or self.io.read(self.state / 'retirement.json') != record):
            raise Refused('setup_authority_anchor_or_history_changed')
        if any(row.serial == SERIAL for row in evidence.revocations):
            raise Refused('setup_device01_is_revoked')
        return authority

    def run(self):
        self.scope()
        # First pass is read-only under the original provision lock. Validate
        # existing registry before publishing any new authority.
        with self.io.lock(self.root / '.provision.lock') as held:
            from membership_admission import admission
            admission(self.io)
            self.scope(); held(); self.transaction_absent()
            record, public = self.materials()
            regpath = self.root / 'devices.json'
            initial = encode(registry.normalize(INITIAL_REGISTRY))
            existing_registry = self.io.read(regpath) if self.io.exists(regpath) else None
            if existing_registry is not None and registry.loads(existing_registry) != registry.normalize(INITIAL_REGISTRY):
                raise Refused('setup_existing_registry_preserved_requires_device_flow')
            has_authority = self.io.exists(self.state) and self.io.exists(self.state / current.AUTHORITY)
            if has_authority:
                self.authority(record, public)
            held(); self.scope()
        if not has_authority:
            # This method acquires/rechecks the ORIGINAL provision lock itself.
            # Partial retained history is exact-byte no-clobber and resumable.
            renewal.Renewal(self.io, self.scope).bootstrap_locked(record, CA_DER_SHA256)
        with self.io.lock(self.root / '.provision.lock') as held:
            admission(self.io)
            self.scope(); held(); self.transaction_absent()
            if self.materials() != (record, public):
                raise Refused('setup_public_material_changed_between_locks')
            authority = self.authority(record, public)
            verify_device01_public()
            if self.materials() != (record, public):
                raise Refused('setup_public_material_changed_during_verification')
            # Use exact original registry bytes if already present; no revision,
            # display-name, enabled-state or address rewriting during inspection.
            wanted = existing_registry if existing_registry is not None else initial
            observed = self.io.read(regpath) if self.io.exists(regpath) else None
            if observed not in (existing_registry, wanted):
                raise Refused('setup_registry_changed_preserved')
            held(); self.scope()
            self.io.put(regpath, wanted)
            self.scope(); held()
            if self.io.read(regpath) != wanted or self.materials() != (record, public):
                raise Refused('setup_final_material_changed')
            checked = self.authority(record, public)
            if checked != authority:
                raise Refused('setup_authority_changed')
            return dict(result='current_authority_and_device01_registry_verified_closed',
                authority_created=not has_authority, registry_created=existing_registry is None,
                current_authority_sha256=sha(self.io.read(self.state / current.AUTHORITY)),
                registry_sha256=sha(wanted), ca_der_sha256=CA_DER_SHA256,
                profile_reference_sha256=PROFILE_SHA256, device_id='device01',
                certificate_reused=True, credentials_regenerated=False, signer_run=False,
                loaded_crl_verified=False, daemon_started=False, production_enabled=False)


def initialize_locked(assert_held, assert_closed):
    """Fixed verified-manager API; callbacks have no arguments and return None.

    assert_held rechecks original manager/native/legacy lock leases.
    assert_closed rechecks manager-owned prior-owner/job/source handoff, not a
    synthetic RESTORED flag. Independent live closure is always checked here.
    """
    if s.CONF != ROOT / 'production-guardian':
        raise Refused('setup_fixed_configuration_root_required')
    for path in (ROOT, RETIREMENT):
        s.trusted(path, 0o700)
    return _Setup(IO(ROOT, 0), IO(RETIREMENT, 0), assert_held, assert_closed).run()
