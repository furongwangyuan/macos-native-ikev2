#!/usr/bin/env python3
"""Manage a private family-VPN CA and candidate iOS credentials.

No operation is implicit. Run init, issue-server, and issue-device retired01 in
order, then make-profile retired01 if needed. Root is required unless an alternate
--root and --allow-unprivileged-test are BOTH supplied. This script has not been
validated with an iPhone and never labels an export as deployment-complete.

The CA key remains in ROOT/ca/private, outside swanctl. Client private keys and
PKCS#12 passwords remain in ROOT/clients/NAME. Only encrypted client material and
public CA data are exported. Never copy the entire ROOT to iCloud.
"""

import argparse
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import uuid


DEFAULT_ROOT = Path("/usr/local/etc/family-vpn")
DEFAULT_OPENSSL = Path("/usr/local/family-vpn/openssl-3.5.9/bin/openssl")
CA_CN = "Family VPN Root CA"
SERVER_ID = "vpn.family.home.arpa"
INITIAL_DEVICE_ID = "retired01.family.home.arpa"
REASONS = ("unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hexadecimal(value):
    result = format(value, "X")
    return ("0" if len(result) % 2 else "") + result + "\n"


def device_name(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise argparse.ArgumentTypeError("device name must contain 1..64 ASCII letters/digits/_/-")
    return value


def dns_name(value):
    if len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", value):
        raise argparse.ArgumentTypeError("identity must be an ASCII DNS name, without URL/path")
    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in value.split(".")):
        raise argparse.ArgumentTypeError("invalid DNS identity")
    return value.lower()


def config_path(path):
    text = str(Path(path))
    if any(c in text for c in ("\n", "\r", "\0")):
        raise ValueError("invalid path for OpenSSL configuration")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


class Provisioner:
    def __init__(self, root, openssl, allow_test=False):
        self.root = Path(root).absolute()
        self.openssl = Path(openssl).absolute()
        if os.geteuid() != 0 and not (allow_test and self.root != DEFAULT_ROOT):
            raise PermissionError("root required; alternate test roots need --allow-unprivileged-test")
        if allow_test and self.root == DEFAULT_ROOT:
            raise ValueError("test mode cannot use the production root")
        if self.root == Path("/") or self.root == Path.home():
            raise ValueError("a dedicated private root directory is required")
        # Avoid resolving a caller-controlled symlink into an unexpected destination.
        for component in (self.root, *self.root.parents):
            if component.is_symlink():
                raise ValueError(f"symlink in root path is not allowed: {component}")
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.check_private(self.root, directory=True)
        self.directory(".transactions")

    @staticmethod
    def check_private(path, directory=False):
        info = Path(path).lstat()
        kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not kind_ok or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError(f"expected owner-only {'directory' if directory else 'file'}: {path}")

    def relative(self, value):
        path = Path(value)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise ValueError("internal paths must be relative and must not escape the root")
        return self.root / path

    def directory(self, relative):
        path = self.relative(relative)
        current = self.root
        for part in path.relative_to(self.root).parts:
            current = current / part
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self.check_private(current, directory=True)
        return path

    @staticmethod
    def sync_directory(path):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, path, data, replace=False):
        path = Path(path)
        self.directory(path.parent.relative_to(self.root))
        if path.exists() or path.is_symlink():
            self.check_private(path)
            if not replace:
                raise FileExistsError(f"refusing to replace existing material: {path}")
        if isinstance(data, str):
            data = data.encode("utf-8")
        temporary = path.parent / (".write-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if replace:
                os.replace(temporary, path)
            else:
                # Hard-link creation is atomic and does not clobber existing files.
                os.link(temporary, path)
                temporary.unlink()
            self.sync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def json_write(self, path, value, replace=False):
        self.write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", replace=replace)

    @contextlib.contextmanager
    def lock(self):
        path = self.root / ".provision.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            self.check_private(path)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.recover_pending()
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def run(self, arguments, input_bytes=None):
        if not self.openssl.is_file() or not os.access(self.openssl, os.X_OK):
            raise FileNotFoundError(f"OpenSSL executable unavailable: {self.openssl}")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("OPENSSL_") and key != "RANDFILE"}
        environment["OPENSSL_CONF"] = os.devnull
        # The default provider is built in. If this installation has loadable
        # modules, use its own directory, never a caller-supplied provider path.
        modules = self.openssl.parent.parent / "lib/ossl-modules"
        if modules.is_dir():
            environment["OPENSSL_MODULES"] = str(modules)
        completed = subprocess.run([str(self.openssl), *map(str, arguments)], input=input_bytes,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                                   env=environment)
        if completed.returncode:
            # Invocations use -out for keys and fd:0 for passwords; neither is printed.
            detail = completed.stderr.decode("utf-8", errors="replace")[-5000:]
            raise RuntimeError(f"OpenSSL {arguments[0]} failed ({completed.returncode}): {detail}")
        return completed.stdout.decode("utf-8", errors="replace").strip()

    def fresh_transaction(self):
        return self.directory(".transactions/tx-" + uuid.uuid4().hex)

    def current_state(self):
        pointer = self.root / "ca/current-state"
        self.check_private(pointer)
        name = pointer.read_text().strip()
        if not re.fullmatch(r"state-[0-9a-f]{32}", name):
            raise ValueError("invalid CA state pointer")
        path = self.root / "ca/states" / name
        self.check_private(path, directory=True)
        for required in ("index.txt", "index.txt.attr", "serial", "crlnumber", "crl.pem"):
            self.check_private(path / required)
        self.check_private(self.root / "ca/private/ca.key.pem")
        self.check_private(self.root / "ca/ca.cert.pem")
        return path

    def next_number(self, counter, minimum=0x1000):
        path = self.root / "ca" / counter
        self.check_private(path)
        value = int(path.read_text().strip(), 16)
        if value < minimum or value >= (1 << 159) - 1:
            raise ValueError(f"invalid {counter} reservation counter")
        # Persist before issuing: a failed issuance skips a number, never reuses it.
        self.write(path, hexadecimal(value + 1), replace=True)
        return value

    def ca_config(self, ca, state, extension=None, identity=None):
        result = f"""[ca]
default_ca = local_ca
[local_ca]
dir = {config_path(ca)}
database = {config_path(state / 'index.txt')}
new_certs_dir = {config_path(state / 'newcerts')}
certificate = {config_path(ca / 'ca.cert.pem')}
private_key = {config_path(ca / 'private/ca.key.pem')}
serial = {config_path(state / 'serial')}
crlnumber = {config_path(state / 'crlnumber')}
default_md = sha256
default_days = 365
default_crl_days = 30
policy = identity_policy
unique_subject = no
copy_extensions = none
email_in_dn = no
crl_extensions = crl_extensions
[identity_policy]
commonName = supplied
[crl_extensions]
authorityKeyIdentifier = keyid:always
"""
        if extension:
            if extension not in ("server_cert", "client_cert"):
                raise ValueError("invalid certificate extension")
            identity = dns_name(identity)
            eku = "serverAuth" if extension == "server_cert" else "clientAuth"
            key_usage = "digitalSignature,keyEncipherment" if extension == "server_cert" else "digitalSignature"
            result += f"""[{extension}]
basicConstraints = critical,CA:false
keyUsage = critical,{key_usage}
extendedKeyUsage = {eku}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:{identity}
"""
        return result

    def generate_crl(self, config, state):
        self.run(["ca", "-batch", "-config", config, "-gencrl", "-out", state / "crl.pem"])

    def init_ca(self):
        ca = self.root / "ca"
        if ca.exists() or ca.is_symlink():
            raise FileExistsError("CA already exists; init never overwrites a CA. Use status or sync-public.")
        transaction = self.fresh_transaction()
        staged_ca = self.directory(transaction.relative_to(self.root) / "ca")
        self.directory(staged_ca.relative_to(self.root) / "private")
        state_name = "state-" + uuid.uuid4().hex
        state = self.directory(staged_ca.relative_to(self.root) / "states" / state_name)
        self.directory(state.relative_to(self.root) / "newcerts")
        for filename, contents in (("index.txt", ""), ("index.txt.attr", "unique_subject = no\n"),
                                   ("serial", "1000\n"), ("crlnumber", "1000\n")):
            self.write(state / filename, contents)
        config = transaction / "root-req.cnf"
        self.write(config, f"""[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[dn]
CN = {CA_CN}
[v3_ca]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
""")
        key = staged_ca / "private/ca.key.pem"
        self.run(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096", "-out", key])
        self.run(["req", "-new", "-x509", "-key", key, "-sha256", "-days", "3650",
                  "-set_serial", "1", "-config", config, "-out", staged_ca / "ca.cert.pem"])
        self.run(["x509", "-in", staged_ca / "ca.cert.pem", "-outform", "DER", "-out", staged_ca / "ca.cert.der"])
        database_config = transaction / "ca.cnf"
        self.write(database_config, self.ca_config(staged_ca, state))
        self.generate_crl(database_config, state)
        self.run(["verify", "-CAfile", staged_ca / "ca.cert.pem", staged_ca / "ca.cert.pem"])
        self.run(["crl", "-in", state / "crl.pem", "-verify", "-CAfile", staged_ca / "ca.cert.pem", "-noout"])
        self.write(staged_ca / "next-serial", "1000\n")
        self.write(staged_ca / "next-crlnumber", (state / "crlnumber").read_bytes())
        self.write(staged_ca / "current-state", state_name + "\n")
        self.json_write(staged_ca / "metadata.json", {"created_utc": now(), "common_name": CA_CN,
                        "algorithm": "RSA4096/SHA256", "validity_days": 3650, "pathlen": 0})
        self.validate_tree(staged_ca)
        self.fsync_tree(staged_ca)
        # Complete CA directory appears at once; no existing CA is replaced.
        os.rename(staged_ca, ca)
        self.sync_directory(self.root)
        shutil.rmtree(transaction)
        self.sync_public()
        print("CA created; no server or client identity has been issued yet.")

    def validate_tree(self, directory):
        self.check_private(directory, directory=True)
        for path in Path(directory).rglob("*"):
            self.check_private(path, directory=path.is_dir() and not path.is_symlink())

    def fsync_tree(self, directory):
        for path in Path(directory).rglob("*"):
            if path.is_file():
                with path.open("rb") as handle:
                    os.fsync(handle.fileno())
        for path in sorted(Path(directory).rglob("*"), reverse=True):
            if path.is_dir():
                self.sync_directory(path)
        self.sync_directory(directory)

    def clone_state(self):
        previous = self.current_state()
        self.validate_tree(previous)
        transaction = self.fresh_transaction()
        staged = transaction / "state"
        shutil.copytree(previous, staged)
        self.validate_tree(staged)
        return transaction, staged, previous.name

    def artifact(self, transaction, source, target, replace=False):
        self.check_private(source)
        relative_target = Path(target)
        self.relative(relative_target)
        return {"source": str(Path(source).relative_to(transaction)), "target": str(relative_target),
                "sha256": sha256(source), "replace": bool(replace)}

    def commit(self, transaction, state, previous, artifacts):
        self.validate_tree(transaction)
        self.fsync_tree(transaction)
        manifest = {"version": 1, "previous": previous, "new_state": "state-" + uuid.uuid4().hex,
                    "created_utc": now(), "artifacts": artifacts}
        self.json_write(transaction / "commit.json", manifest)
        self.finish_commit(transaction, manifest)

    def finish_commit(self, transaction, manifest):
        if manifest.get("version") != 1:
            raise ValueError("unsupported pending transaction")
        name = manifest["new_state"]
        if not re.fullmatch(r"state-[0-9a-f]{32}", name):
            raise ValueError("invalid transaction state name")
        final_state = self.root / "ca/states" / name
        staged_state = transaction / "state"
        if not final_state.exists():
            self.validate_tree(staged_state)
            os.rename(staged_state, final_state)
            self.sync_directory(final_state.parent)
        else:
            self.validate_tree(final_state)
        pointer = self.root / "ca/current-state"
        current = pointer.read_text().strip()
        if current not in (manifest["previous"], name):
            raise RuntimeError("unexpected CA state; manual recovery required")
        if current != name:
            self.write(pointer, name + "\n", replace=True)
        # Authoritative database commits first; crash recovery completes publication.
        for item in manifest["artifacts"]:
            source_relative = Path(item["source"])
            if source_relative.is_absolute() or ".." in source_relative.parts:
                raise ValueError("invalid pending artifact path")
            source = transaction / source_relative
            self.check_private(source)
            if sha256(source) != item["sha256"]:
                raise RuntimeError("pending artifact hash mismatch")
            target = self.relative(item["target"])
            if target.exists() or target.is_symlink():
                self.check_private(target)
                if sha256(target) == item["sha256"]:
                    continue
                if not item["replace"]:
                    raise FileExistsError(f"refusing to overwrite different material during recovery: {target}")
            self.write(target, source.read_bytes(), replace=item["replace"])
        self.sync_public()
        shutil.rmtree(transaction)
        self.sync_directory(transaction.parent)

    def recover_pending(self):
        for transaction in sorted((self.root / ".transactions").glob("tx-*")):
            self.check_private(transaction, directory=True)
            manifest_path = transaction / "commit.json"
            if manifest_path.exists():
                self.check_private(manifest_path)
                print("Completing an interrupted committed PKI transaction.")
                self.finish_commit(transaction, json.loads(manifest_path.read_text()))

    def sync_public(self):
        state = self.current_state()
        for source, target in ((self.root / "ca/ca.cert.pem", "swanctl/x509ca/ca.pem"),
                               (state / "crl.pem", "swanctl/x509crl/ca.crl.pem")):
            self.check_private(source)
            self.write(self.relative(target), source.read_bytes(), replace=True)

    def metadata(self, certificate, identity, kind):
        serial = self.run(["x509", "-in", certificate, "-noout", "-serial"]).split("=", 1)[1].strip()
        return {"identity": identity, "kind": kind, "serial_hex": serial, "issued_utc": now(),
                "validity_days": 365, "algorithm": "RSA3072/SHA256", "revoked": False,
                "certificate_sha256": sha256(certificate)}

    def issue(self, kind, name=None, identity=None):
        if kind == "server":
            identity = dns_name(identity or SERVER_ID)
            targets = {"key.pem": "swanctl/private/server.pem", "cert.pem": "swanctl/x509/server.pem",
                       "request.csr.pem": "server/request.csr.pem", "metadata.json": "server/metadata.json"}
            extension, purpose = "server_cert", "sslserver"
        else:
            name = device_name(name)
            identity = dns_name(identity or name + ".family.home.arpa")
            for existing in (self.root / "clients").glob("*/metadata.json"):
                self.check_private(existing)
                if json.loads(existing.read_text()).get("identity") == identity:
                    raise ValueError("device identity was already issued; use a new unique device identity")
            targets = {filename: f"clients/{name}/{filename}" for filename in
                       ("key.pem", "cert.pem", "request.csr.pem", "identity.p12", "p12-password.txt", "metadata.json")}
            extension, purpose = "client_cert", "sslclient"
        for target in targets.values():
            path = self.relative(target)
            if path.exists() or path.is_symlink():
                raise FileExistsError(f"identity material already exists; refusing replacement: {path}")
        transaction, state, previous = self.clone_state()
        serial = self.next_number("next-serial")
        self.write(state / "serial", hexadecimal(serial), replace=True)
        output = self.directory(transaction.relative_to(self.root) / "identity")
        key, certificate, request = output / "key.pem", output / "cert.pem", output / "request.csr.pem"
        self.run(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", key])
        request_config = transaction / "req.cnf"
        self.write(request_config, "[req]\nprompt = no\ndistinguished_name = dn\n[dn]\nCN = " + identity + "\n")
        self.run(["req", "-new", "-sha256", "-key", key, "-config", request_config, "-out", request])
        config = transaction / "ca.cnf"
        self.write(config, self.ca_config(self.root / "ca", state, extension, identity))
        self.run(["ca", "-batch", "-notext", "-config", config, "-extensions", extension,
                  "-days", "365", "-md", "sha256", "-in", request, "-out", certificate])
        verify = ["verify", "-CAfile", self.root / "ca/ca.cert.pem", "-purpose", purpose]
        if kind == "server":
            verify += ["-verify_hostname", identity]
        self.run([*verify, certificate])
        self.json_write(output / "metadata.json", self.metadata(certificate, identity, kind))
        if kind != "server":
            password = secrets.token_urlsafe(32)
            self.write(output / "p12-password.txt", password + "\n")
            # Explicit 3DES/SHA1 is for PKCS#12 import compatibility only, not IPsec.
            self.run(["pkcs12", "-export", "-inkey", key, "-in", certificate,
                      "-certfile", self.root / "ca/ca.cert.pem", "-name", identity,
                      "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1",
                      "-iter", "2048", "-passout", "fd:0", "-out", output / "identity.p12"],
                     input_bytes=(password + "\n").encode())
            self.run(["pkcs12", "-in", output / "identity.p12", "-passin", "fd:0", "-noout"],
                     input_bytes=(password + "\n").encode())
        number = self.next_number("next-crlnumber")
        self.write(state / "crlnumber", hexadecimal(number), replace=True)
        self.generate_crl(config, state)
        self.run(["crl", "-in", state / "crl.pem", "-verify", "-CAfile", self.root / "ca/ca.cert.pem", "-noout"])
        artifacts = [self.artifact(transaction, output / filename, target) for filename, target in targets.items()]
        self.commit(transaction, state, previous, artifacts)
        print(f"Issued {kind} identity {identity}; serial {hexadecimal(serial).strip()}. Client/network acceptance remains pending.")
        if kind != "server":
            print(f"PKCS#12 password is stored only in {self.root / targets['p12-password.txt']}; it was not printed or exported.")

    def renew_crl(self, revoke_name=None, reason="unspecified"):
        artifacts = []
        certificate = metadata_path = metadata = None
        if revoke_name:
            name = device_name(revoke_name)
            certificate = self.root / "clients" / name / "cert.pem"
            metadata_path = certificate.parent / "metadata.json"
            self.check_private(certificate)
            self.check_private(metadata_path)
            metadata = json.loads(metadata_path.read_text())
            if metadata.get("revoked"):
                print("Device is already marked revoked; renewing the CRL without repeating revocation.")
                certificate = None
        transaction, state, previous = self.clone_state()
        config = transaction / "ca.cnf"
        self.write(config, self.ca_config(self.root / "ca", state))
        if certificate:
            self.run(["ca", "-batch", "-config", config, "-revoke", certificate, "-crl_reason", reason])
            metadata.update(revoked=True, revoked_utc=now(), revocation_reason=reason)
            self.json_write(transaction / "revoked-metadata.json", metadata)
            artifacts.append(self.artifact(transaction, transaction / "revoked-metadata.json",
                                           metadata_path.relative_to(self.root), replace=True))
        number = self.next_number("next-crlnumber")
        self.write(state / "crlnumber", hexadecimal(number), replace=True)
        self.generate_crl(config, state)
        self.run(["crl", "-in", state / "crl.pem", "-verify", "-CAfile", self.root / "ca/ca.cert.pem", "-noout"])
        self.commit(transaction, state, previous, artifacts)
        print("CRL updated on disk. Reload charon credentials to apply it; existing sessions are not automatically terminated by this script.")

    def make_profile(self, name, server_address, remote_id, dns_servers, builder):
        name = device_name(name)
        client = self.root / "clients" / name
        self.check_private(client, directory=True)
        self.check_private(client / "metadata.json")
        metadata = json.loads((client / "metadata.json").read_text())
        if metadata.get("revoked"):
            raise ValueError("refusing to export a revoked device")
        builder = Path(builder).absolute()
        if not builder.is_file():
            raise FileNotFoundError(f"profile builder missing: {builder}")
        # Export only encrypted identity + public CA. No private key or password.
        export = self.directory("clients/" + name + "/exports/candidate-" + uuid.uuid4().hex[:12])
        for source, filename in ((client / "identity.p12", "identity.p12"),
                                 (self.root / "ca/ca.cert.der", "ca.cert.der")):
            self.check_private(source)
            self.write(export / filename, source.read_bytes())
        command = [sys.executable, str(builder), "--device-p12", str(export / "identity.p12"),
                   "--ca-der", str(export / "ca.cert.der"), "--server", server_address,
                   "--remote-id", remote_id, "--device-id", metadata["identity"], "--ca-cn", CA_CN,
                   "--certificate-type", "RSA", "--cipher-suite", "gcm256-ecp256",
                   "--name", "家庭 VPN · 马来西亚（临时入口）", "--candidate-output", str(export / "candidate.mobileconfig")]
        for address in dns_servers:
            command += ["--dns", address]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode:
            raise RuntimeError("candidate profile generation failed: " + completed.stderr.decode(errors="replace")[-3000:])
        self.write(export / "README.txt", "候选客户端材料，尚未通过 iPhone 或互联网验收。\n"
                   f"VPN 入口：{server_address}（临时地址，变化后需更新）。\n"
                   f"服务器证书身份：{remote_id}；设备身份：{metadata['identity']}。\n"
                   "安装 profile 时输入单独传递的 PKCS#12 密码。此目录不含密码或明文私钥。\n"
                   "identity.p12 和 mobileconfig 仍含加密私钥，应只交给对应设备持有人。\n"
                   "不要把 /usr/local/etc/family-vpn 整个目录复制到 iCloud。\n")
        print(f"Unverified encrypted client export created: {export}")
        print("No password/private-key file was exported. Import and network behavior remain untested.")

    def status(self):
        state = self.current_state()
        print("CA state:", state.name)
        print("Next reserved certificate serial:", (self.root / "ca/next-serial").read_text().strip())
        print("Next reserved CRL number:", (self.root / "ca/next-crlnumber").read_text().strip())
        print(self.run(["x509", "-in", self.root / "ca/ca.cert.pem", "-noout", "-subject", "-enddate", "-fingerprint", "-sha256"]))
        print(self.run(["crl", "-in", state / "crl.pem", "-noout", "-lastupdate", "-nextupdate", "-crlnumber"]))
        for path in sorted((self.root / "clients").glob("*/metadata.json")):
            self.check_private(path)
            record = json.loads(path.read_text())
            print(f"Device {path.parent.name}: {record['identity']}, serial={record['serial_hex']}, revoked={record['revoked']}")
        incomplete = sum(not (path / "commit.json").exists() for path in (self.root / ".transactions").glob("tx-*"))
        if incomplete:
            print(f"Uncommitted private staging directories: {incomplete}. Never export these; counters already skip reserved numbers.")
        print("Status of PKI files only; not a VPN/client/network acceptance result.")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    result.add_argument("--openssl", type=Path, default=DEFAULT_OPENSSL)
    result.add_argument("--allow-unprivileged-test", action="store_true")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create only the root CA and initial CRL; never replace an existing CA")
    server = commands.add_parser("issue-server")
    server.add_argument("--server-id", type=dns_name, default=SERVER_ID)
    device = commands.add_parser("issue-device")
    device.add_argument("name", type=device_name)
    device.add_argument("--device-id", type=dns_name)
    commands.add_parser("renew-crl")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("name", type=device_name)
    revoke.add_argument("--reason", choices=REASONS, default="unspecified")
    commands.add_parser("sync-public", help="republish current public CA/CRL to swanctl without exposing CA private key")
    commands.add_parser("status")
    profile = commands.add_parser("make-profile")
    profile.add_argument("name", type=device_name)
    profile.add_argument("--server-address", default="203.0.113.8", help="temporary observed endpoint; replace if it changes")
    profile.add_argument("--remote-id", type=dns_name, default=SERVER_ID)
    profile.add_argument("--dns", action="append", help="repeat to override default ISP DNS servers")
    profile.add_argument("--profile-builder", type=Path, default=Path(__file__).with_name("profile_builder.py"))
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    pki = Provisioner(args.root, args.openssl, args.allow_unprivileged_test)
    with pki.lock():
        if args.command == "init":
            pki.init_ca()
        elif args.command == "issue-server":
            pki.issue("server", identity=args.server_id)
        elif args.command == "issue-device":
            pki.issue("client", name=args.name, identity=args.device_id)
        elif args.command == "renew-crl":
            pki.renew_crl()
        elif args.command == "revoke":
            pki.renew_crl(args.name, args.reason)
        elif args.command == "sync-public":
            pki.sync_public()
        elif args.command == "make-profile":
            pki.make_profile(args.name, args.server_address, args.remote_id,
                             args.dns or ["202.188.18.188", "1.9.1.9"], args.profile_builder)
        elif args.command == "status":
            pki.status()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
