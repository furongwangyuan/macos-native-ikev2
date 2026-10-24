"""Human-operated fixed DDNS helper installation; no scheduler or VPN changes."""
import fcntl
import hashlib
import contextlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

HELPER_SHA = '__HELPER_SHA__'
KNOWN_OLD_SHAS = (
    '01504e40dc01708991044c9df09d402d44544df5609302c6c34de5a64528e487',
    '9d4632bd5f289692239245267d8ad9d84aefe678565b0df0623364c9d4958b1d',
    '4ae66befaee76c5075b99ada76845c2ebf1d676c101ed7b7863f923cfc004d49',
    '0ea3462186e3466bdf3c59f92b58396280aac58d9eebcad0dc6998b1cca63d05',
)
LIMIT = 100000
BASE = Path('/usr/local/family-vpn/dynadot-ddns')
CONFIG_PARENT = Path('/usr/local/etc/family-vpn')
STATE_PARENT = Path('/private/var/db/family-vpn')
STATE = STATE_PARENT / 'dynadot-ddns'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}


def trusted(path, *, private=False, regular=False):
    for item in [path, *path.parents]:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('untrusted_installation_path')
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise RuntimeError('invalid_installation_ancestor')
        p = subprocess.run(['/bin/ls', '-lde', str(item)], capture_output=True,
                           timeout=3, env=ENV)
        if p.returncode or len(p.stdout.splitlines()) != 1:
            raise RuntimeError('extended_acl_requires_review')
    info = path.lstat()
    if not (stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)):
        raise RuntimeError('invalid_installation_type')
    if regular and info.st_nlink != 1:
        raise RuntimeError('multiply_linked_installation_file')
    if private and stat.S_IMODE(info.st_mode) != (0o600 if regular else 0o700):
        raise RuntimeError('private_installation_mode_required')


def signature(info):
    return tuple(getattr(info, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def exists(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def read_file(path, *, private=False):
    """Bounded pinned resource read; never follow a leaf link or open a FIFO."""
    if private:
        trusted(path, private=True, regular=True)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > LIMIT:
        raise RuntimeError('unsafe_or_oversize_resource')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if signature(opened) != signature(before):
            raise RuntimeError('resource_changed_before_read')
        raw = handle.read(LIMIT + 1)
        if (len(raw) > LIMIT or len(raw) != opened.st_size
                or signature(os.fstat(handle.fileno())) != signature(opened)
                or signature(path.lstat()) != signature(opened)):
            raise RuntimeError('resource_changed_during_read')
    return raw, signature(opened)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def directory(path):
    trusted(path.parent, private=path.parent == STATE_PARENT)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    else:
        sync_directory(path.parent)
    trusted(path, private=True)


@contextlib.contextmanager
def locked(path):
    # O_NONBLOCK prevents a replaced FIFO/device from hanging before fstat.
    if exists(path):
        trusted(path, private=True, regular=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        trusted(path, private=True, regular=True)
        opened = os.fstat(fd)
        if signature(opened) != signature(path.lstat()):
            raise RuntimeError('installation_lock_changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sync_directory(path.parent)
        yield
    finally:
        os.close(fd)


def atomic_file(path, content, *, replacing=None, previous_sha=None):
    """No-clobber creation, or replacement of exactly the checked old inode."""
    trusted(path.parent, private=True)
    temp = path.parent / ('.install-' + str(os.getpid()) + '-' + secrets.token_hex(8))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if replacing is None:
            # Atomic create-only: never replace an unexpected existing path.
            os.link(temp, path, follow_symlinks=False)
            temp.unlink()
        else:
            current, identity = read_file(path, private=True)
            if (previous_sha not in KNOWN_OLD_SHAS or identity != replacing
                    or hashlib.sha256(current).hexdigest() != previous_sha):
                raise RuntimeError('existing_helper_changed_during_upgrade')
            os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        if exists(temp):
            temp.unlink()
            sync_directory(path.parent)


def install(content):
    # Caller holds both locks. Backup is source code only; no credentials read.
    if len(content) > LIMIT or hashlib.sha256(content).hexdigest() != HELPER_SHA:
        raise RuntimeError('helper_changed_after_review')
    target = BASE / 'update.py'
    backups = {}
    for old_sha in KNOWN_OLD_SHAS:
        backup = BASE / ('update.py.backup-' + old_sha)
        if exists(backup):
            previous, _ = read_file(backup, private=True)
            if hashlib.sha256(previous).hexdigest() != old_sha:
                raise RuntimeError('unknown_backup_preserved_for_review')
            backups[old_sha] = backup
    if not exists(target):
        if backups:
            raise RuntimeError('missing_helper_with_existing_backup_requires_review')
        atomic_file(target, content)
        result = 'installed'
    else:
        previous, identity = read_file(target, private=True)
        current_sha = hashlib.sha256(previous).hexdigest()
        if current_sha == HELPER_SHA:
            result = 'already_current'
        elif current_sha in KNOWN_OLD_SHAS:
            backup = BASE / ('update.py.backup-' + current_sha)
            if current_sha not in backups:
                atomic_file(backup, previous)
            saved, _ = read_file(backup, private=True)
            if hashlib.sha256(saved).hexdigest() != current_sha:
                raise RuntimeError('old_helper_backup_not_verified')
            atomic_file(target, content, replacing=identity, previous_sha=current_sha)
            result = 'known_version_upgraded'
        else:
            raise RuntimeError('existing_helper_differs_preserved_for_review')
    actual, _ = read_file(target, private=True)
    if hashlib.sha256(actual).hexdigest() != HELPER_SHA:
        raise RuntimeError('installed_helper_verification_failed')
    return result


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise RuntimeError('human_root_launcher_required')
    content, _ = read_file(Path(sys.argv[1]) / 'update.py')
    if hashlib.sha256(content).hexdigest() != HELPER_SHA:
        raise RuntimeError('helper_changed_after_review')
    compile(content, 'update.py', 'exec')
    trusted(BASE.parent)
    trusted(CONFIG_PARENT, private=True)
    trusted(STATE_PARENT, private=True)
    os.umask(0o077)
    directory(BASE)
    with locked(BASE / '.installer.lock'):
        directory(STATE)
        with locked(STATE / 'lock'):
            result = install(content)
    print('DDNS helper installation result: ' + result, flush=True)
    print('Reading setup credential from the private input pipe; no terminal input is requested here.', flush=True)
    print('One fixed vpn.example.com A update will be checked. No timer or VPN service will start.', flush=True)
    os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', str(BASE / 'update.py'), 'configure-once'], ENV)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print('DDNS installer stopped: reviewed files or protected paths require checking.', flush=True)
        sys.exit(1)
