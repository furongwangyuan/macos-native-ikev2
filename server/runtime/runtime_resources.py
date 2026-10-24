"""Fixed runtime file metadata and exact nested inventory; no I/O on import."""
import stat
from pathlib import PurePosixPath
import native_support as s

BINARY = 'crypto/public-crl-verify'
DIRECTORIES = frozenset(('crypto', 'vici'))

def name(value):
    if type(value) is not str or not value or any(c in value for c in ('\0', '\n', '\r', '\\')):
        raise s.Refused('runtime_resource_name')
    p = PurePosixPath(value)
    if (p.is_absolute() or str(p) != value or any(c in ('.', '..') for c in p.parts)
            or len(p.parts) > 2 or len(p.parts) == 2 and p.parts[0] not in DIRECTORIES):
        raise s.Refused('runtime_resource_path')
    return value

def metadata(value):
    name(value)
    return (0o755, 16 * 1024 * 1024) if value == BINARY else (0o600, 131072)

def read(value):
    mode, limit = metadata(value)
    return s.read(s.BASE / value, mode=mode, limit=limit)

def inventory(expected):
    """Validate an exact supplied fixed manifest, including private directories."""
    expected = frozenset(name(v) for v in expected)
    directories = {v.split('/')[0] for v in expected if '/' in v}
    s.trusted(s.BASE, 0o700)
    seen = set()
    for p in s.BASE.iterdir():
        info = p.lstat()
        if stat.S_ISDIR(info.st_mode):
            if p.name not in directories:
                raise s.Refused('runtime_extra_directory')
            s.trusted(p, 0o700)
            for child in p.iterdir():
                resource = p.name + '/' + child.name
                if resource not in expected or not stat.S_ISREG(child.lstat().st_mode):
                    raise s.Refused('runtime_nested_inventory')
                read(resource)
                seen.add(resource)
        else:
            if p.name not in expected or not stat.S_ISREG(info.st_mode):
                raise s.Refused('runtime_root_inventory')
            read(p.name)
            seen.add(p.name)
    if seen != expected:
        raise s.Refused('runtime_missing_resource')
    return seen
