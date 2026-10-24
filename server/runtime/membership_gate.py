"""Fixed read-only membership admission before a native Owner or CRL writer."""
from pathlib import Path
import native_support as support
from pki_io import IO
import membership_admission

ROOT=Path('/usr/local/etc/family-vpn')

def check():
    support.require_local_modules(('membership_gate','membership_admission','pki_io','snapshot_io'))
    support.trusted(ROOT,0o700)
    return membership_admission.admission(IO(ROOT,0))
