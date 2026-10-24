"""Concrete integration seam; no import-time native reads and no CLI.

Installing caller passes its verified same-directory native modules. This
component does not stop an active service, migrate its journal or open traffic.
Native/legacy locks stay held for signing and all publication/recovery steps.
"""
import contextlib, os, subprocess
from pathlib import Path
from pki_io import IO,Refused,encode,decode,sha
from renewal import Renewal,ROOT,ENV

def legacy_writers_absent():
    # These historical candidates do not obey the new native writer lock.
    # Never unload an unknown job here. Installation must retire it explicitly.
    for label in ('org.familyvpn.crl-refresh','org.familyvpn.server'):
        plist=Path('/Library/LaunchDaemons')/(label+'.plist')
        try:plist.lstat()
        except FileNotFoundError:pass
        else:raise Refused('legacy_writer_plist_present')
        result=subprocess.run(['/bin/launchctl','print','system/'+label],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,close_fds=True,timeout=3)
        expected=('Bad request.\nCould not find service "'+label+'" in domain for system\n').encode()
        if result.returncode!=113 or result.stdout or result.stderr!=expected:raise Refused('legacy_writer_absence_unverified')

def closed_readback(s,restoration,saved,prior):
    legacy_writers_absent()
    if sha(encode(s.Store().load()))!=prior:raise Refused('native_owner_changed')
    native=decode(s.read(s.CONF/'config.json'));service=decode(s.read(s.CONF/'supervisor-config.json'))
    if native!={'version':1,'allow_data':False} or service!={'version':1,'enabled':False}:
        raise Refused('maintenance_requires_disabled_service')
    if native.get('allow_data')is not False or service.get('enabled')is not False or type(native.get('version'))is not int or type(service.get('version'))is not int:raise Refused('configuration_type')
    if restoration.verify(s.Store(),saved) is not True:raise Refused('actual_closed_readback_failed')
    values=s.values()
    if any(values[key]!=0 for key in ('net.inet.ip.forwarding','net.inet6.ip6.forwarding')):
        raise Refused('forwarding_not_closed')

@contextlib.contextmanager
def stopped_native(s,runtime,restoration):
    if os.geteuid()!=0:raise Refused('native_maintenance_requires_root')
    runtime.require_closure()
    for part in (ROOT,*ROOT.parents):
        st=part.lstat()
        import stat
        if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise Refused('untrusted_native_root')
    with s.locks():
        saved=s.Store().load()
        if saved is None:raise Refused('actual_restored_owner_required')
        prior=sha(encode(saved))
        def closed():
            return closed_readback(s,restoration,saved,prior)
        closed()
        yield Renewal(IO(ROOT,0),closed)
        closed()

def renew(s,runtime,restoration):
    with stopped_native(s,runtime,restoration) as worker:return worker.renew_locked()
def recover(s,runtime,restoration):
    with stopped_native(s,runtime,restoration) as worker:return worker.recover_locked()

if __name__=='__main__':raise SystemExit('Component only: fixed same-closure installer/Owner integration required.')
