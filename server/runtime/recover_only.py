#!/usr/bin/python3
"""Fixed recovery-only entry. Never starts charon or opens a data gate."""
import os
from pathlib import Path
import sys

BASE=Path('/usr/local/family-vpn/production-guardian')
if __name__=='__main__' and (os.geteuid()!=0 or Path(__file__)!=BASE/'recover_only.py'):
    raise SystemExit('Use only the reviewed fixed recovery installation.')
sys.path.insert(0,str(Path(__file__).parent))
import native_support as s
import native_runtime as runtime
import native_policy as policies


def new_boot_observation(previous,store):
    """Keep original bytes intact for the separately admitted finite boot path.

    Internal same-lock callers do not acquire a second writer. The loaded fixed
    main entry below handles cross-boot closing under its own actual lock lease.
    """
    s.say('recovery_new_boot',result='original_preserved_for_fixed_boot_reconciliation',
          old_ids_or_pids_used=False,data_enabled=False)
    return 2


def recover(store):
    runtime.require_closure()
    s.require_local_modules(('recover_only',))
    previous=store.load()
    if previous is None or not previous['active']:
        return 0 # Idle: no secret read, mutation, daemon launch or log noise.
    if previous['boot']!=s.boot():return new_boot_observation(previous,store)
    owner=runtime.Owner(previous,store)
    return 0 if owner.cleanup() else 2


def main():
    if len(sys.argv)!=1:raise s.Refused('recovery_takes_no_arguments')
    import boot_native as boot_io
    import boot_store
    import boot_reconcile
    import boot_handoff
    boot_io.Native.installed_scope();os.umask(0o077);io=boot_io.Native()
    try:
        with io.locked():
            boot_record=boot_store.Store(io).load()
            previous=s.Store().load()
            production_record=False
            if boot_record is not None:
                context=boot_store.Store(io).originals(boot_record)[1]
                production_record=s.json_value(context).get('kind')=='production-service-v1'
            if production_record or (previous is not None and 'production_run' in previous and previous['boot']!=s.boot()):
                import production_boot
                from continuous_clock import make_clock
                result=production_boot.recover_locked(io,make_clock())
                s.say('production_boot_recovery',**result);return 0
            if boot_record is not None:
                if boot_record['new_boot']!=s.boot():raise s.Refused('subsequent_boot_requires_separate_reconciliation')
                handoff=boot_handoff.Handoff(io,boot_store.Store(io)).load()
                if handoff is None or handoff['phase']!='COMPLETE':
                    result=boot_reconcile.recover_bounded_locked(io)
                    s.say('bounded_boot_recovery',**result);return 0
                # This first finite source is retired, not permission to accept
                # another owner. Revalidate completion without touching it.
                boot_handoff.completed_report_locked(io,boot_store.Store(io))
                return 0
            store=s.Store();previous=store.load()
            if previous is not None and previous['active'] and previous['boot']!=s.boot():
                result=boot_reconcile.recover_bounded_locked(io)
                s.say('bounded_boot_recovery',**result);return 0
            return recover(store)
    except BlockingIOError:
        return 0 # The actual same native/legacy locks remain owned elsewhere.


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:
        s.say('recover_only_refused',result='attention',data_enabled=False);sys.exit(2)
