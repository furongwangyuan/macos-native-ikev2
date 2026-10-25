"""No-native-effects regression tests for host firewall coexistence."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]/'server/runtime'
sys.path.insert(0,str(ROOT))
import alf_transaction as a
import native_runtime as runtime
import fleet_native

SSH='/usr/libexec/sshd-keygen-wrapper'
SCREEN='/System/Library/CoreServices/RemoteManagement/ARDAgent.app'
OTHER='/Applications/Example.app/Contents/MacOS/Example'

def base(blockall=True):
    return dict(global_state=2 if blockall else 1,blockall=blockall,
                stealth='Firewall stealth mode is on',builtin=True,downloaded=True,
                apps={a.CHARON:False,SSH:True,OTHER:False})

class Fixture:
    def __init__(self,blockall=True,version=3,mode='off'):
        self.current=base(blockall)
        if mode!='off':self.current['apps'][a.PROBE]=False
        before=copy.deepcopy(self.current)
        rec=a.new(before,mode)
        if version==2:
            rec['version']=2;rec['changes']=a.plan(before,mode,version=2)
        self.session=dict(version=8,profile=a.PROFILE,allow_data=True,active=True,
                          probe_mode=mode,alf_before=before,alf_transaction=rec)
        self.saved=[];self.commands=[];self.after_command=None
        self.tx=a.Transaction(self.session,SimpleNamespace(save=lambda value:self.saved.append(copy.deepcopy(value))),
                              observe=lambda:copy.deepcopy(self.current),
                              firewall=lambda:(self.current['global_state'],self.current['blockall']),run=self.run)
    def run(self,argv,timeout):
        a.authorize(self.session,argv)
        self.commands.append(argv)
        if argv[1]=='--setblockall':
            self.current['blockall']=argv[2]=='on';self.current['global_state']=2 if self.current['blockall'] else 1
        elif argv[1] in ('--blockapp','--unblockapp'):
            self.current['apps'][argv[2]]=argv[1]=='--unblockapp'
        else:
            self.current[{'--setallowsigned':'builtin','--setallowsignedapp':'downloaded'}[argv[1]]]=argv[2]=='on'
        if self.after_command:self.after_command()
    def open(self):self.tx.prepare();self.tx.open();return self
    def external(self):
        self.current['apps'][SCREEN]=True
        self.current['apps'].pop(OTHER,None)
        self.current['apps'][SSH]=False
        self.current['builtin']=False;self.current['downloaded']=False
        self.current['stealth']='Firewall stealth mode is off'

class Tests(unittest.TestCase):
    def test_new_plan_only_owns_vpn(self):
        f=Fixture();self.assertEqual(f.tx.record['version'],3)
        self.assertEqual([r['key'] for r in f.tx.record['changes']],[a.CHARON])
        f.open();self.assertTrue(f.current['apps'][SSH]);self.assertTrue(f.current['builtin'])
        self.assertFalse(any(c[1] in a.FLAGS.values() or c[-1]==SSH for c in f.commands))

    def test_active_unrelated_changes_do_not_stop(self):
        f=Fixture().open();f.external()
        self.assertTrue(a.active_matches(f.tx.record,f.current))
        f.tx.close();f.tx.restore()
        self.assertTrue(a.restored_matches(f.tx.record,f.current))
        self.assertTrue(f.current['apps'][SCREEN]);self.assertNotIn(OTHER,f.current['apps'])
        self.assertFalse(f.current['apps'][SSH]);self.assertFalse(f.current['builtin'])
        self.assertFalse(f.current['apps'][a.CHARON]);self.assertEqual(f.tx.record['phase'],'restored')
        f.tx.close();f.tx.restore() # Idempotent even with unrelated additions.

    def test_prepare_and_open_allow_concurrent_unrelated_edits(self):
        f=Fixture();f.after_command=f.external
        f.open();self.assertTrue(a.active_matches(f.tx.record,f.current))
        f.tx.close();f.tx.restore();self.assertTrue(a.restored_matches(f.tx.record,f.current))

    def test_normal_enabled_baseline_never_blocks_host_services(self):
        f=Fixture(False).open()
        self.assertTrue(f.current['apps'][SSH]);self.assertEqual(f.current['global_state'],1)
        f.external();f.tx.close();f.tx.restore()
        self.assertFalse(any(c[1]=='--setblockall' for c in f.commands))
        self.assertEqual(f.current['global_state'],1);self.assertFalse(f.current['blockall'])

    def test_unowned_global_changes_are_preserved_on_close(self):
        for state,blockall in ((0,False),(2,True)):
            f=Fixture(False).open()
            f.current.update(global_state=state,blockall=blockall)
            f.tx.close();f.tx.restore()
            self.assertEqual((f.current['global_state'],f.current['blockall']),(state,blockall))
            self.assertFalse(any(c[1]=='--setblockall' for c in f.commands))
            self.assertTrue(a.restored_matches(f.tx.record,f.current))

    def test_closed_preflight_accepts_existing_normal_firewall(self):
        runtime.alf_gate(base(False),False)
        bad=base(False);bad['apps'][a.CHARON]=True
        with self.assertRaises(a.InvalidALF):runtime.alf_gate(bad,False)

    def test_prepared_check_respects_original_global_mode(self):
        for blockall in (True,False):
            f=Fixture(blockall);f.tx.prepare()
            self.assertTrue(a.active_matches(f.tx.record,f.current))
            f.tx.open();self.assertTrue(a.active_matches(f.tx.record,f.current))

    def test_charon_block_or_removal_is_not_masked(self):
        for remove in (False,True):
            f=Fixture().open()
            if remove:f.current['apps'].pop(a.CHARON)
            else:f.current['apps'][a.CHARON]=False
            self.assertFalse(a.active_matches(f.tx.record,f.current))
            if remove:
                f.tx.close()
                with self.assertRaises(a.InvalidALF):f.tx.restore()
                self.assertNotIn(a.CHARON,f.current['apps'])

    def test_real_native_check_allows_only_unrelated_drift(self):
        f=Fixture().open();f.external();blob=b'public-crl'
        owner=SimpleNamespace(same_boot=lambda:None,daemon=None,owned_process=lambda:{'path':str(runtime.s.CHARON)},
            alf_transaction=f.tx,session={'crl':{'next':float('inf'),'sha256':runtime.s.digest(blob)}},
            gate=SimpleNamespace(state={'mode':'closed'},closed=lambda:True),data_mode=True,
            check_uplink=lambda local:None,probe=SimpleNamespace(check=lambda:None))
        with patch.object(runtime.alf,'snapshot',lambda:copy.deepcopy(f.current)),\
             patch.object(runtime.network,'uplink',lambda **kwargs:{}),patch.object(runtime.s,'read',lambda *args,**kwargs:blob):
            runtime.Owner.check_local(owner,5)
            f.current['apps'][a.CHARON]=False
            with self.assertRaisesRegex(runtime.ctl.Fault,'alf_vpn_rule_changed'):runtime.Owner.check_local(owner,5)

    def test_roaming_readback_allows_only_unrelated_drift(self):
        f=Fixture().open();f.external();blob=b'public-crl'
        owner=SimpleNamespace(known_child_alive=lambda:None,fingerprint='same',
            fleet_adapter=SimpleNamespace(_context=lambda:{'context':'same'}),alf_transaction=f.tx,
            session={'crl':{'next':float('inf'),'sha256':runtime.s.digest(blob)}},
            gate=SimpleNamespace(state={'mode':'closed'},closed=lambda:True),probe=SimpleNamespace(check=lambda:None))
        with patch.object(runtime.alf,'snapshot',lambda:copy.deepcopy(f.current)),\
             patch.object(fleet_native.service,'read_configuration',lambda:SimpleNamespace(fingerprint='same')),\
             patch.object(runtime.s,'read',lambda *args,**kwargs:blob):
            self.assertEqual(fleet_native.FleetOwner.uplink_protection_readback(owner),{'context':'same'})
            f.current['apps'].pop(a.CHARON)
            with self.assertRaisesRegex(runtime.ctl.Fault,'alf_vpn_rule_changed'):
                fleet_native.FleetOwner.uplink_protection_readback(owner)

    def test_v2_is_validated_and_unrelated_addition_restores(self):
        f=Fixture(version=2).open();f.current['apps'][SCREEN]=True
        self.assertFalse(f.current['apps'][SSH]) # Historical v2 plan only.
        self.assertTrue(a.active_matches(f.tx.record,f.current))
        f.tx.close();f.tx.restore()
        self.assertTrue(f.current['apps'][SSH]);self.assertTrue(f.current['apps'][SCREEN])
        self.assertEqual(f.tx.record['phase'],'restored')

    def test_legacy_plan_cannot_be_relabelled_to_gain_new_authority(self):
        f=Fixture(version=2);f.tx.record['version']=3
        with self.assertRaises(a.InvalidALF):a.validate_session(f.session)

    def test_probe_is_owned_only_when_requested(self):
        f=Fixture(mode='synthetic-local-v1').open();f.external()
        self.assertTrue(a.active_matches(f.tx.record,f.current))
        f.current['apps'][a.PROBE]=False
        self.assertFalse(a.active_matches(f.tx.record,f.current))
        f.tx.close();f.tx.restore();self.assertFalse(f.current['apps'][a.PROBE])

    def test_already_restored_owned_rule_not_reclaimed_after_external_edit(self):
        f=Fixture().open();f.tx.close();f.tx.restore()
        f.current['apps'][a.CHARON]=True
        with self.assertRaisesRegex(a.InvalidALF,'restored_alf_changed'):f.tx.restore()
        self.assertTrue(f.current['apps'][a.CHARON])

if __name__=='__main__':unittest.main(verbosity=2)
