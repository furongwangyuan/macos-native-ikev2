"""New-boot regression tests: all native effects are simulated, no root I/O."""
import base64, copy, json, os, sys, unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
RUNTIME = Path(__file__).resolve().parents[2] / 'server/runtime'
sys.path.insert(0, str(RUNTIME))
import alf_transaction as alf
import boot_record as r
import boot_reconcile as boot
import native_gate as pf
import native_support as s
import fleet_session
import production_source as production
import service_supervisor


def fixture():
    before = dict(global_state=2, blockall=True, stealth='Firewall stealth mode is on',
                  apps={alf.CHARON:False, '/usr/libexec/sshd-keygen-wrapper':True},
                  builtin=True, downloaded=True)
    # This is a real v2 legacy shape, including the former unrelated-app plan.
    rows = [dict(kind='flag',key=k,before=True,after=False,phase='restored') for k in alf.FLAGS]
    rows += [dict(kind='app',key='/usr/libexec/sshd-keygen-wrapper',before=True,after=False,phase='restored'),
             dict(kind='app',key=alf.CHARON,before=False,after=True,phase='restored')]
    tx = dict(version=2,probe_mode='off',phase='closed',before=copy.deepcopy(before),changes=rows,intent=None)
    original = ('scrub-anchor "com.apple/*"\nnat-anchor "com.apple/*"\nrdr-anchor "com.apple/*"\n'
                'dummynet-anchor "com.apple/*"\nanchor "com.apple/*"\n'
                'load anchor "com.apple" from "/etc/pf.anchors/com.apple"\n').encode()
    registry = dict(version=1,revision=1,usage_timezone='Asia/Kuala_Lumpur',devices=[dict(
        device_id='device01', display_name='Test', ike_identity='device01.family.home.arpa',
        state='enabled', vip4='10.77.26.10', vip6='fd6d:fe83:ab27:2600::10')])
    config = r.encode(dict(version=1,allow_data=True))
    supervisor = r.encode(dict(version=1,enabled=True))
    fp = r.sha(supervisor+b'\0'+config)
    identity = dict(pid=12345,pgid=12345,uid=0,started_sec=10,started_usec=0,path='/usr/bin/python3')
    start = dict(version=1,profile=production.KIND,run='a'*32,boot='old-boot',configuration_sha256=fp,
                 code_sha256='b'*64,kernel_release=os.uname().release,machine=os.uname().machine,owner=identity)
    start_raw=r.encode(start)
    old=dict(version=8,profile='production-native-fleet-v1',active=True,allow_data=True,
        phase='ATTENTION',boot='old-boot',started=10,probe_mode='off',test_action='service',
        cleanup_codes=['alf_baseline_not_restored','native_daemon_or_sad'],recovery_result='protected-needs-attention',
        baseline={**{k:0 for k in s.SYS},s.ESP:0},knobs={},alf_before=before,alf_transaction=tx,
        # Synthetic globally classified probe addresses exercise validation only.
        # This runner prohibits all network calls; these are not deployment data.
        health=dict(inet_gateway='192.0.2.1',inet6_gateway='fe80::1%en0',lan4='192.0.2.8',
                    stable6='2606:4700:1:1::8',public4='1.1.1.2',public6_probe='2606:4700:1:1::9'),
        crl=dict(number=1,sha256='b'*64,der_sha256='c'*64,authority_sha256='d'*64,next=12345.),
        files={k:dict(phase='owned',created=True,sha256=r.sha(k.encode())) for k in r.FILE_KEYS},
        child=dict(phase='exited',identity=identity),floors=[],keepers=[],
        fleet=fleet_session.static(r.encode(registry)),fleet_active=[],
        production_run=dict(version=1,run_id=start['run'],intent_sha256=r.sha(start_raw)),
        pf=dict(before=base64.b64encode(original).decode(),before_sha=r.sha(original),after_sha=r.sha(pf.prepared_main(original)),
                mode=0o644,phase='applied',guard=dict(filters=pf.GUARD.strip().splitlines(),nat=[]),
                root_before=dict(filters=['scrub-anchor "com.apple/*" all fragment reassemble','anchor "com.apple/*" all'],
                                 nat=['nat-anchor "com.apple/*" all','rdr-anchor "com.apple/*" all']),
                auxiliary_before=dict(dummynet=['dummynet-anchor "com.apple/*" all'],
                    apple_filters=['anchor "200.AirDrop/*" all','anchor "250.ApplicationFirewall/*" all'],apple_nat=[]),
                apple_source_sha='e'*64,enabled_before=True,references_before='previous-boot-reference'))
    state=dict(version=1,phase='ATTENTION',boot='old-boot',fingerprint=fp,attempts=[10.],next_due=0,
               reason='recovery_not_proven',updated=12.)
    files={'intent':start_raw,'service-state':r.encode(state),'native-config':config,'supervisor-config':supervisor}
    context=r.encode(dict(version=1,kind=production.KIND,files={k:base64.b64encode(v).decode() for k,v in files.items()}))
    return old,context,fp


class Store:
    def __init__(self,io):self.io=io;self.record=None;self.saved_originals=None
    def preserve(self,*raw):self.saved_originals=raw
    def load(self):return copy.deepcopy(self.record)
    def save(self,record):r.validate(record);self.record=copy.deepcopy(record)
    def originals(self,record):return self.saved_originals


class Fake:
    def __init__(self,old,context,fp):
        self.raw=(r.encode(old),context);self.fp=fp;self.effects=[];self.kernel_ok=True
        self.a=copy.deepcopy(old['alf_before'])
        self.a['apps']['/Applications/Tailscale.app']=True
        self.a.update(global_state=1,blockall=False)
        self.p=dict(sha256=old['pf']['after_sha'],root='owned',anchor=copy.deepcopy(old['pf']['guard']))
        self.f={k:v['sha256'] for k,v in old['files'].items()}
    def held(self):pass
    def originals(self):return self.raw
    def boot(self):return 'new-boot'
    def configuration(self):return self.fp
    def implementation(self):return 'f'*64
    def context_admission(self,raw):pass
    def closed_kernel(self):
        if not self.kernel_ok:raise r.Refused('live_current_kernel_not_empty')
    def alf(self):return copy.deepcopy(self.a)
    def pf(self,old):return copy.deepcopy(self.p)
    def file(self,key):return self.f.get(key)
    def settle(self,record):pass
    def apply(self,record,effect,old):
        self.closed_kernel();self.effects.append(copy.deepcopy(effect))
        if effect['kind']=='replace-pf':self.p['sha256']=effect['sha256']
        elif effect['kind']=='delete-created':self.f[effect['file']]=None
        elif effect['argv'][0]==alf.ALF:
            argv=effect['argv']
            if argv[1]=='--setblockall':raise AssertionError('must not disable remote access')
            if argv[1] in alf.FLAGS.values():self.a[next(k for k,v in alf.FLAGS.items() if v==argv[1])]=argv[2]=='on'
            else:self.a['apps'][argv[2]]=argv[1]=='--unblockapp'
        elif effect['argv'][1]=='-f':self.p['root']='baseline'
        else:self.p['anchor']=dict(filters=[],nat=[])


class Tests(unittest.TestCase):
    def test_attention_from_previous_boot_recovers_without_replaying_old_ids(self):
        old,context,fp=fixture();io=Fake(old,context,fp);store=Store(io);original=io.raw
        with patch.object(s,'process',side_effect=AssertionError('old PID must not be queried')):
            boot.admit(io,store);self.assertTrue(boot.restore_locked(io,store))
        self.assertEqual(store.load()['phase'],'RESTORED');self.assertEqual(store.saved_originals,original)
        self.assertEqual(io.raw,original);self.assertEqual(io.a['global_state'],1)
        self.assertTrue(io.a['apps']['/Applications/Tailscale.app'])
        self.assertTrue(io.a['apps']['/usr/libexec/sshd-keygen-wrapper'])
        self.assertFalse(any(x.get('argv',[None])[0]==alf.ALF for x in io.effects))
        self.assertNotIn('setkey',json.dumps(io.effects));self.assertNotIn('12345',json.dumps(io.effects))

    def test_current_kernel_must_be_closed_before_any_effect_or_record(self):
        old,context,fp=fixture();io=Fake(old,context,fp);store=Store(io);io.kernel_ok=False
        with self.assertRaisesRegex(r.Refused,'live_current_kernel_not_empty'):boot.admit(io,store)
        self.assertEqual(io.effects,[]);self.assertIsNone(store.record);self.assertEqual(store.saved_originals,io.raw)

    def test_new_v3_transaction_preserves_already_normal_firewall_mode(self):
        old,context,fp=fixture();old['alf_before'].update(global_state=1,blockall=False)
        old['alf_transaction']=alf.new(old['alf_before'])
        self.assertEqual(old['alf_transaction']['version'],3)
        old['alf_transaction']['phase']='closed'
        for row in old['alf_transaction']['changes']:row['phase']='applied'
        io=Fake(old,context,fp);io.a['apps'][alf.CHARON]=True;store=Store(io)
        boot.admit(io,store);boot.restore_locked(io,store)
        self.assertEqual(io.a['global_state'],1)
        self.assertTrue(io.a['apps']['/usr/libexec/sshd-keygen-wrapper'])
        self.assertTrue(io.a['apps']['/Applications/Tailscale.app'])
        self.assertFalse(io.a['apps'][alf.CHARON])

    def test_current_kernel_change_after_admission_prevents_mutations(self):
        old,context,fp=fixture();io=Fake(old,context,fp);store=Store(io)
        boot.admit(io,store);io.kernel_ok=False
        with self.assertRaisesRegex(r.Refused,'live_current_kernel_not_empty'):boot.restore_locked(io,store)
        self.assertEqual(io.effects,[])

    def test_released_rule_external_edit_is_preserved_during_resume(self):
        old,context,fp=fixture();old['alf_transaction']['changes'][-1]['phase']='applied'
        io=Fake(old,context,fp);io.a['apps'][alf.CHARON]=True;store=Store(io)
        record=boot.admit(io,store);boot.restore_alf(io,store,record)
        io.a['apps'][alf.CHARON]=True
        before=len(io.effects);boot.restore_locked(io,store)
        self.assertTrue(io.a['apps'][alf.CHARON])
        self.assertFalse(any(x.get('argv',[None])[0]==alf.ALF for x in io.effects[before:]))

    def test_restores_only_still_owned_legacy_rows_preserving_other_rules(self):
        old,context,fp=fixture();old['alf_transaction']['changes'][-1]['phase']='applied'
        io=Fake(old,context,fp);io.a['apps'][alf.CHARON]=True;store=Store(io)
        boot.admit(io,store);boot.restore_locked(io,store)
        self.assertFalse(io.a['apps'][alf.CHARON]);self.assertTrue(io.a['apps']['/Applications/Tailscale.app'])
        commands=[x['argv'] for x in io.effects if x.get('argv',[None])[0]==alf.ALF]
        self.assertEqual(commands,[[alf.ALF,'--blockapp',alf.CHARON]])

    def test_released_conflicting_or_removed_legacy_rules_are_not_reclaimed(self):
        for phase in ('pending','restored','conflict'):
            with self.subTest(phase=phase):
                old,context,fp=fixture();old['alf_transaction']['phase']='attention'
                old['alf_transaction']['changes'][-1]['phase']=phase
                io=Fake(old,context,fp);io.a['apps'].pop(alf.CHARON);store=Store(io)
                boot.admit(io,store);boot.restore_locked(io,store)
                self.assertNotIn(alf.CHARON,io.a['apps']);self.assertTrue(io.a['apps']['/Applications/Tailscale.app'])

    def test_same_boot_attention_is_not_reboot_authority(self):
        old,context,_=fixture()
        with self.assertRaisesRegex(r.Refused,'unsupported_old_boot_session'):r.sources(r.encode(old),context,old['boot'])

    def test_malformed_attention_is_not_treated_as_history(self):
        old,context,_=fixture();old['cleanup_codes']='not-a-list'
        with self.assertRaises(r.Refused):r.sources(r.encode(old),context,'new-boot')

    def test_current_code_upgrade_permitted_only_for_explicit_recovery(self):
        _,context,_=fixture()
        with patch.object(service_supervisor,'code_fingerprint',return_value='c'*64):
            with self.assertRaises(production.Refused):production.verify_current_resources(context)
            production.verify_current_resources(context,recovery=True)

    def test_foreign_machine_remains_rejected_in_recovery(self):
        _,context,_=fixture();value=json.loads(context);files=production.unpack(context)
        intent=json.loads(files['intent']);intent['machine']='other-cpu'
        value['files']['intent']=base64.b64encode(r.encode(intent)).decode()
        with patch.object(service_supervisor,'code_fingerprint',return_value='c'*64):
            with self.assertRaises(production.Refused):production.verify_current_resources(r.encode(value),recovery=True)


if __name__=='__main__':unittest.main(verbosity=2)
