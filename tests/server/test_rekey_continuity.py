"""Only synthetic metadata. Real native effects denied by the shared fixture."""
import copy
import unittest
import json,time
from pathlib import Path
from unittest.mock import patch
import test_selector_readiness as h
from outer_fixture import inner, child
import fleet_policy as p
import fleet_coordinator as fc
import fleet_vici as v
import vici_fixture


def json_event(value):
    """Decode only this local synthetic JSON fixture into VICI metadata types."""
    if type(value) is dict:return {k:json_event(v) for k,v in value.items()}
    if type(value) is list:return [json_event(v) for v in value]
    if type(value) is str:return value.encode('ascii')
    raise AssertionError('unexpected synthetic fixture value')


def replaced(events, overlap=True, index=0, new_id=3):
    result=copy.deepcopy(events)
    old=child(result[index]);new=copy.deepcopy(old)
    new.update(uniqueid=str(new_id).encode(),state=b'INSTALLED',**{
        'spi-in':format(0x12340000+new_id,'08x').encode(),
        'spi-out':format(0x23450000+new_id,'08x').encode()})
    children=inner(result[index])['child-sas']
    if overlap:old['state']=b'DELETED'
    else:children.clear()
    children['internet-'+str(new_id)]=new
    return result


class RekeyContinuity(unittest.TestCase):
    def tearDown(self):h.h.s.MUTATOR=None;h.h.s.DEADLINE=None;h.h.runtime.STOP.clear()

    def start(self,e):
        self.assertEqual(e.c.step().active,('device01','device02'))
        e.k.trace.clear();e.owner.store.saved.clear()
        return copy.deepcopy(e.events)

    def no_close(self,e):
        self.assertEqual(e.c.last_result.active,('device01','device02'))
        self.assertIsNone(e.c.failure)
        self.assertFalse(any('-k' in cmd for cmd in e.k.trace))
        for saved in e.owner.store.saved:
            self.assertEqual({d['device_id'] for d in saved['fleet_active']},{'device01','device02'})
        self.assertEqual(e.a.gate.current()[0].generation.child_id,3)
        self.assertEqual(e.owner.store.durable['fleet_active'][0]['generation']['child_id'],3)

    def test_unique_and_observed_deleted_installed_keep_same_permission(self):
        for overlap in (False,True):
            with self.subTest(overlap=overlap),h.environment() as e:
                old=self.start(e);e.events=replaced(old,overlap)
                self.assertEqual(e.c.step().active,('device01','device02'));self.no_close(e)
                if overlap:
                    self.assertEqual(v.parse_events(e.events,e.reg,h.OUTER).snapshots['device01'].kind,'overlap')
                    e.events=replaced(old,False);e.c.step();self.no_close(e)
                    self.assertFalse(e.c.continuities)

    def test_first_and_second_frame_crossing_gets_one_extra_complete_read(self):
        with h.environment() as e:
            old=self.start(e);new=replaced(old);e.events=new
            e.sequence=[old,new,new,new];before=e.reads
            e.c.step();self.no_close(e);self.assertEqual(e.reads-before,4)

    def test_overlap_to_unique_between_reads_is_same_checked_new_proof(self):
        with h.environment() as e:
            old=self.start(e);over=replaced(old);unique=replaced(old,False);e.events=unique
            e.sequence=[over,unique,unique]
            e.c.step();self.no_close(e)

    def test_cold_overlap_does_not_admit(self):
        with h.environment() as e:
            e.events=replaced(e.events)
            self.assertEqual(e.c.step().active,('device02',))

    def test_bad_scope_in_either_brother_closes_a_keeps_b(self):
        for which in (0,1):
            with self.subTest(which=which),h.environment() as e:
                old=self.start(e);e.events=replaced(old)
                list(inner(e.events[0])['child-sas'].values())[which]['local-ts']=[]
                self.assertEqual(e.c.step().active,('device02',))
                self.assertTrue(any('-k' in cmd for cmd in e.k.trace))

    def test_other_bad_brother_is_not_hidden(self):
        for which in (0,1):
            with self.subTest(which=which),h.environment() as e:
                old=self.start(e);e.events=replaced(old)
                c=list(inner(e.events[0])['child-sas'].values())[which]
                c['local-ts']=[];c['remote-ts']=[b'0.0.0.0/0',b'::/0']
                self.assertEqual(e.c.step().state,'STOPPED')
                self.assertIsNotNone(e.c.failure)

    def test_partial_third_child_or_other_old_state_never_continues(self):
        for state in ('REKEYING','REKEYED','DELETING','CREATED'):
            with self.subTest(state=state),h.environment() as e:
                old=self.start(e);e.events=replaced(old);c=child(e.events[0]);c['state']=state.encode()
                if state=='CREATED':
                    for k in list(c):
                        if k not in v.CHILD_BASE:del c[k]
                self.assertEqual(e.c.step().active,('device02',))

    def test_long_deleted_residue_requires_complete_fresh_proofs_each_tick(self):
        with h.environment() as e,patch.object(time,'monotonic',return_value=100) as clock:
            old=self.start(e);e.events=replaced(old);e.c.step();self.no_close(e)
            relation=e.c.continuities['device01']
            self.assertEqual(len(relation),2)
            for moment in (116,10000,1000000):
                clock.return_value=moment;before=e.reads;e.c.step();self.no_close(e)
                self.assertEqual(e.reads-before,3)
                self.assertEqual(e.c.continuities['device01'],relation)
            e.events=replaced(old,False);e.c.step();self.no_close(e)
            self.assertFalse(e.c.continuities)

    def test_spd_id_or_activity_change_does_not_use_continuation(self):
        for kind in ('id','inactive'):
            with self.subTest(kind=kind),h.environment() as e:
                old=self.start(e);e.events=replaced(old);row=e.records[3]
                if kind=='id':e.active[99]=e.active.pop(row['id']);row['id']=99
                else:e.active[row['id']]=False
                e.c.step();self.assertEqual(e.c.last_result.active,('device02',))
                self.assertTrue(any('-k' in cmd for cmd in e.k.trace))

    def test_route_missing_after_valid_overlap_closes(self):
        with h.environment() as e:
            old=self.start(e);e.events=replaced(old);original=e.a.route
            with patch.object(e.a,'route',side_effect=lambda d:None if d.device_id=='device01' else original(d)):
                e.c.step()
            self.assertEqual(e.c.last_result.active,('device02',))

    def test_missing_postcheck_does_not_keep_authority(self):
        with h.environment() as e:
            old=self.start(e);new=replaced(old);bad=copy.deepcopy(new);child(bad[0])['local-ts']=[]
            e.events=bad;e.sequence=[new,new,bad]
            e.c.step();self.assertEqual(e.c.last_result.active,('device02',))

    def test_endpoint_ike_reqid_or_third_sibling_do_not_make_pair(self):
        for change in ('endpoint','ike','reqid','third'):
            with self.subTest(change=change),h.environment() as e:
                old=self.start(e);e.events=replaced(old);fields=inner(e.events[0]);children=fields['child-sas']
                if change=='endpoint':fields['remote-port']=b'45001'
                elif change=='ike':fields['uniqueid']=b'50'
                elif change=='reqid':children['internet-3']['reqid']=b'50'
                else:
                    c=copy.deepcopy(children['internet-3']);c.update(uniqueid=b'4',**{'spi-in':b'12340004','spi-out':b'23450004'});children['internet-4']=c
                e.c.step();self.assertNotIn('device01',e.c.last_result.active)
                self.assertTrue(any('-k' in cmd for cmd in e.k.trace) or e.c.last_result.state=='STOPPED')

    def test_synthetic_observed_shapes_keep_all_brothers_and_existing_scope(self):
        source=Path(__file__).resolve().parent/'fixtures/rekey_deleted_installed.json'
        fixture=json.loads(source.read_text());self.assertEqual(fixture['version'],1)
        reg=copy.deepcopy(vici_fixture.REG);reg['devices']=reg['devices'][:1]
        current=None;observed=set()
        for index in fixture['sequence']:
            raw=fixture['events'][index]
            event=json_event(raw)
            parsed=v.parse_events([event],reg,h.OUTER);snap=parsed.snapshots['device01']
            g=snap.rekey_pair[1] if snap.rekey_pair else snap.generations[0]
            records=copy.deepcopy(vici_fixture.NATIVE)+vici_fixture.hosts(g,20)
            activity={r['id']:True for r in records}
            proof=p.audit(reg,parsed.snapshots,records,activity,vici_fixture.NATIVE,outer_endpoints=h.OUTER)
            if snap.kind=='overlap':
                self.assertEqual(tuple(x.child_id for x in snap.rekey_pair),(1,3))
                self.assertFalse(proof.devices[0].ready)
                proof=p.audit(reg,parsed.snapshots,records,activity,vici_fixture.NATIVE,
                              outer_endpoints=h.OUTER,continuing={'device01':current})
                self.assertTrue(proof.devices[0].ready)
                self.assertEqual(proof.devices[0].generation.child_id,3)
            current=proof.devices[0];observed.add(snap.kind)
        self.assertEqual(observed,{'unique','overlap'})
        self.assertEqual(len(fixture['sequence']),12)

    def test_retirement_intent_blocks_native_replacement(self):
        with h.environment() as e:
            old=self.start(e);expected=e.a.gate.current();e.events=replaced(old,False)
            parsed=v.parse_events(e.events,e.reg,h.OUTER)
            proof=p.audit(e.reg,parsed.snapshots,e.records,e.active,e.records[:3],outer_endpoints=h.OUTER)
            e.owner.session['fleet_closing']={'version':1,'phase':'intent','devices':['device01']}
            with self.assertRaisesRegex(h.h.s.Refused,'retirement_unfinished'):
                e.a.publish(expected,proof.devices,proof)

    def test_unfinished_relation_rejects_a_later_replacement(self):
        with h.environment() as e:
            old=self.start(e);e.events=replaced(old);e.c.step();self.no_close(e)
            current_unique=replaced(old,False)
            e.events=replaced(current_unique,new_id=5)
            with patch.object(e.a,'publish',wraps=e.a.publish) as publications:e.c.step()
            self.assertEqual(e.c.last_result.active,('device02',))
            self.assertFalse(e.c.continuities)
            self.assertFalse(any(any(d.device_id=='device01' for d in call.args[1]) for call in publications.call_args_list))

    def test_changed_scope_during_other_route_is_not_republished(self):
        with h.environment() as e:
            old=self.start(e);e.events=replaced(old);original=e.a.route;calls=[]
            def route(d):
                answer=original(d);calls.append(d.device_id)
                if calls==['device01','device02']:child(e.events[0])['local-ts']=[]
                return answer
            with patch.object(e.a,'route',side_effect=route),patch.object(e.a,'publish',wraps=e.a.publish) as publications:
                e.c.step()
            self.assertEqual(e.c.last_result.active,('device02',))
            self.assertFalse(any(any(d.device_id=='device01' for d in call.args[1]) for call in publications.call_args_list))
            closed=False
            for saved in e.owner.store.saved:
                present=any(d['device_id']=='device01' for d in saved['fleet_active'])
                if not present:closed=True
                if closed:self.assertFalse(present,'invalidated device was durably republished')
            self.assertTrue(closed)

    def test_two_continuities_long_residue_then_route_loss_only_narrows_one(self):
        with h.environment() as e,patch.object(time,'monotonic',return_value=100) as clock:
            old=self.start(e);e.events=replaced(replaced(old),index=1,new_id=4)
            self.assertEqual(e.c.step().active,('device01','device02'))
            relations=copy.deepcopy(e.c.continuities)
            clock.return_value=1000000
            self.assertEqual(e.c.step().active,('device01','device02'))
            self.assertEqual(e.c.continuities,relations)
            original=e.a.route;e.owner.store.saved.clear()
            def route(d):return None if d.device_id=='device02' else original(d)
            with patch.object(e.a,'route',side_effect=route),patch.object(e.a,'publish',wraps=e.a.publish) as publications:
                e.c.step()
            self.assertEqual(e.c.last_result.active,('device01',))
            self.assertEqual(set(e.c.continuities),{'device01'})
            self.assertFalse(any(any(d.device_id=='device02' for d in call.args[1]) for call in publications.call_args_list))
            self.assertTrue(any('-k' in cmd for cmd in e.k.trace))
            for saved in e.owner.store.saved:
                self.assertIn('device01',{d['device_id'] for d in saved['fleet_active']})


if __name__=='__main__':unittest.main()
