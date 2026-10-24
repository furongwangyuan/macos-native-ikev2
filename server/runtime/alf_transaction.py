"""Actual bounded ALF transaction through the owner's sole durable mutator.

No work on import, no CLI, no direct subprocess, and no add/remove/global-disable
operation. The caller owns native/legacy locks and settles the old mutator first.
"""
import copy
import json
from pathlib import PurePosixPath

ALF='/usr/libexec/ApplicationFirewall/socketfilterfw'
CHARON='/usr/local/family-vpn/strongswan-6.1.0/libexec/ipsec/charon'
PROFILE='production-native-fleet-v1'
VERSION=8
PROBE='/usr/local/libexec/family-vpn-probe/native-probe'
PROBE_MODES=('off','synthetic-local-v1')
FLAGS={'builtin':'--setallowsigned','downloaded':'--setallowsignedapp'}
ROW_PHASES={'pending','apply-intent','applied','restore-intent','restored','conflict'}
PHASES={'planned','preparing','prepared','open-intent','open','closing','closed','restoring','restored','attention'}


class InvalidALF(ValueError):pass


def app_path(value):
    return (type(value)is str and value.startswith('/') and len(value.encode('utf-8'))<=512
        and value==value.strip() and not any(c in value for c in ('\0','\r','\n'))
        and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts)


def snapshot(value,baseline=False):
    if (type(value)is not dict or set(value)!={'global_state','blockall','stealth','apps','builtin','downloaded'}
            or type(value['global_state'])is not int or value['global_state'] not in (0,1,2)
            or any(type(value[key])is not bool for key in ('blockall','builtin','downloaded'))
            or value['stealth'] not in ('Firewall stealth mode is on','Firewall stealth mode is off')
            or type(value['apps'])is not dict or not 1<=len(value['apps'])<=64
            or any(not app_path(k) or type(v)is not bool for k,v in value['apps'].items())):
        raise InvalidALF('unknown_alf_snapshot')
    if (value['global_state']==2)!=value['blockall']:raise InvalidALF('inconsistent_alf_blockall')
    if baseline and ((value['global_state'],value['blockall'])!=(2,True) or value['apps'].get(CHARON)is not False):
        raise InvalidALF('known_closed_alf_baseline_required')
    return value


def probe_mode(value):
    if type(value)is not str or value not in PROBE_MODES:raise InvalidALF('unknown_probe_mode')
    return value


def plan(before,mode='off'):
    snapshot(before,True)
    probe_mode(mode)
    if PROBE in before['apps'] and before['apps'][PROBE]is not False:
        raise InvalidALF('probe_baseline_must_remain_blocked')
    if mode!='off' and before['apps'].get(PROBE)is not False:
        raise InvalidALF('probe_requires_preinstalled_blocked_baseline')
    changes=[dict(kind='flag',key=key,before=True,after=False,phase='pending')
        for key in FLAGS if before[key]]
    changes.extend(dict(kind='app',key=key,before=True,after=False,phase='pending')
        for key,value in sorted(before['apps'].items()) if value)
    changes.append(dict(kind='app',key=CHARON,before=False,after=True,phase='pending'))
    if mode!='off':changes.append(dict(kind='app',key=PROBE,before=False,after=True,phase='pending'))
    return changes


def argv_for(row,restore=False):
    value=row['before'] if restore else row['after']
    if row['kind']=='flag':return [ALF,FLAGS[row['key']],'on' if value else 'off']
    return [ALF,'--unblockapp' if value else '--blockapp',row['key']]


def new(before,probe_mode='off'):
    value=dict(version=2,probe_mode=probe_mode,phase='planned',before=copy.deepcopy(before),changes=plan(before,probe_mode),intent=None)
    validate(value,before);return value


def validate(record,before):
    if (type(record)is not dict or set(record)!={'version','probe_mode','phase','before','changes','intent'}
            or type(record['version'])is not int or record['version']!=2 or record['phase'] not in PHASES
            or record['before']!=before or type(record['changes'])is not list):
        raise InvalidALF('unknown_alf_transaction')
    snapshot(record['before'],True);snapshot(before,True)
    if len(json.dumps(record,ensure_ascii=True,allow_nan=False).encode())>49152:raise InvalidALF('alf_journal_limit')
    expected=plan(before,record['probe_mode'])
    if len(expected)!=len(record['changes']):raise InvalidALF('alf_plan_count_changed')
    for actual,wanted in zip(record['changes'],expected):
        if (type(actual)is not dict or set(actual)!=set(wanted) or actual['phase'] not in ROW_PHASES
                or any(type(actual[k])is not bool for k in ('before','after'))
                or any(actual[k]!=wanted[k] for k in ('kind','key','before','after'))):
            raise InvalidALF('alf_plan_changed')
    if record['phase']=='planned' and any(r['phase']!='pending' for r in record['changes']):
        raise InvalidALF('alf_planned_state_changed')
    intent=record['intent']
    if intent is not None:
        if type(intent)is not dict or set(intent)!={'purpose','index','argv'} or type(intent['argv'])is not list:
            raise InvalidALF('unknown_alf_intent')
        purpose=intent['purpose'];index=intent['index']
        if purpose in ('apply','restore'):
            if type(index)is not int or not 0<=index<len(expected):raise InvalidALF('unknown_alf_target')
            row=record['changes'][index]
            if (row['phase']!=purpose+'-intent' or intent['argv']!=argv_for(row,purpose=='restore')
                    or record['phase']!=('preparing' if purpose=='apply' else 'restoring')):
                raise InvalidALF('alf_intent_scope_changed')
        elif purpose in ('open','close'):
            if (index is not None or intent['argv']!=[ALF,'--setblockall','off' if purpose=='open' else 'on']
                    or record['phase']!=('open-intent' if purpose=='open' else 'closing')):
                raise InvalidALF('alf_blockall_intent_changed')
        else:raise InvalidALF('unknown_alf_purpose')
    elif record['phase'] in ('open-intent','closing'):
        raise InvalidALF('alf_intent_missing')
    if record['phase'] in ('prepared','open-intent','open') and any(r['phase']!='applied' for r in record['changes']):
        raise InvalidALF('alf_preparation_incomplete')
    if record['phase']=='restored' and (intent is not None or any(r['phase'] not in ('pending','restored') for r in record['changes'])):
        raise InvalidALF('alf_restoration_incomplete')
    return record


def validate_session(session):
    if (type(session)is not dict or type(session.get('version'))is not int or session['version']!=VERSION
            or session.get('profile')!=PROFILE or type(session.get('allow_data'))is not bool
            or type(session.get('probe_mode'))is not str or session['probe_mode'] not in PROBE_MODES):
        raise InvalidALF('alf_session_profile')
    record=session.get('alf_transaction')
    if session['allow_data']:
        validate(record,session.get('alf_before'))
        if record['probe_mode']!=session['probe_mode']:raise InvalidALF('alf_probe_mode_changed')
        if session.get('active')is False and record['phase']!='restored':raise InvalidALF('inactive_unrestored_alf')
    elif record is not None or session['probe_mode']!='off':raise InvalidALF('closed_session_has_alf_writer')


def authorize(session,argv):
    validate_session(session)
    record=session.get('alf_transaction')
    if (session['allow_data']is not True or session.get('active')is not True or record is None
            or record['intent'] is None or record['intent']['argv']!=list(argv)):
        raise InvalidALF('alf_mutation_not_in_durable_intent')


class Transaction:
    def __init__(self,session,store,*,observe=None,firewall=None,run=None):
        # Defaults bind only fixed native readers/dispatcher; seams are ordinary
        # test injection, not environment settings or privileged CLI parameters.
        import alf_readonly as alf
        import native_support as support
        self.session,self.store=session,store
        self.observe=observe or alf.snapshot;self.firewall=firewall or alf.firewall;self.run=run or support.run
        validate_session(session)
        if not session['allow_data']:raise InvalidALF('alf_writer_requires_data_profile')
    @property
    def record(self):return validate(self.session['alf_transaction'],self.session['alf_before'])
    def save(self):
        validate_session(self.session);self.store.save(self.session)
    def expected(self,opened=None):
        record=self.record;value=copy.deepcopy(record['before'])
        for row in record['changes']:
            if row['kind']=='app':value['apps'][row['key']]=row['after']
            else:value[row['key']]=row['after']
        if opened is None:
            if record['phase'] not in ('prepared','open'):raise InvalidALF('alf_not_ready_for_local_check')
            opened=record['phase']=='open'
        value.update(global_state=1 if opened else 2,blockall=not opened)
        return value
    def _intent(self,purpose,index,argv):
        record=self.record
        record['phase']={'apply':'preparing','restore':'restoring','open':'open-intent','close':'closing'}[purpose]
        if index is not None:record['changes'][index]['phase']=purpose+'-intent'
        record['intent']=dict(purpose=purpose,index=index,argv=argv)
        self.save() # Required before the sole dispatcher can record/GO a mutator.
        self.run(argv,timeout=3)
    def prepare(self):
        record=self.record
        if record['phase']!='planned' or self.observe()!=record['before']:raise InvalidALF('alf_baseline_changed')
        current=copy.deepcopy(record['before'])
        for index,row in enumerate(record['changes']):
            self._intent('apply',index,argv_for(row))
            if row['kind']=='app':current['apps'][row['key']]=row['after']
            else:current[row['key']]=row['after']
            if self.observe()!=current:raise InvalidALF('alf_preparation_readback_failed')
            row['phase']='applied';record['intent']=None;self.save()
        record['phase']='prepared';self.save()
    def open(self):
        record=self.record
        if record['phase']!='prepared' or self.observe()!=self.expected(False):raise InvalidALF('alf_prepared_state_changed')
        self._intent('open',None,[ALF,'--setblockall','off'])
        if self.observe()!=self.expected(True):raise InvalidALF('alf_open_readback_failed')
        record['phase']='open';record['intent']=None;self.save()
    def close(self):
        record=self.record
        if record['phase']=='restored':
            if self.observe()!=record['before']:raise InvalidALF('restored_alf_changed')
            return
        self._intent('close',None,[ALF,'--setblockall','on'])
        if self.firewall()!=(2,True):raise InvalidALF('alf_close_unverified')
        record['phase']='closed';record['intent']=None;self.save()
    def restore(self):
        record=self.record
        if record['phase']=='restored':
            if self.observe()!=record['before']:raise InvalidALF('restored_alf_changed')
            return
        if record['phase']!='closed' or self.firewall()!=(2,True):raise InvalidALF('alf_restore_requires_closed')
        errors=[]
        for index in reversed(range(len(record['changes']))):
            row=record['changes'][index]
            if row['phase']=='pending':continue # Never undo an unattempted/external change.
            if row['phase']=='conflict':
                # A matching later value does not re-establish lost ownership.
                errors.append(index);continue
            current=snapshot(self.observe())
            if (current['global_state'],current['blockall'])!=(2,True):raise InvalidALF('alf_reopened_during_restore')
            actual=current['apps'].get(row['key']) if row['kind']=='app' else current[row['key']]
            if actual is row['before']:
                row['phase']='restored';record['intent']=None;self.save();continue
            if actual is not row['after'] or row['phase']=='restored':
                row['phase']='conflict';record['intent']=None;record['phase']='restoring';self.save();errors.append(index);continue
            self._intent('restore',index,argv_for(row,True))
            current=snapshot(self.observe())
            actual=current['apps'].get(row['key']) if row['kind']=='app' else current[row['key']]
            if (current['global_state'],current['blockall'])!=(2,True) or actual is not row['before']:
                raise InvalidALF('alf_restore_readback_failed')
            row['phase']='restored';record['intent']=None;self.save()
        exact=self.observe()==record['before']
        record['phase']='restored' if exact and not errors else 'attention';record['intent']=None;self.save()
        if not exact or errors:raise InvalidALF('alf_external_changes_preserved_not_restored')
