"""Original actual server93600 source plus its actual successful finite900 chain.

Only fixed root-owned files are read. No external control code is imported, and
no finite marker is synthesized for the server owner. The separate historical
short record is validated as a short record using its actual stored bytes.
"""
import base64,math
from pathlib import Path
import native_support as s
import boot_finite_source as f

STATE=Path('/private/var/db/family-vpn/production-acceptance')
CONTROL=Path('/usr/local/family-vpn/production-acceptance')
KIND='server93600'
SERVER_FILES=('admission.py','runner.py','server_service.py','server_observe.py','root_entry.py')
NAMES={'pointer','intent','owner','short-pointer','short-intent','short-owner','short-result','short-restoration',
       'short-session','short-previous-session','closed-proof','closed-session','native-config','supervisor-config','implementation-manifest'}
Refused=f.Refused
sha=f.sha;encode=f.encode;decode=f.decode


def snapshot():
    f.absent_service();ptr=s.read(STATE/'server/current.json');run=f.pointer(ptr);root=STATE/'server'/run
    shortptr=s.read(STATE/'current-data.json');short=f.pointer(shortptr);shortroot=STATE/'data'/short
    s.trusted(root,0o700);s.trusted(shortroot,0o700)
    paths={'intent':root/'intent.json','owner':root/'owner.json','short-intent':shortroot/'intent.json',
        'short-owner':shortroot/'owner.json','short-result':shortroot/'result.json','short-restoration':shortroot/'restoration.json',
        'short-session':shortroot/'final-session.json','short-previous-session':shortroot/'previous-session.json','closed-proof':STATE/'closed-proof.json',
        'closed-session':STATE/'closed-final-session.json','native-config':s.CONF/'config.json',
        'supervisor-config':s.CONF/'supervisor-config.json','implementation-manifest':s.BASE/'candidate-pins.json'}
    files={'pointer':ptr,'short-pointer':shortptr,**{name:s.read(path) for name,path in paths.items()}}
    if s.read(STATE/'server/current.json')!=ptr or s.read(STATE/'current-data.json')!=shortptr:
        raise Refused('server_pointer_changed')
    f.absent_service()
    raw=encode(dict(version=1,kind=KIND,service_state_absent=True,files={k:base64.b64encode(v).decode() for k,v in files.items()}))
    if len(raw)>393216:raise Refused('server_context_limit')
    return raw


def unpack(raw):
    if type(raw)is not bytes or len(raw)>393216:raise Refused('server_context_limit')
    value=decode(raw)
    if (type(value)is not dict or set(value)!={'version','kind','service_state_absent','files'}
            or type(value['version'])is not int or value['version']!=1 or value['kind']!=KIND
            or value['service_state_absent']is not True or type(value['files'])is not dict or set(value['files'])!=NAMES):
        raise Refused('server_context_unknown')
    out={}
    for name,encoded in value['files'].items():
        if type(encoded)is not str:raise Refused('server_context_file_type')
        item=base64.b64decode(encoded,validate=True)
        if len(item)>131072:raise Refused('server_context_file_limit')
        out[name]=item
    return out


def short_result(value,run):
    keys={'run_id','seconds','execution','controller_entered','stop_requested','generations','expiry_observed',
        'service_phase_elapsed_seconds','continuous_elapsed_seconds','failure','cleanup_failure',
        'owner_cleanup_returned_true','same_run_restored_journal','independent_restoration_verified',
        'native_acceptance','production_enabled','diagnostic'}
    if (type(value)is not dict or set(value)!=keys or value['run_id']!=run or type(value['seconds'])is not int
            or value['seconds']!=900 or value['execution']!='cooperative_window_returned'
            or any(value[k]is not True for k in ('controller_entered','expiry_observed','owner_cleanup_returned_true','same_run_restored_journal'))
            or any(value[k]is not False for k in ('stop_requested','independent_restoration_verified','native_acceptance','production_enabled'))
            or value['failure']is not None or value['cleanup_failure']is not None
            or type(value['generations'])is not int or value['generations']<1):raise Refused('server_short_result_not_successful')
    diagnostic=value['diagnostic']
    if (type(diagnostic)is not dict or set(diagnostic)!={'version','run','initial','cleanup','cleanup_codes'}
            or type(diagnostic['version'])is not int or diagnostic['version']!=1 or diagnostic['run']!=run
            or diagnostic['initial']is not None or diagnostic['cleanup']is not None or diagnostic['cleanup_codes']!=[]):
        raise Refused('server_short_diagnostic_not_clean')
    phase,total=value['service_phase_elapsed_seconds'],value['continuous_elapsed_seconds']
    if any(type(v)not in(int,float) or not math.isfinite(v) for v in (phase,total)) or not 900<=phase<=total:
        raise Refused('server_short_timing_unknown')


def validate(native,raw,*,permission_closed=False):
    if type(permission_closed)is not bool:raise Refused('fixed_permission_closed_mode')
    if native.get('probe_mode')!='off':raise Refused('server_probe_mode_not_off')
    files=unpack(raw);run=f.pointer(files['pointer']);short=f.pointer(files['short-pointer'])
    intent=decode(files['intent']);short_intent=decode(files['short-intent']);previous=decode(files['short-session'])
    keys={'version','run','boot','resources','common_sha256','seconds','short_admission','previous_session_sha256','server_resources'}
    if (type(intent)is not dict or set(intent)!=keys or type(intent['version'])is not int or intent['version']!=1
            or intent['run']!=run or type(intent['boot'])is not str or not intent['boot'] or intent['boot']!=native.get('boot')
            or type(intent['seconds'])is not int or intent['seconds']!=93600 or not f.hash_value(intent['common_sha256'])
            or intent['previous_session_sha256']!=sha(files['short-session'])):raise Refused('server_intent_not_bound')
    f.resources(intent['resources'])
    source=intent['server_resources']
    if type(source)is not dict or set(source)!=set(SERVER_FILES) or any(not f.hash_value(v) for v in source.values()):
        raise Refused('server_observer_source_map')
    # Validate the real earlier short source independently. These bytes already
    # exist on disk; no server identity/marker is cast into a finite identity.
    names={'pointer':'short-pointer','intent':'short-intent','owner':'short-owner','previous-session':'short-previous-session',
           **{k:k for k in ('closed-proof','closed-session','native-config','supervisor-config','implementation-manifest')}}
    short_raw=encode(dict(version=1,kind=f.KIND,service_state_absent=True,
        files={name:base64.b64encode(files[old]).decode() for name,old in names.items()}))
    f.validate(previous,short_raw,permission_closed=permission_closed);s.session_history(previous)
    if (previous.get('active')is not False or previous.get('phase')!='RESTORED' or previous.get('cleanup_codes')!=[]
            or previous.get('recovery_result')!='restored' or previous.get('boot')!=intent['boot']
            or previous.get('child',{}).get('phase')!='exited' or previous.get('mutation',{}).get('phase')!='settled'):
        raise Refused('server_previous_short_not_restored')
    result=decode(files['short-result']);short_result(result,short)
    restored=decode(files['short-restoration'])
    if (type(restored)is not dict or set(restored)!={'version','run','restored','session_sha256','baseline'}
            or type(restored['version'])is not int or restored['version']!=1 or restored['run']!=short
            or restored['restored']is not True or restored['session_sha256']!=sha(files['short-session'])
            or type(restored['baseline'])is not dict):raise Refused('server_short_restoration_binding')
    admission=intent['short_admission']
    if (type(admission)is not dict or set(admission)!={'short_run','short_result_sha256','short_restoration_sha256','previous_session_sha256','fresh_baseline'}
            or admission['short_run']!=short or admission['short_result_sha256']!=sha(encode(result))
            or admission['short_restoration_sha256']!=sha(encode(restored))
            or admission['previous_session_sha256']!=sha(files['short-session']) or type(admission['fresh_baseline'])is not dict):
        raise Refused('server_short_admission_binding')
    if (intent['resources']!=short_intent['resources'] or intent['common_sha256']!=short_intent['common_sha256']):
        raise Refused('server_short_closure_changed')
    owner=decode(files['owner']);wanted={'pid','uid','pgid','started_sec','started_usec','path'}
    if (type(owner)is not dict or set(owner)!=wanted or any(type(owner[k])is not int for k in wanted-{'path'})
            or owner['pid']<=1 or owner['pgid']!=owner['pid'] or owner['uid']!=0 or owner['started_sec']<=0
            or not 0<=owner['started_usec']<1000000 or type(owner['path'])is not str or not owner['path'].startswith('/')
            or any(x in owner['path'] for x in ('\0','\n','\r'))):raise Refused('server_original_owner_receipt')
    marker=native.get('server_window');ready=native.get('server_ready')
    if (native.get('test_action')!='server-observation-26h' or type(marker)is not dict
            or set(marker)!={'version','run_id','seconds','continuous_start','continuous_deadline'}
            or type(marker['version'])is not int or marker['version']!=1 or marker['run_id']!=run
            or type(marker['seconds'])is not int or marker['seconds']!=93600
            or any(type(marker[k])not in(int,float) or not math.isfinite(marker[k]) or marker[k]<0 for k in ('continuous_start','continuous_deadline'))
            or marker['continuous_deadline']-marker['continuous_start']!=93600):raise Refused('server_original_window')
    if ready is not None and (type(ready)is not dict or set(ready)!={'version','run_id','setup_completed'}
            or type(ready['version'])is not int or ready['version']!=1 or ready['run_id']!=run or ready['setup_completed']is not True):
        raise Refused('server_ready_unknown')
    if native.get('phase')in('WAITING','ACTIVE') and ready is None:raise Refused('server_ready_missing')
    return dict(kind=KIND,boot=intent['boot'],configuration_sha256=sha(files['supervisor-config']+b'\0'+files['native-config']),run=run)


def verify_current_resources(raw):
    files=unpack(raw);intent=decode(files['intent'])
    # Share the same runtime-local fixed inventory+public-binary verifier.
    f.verify_source_and_resources(files,intent)
    if {name:sha(s.read(CONTROL/name)) for name in SERVER_FILES}!=intent['server_resources']:
        raise Refused('server_observer_sources_changed')
