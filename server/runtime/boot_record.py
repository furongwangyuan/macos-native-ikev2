"""Narrow new-boot persistent-closure record; no I/O or old-ID authority."""
import base64,copy,hashlib,json,re,math
import alf_transaction as alf
import native_gate as pf
import native_support as s
import boot_source as source
from mutation_spec import require_mutation
import native_policy
import network_readonly

PROFILE='boot-persistent-fleet-v1'
PHASES={'ADMITTED','RESTORING','RESTORED','ATTENTION'}
HEX=re.compile('[0-9a-f]{64}')
ALLOWED_PHASES={'WAITING','ACTIVE','PREPARING','CLOSING'}
FILE_KEYS={'daemon','connection'}
ROOT_KEYS=frozenset('version profile active phase boot started allow_data baseline alf_before health crl alf_transaction files knobs network pf pf_reference floors keepers floor_gc child mutation test_action fault_control stale_socket_unlink_intent events child_seen activation_generation gate_intent floor_removal_started floor_survived_child cleanup_codes recovery_result alf_external_changes_preserved pf_external_reference_change_preserved fault_run fault_intent_sha256 finite_window finite_ready server_window server_ready probe_mode probe_child probe_generation probe_result probe_retired production_run fleet fleet_active fleet_closing'.split())

class Refused(RuntimeError):pass

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,allow_nan=False,separators=(',',':'))+'\n').encode()
def exact_hash(value):return type(value)is str and HEX.fullmatch(value) is not None

def sources(native_raw,context_raw,new_boot):
    if type(native_raw)is not bytes or type(context_raw)is not bytes or len(native_raw)>131072 or len(context_raw)>393216:
        raise Refused('original_size_or_type')
    n=s.json_value(native_raw);v=source.validate(n,context_raw)
    production=v.get('kind')=='production-service-v1'
    # Cleanup failures describe the previous kernel. A real reboot has already
    # discarded its processes and SAD/SPD; admit the validated journal so the
    # caller can prove that fresh state before touching persistent leftovers.
    interrupted_production=(production and n.get('phase')=='ATTENTION' and n.get('active')is True
        and type(n.get('cleanup_codes',[]))is list and len(n.get('cleanup_codes',[]))<=32
        and all(type(code)is str and re.fullmatch('[a-z0-9_]{1,80}',code) for code in n.get('cleanup_codes',[]))
        and n.get('recovery_result') in (None,'restored','protected-needs-attention','protection-unverified'))
    clean_production=(v.get('kind')=='production-service-v1' and n.get('phase')=='RESTORED'
        and n.get('active')is False and n.get('cleanup_codes')==[] and n.get('recovery_result')=='restored')
    if (type(n)is not dict or set(n)-ROOT_KEYS or type(n.get('version'))is not int or n['version']!=8
            or n.get('profile')!='production-native-fleet-v1' or not(clean_production or n.get('active')is True) or n.get('allow_data')is not True
            or not(clean_production or interrupted_production or n.get('phase') in ALLOWED_PHASES) or type(n.get('boot'))is not str
            or not n['boot'] or len(n['boot'])>256 or v['boot']!=n['boot']
            or type(new_boot)is not str or not new_boot or len(new_boot)>256 or new_boot==n['boot']
            or not interrupted_production and (n.get('cleanup_codes',[])!=[] or n.get('recovery_result') not in (None,'restored'))):
        raise Refused('unsupported_old_boot_session')
    s.session_history(n)
    baseline=n.get('baseline');knobs=n.get('knobs')
    if (type(baseline)is not dict or set(baseline)!=set(s.SYS)|{s.ESP} or type(knobs)is not dict
            or any(type(v)is not int or v not in ((0,1) if 'redirect' in k else (0,)) for k,v in baseline.items())):
        raise Refused('unknown_old_baseline')
    for key,row in knobs.items():
        if (key not in baseline or type(row)is not dict or set(row)!={'before','after','phase'}
                or row['phase'] not in ('untouched','apply-intent','applied','restore-intent','restored')
                or type(row['before'])is not int or type(row['after'])is not int or row['before']!=baseline[key]
                or row['after']!=(4500 if key==s.ESP else s.SYS[key])):raise Refused('unknown_old_knob')
    network_readonly.known_change(n['health'],{k:n['health'][k] for k in network_readonly.LOCAL_KEYS})
    crl=n.get('crl')
    if (type(crl)is not dict or set(crl)!={'number','sha256','der_sha256','next','authority_sha256'} or type(crl['number'])is not int
            or crl['number']<0 or any(not exact_hash(crl[k]) for k in ('sha256','der_sha256','authority_sha256'))
            or type(crl['next']) not in (int,float) or not math.isfinite(crl['next']) or crl['next']<=0):
        raise Refused('unknown_historical_crl_metadata')
    native_policy.cleanup_records(n) # Pure shape/scope validation; NEVER queries or deletes old IDs.
    for row in n.get('floors',[])+n.get('keepers',[])+([n['floor_gc']] if n.get('floor_gc') else []):
        if 'id' in row and type(row['id'])is not int:raise Refused('old_policy_id_type')
    for label in ('child','mutation'):
        entry=n.get(label)
        if entry is None:continue
        if type(entry)is not dict:raise Refused('old_process_receipt')
        identity=entry.get('identity')
        if identity is not None and (type(identity)is not dict or set(identity)!={'pid','uid','pgid','started_sec','started_usec','path'}
                or any(type(identity[k])is not int for k in ('pid','uid','pgid','started_sec','started_usec'))
                or identity['uid']!=0 or identity['pid']<=1 or identity['pgid']!=identity['pid']
                or identity['started_sec']<=0 or not 0<=identity['started_usec']<1000000
                or type(identity['path'])is not str or not identity['path'].startswith('/')
                or any(x in identity['path'] for x in ('\0','\n','\r'))):raise Refused('old_process_identity_shape')
        if label=='child':
            if set(entry)!={'phase','identity'} or entry['phase'] not in ('spawn-intent','go-intent','go-sent','stop-intent','exited'):
                raise Refused('old_child_phase')
            if identity is None and entry['phase'] not in ('spawn-intent','exited'):raise Refused('old_child_identity_missing')
        else:
            if (set(entry)-{'version','phase','argv','identity','never_sent_go'} or type(entry.get('version'))is not int
                    or entry['version']!=1 or entry.get('phase') not in ('spawn-intent','go-intent','settled')):
                raise Refused('old_mutation_shape')
            require_mutation(entry.get('argv'))
            if ('never_sent_go' in entry and not(entry['never_sent_go']is True and identity is None and entry['phase']=='settled')
                    or identity is None and entry['phase']!='spawn-intent' and entry.get('never_sent_go')is not True
                    or identity is not None and entry['phase']=='spawn-intent'):raise Refused('old_mutation_identity_missing')
    if type(n.get('files'))is not dict or set(n['files'])-FILE_KEYS:raise Refused('unknown_old_file_scope')
    for row in n['files'].values():
        if (type(row)is not dict or set(row)!={'phase','created','sha256'} or type(row['created'])is not bool
                or row['phase'] not in ('apply-intent','owned','restore-intent','restored') or not exact_hash(row['sha256'])):
            raise Refused('unknown_old_file_receipt')
    if n['phase'] in ('WAITING','ACTIVE') and (set(n['files'])!=FILE_KEYS or any(x['phase']!='owned' for x in n['files'].values())
            or n['alf_transaction']['phase']!='open' or n.get('child',{}).get('phase')!='go-sent'
            or len(n.get('floors',[]))!=2 or len(n.get('keepers',[]))!=1
            or any(row['status']!='owned' for row in n['floors']+n['keepers'])):
        raise Refused('running_setup_not_complete')
    if not production:
        if any(row['phase']=='conflict' for row in n['alf_transaction']['changes']):raise Refused('old_alf_conflict_retained')
        if n['alf_transaction']['phase']=='attention':raise Refused('old_alf_attention_retained')
    p=n.get('pf')
    # First scope requires a known persistent PF receipt, including apply-intent.
    required={'before','before_sha','after_sha','mode','phase','guard','root_before','auxiliary_before','apple_source_sha','enabled_before','references_before'}
    if (type(p)is not dict or set(p)!=required or p['phase'] not in ('apply-intent','applied','restore-intent','restored')
            or type(p['mode'])is not int or p['mode']!=0o644 or type(p['before'])is not str
            or any(not exact_hash(p[k]) for k in ('before_sha','after_sha','apple_source_sha'))):
        raise Refused('unsupported_old_pf_receipt')
    original=base64.b64decode(p['before'],validate=True)
    if len(original)>20000 or sha(original)!=p['before_sha'] or sha(pf.prepared_main(original))!=p['after_sha']:
        raise Refused('old_pf_source_not_fixed_transform')
    pf.default_root('\n'.join(p['root_before']['filters']),'\n'.join(p['root_before']['nat']))
    pf.default_auxiliary(p['auxiliary_before'])
    return n,v


def alf_scope(old,current,completed):
    before=old['alf_before'];record=old['alf_transaction'];alf.snapshot(current)
    if 'production_run' in old:
        # The current kernel is independently checked closed by the caller.
        # Foreign app/flag edits and changes to already released rules are not
        # authority to undo those edits or disable unrelated remote access.
        if current['global_state'] not in (1,2):raise Refused('alf_disabled_or_unknown')
        return current
    if (current['stealth']!=before['stealth'] or set(current['apps'])!=set(before['apps'])
            or current['global_state'] not in (1,2)):
        raise Refused('alf_shape_or_external_change')
    if current['global_state']==1 and (record['phase'] not in ('open','open-intent','closing')
            or any(r['phase']!='applied' for r in record['changes']) or 'alf-close' in completed):
        raise Refused('alf_open_not_owned')
    touched={}
    for index,row in enumerate(record['changes']):
        key=('app',row['key']) if row['kind']=='app' else ('flag',row['key'])
        value=current['apps'][row['key']] if row['kind']=='app' else current[row['key']]
        # pending was never attempted; restored/conflict is not re-claimable.
        must_before=row['phase'] in ('pending','restored') or 'alf-'+str(index) in completed
        if row['phase']=='conflict' or (must_before and value is not row['before']):raise Refused('alf_rule_not_owned')
        if not must_before and value not in (row['before'],row['after']):raise Refused('alf_rule_unknown')
        touched[key]=True
    for path,value in current['apps'].items():
        if ('app',path) not in touched and value is not before['apps'][path]:raise Refused('unmodified_alf_app_changed')
    for key in ('builtin','downloaded'):
        if ('flag',key) not in touched and current[key] is not before[key]:raise Refused('unmodified_alf_flag_changed')
    return current


def alf_finished(old,current,completed):
    alf_scope(old,current,completed)
    if 'production_run' not in old and current!=old['alf_before']:
        raise Refused('boot_alf_not_exact_baseline')
    return current


def new(native_raw,context_raw,new_boot,configuration_sha,implementation_sha):
    old,_=sources(native_raw,context_raw,new_boot)
    return dict(version=1,profile=PROFILE,phase='ADMITTED',old_boot=old['boot'],new_boot=new_boot,
        native_sha256=sha(native_raw),context_sha256=sha(context_raw),configuration_sha256=configuration_sha,
        implementation_sha256=implementation_sha,completed=[],intent=None,mutation=None)


def validate(record):
    keys={'version','profile','phase','old_boot','new_boot','native_sha256','context_sha256','configuration_sha256','implementation_sha256','completed','intent','mutation'}
    if (type(record)is not dict or set(record)!=keys or type(record['version'])is not int or record['version']!=1
            or record['profile']!=PROFILE or record['phase'] not in PHASES
            or any(type(record[k])is not str or not record[k] or len(record[k])>256 for k in ('old_boot','new_boot'))
            or record['old_boot']==record['new_boot']
            or any(not exact_hash(record[k]) for k in ('native_sha256','context_sha256','configuration_sha256','implementation_sha256'))
            or type(record['completed'])is not list or len(record['completed'])>76
            or any(type(x)is not str or not re.fullmatch(r'alf-close|alf-[0-9]{1,2}|pf-source|pf-load|pf-clear|file-(?:daemon|connection)',x) for x in record['completed'])
            or len(set(record['completed']))!=len(record['completed'])):
        raise Refused('unknown_boot_record')
    if record['phase']=='RESTORED' and record['intent'] is not None:raise Refused('restored_with_pending_intent')
    if record['intent'] is not None:
        intent=record['intent']
        if type(intent)is not dict or set(intent)!={'key','effect'} or intent['key'] in record['completed']:
            raise Refused('unknown_boot_intent')
        if type(intent['key'])is not str or not re.fullmatch(r'alf-close|alf-[0-9]{1,2}|pf-source|pf-load|pf-clear|file-(?:daemon|connection)',intent['key']):
            raise Refused('unknown_boot_intent_key')
        if type(intent['effect'])is not dict:raise Refused('unknown_boot_intent_effect')
    mutation=record['mutation']
    if mutation is not None:
        if (type(mutation)is not dict or not {'version','phase','argv','identity'}<=set(mutation)
                or set(mutation)-{'version','phase','argv','identity','never_sent_go'}
                or type(mutation['version'])is not int or mutation['version']!=1
                or mutation['phase'] not in ('spawn-intent','go-intent','settled')):
            raise Refused('unknown_boot_mutation')
        command(mutation['argv']);identity=mutation['identity']
        if identity is not None and (type(identity)is not dict or set(identity)!={'pid','uid','pgid','started_sec','started_usec','path'}
                or any(type(identity[k])is not int for k in ('pid','uid','pgid','started_sec','started_usec'))
                or identity['pid']<=1 or identity['pgid']!=identity['pid'] or identity['uid']<0 or identity['started_sec']<=0
                or not 0<=identity['started_usec']<1000000 or type(identity['path'])is not str or not identity['path'].startswith('/')
                or any(x in identity['path'] for x in ('\0','\n','\r'))):raise Refused('unknown_boot_mutator_identity')
        if ('never_sent_go' in mutation and not(mutation['never_sent_go']is True and identity is None and mutation['phase']=='settled')
                or identity is None and mutation['phase']!='spawn-intent' and mutation.get('never_sent_go')is not True
                or identity is not None and mutation['phase']=='spawn-intent'):raise Refused('unknown_boot_mutator_phase')
        if mutation['phase']!='settled' and (record['intent'] is None or record['intent']['effect']!={'kind':'command','argv':mutation['argv']}):
            raise Refused('boot_mutator_intent_binding')
        if record['phase']=='RESTORED' and mutation['phase']!='settled':raise Refused('boot_unsettled_at_completion')
    return record


def command(argv):
    if type(argv)is not list or any(type(x)is not str for x in argv):raise Refused('boot_command_type')
    if argv in ([alf.ALF,'--setblockall','on'],[pf.PF,'-f',str(s.PFC)],
                [pf.PF,'-a',pf.ANCHOR,'-f','/dev/null']):return argv
    if len(argv)==3 and argv[0]==alf.ALF:
        if argv[1] in alf.FLAGS.values() and argv[2]=='on':return argv
        if argv[1] in ('--blockapp','--unblockapp') and alf.app_path(argv[2]):return argv
    raise Refused('boot_command_not_close_restore_scope')


def effect(old,key):
    if key=='alf-close':return {'kind':'command','argv':[alf.ALF,'--setblockall','on']}
    if key.startswith('alf-') and key[4:].isdigit():
        index=int(key[4:]);rows=old['alf_transaction']['changes']
        if not 0<=index<len(rows) or rows[index]['phase'] in ('pending','restored','conflict'):
            raise Refused('unattempted_or_released_alf_rule')
        return {'kind':'command','argv':alf.argv_for(rows[index],True)}
    if key=='pf-source':return {'kind':'replace-pf','sha256':old['pf']['before_sha'],'mode':old['pf']['mode']}
    if key=='pf-load':return {'kind':'command','argv':[pf.PF,'-f',str(s.PFC)]}
    if key=='pf-clear':return {'kind':'command','argv':[pf.PF,'-a',pf.ANCHOR,'-f','/dev/null']}
    if key.startswith('file-'):
        name=key[5:];row=old['files'].get(name)
        if name not in FILE_KEYS or row is None or not row['created'] or row['phase']=='restored':
            raise Refused('file_not_created_or_already_released')
        return {'kind':'delete-created','file':name,'sha256':row['sha256']}
    raise Refused('unknown_boot_fixed_effect')


def bind(record,native_raw,context_raw):
    validate(record);old,context=sources(native_raw,context_raw,record['new_boot'])
    if (sha(native_raw)!=record['native_sha256'] or sha(context_raw)!=record['context_sha256']
            or old['boot']!=record['old_boot'] or context['configuration_sha256']!=record['configuration_sha256']):
        raise Refused('boot_original_binding')
    allowed={'alf-close','pf-source','pf-load','pf-clear'}|{'alf-'+str(i) for i in range(len(old['alf_transaction']['changes']))}|{'file-'+k for k in FILE_KEYS}
    if set(record['completed'])-allowed:raise Refused('unknown_completed_boot_target')
    if record['intent'] is not None and record['intent']['effect']!=effect(old,record['intent']['key']):
        raise Refused('boot_effect_not_derived_from_original')
    return old
