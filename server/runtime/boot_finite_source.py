"""Actual finite-900 original context; never synthesizes a service lifecycle.
All filesystem names are fixed except the already validated 32-hex run directory.
"""
import base64,hashlib,json,math,re,os,stat
from pathlib import Path
import native_support as s
import runtime_resources

STATE=Path('/private/var/db/family-vpn/production-acceptance')
PREFIX=Path('/usr/local/family-vpn/strongswan-6.1.0')
BINARY_ROOTS=(PREFIX/'sbin',PREFIX/'libexec',PREFIX/'lib',Path('/usr/local/family-vpn/openssl-3.5.9/lib'))
STRONGSWAN_CONFIG=Path('/usr/local/etc/family-vpn/strongswan.conf')
KIND='finite900'
NAMES={'pointer','intent','owner','closed-proof','closed-session','previous-session','native-config','supervisor-config','implementation-manifest'}

class Refused(RuntimeError):pass

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,allow_nan=False,separators=(',',':'))+'\n').encode()
def hash_value(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None

def decode(raw):return s.json_value(raw)
def run_id(value):return type(value)is str and re.fullmatch('[0-9a-f]{32}',value)is not None

def absent_service():
    path=s.STATE/'service-state.json'
    try:path.lstat()
    except FileNotFoundError:return
    raise Refused('finite_boot_requires_actual_service_state_absence')

def pointer(raw):
    value=decode(raw)
    if (type(value)is not dict or set(value)!={'version','run'} or type(value['version'])is not int
            or value['version']!=1 or not run_id(value['run'])):raise Refused('finite_pointer_unknown')
    return value['run']

def snapshot():
    absent_service();ptr=s.read(STATE/'current-data.json');run=pointer(ptr);root=STATE/'data'/run
    s.trusted(root,0o700)
    paths={'intent':root/'intent.json','owner':root/'owner.json','closed-proof':STATE/'closed-proof.json',
        'closed-session':STATE/'closed-final-session.json','previous-session':root/'previous-session.json','native-config':s.CONF/'config.json',
        'supervisor-config':s.CONF/'supervisor-config.json','implementation-manifest':s.BASE/'candidate-pins.json'}
    files={'pointer':ptr,**{name:s.read(path) for name,path in paths.items()}}
    if s.read(STATE/'current-data.json')!=ptr:raise Refused('finite_pointer_changed')
    absent_service()
    raw=encode(dict(version=1,kind=KIND,service_state_absent=True,files={k:base64.b64encode(v).decode() for k,v in files.items()}))
    if len(raw)>262144:raise Refused('finite_context_limit')
    return raw

def unpack(raw):
    if type(raw)is not bytes or len(raw)>262144:raise Refused('finite_context_limit')
    value=decode(raw)
    if (type(value)is not dict or set(value)!={'version','kind','service_state_absent','files'}
            or type(value['version'])is not int or value['version']!=1 or value['kind']!=KIND
            or value['service_state_absent']is not True or type(value['files'])is not dict or set(value['files'])!=NAMES):
        raise Refused('finite_context_unknown')
    out={}
    for name,encoded in value['files'].items():
        if type(encoded)is not str:raise Refused('finite_context_file_type')
        item=base64.b64decode(encoded,validate=True)
        if len(item)>131072:raise Refused('finite_context_file_limit')
        out[name]=item
    return out

def resources(value):
    if type(value)is not dict or not 2<=len(value)<=4096:raise Refused('finite_resource_map')
    roots=('/usr/local/family-vpn/strongswan-6.1.0/sbin/','/usr/local/family-vpn/strongswan-6.1.0/libexec/',
        '/usr/local/family-vpn/strongswan-6.1.0/lib/','/usr/local/family-vpn/openssl-3.5.9/lib/')
    fixed={str(s.CONF/'config.json'),'/usr/local/etc/family-vpn/strongswan.conf'}
    for path,entry in value.items():
        if type(path)is not str or (path not in fixed and not path.startswith(roots)) or any(x in path for x in ('\0','\n','\r')) or '..' in Path(path).parts:
            raise Refused('finite_resource_path')
        if type(entry)is not dict or len(entry)!=1:raise Refused('finite_resource_entry')
        if set(entry)=={'sha256'} and hash_value(entry['sha256']):continue
        if set(entry)=={'link'} and type(entry['link'])is str and entry['link'] and not any(x in entry['link'] for x in ('\0','\n','\r')):continue
        raise Refused('finite_resource_entry')
    if not fixed<=set(value) or str(s.CHARON) not in value or str(s.SWAN) not in value:raise Refused('finite_required_resource_missing')
    return value

def validate(native,raw,*,permission_closed=False):
    if type(permission_closed)is not bool:raise Refused('fixed_permission_closed_mode')
    if native.get('probe_mode')!='off':raise Refused('finite_probe_mode_not_fixed')
    files=unpack(raw);run=pointer(files['pointer']);intent=decode(files['intent']);proof=decode(files['closed-proof'])
    expected={'version','run','boot','resources','common_sha256','seconds','previous_session_sha256'}
    if (type(intent)is not dict or set(intent)!=expected or type(intent['version'])is not int or intent['version']!=1
            or intent['run']!=run or type(intent['boot'])is not str or not intent['boot'] or intent['boot']!=native.get('boot')
            or type(intent['seconds'])is not int or intent['seconds']!=900 or not hash_value(intent['common_sha256'])
            or not hash_value(intent['previous_session_sha256'])):raise Refused('finite_intent_not_bound')
    resources(intent['resources'])
    fields={'version','profile','common_sha256','boot','resources','baseline','fault_run','session_sha256',
        'native_closed_suite','native_owner_sigkill','native_mutator_ownerkill','native_data_faults'}
    if (type(proof)is not dict or set(proof)!=fields or type(proof['version'])is not int or proof['version']!=1
            or proof['profile']!='production-native-fleet-v1' or proof['boot']!=intent['boot']
            or proof['common_sha256']!=intent['common_sha256'] or proof['resources']!=intent['resources']
            or sha(files['closed-session'])!=proof['session_sha256']
            or not run_id(proof['fault_run']) or type(proof['baseline'])is not dict
            or proof['native_closed_suite']is not True or proof['native_owner_sigkill']is not True
            or proof['native_mutator_ownerkill']is not False or proof['native_data_faults']is not False):
        raise Refused('finite_prior_proof_binding')
    closed=decode(files['closed-session']);s.session_history(closed)
    if (closed.get('allow_data')is not False or closed.get('probe_mode')!='off' or closed.get('active')is not False or closed.get('phase')!='RESTORED'
            or closed.get('boot')!=intent['boot']):raise Refused('finite_prior_not_closed_restored')
    previous=decode(files['previous-session']);s.session_history(previous)
    if (sha(files['previous-session'])!=intent['previous_session_sha256']
            or type(previous.get('version'))is not int or previous['version']!=8
            or previous.get('profile')!='production-native-fleet-v1' or previous.get('boot')!=intent['boot']
            or previous.get('active')is not False or previous.get('phase')!='RESTORED'
            or previous.get('cleanup_codes')!=[] or previous.get('recovery_result')!='restored'
            or 'server_window' in previous or 'server_ready' in previous
            or previous.get('child') is not None and previous['child'].get('phase')!='exited'
            or previous.get('mutation') is not None and previous['mutation'].get('phase')!='settled'):
        raise Refused('finite_previous_not_exact_restored')
    # Same-version actual prior short is retained as raw history, not recursively
    # elevated into another admission proof. Original closed evidence is separate.
    if files['previous-session']!=files['closed-session']:
        marker=previous.get('finite_window')
        if (type(marker)is not dict or not run_id(marker.get('run_id')) or marker['run_id']==run
                or type(marker.get('seconds'))is not int or marker['seconds']!=900
                or previous.get('probe_mode')!='off'):
            raise Refused('finite_previous_short_scope')
    manifest=decode(files['implementation-manifest'])
    if (sha(files['implementation-manifest'])!=intent['common_sha256'] or type(manifest)is not dict
            or type(manifest.get('journal_version'))is not int or manifest['journal_version']!=8
            or manifest.get('profile')!='production-native-fleet-v1' or type(manifest.get('runtime'))is not dict
            or not manifest['runtime'] or any(runtime_resources.name(k)!=k or not hash_value(v) for k,v in manifest['runtime'].items())):
        raise Refused('finite_source_manifest_binding')
    owner=decode(files['owner'])
    if (type(owner)is not dict or set(owner)!={'pid','uid','pgid','started_sec','started_usec','path'}
            or any(type(owner[k])is not int for k in ('pid','uid','pgid','started_sec','started_usec'))
            or owner['pid']<=1 or owner['pgid']!=owner['pid'] or owner['uid']!=0 or owner['started_sec']<=0
            or not 0<=owner['started_usec']<1000000 or type(owner['path'])is not str or not owner['path'].startswith('/')
            or any(x in owner['path'] for x in ('\0','\n','\r'))):raise Refused('finite_original_owner_receipt')
    config=decode(files['native-config']);supervisor=decode(files['supervisor-config'])
    if (type(config)is not dict or set(config)!={'version','allow_data'} or type(config['version'])is not int or config['version']!=1
            or config['allow_data']is not (not permission_closed) or type(supervisor)is not dict or set(supervisor)!={'version','enabled'}
            or type(supervisor['version'])is not int or supervisor['version']!=1 or supervisor['enabled']is not False
            or intent['resources'][str(s.CONF/'config.json')]!=dict(sha256=sha(encode(dict(version=1,allow_data=True))))):
        raise Refused('finite_original_permission_scope')
    marker=native.get('finite_window');ready=native.get('finite_ready')
    if (native.get('test_action')!='finite-service-900' or type(marker)is not dict
            or set(marker)!={'version','run_id','seconds','continuous_start','continuous_deadline'}
            or type(marker['version'])is not int or marker['version']!=1 or marker['run_id']!=run
            or type(marker['seconds'])is not int or marker['seconds']!=900
            or any(type(marker[k])not in(int,float) or not math.isfinite(marker[k]) or marker[k]<0 for k in ('continuous_start','continuous_deadline'))
            or marker['continuous_deadline']-marker['continuous_start']!=900):raise Refused('finite_original_window')
    if ready is not None and (type(ready)is not dict or set(ready)!={'version','run_id','setup_completed'}
            or type(ready['version'])is not int or ready['version']!=1 or ready['run_id']!=run or ready['setup_completed']is not True):
        raise Refused('finite_ready_unknown')
    if native.get('phase')in('WAITING','ACTIVE') and ready is None:raise Refused('finite_ready_missing')
    return dict(kind=KIND,boot=intent['boot'],configuration_sha256=sha(files['supervisor-config']+b'\0'+files['native-config']),run=run)

def public_resource_snapshot():
    """Exact fixed public inventory used by the finite parent; never import it.

    Same bounds/link rules as its reviewed native_adapter.resource_snapshot.
    No private PKI path or directory selected by an argument is traversed.
    """
    out={};count=0;total=0
    for root in BINARY_ROOTS:
        s.trusted(root);stack=[root]
        while stack:
            folder=stack.pop();s.trusted(folder)
            for path in sorted(folder.iterdir()):
                count+=1
                if count>4096:raise Refused('binary_inventory_limit')
                info=path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    if info.st_uid!=0:raise Refused('binary_link_owner')
                    target=path.resolve(strict=True)
                    if not target.is_relative_to(root.resolve()):raise Refused('binary_link_outside_fixed_root')
                    s.trusted(target);out[str(path)]={'link':os.readlink(path)}
                elif stat.S_ISDIR(info.st_mode):stack.append(path)
                elif stat.S_ISREG(info.st_mode):
                    total+=info.st_size
                    if total>512*1024*1024:raise Refused('binary_inventory_byte_limit')
                    out[str(path)]={'sha256':s.digest(s.read(path,mode=None,limit=64*1024*1024))}
                else:raise Refused('binary_inventory_type')
    if str(s.CHARON) not in out or str(s.SWAN) not in out:raise Refused('binary_required_missing')
    for path in (s.CONF/'config.json',STRONGSWAN_CONFIG):
        out[str(path)]={'sha256':s.digest(s.read(path))}
    return out


def verify_current_resources(raw):
    # Only local installed runtime modules are imported. No external harness
    # module executes merely because it occupies the expected pathname.
    import boot_native
    files=unpack(raw);intent=decode(files['intent'])
    return verify_source_and_resources(files,intent)


def verify_source_and_resources(files,intent):
    import boot_native
    current=s.read(s.BASE/'candidate-pins.json')
    manifest=decode(current);pins=manifest.get('runtime') if type(manifest)is dict else None
    expected=set(boot_native.RUNTIME_RESOURCES)|{'boot-runtime-pins.json'}
    if (current!=files['implementation-manifest'] or sha(current)!=intent['common_sha256']
            or type(pins)is not dict or set(pins)!=expected
            or runtime_resources.inventory(expected|{'candidate-pins.json'})!=expected|{'candidate-pins.json'}):
        raise Refused('finite_current_source_inventory_changed')
    for name,digest in pins.items():
        if not hash_value(digest) or sha(runtime_resources.read(name))!=digest:raise Refused('finite_current_source_bytes_changed')
    if public_resource_snapshot()!=intent['resources']:
        raise Refused('finite_current_resources_changed')
