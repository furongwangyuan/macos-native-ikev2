"""Pure, bounded normalization of complete structured VICI list-sas events.

No socket, process, certificate, file or kernel access. The caller must establish
the source daemon and the exact loaded pubkey/strict-revocation configuration,
and supply one complete unfiltered event sequence. ESTABLISHED is daemon state,
not independent cryptographic proof. This candidate is not wired into runtime.
"""
from dataclasses import dataclass
import ipaddress
import re
import outer_endpoints as endpoints

from registry import normalize
from fleet_policy import Fault, Generation, Snapshot, checked_generation, generation_groups, checked_snapshot, MAX_IKE_EVENTS, MAX_CHILDREN_PER_IKE, MAX_GENERATIONS


@dataclass(frozen=True)
class ParseResult:
    snapshots: dict
    unattributed_pending_count: int


IKE_BASE = frozenset(('uniqueid', 'version', 'state', 'local-host', 'local-port',
    'local-id', 'remote-host', 'remote-port', 'remote-id', 'initiator-spi',
    'responder-spi', 'child-sas'))
IKE_OPTIONAL = frozenset(('remote-eap-id', 'remote-xauth-id', 'initiator',
    'nat-local', 'nat-remote', 'nat-fake', 'nat-any', 'if-id-in', 'if-id-out',
    'encr-alg', 'encr-keysize', 'integ-alg', 'integ-keysize', 'prf-alg', 'dh-group',
    'ppk', 'established', 'rekey-time', 'reauth-time', 'local-vips', 'remote-vips',
    'tasks-queued', 'tasks-active', 'tasks-passive', *('ake'+str(n) for n in range(1,8))))
CHILD_BASE = frozenset(('name', 'uniqueid', 'reqid', 'state', 'mode', 'local-ts', 'remote-ts'))
CHILD_IPSEC = frozenset(('protocol', 'encap', 'spi-in', 'spi-out', 'encr-alg',
    'encr-keysize', 'integ-alg', 'integ-keysize', 'dh-group', 'bytes-in', 'bytes-out',
    'packets-in', 'packets-out', 'use-in', 'use-out', 'rekey-time', 'life-time', 'install-time'))
COMPLETE_CHILD = frozenset(('INSTALLED', 'REKEYING', 'REKEYED', 'DELETING', 'DELETED'))
PARTIAL_CHILD = frozenset(('CREATED', 'ROUTED', 'INSTALLING', 'UPDATING', 'RETRYING', 'DESTROYING'))


def bounded_tree(events):
    """Accept the official decoder's dict/OrderedDict, bytes and list tree only."""
    if type(events) is not list or len(events)>MAX_IKE_EVENTS:
        raise Fault('VICI event count or sequence type')
    budget=[0,0]
    def walk(value, depth):
        budget[0]+=1
        if depth>6 or budget[0]>8192:raise Fault('VICI tree bound')
        if isinstance(value,dict):
            if len(value)>64:raise Fault('VICI section bound')
            for key,item in value.items():
                if (type(key) is not str or not 1<=len(key)<=128
                        or not (re.fullmatch(r'[A-Za-z0-9_-]+',key)
                                or (depth==1 and key=='(unnamed)'))):
                    raise Fault('VICI section key')
                budget[1]+=len(key)
                walk(item,depth+1)
        elif type(value) is list:
            if len(value)>(MAX_IKE_EVENTS if depth==0 else 32):raise Fault('VICI list bound')
            for item in value:walk(item,depth+1)
        elif type(value) is bytes:
            if len(value)>1024:raise Fault('VICI scalar bound')
            budget[1]+=len(value)
        else:raise Fault('VICI decoded type')
        if budget[1]>262144:raise Fault('VICI byte bound')
    walk(events,0)


def section(value, required, allowed):
    if not isinstance(value,dict) or not required<=set(value) or not set(value)<=allowed:
        raise Fault('VICI section fields')


def value(section, key):
    raw=section.get(key)
    if type(raw) is not bytes or not 1<=len(raw)<=256:
        raise Fault('VICI scalar field')
    try:result=raw.decode('ascii')
    except UnicodeError:raise Fault('VICI scalar encoding') from None
    if any(ord(c)<32 or ord(c)>126 for c in result):raise Fault('VICI scalar controls')
    return result


def integer(section,key,minimum=0,maximum=2**64-1,signed=False):
    raw=value(section,key)
    pattern=r'(?:0|[1-9][0-9]*|-[1-9][0-9]*)' if signed else r'(?:0|[1-9][0-9]*)'
    if len(raw)>20 or not re.fullmatch(pattern,raw):raise Fault('VICI integer encoding')
    number=int(raw)
    if not minimum<=number<=maximum:raise Fault('VICI integer range')
    return number


def spi(section,key,width):
    raw=value(section,key)
    if not re.fullmatch('[0-9a-f]{'+str(width)+'}',raw) or int(raw,16)==0:
        raise Fault('VICI SPI encoding')
    return raw


def strings(section,key,limit=16):
    items=section.get(key)
    if type(items) is not list or len(items)>limit:raise Fault('VICI list field')
    return tuple(value({'v':item},'v') for item in items)


def exact_list(section,key,expected):
    actual=strings(section,key,len(expected))
    if len(actual)!=len(expected) or set(actual)!=set(expected):
        raise Fault('VICI exact dual-stack scope differs')


def proposal(fields,ike):
    cipher=value(fields,'encr-alg')
    if integer(fields,'encr-keysize',1,65535)!=256:raise Fault('VICI encryption key size')
    if 'integ-keysize' in fields:raise Fault('VICI unexpected integrity key size')
    if cipher=='AES_GCM_16':
        if 'integ-alg' in fields:raise Fault('VICI unexpected AEAD integrity transform')
        group='ECP_256'
    elif cipher=='AES_CBC':
        if value(fields,'integ-alg')!='HMAC_SHA2_256_128':raise Fault('VICI integrity transform')
        group='MODP_2048'
    else:raise Fault('VICI encryption transform')
    # The initial IKE_AUTH CHILD has no separate DH transform. Subsequent
    # CHILD proposals, when a DH field is present, must match the fixed suite.
    if ike or 'dh-group' in fields:
        if value(fields,'dh-group')!=group:raise Fault('VICI key exchange transform')
    if ike and value(fields,'prf-alg')!='PRF_HMAC_SHA2_256':raise Fault('VICI PRF transform')


def established_ike(fields,device,established=True,outer_endpoints=endpoints.IPV4):
    required=IKE_BASE|{'encr-alg','encr-keysize','prf-alg','dh-group'}
    if established:required=required|{'established'}
    section(fields,required,IKE_BASE|IKE_OPTIONAL)
    forbidden={'remote-eap-id','remote-xauth-id','local-vips','if-id-in','if-id-out','ppk'}
    forbidden.update('ake'+str(n) for n in range(1,8))
    if set(fields)&forbidden:raise Fault('VICI unsupported IKE feature')
    if value(fields,'local-id')!='vpn.family.home.arpa' or value(fields,'remote-id')!=device['ike_identity']:
        raise Fault('VICI registered authentication identity differs')
    local=value(fields,'local-host')
    if integer(fields,'local-port',1,65535)!=4500:
        raise Fault('VICI local endpoint differs')
    peer=value(fields,'remote-host')
    try:endpoints.pair(local,peer,outer_endpoints)
    except (ValueError,TypeError):raise Fault('VICI outer endpoint differs') from None
    port=integer(fields,'remote-port',1,65535)
    spi(fields,'initiator-spi',16);spi(fields,'responder-spi',16)
    for key in ('initiator','nat-local','nat-remote','nat-fake','nat-any'):
        if key in fields and value(fields,key)!='yes':raise Fault('VICI condition value')
    if established:integer(fields,'established',0,2**63-1)
    elif any(k in fields for k in ('established','rekey-time','reauth-time')):
        raise Fault('VICI non-established IKE has established-only statistics')
    for key in ('rekey-time','reauth-time'):
        if key in fields:integer(fields,key,-2**63,2**63-1,signed=True)
    for key in ('tasks-queued','tasks-active','tasks-passive'):
        if key in fields and any(not re.fullmatch('[A-Z][A-Z0-9_]*',s) for s in strings(fields,key)):
            raise Fault('VICI task name')
    proposal(fields,True)
    if 'remote-vips' in fields:exact_list(fields,'remote-vips',(device['vip4'],device['vip6']))
    return peer,port,local,4500


def parse_child(name,fields,ike,device,endpoint,seen_children,seen_reqid,outer_endpoints=endpoints.IPV4):
    section(fields,CHILD_BASE,CHILD_BASE|CHILD_IPSEC)
    ident=integer(fields,'uniqueid',1,2**32-1)
    if name!='internet-'+str(ident) or value(fields,'name')!='internet':
        raise Fault('VICI CHILD configuration identity differs')
    if ident in seen_children:raise Fault('VICI duplicate CHILD unique identity')
    seen_children.add(ident)
    if value(fields,'mode')!='TUNNEL':raise Fault('VICI CHILD mode')
    state=value(fields,'state')
    reqid=integer(fields,'reqid',0,2**32-1)
    if reqid:
        owner=device['device_id']
        if reqid in seen_reqid and seen_reqid[reqid]!=owner:
            raise Fault('VICI cross-device reqid ownership')
        seen_reqid[reqid]=owner
    if state in PARTIAL_CHILD:
        section(fields,CHILD_BASE,CHILD_BASE)
        strings(fields,'local-ts');strings(fields,'remote-ts')
        return state,None,False
    if state not in COMPLETE_CHILD:raise Fault('VICI unsupported CHILD state')
    section(fields,CHILD_BASE|{'protocol','encap','spi-in','spi-out','encr-alg','encr-keysize',
        'bytes-in','bytes-out','packets-in','packets-out','install-time'},CHILD_BASE|CHILD_IPSEC)
    if value(fields,'protocol')!='ESP' or value(fields,'encap')!='yes':
        raise Fault('VICI ESP UDP encapsulation required')
    exact_list(ike,'remote-vips',(device['vip4'],device['vip6']))
    # A structurally valid local scope mismatch makes this entire device
    # unready, not an unknown fleet inventory. Keep checking every other
    # field and retain its generation for complete ownership/overlap checks.
    local_ts=strings(fields,'local-ts')
    scope_ready=len(local_ts)==2 and set(local_ts)=={'0.0.0.0/0','::/0'}
    exact_list(fields,'remote-ts',(device['vip4']+'/32',device['vip6']+'/128'))
    proposal(fields,False)
    for key in ('bytes-in','bytes-out','packets-in','packets-out','use-in','use-out'):
        if key in fields:integer(fields,key)
    integer(fields,'install-time',0,2**63-1)
    for key in ('rekey-time','life-time'):
        if key in fields:integer(fields,key,-2**63,2**63-1,signed=True)
    generation=Generation(integer(ike,'uniqueid',1,2**32-1),ident,
        integer(fields,'reqid',1,2**32-1),device['ike_identity'],endpoint[0],endpoint[1],
        endpoint[2],endpoint[3],device['vip4'],device['vip6'],spi(fields,'spi-in',8),spi(fields,'spi-out',8))
    checked_generation(generation,device,outer_endpoints)
    return state,generation,scope_ready


def parse_events(events,registry,outer_endpoints=endpoints.IPV4):
    """Return every registered device, preserving ambiguity without a winner.

    CREATED/CONNECTING may contain an attacker-claimed name or identity. They
    increase only an unattributed count; never erase an authenticated device.
    The upper layer must still audit the entire native policy inventory.
    Mapped, fully checked DELETING/REKEYING IKEs with data-plane scope produce pending/overlap only,
    never unique; established-only statistics must be absent as upstream emits.
    A complete CHILD with nonmatching local-ts retains its actual state and
    ownership metadata but cannot make its device unique/ready.
    Other states and duplicate inherited CHILD ownership remain unsupported.
    """
    outer_endpoints=endpoints.normalize(outer_endpoints)
    registry=normalize(registry)
    bounded_tree(events)
    devices={d['device_id']:d for d in registry['devices']}
    names={'family-vpn-'+i:i for i in devices}
    groups={i:[] for i in devices}
    seen_ike=set();seen_children=set();seen_reqid={};pending=0;complete_count=0
    for event in events:
        if not isinstance(event,dict) or len(event)!=1:raise Fault('VICI event shape')
        name,ike=next(iter(event.items()))
        section(ike,{'uniqueid','version','state'},IKE_BASE|IKE_OPTIONAL)
        ident=integer(ike,'uniqueid',1,2**32-1)
        if ident in seen_ike:raise Fault('VICI duplicate IKE unique identity')
        seen_ike.add(ident)
        if integer(ike,'version',2,2)!=2:raise Fault('VICI IKE version')
        state=value(ike,'state')
        if state in ('CREATED','CONNECTING'):
            pending+=1
            if pending>MAX_IKE_EVENTS:raise Fault('VICI pending IKE bound')
            continue
        if state not in ('ESTABLISHED','DELETING','REKEYING','REKEYED'):raise Fault('VICI unsupported IKE lifecycle state')
        if name not in names:raise Fault('VICI unknown established connection')
        device=devices[names[name]]
        endpoint=established_ike(ike,device,established=state=='ESTABLISHED',outer_endpoints=outer_endpoints)
        children=ike['child-sas']
        if not isinstance(children,dict) or len(children)>MAX_CHILDREN_PER_IKE:raise Fault('VICI CHILD section bound')
        # Every authenticated event is fully checked within the unchanged
        # complete-read event/tree/byte budgets. Repeated ordinary reconnects
        # can retain several resource IKEs; no per-device IKE count picks a
        # winner or makes other devices unavailable. Empty REKEYED IKEs have
        # inherited all CHILDs/VIPs and contribute no data-plane generation.
        if state=='REKEYED':
            if children or 'remote-vips' in ike:
                raise Fault('VICI rekeyed IKE retains CHILD or virtual IP')
            continue
        if state=='DELETING' and not children and 'remote-vips' not in ike:
            continue
        records=[parse_child(key,fields,ike,device,endpoint,seen_children,seen_reqid,outer_endpoints) for key,fields in children.items()]
        complete_count+=sum(g is not None for _,g,_scope_ready in records)
        if complete_count>MAX_GENERATIONS:raise Fault('VICI fleet complete generation budget')
        groups[device['device_id']].append((state,records))
    snapshots={};seen_in={};seen_out={}
    for ident,ikes in groups.items():
        if not ikes:
            snapshots[ident]=Snapshot('absent')
            continue
        records=[record for _state,children in ikes for record in children]
        complete=[(state,g) for state,g,_scope_ready in records if g is not None]
        scope_ready=all(ready for _state,_generation,ready in records)
        if len(complete)>MAX_GENERATIONS:raise Fault('VICI complete generation bound')
        complete.sort(key=lambda row:(row[1].ike_id,row[1].child_id))
        generations=tuple(g for _,g in complete)
        generation_groups(generations)
        # Keep every complete retired generation, even on the first poll or
        # with no current INSTALLED sibling. Closed metadata does not grant
        # forwarding, deletion, or permission to select another winner.
        for g in generations:
            for seen,key in ((seen_in,(g.local4,g.spi_in)),(seen_out,(g.peer4,g.spi_out))):
                if key in seen:raise Fault('VICI duplicate endpoint SPI ownership')
                seen[key]=(ident,g.child_id)
        deleted=tuple(g for state,g in complete if state=='DELETED')
        if len(generations)>=2:kind='overlap'
        elif len(ikes)==1 and ikes[0][0]=='ESTABLISHED' and len(records)==1 and complete and complete[0][0]=='INSTALLED' and scope_ready:kind='unique'
        else:kind='pending'
        pair=()
        # Keep the real overlap and every checked sibling; this annotation alone
        # grants no cold admission. Only the exact observed retirement shape.
        if (kind=='overlap' and len(ikes)==1 and ikes[0][0]=='ESTABLISHED'
                and len(records)==2 and len(complete)==2 and scope_ready
                and sorted(state for state,_g in complete)==['DELETED','INSTALLED']):
            old=next(g for state,g in complete if state=='DELETED')
            new=next(g for state,g in complete if state=='INSTALLED')
            from fleet_policy import same_child_authority
            if same_child_authority(old,new):pair=(old,new)
        snapshot=Snapshot(kind,generations,deleted=deleted,rekey_pair=pair)
        checked_snapshot(snapshot)
        snapshots[ident]=snapshot
    return ParseResult(snapshots,pending)
