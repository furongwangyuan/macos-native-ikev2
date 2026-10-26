"""Pure fleet-wide SPD inventory and exact-active-set rule candidate.

No VICI, syscalls, sockets, PF loading or deletion. Inputs must come from a
separately trusted adapter. A metadata proof does not prove ESP ingress source
authentication, actual kernel liveness, or atomic snapshot/activation.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

from registry import normalize
import outer_endpoints as endpoints

BASE_TEMPLATE_SHA256 = 'd8a7ed883f5056cd6c2ebc45de62435e792733225cc462714729fad9c2e3c463'
# Keep the existing complete-read resource budgets. Distribution across devices
# may vary while one device reconnects; readiness is still exactly four rows.
MAX_POLICY_RECORDS = 3 + 16 * (8 + 2)
MAX_HOST_RECORDS = MAX_POLICY_RECORDS - 3
MAX_IKE_EVENTS = 48
# The existing VICI section limit is a resource budget, not a protocol
# maximum. Retired CHILDs can accumulate across normal rapid MOBIKE rekeys.
MAX_CHILDREN_PER_IKE = 64
MAX_GENERATIONS = 144

class Fault(ValueError):
    pass


class PolicyTransition(Fault):
    """An unmatched host requires a closed, independently rechecked snapshot."""
    pass


@dataclass(frozen=True)
class Generation:
    ike_id: int
    child_id: int
    reqid: int
    remote_id: str
    peer4: str
    peer_port: int
    local4: str
    local_port: int
    vip4: str
    vip6: str
    spi_in: str
    spi_out: str


@dataclass(frozen=True)
class Snapshot:
    kind: str
    generations: tuple = ()
    deleted: tuple = ()
    # Compatibility-only annotation; never grants readiness or provenance.
    # New parser outputs leave this empty.
    installed: tuple = ()
    # Closed, fully checked facts only; never admission without a current proof.
    # Exactly (DELETED old, INSTALLED new), with every sibling full-scope.
    rekey_pair: tuple = ()


@dataclass(frozen=True)
class DeviceProof:
    device_id: str
    ready: bool
    generation: object
    hosts: tuple
    policy_ids: tuple


@dataclass(frozen=True)
class FleetProof:
    registry_sha256: str
    native: tuple
    devices: tuple
    outer_endpoints: tuple = endpoints.IPV4


def registry_digest(registry):
    return hashlib.sha256(json.dumps(normalize(registry),sort_keys=True,
        separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def record_key(record):
    fields={'id','src','dst','direction','kind','requests'}
    if (type(record) is not dict or set(record)!=fields or type(record['id']) is not int
            or not 0<record['id']<2**32 or record['direction'] not in ('in','out')
            or record['kind'] not in ('ipsec','generate','discard')
            or type(record['requests']) is not list or len(record['requests'])>1
            or any(type(item) is not str or len(item)>160 for item in record['requests'])):
        raise Fault('malformed policy metadata')
    try:
        src=ipaddress.ip_network(record['src'],strict=True)
        dst=ipaddress.ip_network(record['dst'],strict=True)
        if str(src)!=record['src'] or str(dst)!=record['dst'] or src.version!=dst.version:
            raise ValueError()
    except (ValueError,TypeError):
        raise Fault('noncanonical policy selectors') from None
    return (record['id'],record['src'],record['dst'],record['direction'],record['kind'],tuple(record['requests']))


def record_from_key(key):
    if type(key) is not tuple or len(key)!=6 or type(key[5]) is not tuple:
        raise Fault('invalid frozen policy metadata')
    result=dict(zip(('id','src','dst','direction','kind'),key[:5]))
    result['requests']=list(key[5])
    if record_key(result)!=key:raise Fault('invalid frozen policy metadata')
    return result


def native_keys(owned):
    if type(owned) is not list or len(owned)!=3:raise Fault('three native owned policies required')
    keys=tuple(sorted(record_key(r) for r in owned))
    if len({r[0] for r in keys})!=3:raise Fault('duplicate native identity')
    scopes={(r[1],r[2],r[3],r[4],r[5]) for r in keys}
    if scopes!={('0.0.0.0/0','10.77.26.0/24','out','generate',()),
                ('::/0','fd6d:fe83:ab27:2600::/64','out','generate',()),
                ('0.0.0.0/0','10.77.26.253/32','out','discard',())}:
        raise Fault('native floor and keeper scope differs')
    return keys


def validate_proof(proof,registry=None,outer_endpoints=None):
    """Check transport invariants; this is not a signature or freshness proof.

    Only current in-memory audit outputs may reach an eventual privileged
    adapter. Deserializing metadata cannot acquire permission through this API.
    """
    if (type(proof) is not FleetProof or type(proof.registry_sha256) is not str
            or not re.fullmatch('[0-9a-f]{64}',proof.registry_sha256)
            or type(proof.native) is not tuple or type(proof.devices) is not tuple
            or not 1<=len(proof.devices)<=16):raise Fault('invalid fleet proof structure')
    scope=endpoints.normalize(proof.outer_endpoints)
    if outer_endpoints is not None and scope!=endpoints.normalize(outer_endpoints):raise Fault('proof outer scope differs')
    owned=[record_from_key(k) for k in proof.native]
    if native_keys(owned)!=proof.native:raise Fault('invalid native proof')
    byid=None if registry is None else {d['device_id']:d for d in normalize(registry)['devices']}
    if registry is not None and registry_digest(registry)!=proof.registry_sha256:raise Fault('registry proof differs')
    seen_ids=set(k[0] for k in proof.native);devices=set();host_count=0
    for d in proof.devices:
        if (type(d) is not DeviceProof or type(d.device_id) is not str
                or not re.fullmatch('[a-z][a-z0-9-]{0,30}[a-z0-9]',d.device_id)
                or d.device_id in devices or type(d.ready) is not bool
                or type(d.hosts) is not tuple or len(d.hosts)>MAX_HOST_RECORDS or type(d.policy_ids) is not tuple
                or any(type(i) is not int or not 0<i<2**32 for i in d.policy_ids)):
            raise Fault('invalid device proof structure')
        host_count+=len(d.hosts)
        if host_count>MAX_HOST_RECORDS:raise Fault('fleet host proof budget')
        devices.add(d.device_id)
        if byid is not None and d.device_id not in byid:raise Fault('unknown proof device')
        hosts=[record_from_key(k) for k in d.hosts]
        if tuple(sorted(d.hosts))!=d.hosts:raise Fault('unordered host proof')
        for r in hosts:
            if r['kind']!='ipsec' or r['id'] in seen_ids:raise Fault('duplicate or non-host proof')
            seen_ids.add(r['id'])
        if d.generation is not None:
            if type(d.generation) is not Generation:raise Fault('invalid proof generation')
            descriptor=byid[d.device_id] if byid is not None else normalize(dict(version=1,revision=1,
                usage_timezone='Asia/Kuala_Lumpur',devices=[dict(device_id=d.device_id,display_name='proof',
                ike_identity=d.device_id+'.family.home.arpa',state='enabled',
                vip4=d.generation.vip4,vip6=d.generation.vip6)]))['devices'][0]
            checked_generation(d.generation,descriptor,scope)
        if d.ready:
            if (d.generation is None or len(hosts)!=4 or d.policy_ids!=tuple(sorted(r['id'] for r in hosts))
                    or len({(r['direction'],r['src'],r['dst']) for r in hosts})!=4
                    or not all(host_matches(r,d.generation) for r in hosts)
                    or (byid is not None and byid[d.device_id]['state']!='enabled')):
                raise Fault('ready proof lacks exact complete host policy metadata')
        elif d.policy_ids:
            raise Fault('guarded device cannot hold active policy IDs')
    if byid is not None and devices!=set(byid):raise Fault('incomplete proof device scope')


def checked_generation(g, device, outer_endpoints=endpoints.IPV4):
    if type(g) is not Generation:raise Fault('normalized generation required')
    if any(type(getattr(g,k)) is not int or not 0<getattr(g,k)<2**32 for k in ('ike_id','child_id','reqid')):
        raise Fault('invalid generation identifier')
    if (g.remote_id,g.vip4,g.vip6)!=(device['ike_identity'],device['vip4'],device['vip6']):
        raise Fault('generation and permanent registered identity differ')
    if type(g.local_port) is not int or g.local_port!=4500:
        raise Fault('unexpected local endpoint')
    if type(g.peer_port) is not int or not 1<=g.peer_port<=65535:raise Fault('unexpected peer port')
    try:endpoints.pair(g.local4,g.peer4,outer_endpoints)
    except (ValueError,TypeError):raise Fault('unexpected outer endpoint') from None
    if any(type(s) is not str or not re.fullmatch('[0-9a-f]{8}',s) or int(s,16)==0
           for s in (g.spi_in,g.spi_out)):raise Fault('unexpected ESP SPI')


def generation_groups(generations):
    """Apply independent global and per-section complete-read budgets."""
    if (type(generations) is not tuple or len(generations)>MAX_GENERATIONS
            or any(type(g) is not Generation for g in generations)):
        raise Fault('invalid grouped generations')
    groups={}
    for g in generations:groups.setdefault(g.ike_id,[]).append(g)
    if len(groups)>MAX_IKE_EVENTS or any(len(group)>MAX_CHILDREN_PER_IKE for group in groups.values()):
        raise Fault('grouped IKE or CHILD bound')
    return tuple(tuple(group) for group in groups.values())


def checked_snapshot(snapshot):
    """Validate closed metadata, without deriving permission from retirement.

    A complete authenticated DELETED CHILD may be the first row observed.
    It stays in the snapshot and cannot make an INSTALLED sibling unique.
    Identity, SPI ownership and the complete SPD inventory are checked by audit.
    """
    bounds={'absent':(0,),'pending':(0,1),'unique':(1,),'overlap':range(2,MAX_GENERATIONS+1)}
    if (type(snapshot) is not Snapshot or snapshot.kind not in bounds
            or type(snapshot.generations) is not tuple
            or len(snapshot.generations) not in bounds[snapshot.kind]):
        raise Fault('invalid normalized fleet snapshot')
    generation_groups(snapshot.generations)
    if len(set(snapshot.generations))!=len(snapshot.generations):raise Fault('duplicate generation')
    if (type(snapshot.deleted) is not tuple or len(snapshot.deleted)>MAX_GENERATIONS
            or len(set(snapshot.deleted))!=len(snapshot.deleted)
            or any(g not in snapshot.generations for g in snapshot.deleted)
            or (snapshot.deleted and snapshot.kind not in ('pending','overlap'))):
        raise Fault('invalid deleted generation metadata')
    if (type(snapshot.installed) is not tuple or len(snapshot.installed)>MAX_IKE_EVENTS
            or len(set(snapshot.installed))!=len(snapshot.installed)
            or any(g not in snapshot.generations or g in snapshot.deleted for g in snapshot.installed)
            or (snapshot.installed and snapshot.kind!='overlap')):
        raise Fault('invalid compatibility installed annotation')
    pair=snapshot.rekey_pair
    if (type(pair) is not tuple or len(pair) not in (0,2)
            or (pair and (snapshot.kind!='overlap' or len(snapshot.generations)!=2
                or set(pair)!=set(snapshot.generations) or snapshot.deleted!=(pair[0],)
                or not same_child_authority(pair[0],pair[1])))):
        raise Fault('invalid complete rekey annotation')


def same_child_authority(old,new):
    """A CHILD replacement changes only its ID and both SPIs, never authority."""
    if type(old) is not Generation or type(new) is not Generation:return False
    changed=('child_id','spi_in','spi_out')
    return (all(getattr(old,k)==getattr(new,k) for k in Generation.__dataclass_fields__ if k not in changed)
            and all(getattr(old,k)!=getattr(new,k) for k in changed))


def continuation_target(snapshot,current):
    checked_snapshot(snapshot)
    if snapshot.kind=='unique':
        target=snapshot.generations[0]
        return target if target==current or same_child_authority(current,target) else None
    if snapshot.rekey_pair and current in snapshot.rekey_pair:return snapshot.rekey_pair[1]
    return None


def same_device_authority(old,new):
    return (type(old) is DeviceProof and type(new) is DeviceProof and old.ready is True and new.ready is True
            and old.device_id==new.device_id and old.hosts==new.hosts and old.policy_ids==new.policy_ids
            and (old.generation==new.generation or same_child_authority(old.generation,new.generation)))


def host_matches(r,g):
    for family,vip in ((4,g.vip4),(6,g.vip6)):
        host=str(ipaddress.ip_network(vip)); anynet='0.0.0.0/0' if family==4 else '::/0'
        for direction in ('in','out'):
            src,dst=(host,anynet) if direction=='in' else (anynet,host)
            outer=(g.peer4,g.local4) if direction=='in' else (g.local4,g.peer4)
            req='esp/tunnel/'+'-'.join(outer)+'/unique'
            if (r['src'],r['dst'],r['direction'],r['kind'])==(src,dst,direction,'ipsec'):
                return r['requests'] in ([req+':'+str(g.reqid)],[req+'#'+str(g.reqid)])
    return False



def host_request_reqid(record,outer_endpoints=endpoints.IPV4):
    """Validate one exact host tunnel request, without inferring authentication."""
    requests=record['requests']
    match=(re.fullmatch(r'esp/tunnel/([^/\s]+)-([^/\s]+)/unique[:#]([1-9][0-9]{0,9})',requests[0])
           if len(requests)==1 else None)
    if match is None or not 0<int(match[3])<2**32:
        raise Fault('host tunnel request differs')
    outer_in,outer_out=match[1],match[2]
    peer,local=(outer_in,outer_out) if record['direction']=='in' else (outer_out,outer_in)
    try:endpoints.pair(local,peer,outer_endpoints)
    except (ValueError,TypeError):raise Fault('host tunnel endpoint differs') from None
    return int(match[3])


def audit(registry,snapshots,records,active,owned_native,remembered=None,handovers=None,outer_endpoints=endpoints.IPV4,continuing=None):
    """Return independent device readiness after validating the entire inventory.

    Exact remembered keys come only from a previous complete inventory audit,
    including closed exclusive-selector scope during installation/teardown.
    These keys never activate a device. This function does not grant deletion
    ownership. Cold overlapping CHILD/IKE generations stay closed. The optional
    continuing input must be the adapter's actual published active proof; only
    its completely checked retirement pair may carry the same permission.
    """
    outer_endpoints=endpoints.normalize(outer_endpoints)
    registry=normalize(registry)
    devices={d['device_id']:d for d in registry['devices']}
    continuing={} if continuing is None else continuing
    if (type(continuing) is not dict or not set(continuing)<=set(devices)
            or any(type(d) is not DeviceProof or d.ready is not True or d.device_id!=i for i,d in continuing.items())):
        raise Fault('invalid active continuity provenance')
    for ident,d in continuing.items():
        checked_generation(d.generation,devices[ident],outer_endpoints)
        hosts=[record_from_key(k) for k in d.hosts]
        if (len(hosts)!=4 or d.hosts!=tuple(sorted(d.hosts))
                or d.policy_ids!=tuple(sorted(r['id'] for r in hosts))
                or len({(r['direction'],r['src'],r['dst']) for r in hosts})!=4
                or not all(host_matches(r,d.generation) for r in hosts)):
            raise Fault('incomplete active continuity proof')
    if type(snapshots) is not dict or set(snapshots)!=set(devices):raise Fault('incomplete fleet snapshot')
    remembered={} if remembered is None else remembered
    if type(remembered) is not dict or not set(remembered)<=set(devices):raise Fault('unknown remembered device')
    handovers={} if handovers is None else handovers
    if type(handovers) is not dict or not set(handovers)<=set(devices):
        raise Fault('unknown handover device')
    for ident,history in handovers.items():
        if type(history) is not tuple or len(history) not in (2,4):
            raise Fault('invalid handover provenance')
        for old,mapped in zip(history[::2],history[1::2]):
            checked_generation(old,devices[ident],outer_endpoints);checked_generation(mapped,devices[ident],outer_endpoints)
            # Only the validated outer endpoints may differ. The extra pair is at most
            # one previously retired CHILD, retained solely as closed history.
            old_fields=tuple(getattr(old,k) for k in Generation.__dataclass_fields__ if k not in ('peer4','peer_port','local4','local_port'))
            mapped_fields=tuple(getattr(mapped,k) for k in Generation.__dataclass_fields__ if k not in ('peer4','peer_port','local4','local_port'))
            if old_fields!=mapped_fields:
                raise Fault('handover provenance changed beyond endpoint')
    seen_child={}; seen_reqid={}; seen_ike={}; seen_in={}; seen_out={}
    generation_count=0;ike_count=0;remembered_count=0
    for ident,snapshot in snapshots.items():
        checked_snapshot(snapshot)
        generation_count+=len(snapshot.generations)
        ike_count+=len({g.ike_id for g in snapshot.generations})
        if generation_count>MAX_GENERATIONS or ike_count>MAX_IKE_EVENTS:
            raise Fault('fleet normalized generation budget')
        for g in snapshot.generations:
            checked_generation(g,devices[ident],outer_endpoints)
            for seen,value,label in ((seen_child,g.child_id,'CHILD'),(seen_reqid,g.reqid,'reqid'),(seen_ike,g.ike_id,'IKE')):
                if value in seen and seen[value]!=ident:raise Fault('cross-device '+label+' reuse')
                seen[value]=ident
            child_identity=(ident,g.child_id,g.reqid,g.peer4,g.local4,g.spi_in,g.spi_out)
            for seen,key in ((seen_in,(g.local4,g.spi_in)),(seen_out,(g.peer4,g.spi_out))):
                if key in seen and seen[key]!=child_identity:raise Fault('duplicate endpoint SPI ownership')
                seen[key]=child_identity
        known=remembered.get(ident,())
        if type(known) is not tuple or len(known)>MAX_HOST_RECORDS or any(type(k) is not tuple or len(k)!=6 for k in known):
            raise Fault('invalid remembered metadata')
        remembered_count+=len(known)
        if remembered_count>MAX_HOST_RECORDS:raise Fault('fleet remembered metadata budget')
        for key in known:
            restored=dict(zip(('id','src','dst','direction','kind'),key[:5]))
            if type(key[5]) is not tuple:raise Fault('invalid remembered requests')
            restored['requests']=list(key[5])
            if record_key(restored)!=key or restored['kind']!='ipsec':raise Fault('invalid remembered policy')
            device=devices[ident]
            selectors=set()
            for family,vip in ((4,device['vip4']),(6,device['vip6'])):
                host=str(ipaddress.ip_network(vip));anynet='0.0.0.0/0' if family==4 else '::/0'
                selectors.update((('in',host,anynet),('out',anynet,host)))
            if (restored['direction'],restored['src'],restored['dst']) not in selectors:
                raise Fault('remembered host belongs to another registration')
    native=native_keys(owned_native)
    if type(records) is not list or len(records)>MAX_POLICY_RECORDS or type(active) is not dict:
        raise Fault('policy inventory bound')
    keys=[record_key(r) for r in records]
    ids={r['id'] for r in records}
    if (len(ids)!=len(records) or set(active)!=ids
            or any(type(k) is not int or not 0<k<2**32 for k in active)
            or any(type(v) is not bool for v in active.values())):
        raise Fault('incomplete exact-ID policy activity')
    actual_native=tuple(sorted(record_key(r) for r in records if r['kind']!='ipsec'))
    if not set(native)<=set(actual_native) or not all(active[k[0]] for k in native):
        raise Fault('native ownership changed or inactive')
    extra=set(actual_native)-set(native)
    blocked=set()
    if extra:
        # A MOBIKE update can briefly install outbound DROP for one device.
        # Only an exact, uniquely attributed authenticated VIP is recognized;
        # the DROP is never owned, removed, or added to the native proof.
        # Continue auditing every host row before keeping other devices ready.
        allowed={}
        origins=[(ident,g) for ident,snapshot in snapshots.items() for g in snapshot.generations]
        origins.extend((ident,old) for ident,history in handovers.items() for old in history[::2])
        for ident,old in origins:
            for selector in (('0.0.0.0/0',old.vip4+'/32','out','discard',()),
                             ('::/0',old.vip6+'/128','out','discard',())):
                allowed.setdefault(selector,set()).add(ident)
        if (len(extra)>len(allowed) or len({k[1:] for k in extra})!=len(extra)
                or any(len(allowed.get(k[1:],()))!=1 for k in extra)):
            raise Fault('native ownership changed or inactive')
        for key in extra:
            blocked.update(allowed[key[1:]])
    # All registered addresses, generation identities and remembered keys were
    # fully checked above. A host selector can belong to only one registration;
    # use that exact scope to avoid matching every other device's generations.
    owner_by_selector={}
    for ident,device in devices.items():
        for host,anynet in ((device['vip4']+'/32','0.0.0.0/0'),
                            (device['vip6']+'/128','::/0')):
            owner_by_selector[('in',host,anynet)]=ident
            owner_by_selector[('out',anynet,host)]=ident
    assigned={ident:[] for ident in devices}
    active_host_reqids={}
    selectors=set()
    for r,key in zip(records,keys):
        if r['kind']!='ipsec':continue
        sel=(r['direction'],r['src'],r['dst'])
        if active[r['id']]:
            if sel in selectors:raise Fault('duplicate active host selector')
            selectors.add(sel)
        owners=[]
        ident=owner_by_selector.get(sel)
        if ident is not None:
            snapshot=snapshots[ident]
            if not (any(host_matches(r,g) for g in snapshot.generations)
                    or any(host_matches(r,g) for g in handovers.get(ident,()))
                    or key in remembered.get(ident,())):
                # VICI and the kernel inventory are independent reads. A new
                # host policy may appear before its authenticated CHILD is in
                # this snapshot. Its exact exclusive selector is closed scope
                # only: retain the metadata, never choose a generation or
                # grant forwarding/deletion rights. Other rows still undergo
                # the complete audit, including native and reqid ownership.
                host_request_reqid(r,outer_endpoints)
                blocked.add(ident)
            # Existing authenticated/remembered matches keep their original
            # semantics. Only current active SPD rows can conflict with a new
            # closed row: released reqids may be reused while DEAD rows or an
            # earlier VICI generation remain visible.
            if active[r['id']] and len(r['requests'])==1:
                reqid_match=re.search(r'/unique[:#]([1-9][0-9]*)$',r['requests'][0])
                if reqid_match:
                    active_host_reqids.setdefault(int(reqid_match[1]),set()).add(ident)
            owners.append(ident)
        if not owners:raise PolicyTransition('fleet_host_policy_transition')
        if len(owners)!=1:raise Fault('unknown or multiply attributed host policy')
        assigned[owners[0]].append(r)
    if any(len(owners)!=1 for owners in active_host_reqids.values()):
        raise Fault('cross-device active host reqid reuse')
    result=[]
    for ident in sorted(devices):
        snapshot=snapshots[ident]; hosts=assigned[ident]
        g=snapshot.generations[0] if snapshot.kind=='unique' else None
        previous=continuing.get(ident)
        if g is None and previous is not None:
            g=continuation_target(snapshot,previous.generation)
        ready=bool(ident not in blocked and devices[ident]['state']=='enabled' and g is not None and len(hosts)==4
            and all(active[r['id']] and host_matches(r,g) for r in hosts))
        if snapshot.kind!='unique' and ready:
            ready=(tuple(sorted(record_key(r) for r in hosts))==previous.hosts
                   and tuple(sorted(r['id'] for r in hosts))==previous.policy_ids)
        result.append(DeviceProof(ident,ready,g,tuple(sorted(record_key(r) for r in hosts)),
                                  tuple(sorted(r['id'] for r in hosts)) if ready else ()))
    proof=FleetProof(registry_digest(registry),native,tuple(result),outer_endpoints)
    validate_proof(proof,registry)
    return proof


def transition(previous,current):
    """Plan which existing device gates must close before adding replacements.

    This does not execute a PF transaction or clear states. Global floor identity
    must remain fixed. A registry change requires a separate guarded transaction.
    """
    validate_proof(current)
    if previous is not None:validate_proof(previous)
    if previous is not None and (previous.native!=current.native or previous.registry_sha256!=current.registry_sha256 or previous.outer_endpoints!=current.outer_endpoints):
        raise Fault('registry or native scope changed; full guarded transaction required')
    before={} if previous is None else {d.device_id:d for d in previous.devices if d.ready}
    after={d.device_id:d for d in current.devices if d.ready}
    keep=tuple(sorted(i for i in before if i in after and before[i]==after[i]))
    return dict(keep=keep,close=tuple(sorted(set(before)-set(keep))),
                open=tuple(sorted(set(after)-set(keep))))


def render(template,registry,proof):
    """Render an offline exact-set candidate; never load it into PF."""
    validate_proof(proof,registry)
    if type(template) is not str or hashlib.sha256(template.encode()).hexdigest()!=BASE_TEMPLATE_SHA256:
        raise Fault('reviewed base template changed')
    ready=[d.generation for d in proof.devices if d.ready]
    expected=normalize(registry)
    byid={d['device_id']:d for d in expected['devices']}
    if (type(proof.devices) is not tuple or len(proof.devices)!=len(byid)
            or any(type(d) is not DeviceProof or type(d.ready) is not bool for d in proof.devices)
            or set(d.device_id for d in proof.devices)!=set(byid)):
        raise Fault('proof device scope differs')
    for d in proof.devices:
        if d.ready:
            if byid[d.device_id]['state']!='enabled':raise Fault('disabled registration cannot be activated')
            checked_generation(d.generation,byid[d.device_id],proof.outer_endpoints)
    markers={'# ACTIVE_IPV4_RETURN_RULE':
        'pass out quick on $wan inet from any to <familyvpn_active4> tagged FAMILYVPN_EGRESS4 no state label "familyvpn_return4"',
        'table <familyvpn_home4>':
        'table <familyvpn_active4> const { '+', '.join(sorted(g.vip4+'/32' for g in ready))+' }\n'+
        'table <familyvpn_active6> const { '+', '.join(sorted(g.vip6+'/128' for g in ready))+' }\ntable <familyvpn_home4>',
        'pass in quick on $wan inet proto udp to ($wan) port { 500, 4500 }':
        'pass in quick on $wan inet proto udp from any to 192.0.2.8 port { 500, 4500 }'}
    for version,family in ((4,'inet'),(6,'inet6')):
        for start,end in (('nat on $wan '+family+' from <familyvpn_v'+str(version)+'> to !',
                          'nat on $wan '+family+' from <familyvpn_active'+str(version)+'> to !'),
                         ('pass in quick on $wan '+family+' from <familyvpn_v'+str(version)+'> to any no state',
                          'pass in quick on $wan '+family+' from <familyvpn_active'+str(version)+'> to any no state')):
            markers[start]=end
    for old,new in markers.items():
        if template.count(old)!=1:raise Fault('fixed template structure differs')
        template=template.replace(old,new,1)
    if len(proof.outer_endpoints)==2:
        marker='pass in quick on $wan inet proto udp from any to 192.0.2.8 port { 500, 4500 } keep state (if-bound) label "familyvpn_ike"'
        addition='pass in quick on $wan inet6 proto udp from any to '+proof.outer_endpoints[1]+' port { 500, 4500 } keep state (if-bound) label "familyvpn_ike6"'
        template=template.replace(marker,marker+'\n'+addition,1)
    return template
