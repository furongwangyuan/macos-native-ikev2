"""Candidate registry attribution of official VICI list-sa events to telemetry rows.

Only selected counters leave this function. Network addresses and raw events
are not persisted. This is observation, never an authorization/control path.
"""
import hashlib
import math
import re

from registry import normalize, monitor_maps

class Unavailable(ValueError):
    pass

def field(row, key):
    value = row.get(key)
    if not isinstance(value, bytes) or len(value) > 256:
        raise Unavailable('unrecognized VICI field')
    return value.decode('ascii', errors='strict')

def integer(row, key, maximum=2**64-1):
    value = field(row,key)
    if not re.fullmatch(r'0|[1-9][0-9]{0,19}',value) or int(value)>maximum:
        raise Unavailable('invalid VICI integer')
    return int(value)

def exact_values(row, key, expected):
    raw=row.get(key)
    if type(raw)is not list or len(raw)!=len(expected):
        raise Unavailable('incomplete transition scope')
    values=[field({'value':value},'value') for value in raw]
    if len(set(values))!=len(values) or set(values)!=set(expected):
        raise Unavailable('transition scope differs')

def transition_scope(ike, device, child=None):
    # These extra checks only admit a non-accounting, unknown observation.
    # They never select a replacement CHILD or authorize any VPN traffic.
    exact_values(ike,'remote-vips',(device['vip4'],device['vip6']))
    if child is not None:
        if not integer(child,'reqid',2**32-1):raise Unavailable('invalid transition reqid')
        exact_values(child,'local-ts',('0.0.0.0/0','::/0'))
        exact_values(child,'remote-ts',(device['vip4']+'/32',device['vip6']+'/128'))

def parse_events(events, daemon_epoch, wall, registry, *, allow_legacy_device01=False, with_unknown=False):
    """Observe exact registered identities; this never grants authorization.

    Disabled/revoked records remain attributable if a residual live SA is seen.
    The legacy contract rejects incomplete samples as a whole. With explicit
    unknown-device output, only narrowly checked transitions are isolated; an
    unknown device never supplies a false OFF or measured zero. The caller must
    verify the private VICI source.
    """
    registry = normalize(registry)
    if type(allow_legacy_device01) is not bool or type(with_unknown) is not bool:
        raise Unavailable('invalid legacy compatibility mode')
    identity_map = monitor_maps(registry)['identities']
    device_map = {d['device_id']:d for d in registry['devices']}
    connection_map = {'family-vpn-'+d['device_id']: d['device_id'] for d in registry['devices']}
    if allow_legacy_device01 and 'device01' in connection_map.values():
        connection_map['family-vpn'] = 'device01'
    ike_ids=set(); device_ikes={}; counted_ikes={}
    if (not isinstance(events,list) or len(events)>(48 if with_unknown else 32) or type(daemon_epoch) is not str or not re.fullmatch('[0-9a-f]{64}',daemon_epoch)
            or type(wall) not in (int,float) or not math.isfinite(wall) or wall<0):
        raise Unavailable('invalid sample envelope')
    rows=[]; identities=set(); child_ids=set(); unknown=set(); authenticated=set(); retired=set(); preauth=0
    for event in events:
        if not isinstance(event,dict) or len(event)!=1:
            raise Unavailable('unexpected filtered IKE event')
        name=next(iter(event))
        if not isinstance(name,str) or not isinstance(event[name],dict):
            raise Unavailable('unregistered connection name')
        ike=event[name]
        state=field(ike,'state')
        if state in ('CREATED','CONNECTING') and with_unknown:
            # Pre-authentication names/remote IDs cannot identify a device.
            # Keep verified established devices, but do not infer the others
            # are offline just because no authenticated CHILD was observed.
            if (name not in connection_map and name!='(unnamed)') or field(ike,'version')!='2':
                raise Unavailable('unexpected preauthentication envelope')
            if field(ike,'local-id') not in ('vpn.family.home.arpa','%any'):
                raise Unavailable('unexpected server identity')
            field(ike,'remote-id')  # Validate bounded ASCII, never use as attribution.
            ike_id=integer(ike,'uniqueid',2**32-1)
            if not ike_id or ike_id in ike_ids:raise Unavailable('invalid or duplicate IKE id')
            ike_ids.add(ike_id)
            if type(ike.get('child-sas')) is not dict or ike['child-sas']:
                raise Unavailable('preauthentication CHILD inventory')
            preauth+=1
            if preauth>32:raise Unavailable('excessive preauthentication inventory')
            continue
        if name not in connection_map:raise Unavailable('unregistered connection name')
        transition=with_unknown and state in ('REKEYED','DELETING','REKEYING')
        if state!='ESTABLISHED' and not transition:
            raise Unavailable('IKE transition')
        remote=field(ike,'remote-id')
        if remote not in identity_map or identity_map[remote] != connection_map[name]:
            raise Unavailable('connection and registered identity differ')
        device=identity_map[remote]
        device_ikes[device]=device_ikes.get(device,0)+1
        if device_ikes[device]>(3 if with_unknown else 2):
            raise Unavailable('excessive per-device IKE inventory')
        if field(ike,'local-id')!='vpn.family.home.arpa' or field(ike,'version')!='2':
            raise Unavailable('unexpected server identity')
        ike_id=integer(ike,'uniqueid',2**32-1)
        if not ike_id or ike_id in ike_ids:raise Unavailable('invalid or duplicate IKE id')
        ike_ids.add(ike_id)
        # Only verified empty REKEYED records gain the third-object exception.
        # DELETING still counts toward the original two-object device bound.
        if not (transition and state=='REKEYED'):
            counted_ikes[device]=counted_ikes.get(device,0)+1
            if counted_ikes[device]>2:raise Unavailable('excessive counted IKE inventory')
        children=ike.get('child-sas')
        empty_retirement=transition and (state=='REKEYED' or (state=='DELETING' and type(children)is dict and not children and 'remote-vips' not in ike))
        if empty_retirement:
            if (type(ike.get('child-sas')) is not dict or ike['child-sas'] or
                    'remote-vips' in ike):
                raise Unavailable('retired IKE still has resources')
            retired.add(device)
            continue
        if transition:
            # Normal IKE deletion/rekeying retains complete CHILDs and VIPs.
            # Until it clears, this device's full inventory is uncertain even
            # if a new established IKE also exists. Other devices stay usable.
            transition_scope(ike,device_map[device]);unknown.add(device)
            age=None  # Official VICI only emits age for ESTABLISHED IKEs.
        else:
            age=integer(ike,'established',2**32-1)
            if age>wall:raise Unavailable('invalid IKE age')
        if not isinstance(children,dict) or len(children)>8:
            raise Unavailable('CHILD transition or excessive inventory')
        if not children:
            if not with_unknown:raise Unavailable('CHILD transition or excessive inventory')
            unknown.add(device)
            continue
        active=False;selected=[]
        for name,child in children.items():
            if not isinstance(child,dict) or not isinstance(name,str) or not re.fullmatch(r'internet-[1-9][0-9]*',name):
                raise Unavailable('unexpected CHILD')
            state=field(child,'state')
            if state not in (('INSTALLED','REKEYING','REKEYED','DELETING','DELETED') if with_unknown else ('INSTALLED','REKEYING','REKEYED','DELETING')):
                raise Unavailable('CHILD transition')
            active |= state in ('INSTALLED','REKEYING')
            child_id=integer(child,'uniqueid',2**32-1)
            if not child_id or name!='internet-'+str(child_id) or field(child,'name')!='internet' or field(child,'protocol')!='ESP' or field(child,'mode')!='TUNNEL':
                raise Unavailable('unattributed CHILD')
            spi_in,spi_out=field(child,'spi-in'),field(child,'spi-out')
            if any(not re.fullmatch('[0-9a-fA-F]{8}',s) or int(s,16)==0 for s in (spi_in,spi_out)):
                raise Unavailable('invalid SPI pair')
            if transition or state=='DELETED':
                transition_scope(ike,device_map[device],child)
                unknown.add(device)
            # CHILD ids are daemon-global. IKE rekey inherits the same CHILD
            # object (and counters) into a new IKE: changing only the IKE id
            # must not make us add that CHILD's historical bytes a second time.
            unique=(child_id,spi_in.lower(),spi_out.lower())
            if unique in identities or child_id in child_ids:raise Unavailable('duplicate CHILD identity')
            identities.add(unique)
            child_ids.add(child_id)
            # Hashing omits public/internal IPs and avoids exporting even SPIs.
            key=hashlib.sha256((daemon_epoch+'|'+ '|'.join(map(str,unique))).encode('ascii')).hexdigest()
            up,down=integer(child,'bytes-in'),integer(child,'bytes-out')
            if age is not None:
                selected.append(dict(device=device,sa_key=key,upload_bytes=up,download_bytes=down,
                                     connected_since=wall-age))
        if not active:
            if not with_unknown:raise Unavailable('no stable active CHILD')
            unknown.add(device)
            continue
        authenticated.add(device)
        rows.extend(selected)
    if len(rows)>200:raise Unavailable('excessive selected inventory')
    if with_unknown:
        unknown.update(retired-authenticated)
        if preauth:unknown.update(set(identity_map.values())-authenticated)
        # An authenticated device with an incomplete second IKE cannot present
        # only one CHILD as its complete per-device accounting observation.
        return dict(rows=[row for row in rows if row['device'] not in unknown],unknown_devices=sorted(unknown))
    return rows
