"""Strict v8 fleet ownership metadata; no I/O and no permission from deserialization."""
from dataclasses import asdict
from pathlib import Path
import hashlib,json,re
import registry as registration
import fleet_policy as policy
import outer_endpoints as outer

VERSION=8
PROFILE='production-native-fleet-v1'
REGISTRY=Path('/usr/local/etc/family-vpn/devices.json')
HEX=re.compile('[0-9a-f]{64}')

class Invalid(ValueError):pass

def sha(raw):return hashlib.sha256(raw).hexdigest()
def static(raw,outer_endpoints=None):
    normalized=registration.loads(raw)
    scope=outer.normalize(outer.IPV4 if outer_endpoints is None else outer_endpoints)
    connection=registration.render_swanctl(normalized,scope).encode()
    result=dict(version=1,registry_sha256=sha(raw),registry=normalized,connection_sha256=sha(connection))
    if scope!=outer.IPV4:
        result.update(version=2,outer_endpoints=list(scope))
    return result


def endpoints(value):
    return outer.IPV4 if value.get('version')==1 else outer.normalize(value['outer_endpoints'])


def validate_static(value):
    base={'version','registry_sha256','registry','connection_sha256'}
    if type(value)is not dict or type(value.get('version'))is not int or value['version'] not in (1,2):
        raise Invalid('fleet_binding_shape')
    required=base if value['version']==1 else base|{'outer_endpoints'}
    if (set(value)!=required
            or any(type(value[k])is not str or not HEX.fullmatch(value[k]) for k in ('registry_sha256','connection_sha256'))):
        raise Invalid('fleet_binding_shape')
    try:scope=endpoints(value)
    except (ValueError,TypeError,KeyError):raise Invalid('fleet_outer_scope') from None
    if value['version']==2 and (type(value['outer_endpoints'])is not list or len(scope)!=2):
        raise Invalid('fleet_outer_scope')
    normalized=registration.normalize(value['registry'])
    if normalized!=value['registry'] or sha(registration.render_swanctl(normalized,scope).encode())!=value['connection_sha256']:
        raise Invalid('fleet_registry_connection_binding')
    return normalized

def encode_device(d):
    if type(d)is not policy.DeviceProof or d.ready is not True:raise Invalid('fleet_only_ready_device')
    return dict(device_id=d.device_id,ready=True,generation=asdict(d.generation),
                hosts=[list(k[:5])+[list(k[5])] for k in d.hosts],policy_ids=list(d.policy_ids))

def decode_active(value,registry,outer_endpoints=outer.IPV4):
    if type(value)is not list or len(value)>16:raise Invalid('fleet_active_shape')
    out=[];seen=set();policy_ids=set();children=set();ikes=set();spis=set();reqids=set()
    byid={d['device_id']:d for d in registry['devices']}
    for row in value:
        if (type(row)is not dict or set(row)!={'device_id','ready','generation','hosts','policy_ids'}
                or row['ready']is not True or type(row['device_id'])is not str or row['device_id'] not in byid
                or row['device_id'] in seen or byid[row['device_id']]['state']!='enabled'
                or type(row['generation'])is not dict or set(row['generation'])!=set(policy.Generation.__dataclass_fields__)
                or type(row['hosts'])is not list or len(row['hosts'])!=4 or type(row['policy_ids'])is not list
                or len(row['policy_ids'])!=4 or any(type(i)is not int or not 0<i<2**32 for i in row['policy_ids'])):
            raise Invalid('fleet_active_device_shape')
        g=policy.Generation(**row['generation']);policy.checked_generation(g,byid[row['device_id']],outer_endpoints)
        hosts=[]
        for k in row['hosts']:
            if type(k)is not list or len(k)!=6 or type(k[5])is not list:raise Invalid('fleet_active_host_shape')
            key=tuple(k[:5])+(tuple(k[5]),);record=policy.record_from_key(key)
            if record['kind']!='ipsec' or not policy.host_matches(record,g):raise Invalid('fleet_active_host_scope')
            hosts.append(key)
        ids=tuple(row['policy_ids'])
        # ESP identities include the receiving address; unrelated receivers
        # may choose the same SPI. Keep same-destination collisions rejected.
        endpoint_spis={(g.local4,g.spi_in),(g.peer4,g.spi_out)}
        if (tuple(sorted(hosts))!=tuple(hosts) or ids!=tuple(sorted(k[0] for k in hosts)) or len(set(ids))!=4
                or len({k[1:4] for k in hosts})!=4 or set(ids)&policy_ids
                or g.child_id in children or g.ike_id in ikes or g.reqid in reqids or endpoint_spis&spis):
            raise Invalid('fleet_active_identity_overlap')
        seen.add(row['device_id']);policy_ids.update(ids);children.add(g.child_id);ikes.add(g.ike_id);reqids.add(g.reqid);spis.update(endpoint_spis)
        out.append(policy.DeviceProof(row['device_id'],True,g,tuple(hosts),ids))
    if [d.device_id for d in out]!=sorted(seen):raise Invalid('fleet_active_order')
    return tuple(out)

def history(session):
    if (type(session)is not dict or type(session.get('version'))is not int or session['version']!=VERSION
            or session.get('profile')!=PROFILE or session.get('probe_mode')!='off'):
        raise Invalid('fleet_session_mode')
    registry=validate_static(session.get('fleet'))
    scope=endpoints(session['fleet'])
    if scope!=outer.IPV4 and scope!=outer.from_health(session['health']):raise Invalid('fleet_outer_health_binding')
    active=decode_active(session.get('fleet_active'),registry,scope)
    if (session.get('allow_data')is False or session.get('phase')=='RESTORED') and active:
        raise Invalid('closed_or_restored_fleet_active')
    # Reusing the old single identity fields would misdescribe the active set.
    if 'activation_generation' in session or any(k in session for k in ('probe_child','probe_generation','probe_result','probe_retired')):
        raise Invalid('fleet_single_identity_or_probe_fields')
    closing=session.get('fleet_closing')
    if closing is not None:
        ids={d['device_id'] for d in registry['devices']}
        if (type(closing)is not dict or set(closing)!={'version','devices','phase'}
                or type(closing['version'])is not int or closing['version']!=1
                or closing['phase'] not in ('intent','verified') or type(closing['devices'])is not list
                or not 1<=len(closing['devices'])<=16 or any(type(i)is not str or i not in ids for i in closing['devices'])
                or closing['devices']!=sorted(set(closing['devices']))):raise Invalid('fleet_closing_shape')
    intent=session.get('gate_intent')
    if intent is not None:
        import fleet_tables
        if not {'previous','fleet_tables_before','fleet_tables_after'}<=set(intent):raise Invalid('fleet_gate_intent_fields')
        for name in ('fleet_tables_before','fleet_tables_after'):
            tables=fleet_tables.validate(intent[name])
            ids4={d['device_id'] for d in registry['devices'] if d['vip4'] in tables['active4']}
            ids6={d['device_id'] for d in registry['devices'] if d['vip6'] in tables['active6']}
            if (ids4!=ids6 or len(ids4)!=len(tables['active4']) or len(ids6)!=len(tables['active6'])):
                raise Invalid('fleet_table_registry_scope')
    if intent is not None and 'previous' in intent:
        rules=intent['previous']
        if (type(rules)is not dict or set(rules)!={'filters','nat'} or any(type(rules[k])is not list or len(rules[k])>512
                or any(type(line)is not str or len(line)>2048 for line in rules[k]) for k in rules)):
            raise Invalid('fleet_previous_rules_shape')
    return registry

def authorize_state_delete(durable,argv):
    """Individual host -k needs the last durable, narrowed device intent."""
    if not argv or argv[0]!='/sbin/pfctl' or '-k' not in argv:return
    address=argv[-1]
    if address in ('10.77.26.0/24','fd6d:fe83:ab27:2600::/64'):return # global owner recovery path
    registry=history(durable)
    close=durable.get('fleet_closing')
    if type(close)is not dict or close.get('phase')!='intent':raise Invalid('fleet_delete_without_durable_intent')
    allowed={d[k] for d in registry['devices'] if d['device_id'] in close['devices'] for k in ('vip4','vip6')}
    if address not in allowed:raise Invalid('fleet_delete_not_registered_retirement')
    if any(address in (d.generation.vip4,d.generation.vip6) for d in decode_active(durable['fleet_active'],registry,endpoints(durable['fleet']))):
        raise Invalid('fleet_delete_still_active')
