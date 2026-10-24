"""Fixed synthetic endpoint scope. Pure checks do not authenticate packets."""
import ipaddress
import math
import controller as ctl
import reviewed_policy as policy

MODE='synthetic-local-v1'
PORT=47729
BIND='192.0.2.8'
MARKER='block drop quick inet from <familyvpn_v4> to self label "familyvpn_no_host4"'


def mode(value, data):
    if type(value)is not str or value not in ('off',MODE) or (value!= 'off' and data is not True):
        raise ctl.Fault('unknown_probe_mode')
    return value


def generation(value):
    keys=set(ctl.Generation.__dataclass_fields__)
    if type(value)is not dict or set(value)!=keys:raise ctl.Fault('probe_generation_shape')
    for key in ('ike_id','child_id','reqid','peer_port','local_port'):
        if type(value[key])is not int or value[key]<=0:raise ctl.Fault('probe_generation_integer')
    for key in keys-{'ike_id','child_id','reqid','peer_port','local_port'}:
        if type(value[key])is not str:raise ctl.Fault('probe_generation_text')
    if (value['local4']!=BIND or value['local_port']!=4500 or value['peer_port']>65535
            or value['remote_id']!=policy.DEVICE_ID):raise ctl.Fault('probe_generation_identity')
    try:
        if policy._peer4(value['peer4'])!=value['peer4']:raise ValueError()
        policy._vip_pair([ipaddress.ip_network(value['vip4']),ipaddress.ip_network(value['vip6'])])
        for key in ('spi_in','spi_out'):
            if len(value[key])!=8 or any(x not in '0123456789abcdef' for x in value[key]):raise ValueError()
    except ValueError as error:raise ctl.Fault('probe_generation_address_or_spi') from error
    return ctl.Generation(**value)


def verified_reply_scope(current, proof):
    """Consume the real caller's latest audit; not a substitute for that audit."""
    if type(current)is not ctl.Generation or type(proof)is not ctl.Proof or not proof.ready or proof.generation!=current:
        raise ctl.Fault('probe_requires_current_generation_audit')
    generation(current.info())
    # Complete host selectors and live OUT floor cover local Mac replies too.
    # IN provenance is deliberately not claimed for this synthetic endpoint.
    floors=[x for x in proof.native if x[1:]==('0.0.0.0/0','10.77.26.0/24','out','generate',())]
    hosts=[x for x in proof.hosts if x[1:5]==('0.0.0.0/0',current.vip4+'/32','out','ipsec')]
    if len(floors)!=1 or len(hosts)!=1 or hosts[0][0] not in proof.policy_ids:
        raise ctl.Fault('probe_local_reply_policy_missing')
    record=dict(zip(('id','src','dst','direction','kind','requests'),hosts[0]))
    record['requests']=list(record['requests'])
    if not ctl.host_matches(record,current):raise ctl.Fault('probe_local_reply_policy_changed')


def rules(rendered,current):
    generation(current.info())
    if rendered.count(MARKER)!=1 or 'familyvpn_probe_' in rendered:
        raise ctl.Fault('probe_pf_template_changed')
    pair=(f'pass in quick on $wan inet proto tcp from {current.vip4}/32 to {BIND} port {PORT} no state label "familyvpn_probe_in"\n'
          f'pass out quick on $wan inet proto tcp from {BIND} port {PORT} to {current.vip4}/32 no state label "familyvpn_probe_out"\n')
    return rendered.replace(MARKER,pair+MARKER,1)


def seconds(session, now):
    marker=session.get('finite_window')
    if (session.get('test_action')!='finite-service-900' or type(marker)is not dict
            or type(marker.get('continuous_start'))not in (int,float)
            or type(marker.get('continuous_deadline'))not in (int,float)
            or type(now)not in (int,float)):
        raise ctl.Fault('probe_requires_fixed_finite_window')
    start,end=marker['continuous_start'],marker['continuous_deadline']
    if not all(math.isfinite(x) for x in (start,end,now)) or end-start!=900 or not start<=now<end:
        raise ctl.Fault('probe_window_not_current')
    # Ceil keeps the endpoint's own limit just after the owner's fixed deadline;
    # the owner still stops it at its earlier actual window deadline.
    return min(900,math.ceil(end-now))
