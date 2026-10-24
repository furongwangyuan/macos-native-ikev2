"""Sole-owner active-set replacement and exclusive-VIP state retirement.

PF -k is address scoped, never SA/anchor scoped. A is removed from both active
sets before all A-address states are cleared, including any A old/new generation.
This preserves unrelated B addresses in the command selectors; actual traffic
continuity and macOS NAT direction semantics still need native observation.
"""
import copy,ipaddress,re
import native_support as s
import native_gate as native
import fleet_policy as policy
import fleet_session as session
import fleet_tables


def _endpoint(text):
    # pfctl displays IPv4 :port, IPv6 [port], or address-only protocol endpoints.
    # NAT aliases may be parenthesized; every alias is included, never skipped.
    if text.startswith('(') and text.endswith(')'):text=text[1:-1]
    elif '(' in text or ')' in text:raise s.Refused('fleet_state_endpoint_unknown')
    address=text
    bracket=re.fullmatch(r'(.+)\[([0-9]+)\]',text)
    if bracket:
        address=bracket[1]
        if not 0<=int(bracket[2])<=65535:raise s.Refused('fleet_state_port_unknown')
    elif text.startswith('['):
        bracket=re.fullmatch(r'\[([^]]+)\]:([0-9]+)',text)
        if bracket is None or not 0<=int(bracket[2])<=65535:raise s.Refused('fleet_state_endpoint_unknown')
        address=bracket[1]
    elif text.count(':')==1 and '.' in text:
        address,port=text.rsplit(':',1)
        if not port.isascii() or not port.isdecimal() or not 0<=int(port)<=65535:raise s.Refused('fleet_state_port_unknown')
    try:ip=ipaddress.ip_address(address)
    except ValueError:raise s.Refused('fleet_state_endpoint_unknown') from None
    if getattr(ip,'scope_id',None) is not None:raise s.Refused('fleet_state_scope_unknown')
    return ip


def no_address_state(text,addresses):
    # Full endpoint token parsing, including NAT views. This remains an address
    # absence readback, NOT per-SA ownership or a packet-level close timestamp.
    if type(text)is not str or len(text)>500000 or any(ord(c)<32 and c not in '\n\t\r' for c in text):
        raise s.Refused('fleet_state_output_unknown')
    found=set()
    for line in text.splitlines():
        if not line.strip():continue
        parts=line.split()
        if (not 6<=len(parts)<=8 or not re.fullmatch('[A-Za-z0-9_.:-]+',parts[0])
                or not re.fullmatch('[a-z0-9_-]+',parts[1])
                or not re.fullmatch(r'(?:[A-Z][A-Z0-9_]*|[0-9]+)(?::(?:[A-Z][A-Z0-9_]*|[0-9]+))?',parts[-1])):
            raise s.Refused('fleet_state_line_unknown')
        body=parts[2:-1];arrows=[i for i,x in enumerate(body) if x in ('->','<-')]
        if len(arrows)!=1 or arrows[0] not in (1,2) or len(body)-arrows[0]-1 not in (1,2):
            raise s.Refused('fleet_state_line_unknown')
        for side in (body[:arrows[0]],body[arrows[0]+1:]):
            if len(side)==2 and not (side[1].startswith('(') and side[1].endswith(')')):
                raise s.Refused('fleet_state_nat_view_unknown')
            for token in side:found.add(_endpoint(token))
    return not (found & {ipaddress.ip_address(a) for a in addresses})


class FleetGate:
    def __init__(self,owner):self.owner=owner;self.gate=owner.gate
    @property
    def state(self):return self.owner.session
    def current(self):
        registry=session.history(self.state)
        return session.decode_active(self.state['fleet_active'],registry)
    def native(self):
        owned=self.state.get('floors',[])+self.state.get('keepers',[])
        if len(owned)!=3 or any(r.get('status')!='owned' for r in owned):raise s.Refused('fleet_native_floor_receipt')
        return policy.native_keys([{k:r[k] for k in ('id','src','dst','direction','kind','requests')} for r in owned])
    def rules(self,active):
        registry=self.state['fleet']['registry'];byid={d.device_id:d for d in active}
        proof=policy.FleetProof(policy.registry_digest(registry),self.native(),tuple(
            byid.get(d['device_id'],policy.DeviceProof(d['device_id'],False,None,(),())) for d in registry['devices']))
        text=policy.render(s.read(s.BASE/'family-vpn.fleet.pf').decode(),registry,proof)
        text,count=re.subn(r'^table <familyvpn_home4> persist \{[^\n]*\}$',
            'table <familyvpn_home4> persist { '+self.state['health']['public4']+' }',text,flags=re.M)
        if count!=1:raise s.Refused('fleet_public4_table')
        return text
    def replace(self,expected,proposed):
        if self.state['allow_data']is not True or self.state['probe_mode']!='off':raise s.Refused('fleet_gate_mode')
        if self.current()!=expected:raise s.Refused('fleet_active_changed')
        self.owner.check_local(10)
        if any(d not in expected for d in proposed):self.owner.registry_current()
        gate=self.gate
        if gate.state.get('mode')=='active':
            if not gate.verify_active():raise s.Refused('fleet_existing_gate_unverified')
            before=copy.deepcopy(self.state['gate_intent']['expected'])
        else:
            if expected or not gate.closed():raise s.Refused('fleet_initial_gate_not_closed')
            before=copy.deepcopy(self.state['pf']['guard'])
        text=self.rules(proposed);path,compiled=gate.compile_rules(text,'active.pf')
        self.state['gate_intent']=dict(phase='apply-intent',sha256=s.digest(text.encode()),expected=compiled,previous=before,
            fleet_tables_before=fleet_tables.expected(expected),fleet_tables_after=fleet_tables.expected(proposed))
        self.owner.save() # Original and replacement rules survive a death before/after load.
        if gate.state.get('mode')!='active':
            # From globally closed guard only: no retained B can be interrupted.
            for key,value in s.SYS.items():gate.set_knob(key,value)
        if s.values()!=s.SYS:raise s.Refused('fleet_forwarding_readback')
        s.run([native.PF,'-a',native.ANCHOR,'-f',path]) # same durable Dispatcher
        if not gate.rules_equal(compiled) or fleet_tables.read()!=fleet_tables.expected(proposed):
            raise s.Refused('fleet_active_rules_or_tables_readback')
        gate.state['mode']='active';self.state['fleet_active']=[session.encode_device(d) for d in proposed]
        self.state['gate_intent']['phase']='applied';self.owner.save()
        if not gate.verify_active():raise s.Refused('fleet_active_postreadback')
    def retire(self,requests):
        if not requests:return
        registry={d['device_id']:d for d in self.state['fleet']['registry']['devices']}
        current={d.device_id for d in self.current()};ids=[];addresses=[]
        for req in requests:
            row=registry.get(req.device_id)
            if (row is None or req.device_id in current or req.device_id in ids
                    or (req.vip4,req.vip6)!=(row['vip4'],row['vip6'])):raise s.Refused('fleet_retire_scope')
            ids.append(req.device_id);addresses.extend((req.vip4,req.vip6))
        self.state['fleet_closing']=dict(version=1,devices=sorted(ids),phase='intent');self.owner.save()
        # No global guard, forwarding write or pool selector on this narrow path.
        for address in addresses:
            anynet='0.0.0.0/0' if ipaddress.ip_address(address).version==4 else '::/0'
            s.run([native.PF,'-k',address]);s.run([native.PF,'-k',anynet,'-k',address])
        output=s.run([native.PF,'-ss'])
        if (output.stderr.strip() not in ('','No ALTQ support in kernel\nALTQ related functions disabled')
                or not no_address_state(output.stdout,addresses)):
            raise s.Refused('fleet_address_states_remain_or_unknown')
        if not self.gate.verify_active():raise s.Refused('fleet_narrow_gate_changed')
        self.state['fleet_closing']['phase']='verified';self.owner.save()
