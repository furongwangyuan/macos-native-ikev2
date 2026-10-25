"""Sole-owner active-set replacement and exclusive-VIP state retirement.

PF -k is address scoped, never SA/anchor scoped. A is removed from both active
sets before all A-address states are cleared, including any A old/new generation.
This preserves unrelated B addresses in the command selectors; actual traffic
continuity and macOS NAT direction semantics still need native observation.
"""
import copy,ipaddress,re,subprocess
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
        if (len(body)==5 and arrows==[1,3] and body[1]==body[3]):
            # Darwin also prints NAT as original -> translated -> peer (or
            # the reverse arrow form). Every endpoint, including the original
            # private VIP, participates in the exact address absence check.
            tokens=body[::2]
        elif len(arrows)==1 and arrows[0] in (1,2) and len(body)-arrows[0]-1 in (1,2):
            tokens=[]
            for side in (body[:arrows[0]],body[arrows[0]+1:]):
                if len(side)==2 and not (side[1].startswith('(') and side[1].endswith(')')):
                    raise s.Refused('fleet_state_nat_view_unknown')
                tokens.extend(side)
        else:
            raise s.Refused('fleet_state_line_unknown')
        for token in tokens:found.add(_endpoint(token))
    return not (found & {ipaddress.ip_address(a) for a in addresses})


class FleetGate:
    def __init__(self,owner):self.owner=owner;self.gate=owner.gate
    @property
    def state(self):return self.owner.session
    def current(self):
        registry=session.history(self.state)
        return session.decode_active(self.state['fleet_active'],registry,session.endpoints(self.state['fleet']))
    def native(self):
        owned=self.state.get('floors',[])+self.state.get('keepers',[])
        if len(owned)!=3 or any(r.get('status')!='owned' for r in owned):raise s.Refused('fleet_native_floor_receipt')
        return policy.native_keys([{k:r[k] for k in ('id','src','dst','direction','kind','requests')} for r in owned])
    def rules(self,active):
        registry=self.state['fleet']['registry'];byid={d.device_id:d for d in active}
        proof=policy.FleetProof(policy.registry_digest(registry),self.native(),tuple(
            byid.get(d['device_id'],policy.DeviceProof(d['device_id'],False,None,(),())) for d in registry['devices']),session.endpoints(self.state['fleet']))
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
        self.state['gate_intent']=dict(phase='apply-intent',sha256=s.digest(s.read(path)),expected=compiled,previous=before,
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
    def _states_clear(self,addresses):
        # Only this fixed read is recoverably unavailable. A false result is
        # never an absence receipt; the already-narrowed device stays barred.
        args=[native.PF,'-ss']
        try:output=s.run(args,timeout=2,check=False)
        except subprocess.TimeoutExpired as error:
            if (type(error)is subprocess.TimeoutExpired and error.cmd==args
                    and type(error.timeout)in (int,float) and 0<error.timeout<=2):return False
            raise
        except UnicodeDecodeError:return False
        except s.Refused as error:
            if type(error)is s.Refused and error.args==('command_output_limit',):return False
            raise
        if (output.returncode!=0 or output.stderr.strip() not in
                ('','No ALTQ support in kernel\nALTQ related functions disabled')):return False
        try:return no_address_state(output.stdout,addresses)
        except s.Refused as error:
            if type(error)is s.Refused and error.args in tuple((code,) for code in (
                    'fleet_state_output_unknown','fleet_state_line_unknown',
                    'fleet_state_nat_view_unknown','fleet_state_endpoint_unknown',
                    'fleet_state_port_unknown','fleet_state_scope_unknown')):return False
            raise
    def retire(self,requests):
        if not requests:return True
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
        clear=self._states_clear(addresses)
        # Rule/table/forwarding ownership failures remain separate hard errors.
        # An unknown state-display row must not hide a changed shared gate.
        if not self.gate.verify_active():raise s.Refused('fleet_narrow_gate_changed')
        if not clear:return False
        self.state['fleet_closing']['phase']='verified';self.owner.save()
        return True
