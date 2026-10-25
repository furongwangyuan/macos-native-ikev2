"""Concrete native fleet adapter. Imports do nothing; caller owns original locks.

Uses the one ServiceOwner/Dispatcher, protected fixed VICI socket, complete raw
bounded list-sas exchange, full SPD ID queries and actual route/PF readbacks.
No generic callback, PID, command, path or network selector is exposed.
"""
import copy,hashlib,json,re,socket,subprocess,time,sys
from pathlib import Path
import native_support as s
import native_runtime as runtime
import native_policy as policies
import reviewed_policy
import fleet_session as session
import outer_endpoints as endpoints
import fleet_policy as policy
import fleet_coordinator as coordinator
import fleet_vici,fleet_transport,fleet_wire
from fleet_gate import FleetGate
from service_supervisor import ServiceOwner
import service_supervisor as service
from supervisor_core import KnownUplinkChange,ConfigurationChanged
from vici.protocol import Message,FiniteStream


def require_closure():
    s.require_local_modules(('fleet_native','fleet_controller','fleet_session','fleet_gate','fleet_tables',
        'registry','outer_endpoints','fleet_policy','fleet_vici','fleet_wire','fleet_exchange','fleet_transport','fleet_coordinator'))
    here=Path(__file__).resolve().parent
    for name in ('vici','vici.protocol','vici.exception','vici.session','vici.command_wrappers','vici.event_listener'):
        module=sys.modules.get(name);filename=getattr(module,'__file__',None)
        relative='vici/__init__.py' if name=='vici' else name.replace('.','/')+'.py'
        if type(filename)is not str or Path(filename).resolve()!=here/relative:
            raise s.Refused('fleet_official_codec_mixed_source')


class FleetOwner(ServiceOwner):
    def __init__(self,*args):
        # Lazy controller import resolves its intentional Owner type dependency.
        import fleet_controller
        require_closure()
        super().__init__(*args)
        self.fleet_adapter=NativeFleetAdapter(self)
    def same_boot(self):
        try:super().same_boot()
        except subprocess.TimeoutExpired as error:
            # This one fixed read is s.boot() -> sysctl kern.boottime. A timeout
            # supplies no identity result and must never authorize publication.
            if (type(error)is subprocess.TimeoutExpired
                    and error.cmd==['/usr/sbin/sysctl','-n','kern.boottime']
                    and type(error.timeout)in (int,float) and 0<error.timeout<=5):
                raise fleet_transport.TransientTransportFault('vici_exchange_timeout') from None
            raise
        except s.Refused as error:
            # Only the known pre-command budget refusal of that same read;
            # boot_changed and all later validation/protection errors stay hard.
            if (type(error)is s.Refused and error.args==('command_budget',)
                    and s.DEADLINE is not None and time.monotonic()>=s.DEADLINE):
                raise fleet_transport.TransientTransportFault('vici_exchange_timeout') from None
            raise
    def registry_current(self):
        raw=s.read(session.REGISTRY,limit=65536)
        if session.static(raw,session.endpoints(self.session['fleet']))!=self.session['fleet']:raise s.Refused('fleet_registry_changed')
        return raw
    def connection_configuration(self):
        self.registry_current()
        return super().connection_configuration()
    def check_local(self,timeout):
        value=super().check_local(timeout)
        self.registry_current()
        return value
    def observe(self,timeout):
        # Closed inherited setup only needs a no-IKE assertion. Data controllers
        # use NativeFleetAdapter directly and never fall back to a single-device parser.
        parsed=self.fleet_adapter.read_fleet(timeout)
        if self.data_mode:raise s.Refused('single_snapshot_interface_disabled_for_fleet')
        absent=not parsed.unattributed_pending_count and all(x.kind=='absent' for x in parsed.snapshots.values())
        return runtime.ctl.Snapshot('absent' if absent else 'pending')
    def check_uplink(self,local):
        if not self.data_mode or not runtime.network.known_change(self.session['health'],local):
            return runtime.Owner.check_uplink(self,local)
        # No mutation, NAT rewrite or old baseline edit. All already-published
        # devices must remain the same complete uniquely authenticated fleet in
        # two independent native frames. Simultaneous rekey/joins/teardown and
        # unavailable/ambiguous network stay unknown rather than hiding damage.
        first=self.fleet_adapter.uplink_change_frame()
        second=self.fleet_adapter.uplink_change_frame()
        if first!=second:raise runtime.ctl.Fault('fleet_uplink_evidence_changed')
        if runtime.network.local_parameters(runtime.network.uplink(external=False))!=local:
            raise runtime.ctl.Fault('fleet_uplink_change_not_stable')
        if s.DEADLINE is None or time.monotonic()>=s.DEADLINE:
            raise runtime.ctl.Fault('fleet_uplink_change_late_or_unbounded')
        raise KnownUplinkChange('known_fleet_en0_dualstack_change')

    def uplink_protection_readback(self):
        # Called only by the rare transition reader. Do not call check_local:
        # that invokes check_uplink recursively. These are the same actual
        # protection reads, with the configuration checked again without its
        # routine five-second optimization. Nothing here grants writer scope.
        self.known_child_alive()
        if service.read_configuration().fingerprint!=self.fingerprint:
            raise ConfigurationChanged('configuration_changed')
        context=self.fleet_adapter._context()
        current_alf=runtime.alf.snapshot()
        matches=(runtime.alf_transaction.active_matches(self.alf_transaction.record,current_alf)
                 if self.alf_transaction is not None else current_alf==self.session['alf_before'])
        if not matches:raise runtime.ctl.Fault('alf_vpn_rule_changed')
        if self.session['crl']['next']<=time.time():raise runtime.ctl.Fault('crl_expired')
        if s.digest(s.read(runtime.crl_gate.CRL))!=self.session['crl']['sha256']:
            raise runtime.ctl.Fault('crl_changed')
        if self.gate.state.get('mode')=='active':
            if not self.gate.verify_active():raise runtime.ctl.Fault('active_gate_changed')
        elif not self.gate.closed():raise runtime.ctl.Fault('closed_gate_changed')
        self.probe.check()
        return context
    def activate(self,*_args):raise s.Refused('single_generation_activation_disabled_for_fleet')
    def audit(self,*_args):raise s.Refused('single_generation_audit_disabled_for_fleet')


class NativeFleetAdapter:
    def __init__(self,owner):
        if type(owner)is not FleetOwner:raise s.Refused('concrete_fleet_owner_required')
        self.owner=owner;self.gate=FleetGate(owner);self.last_context=None
    def _context(self):
        owner=self.owner
        owner.same_boot()
        owner.known_child_alive()
        try:current=owner.owned_process()
        except s.Refused as error:
            # An owned child can exit between poll() and libproc's identity
            # reads. Missing metadata alone is not proof; only re-poll the
            # same owned Popen for these exact unavailable observations.
            if (type(error)is s.Refused and error.args in
                    (('process_identity_unavailable',),('process_path_unavailable',))):
                owner.known_child_alive()
            raise
        if current is None:owner.known_child_alive()
        if current is None or current['path']!=str(s.CHARON):raise s.Refused('fleet_charon_identity')
        registry_raw=s.read(session.REGISTRY,limit=65536)
        if session.static(registry_raw,session.endpoints(owner.session['fleet']))!=owner.session['fleet']:raise s.Refused('fleet_registry_changed')
        files=owner.session.get('files',{})
        if set(files)!={'daemon','connection'}:raise s.Refused('fleet_loaded_config_missing')
        for name,row in files.items():
            if row.get('phase')!='owned' or s.digest(s.read(runtime.FILES[name]))!=row['sha256']:
                raise s.Refused('fleet_loaded_config_changed')
        if files['connection']['sha256']!=owner.session['fleet']['connection_sha256']:
            raise s.Refused('fleet_generated_connection_not_loaded')
        runtime.native_socket()
        identity=s.signature(s.SOCKET.lstat())
        return dict(boot=owner.session['boot'],child=current,socket=identity,
                    registry_sha256=s.digest(registry_raw),files=copy.deepcopy(files),crl=owner.session['crl'])
    def read_fleet(self,timeout=10):
        if runtime.STOP.is_set():raise runtime.ctl.Cancelled('requested_stop')
        with runtime.budget(min(timeout,6)):
            self.last_context=None
            # The two complete fresh exchanges share six seconds at most and
            # never extend a shorter enclosing native operation budget.
            deadline=s.DEADLINE
            before=self._context()
            for attempt in range(2):
                if runtime.STOP.is_set():raise runtime.ctl.Cancelled('requested_stop')
                if attempt:
                    # A retry grants no exemption to ownership/configuration or
                    # the actual firewall/CRL/gate checks. No stale proof is used.
                    if self.owner.uplink_protection_readback()!=before:
                        raise s.Refused('fleet_vici_context_changed_or_late')
                if time.monotonic()>=deadline:
                    raise fleet_transport.TransientTransportFault('vici_exchange_timeout')
                try:
                    result=self._exchange(before,deadline)
                    break
                except fleet_transport.TransientTransportFault:
                    if attempt==1 or time.monotonic()>=deadline:raise
            events=[]
            for raw in result.event_messages:
                fleet_wire.validate_message(raw)
                events.append(Message.deserialize(FiniteStream(raw)))
            after=self._context()
            if before!=after:raise s.Refused('fleet_vici_context_changed_or_late')
            parsed=fleet_vici.parse_events(events,self.owner.session['fleet']['registry'],session.endpoints(self.owner.session['fleet']))
            # A complete valid read can finish its identity/parse checks just
            # after the budget. Discard it as unavailable, not changed identity.
            # Exceptions from those checks remain hard failures even when late.
            if time.monotonic()>=s.DEADLINE:
                raise fleet_transport.TransientTransportFault('vici_exchange_timeout')
            self.last_context=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:32]
            return parsed
    def _exchange(self,context,deadline):
        # Each attempt owns a fresh socket and transcript. The fixed path and
        # exact peer PID remain mandatory; failed bytes are never reused.
        attempt_deadline=min(deadline,time.monotonic()+3)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            remaining=attempt_deadline-time.monotonic()
            if remaining<=0:raise fleet_transport.TransientTransportFault('vici_exchange_timeout')
            sock.settimeout(remaining)
            try:sock.connect(str(s.SOCKET))
            except OSError as error:raise fleet_transport.socket_error(error) from None
            # Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=0x002.
            try:peer_pid=sock.getsockopt(0,0x002)
            except OSError:raise s.Refused('fleet_vici_peerpid_unverified') from None
            if type(peer_pid)is not int or peer_pid<=0 or peer_pid!=context['child']['pid']:
                raise s.Refused('fleet_vici_peerpid_unverified')
            return fleet_transport.query(sock,deadline=attempt_deadline)
    def observe(self):
        self.owner.check_local(10)
        parsed=self.read_fleet(10)
        return coordinator.View(copy.deepcopy(self.owner.session['fleet']['registry']),parsed,self.last_context)
    def inventory(self):
        # Fixed coordinator callers just ran observe() with its full local check.
        with runtime.budget(15):
            return self._inventory()
    def _inventory(self):
        # Internal read-only inventory for check_local's uplink hook; caller is
        # already in the enclosing native budget and has protection readbacks.
        records=policies.parse_spd(s.run(['/usr/sbin/setkey','-DP']).stdout)
        if len(records)>policy.MAX_POLICY_RECORDS:raise s.Refused('fleet_spd_inventory_bound')
        owned=self.owner.session.get('floors',[])+self.owner.session.get('keepers',[])
        if len(owned)!=3 or any(x.get('status')!='owned' for x in owned):raise s.Refused('fleet_native_journal_incomplete')
        native=[{k:r[k] for k in ('id','src','dst','direction','kind','requests')} for r in owned]
        active={}
        for row in records:
            kind={'generate':5,'discard':0,'ipsec':2}.get(row['kind'])
            if kind is None:raise s.Refused('fleet_unknown_spd_kind')
            remaining=s.DEADLINE-time.monotonic()
            if remaining<=0:raise s.Refused('fleet_spd_audit_deadline')
            active[row['id']]=policies.policy_id_active(row['id'],kind,1 if row['direction']=='in' else 2,timeout=min(3,remaining))
        return records,active,native
    def _route_output(self,flag,destination):
        args=['/sbin/route','-n','get',flag,destination]
        try:result=s.run(args,check=False)
        except subprocess.TimeoutExpired as error:
            # This fixed read-only lookup supplies evidence for one device.
            # s.run has already killed/reaped its child. Missing evidence
            # narrows that device via _route_valid(None), not the whole fleet.
            if (type(error)is subprocess.TimeoutExpired and error.cmd==args
                    and type(error.timeout)in (int,float) and 0<error.timeout<=5):
                return None
            raise
        return result.stdout if result.returncode==0 else None
    def route(self,device):
        with runtime.budget(10):
            g=device.generation;routes=[]
            for flag,vip in (('-inet',g.vip4),('-inet6',g.vip6)):
                raw=self._route_output(flag,vip)
                if raw is None:return None
                try:reviewed_policy.verify_route(raw,vip)
                except ValueError:return None
                routes.append(coordinator.Route(vip,'en0',True,True))
            raw=self._route_output(endpoints.route_family(g.peer4),g.peer4)
            if raw is None:return None
            interface=re.findall(r'^\s*interface:\s+(\S+)\s*$',raw,re.M)
            flags=re.findall(r'^\s*flags:\s*<([^>]+)>\s*$',raw,re.M)
            if interface!=['en0'] or len(flags)!=1 or 'UP' not in flags[0].split(','):return None
            routes.append(coordinator.Route(g.peer4,'en0',True,'HOST' in flags[0].split(',')))
            return coordinator.Routes(g,*routes)
    def uplink_change_frame(self):
        owner=self.owner
        before=owner.uplink_protection_readback()
        current=self.gate.current()
        parsed=self.read_fleet(5)
        if parsed.unattributed_pending_count or any(
                x.kind not in ('unique','absent') or x.deleted for x in parsed.snapshots.values()):
            raise runtime.ctl.Fault('fleet_uplink_transition_scope_unknown')
        records,activity,native=self._inventory()
        proof=policy.audit(owner.session['fleet']['registry'],parsed.snapshots,records,activity,native,
            outer_endpoints=session.endpoints(owner.session['fleet']))
        # Exact equality to the durably published active generation set avoids
        # reclassifying a simultaneous per-device transition as an uplink event.
        ready=tuple(d for d in proof.devices if d.ready)
        if (ready!=current or any(d.hosts for d in proof.devices if not d.ready)
                or any(parsed.snapshots[d.device_id]!=policy.Snapshot('unique',(d.generation,)) for d in ready)
                or any(parsed.snapshots[d.device_id]!=policy.Snapshot('absent') for d in proof.devices if not d.ready)):
            raise runtime.ctl.Fault('fleet_uplink_native_scope_unknown')
        routes=[]
        for d in ready:
            e=self.route(d);g=d.generation
            if (type(e)is not coordinator.Routes or type(e.generation)is not policy.Generation
                    or any(type(r)is not coordinator.Route or type(r.up)is not bool or type(r.host)is not bool
                           for r in (e.ipv4,e.ipv6,e.peer))
                    or e.generation!=g or e.ipv4!=coordinator.Route(g.vip4,'en0',True,True)
                    or e.ipv6!=coordinator.Route(g.vip6,'en0',True,True)
                    or e.peer.destination!=g.peer4 or e.peer.interface!='en0' or not e.peer.up):
                raise runtime.ctl.Fault('fleet_uplink_route_scope_unknown')
            routes.append(e)
        after=owner.uplink_protection_readback()
        if before!=after or current!=self.gate.current():
            raise runtime.ctl.Fault('fleet_uplink_protection_changed')
        return parsed,proof,tuple(routes),self.last_context,before

    def narrow(self,expected,remaining,requests):
        with runtime.budget(25):
            removed={d.device_id:d for d in expected if d not in remaining}
            if (any(d not in expected for d in remaining) or set(removed)!={r.device_id for r in requests}
                    or len(removed)!=len(requests)):raise s.Refused('fleet_narrow_request_scope')
            for request in requests:
                d=removed[request.device_id]
                if request!=coordinator.CloseRequest(d.device_id,d.generation,d.generation.vip4,d.generation.vip6,d.hosts):
                    raise s.Refused('fleet_narrow_generation_not_previous')
            self.gate.replace(expected,remaining) # Remove A first, retaining B's rules/forwarding.
            if self.gate.retire(requests):return coordinator.NarrowReceipt(remaining,requests)
            return coordinator.NarrowReceipt(remaining,(),requests)
    def retry_retirement(self,expected,requests):
        # Called once per next controller tick, with the exact retained requests.
        # No active-set replacement or shared closure occurs on this retry.
        with runtime.budget(25):
            self.owner.check_local(10)
            if self.gate.current()!=expected:raise s.Refused('fleet_retirement_active_changed')
            if self.gate.retire(requests):return coordinator.NarrowReceipt(expected,requests)
            return coordinator.NarrowReceipt(expected,(),requests)
    def publish(self,expected,proposed,proof):
        with runtime.budget(25):
            policy.validate_proof(proof,self.owner.session['fleet']['registry'],session.endpoints(self.owner.session['fleet']))
            byid={d.device_id:d for d in proof.devices if d.ready}
            if any(byid.get(d.device_id)!=d for d in proposed) or any(d not in proposed for d in expected):
                raise s.Refused('fleet_publish_not_current_superset')
            self.gate.replace(expected,proposed)
            return proposed
    def guard_all(self,_reason):
        self.owner.guard('fleet_global_guard',20)
        return self.owner.gate.closed() and self.owner.session['fleet_active']==[]
