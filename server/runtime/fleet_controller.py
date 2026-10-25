"""Concrete service loop; uses the actual sole-writer native adapter."""
import math
import native_runtime as runtime
import fleet_coordinator as fleet
import service_pki
import fleet_session
from supervisor_core import MaintenanceDue
from fleet_native import FleetOwner,NativeFleetAdapter

class Controller:
    def __init__(self,owner,deadline,clock):
        if type(owner)is not FleetOwner or type(owner.fleet_adapter)is not NativeFleetAdapter:
            raise runtime.s.Refused('fleet_concrete_service_owner_required')
        self.owner,self.deadline,self.clock=owner,deadline,clock
        self.coordinator=fleet.Coordinator(owner.session['fleet']['registry'],owner.fleet_adapter,outer_endpoints=fleet_session.endpoints(owner.session['fleet']))
        self.failure=None
        # Distinct generation history is admission evidence for a bounded test,
        # not lifetime production telemetry. The live coordinator already keeps
        # only the registered devices' current/last generations.
        self.track_generations=math.isfinite(deadline)
        self.generations=set()
        self.generation_count=0
    def run(self):
        try:
            while not runtime.STOP.is_set() and self.clock()<self.deadline:
                # Each observation frame checks local protection before reading VICI.
                if self.owner.session.get('test_action')=='service' and service_pki.due(self.owner.session):
                    raise MaintenanceDue('current_crl_renewal_due')
                result=self.coordinator.step()
                if result.state=='STOPPED':
                    raise runtime.ctl.Fault('fleet_controller_stopped') from self.coordinator.failure
                # Count only generations retained by the actual publish and
                # postcheck path. Pending/failed observations never count.
                if self.track_generations:
                    self.generations.update((ident,self.coordinator.active[ident].generation)
                                            for ident in result.active)
                    self.generation_count=len(self.generations)
                phase='ACTIVE' if result.active else 'WAITING'
                seen=bool(self.owner.session.get('child_seen') or result.active)
                # Native gate and mutation intents persist at their own exact
                # boundaries. An unchanged loop result introduces no new native
                # effect or recovery fact and needs no duplicate journal write.
                if self.owner.session.get('phase')!=phase or self.owner.session.get('child_seen') is not seen:
                    self.owner.session.update(phase=phase,child_seen=seen)
                    self.owner.save()
                self.owner.wait(1)
        except BaseException as error:
            self.failure=error
            raise
        finally:
            # Outer NativeDependencies performs full cleanup/fresh readback.
            self.owner.guard('fleet_loop_exit',20)
