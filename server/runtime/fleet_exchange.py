"""Pure bounded transcript state machine for exactly one read-only list-sas.

No sockets, callbacks, configurable commands, codec imports or environment I/O.
The future adapter must send each returned frame completely, call receive_limit
before every read, reject send/read failures, prove the daemon/config/registry
identity boundary, and discard the connection after completion. This object
checks a supplied transcript; it cannot authenticate where its bytes came from.
"""
from dataclasses import dataclass
import math

from fleet_wire import MAX_FRAME, WireFault, validate_frame


MAX_EVENTS = 48
MAX_FRAMES = 51                   # Register confirm + 48 events + reply + unregister confirm.
MAX_RECEIVED = 1048576            # All inbound length headers and packet bytes.
DEADLINE_SECONDS = 3.0            # Total transaction, never a per-fragment reset.
MAX_CLOCK = 2**40                 # Fixed finite monotonic range with subsecond precision.

_REGISTER = b'\x00\x00\x00\x09\x03\x07list-sa'
_QUERY = b'\x00\x00\x00\x0a\x00\x08list-sas'
_UNREGISTER = b'\x00\x00\x00\x09\x04\x07list-sa'
_SEND = {'SEND_REGISTER':(_REGISTER,'WAIT_REGISTER'),
         'SEND_QUERY':(_QUERY,'READING'),
         'SEND_UNREGISTER':(_UNREGISTER,'WAIT_UNREGISTER')}
_RECEIVE = frozenset(('WAIT_REGISTER','READING','WAIT_UNREGISTER'))


class ExchangeFault(ValueError):
    """A fixed failure category, never raw input or exception text."""


@dataclass(frozen=True)
class ExchangeResult:
    event_messages: tuple
    received_bytes: int
    received_frames: int
    elapsed_seconds: float


def _clock(value):
    if type(value) not in (int,float) or not 0<=value<=MAX_CLOCK:
        raise ExchangeFault('invalid_clock')
    result=float(value)
    if not math.isfinite(result):raise ExchangeFault('invalid_clock')
    return result


class Exchange:
    """Fixed three-request conversation; only completed raw events escape.

    Construction emits nothing. outbound(now) is required at each SEND phase;
    it returns a complete transport frame and enters the corresponding receive
    phase. A failed/partial external send must call abort or discard this object.
    feed accepts no more bytes than the last/current receive_limit permits.
    A header and its body are separate receive sections, so an oversized length
    is rejected before a body read or allocation is authorized.
    """
    def __init__(self,started):
        self._started=_clock(started)
        self._last=self._started
        self._phase='SEND_REGISTER'
        self._header=bytearray()
        self._body=bytearray()
        self._expected=None
        self._received=0
        self._frames=0
        self._events=[]
        self._finished=None

    @property
    def phase(self):return self._phase

    @property
    def complete(self):return self._phase=='COMPLETE'

    def _fail(self,code):
        self._phase='FAILED'
        self._header.clear();self._body.clear();self._events.clear()
        self._expected=None;self._finished=None
        raise ExchangeFault(code)

    def _tick(self,now):
        if self._phase=='FAILED':raise ExchangeFault('exchange_failed')
        try:current=_clock(now)
        except ExchangeFault:self._fail('invalid_clock')
        if current<self._last:self._fail('clock_regression')
        if current-self._started>=DEADLINE_SECONDS:self._fail('exchange_deadline')
        self._last=current

    def outbound(self,now):
        self._tick(now)
        if self._phase not in _SEND or self._header or self._body or self._expected is not None:
            self._fail('outbound_out_of_order')
        packet,phase=_SEND[self._phase]
        self._phase=phase
        return packet

    def receive_limit(self,now):
        """Maximum bytes for the next external read; never a body-sized guess."""
        self._tick(now)
        if self._phase not in _RECEIVE:self._fail('receive_out_of_order')
        remaining=MAX_RECEIVED-self._received
        if remaining<=0:self._fail('total_byte_limit')
        count=4-len(self._header) if self._expected is None else self._expected-len(self._body)
        if count<=0:self._fail('invalid_receive_section')
        return min(count,remaining)

    def feed(self,data,now):
        limit=self.receive_limit(now)
        if type(data) is not bytes or not 1<=len(data)<=limit:self._fail('fragment_type_or_size')
        self._received+=len(data)
        if self._expected is None:
            self._header.extend(data)
            if len(self._header)==4:
                expected=int.from_bytes(self._header,'big')
                if not 1<=expected<=MAX_FRAME:self._fail('frame_size')
                if expected>MAX_RECEIVED-self._received:self._fail('total_byte_limit')
                if self._frames>=MAX_FRAMES:self._fail('frame_count')
                self._frames+=1
                self._expected=expected
            return
        self._body.extend(data)
        if len(self._body)==self._expected:
            try:packet=validate_frame(bytes(self._header)+bytes(self._body))
            except WireFault:self._fail('invalid_frame')
            self._header.clear();self._body.clear();self._expected=None
            self._accept(packet)

    def _accept(self,packet):
        if self._phase=='WAIT_REGISTER':
            if packet.packet_type!=5:self._fail('registration_not_confirmed')
            self._phase='SEND_QUERY'
        elif self._phase=='READING':
            if packet.packet_type==7:
                if len(self._events)>=MAX_EVENTS:self._fail('event_count')
                self._events.append(packet.message)
            elif packet.packet_type==1:
                # vici_query.c list_sas ends with a newly finalized empty
                # builder, not a success flag. Any changed/failed reply rejects.
                if packet.message:self._fail('unexpected_query_response')
                self._phase='SEND_UNREGISTER'
            else:self._fail('query_sequence')
        elif self._phase=='WAIT_UNREGISTER':
            if packet.packet_type!=5:self._fail('unregistration_not_confirmed')
            self._phase='COMPLETE';self._finished=self._last
        else:self._fail('packet_out_of_order')

    def eof(self,now):
        """EOF is never substituted for an empty query response or confirmation."""
        self._tick(now)
        self._fail('truncated_frame' if self._header or self._body else 'unexpected_eof')

    def abort(self,now):
        """Latch an external send/read failure; no retry/reset on this object."""
        self._tick(now)
        self._fail('external_io_failure')

    def result(self,now):
        self._tick(now)
        if not self.complete or self._header or self._body or self._expected is not None:
            self._fail('incomplete_exchange')
        return ExchangeResult(tuple(self._events),self._received,self._frames,
                              self._finished-self._started)
