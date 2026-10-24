"""Pure pre-decode integrity checks for one candidate fleet VICI frame.

No I/O, socket, official Session or decoded event handling. A validated frame is
not a complete request: the future caller must establish source identity,
registration/response ordering, deadlines and complete unfiltered enumeration.
Raw values are opaque blobs; numeric/authentication semantics belong to the
separately reviewed fleet_vici parser after official decoding.
"""
from dataclasses import dataclass


MAX_FRAME = 65536                 # Packet bytes, excluding transport uint32.
MAX_MESSAGE = 65536
MAX_NAME = 128
MAX_BLOB = 1024
MAX_DEPTH = 4                     # Explicit sections; implicit root has depth 0.
MAX_SECTION_ENTRIES = 64
MAX_LIST_ITEMS = 32
MAX_NAMED_ENTRIES = 4096
MAX_ELEMENTS = 8192


class WireFault(ValueError):
    """Only fixed diagnostic categories; never include raw names or values."""


@dataclass(frozen=True)
class MessageStats:
    message_bytes: int
    elements: int
    named_entries: int
    list_items: int
    max_section_depth: int


@dataclass(frozen=True)
class ValidatedFrame:
    packet_type: int
    event_name: object
    message: bytes
    stats: MessageStats


def validate_message(payload):
    """Reject overwrite ambiguity and malformed structure before decoding.

    Duplicate section, scalar or list names share one namespace per section.
    All element bytes are consumed; unknown markers and trailing terminators
    fail instead of being ignored. Empty messages/lists/values are wire-valid.
    This fixed candidate intentionally accepts a narrower set than generic VICI.
    """
    if type(payload) is not bytes or len(payload)>MAX_MESSAGE:
        raise WireFault('message_type_or_size')
    size=len(payload);offset=0
    names=[set()]
    in_list=False;items_here=0
    elements=0;named_entries=0;list_items=0;max_depth=0

    def take(length):
        nonlocal offset
        if length>size-offset:raise WireFault('truncated_element')
        start=offset;offset+=length
        return payload[start:offset]

    def name():
        length=take(1)[0]
        if not 1<=length<=MAX_NAME:raise WireFault('name_length')
        result=take(length)
        # VICI specifies ASCII names; fixed scope also rejects controls/NUL.
        # Parentheses remain legal for the upstream '(unnamed)' IKE section.
        if any(c<32 or c>126 for c in result):raise WireFault('name_encoding')
        return result

    def blob():
        nonlocal offset
        length=int.from_bytes(take(2),'big')
        if length>MAX_BLOB:raise WireFault('blob_length')
        if length>size-offset:raise WireFault('truncated_blob')
        offset+=length              # No copy/allocation based on the blob length.

    while offset<size:
        marker=take(1)[0]
        elements+=1
        if elements>MAX_ELEMENTS:raise WireFault('element_count')
        if in_list:
            if marker==5:
                items_here+=1;list_items+=1
                if items_here>MAX_LIST_ITEMS:raise WireFault('list_item_count')
                blob()
            elif marker==6:
                in_list=False
            else:raise WireFault('illegal_list_element')
            continue
        if marker in (1,3,4):
            field=name()
            if field in names[-1]:raise WireFault('duplicate_section_name')
            if len(names[-1])>=MAX_SECTION_ENTRIES:raise WireFault('section_entry_count')
            names[-1].add(field)
            named_entries+=1
            if named_entries>MAX_NAMED_ENTRIES:raise WireFault('named_entry_count')
            if marker==1:
                depth=len(names)
                if depth>MAX_DEPTH:raise WireFault('section_depth')
                max_depth=max(max_depth,depth)
                names.append(set())
            elif marker==3:
                blob()
            else:
                in_list=True;items_here=0
        elif marker==2:
            if len(names)==1:raise WireFault('unmatched_section_end')
            names.pop()
        else:raise WireFault('unknown_or_misplaced_element')
    if in_list:raise WireFault('unclosed_list')
    if len(names)!=1:raise WireFault('unclosed_section')
    return MessageStats(size,elements,named_entries,list_items,max_depth)


def validate_frame(frame):
    """Validate exactly one transport frame for a future list-sas reader.

    Input includes its four-byte big-endian length. Only inbound CMD_RESPONSE,
    CMD_UNKNOWN, EVENT_CONFIRM, EVENT_UNKNOWN and an exact list-sa EVENT are
    accepted. Confirmation/failure controls must carry no message. This says
    nothing about whether a confirmation is expected at this point in a request.
    The caller must bound a length header before receiving/allocating its body;
    this function operates on already assembled bytes and cannot enforce that.
    """
    if type(frame) is not bytes or not 5<=len(frame)<=MAX_FRAME+4:
        raise WireFault('frame_type_or_size')
    length=int.from_bytes(frame[:4],'big')
    if not 1<=length<=MAX_FRAME or length!=len(frame)-4:
        raise WireFault('frame_length')
    packet_type=frame[4]
    if packet_type not in (1,2,5,6,7):raise WireFault('unexpected_inbound_packet')
    event_name=None;offset=5
    if packet_type==7:
        if offset>=len(frame):raise WireFault('truncated_event_name')
        count=frame[offset];offset+=1
        if count!=7 or len(frame)-offset<count or frame[offset:offset+count]!=b'list-sa':
            raise WireFault('unexpected_event_name')
        offset+=count;event_name='list-sa'
    message=frame[offset:]
    if packet_type in (2,5,6) and message:raise WireFault('unexpected_control_payload')
    return ValidatedFrame(packet_type,event_name,message,validate_message(message))
