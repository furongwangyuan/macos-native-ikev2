"""Pure outer-address scope. Legacy journals retain their IPv4-only meaning."""
import ipaddress

IPV4 = ('192.0.2.8',)


def normalize(values=IPV4):
    if type(values) not in (tuple,list) or len(values) not in (1,2) or values[0]!=IPV4[0]:
        raise ValueError('outer local scope')
    if len(values)==2:
        value=values[1]
        if type(value)is not str:
            raise ValueError('outer local IPv6 type')
        address=ipaddress.IPv6Address(value)
        if (str(address)!=value or not address.is_global or address.is_multicast
                or address.ipv4_mapped is not None or address.scope_id is not None):
            raise ValueError('outer local IPv6 scope')
    return tuple(values)


def from_health(health):
    return normalize((health['lan4'],health['stable6']))


def pair(local,peer,allowed=IPV4):
    allowed=normalize(allowed)
    if type(local)is not str or type(peer)is not str or local not in allowed:
        raise ValueError('outer local endpoint')
    address=ipaddress.ip_address(peer)
    if (str(address)!=peer or address.version!=ipaddress.ip_address(local).version
            or address.is_unspecified or address.is_loopback or address.is_link_local
            or address.is_multicast or peer in (local,'255.255.255.255')
            or (address.version==6 and (address.scope_id is not None or address.ipv4_mapped is not None))):
        raise ValueError('outer peer endpoint')
    return local,peer


def route_family(peer):
    return '-inet6' if ipaddress.ip_address(peer).version==6 else '-inet'


def ike_sockets(text,allowed=IPV4):
    """Compare the owned daemon's exact UDP family/port inventory, not row order."""
    expected={(family,port) for family in ('IPv4','IPv6')[:len(normalize(allowed))] for port in (500,4500)}
    seen=[];family=None
    for line in text.splitlines():
        if line.startswith('f'):
            family=None
        elif line.startswith('t'):
            family=line[1:]
        elif line.startswith('n'):
            address,separator,port=line[1:].rpartition(':')
            if not separator or address not in ('*','[::]','0.0.0.0') or not port.isdecimal():
                return False
            seen.append((family,int(port)))
    return len(seen)==len(expected) and set(seen)==expected
