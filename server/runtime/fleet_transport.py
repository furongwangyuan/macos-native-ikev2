"""Bounded fixed read-only exchange on an already connected owned Unix socket.

No connect/path/CLI or command selector. The caller must independently establish
the protected socket and daemon/config/registry identity before and after this
function, and impose an outer worker deadline. This does not authenticate peers.
The supplied socket is exclusively consumed and closed on every accepted path.
"""
import errno
import math
import socket
import time

from fleet_exchange import DEADLINE_SECONDS, Exchange, ExchangeFault


class TransportFault(ValueError):
    pass


class TransientTransportFault(TransportFault):
    """A complete observation was unavailable; no partial inventory is usable."""


def socket_error(error):
    """Classify fixed socket failures without disclosing OS error text."""
    if isinstance(error, (TimeoutError, socket.timeout)):
        return TransientTransportFault('vici_exchange_timeout')
    if isinstance(error, OSError) and error.errno in {
            errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT,
            errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE, errno.ENOTCONN,
            errno.ECONNREFUSED}:
        return TransientTransportFault('vici_exchange_io')
    return TransportFault('vici_exchange_socket')


def query(sock, *, deadline=None):
    if type(sock) is not socket.socket:
        raise TransportFault('concrete_owned_socket_required')
    started = time.monotonic()
    exchange = Exchange(started)
    try:
        with sock:
            if deadline is not None and (type(deadline) not in (int, float)
                    or not math.isfinite(deadline)):
                raise TransportFault('vici_exchange_deadline_invalid')
            end = min(started + DEADLINE_SECONDS, deadline) if deadline is not None else started + DEADLINE_SECONDS
            if sock.family != socket.AF_UNIX or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                raise TransportFault('connected_unix_stream_required')
            # getpeername is just a connectedness check, not peer authentication.
            sock.getpeername()
            while not exchange.complete:
                now = time.monotonic()
                remaining = end - now
                if remaining <= 0:
                    raise TransientTransportFault('vici_exchange_timeout')
                sock.settimeout(remaining)
                if exchange.phase.startswith('SEND_'):
                    packet = exchange.outbound(now)
                    sock.sendall(packet)
                else:
                    limit = exchange.receive_limit(now)
                    data = sock.recv(limit)
                    now = time.monotonic()
                    if not data:
                        exchange.eof(now)
                    exchange.feed(data, now)
            now = time.monotonic()
            if now >= end:
                raise TransientTransportFault('vici_exchange_timeout')
            return exchange.result(now)
    except TransportFault:
        raise
    except OSError as error:
        raise socket_error(error) from None
    except ExchangeFault as error:
        # The bounded transcript was discarded before any partial inventory
        # escaped. Exact event-capacity pressure may use the existing fully
        # closed recovery path; malformed packets and other limits stay hard.
        if type(error) is ExchangeFault and error.args == ('event_count',):
            raise TransientTransportFault('vici_exchange_capacity') from None
        if error.args == ('exchange_deadline',):
            raise TransientTransportFault('vici_exchange_timeout') from None
        if error.args in (('unexpected_eof',), ('truncated_frame',)):
            raise TransientTransportFault('vici_exchange_eof') from None
        raise TransportFault('vici_exchange_protocol') from None
    except ValueError:
        # No raw payload, addresses, paths, peer details or exception text escape.
        raise TransportFault('vici_exchange_protocol') from None
