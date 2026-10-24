#!/usr/bin/env python3
"""Loopback-only read-only preview. No privileged commands or VPN controls."""
import argparse
import ctypes
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import os
import stat
import threading
from schema import EMPTY, sanitize

ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/index.html': ('index.html', 'text/html; charset=utf-8'),
          '/style.css': ('style.css', 'text/css; charset=utf-8'),
          '/app.mjs': ('app.mjs', 'text/javascript; charset=utf-8'),
          '/model.mjs': ('model.mjs', 'text/javascript; charset=utf-8'),
          '/daily_model_v2.mjs': ('daily_model_v2.mjs', 'text/javascript; charset=utf-8')}


def snapshot_no_acl(fd):
    """Root-owned mode 0644 must not conceal an ACL granting extra writers."""
    lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    lib.acl_get_fd_np.argtypes=[ctypes.c_int,ctypes.c_int]
    lib.acl_get_fd_np.restype=ctypes.c_void_p
    lib.acl_free.argtypes=[ctypes.c_void_p]
    lib.acl_free.restype=ctypes.c_int
    ctypes.set_errno(0)
    acl=lib.acl_get_fd_np(fd,0x100)
    error=ctypes.get_errno()
    if acl:
        try:raise ValueError('extended telemetry ACL')
        finally:
            if lib.acl_free(acl)!=0:raise ValueError('telemetry ACL release failed')
    if error!=errno.ENOENT:raise ValueError('telemetry ACL status unknown')


class LocalServer(ThreadingHTTPServer):
    """A fixed small thread budget for the persistent local-only reader."""
    daemon_threads=True
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(16)
        super().__init__(*args,**kwargs)

    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:super().process_request(request,client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()


class SnapshotReplaced(ValueError):
    """The fixed path names another inode; retry once, never serve old bytes."""


def snapshot_stamp(info):
    # Reading can change atime. Keep identity, permissions and mutation fields.
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def snapshot_unchanged(path, fd, before):
    after = os.fstat(fd)
    current = path.lstat()
    if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
        raise SnapshotReplaced('telemetry export replaced')
    if snapshot_stamp(after) != snapshot_stamp(before) or snapshot_stamp(current) != snapshot_stamp(before):
        raise ValueError('telemetry export changed in place')


def read_snapshot_once(path):
    # Export is a dedicated telemetry-only file, never a general log or key.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        # Keep raw-FD ownership until the outer finally, including fdopen/setup
        # failure. The read-only wrapper never owns or double-closes this FD.
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            s = os.fstat(handle.fileno())
            snapshot_unchanged(path, fd, s)
            if (not stat.S_ISREG(s.st_mode) or s.st_size > 131072 or s.st_uid!=0
                    or stat.S_IMODE(s.st_mode)!=0o644 or s.st_nlink!=1):
                raise ValueError('invalid telemetry export')
            snapshot_no_acl(handle.fileno())
            snapshot_unchanged(path, fd, s)
            raw = handle.read(131073)
            snapshot_unchanged(path, fd, s)
            if len(raw) > 131072 or len(raw)!=s.st_size:
                raise ValueError('oversized telemetry export')
            data = json.loads(raw)
    finally:
        os.close(fd)
    return sanitize(data)


def read_snapshot(path):
    if path is None:
        return EMPTY
    for attempt in range(2):
        try:
            return read_snapshot_once(path)
        except SnapshotReplaced:
            if attempt:
                raise


def make_handler(root, snapshot, port):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *args):
            pass

        def reply(self, code, body=b'', mime='text/plain; charset=utf-8'):
            self.send_response(code)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
            if (self.headers.get_all('Host', []) not in [[h] for h in hosts]
                    or self.headers.get('Origin') not in {None, *('http://' + h for h in hosts)}
                    or self.headers.get('Sec-Fetch-Site') == 'cross-site'
                    or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length') not in {None, '0'}):
                return self.reply(403, b'Local access only')
            if self.path == '/api/status':
                try:
                    data = read_snapshot(snapshot)
                    body = json.dumps(data, ensure_ascii=False, allow_nan=False).encode()
                except (OSError, ValueError, TypeError, KeyError):
                    body = json.dumps(EMPTY).encode()
                return self.reply(200, body, 'application/json; charset=utf-8')
            if self.path not in ASSETS:
                return self.reply(404)
            name, mime = ASSETS[self.path]
            return self.reply(200, (root / name).read_bytes(), mime)

        def do_POST(self):
            self.reply(405, b'Read only')

    return Handler


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--port', type=int, default=8767)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('local HTTP server must run as an unprivileged user')
    if not 1024 <= args.port <= 65535:
        parser.error('unprivileged local port required')
    root = args.root.resolve(strict=True)
    for name, _ in ASSETS.values():
        if not (root / name).is_file() or (root / name).is_symlink():
            parser.error('missing or unexpected static asset')
    server = LocalServer(('127.0.0.1', args.port), make_handler(root, args.snapshot, args.port))
    server.daemon_threads = True
    print(f'Local preview: http://127.0.0.1:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
