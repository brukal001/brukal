"""
egress_proxy.py — a minimal, runnable HTTP/HTTPS(CONNECT) forward proxy for the
cage (SP-C, slice 1). It composes `egress.py` (the pure decision core) with the
only real I/O this milestone needs: DNS resolution (injectable, so tests never
touch the real network) and a TCP connect to the resolved address.

Shape, deliberately: this module does NO judging itself. Every request is
parsed by `egress.parse_http_target` / `egress.parse_connect_target`, resolved
through the injected resolver, and judged by `egress.egress_decision` against
the frozen `Scope` the proxy was started with — exactly the same scope object
the rest of the engagement uses, never re-derived or re-parsed here. On ALLOW
we tunnel to a resolved PUBLIC ip; on DENY we answer 403 and close. Belt and
suspenders: even after an ALLOW, we connect only to a resolved address that
`egress.is_blocked_ip` itself says is not blocked — the decision already
excludes them, so this can only ever be a no-op, never a widening.

Every module-level lookup below goes through `egress.<name>` (not a bare
imported name) so a test can monkeypatch `brukal.egress.is_blocked_ip` (or any
other function here) and have BOTH `egress_decision`'s internal check and this
module's own belt-and-suspenders check see the same patched behaviour — the
two are never allowed to disagree about what counts as blocked.

Slice 1 explicitly does NOT: rewire the live cage's nftables egress, perform
TLS interception (so path exclusions are unenforceable on CONNECT — the
decision is host-only there, documented in egress.py), or run against a real
target. That is slice 2, separately authorised.
"""
from __future__ import annotations

import select
import socket
import socketserver
import threading
from typing import Callable

from . import egress

_CONNECT_TIMEOUT = 10.0
_IDLE_TIMEOUT = 30.0
_MAX_LINE = 65536


def default_resolver(host: str) -> list:
    """The real resolver: `socket.getaddrinfo`. Never used in a test — tests
    always inject their own so no test touches a real DNS server."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    seen, out = set(), []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _relay(a: socket.socket, b: socket.socket, timeout: float = _IDLE_TIMEOUT) -> None:
    """Shovel bytes both ways between two connected sockets until either side
    closes, errors, or goes idle past `timeout`. Used for both the CONNECT
    tunnel (raw TLS bytes) and the plain-HTTP relay (request + response) —
    slice 1 does not otherwise parse HTTP framing once a request has been
    judged and forwarded, so this one routine covers both paths."""
    socks = [a, b]
    try:
        while True:
            try:
                readable, _, errored = select.select(socks, [], socks, timeout)
            except OSError:
                break
            if errored or not readable:
                break
            stop = False
            for s in readable:
                other = b if s is a else a
                try:
                    data = s.recv(65536)
                except OSError:
                    stop = True
                    break
                if not data:
                    stop = True
                    break
                try:
                    other.sendall(data)
                except OSError:
                    stop = True
                    break
            if stop:
                break
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def _first_public_ip(ips) -> str | None:
    """Belt-and-suspenders: pick a resolved address that is not blocked, even
    though `egress_decision` having ALLOWed already means none of them are.
    Never connects to a blocked ip regardless of the decision."""
    for ip in ips:
        if not egress.is_blocked_ip(ip):
            return ip
    return None


class _ProxyHandler(socketserver.StreamRequestHandler):
    """One connection, one request (slice 1: no keep-alive/pipelining). The
    scope, audit log, and resolver live on `self.server` (set by
    `build_server`) so every handler instance shares the one frozen scope."""

    def setup(self):
        super().setup()
        try:
            self.connection.settimeout(_CONNECT_TIMEOUT)
        except OSError:
            pass

    def handle(self):
        try:
            first_line = self.rfile.readline(_MAX_LINE).decode("iso-8859-1", "replace")
        except Exception:
            return
        first_line = first_line.rstrip("\r\n")
        if not first_line:
            return
        try:
            headers = self._read_headers()
        except Exception:
            return
        if first_line.upper().startswith("CONNECT "):
            self._handle_connect(first_line)
        else:
            self._handle_http(first_line, headers)

    def _read_headers(self) -> dict:
        headers: dict = {}
        while True:
            line = self.rfile.readline(_MAX_LINE).decode("iso-8859-1", "replace")
            if line in ("\r\n", "\n", ""):
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers

    def _deny(self) -> None:
        try:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
        except OSError:
            pass

    def _judge(self, host: str, path: str) -> "egress.EgressDecision":
        ips = self.server.resolver(host) if host else []
        decision = egress.egress_decision(self.server.scope, host, path, ips)
        self.server.audit.append("egress_decision", decision)
        return decision, ips

    def _handle_connect(self, request_line: str) -> None:
        host, port = egress.parse_connect_target(request_line)
        # CONNECT carries no path (HTTPS is encrypted end to end) — judged host-only,
        # the documented limitation in egress.py.
        decision, ips = self._judge(host, "")
        if not decision.allow:
            self._deny()
            return
        target_ip = _first_public_ip(ips)
        if target_ip is None:                       # belt-and-suspenders, unreachable on ALLOW
            self._deny()
            return
        try:
            port_i = int(port)
        except ValueError:
            self._deny()
            return
        try:
            upstream = socket.create_connection((target_ip, port_i), timeout=_CONNECT_TIMEOUT)
        except OSError:
            self._deny()
            return
        try:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            upstream.close()
            return
        _relay(self.connection, upstream)

    def _handle_http(self, request_line: str, headers: dict) -> None:
        host, path = egress.parse_http_target(request_line, headers)
        decision, ips = self._judge(host, path)
        if not decision.allow:
            self._deny()
            return
        target_ip = _first_public_ip(ips)
        if target_ip is None:                        # belt-and-suspenders, unreachable on ALLOW
            self._deny()
            return
        port = 80
        host_header = headers.get("Host") or headers.get("host") or ""
        if host_header and not host_header.startswith("["):
            if host_header.count(":") == 1:
                try:
                    port = int(host_header.rsplit(":", 1)[1])
                except ValueError:
                    port = 80
        try:
            upstream = socket.create_connection((target_ip, port), timeout=_CONNECT_TIMEOUT)
        except OSError:
            self._deny()
            return
        try:
            upstream.sendall((request_line + "\r\n").encode("iso-8859-1", "replace"))
            header_bytes = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            upstream.sendall((header_bytes + "\r\n").encode("iso-8859-1", "replace"))
        except OSError:
            upstream.close()
            return
        _relay(self.connection, upstream)


class EgressProxyServer(socketserver.ThreadingTCPServer):
    """Threaded so one slow/tunnelled connection never blocks another — an
    implementation choice, not a design requirement (slice 1 only requires
    correctness, not concurrency); each connection is still judged by the one
    deterministic, side-effect-free `egress_decision` call."""
    daemon_threads = True
    allow_reuse_address = True


def build_server(scope, port: int, audit, resolver: Callable[[str], list] | None = None
                 ) -> EgressProxyServer:
    """Construct (but do not start) the proxy server bound to localhost:port,
    holding the given FROZEN scope, audit log, and resolver. Split out from
    `run_proxy` so tests can start/stop it explicitly around a loopback
    integration check without blocking on `serve_forever()`."""
    server = EgressProxyServer(("127.0.0.1", port), _ProxyHandler)
    server.scope = scope
    server.audit = audit
    server.resolver = resolver or default_resolver
    return server


def run_proxy(scope, port: int, audit, resolver: Callable[[str], list] | None = None) -> None:
    """The runnable entry point: build the server and serve forever. Binds
    localhost only — this is the cage-local proxy the cage's HTTP(S)_PROXY
    environment points at, not something meant to be reachable off-box."""
    server = build_server(scope, port, audit, resolver=resolver)
    try:
        server.serve_forever()
    finally:
        server.server_close()
