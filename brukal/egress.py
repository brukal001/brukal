"""
egress.py — deterministic, pure decision core for the scope-aware egress proxy
(SP-C, slice 1).

This module is the "gate" for OUTBOUND traffic, the same shape as `gate.py` is
the gate for tool invocation: no LLM, no network I/O, fail-closed on anything
ambiguous or unparseable. It answers exactly one question — "may this request
leave the cage?" — from data the caller supplies (the request line, its
headers, and an already-resolved IP list). It never resolves DNS itself and
never opens a socket; `egress_proxy.py` composes this with real I/O.

Why a per-request host check, not just the kernel's IP allowlist: a real
program is a domain/wildcard behind rotating CDN IPs, so a static IP lock
can't be both tight and reachable. Enforcing on the host survives rotation;
the kernel egress lock stays as a coarse backstop underneath this.

Why resolved IPs are checked too, not just the host: a malicious or careless
DNS answer for an in-scope host could point at a private/internal address
(DNS rebinding). The host being in scope only ever authorises WHICH NAME may
be asked for; it never authorises WHICH IP the answer may land on. Checking
every resolved IP against `is_blocked_ip` is what defeats that — an in-scope
host that momentarily resolves to 169.254.169.254 or 10.0.0.5 is DENIED, not
silently tunnelled to an internal address.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

# The AWS/GCP/Azure link-local metadata address. It is also covered by
# `is_link_local` below, but it is named explicitly because it is the single
# highest-value address to block by name, not by accident of a broader rule.
_METADATA_IP = "169.254.169.254"


def is_blocked_ip(ip: str) -> bool:
    """True for any IP that must never be dialled from inside the cage: RFC1918
    private space (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
    link-local (169.254/16, fe80::/10) including the cloud-metadata address,
    ULA (fc00::/7), unspecified (0.0.0.0, ::), and multicast/reserved space.

    Fail-closed (invariant 2): anything that does not parse as an IP address
    at all is treated as blocked — we never dial something we could not even
    classify.
    """
    text = (ip or "").strip()
    if not text:
        return True
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return True
    if text == _METADATA_IP:
        return True
    return bool(
        addr.is_private          # RFC1918, ULA (fc00::/7), loopback, link-local, ...
        or addr.is_loopback
        or addr.is_link_local    # covers 169.254/16 and fe80::/10
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _host_no_port(raw: str) -> str:
    """Lowercase a host, dropping a trailing `:port`. Handles a bracketed IPv6
    literal (`[::1]` / `[::1]:8443`). Malformed input (unbalanced bracket)
    fails closed to the empty string."""
    h = (raw or "").strip().lower()
    if not h:
        return ""
    if h.startswith("["):
        end = h.find("]")
        if end == -1:
            return ""            # malformed: no closing bracket
        return h[1:end]
    if h.count(":") == 1 and not h.replace(":", "").isalpha():
        h = h.split(":", 1)[0]
    return h


def _get_header(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. `headers` is a plain dict as handed to
    us by the proxy; keys may arrive in any case."""
    if not headers:
        return ""
    name = name.lower()
    for k, v in headers.items():
        if str(k).strip().lower() == name:
            return str(v).strip()
    return ""


def parse_http_target(request_line: str, headers: dict) -> tuple[str, str]:
    """Extract `(host, path)` from one proxied HTTP request. Supports:

      * absolute-form  — `GET http://host[:port]/path HTTP/1.1` (what a
        correctly-configured HTTP proxy client sends)
      * origin-form     — `GET /path HTTP/1.1` plus a `Host:` header (what a
        client sends once a CONNECT tunnel — or plain HTTP behind a
        transparent proxy — is already established)

    Fails closed to `("", "")` on anything that does not parse cleanly: a
    malformed request line, an unsupported method line shape, an absolute-form
    URI with no host, or an origin-form request with no usable Host header.
    """
    try:
        line = (request_line or "").strip()
        parts = line.split(" ")
        if len(parts) != 3:
            return ("", "")
        _method, uri, version = parts
        if not version.upper().startswith("HTTP/"):
            return ("", "")
        if uri.lower().startswith("http://") or uri.lower().startswith("https://"):
            sp = urlsplit(uri)
            host = _host_no_port(sp.hostname or "")
            if not host:
                return ("", "")
            path = sp.path or "/"
            if sp.query:
                path = f"{path}?{sp.query}"
            return (host, path)
        if uri.startswith("/"):
            host = _host_no_port(_get_header(headers, "host"))
            if not host:
                return ("", "")
            return (host, uri)
        return ("", "")
    except Exception:
        return ("", "")


def parse_connect_target(connect_line: str) -> tuple[str, str]:
    """Extract `(host, port)` from a `CONNECT host:port HTTP/1.1` request line.

    HTTPS traffic inside the tunnel is encrypted, so per-path exclusions are
    NOT enforceable on a CONNECT request — only the host (and host-level
    exclusions) can be judged here. That is a documented limitation of slice
    1; slice 2 may add TLS interception to recover path visibility.

    Fails closed to `("", "")` on anything malformed.
    """
    try:
        line = (connect_line or "").strip()
        parts = line.split(" ")
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            return ("", "")
        authority, version = parts[1], parts[2]
        if not version.upper().startswith("HTTP/"):
            return ("", "")
        if authority.startswith("["):
            end = authority.find("]")
            if end == -1:
                return ("", "")
            host = authority[1:end]
            rest = authority[end + 1:]
            if not (rest.startswith(":") and rest[1:].isascii() and rest[1:].isdigit()):
                return ("", "")
            port = rest[1:]
        else:
            if authority.count(":") != 1:
                return ("", "")
            host, port = authority.split(":", 1)
            if not (port.isascii() and port.isdigit()):
                return ("", "")
        host = host.strip().lower()
        if not host:
            return ("", "")
        return (host, port)
    except Exception:
        return ("", "")


@dataclass
class EgressDecision:
    """The structured ruling for one proxied request — the egress equivalent of
    `gate.Decision`. Exactly what gets written to the audit log."""
    allow: bool
    reason: str
    host: str
    path: str


def egress_decision(scope, host: str, path: str, resolved_ips: list) -> EgressDecision:
    """ALLOW iff every check holds, else DENY on the first failing one
    (fail-closed, deterministic, no network — the caller resolves DNS and
    hands the answers in):

      (a) `host` is non-empty;
      (b) `scope.in_scope(host, path)` (SP-A's own scope logic — reused, never
          re-implemented here);
      (c) `resolved_ips` is non-empty (an empty resolution is refused, not
          treated as "nothing to check");
      (d) no IP in `resolved_ips` is `is_blocked_ip` — ANY private/metadata
          resolution denies the whole request, which is what defeats
          DNS-rebinding an in-scope host to an internal address.
    """
    h = (host or "").strip()
    p = path or ""
    if not h:
        return EgressDecision(False, "empty host", h, p)
    if not scope.in_scope(h, p):
        return EgressDecision(False, "host/path not in scope", h, p)
    ips = list(resolved_ips or [])
    if not ips:
        return EgressDecision(False, "empty DNS resolution", h, p)
    for ip in ips:
        if is_blocked_ip(ip):
            return EgressDecision(
                False, f"resolved ip {ip} is private/metadata/blocked", h, p)
    return EgressDecision(True, "in-scope host, public resolution", h, p)
