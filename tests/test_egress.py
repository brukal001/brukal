"""
test_egress.py — SP-C slice 1: the deterministic egress-decision core, the
runnable forward proxy, the tls-mandatory-for-domain-scopes load_scope rule,
and the hard `is_authorized()` gate at the top of `engagement.run`.

All offline: no live internet, no Docker, no real target. The proxy tests use
an injected resolver (never real DNS) and a real loopback TCP server to stand
in for "the internet", with the private-IP guard relaxed ONLY for that one
test via monkeypatching `brukal.egress.is_blocked_ip` (documented at the top
of that test — every other test keeps the guard real).
"""
from __future__ import annotations

import http.server
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import egress
from brukal.egress import (
    EgressDecision,
    egress_decision,
    is_blocked_ip,
    parse_connect_target,
    parse_http_target,
)
from brukal.egress_proxy import build_server
from brukal.scope import Scope, load_scope


# --------------------------------------------------------------------------- #
# is_blocked_ip
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ip", [
    "10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "fe80::1", "fc00::1",
    "0.0.0.0", "172.16.0.5", "192.168.1.1", "224.0.0.1", "::",
])
def test_is_blocked_ip_true_for_non_public(ip):
    assert is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["1.1.1.1", "93.184.216.34", "2606:4700::1"])
def test_is_blocked_ip_false_for_public(ip):
    assert is_blocked_ip(ip) is False


@pytest.mark.parametrize("junk", ["", "not-an-ip", "999.999.999.999", "   ", None])
def test_is_blocked_ip_fails_closed_on_junk(junk):
    assert is_blocked_ip(junk) is True


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

def test_parse_http_target_origin_form_uses_host_header():
    host, path = parse_http_target("GET /a/b?x=1 HTTP/1.1", {"Host": "Example.com:8080"})
    assert (host, path) == ("example.com", "/a/b?x=1")


def test_parse_http_target_absolute_form():
    host, path = parse_http_target("GET http://Example.com:8080/p HTTP/1.1", {})
    assert (host, path) == ("example.com", "/p")


def test_parse_http_target_absolute_form_no_path_defaults_to_slash():
    host, path = parse_http_target("GET http://example.com HTTP/1.1", {})
    assert (host, path) == ("example.com", "/")


@pytest.mark.parametrize("line,headers", [
    ("not a valid request line", {}),
    ("GET /p HTTP/1.1", {}),                      # origin-form, no Host header
    ("GET http:// HTTP/1.1", {}),                 # absolute-form, no host
    ("", {}),
    ("GET /p NOT-HTTP", {}),
])
def test_parse_http_target_fails_closed(line, headers):
    assert parse_http_target(line, headers) == ("", "")


def test_parse_connect_target_host_port():
    assert parse_connect_target("CONNECT example.com:443 HTTP/1.1") == ("example.com", "443")


def test_parse_connect_target_bracketed_ipv6():
    assert parse_connect_target("CONNECT [::1]:443 HTTP/1.1") == ("::1", "443")


@pytest.mark.parametrize("line", [
    "GET example.com:443 HTTP/1.1",       # wrong method
    "CONNECT example.com HTTP/1.1",       # no port
    "CONNECT example.com:notaport HTTP/1.1",
    "CONNECT HTTP/1.1",
    "",
    "CONNECT example.com:443 NOT-HTTP",
])
def test_parse_connect_target_fails_closed(line):
    assert parse_connect_target(line) == ("", "")


# --------------------------------------------------------------------------- #
# egress_decision
# --------------------------------------------------------------------------- #

def _scope_with_host(host="api.x.com", exclusions=frozenset()):
    return Scope("t", (), frozenset({"*"}), 60,
                authorized_hosts=frozenset({host}), exclusions=exclusions)


def test_egress_decision_allows_in_scope_host_with_public_ip():
    scope = _scope_with_host()
    d = egress_decision(scope, "api.x.com", "/", ["93.184.216.34"])
    assert isinstance(d, EgressDecision)
    assert d.allow is True


def test_egress_decision_denies_out_of_scope_host():
    scope = _scope_with_host()
    d = egress_decision(scope, "evil.example.com", "/", ["93.184.216.34"])
    assert d.allow is False
    assert "scope" in d.reason


def test_egress_decision_denies_excluded_path():
    scope = _scope_with_host("api.x.com", exclusions=frozenset({("api.x.com", "/blog")}))
    d = egress_decision(scope, "api.x.com", "/blog/post1", ["93.184.216.34"])
    assert d.allow is False


def test_egress_decision_denies_on_any_private_resolution():
    """DNS rebinding: an in-scope host that resolves to even one private/internal
    address is denied in full, not tunnelled to the safe-looking address."""
    scope = _scope_with_host()
    d = egress_decision(scope, "api.x.com", "/", ["93.184.216.34", "10.0.0.5"])
    assert d.allow is False
    assert "10.0.0.5" in d.reason


def test_egress_decision_denies_metadata_resolution():
    scope = _scope_with_host()
    d = egress_decision(scope, "api.x.com", "/", ["169.254.169.254"])
    assert d.allow is False


def test_egress_decision_denies_empty_resolution():
    scope = _scope_with_host()
    d = egress_decision(scope, "api.x.com", "/", [])
    assert d.allow is False
    assert "resolution" in d.reason


def test_egress_decision_denies_empty_host():
    scope = _scope_with_host()
    d = egress_decision(scope, "", "/", ["93.184.216.34"])
    assert d.allow is False


# --------------------------------------------------------------------------- #
# proxy — loopback integration
# --------------------------------------------------------------------------- #

class _EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello-from-origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _start_origin_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get_via_proxy(proxy_port, host, path="/"):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    try:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode("ascii"))
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        s.close()


def test_proxy_tunnels_in_scope_host_and_returns_origin_body(monkeypatch):
    """Loopback plumbing test. A real origin server stands in for the internet at
    127.0.0.1, which is normally BLOCKED (is_blocked_ip) — relaxed here, and only
    here, by monkeypatching the module-level guard that both `egress.egress_decision`
    and `egress_proxy` consult. Every other test in this file keeps the real guard."""
    origin = _start_origin_server()
    origin_port = origin.server_address[1]
    monkeypatch.setattr(egress, "is_blocked_ip", lambda ip: False)

    scope = Scope("t", (), frozenset({"*"}), 6000,
                  authorized_hosts=frozenset({"test.host"}))
    audit_path = None
    import tempfile
    tmp = tempfile.mkdtemp()
    from brukal.audit import AuditLog
    audit = AuditLog(Path(tmp) / "audit.jsonl")

    def resolver(host):
        return ["127.0.0.1"] if host == "test.host" else []

    proxy_port = _free_port()
    server = build_server(scope, proxy_port, audit, resolver=resolver)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        raw = _http_get_via_proxy(server.server_address[1], f"test.host:{origin_port}")
        assert b"200" in raw.splitlines()[0]
        assert b"hello-from-origin" in raw

        raw_denied = _http_get_via_proxy(server.server_address[1], "out-of-scope.example.com")
        assert b"403" in raw_denied.splitlines()[0]
    finally:
        server.shutdown()
        server.server_close()
        origin.shutdown()
        origin.server_close()

    kinds = [json.loads(l)["kind"] for l in open(audit.path) if l.strip()]
    data = [json.loads(l)["data"] for l in open(audit.path) if l.strip()]
    assert kinds.count("egress_decision") == 2
    allows = [d for d in data if d.get("allow") is True]
    denies = [d for d in data if d.get("allow") is False]
    assert len(allows) == 1 and len(denies) == 1


# --------------------------------------------------------------------------- #
# tls rule — domain/wildcard scopes must verify TLS
# --------------------------------------------------------------------------- #

def _write(tmp_path, data):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_domain_scope_without_tls_verify_raises(tmp_path):
    p = _write(tmp_path, {
        "engagement": "t", "authorized_cidrs": [], "allowlisted_tools": "all",
        "rate_limit_per_min": 30, "authorized_hosts": ["*.x.com"], "tls_verify": False,
    })
    with pytest.raises(ValueError):
        load_scope(p)


def test_domain_scope_with_tls_verify_true_loads(tmp_path):
    p = _write(tmp_path, {
        "engagement": "t", "authorized_cidrs": [], "allowlisted_tools": "all",
        "rate_limit_per_min": 30, "authorized_hosts": ["*.x.com"], "tls_verify": True,
    })
    scope = load_scope(p)
    assert scope.has_domain_asset() is True


def test_ip_only_scope_with_tls_verify_false_loads_fine(tmp_path):
    p = _write(tmp_path, {
        "engagement": "t", "authorized_cidrs": ["172.20.0.12/32"],
        "allowlisted_tools": "all", "rate_limit_per_min": 30, "tls_verify": False,
    })
    scope = load_scope(p)
    assert scope.has_domain_asset() is False
    assert scope.tls_verify is False


def test_real_crapi_and_dvwa_lab_scopes_still_load():
    root = Path(__file__).resolve().parents[1]
    for name in ("scope.crapi.json", "scope.dvwa.json"):
        f = root / name
        if not f.exists():
            pytest.skip(f"{name} not present in this checkout")
        scope = load_scope(f)
        assert scope.has_domain_asset() is False
        assert scope.tls_verify is False


# --------------------------------------------------------------------------- #
# authorization gate — engagement.run refuses an unauthorized scope
# --------------------------------------------------------------------------- #

def test_engagement_run_refuses_unauthorized_scope_before_acting(tmp_path, monkeypatch, capsys):
    """An `authorized:false` (here: no `authorization` statement at all, and NOT
    expired) scope must be refused by the new hard gate specifically — never reaching
    agent construction, the cage, or any tool use."""
    from brukal import engagement

    scope_path = _write(tmp_path, {
        "engagement": "t", "authorized_cidrs": ["10.10.10.5/32"],
        "allowlisted_tools": "all", "rate_limit_per_min": 30,
        # authorization deliberately absent -> is_authorized() False, not expired
    })

    def _must_not_run(*a, **k):
        raise AssertionError("agents must never be constructed on a refused run")

    monkeypatch.setattr(engagement, "Orchestrator", _must_not_run)
    monkeypatch.setattr(engagement, "DockerKali", _must_not_run)
    monkeypatch.setattr(engagement, "FakeKali", _must_not_run)

    rc = engagement.run("10.10.10.5", fake=True, scope_path=str(scope_path),
                        audit_path=str(tmp_path / "audit.jsonl"),
                        vault_path=str(tmp_path / "vault"))
    assert rc == 2
    out = capsys.readouterr().out.lower()
    assert "not authoris" in out or "no authorization" in out


def test_engagement_run_proceeds_past_authorization_check_when_authorized(
        tmp_path, capsys, monkeypatch):
    """An authorized (and non-expired) scope must get PAST the new gate — the
    refusal text the previous test looks for must NOT appear. Whatever happens next
    is a later, different refusal — here forced to be `LLMClient` construction (no
    network access even if a key happens to be set in this environment), so this
    test stays fully offline like every other test in this file."""
    from brukal import engagement
    import brukal.llm as llm_mod

    class _NoNetworkLLMClient:
        def __init__(self, *a, **k):
            raise RuntimeError("stubbed: no network in this test")

    monkeypatch.setattr(llm_mod, "LLMClient", _NoNetworkLLMClient)

    scope_path = _write(tmp_path, {
        "engagement": "t", "authorized_cidrs": ["10.10.10.5/32"],
        "allowlisted_tools": "all", "rate_limit_per_min": 30,
        "authorization": "SOW-1, signed off",
    })
    rc = engagement.run("10.10.10.5", fake=True, scope_path=str(scope_path),
                        audit_path=str(tmp_path / "audit.jsonl"),
                        vault_path=str(tmp_path / "vault"))
    out = capsys.readouterr().out.lower()
    assert "not authoris" not in out and "no authorization" not in out
    assert "could not initialise the model client" in out   # got past the gate, into LLMClient
    assert rc == 2
    assert load_scope(scope_path).is_authorized() is True
