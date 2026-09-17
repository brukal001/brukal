"""
test_tls_policy.py — TLS on a pentest target: decided, disclosed, and recorded.

THE DECISION (2026-09-17, from the CR1 pre-flight against crAPI)

    crAPI serves a self-signed certificate; so does nearly every lab appliance, and so
    do a great many real internal targets. Two things follow, and they are separate:

    1. A VERIFICATION FAILURE IS INFORMATION ABOUT THE TARGET. "This host's certificate
       cannot be validated" is a finding-class observation about the target's
       configuration. Discarding it — which is what an exception swallowed into a health
       counter does — throws away a real observation and produces a worse record than
       recording it.

    2. PROCEEDING UNVERIFIED IS A POLICY CHOICE, AND IT IS THE OPERATOR'S. So it is a
       per-engagement parameter carried in the SCOPE, the same idiom as
       `rate_limit_per_min`, disclosed in the ledger, and defaulting to verification ON
       (invariant 2, fail-closed). Never silent, never inferred from the target's
       behaviour, and never something a cage can turn on for itself.

    What we deliberately did NOT do: retry unverified automatically when the scope does
    not say so. That would be the harness widening its own policy at runtime in response
    to what the target did — the exact shape invariant 5 exists to forbid.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, load_scope
from brukal.scope import authorization_record
from brukal.web import GovernedBrowser, WebAction, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
CERT_ERR = ("<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "self signed certificate (_ssl.c:1010)>")


def _scope(tmp_path, **over):
    data = json.loads(SCOPE.read_text())
    data.update(over)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(data))
    return load_scope(p)


class _SelfSignedCage:
    """A target with a self-signed certificate. Verified fetches fail; unverified ones
    answer. Records what policy it was handed, so the test can prove the cage never
    chooses for itself."""

    def __init__(self):
        self.tls_verify = True
        self.policy_calls = []

    def set_tls_verify(self, verify: bool) -> None:
        self.tls_verify = bool(verify)
        self.policy_calls.append(bool(verify))

    def run(self, action):
        if not action.url.startswith("https://"):
            return WebResult(status=200, url=action.url, body="plain")
        if self.tls_verify:
            return WebResult(url=action.url, note=CERT_ERR)
        return WebResult(status=200, url=action.url, body="secured-but-unverified",
                         note="TLS verification DISABLED by scope (tls_verify=false); "
                              "certificate NOT validated: self signed certificate")


class _ValidCertCage:
    def __init__(self):
        self.tls_verify = True

    def set_tls_verify(self, verify: bool) -> None:
        self.tls_verify = bool(verify)

    def run(self, action):
        return WebResult(status=200, url=action.url, body="ok")


def _rows(audit, kind):
    return [json.loads(l) for l in open(audit.path) if json.loads(l)["kind"] == kind]


# --------------------------------------------------------------------------- #
# The parameter: in the scope, defaulting closed, visible in the fingerprint
# --------------------------------------------------------------------------- #

def test_verification_is_ON_by_default(tmp_path):
    """Fail-closed. A scope that says nothing about TLS verifies."""
    assert _scope(tmp_path).tls_verify is True


def test_the_operator_can_disclose_the_decision_in_the_scope(tmp_path):
    assert _scope(tmp_path, tls_verify=False).tls_verify is False


def test_the_decision_changes_the_scope_FINGERPRINT(tmp_path):
    """The fingerprint pins what a run was permitted under. A policy this material must
    not be invisible in it, or two runs under different TLS policies look identical."""
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    a = _scope(tmp_path / "a", tls_verify=True)
    b = _scope(tmp_path / "b", tls_verify=False)
    assert a.fingerprint() != b.fingerprint()


def test_the_decision_is_disclosed_in_the_authorization_record(tmp_path):
    rec = authorization_record(_scope(tmp_path, tls_verify=False), TARGET)
    assert rec.get("tls_verify") is False, (
        "the ledger's authorisation entry does not disclose that this run did not "
        "verify certificates")


def test_the_policy_is_announced_in_the_ledger_on_first_use(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path, tls_verify=False), _SelfSignedCage(), audit)
    b.run(WebAction("get", url=f"https://{TARGET}/"))
    rows = _rows(audit, "tls_policy")
    assert rows and rows[0]["data"]["verify"] is False
    assert rows[0]["data"]["source"] == "scope"


def test_the_cage_cannot_choose_its_own_TLS_policy(tmp_path):
    """BOUNDARY, and the one that matters: policy flows from the immutable scope through
    the browser. A cage never decides, and never keeps a default of its own."""
    cage = _SelfSignedCage()
    GovernedBrowser(_scope(tmp_path, tls_verify=False), cage, AuditLog(tmp_path / "a.jsonl"))
    assert cage.policy_calls == [False]
    cage2 = _SelfSignedCage()
    GovernedBrowser(_scope(tmp_path), cage2, AuditLog(tmp_path / "b.jsonl"))
    assert cage2.policy_calls == [True] and cage2.tls_verify is True


# --------------------------------------------------------------------------- #
# The observation: information about the target, bounded
# --------------------------------------------------------------------------- #

def test_a_verification_failure_is_recorded_as_information_about_the_target(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path), _SelfSignedCage(), audit)
    b.run(WebAction("get", url=f"https://{TARGET}/"))
    rows = _rows(audit, "tls_observation")
    assert rows, "the certificate observation was discarded"
    assert "certificate" in rows[0]["data"]["evidence"].lower()
    assert b.tls_observations, "nothing was kept for the report"


def test_the_observation_is_recorded_once_per_host(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path), _SelfSignedCage(), audit)
    for i in range(5):
        b.run(WebAction("get", url=f"https://{TARGET}/p{i}"))
    assert len(_rows(audit, "tls_observation")) == 1


def test_the_observation_is_BOUNDED_not_an_authorization_or_availability_claim(tmp_path):
    """It says the certificate cannot be validated. It does not say anyone got in, and
    it does not say anything went down."""
    b = GovernedBrowser(_scope(tmp_path), _SelfSignedCage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction("get", url=f"https://{TARGET}/"))
    f = b.tls_observations[0]
    assert f["severity"] in ("info", "low"), f
    assert f["category"] == "tls", f
    assert "certificate" in f["title"].lower()
    blob = json.dumps(f).lower()
    for forbidden in ("bypass", "unauthorized access", "account takeover",
                      "denial of service", "took the target down", "authentication"):
        assert forbidden not in blob, f"the observation is dressed as something else: {forbidden}"


def test_an_unverified_run_still_records_the_observation(tmp_path):
    """Proceeding is not the same as not noticing. With verification disclosed OFF, the
    request succeeds AND the certificate is still recorded as an observation."""
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path, tls_verify=False), _SelfSignedCage(), audit)
    d, r = b.run(WebAction("get", url=f"https://{TARGET}/"))
    assert r.status == 200
    assert _rows(audit, "tls_observation"), "we proceeded unverified and recorded nothing"


def test_a_self_signed_target_is_REACHABLE_when_the_scope_discloses_it(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path, tls_verify=False), _SelfSignedCage(), audit)
    _d, r = b.run(WebAction("get", url=f"https://{TARGET}/"))
    assert r is not None and r.status == 200
    assert b.health.client_failures == 0, "a successful fetch was counted as our failure"


def test_a_properly_verified_target_is_unaffected(tmp_path):
    """BOUNDARY: nothing new fires for a target whose certificate validates."""
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path), _ValidCertCage(), audit)
    b.run(WebAction("get", url=f"https://{TARGET}/"))
    assert not _rows(audit, "tls_observation")
    assert not b.tls_observations
    assert b.health.state == "healthy"


def test_verification_stays_ON_unless_the_scope_says_otherwise(tmp_path):
    """The failure is surfaced as a harness limit (Fix 1) and the request is NOT retried
    unverified — the harness never widens its own policy in response to the target."""
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(_scope(tmp_path), _SelfSignedCage(), audit)
    _d, r = b.run(WebAction("get", url=f"https://{TARGET}/"))
    assert r.status is None
    assert _rows(audit, "harness_limit")[0]["data"]["cause"] == "tls-verification"


# --------------------------------------------------------------------------- #
# The real backend, against a real self-signed server
# --------------------------------------------------------------------------- #

def _self_signed_server(tmp_path):
    """A real HTTPS server with a real self-signed certificate, or a skip."""
    import http.server, ssl, subprocess, threading
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
                        str(key), "-out", str(crt), "-days", "1", "-nodes",
                        "-subj", "/CN=localhost"],
                       capture_output=True, timeout=60, check=True)
    except Exception as e:                                  # pragma: no cover
        pytest.skip(f"openssl unavailable: {e}")
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2")
            self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"https://127.0.0.1:{srv.server_address[1]}/"


def test_the_real_cage_refuses_a_self_signed_certificate_by_default(tmp_path):
    from brukal.web import HttpWebCage
    srv, url = _self_signed_server(tmp_path)
    try:
        r = HttpWebCage().run(WebAction("get", url=url))
        assert r.status is None
        assert "certificate" in (r.note or "").lower()
    finally:
        srv.shutdown()


def test_the_real_cage_proceeds_when_the_policy_says_so_and_says_it_did(tmp_path):
    from brukal.web import HttpWebCage
    srv, url = _self_signed_server(tmp_path)
    try:
        cage = HttpWebCage()
        cage.set_tls_verify(False)
        r = cage.run(WebAction("get", url=url))
        assert r.status == 200 and r.body == "ok"
        assert "not validated" in (r.note or "").lower(), (
            "the response came back with no record that it was unverified")
    finally:
        srv.shutdown()
