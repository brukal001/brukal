"""
test_experiment_body_capture.py — an experiment result without its body has no evidence.

THE MEASURED PROBLEM (run CM3, 2026-09-14)
    `GET /rest/basket/8` issued as principal A returned
    `{"status":"success","data":{"id":8,"UserId":27,...}}`. **`UserId: 27` is the entire
    finding** — it is what makes the read a cross-account read rather than an ordinary one.
    The ledger recorded `{"status":200,"url":...,"note":"","bytes":154}` and threw the body
    away, so the one field that carried the claim was never written down.

    The web plane got body capture in August (`_absorb_web`). The experiment plane — the
    one that produces findings — did not.

THE PROPERTY
    A control/variant result carries a BOUNDED excerpt of its response body onto the
    ledger, through the same redaction funnel as every other record. Bounded because a
    response is untrusted target data of unknown size; truncation RECORDED because a
    silently-cut body is a body a reader cannot reason about.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope, redact
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal import hypothesis as hyp
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"
LOGIN = f"{BASE}/rest/user/login"
TOKEN_A = "tok-AAAA-1111-secret"
USER_A, PASS_A = "a@brukal.test", "Pw-A-1!"

RESULT = "experiment_result"


class _Target:
    """CM3's shape: basket 8 answers with an owner field, and 401 to a stranger."""

    ACCOUNTS = {USER_A: {"token": TOKEN_A, "id": 25, "bid": 6}}

    def __init__(self, big: bool = False, echo_token: bool = False):
        self.big = big
        self.echo_token = echo_token

    def _authed(self, headers):
        for k, v in (headers or {}).items():
            if k.lower() == "authorization" and TOKEN_A in (v or ""):
                return True
            if k.lower() == "cookie" and TOKEN_A in (v or ""):
                return True
        return False

    def run(self, action):
        url = action.url
        if url.endswith("/rest/user/login"):
            body = {"authentication": {"token": TOKEN_A, "umail": USER_A, "bid": 6}}
            return WebResult(status=200, url=url, headers={}, body=json.dumps(body))
        if "/rest/basket/" in url:
            if not self._authed(action.headers):
                return WebResult(status=401, url=url, headers={},
                                 body='{"error":"Unauthorized"}')
            want = url.rsplit("/", 1)[-1]
            data = {"id": int(want), "coupon": None, "UserId": 27, "Products": []}
            if self.big:
                data["padding"] = "P" * 9000
            if self.echo_token:
                data["echo"] = TOKEN_A
            return WebResult(status=200, url=url, headers={},
                             body=json.dumps({"status": "success", "data": data}))
        return WebResult(status=404, url=url, headers={}, body="nope")


class _Kali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _LLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return "[]"


def _session(tmp_path, target):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(_LLM()),
                      browser=GovernedBrowser(scope, target, audit))
    s.allow_intrusive = True
    s.login(LOGIN, USER_A, PASS_A, user_field="email", login_type="json")
    return s, audit


def _cm3_hypothesis():
    """Exactly CM3's confirmed experiment: anonymous vs self on another user's basket."""
    return hyp.Hypothesis(
        title="anonymous access to another user's basket",
        severity="high", comparator="a_denied_b_allowed", setup=[],
        control={"method": "GET", "url": f"{BASE}/rest/basket/8", "as": "anonymous"},
        variant={"method": "GET", "url": f"{BASE}/rest/basket/8", "as": "self"})


def _records(audit_path, kind=RESULT) -> list[dict]:
    out = []
    for line in Path(audit_path).read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("kind") == kind:
            out.append(e.get("data", {}))
    return out


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_the_cm3_case_is_recorded_with_its_body(tmp_path):
    """THE DEFECT. `UserId: 27` is the whole finding and it was never written down."""
    s, audit = _session(tmp_path, _Target())
    s._run_one_round([_cm3_hypothesis()], [])

    recs = _records(audit.path)
    assert recs, "no experiment_result record reached the ledger"

    variant = [r for r in recs if r.get("role") == "variant"]
    assert variant, f"no variant result recorded: {recs}"
    assert '"UserId": 27' in variant[0]["body"] or '"UserId":27' in variant[0]["body"], (
        f"the owning id was not captured: {variant[0]!r}")


def test_both_sides_are_recorded_not_only_the_variant(tmp_path):
    """A comparator reads two sides; a record that keeps one cannot be checked."""
    s, audit = _session(tmp_path, _Target())
    s._run_one_round([_cm3_hypothesis()], [])

    roles = {r.get("role") for r in _records(audit.path)}
    assert roles == {"control", "variant"}, roles


def test_the_excerpt_is_bounded_and_truncation_is_recorded(tmp_path):
    """Bounded because a response is untrusted data of unknown size; RECORDED because a
    silently-cut body is one a reader cannot reason about."""
    s, audit = _session(tmp_path, _Target(big=True))
    s._run_one_round([_cm3_hypothesis()], [])

    variant = [r for r in _records(audit.path) if r.get("role") == "variant"][0]
    assert len(variant["body"]) <= hyp.EXPERIMENT_BODY_MAX, len(variant["body"])
    assert variant["truncated"] is True, variant
    # The full size is still stated, so a reader knows what was cut.
    assert variant["bytes"] > len(variant["body"]), variant


def test_an_untruncated_body_says_so(tmp_path):
    """The flag has to distinguish, or it says nothing."""
    s, audit = _session(tmp_path, _Target())
    s._run_one_round([_cm3_hypothesis()], [])

    variant = [r for r in _records(audit.path) if r.get("role") == "variant"][0]
    assert variant["truncated"] is False, variant
    assert variant["bytes"] == len(variant["body"]), variant


def test_a_token_echoed_in_a_captured_body_is_masked(tmp_path):
    """DRIVEN, not assumed. Capturing bodies verbatim is exactly how a credential the
    TARGET discloses reaches an artifact, so the funnel has to be on this path."""
    s, audit = _session(tmp_path, _Target(echo_token=True))
    s._run_one_round([_cm3_hypothesis()], [])

    blob = Path(audit.path).read_text(errors="replace")
    assert TOKEN_A not in blob, "a captured body put the live session token on the ledger"

    variant = [r for r in _records(audit.path) if r.get("role") == "variant"][0]
    assert "[REDACTED:" in variant["body"], (
        f"absence alone proves nothing — the echo must be MASKED: {variant['body']!r}")


def test_existing_experiment_principal_records_keep_their_fields(tmp_path):
    """BOUNDARY. The provenance record that made CM3 readable at all is not disturbed."""
    s, audit = _session(tmp_path, _Target())
    s._run_one_round([_cm3_hypothesis()], [])

    eps = _records(audit.path, kind="experiment_principal")
    assert len(eps) == 2, eps
    for e in eps:
        assert set(e) == {"role", "requested", "resolved", "session", "url", "target"}, e
