"""
test_unauthenticated_exposure.py — the finding four consecutive runs could not publish.

THE MEASURED PROBLEM (CR1 runs 4, 5, 6, 7)
    crAPI's /workshop/api/shop/orders/{id} returns another tenant's complete order —
    email, phone, product, payment — to a caller with NO CREDENTIALS AT ALL. Verified
    live, repeatedly:

        anonymous GET /workshop/api/shop/orders/1  ->  200
        {"order":{"id":1,"user":{"email":"adam007@example.com","number":"9876895423"},…}}

    Brukal saw it every time. The bridge turned it into an experiment. And every one came
    back `not_confirmed`, because the only question available was `a_denied_b_allowed` —
    "is the anonymous caller refused and are we accepted?" — whose answer is genuinely NO.
    The comparator was right to refuse: that claim is false, nothing is enforced there.

    The truth is strictly worse than the question, and there was no comparator for it. So
    a real, serious vulnerability sat in the ledger unpublished across four runs while
    recall reported 0.

THE FIX
    An observation now becomes TWO questions, because it is compatible with two truths and
    which one holds is up to the target: authentication enforced but not authorization
    (BOLA), or nothing enforced at all. Exactly one can hold.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import from_foreign_record
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
ORDER = f"{BASE}/workshop/api/shop/orders/1"
OURS = "us@brukal.test"
# crAPI's real body, from the live container.
FOREIGN = json.dumps({"order": {"id": 1, "status": "delivered",
                                "user": {"email": "adam007@example.com",
                                         "number": "9876895423"},
                                "product": {"id": 1, "name": "Seat", "price": "10.00"}}})


class _Crapi:
    """crAPI as measured: the order endpoint authenticates nobody."""

    def __init__(self, require_auth=False):
        self.require_auth = require_auth

    def run(self, action):
        authed = "Authorization" in (action.headers or {})
        if self.require_auth and not authed:
            return WebResult(status=401, url=action.url, body='{"message":"unauthorized"}')
        return WebResult(status=200, url=action.url, body=FOREIGN)


def _session(tmp_path, cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s.identity = OURS
    s.browser.auth_header = "Bearer ours"
    s.surface = AttackSurface(seed=f"{BASE}/")
    return s, audit


def _outcomes(audit):
    return [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == "experiment_outcome"]


def test_crAPIs_real_case_is_FINALLY_a_finding(tmp_path):
    """THE WHOLE POINT. Four runs saw this and published nothing."""
    s, audit = _session(tmp_path, _Crapi())
    s._run_one_round(from_foreign_record(ORDER, FOREIGN, {OURS}), [], [])
    out = _outcomes(audit)
    by = {o["comparator"]: o["outcome"] for o in out}
    assert by.get("unauthenticated_exposure") == "confirmed", out
    # And the BOLA question correctly does NOT hold — nothing was enforced to bypass.
    assert by.get("a_denied_b_allowed") == "not_confirmed", out


def test_when_auth_IS_enforced_the_other_question_holds_instead(tmp_path):
    """BOUNDARY: exactly one of the two can hold. On a target that refuses the anonymous
    caller and accepts us, the BOLA claim is the true one and the exposure claim is not."""
    s, audit = _session(tmp_path, _Crapi(require_auth=True))
    s._run_one_round(from_foreign_record(ORDER, FOREIGN, {OURS}), [], [])
    by = {o["comparator"]: o["outcome"] for o in _outcomes(audit)}
    assert by.get("a_denied_b_allowed") == "confirmed", by
    assert by.get("unauthenticated_exposure") == "not_confirmed", by


def test_our_OWN_record_read_anonymously_is_not_this_finding(tmp_path):
    """BOUNDARY: an endpoint that needs no auth and returns OUR data is an availability
    choice, not somebody else's record. The party test is what separates them."""
    ours_body = json.dumps({"order": {"id": 1, "user": {"email": OURS}}})
    class _Ours(_Crapi):
        def run(self, action):
            return WebResult(status=200, url=action.url, body=ours_body)
    s, audit = _session(tmp_path, _Ours())
    made = from_foreign_record(ORDER, ours_body, {OURS})
    assert not made, "our own record should not even propose"


def test_a_refusal_is_never_this_finding(tmp_path):
    """BOUNDARY: a 401/403 to the anonymous caller is the application working."""
    class _Locked(_Crapi):
        def run(self, action):
            return WebResult(status=403, url=action.url, body='{"message":"forbidden"}')
    s, audit = _session(tmp_path, _Locked())
    s._run_one_round(from_foreign_record(ORDER, FOREIGN, {OURS}), [], [])
    by = {o["comparator"]: o["outcome"] for o in _outcomes(audit)}
    assert by.get("unauthenticated_exposure") == "not_confirmed", by


def test_the_published_claim_says_what_was_shown(tmp_path):
    """Bounded: an unauthenticated caller retrieved a record naming someone who is not us.
    Not 'database breach', not 'account takeover'."""
    s, audit = _session(tmp_path, _Crapi())
    s._run_one_round(from_foreign_record(ORDER, FOREIGN, {OURS}), [], [])
    blob = " ".join(f"{getattr(f, 'title', '')} {getattr(f, 'evidence', '')} "
                    f"{getattr(f, 'category', '')}" for f in s.findings.all()).lower()
    assert "unauthenticated" in blob or "no credentials" in blob, blob[:400]
    # Word boundaries: a substring check for "rce" matches inside "source" and "force",
    # which is how this assertion failed itself the first time.
    import re as _re
    for overclaim in ("takeover", "breach", "rce", "all users"):
        assert not _re.search(rf"\b{overclaim}\b", blob), blob[:400]
    # And the severity is earned, not inherited: without an explicit evidence-class entry
    # this published crAPI's unauthenticated PII exposure as a LOW.
    assert any(f.severity in ("high", "critical") for f in s.findings.all()), \
        [(f.severity, f.title) for f in s.findings.all()]


def test_the_headline_does_not_contradict_its_own_evidence(tmp_path):
    """RUN 9's DEFECT. The finding published as:

        "anonymous refused, self accepted at /workshop/api/shop/orders/2 —
         anonymous vs self, 200/548B vs 200/548B"

    The anonymous caller was NOT refused. Both sides answered 200 — that IS the finding.
    The generic authorization headline was applied because this class is flagged as an
    access-control finding, and it stated the opposite of the evidence printed beside it.
    """
    from brukal.hypothesis import derive_claim
    got = derive_claim("unauthenticated_exposure", "anonymous", "self",
                       control={"url": ORDER, "status": 200, "size": 548},
                       variant={"url": ORDER, "status": 200, "size": 548})
    head = got["title"].lower()
    assert "refused" not in head, got["title"]
    assert "unauthenticated" in head, got["title"]
    assert got["severity_cap"] == "high", got
