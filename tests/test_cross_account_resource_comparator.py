"""
test_cross_account_resource_comparator.py — a comparator for the canonical IDOR shape.

THE MEASURED PROBLEM (run CM3, 2026-09-14)
    Experiment #3 issued `GET /api/Users/27` as the SECOND principal and as SELF, and got
    **200/329B on both sides**. It was correctly not confirmed: `a_denied_b_allowed` needs
    a refusal, `b_reveals_more` needs a 2x size difference, and neither happened.

    But principal A had just read a resource belonging to principal B. **The canonical BOLA
    shape is BOTH SIDES ALLOWED**, and nothing in the closed comparator set could ask
    whether an allowed read was allowed WRONGLY — so the one thing the capability milestone
    is about was unaskable.

THE PROPERTY
    A comparator confirms when both sides succeeded AND the variant's captured body carries
    an identifier the LEDGER'S OWNERSHIP RECORD attributes to a different registered
    principal. Deterministic: the ownership map is recorded (Fix 1), the id is in the
    captured body (Fix 2), and no model is anywhere in the decision.

    It EARNS a cross-account claim at high severity precisely because it is grounded in
    recorded ownership rather than in a model's sentence — which is the defect `1940f09`
    exists to prevent.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp

COMPARATOR = "cross_account_resource"


class _R:
    """One observed response."""

    def __init__(self, status, body=""):
        self.status = status
        self.body = body


def _h(comparator=COMPARATOR, control_as="second", variant_as="self"):
    return hyp.Hypothesis(
        title="cross-account read", severity="high", comparator=comparator, setup=[],
        control={"method": "GET", "url": "http://t:3000/rest/basket/8", "as": control_as},
        variant={"method": "GET", "url": "http://t:3000/rest/basket/8", "as": variant_as})


# The ledger's ownership record, in the shape `principal_identifiers()` returns and
# `principal_ownership` records: A owns user 25 / basket 6, B owns user 27 / basket 8.
OWNERSHIP = {
    "self": {"whoami.user.id": 25, "login.authentication.bid": 6},
    "second": {"signup.data.id": 27, "login.authentication.bid": 8},
}

# CM3's real body, verbatim in shape.
B_BASKET = json.dumps({"status": "success",
                       "data": {"id": 8, "coupon": None, "UserId": 27, "Products": []}})
A_BASKET = json.dumps({"status": "success",
                       "data": {"id": 6, "coupon": None, "UserId": 25, "Products": []}})


def _ctx(variant_as="self", ownership=None):
    return {"ownership": OWNERSHIP if ownership is None else ownership,
            "variant_as": variant_as}


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_the_cm3_sequence_now_confirms(tmp_path):
    """THE DEFECT. A reads basket 8, which the ledger records as owned by the second
    principal. Both sides 200 — the shape every existing comparator had to decline."""
    holds, meaning = hyp.judge(_h(), _R(200, A_BASKET), _R(200, B_BASKET),
                               None, _ctx("self"))
    assert holds, "the canonical BOLA shape still cannot be confirmed"
    assert meaning


def test_a_principal_reading_its_own_resource_does_not_confirm():
    """The control that stops this becoming a detector for 'a 200 happened'."""
    holds, _ = hyp.judge(_h(variant_as="second"), _R(200, A_BASKET), _R(200, B_BASKET),
                         None, _ctx("second"))
    assert not holds, "the OWNER reading its own resource was reported as cross-account"


def test_an_id_no_ownership_record_covers_does_not_confirm():
    """FAIL CLOSED. An id the ledger cannot attribute proves nothing about ownership."""
    unknown = json.dumps({"status": "success", "data": {"id": 999, "UserId": 998}})
    holds, _ = hyp.judge(_h(), _R(200, A_BASKET), _R(200, unknown), None, _ctx("self"))
    assert not holds, "an unrecorded id was treated as owned"


def test_no_ownership_map_at_all_does_not_confirm():
    """FAIL CLOSED. Before Fix 1 there was no map; absence must never read as a hit."""
    holds, _ = hyp.judge(_h(), _R(200, A_BASKET), _R(200, B_BASKET), None, _ctx("self", {}))
    assert not holds
    holds, _ = hyp.judge(_h(), _R(200, A_BASKET), _R(200, B_BASKET), None, None)
    assert not holds


def test_a_failed_request_does_not_confirm():
    """Both sides must have SUCCEEDED; a 401 carrying an error body is not a read."""
    holds, _ = hyp.judge(_h(), _R(200, A_BASKET), _R(401, B_BASKET), None, _ctx("self"))
    assert not holds


def test_the_derived_claim_names_both_principals_and_the_resource():
    """`1940f09`: the title is assembled from ledger facts, never from model prose."""
    cl = hyp.derive_claim(
        COMPARATOR, "second", "self",
        control={"url": "http://t:3000/rest/basket/8", "status": 200, "size": 154},
        variant={"url": "http://t:3000/rest/basket/8", "status": 200, "size": 154,
                 "owner": "second"})
    assert cl["authz"] is True
    assert cl["severity_cap"] == "high"
    assert "self" in cl["title"] and "second" in cl["title"], cl["title"]
    assert "/rest/basket/8" in cl["title"], cl["title"]
    assert "owned" in cl["claim"] and "ledger" in cl["claim"], cl["claim"]


def test_the_claim_fails_closed_when_no_owner_is_recorded():
    """A derived claim may not assert ownership the record does not carry."""
    cl = hyp.derive_claim(
        COMPARATOR, "self", "self",
        control={"url": "http://t:3000/rest/basket/8", "status": 200, "size": 154},
        variant={"url": "http://t:3000/rest/basket/8", "status": 200, "size": 154})
    assert cl["authz"] is False
    assert cl["severity_cap"] != "high"


# --------------------------------------------------------------------------- #
# BOUNDARY — the closed set keeps every verdict it already had
# --------------------------------------------------------------------------- #

def test_a_denial_shaped_case_still_routes_to_a_denied_b_allowed():
    """The denial shape is unchanged and still earns its own class."""
    # Called through the PRE-EXISTING signature, so this guard is green before and after
    # the new class exists: it fails only if the closed set actually moved.
    holds, _ = hyp.judge(_h(comparator="a_denied_b_allowed"),
                         _R(401, '{"error":"no"}'), _R(200, B_BASKET), None)
    assert holds
    cl = hyp.derive_claim("a_denied_b_allowed", "anonymous", "self",
                          control={"url": "http://t:3000/rest/basket/8", "status": 401,
                                   "size": 972},
                          variant={"url": "http://t:3000/rest/basket/8", "status": 200,
                                   "size": 154})
    assert cl["evidence_class"] == "a_denied_b_allowed"
    assert cl["severity_cap"] == "high" and cl["authz"] is True


@pytest.mark.parametrize("name,a,b,expected", [
    ("status_differs", _R(200, "x"), _R(404, "y"), True),
    ("status_differs", _R(200, "x"), _R(200, "y"), False),
    ("b_reveals_more", _R(200, "x" * 10), _R(200, "y" * 900), True),
    ("b_reveals_more", _R(200, "x" * 10), _R(200, "y" * 12), False),
    ("b_errors_a_does_not", _R(200, "x"), _R(500, "y"), True),
    ("b_errors_a_does_not", _R(200, "x"), _R(200, "y"), False),
])
def test_every_existing_comparator_keeps_its_verdict(name, a, b, expected):
    """BOUNDARY. Adding a class to a closed set must not move any other member."""
    # PRE-EXISTING signature, deliberately: a boundary that only holds under the new call
    # shape would not notice the old one breaking.
    holds, _ = hyp.judge(_h(comparator=name), a, b, None)
    assert holds is expected, name


def test_the_new_class_is_in_the_evidence_table_with_a_bound():
    """A comparator that gains a meaning gains a bound in the SAME edit — the two tables
    must never drift."""
    assert COMPARATOR in hyp.comparator_names()
    cl = hyp.derive_claim(COMPARATOR, "second", "self",
                          control={"url": "http://t/x", "status": 200, "size": 1},
                          variant={"url": "http://t/x", "status": 200, "size": 1,
                                   "owner": "second"})
    assert cl["evidence_class"] == COMPARATOR


# --------------------------------------------------------------------------- #
# END TO END — the three fixes together, through the real loop
# --------------------------------------------------------------------------- #

from brukal import AuditLog, Executor, Gate, load_scope, redact          # noqa: E402
from brukal.agents import StrategistAgent                                # noqa: E402
from brukal.assist import AssistSession                                  # noqa: E402
from brukal.kali import ExecResult                                       # noqa: E402
from brukal.web import GovernedBrowser, WebResult                        # noqa: E402

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
E2E_TARGET = "10.10.10.5"
E2E_BASE = f"http://{E2E_TARGET}:3000"
TOK_A, TOK_B = "tok-AAAA-1111-secret", "tok-BBBB-2222-secret"
MAIL_A, PASS_A = "a@brukal.test", "Pw-A-1!"


class _JuiceLike:
    """CM3's target, reduced: A owns basket 6, the second account owns basket 8, and
    `/rest/basket/:id` checks that you are logged in and NOT that you own it."""

    def __init__(self):
        self.accounts = {MAIL_A: {"token": TOK_A, "id": 25, "bid": 6}}

    def _who(self, headers):
        for k, v in (headers or {}).items():
            val = v or ""
            if k.lower() in ("authorization", "cookie"):
                for mail, acc in self.accounts.items():
                    if acc["token"] in val:
                        return mail, acc
        return "", None

    def run(self, action):
        url, body = action.url, action.body or ""
        if url.endswith("/rest/user/login"):
            try:
                sent = json.loads(body or "{}")   # the JSON strategy; others are refused
            except Exception:
                sent = {}
            acc = self.accounts.get(sent.get("email", ""))
            if not acc:
                return WebResult(status=401, url=url, headers={}, body='{"error":"no"}')
            return WebResult(status=200, url=url, headers={}, body=json.dumps(
                {"authentication": {"token": acc["token"], "umail": sent["email"],
                                    "bid": acc["bid"]}}))
        if url.endswith("/api/Users") and action.method == "POST":
            try:
                sent = json.loads(body)           # the JSON signup path
            except Exception:
                return WebResult(status=400, url=url, headers={},
                                 body='{"error":"json expected"}')
            if not sent.get("email"):
                return WebResult(status=400, url=url, headers={}, body='{"error":"no"}')
            self.accounts[sent["email"]] = {"token": TOK_B, "id": 27, "bid": 8}
            return WebResult(status=201, url=url, headers={}, body=json.dumps(
                {"status": "success", "data": {"id": 27, "email": sent["email"]}}))
        if url.endswith("/rest/user/whoami"):
            mail, acc = self._who(action.headers)
            if acc is None:
                return WebResult(status=200, url=url, headers={}, body='{"user":{}}')
            return WebResult(status=200, url=url, headers={}, body=json.dumps(
                {"user": {"id": acc["id"], "email": mail}}))
        if "/rest/basket/" in url:
            _mail, acc = self._who(action.headers)
            if acc is None:                       # logged out only
                return WebResult(status=401, url=url, headers={},
                                 body='{"error":"Unauthorized"}')
            want = int(url.rsplit("/", 1)[-1])
            owner = 25 if want == 6 else 27       # THE FLAW: ownership is never checked
            return WebResult(status=200, url=url, headers={}, body=json.dumps(
                {"status": "success",
                 "data": {"id": want, "coupon": None, "UserId": owner, "Products": []}}))
        if url.rstrip("/") in (E2E_BASE, f"http://{E2E_TARGET}:3000"):
            return WebResult(status=200, url=url, headers={"Content-Type": "text/html"},
                             body='<html><body><script>fetch("/api/Users");'
                                  'fetch("/rest/user/whoami");</script></body></html>')
        return WebResult(status=404, url=url, headers={}, body="nope")


class _E2EKali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _E2ELLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return "[]"


def test_end_to_end_the_milestone_event_is_confirmed_and_the_ledger_carries_it(tmp_path):
    """THE MILESTONE, as restated 2026-09-14. Principal A reads basket 8, the ledger
    records basket 8 as the second principal's, and the comparator earns the claim —
    with BOTH principals established in-harness and no external seeding."""
    redact.clear()
    target = _JuiceLike()
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _E2EKali(), audit, approver=lambda d: True)
    s = AssistSession(E2E_TARGET, ex, StrategistAgent(_E2ELLM()),
                      browser=GovernedBrowser(scope, target, audit))
    s.allow_intrusive = True

    s.login(f"{E2E_BASE}/rest/user/login", MAIL_A, PASS_A,
            user_field="email", login_type="json")
    s.confirm_authentication()
    s.crawl(seeds=[E2E_BASE + "/"], max_pages=5, max_depth=1)
    second = s.establish_second_identity()
    assert second, "the second principal was not established in-harness"

    h = hyp.Hypothesis(
        title="basket read across accounts", severity="high",
        comparator=COMPARATOR, setup=[],
        control={"method": "GET", "url": f"{E2E_BASE}/rest/basket/8", "as": "second"},
        variant={"method": "GET", "url": f"{E2E_BASE}/rest/basket/8", "as": "self"})
    outcomes: list = []
    confirmed = s._run_one_round([h], outcomes)

    assert confirmed == 1, outcomes

    entries = [json.loads(l) for l in Path(audit.path).read_text().splitlines() if l]
    kinds = {e["kind"] for e in entries}
    assert {"principal_ownership", "experiment_result", "experiment_principal"} <= kinds

    # Fix 1: the ledger says the SECOND principal owns basket 8.
    owns8 = [e["data"] for e in entries if e["kind"] == "principal_ownership"
             and str(e["data"]["value"]) == "8"]
    assert owns8 and owns8[0]["principal"] == "second", owns8
    assert owns8[0]["source"], "no provenance for the ownership that carries the claim"

    # Fix 2: the body that proves it is in the ledger.
    variant = [e["data"] for e in entries if e["kind"] == "experiment_result"
               and e["data"]["role"] == "variant"][0]
    assert '"UserId": 27' in variant["body"] or '"UserId":27' in variant["body"], variant

    # Fix 3: the finding names both principals and the resource, at high severity.
    finding = [f for f in s.findings.all() if f.confirmed
               and f.evidence_class == COMPARATOR][0]
    assert finding.severity == "high", finding.severity
    assert "self" in finding.title and "second" in finding.title, finding.title
    assert "/rest/basket/8" in finding.title, finding.title
    redact.clear()
