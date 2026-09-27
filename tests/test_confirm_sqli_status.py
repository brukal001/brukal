"""
test_confirm_sqli_status.py — SQL injection confirmed by a quote-balance HTTP-STATUS
differential (crAPI challenge 13: apply_coupon).

Brukal already had two SQLi provers and neither could see crAPI's coupon SQLi:

  * confirm_sqli (boolean, body-ratio) — the app's two states are "Coupon not found" and
    "already claimed", with no clean TRUE-tracks-baseline / FALSE-diverges body signal;
  * confirm_sqli_error (body SQL-string grep) — the broken query returns a bare Django
    HTML "Server Error (500)" page with NO SQL keywords, so scan_exposures finds nothing.

The signal that IS present is the HTTP status: an unbalanced quote (`1'`) makes the
endpoint 500 while the balanced form (`1''`) does not. That is a third, independent SQLi
oracle. Two false-positive guards are load-bearing and tested here: an endpoint that 500s
on clean input, and one that 500s on ANY quote (not specifically an unbalanced one), must
BOTH be left alone.

A second live condition is that crAPI's apply_coupon only reaches the injectable query
when a companion `amount` field is present; with `{coupon_code: ...}` alone it 400s before
building the query. The coupon sink sweep must supply the companion, tested at the bottom.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
APPLY = "/workshop/api/shop/apply_coupon"


def _code(action):
    try:
        body = json.loads(action.body or "{}")
    except Exception:
        body = {}
    return str(body.get("coupon_code", "")), body


class _QuoteBalanceSQL:
    """apply_coupon in miniature: the coupon_code is concatenated into a SQL string, so an
    ODD number of single quotes leaves the literal unterminated -> DB error (500). An even
    number is balanced -> the query runs and returns a normal 400 'not found'. When
    `require_amount` is set the injectable path is reached only if `amount` is also sent
    (crAPI's real behaviour), which is what the sink-sweep companion test exercises."""
    def __init__(self, vulnerable=True, require_amount=False):
        self.vulnerable = vulnerable
        self.require_amount = require_amount
        self.seen: list = []

    def run(self, action):
        self.seen.append(action.url)
        code, body = _code(action)
        if self.require_amount and "amount" not in body:
            return WebResult(status=400, url=action.url, body='{"message":"Coupon not found"}')
        if self.vulnerable and code.count("'") % 2 == 1:      # unbalanced quote -> broken SQL
            return WebResult(status=500, url=action.url,
                             body="<!doctype html><h1>Server Error (500)</h1>")
        return WebResult(status=400, url=action.url, body='{"message":"Coupon not found"}')


class _AlwaysError:
    """500 on everything, clean input included: no readable differential -> must NOT confirm."""
    def run(self, action):
        return WebResult(status=500, url=action.url, body="<h1>Server Error (500)</h1>")


class _StableApp:
    """A non-injectable endpoint (like /identity/api/auth/login): 400 regardless of quotes."""
    def run(self, action):
        return WebResult(status=400, url=action.url, body='{"message":"bad request"}')


class _ErrorsOnAnyQuote:
    """500 whenever a quote appears — balanced OR not. That is input validation, not an
    unbalanced-literal SQL error, so the balanced-quote control must veto it."""
    def run(self, action):
        code, _b = _code(action)
        if "'" in code:
            return WebResult(status=500, url=action.url, body="<h1>Server Error (500)</h1>")
        return WebResult(status=400, url=action.url, body='{"message":"Coupon not found"}')


def _session(cage):
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    scope = load_scope(SCOPE)
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    llm = type("L", (), {"last_stop_reason": "end", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(llm), browser=GovernedBrowser(scope, cage, audit))
    s.blackboard = Blackboard(root / "vault", scope)
    s.allow_intrusive = True
    s.surface = AttackSurface(seed=f"{BASE}/")
    s._confirm_budget = 200
    return s, root / "a.jsonl"


# --------------------------------------------------------------------------- #
# The prover itself: positive, and the three false-positive guards.
# --------------------------------------------------------------------------- #

def test_quote_balance_status_differential_confirms_sqli():
    s, _ = _session(_QuoteBalanceSQL(vulnerable=True))
    assert s.confirm_sqli_status(f"{BASE}{APPLY}", "coupon_code", method="JSON") is True
    f = next(f for f in s.findings.all()
             if f.title == "SQL injection (error-based, status differential)")
    assert f.confirmed and f.severity == "critical"


def test_an_endpoint_that_errors_on_clean_input_is_not_confirmed():
    s, _ = _session(_AlwaysError())
    assert s.confirm_sqli_status(f"{BASE}{APPLY}", "coupon_code", method="JSON") is False
    assert not any("status differential" in f.title for f in s.findings.all())


def test_a_stable_endpoint_is_not_confirmed():
    s, _ = _session(_StableApp())
    assert s.confirm_sqli_status(f"{BASE}{APPLY}", "coupon_code", method="JSON") is False


def test_an_endpoint_that_errors_on_any_quote_is_vetoed_by_the_balanced_control():
    s, _ = _session(_ErrorsOnAnyQuote())
    assert s.confirm_sqli_status(f"{BASE}{APPLY}", "coupon_code", method="JSON") is False
    assert not any("status differential" in f.title for f in s.findings.all())


# --------------------------------------------------------------------------- #
# It emits a scorable experiment, and that experiment credits #13 (and not #12).
# --------------------------------------------------------------------------- #

def test_it_emits_a_confirmed_experiment_on_apply_coupon():
    s, ap = _session(_QuoteBalanceSQL(vulnerable=True))
    assert s.confirm_sqli_status(f"{BASE}{APPLY}", "coupon_code", method="JSON") is True
    rows = [json.loads(l) for l in open(ap) if l.strip()]
    outcomes = [r for r in rows if r.get("kind") == "experiment_outcome"]
    assert len(outcomes) == 1
    o = outcomes[0]["data"]
    assert o["outcome"] == "confirmed"
    assert o["comparator"] == "sqli_error_status_differential"
    results = [r for r in rows if r.get("kind") == "experiment_result"]
    assert any(APPLY in (r["data"].get("url") or "") for r in results)


def test_the_emitted_experiment_credits_challenge_13():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "crapi_recall", Path(__file__).resolve().parents[1] / "benchmarks" / "crapi_recall.py")
    cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)
    s, ap = _session(_QuoteBalanceSQL(vulnerable=True))
    assert s.confirm_sqli_status(f"{BASE}{APPLY}", "coupon_code", method="JSON") is True
    res = {r["id"]: r for r in cr.measure(ap)["results"]}
    assert res[13]["state"] == "FOUND", res[13]
    assert res[12]["state"] != "FOUND", res[12]      # a SQL finding must not credit the NoSQL one


# --------------------------------------------------------------------------- #
# The sink sweep reaches apply_coupon AND supplies the companion field.
# --------------------------------------------------------------------------- #

def test_the_sink_sweep_confirms_the_status_sqli_on_apply_coupon():
    s, _ = _session(_QuoteBalanceSQL(vulnerable=True))
    s.surface.confirmed_routes = [APPLY]
    assert s.confirm_nosqli_sinks() >= 1
    assert any(f.title == "SQL injection (error-based, status differential)" and f.confirmed
               and "apply_coupon" in f.target for f in s.findings.all())


def test_the_sweep_supplies_the_amount_companion_that_reaches_the_injectable_path():
    """With {coupon_code: ...} alone crAPI's apply_coupon 400s before building the query;
    the injectable path needs a companion `amount`. The sweep must supply it, or the live
    #13 stays MEASURED-NOT-CONFIRMED (the second half of the 2026-09-27 diagnosis)."""
    s, _ = _session(_QuoteBalanceSQL(vulnerable=True, require_amount=True))
    s.surface.confirmed_routes = [APPLY]
    assert s.confirm_nosqli_sinks() >= 1
    assert any(f.title == "SQL injection (error-based, status differential)" and f.confirmed
               for f in s.findings.all())


def test_the_status_sqli_sweep_needs_allow_intrusive():
    s, _ = _session(_QuoteBalanceSQL(vulnerable=True))
    s.allow_intrusive = False
    s.surface.confirmed_routes = [APPLY]
    assert s.confirm_nosqli_sinks() == 0
