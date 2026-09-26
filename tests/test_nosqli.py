"""
test_nosqli.py — NoSQL operator-injection confirmation (crAPI challenge 12).

Brukal proved SQL injection but had no NoSQL prover, so a Mongo-backed lookup that trusts a
client-supplied operator (`{"$ne": null}` in a coupon field → any coupon matches) was
unreachable. The proof is a benign-vs-always-true-operator differential in a JSON body.
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
COUPON = "/community/api/v2/coupon/validate-coupon"


class _CouponMongo:
    """crAPI's coupon lookup in miniature: a benign string matches no coupon (404); a NoSQL
    operator object matches ANY coupon (200) — the challenge-12 bug."""
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.seen: list = []

    def run(self, action):
        self.seen.append(action.url)
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            body = {}
        code = body.get("coupon_code")
        if isinstance(code, dict):                       # a client-supplied operator
            if self.vulnerable:
                return WebResult(status=200, url=action.url,
                                 body=json.dumps({"coupon": "TRAC075", "amount": 75}))
            return WebResult(status=500, url=action.url, body='{"error":"bad query"}')
        return WebResult(status=404, url=action.url, body='{"message":"Coupon not found"}')


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
    return s


def test_operator_injection_is_confirmed_by_the_benign_vs_bypass_differential():
    s = _session(_CouponMongo(vulnerable=True))
    assert s.confirm_nosqli(f"{BASE}{COUPON}", "coupon_code") is True
    f = next(f for f in s.findings.all() if f.title == "NoSQL injection (operator)")
    assert f.confirmed and f.severity == "critical"


def test_a_non_vulnerable_lookup_is_left_alone():
    s = _session(_CouponMongo(vulnerable=False))     # operator -> 500, benign -> 404
    assert s.confirm_nosqli(f"{BASE}{COUPON}", "coupon_code") is False
    assert not any(f.title == "NoSQL injection (operator)" for f in s.findings.all())


def test_the_sweep_finds_the_coupon_field_the_crawl_never_surfaced():
    s = _session(_CouponMongo(vulnerable=True))
    s.surface.confirmed_routes = [COUPON]
    assert s.confirm_nosqli_sinks() == 1
    assert any(f.title == "NoSQL injection (operator)" and f.confirmed
               for f in s.findings.all())


def test_the_sweep_reaches_a_POST_only_mined_route_never_GET_confirmed():
    """The live crAPI gap (2026-09-26 A/B). validate-coupon is POST-only, so it answers
    the crawl's GET with 405 and never lands in confirmed_routes — yet it is exactly the
    NoSQL sink for challenge 12. The audit of both A/B arms showed ZERO operator payloads
    were ever sent, because the sink sweep drew candidates only from confirmed_routes. It
    must also draw from the mined api_routes: confirm_nosqli POSTs and runs its own
    differential, so a GET-405 route is fine, and the hint filter + allow_intrusive gate
    keep an operator body to lookup/validate routes only."""
    s = _session(_CouponMongo(vulnerable=True))
    s.surface.confirmed_routes = []                  # nothing GET-confirmed (405 on GET)
    s.surface.api_routes = [COUPON]                  # mined only — the real live situation
    assert s.confirm_nosqli_sinks() == 1
    assert any(f.title == "NoSQL injection (operator)" and f.confirmed
               for f in s.findings.all())


def test_a_templated_route_does_not_abort_the_sink_sweep():
    """2026-09-26: drawing sink candidates from mined api_routes mixes in templated ({id})
    routes, and the loop did `break` on the first template — silently skipping the concrete
    coupon sink behind it, so 0 operator payloads were sent even with the rate wall gone.
    A template must be SKIPPED (or ordered last), never abort the sweep."""
    s = _session(_CouponMongo(vulnerable=True))
    s.surface.confirmed_routes = []
    # a templated hint-matching route AHEAD of the concrete coupon route
    s.surface.api_routes = ["/community/api/v2/coupon/{id}/validate", COUPON]
    assert s.confirm_nosqli_sinks() == 1
    assert any(f.title == "NoSQL injection (operator)" and f.confirmed
               for f in s.findings.all())


def test_the_field_injection_sinks_run_before_the_expensive_route_sweeps():
    """Regression for the 2026-09-26 rate-starvation. The field-injection sinks
    (object mass-assignment / SSRF / NoSQL — crAPI #8/#9/#10/#11/#12) must be dispatched
    in confirm_surface BEFORE the expensive per-route sweeps (collection at pass 4, mined
    routes at pass 6b), or the scope's 120/min limit is spent by those sweeps and the
    sinks — which used to run last — send ZERO operator payloads (both live A/B arms did
    exactly that). A source-order guard so the hoist can't silently regress."""
    import inspect
    from brukal.assist import AssistSession
    src = inspect.getsource(AssistSession.confirm_surface)
    i_nosql = src.index("confirm_nosqli_sinks()")
    i_ssrf = src.index("confirm_ssrf_sinks()")
    i_objma = src.index("confirm_object_mass_assignment_sinks()")
    i_collection = src.index("# 4) COLLECTION endpoints")
    i_mined = src.index("# 6b) MINED API ROUTES")
    assert max(i_nosql, i_ssrf, i_objma) < min(i_collection, i_mined), (
        "a field-injection sink is dispatched AFTER the expensive collection/mined-route "
        "sweeps — under a rate limit those sweeps starve it (2026-09-26 regression)")


def test_the_sweep_needs_allow_intrusive():
    s = _session(_CouponMongo(vulnerable=True))
    s.allow_intrusive = False
    s.surface.confirmed_routes = [COUPON]
    assert s.confirm_nosqli_sinks() == 0


class _CouponSQL:
    """A SQL-backed coupon lookup (`WHERE code='<input>'`) reflected as a boolean — a TRUE
    condition returns the found row, a FALSE condition returns nothing. crAPI challenge 13."""
    def run(self, action):
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            body = {}
        code = str(body.get("coupon_code", ""))
        false_cond = ("'1'='2" in code or "1=2" in code or '"1"="2' in code)
        if false_cond:
            return WebResult(status=200, url=action.url, body='{"result":[]}')
        return WebResult(status=200, url=action.url,
                         body='{"result":[{"coupon":"TRAC075","amount":75,"valid":true}]}')


def test_the_sweep_also_catches_boolean_sql_injection_in_the_json_body():
    """crAPI #13: SQL injection lives in the SAME JSON coupon field, so the lookup sweep
    runs the boolean SQLi differential (method=JSON) beside the NoSQL operator check."""
    s = _session(_CouponSQL())
    s.surface.confirmed_routes = [COUPON]
    assert s.confirm_nosqli_sinks() == 1
    assert any(f.title == "SQL injection (boolean-based)" and f.confirmed
               for f in s.findings.all())
