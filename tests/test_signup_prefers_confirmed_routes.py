"""
test_signup_prefers_confirmed_routes.py — the second principal was lost to an unprefixed guess.

THE MEASURED PROBLEM (crAPI, 2026-09-20)
    A live run derived 13 `state_changed` experiments — the comparator no model in either
    series had ever proposed — and TEN died `second_unavailable`, so the cross-account
    class could not execute at all. The reason was not the experiments:

        second principal NOT established — signup at http://172.20.0.12/REGISTER
        refused with 404

    `/REGISTER` is an unprefixed fragment mined from the bundle. crAPI's real endpoint is
    `/identity/api/auth/signup`, and by then it had ALREADY BEEN CONFIRMED by request —
    it is one of the 33 endpoints mount/suffix discovery proves. The knowledge was in the
    surface and the chooser was not looking at it.

    This is GAP #10's shape again ("the knowledge was there; the match was too literal"),
    one consumer along: candidates came from `api_routes`, the UNVERIFIED tier, while
    `confirmed_routes` — paths the target itself answered — were ignored.

THE PROPERTY
    A route the target has CONFIRMED outranks a fragment someone mined.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent.parent / "scope.crapi.json"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession("172.20.0.12", ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()))
    s.surface = AttackSurface(seed="http://172.20.0.12/")
    return s


def test_a_confirmed_signup_route_is_tried_before_a_mined_fragment(tmp_path):
    """crAPI's exact state: /REGISTER mined and unprefixed, the real one confirmed."""
    s = _session(tmp_path)
    s.surface.api_routes = ["/REGISTER", "/auth/signup"]
    s.surface.confirmed_routes = ["/identity/api/auth/signup"]

    cands = s._json_signup_candidates()
    assert cands, "no signup candidate at all"
    assert cands[0].endswith("/identity/api/auth/signup"), (
        f"an unverified fragment was tried before the route the target CONFIRMED: {cands}")


def test_mined_fragments_are_still_tried_when_nothing_is_confirmed(tmp_path):
    """BOUNDARY: on a target where discovery confirms nothing, the old behaviour is all
    there is and must survive."""
    s = _session(tmp_path)
    s.surface.api_routes = ["/auth/signup"]
    cands = s._json_signup_candidates()
    assert any(c.endswith("/auth/signup") for c in cands), cands


def test_a_confirmed_route_that_is_not_a_signup_is_not_posted_to(tmp_path):
    """The allowlist half still holds: a speculative POST at an arbitrary confirmed route
    is exactly the unrequested state change this project refuses to make."""
    s = _session(tmp_path)
    s.surface.confirmed_routes = ["/identity/api/v2/user/dashboard",
                                  "/workshop/api/shop/orders"]
    assert s._json_signup_candidates() == []
