"""
test_resolution_yields_to_principals.py — the cheap, load-bearing acquisition goes first.

THE MEASURED REGRESSION (CR1 runs 7 and 8, introduced by prefix learning)

    run | web requests | hard:web-rate denials | both principals confirmed
      5 | 264          | 10                    | yes
      6 | 193          | 10                    | yes
      7 | 366          | 15                    | NO  — second principal unconfirmed
      8 | 200          | 15                    | NO

    The denied requests were exactly the second principal's identity probes — /me,
    /api/user/me, ... and /identity/api/v2/user/dashboard, which is crAPI's actual
    oracle. Route resolution had spent the web-rate allowance first.

    `_establish_principals` already documents this failure, from the 2C3 pre-flights:
    "the cheapest and most load-bearing acquisition in the engagement was queued behind
    the most expensive sweep." I recreated it with a different sweep, and it broke CR1's
    fourth clause — both principals verified — which runs 1 to 6 had met.

THE FIX, and why it is not simply "resolve later"
    Establishment DEPENDS on resolution: `_json_signup_candidates` reads the resolved
    routes, and GAP #4 was that crAPI's signup was unreachable until its prefix was
    learned. So the pre-establishment pass is not deferred, it is NARROWED — it resolves
    only the fragments establishment actually needs, and the full sweep waits until the
    principals are in hand.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.web import WebResult
from brukal.web import GovernedBrowser
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"

# crAPI's mined set: one signup, one login, and a long tail of everything else.
FRAGMENTS = (["/auth/signup", "/auth/login"]
             + [f"/v2/user/thing{i}" for i in range(20)])
REAL = {"/identity/api/auth/signup", "/identity/api/auth/login"} | {
    f"/identity/api/v2/user/thing{i}" for i in range(20)}


class _App:
    def __init__(self):
        self.asked: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        path = urlsplit(action.url).path
        self.asked.append(path)
        if path in REAL:
            return WebResult(status=200, url=action.url, body='{"ok":true}')
        return WebResult(status=404, url=action.url, body='{}')


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    app = _App()
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, app, audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(FRAGMENTS))
    s.surface = surface
    s._login_url = f"{BASE}/identity/api/auth/login"
    return s, app


def test_before_the_principals_exist_resolution_is_CHEAP(tmp_path):
    """THE REGRESSION. The full sweep spent the rate allowance that the second
    principal's identity probes needed."""
    s, app = _session(tmp_path)
    s.resolve_mined_routes()
    # A deliberate budget, not an accident: twelve, against a full sweep that costs a
    # probe per fragment plus a composition per prefix across two dozen of them.
    assert len(app.asked) <= 14, f"{len(app.asked)} requests before the principals exist"


def test_but_it_still_finds_what_ESTABLISHMENT_NEEDS(tmp_path):
    """The reason it cannot simply be deferred: establishment reads the resolved routes,
    and GAP #4 was that crAPI's signup was unreachable until its prefix was learned."""
    s, app = _session(tmp_path)
    s.resolve_mined_routes()
    assert "/identity/api/auth/signup" in s.surface.confirmed_routes, s.surface.confirmed_routes


def test_the_full_sweep_runs_once_the_principals_are_IN_HAND(tmp_path):
    """Ordering, not abandonment. Everything else resolves after the load-bearing
    acquisition is done."""
    s, app = _session(tmp_path)
    s.resolve_mined_routes()
    before = len(s.surface.confirmed_routes)
    s._principals_established = True
    s.resolve_mined_routes()
    assert len(s.surface.confirmed_routes) > before, s.surface.confirmed_routes
    assert any("thing" in r for r in s.surface.confirmed_routes)


def test_the_loop_marks_the_principals_as_established(tmp_path):
    """The flag has to be set by the thing that does the acquiring, or the sweep never
    gets its turn."""
    from brukal.loop import GroundedLoop
    s, _app = _session(tmp_path)
    loop = GroundedLoop(s, max_steps=2)
    loop._establish_principals()
    assert getattr(s, "_principals_established", False) is True
