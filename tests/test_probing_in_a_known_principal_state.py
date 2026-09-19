"""
test_probing_in_a_known_principal_state.py — existence must be judged in a KNOWN state.

THE MEASURED FAULT
    Confirmed-route counts on the same target, same code path, across runs:

        run 10: 2     run 12: 3     run 13: 11     run 9: 24     run 7: 25

    Route probing calls the governed browser directly, so it inherits whatever principal
    state the browser is in at that moment. crAPI's dashboard is a header-reading oracle:
    404 to a stranger, 200 to us. Probed while a `_separate_identity` block had the jar
    cleared, it looks absent; probed with the session, it exists. Same endpoint, same
    code, different answer depending on when the sweep happened to run.

    Run 13 is the concrete cost: /identity/api/v2/user/dashboard was NOT confirmed, so the
    model kept proposing the unprefixed /v2/user/dashboard/30 — four of that run's twelve
    experiment 404s — and proposal repair had no mapping to repair it with.

THE RULE
    Probe as the principal the experiments will run as. Both halves — the absent-signature
    control and the candidate — must be taken in the SAME state, or the comparison between
    them means nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"


class _OracleApp:
    """crAPI's shape: the dashboard is 200 to a bearer and 404 to a stranger, and the
    prefix answers 404 for genuinely absent paths."""

    DASH = "/identity/api/v2/user/dashboard"
    LOGIN = "/identity/api/auth/login"

    def __init__(self):
        self.seen: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        path = urlsplit(action.url).path
        authed = "Bearer" in ((action.headers or {}).get("Authorization") or "")
        self.seen.append((path, authed))
        if path == self.DASH:
            return WebResult(status=200 if authed else 404, url=action.url,
                             body='{"id":9}' if authed else '{"message":"not registered"}')
        if path == self.LOGIN:
            return WebResult(status=405, url=action.url, body="{}")
        return WebResult(status=404, url=action.url, body="{}")


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    cage = _OracleApp()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s._principals_established = True
    s.identity = "us@brukal.test"
    s.browser.auth_header = "Bearer ours"          # the session experiments will use
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(["/auth/login", "/v2/user/dashboard"])
    s.surface = surface
    s._login_url = f"{BASE}{_OracleApp.LOGIN}"
    return s, cage


def test_an_auth_gated_route_is_CONFIRMED_because_we_probe_as_ourselves(tmp_path):
    """RUN 13's loss: the oracle went unconfirmed, so the model kept proposing the
    unprefixed path and four experiment requests 404'd."""
    s, _cage = _session(tmp_path)
    s.resolve_mined_routes()
    assert _OracleApp.DASH in s.surface.confirmed_routes, s.surface.confirmed_routes


def test_every_probe_carries_the_same_session(tmp_path):
    """Both halves in the same state. A control taken as a stranger and a candidate taken
    as us is a comparison between two different worlds."""
    s, cage = _session(tmp_path)
    s.resolve_mined_routes()
    assert cage.seen, "nothing was probed"
    assert all(authed for _p, authed in cage.seen), \
        [p for p, a in cage.seen if not a]


def test_the_repair_map_gets_the_entry(tmp_path):
    """And with the route resolved, a proposal naming the fragment — with or without a
    suffix — can finally be repaired."""
    s, _cage = _session(tmp_path)
    s.resolve_mined_routes()
    assert "/v2/user/dashboard" in getattr(s, "_resolved_map", {}), \
        getattr(s, "_resolved_map", {})
    from brukal.hypothesis import Hypothesis
    h = Hypothesis(title="t", severity="high", comparator="cross_account_resource",
                   control={"method": "GET", "url": f"{BASE}/v2/user/dashboard/30"},
                   variant={"method": "GET", "url": f"{BASE}/v2/user/dashboard/30"},
                   setup=[])
    s.repair_proposals([h])
    assert h.control["url"] == f"{BASE}{_OracleApp.DASH}/30", h.control
