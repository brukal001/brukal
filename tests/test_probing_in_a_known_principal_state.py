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


def test_a_probe_from_BEFORE_the_principals_does_not_bind_afterwards(tmp_path):
    """RUN 14's loss, reproduced. A path probed while we held a different session (or
    none) recorded a 404 and `_composed_tried` made that permanent — so the route was
    excluded for the rest of the run even though it answers 200 to us now.

    A direct replay of run 14's own fragment list confirms the dashboard without
    trouble, which is what says the mechanism was right and the memory was wrong."""
    s, cage = _session(tmp_path)
    # the early, pre-establishment world: no session yet
    s._principals_established = False
    s.browser.auth_header = ""
    s.resolve_mined_routes()
    assert _OracleApp.DASH not in s.surface.confirmed_routes, "fixture is not reproducing"
    # ...the principals are acquired, and the world is now different
    s.browser.auth_header = "Bearer ours"
    s._principals_established = True
    s.resolve_mined_routes()
    assert _OracleApp.DASH in s.surface.confirmed_routes, (
        "an early miss in a different state is still excluding the route")


def test_the_requalification_happens_ONCE(tmp_path):
    """BOUNDARY: it is a state change, not a licence to re-probe every turn. Clearing on
    every pass would spend the budget re-asking questions already answered in the right
    state."""
    s, cage = _session(tmp_path)
    s.resolve_mined_routes()
    n = len(cage.seen)
    s.resolve_mined_routes()
    s.resolve_mined_routes()
    assert len(cage.seen) == n, f"{len(cage.seen)-n} re-probes after requalification"


def test_a_prefix_is_never_composed_ONTO_ITSELF(tmp_path):
    """MEASURED WASTE, found while explaining run 14. Resolution REPLACES a fragment with
    its composed form, so on the next pass the fragment already carries the prefix — and
    composition put it on a second time:

        /identity/api/identity/api/auth/login

    A path that cannot exist, one gated request each, billed against the same cap that
    decides whether later fragments get probed at all. Resolution runs every turn, so this
    is paid on a target's every mount point, and the requests it displaces are the ones
    that would have found real routes."""
    s, cage = _session(tmp_path)
    s.resolve_mined_routes()
    before = len(cage.seen)
    s.resolve_mined_routes()
    doubled = [p for p, _ in cage.seen[before:] if p.count("/identity/api") > 1]
    assert not doubled, f"composed a prefix onto itself: {doubled}"


class _RateLimited:
    """The cage behind a gate that refuses the first N probes. The TARGET is healthy
    throughout — it is never asked."""

    def __init__(self, oracle, deny_first):
        self.oracle, self.left, self.seen = oracle, deny_first, oracle.seen

    def run(self, action):
        return self.oracle.run(action)


def test_a_probe_OUR_gate_refused_is_not_recorded_as_absent(tmp_path):
    """RUN 14'S ACTUAL FAULT, read out of its ledger.

        301 ALLOW  GET /v2/user/dashboard
        302 DENY   web rate limit exceeded          <- layer "hard:web-rate", 43 times
        304 ALLOW  GET /identity/api/v2/user/dashboard
        305 DENY   web rate limit exceeded

    `tried.add(composed)` runs BEFORE the request, so both the bare and the composed
    dashboard were written off permanently — by OUR rate limiter, having never asked the
    target anything. The run finished with thirteen confirmed routes and not the one that
    is crAPI's whole identity surface, and a direct replay of the same sequence confirms
    it without trouble. That gap was the run's largest single loss.

    This is [origin-aware health] applied to route resolution: a silence WE caused is not
    evidence about the target, and must not be remembered as if it were."""
    s, cage = _session(tmp_path)
    s.browser._rate_ok = lambda: False          # our gate, not the target
    s.resolve_mined_routes()
    assert _OracleApp.DASH not in s.surface.confirmed_routes
    assert not cage.seen, "the target was asked something during a total refusal"

    s.browser._rate_ok = lambda: True           # the window refills
    s.resolve_mined_routes()
    assert _OracleApp.DASH in s.surface.confirmed_routes, (
        "our own rate-limit denial was remembered as the target saying 'absent'")


def test_an_ALREADY_CONFIRMED_fragment_is_not_composed_again(tmp_path):
    """RUN 16, caught live at $0.00 spend. The GAP #9 guard was too narrow.

    Resolution rewrites a fragment to its composed form, so on a later pass the fragment
    IS `/identity/api/v2/user/dashboard`. Its bare probe is already in `tried`, so the
    probe is skipped — and control falls straight through to the composition loop, which
    skipped only the prefix the path already carries. Every OTHER mount was composed onto
    a route we had already proven:

        404 /workshop/api/shop/identity/api/v2/user/dashboard
        404 /identity/api/auth/identity/api/v2/user/dashboard

    Real gated requests, every pass, for every resolved route times every mount — spent
    against the same rate allowance whose exhaustion cost run 14 this exact route.

    THE RULE: a fragment already confirmed needs nothing. Skip it whole."""
    s, cage = _session(tmp_path)
    # TWO mounts, as run 16 had: the composition loop must have something other than the
    # prefix the path already carries, or the narrow guard hides the defect.
    s._answered_paths = ["/identity/api/auth/login", "/workshop/api/shop/orders/all"]
    s.surface.add_routes(["/orders/all"])
    s.resolve_mined_routes()
    assert _OracleApp.DASH in s.surface.confirmed_routes, "fixture is not resolving"
    before = len(cage.seen)
    s.resolve_mined_routes()
    s.resolve_mined_routes()
    again = [p for p, _ in cage.seen[before:] if "v2/user/dashboard" in p]
    assert not again, f"re-probed a route already proven: {again}"
