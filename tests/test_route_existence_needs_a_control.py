"""
test_route_existence_needs_a_control.py — THE root fault behind ten CR1 runs.

MEASURED ON THE LIVE TARGET, 2026-09-18

    prefix            an ABSENT path answers      a REAL path answers
    /identity/api     401                         405
    /workshop/api     404                         500
    /community/api    404                         401

    `/identity/api/total/nonsense/xyz` -> 401. `/identity/api/zz9nonexistent/qq` -> 401.
    The identity service answers 401 to EVERYTHING under its prefix.

WHAT THAT DID
    Route confirmation treated any non-404 as "this route exists". So under /identity/api
    every phantom was confirmed — a direct probe produced

        /identity/api/identity/api/auth/login   [GET]   (double-prefixed garbage)
        /identity/api/orders/all                [GET]   (not a real crAPI route)

    while the REAL dashboard, which answers 404 to a stranger because it reads the
    Authorization header, looked absent. Exactly inverted.

    Everything downstream inherited it: the model planned against phantom paths and its
    experiments 404'd, seeding matched recipes on phantoms, coverage swept phantoms. I
    spent this session fixing the symptoms — prefix learning, budget, ordering — while
    the list they all consume was wrong.

AND NO GLOBAL RULE CAN WORK
    401 means "absent" under /identity/api and "real" under /community/api. Existence is
    only meaningful against a CONTROL taken under the same prefix — the positive-control
    discipline this project already applies to findings, applied to routes.
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


class _CrapiGateway:
    """The three services, each with the absent-signature measured from the real target."""

    REAL = {"/identity/api/auth/login": 405,
            "/identity/api/v2/user/dashboard": 404,      # header-reading oracle
            "/workshop/api/shop/orders": 500,
            "/community/api/v2/community/posts/recent": 401}

    def __init__(self):
        self.asked: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        path = urlsplit(action.url).path
        self.asked.append(path)
        if path in self.REAL:
            return WebResult(status=self.REAL[path], url=action.url, body="{}")
        if path.startswith("/identity/api"):
            return WebResult(status=401, url=action.url, body='{"message":"unauthorized"}')
        if path.startswith(("/workshop/api", "/community/api")):
            return WebResult(status=404, url=action.url, body='{"detail":"Not found."}')
        return WebResult(status=404, url=action.url, body="{}")


def _session(tmp_path, routes):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    cage = _CrapiGateway()
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s._principals_established = True
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(routes))
    s.surface = surface
    s._login_url = f"{BASE}/identity/api/auth/login"
    return s, cage


def test_a_PHANTOM_under_a_401_catch_all_is_not_confirmed(tmp_path):
    """THE FAULT. /identity/api answers 401 to everything, so 'non-404 means it exists'
    confirmed every composition it tried."""
    s, _cage = _session(tmp_path, ["/auth/login", "/orders/all"])
    s.resolve_mined_routes()
    assert not any("orders/all" in r for r in s.surface.confirmed_routes), \
        s.surface.confirmed_routes


def test_the_REAL_route_under_the_same_prefix_still_is(tmp_path):
    """And the control must not throw the good ones away: 405 differs from the prefix's
    401 signature, so the login route is still confirmed."""
    s, _cage = _session(tmp_path, ["/auth/login"])
    s.resolve_mined_routes()
    assert "/identity/api/auth/login" in s.surface.confirmed_routes, s.surface.confirmed_routes


def test_a_401_is_REAL_under_a_prefix_whose_absent_signature_is_404(tmp_path):
    """Why no global rule works. Under /community/api an absent path answers 404, so a
    401 is a genuine answer — the exact opposite reading from /identity/api."""
    s, cage = _session(tmp_path, ["/v2/community/posts/recent"])
    s._login_url = f"{BASE}/community/api/v2/community/posts/recent"
    s.resolve_mined_routes()
    assert any("community" in r for r in s.surface.confirmed_routes), s.surface.confirmed_routes


def test_the_control_costs_ONE_probe_per_prefix(tmp_path):
    """Not one per route: the signature is a property of the mount point."""
    s, cage = _session(tmp_path, ["/auth/login", "/auth/signup", "/auth/verify",
                                  "/v2/user/videos", "/v2/user/pictures"])
    s.resolve_mined_routes()
    controls = [p for p in cage.asked if "brukal-absent" in p]
    routes = [p for p in cage.asked if "brukal-absent" not in p]
    assert len(controls) < len(routes), (controls, routes)
    assert len(set(controls)) <= 4, controls


def test_an_unusable_control_confirms_NOTHING_under_that_prefix(tmp_path):
    """Fail-closed: if the control probe cannot be taken, existence cannot be judged, and
    confirming on a guess is what produced the phantoms."""
    class _Dead(_CrapiGateway):
        def run(self, action):
            if "brukal-absent" in action.url or "zz9" in action.url:
                return WebResult(status=None, url=action.url, body="")
            return super().run(action)
    s, _cage = _session(tmp_path, ["/auth/login"])
    s.browser._cage = _Dead()
    s.resolve_mined_routes()
    assert s.surface.confirmed_routes == [], s.surface.confirmed_routes


def test_a_single_service_app_still_resolves_NOTHING(tmp_path):
    """BOUNDARY, and a KNOWN GAP recorded rather than widened here: resolution only runs
    when there is a mount prefix to learn, so on a single-service application it does
    nothing at all — and `confirmed_routes` stays empty, which means seeding recipes and
    coverage forcing never fire there either. That is a real hole, separate from the
    phantom-confirmation fault this file is about, and it is not fixed in the same change.
    """
    class _Plain:
        def __init__(self): self.asked = []
        def run(self, action):
            from urllib.parse import urlsplit
            p = urlsplit(action.url).path
            self.asked.append(p)
            ok = p in ("/rest/user/whoami", "/api/Users")
            return WebResult(status=200 if ok else 404, url=action.url, body="{}")
    s, _ = _session(tmp_path, ["/rest/user/whoami", "/api/Users"])
    s.browser._cage = _Plain()
    s._login_url = f"{BASE}/rest/user/whoami"
    s.resolve_mined_routes()
    assert s.surface.confirmed_routes == [], s.surface.confirmed_routes
    assert s.browser._cage.asked == [], s.browser._cage.asked
