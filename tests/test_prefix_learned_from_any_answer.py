"""
test_prefix_learned_from_any_answer.py — one answered path unlocks a whole service.

THE MEASURED PROBLEM (CR1 run 6, 2026-09-18)
    crAPI runs three services behind one front door. Run 6 confirmed 16 routes and EVERY
    ONE was under `/identity/api`, because mount-prefix alignment only ever had one
    answered path to align against: the login URL the operator supplied.

        mined:      /orders/all        (really /workshop/api/shop/orders/all)
        composed:   /identity/api/orders/all   -> 404 -> discarded
        confirmed:  16 routes, all /identity/api/*

    So seeding found no vehicle routes and no-op'd, coverage found no unvisited family and
    no-op'd, and every experiment in the run was asked about a third of the application.
    Run 4 only reached /workshop/api/shop/orders because the MODEL guessed it — the
    surface never knew that service existed.

THE FIX
    Any request that ANSWERS teaches its prefix, not just the login URL. The agent's own
    exploration is evidence: the moment anything touches /workshop/api/shop/orders and
    gets a reply, `/workshop/api/shop` becomes an alignment candidate and every mined
    fragment that failed under the old prefix gets another, confirmed, chance.

    The model's luck stops evaporating and becomes the surface's knowledge.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.gate import Decision
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebAction, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
# crAPI's real shape: three services, and the bundle yields unprefixed fragments.
FRAGMENTS = ["/auth/login", "/orders", "/orders/all", "/v2/vehicle/add_vehicle",
             "/v2/vehicle/resend_email"]
REAL = {"/identity/api/auth/login", "/identity/api/v2/vehicle/add_vehicle",
        "/identity/api/v2/vehicle/resend_email",
        "/workshop/api/shop/orders", "/workshop/api/shop/orders/all"}


class _ThreeServices:
    def __init__(self):
        self.asked: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        path = urlsplit(action.url).path
        self.asked.append(path)
        if path in REAL:
            return WebResult(status=200, url=action.url, body='{"ok":true}')
        return WebResult(status=404, url=action.url, body='{"message":"nope"}')


def _session(tmp_path, cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(FRAGMENTS))
    s.surface = surface
    s._login_url = f"{BASE}/identity/api/auth/login"
    return s, audit


def test_run_6s_exact_case_only_ONE_service_is_reachable_at_first(tmp_path):
    """The starting position: with the login URL as the only evidence, the workshop
    service is invisible."""
    s, _ = _session(tmp_path, _ThreeServices())
    s.resolve_mined_routes()
    confirmed = s.surface.confirmed_routes
    assert any("/identity/api/v2/vehicle" in r for r in confirmed), confirmed
    assert not any("/workshop" in r for r in confirmed), confirmed


def test_ONE_answered_path_unlocks_the_service(tmp_path):
    """THE FIX. The agent touches /workshop/api/shop/orders and gets a reply; that is
    evidence, and the fragments that failed under the old prefix get another chance."""
    cage = _ThreeServices()
    s, _ = _session(tmp_path, cage)
    s.resolve_mined_routes()
    # ...the agent explores, the way run 4's model did
    s._absorb_web(WebAction("request", method="GET", url=f"{BASE}/workshop/api/shop/orders"),
                  Decision(verdict="ALLOW", action="x", target=TARGET, agent="t",
                           reason="t", layer="t"),
                  WebResult(status=200, url=f"{BASE}/workshop/api/shop/orders", body='{"ok":1}'))
    s.resolve_mined_routes()
    confirmed = s.surface.confirmed_routes
    assert "/workshop/api/shop/orders/all" in confirmed, confirmed


def test_a_command_teaches_it_too(tmp_path):
    """Both planes: run 4's discovery came from a curl in the cage, not the browser."""
    cage = _ThreeServices()
    s, _ = _session(tmp_path, cage)
    s.resolve_mined_routes()
    cmd = f"curl -s {BASE}/workshop/api/shop/orders"
    s._absorb_shell(cmd, Decision(verdict="ALLOW", action=cmd, target=TARGET, agent="t",
                                  reason="t", layer="t"),
                    ExecResult(cmd, 0, '{"order":{"id":1}}', ""))
    s.resolve_mined_routes()
    assert any("/workshop" in r for r in s.surface.confirmed_routes), s.surface.confirmed_routes


def test_a_404_teaches_NOTHING(tmp_path):
    """BOUNDARY: only an answer is evidence. A 404 means the path is not there, and
    learning a prefix from it would poison every later composition."""
    cage = _ThreeServices()
    s, _ = _session(tmp_path, cage)
    s._absorb_web(WebAction("request", method="GET", url=f"{BASE}/nonsense/api/thing"),
                  Decision(verdict="ALLOW", action="x", target=TARGET, agent="t",
                           reason="t", layer="t"),
                  WebResult(status=404, url=f"{BASE}/nonsense/api/thing", body="{}"))
    s.resolve_mined_routes()
    assert not any("/nonsense" in r for r in s.surface.confirmed_routes)


def test_a_composed_path_is_never_probed_twice(tmp_path):
    """Re-resolution must not re-spend requests on compositions already disproved."""
    cage = _ThreeServices()
    s, _ = _session(tmp_path, cage)
    s.resolve_mined_routes()
    first = len(cage.asked)
    s.resolve_mined_routes()
    s.resolve_mined_routes()
    assert len(cage.asked) == first, f"{len(cage.asked) - first} wasted re-probes"


def test_a_single_service_app_is_unchanged(tmp_path):
    """BOUNDARY — Juice Shop. Its own paths answer, so nothing new is ever learned and no
    re-resolution happens."""
    class _JuiceShop:
        def __init__(self): self.asked = []
        def run(self, action):
            self.asked.append(action.url)
            return WebResult(status=200, url=action.url, body="{}")
    cage = _JuiceShop()
    s, _ = _session(tmp_path, cage)
    s.surface.api_routes = ["/rest/user/login", "/api/Users"]
    s._login_url = f"{BASE}/rest/user/login"
    assert s.resolve_mined_routes() == []
    assert cage.asked == []
