"""
test_surface_is_settled_before_proposing.py — do not ask the model to plan against a
surface that has not finished resolving.

THE MEASURED FAULT (CR1 run 9)
    The first experiment was proposed at ledger entry 270. FIFTY-SEVEN of the sixty
    resolution probes for /identity/api/v2/user happened AFTER it. So the model planned
    against the unverified, unprefixed fragment list and proposed:

        /v2/user/dashboard   /v2/user/pictures   /v2/user/videos/0   /orders/all

    Eight of sixteen experiment requests in that run were 404s — while the confirmed
    /identity/api/... equivalents existed by the end. By report time the surface looked
    perfect, which is exactly why this stayed invisible across nine runs.

    My own rate-budget fix caused it: deferring the full sweep until after the principals
    are established pushed it past the first hypothesis round.

AND THE SEEDING MEMO (all nine runs)
    `_seed_principals` marked a principal done BEFORE attempting, so the early call —
    when no recipe could match yet, because nothing was confirmed — permanently consumed
    the only chance. Run 9's recipe matches at report time and seeding still never ran.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_seed_recipes import CRAPI_ROUTES, _CrAPI  # noqa: E402

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"


class _App:
    """Only prefixed paths exist — crAPI's shape."""
    def __init__(self):
        self.asked: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        p = urlsplit(action.url).path
        self.asked.append(p)
        if p.startswith("/identity/api/"):
            return WebResult(status=200, url=action.url, body='{"ok":1}')
        return WebResult(status=404, url=action.url, body="{}")


def _session(tmp_path, cage=None):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage or _App(), audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(["/auth/login", "/v2/user/dashboard", "/v2/user/pictures"])
    s.surface = surface
    s._login_url = f"{BASE}/identity/api/auth/login"
    return s


def test_the_surface_is_RESOLVED_before_the_model_is_asked(tmp_path):
    """THE FAULT: run 9 asked first and resolved afterwards."""
    s = _session(tmp_path)
    s._principals_established = True
    seen_at_prompt = {}

    def _capture(*a, **k):
        seen_at_prompt["summary"] = s.surface.summary()
        return "[]"
    s.strategist._llm.propose = _capture
    s.run_hypotheses()
    assert "summary" in seen_at_prompt, "the model was never asked"
    assert "/identity/api/v2/user/dashboard" in seen_at_prompt["summary"], \
        "the model planned against unresolved fragments — run 9's exact defect"


def test_it_does_not_resolve_before_the_principals_exist(tmp_path):
    """BOUNDARY: the rate-budget fix stands. Resolution still yields to the acquisition
    that the second principal depends on."""
    s = _session(tmp_path)
    s.run_hypotheses()
    assert not getattr(s, "_principals_established", False)
    assert len(s.browser._cage.asked) <= 14, len(s.browser._cage.asked)


def test_a_principal_is_marked_seeded_only_when_a_recipe_actually_RAN(tmp_path):
    """THE SEEDING FAULT. The early call cannot match a recipe, because nothing is
    confirmed yet — and it consumed the only chance."""
    from brukal.loop import GroundedLoop
    app = _CrAPI()
    s = _session(tmp_path, app)
    s.surface.confirmed_routes = []                      # nothing confirmed yet
    loop = GroundedLoop(s, max_steps=1)
    loop._seed_principals()                              # the early, futile call
    assert not getattr(s, "_seeded_principals", set()), \
        "a no-op consumed the principal's only seeding attempt"
    s.surface.confirmed_routes = list(CRAPI_ROUTES)      # ...the agent explores
    loop._seed_principals()
    assert [c for c in app.seen if c[1].endswith("/add_vehicle")], \
        "the recipe matched later and seeding never happened"


def test_a_recipe_that_RAN_is_not_run_twice(tmp_path):
    """BOUNDARY: the memo still does its job — every recipe creates real state."""
    from brukal.loop import GroundedLoop
    app = _CrAPI()
    s = _session(tmp_path, app)
    s.surface.confirmed_routes = list(CRAPI_ROUTES)
    loop = GroundedLoop(s, max_steps=1)
    loop._seed_principals()
    n = len([c for c in app.seen if c[1].endswith("/add_vehicle")])
    loop._seed_principals()
    loop._seed_principals()
    assert len([c for c in app.seen if c[1].endswith("/add_vehicle")]) == n
