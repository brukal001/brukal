"""
test_seeding_is_wired.py — the engine has to actually run, and what it creates has to
reach the ledger the comparator reads.

THE MEASURED PROBLEM
    `GET /identity/api/v2/vehicle/vehicles?id=1 -> []` across CR1 runs 1-5. Six of the
    twelve missed challenges fail on that empty control. The recipe engine exists; nothing
    calls it, and a seeded resource nobody records is invisible to the comparator anyway —
    `ownership_evidence` reads `principal_identifiers()`, so a vehicle created but never
    written to the ownership ledger leaves the cross-account claim exactly as unprovable
    as before.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.loop import GroundedLoop
from brukal.seed import CRAPI_VEHICLE, run_seed
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_seed_recipes import CRAPI_MAILBOX, CRAPI_ROUTES, _CrAPI  # noqa: E402

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"


def _session(tmp_path, app):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, app, audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    surface = AttackSurface(seed=f"http://{TARGET}/")
    surface.confirmed_routes = list(CRAPI_ROUTES)
    # A real run reaches the principal/seed reflex only once the surface is probeable, and
    # route confirmation always leaves the confirmed paths in `api_routes`. The fixture
    # mirrors that rather than pretending the reflex fires on an empty map.
    surface.add_routes(list(CRAPI_ROUTES))
    s.surface = surface
    return s, audit


def test_what_seeding_CREATES_reaches_the_ownership_ledger(tmp_path):
    """THE POINT. A vehicle created but never recorded is invisible to
    `ownership_evidence`, so the cross-account claim stays exactly as unprovable."""
    s, audit = _session(tmp_path, _CrAPI())
    run_seed(s, "self", CRAPI_VEHICLE)
    owners = [json.loads(l)["data"] for l in open(audit.path)
              if json.loads(l)["kind"] == "principal_ownership"]
    assert owners, "nothing was recorded — the comparator cannot see the new resource"
    # The UUID is what crAPI addresses the vehicle by, but the ledger's extractor only
    # understands numeric identifiers — so what must land here is the id, from the whole
    # bound set rather than the recipe's headline value.
    assert any(o["principal"] == "self" and str(o["value"]) == "31" for o in owners), owners
    assert any(o["source"] == "seed" for o in owners), owners
    assert "31" in json.dumps(s.principal_identifiers()), s.principal_identifiers()


def test_the_loop_seeds_BOTH_principals_once(tmp_path):
    """A cross-account comparator needs a control AND a variant, so both sides get one —
    and only once per engagement, because each seeding creates real state."""
    app = _CrAPI()
    s, _audit = _session(tmp_path, app)
    s._second_identity = {"user": "them@brukal.test", "password": "x",
                          "cookies": {}, "auth": "Bearer them"}
    loop = GroundedLoop(s, max_steps=2)
    loop.run()
    adds = [c for c in app.seen if c[1].endswith("/add_vehicle")]
    assert len(adds) == 2, f"seeded {len(adds)} principal(s), expected self and second"
    loop2 = GroundedLoop(s, max_steps=2)
    loop2.run()
    assert len([c for c in app.seen if c[1].endswith("/add_vehicle")]) == 2, \
        "it seeded again on a later turn — that is real state created twice"


def test_a_target_with_no_recipe_costs_nothing(tmp_path):
    """BOUNDARY: most targets have no recipe. No requests, no notes, no change."""
    class _Plain:
        def __init__(self): self.seen = []
        def run(self, action):
            self.seen.append(action.url)
            return WebResult(status=200, url=action.url, body="{}")
    app = _Plain()
    s, _audit = _session(tmp_path, app)
    s.surface.confirmed_routes = ["/rest/user/whoami"]
    GroundedLoop(s, max_steps=1).run()
    assert not [u for u in app.seen if "vehicle" in u]


def test_a_failed_seeding_is_recorded_and_does_not_stop_the_run(tmp_path):
    """Instrumentation rule: seeding is capability, not governance. A target that refuses
    it leaves a reason and the engagement continues."""
    class _Refuses(_CrAPI):
        def run(self, action):
            if action.url.endswith("/add_vehicle"):
                return WebResult(status=403, url=action.url, body='{"message":"no"}')
            return super().run(action)
    s, audit = _session(tmp_path, _Refuses())
    result = GroundedLoop(s, max_steps=2).run()
    assert result is not None
    assert any("seed" in n.lower() for n in s.notes), s.notes[-4:]


def test_seeding_happens_when_the_recipe_BECOMES_matchable(tmp_path):
    """RUN 7's DEFECT. Prefix learning confirmed all three of crAPI's services and
    seeding still produced nothing, because `_seed_principals` fires once in the early
    reflex and the vehicle routes were only confirmed later, as the agent explored.

    Same ordering defect as the derived-experiment drain, one mechanism over: the
    consumer runs once and the evidence arrives afterwards."""
    app = _CrAPI()
    s, _audit = _session(tmp_path, app)
    s.surface.confirmed_routes = []                 # nothing confirmed yet
    s.surface.api_routes = ["/identity/api/v2/user/dashboard"]
    loop = GroundedLoop(s, max_steps=3)
    # the agent explores, and the vehicle routes get confirmed mid-run
    s._answered_paths = ["/identity/api/v2/vehicle/vehicles"]
    s.surface.confirmed_routes = list(CRAPI_ROUTES)
    loop.run()
    assert [c for c in app.seen if c[1].endswith("/add_vehicle")], \
        "the recipe became matchable mid-run and nothing seeded"
