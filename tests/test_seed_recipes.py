"""
test_seed_recipes.py — the mechanism that gives a principal something to own.

THE MEASURED PROBLEM (CR1 runs 1-4)
    Six of twelve missed crAPI challenges fail on one fact, and it is not intelligence:

        GET /identity/api/v2/vehicle/vehicles?id=1  ->  []

    A cross-account comparator needs OUR resource and THEIRS. With nothing on our side
    the control is empty and the experiment cannot hold however well it is proposed.

WHAT IS BEING TESTED HERE IS THE MECHANISM, NOT A TARGET
    Onboarding is application-specific by nature, and this project's recurring mistake is
    encoding one application's shape as the harness's behaviour. So the shape is DATA and
    these tests pin the general contract: a recipe fires only on CONFIRMED routes, every
    step goes through the gate, a step that does not answer as expected stops the
    sequence with a reason, and bound values reach request BODIES only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.seed import SeedRecipe, SeedStep, extract, recipe_for, run_seed
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"

# The shape a real onboarding has: ask, read a token out of PROSE in a mailbox, redeem it.
MAIL = json.dumps({"items": [{"Content": {"Body": "Hello, your vehicle VIN is 9NZPV8LB2SL and "
                                                  "the pincode is 1234. Drive safely."}}]})
RECIPE = SeedRecipe(
    name="test-vehicle-onboarding",
    requires=("/api/vehicle/resend_email", "/api/vehicle/add_vehicle"),
    steps=(
        SeedStep("POST", "/api/vehicle/resend_email", note="ask for the details"),
        SeedStep("GET", "/mail/api/v2/messages",
                 binds={"vin": "re:VIN is ([A-Z0-9]+)", "pin": "re:pincode is (\\d+)"},
                 note="read the mailbox"),
        SeedStep("POST", "/api/vehicle/add_vehicle",
                 body={"vin": "{vin}", "pincode": "{pin}"},
                 binds={"id": "id"}, note="redeem"),
    ),
    owns="id")
CONFIRMED = ["/api/vehicle/resend_email", "/api/vehicle/add_vehicle", "/mail/api/v2/messages"]


class _App:
    def __init__(self, add_status=200):
        self.seen: list = []
        self.add_status = add_status

    def run(self, action):
        self.seen.append((action.method, action.url, action.body))
        if action.url.endswith("/resend_email"):
            return WebResult(status=200, url=action.url, body='{"message":"sent"}')
        if "messages" in action.url:
            return WebResult(status=200, url=action.url, body=MAIL)
        if action.url.endswith("/add_vehicle"):
            return WebResult(status=self.add_status, url=action.url,
                             body='{"id": 77, "vin": "9NZPV8LB2SL"}')
        return WebResult(status=404, url=action.url, body="{}")


def _session(tmp_path, app, confirmed=CONFIRMED, intrusive=True):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, app, audit))
    s.allow_intrusive = intrusive
    s.identity = "us@brukal.test"
    surface = AttackSurface(seed=f"{BASE}/")
    surface.confirmed_routes = list(confirmed)
    s.surface = surface
    return s, audit


# --------------------------------------------------------------------------- #

def test_a_token_is_read_out_of_PROSE_not_only_json():
    """Real onboarding mail carries the details in a sentence. A JSON path alone cannot
    reach them, which is why `extract` takes a regex form."""
    assert extract(MAIL, "re:VIN is ([A-Z0-9]+)") == "9NZPV8LB2SL"
    assert extract(MAIL, "re:pincode is (\\d+)") == "1234"
    assert extract('{"a": {"b": 5}}', "a.b") == 5


def test_a_recipe_fires_only_on_CONFIRMED_routes():
    """Never on a mined guess: these steps CREATE state on a live application."""
    assert recipe_for(CONFIRMED, [RECIPE]) is RECIPE
    assert recipe_for(["/something/else"], [RECIPE]) is None
    assert recipe_for([], [RECIPE]) is None


def test_seeding_gives_the_principal_something_to_own(tmp_path):
    """THE POINT: after this, a cross-account comparator has a control to compare."""
    s, audit = _session(tmp_path, _App())
    out = run_seed(s, "self", RECIPE)
    assert out["owned"] == "77", out
    assert out["bound"]["vin"] == "9NZPV8LB2SL"
    rows = [json.loads(l)["data"] for l in open(audit.path) if json.loads(l)["kind"] == "seed"]
    assert rows and rows[0]["value"] == "77", rows


def test_every_step_goes_through_the_GATE(tmp_path):
    """Invariant 4: seeding is not a side channel. Three requests, three gated decisions."""
    s, audit = _session(tmp_path, _App())
    run_seed(s, "self", RECIPE)
    decisions = [json.loads(l) for l in open(audit.path)
                 if json.loads(l)["kind"] == "web_decision"]
    assert len(decisions) >= 3, decisions


def test_a_step_that_does_not_answer_as_expected_STOPS_with_a_reason(tmp_path):
    """A half-seeded principal is worse than an unseeded one: the comparator would reason
    about a resource that may not exist."""
    s, _audit = _session(tmp_path, _App(add_status=500))
    out = run_seed(s, "self", RECIPE)
    assert out["owned"] == ""
    assert "answered 500" in out["reason"], out


def test_a_bound_value_reaches_the_BODY_only(tmp_path):
    """A value the target supplied must not be able to redirect where the next request
    goes, which substituting into a URL would allow."""
    app = _App()
    s, _ = _session(tmp_path, app)
    run_seed(s, "self", RECIPE)
    add = [c for c in app.seen if c[1].endswith("/add_vehicle")][0]
    assert "9NZPV8LB2SL" in add[2], add          # in the body
    assert "9NZPV8LB2SL" not in add[1], add      # never in the URL


def test_without_full_send_it_does_nothing(tmp_path):
    """BOUNDARY: seeding creates state, so it needs the same authorisation an experiment's
    setup steps already need."""
    app = _App()
    s, _ = _session(tmp_path, app, intrusive=False)
    out = run_seed(s, "self", RECIPE)
    assert out["owned"] == "" and "full-send" in out["reason"]
    assert app.seen == [], "it touched the target without authorisation"


def test_a_target_with_no_recipe_seeds_nothing_and_says_so(tmp_path):
    """BOUNDARY: most targets have no recipe, and that must be a quiet, stated no-op."""
    app = _App()
    s, _ = _session(tmp_path, app, confirmed=["/unrelated"])
    out = run_seed(s, "self")
    assert out["owned"] == "" and "no seed recipe" in out["reason"]
    assert app.seen == []
