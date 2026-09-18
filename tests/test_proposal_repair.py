"""
test_proposal_repair.py — a proposal that names a fragment we RESOLVED is repaired.

THE MEASURED FAULT (CR1 runs 9 through 12, after the surface was already correct)
    Run 12's surface was right: /identity/api/v2/user/dashboard confirmed [GET], phantoms
    gone, methods annotated. The model still proposed

        /v2/user/dashboard     /v2/user/videos/0     /v2/user/pictures/29

    and nine of eleven experiment 404s came from that. It was taking paths from the
    UNVERIFIED fragment list that sits beside the confirmed one — the list whose own
    label says "prefer the fetched paths above".

    That label has been there since GAP #4 and has never once worked, which is this
    session's most-repeated lesson: a caveat in prose that no code enforces is a comment,
    not a safeguard.

THE FIX, and why repair rather than refusal
    Resolution already knows `/v2/user/dashboard` became `/identity/api/v2/user/dashboard`
    — it proved it with a request. So a proposal naming the fragment is not wrong about
    WHAT to test, only about where it lives. Repairing it deterministically turns a
    guaranteed 404 into a real experiment; refusing it would spend the proposal on
    nothing. No model is involved: the mapping is the one resolution recorded.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import Hypothesis
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, type("C", (), {
                          "run": lambda self, a: WebResult(status=200, url=a.url, body="{}")})(),
                          audit))
    s.allow_intrusive = True
    surface = AttackSurface(seed=f"{BASE}/")
    s.surface = surface
    # what resolution proved, exactly as it records it
    s._resolved_map = {"/v2/user/dashboard": "/identity/api/v2/user/dashboard",
                       "/v2/user/videos": "/identity/api/v2/user/videos"}
    surface.confirmed_routes = list(s._resolved_map.values())
    return s, audit


def _h(url, variant=None):
    return Hypothesis(title="t", severity="high", comparator="cross_account_resource",
                      control={"method": "GET", "url": url, "as": "self"},
                      variant={"method": "GET", "url": variant or url, "as": "second"},
                      setup=[])


def test_a_proposal_naming_a_resolved_fragment_is_REPAIRED(tmp_path):
    """RUN 12's defect: nine of eleven experiment 404s were this."""
    s, _ = _session(tmp_path)
    got = s.repair_proposals([_h(f"{BASE}/v2/user/dashboard")])
    assert got[0].control["url"] == f"{BASE}/identity/api/v2/user/dashboard", got[0].control
    assert got[0].variant["url"] == f"{BASE}/identity/api/v2/user/dashboard"


def test_the_query_string_and_path_suffix_survive(tmp_path):
    """`?user_id=29` and `/0` are the experiment; only the mount is wrong."""
    s, _ = _session(tmp_path)
    got = s.repair_proposals([_h(f"{BASE}/v2/user/dashboard?user_id=29",
                                 f"{BASE}/v2/user/videos/0")])
    assert got[0].control["url"].endswith("/identity/api/v2/user/dashboard?user_id=29")
    assert got[0].variant["url"].endswith("/identity/api/v2/user/videos/0")


def test_a_proposal_already_correct_is_untouched(tmp_path):
    """BOUNDARY: repair must not rewrite what the model got right."""
    s, _ = _session(tmp_path)
    url = f"{BASE}/identity/api/v2/user/dashboard"
    got = s.repair_proposals([_h(url)])
    assert got[0].control["url"] == url


def test_a_path_we_never_resolved_is_left_alone(tmp_path):
    """BOUNDARY: we only correct what we PROVED. An unknown path stays as proposed, and
    is judged on what the target says about it."""
    s, _ = _session(tmp_path)
    url = f"{BASE}/something/we/never/saw"
    got = s.repair_proposals([_h(url)])
    assert got[0].control["url"] == url


def test_the_repair_is_on_the_LEDGER(tmp_path):
    """A request that is not the one the model wrote must be visible as such."""
    s, audit = _session(tmp_path)
    s.repair_proposals([_h(f"{BASE}/v2/user/dashboard")])
    rows = [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == "proposal_repaired"]
    assert rows, "a proposal was rewritten with no record of it"
    assert rows[0]["from"].endswith("/v2/user/dashboard")
    assert rows[0]["to"].endswith("/identity/api/v2/user/dashboard")


def test_with_nothing_resolved_nothing_is_repaired(tmp_path):
    """BOUNDARY: on a target where resolution did nothing — a single-service app — this
    mechanism is inert."""
    s, _ = _session(tmp_path)
    s._resolved_map = {}
    url = f"{BASE}/v2/user/dashboard"
    assert s.repair_proposals([_h(url)])[0].control["url"] == url
