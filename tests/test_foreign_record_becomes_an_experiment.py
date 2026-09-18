"""
test_foreign_record_becomes_an_experiment.py — the seam CR1 measured, closed.

THE MEASURED PROBLEM (CR1 run 2, 2026-09-18)
    The exploit agent issued, through the gate, with our own bearer:

        GET /workshop/api/shop/orders/2  ->  200
        {"order":{"id":2,"user":{"email":"pogba006@example.com","number":"9876570006"},…}}

    Another tenant's complete order. The evidence went into the ledger as an `execution`
    row, the model recognised it — it is the text of the handoff that ended the run — and
    **no finding was published**, because a finding must be derived from a comparator and
    no comparator ever judged it. Recall scored the run 0 of 14.

    Brukal has two paths to a finding. The COMPARATOR path is rigorous and is the only one
    that publishes; the COMMAND path is where the agent actually finds things and it
    publishes nothing. Almost all the capability lives on the path that cannot produce a
    finding.

THE FIX, and what it is careful not to do
    An observation that a resource ADDRESSED BY ID returned a record naming a party that
    is not us becomes a PROPOSED EXPERIMENT, which the existing comparator then judges
    like any other. Derived deterministically — no model anywhere in it — and dispatched
    through the same governed path, so nothing about how a finding is established changes.

    The experiment is `a_denied_b_allowed`: control ANONYMOUS (must be refused), variant
    as US (returns the record). That is the honest claim available here — authentication
    is enforced, authorization is not — and it is bounded by what the comparator can show.
    The foreign party is established at observation time and carried as evidence, never
    re-derived by the comparator.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.gate import Decision
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import foreign_parties, from_foreign_record
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
ORDERS_2 = f"{BASE}/workshop/api/shop/orders/2"

# CR1 run 2's actual response, trimmed.
FOREIGN_BODY = json.dumps({"order": {"id": 2, "status": "delivered",
                                     "user": {"email": "pogba006@example.com",
                                              "number": "9876570006"},
                                     "product": {"id": 1, "name": "Seat"}}})
OURS = "brk726c8f6e@brukal.test"
OUR_BODY = json.dumps({"order": {"id": 1, "user": {"email": OURS}}})


# --------------------------------------------------------------------------- #
# The observation
# --------------------------------------------------------------------------- #

def test_a_record_naming_someone_who_is_not_us_is_recognised():
    assert foreign_parties(FOREIGN_BODY, {OURS}) == ["pogba006@example.com"]


def test_OUR_OWN_record_is_not_a_foreign_party():
    """THE BOUNDARY THAT MATTERS. Reading our own data must never propose an experiment,
    or every authenticated request becomes a false cross-account lead."""
    assert foreign_parties(OUR_BODY, {OURS}) == []
    assert not from_foreign_record(f"{BASE}/workshop/api/shop/orders/1", OUR_BODY, {OURS})


@pytest.mark.parametrize("addr", ["noreply@crapi.io", "support@example.com",
                                  "no-reply@vendor.test", "admin@localhost"])
def test_role_addresses_are_not_parties(addr):
    """A bounce address in a template is not a tenant whose data we just read."""
    body = json.dumps({"mail": {"from": addr}})
    assert foreign_parties(body, {OURS}) == []


# --------------------------------------------------------------------------- #
# The experiment it becomes
# --------------------------------------------------------------------------- #

def test_the_observation_becomes_TWO_governed_experiments():
    """The observation is compatible with two different truths and we do not know which
    until the target answers: authentication enforced but not authorization, or nothing
    enforced at all. Asking only the first left crAPI's order exposure unpublished in four
    consecutive runs."""
    made = from_foreign_record(ORDERS_2, FOREIGN_BODY, {OURS})
    assert made, "CR1's finding would be lost again"
    assert [x.comparator for x in made] == ["a_denied_b_allowed",
                                            "unauthenticated_exposure"], made
    h = made[0]
    assert h.control["url"] == ORDERS_2 and h.variant["url"] == ORDERS_2
    assert h.control.get("as") == "anonymous", h.control
    assert h.variant.get("as") == "self", h.variant
    assert h.setup == [] or h.setup is None


def test_a_listing_is_not_an_addressed_record():
    """`/orders` returns our own list; only a resource addressed BY ID can be somebody
    else's. Without this every collection endpoint proposes an experiment."""
    assert not from_foreign_record(f"{BASE}/workshop/api/shop/orders", FOREIGN_BODY, {OURS})


def test_the_party_is_MASKED_in_the_proposal():
    """Evidence hygiene: the finding is about the exposure, and the proposal travels into
    notes, prompts and the report. The full value stays in the ledger's execution row."""
    blob = json.dumps([[h.title, h.rationale]
                       for h in from_foreign_record(ORDERS_2, FOREIGN_BODY, {OURS})])
    assert "pogba006@example.com" not in blob, blob
    assert "pog" in blob or "@example.com" in blob, "it masked the evidence out of existence"


def test_the_title_says_what_was_observed_not_what_is_hoped():
    for h in from_foreign_record(ORDERS_2, FOREIGN_BODY, {OURS}):
        low = h.title.lower()
        assert "orders" in low or "record" in low
        for overclaim in ("takeover", "critical", "rce", "all users", "database"):
            assert overclaim not in low, h.title


# --------------------------------------------------------------------------- #
# The wiring: the command plane reaches the experiment queue
# --------------------------------------------------------------------------- #

def _allow(action):
    return Decision(verdict="ALLOW", action=action, target=TARGET, agent="test",
                    reason="test", layer="test")


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, type("C", (), {
                          "run": lambda self, a: WebResult(status=200, url=a.url, body="{}")})(),
                          audit),
                      blackboard=None)
    s.surface = AttackSurface(seed=f"{BASE}/")
    s.identity = OURS
    return s, audit


def test_a_curl_that_returns_a_foreign_record_queues_an_experiment(tmp_path):
    """END TO END on the command plane — CR1's exact case."""
    s, audit = _session(tmp_path)
    cmd = f"curl -s -i {ORDERS_2} -H 'Authorization: Bearer x'"
    s._absorb_shell(cmd, _allow(cmd), ExecResult(cmd, 0, FOREIGN_BODY, ""))
    queued = s.derived_hypotheses()
    assert queued, "the command plane still cannot reach the comparator"
    assert queued[0].control["url"] == ORDERS_2
    rows = [json.loads(l) for l in open(audit.path)
            if json.loads(l)["kind"] == "foreign_record"]
    assert rows, "the observation left no ledger record"
    assert "pogba006@example.com" not in json.dumps(rows[0]["data"]), rows[0]["data"]


def test_the_WEB_plane_reaches_it_too(tmp_path):
    """Same door discipline as the redaction fix: a second plane must not go unhooked."""
    s, _audit = _session(tmp_path)
    from brukal.web import WebAction
    s._absorb_web(WebAction("request", method="GET", url=ORDERS_2), _allow(ORDERS_2),
                  WebResult(status=200, url=ORDERS_2, body=FOREIGN_BODY))
    assert s.derived_hypotheses(), "the web plane's observations are still discarded"


def test_our_own_data_on_the_command_plane_queues_NOTHING(tmp_path):
    s, _ = _session(tmp_path)
    cmd = f"curl -s {BASE}/workshop/api/shop/orders/1"
    s._absorb_shell(cmd, _allow(cmd), ExecResult(cmd, 0, OUR_BODY, ""))
    assert s.derived_hypotheses() == []


def test_the_queue_is_bounded_and_deduplicated(tmp_path):
    s, _ = _session(tmp_path)
    for i in range(40):
        cmd = f"curl -s {BASE}/workshop/api/shop/orders/2"
        s._absorb_shell(cmd, _allow(cmd), ExecResult(cmd, 0, FOREIGN_BODY, ""))
    assert len(s.derived_hypotheses()) == 2, "the same observation queued repeatedly"


def test_derived_proposals_are_DISPATCHED_not_merely_queued(tmp_path):
    """The last link. A queued experiment that never reaches `_run_one_round` publishes
    exactly as much as the note CR1 left behind: nothing."""
    s, audit = _session(tmp_path)
    s.allow_intrusive = True
    cmd = f"curl -s {ORDERS_2}"
    s._absorb_shell(cmd, _allow(cmd), ExecResult(cmd, 0, FOREIGN_BODY, ""))
    seen = []
    s._run_one_round = lambda proposals, outcomes, shapes=None: (
        seen.extend(proposals) or 0)
    s.run_hypotheses(max_run=4)
    assert seen, "the derived experiment never reached the round"
    assert seen[0].comparator == "a_denied_b_allowed"
    assert s.derived_hypotheses() == [], "it was not drained and will be proposed twice"
