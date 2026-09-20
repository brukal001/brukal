"""
test_cross_principal_experiments_wait.py — an experiment that cannot run YET must not be spent.

THE MEASURED PROBLEM (crAPI, 2026-09-20)
    A recorded human session produced the three `state_changed` experiments this project
    had been trying to reach for two series — a purchase, a return, a coupon validation,
    each with a control the target had already accepted. All three were recorded
    `second_unavailable` and discarded. Reading the ledger in order:

        row 181,190,199   state_changed -> second_unavailable   <- experiments run
        row 322           signup POST                            <- principal CREATED
        row 755           SECOND principal used

    The second principal existed 120 rows later and was used successfully. The
    experiments were not impossible; they were EARLY. The loop drains derived hypotheses
    at the top of every turn, principals are established later in REFLEX 0b, and a
    cross-principal experiment drained before then is consumed and written off as a
    harness limit it will never get to retry.

    `second_unavailable` is recorded as HARNESS-LIMIT, which is true and useless: the
    harness limit was the SCHEDULE, and the record made it look like a capability the
    engagement lacked.

THE PROPERTY
    An experiment naming a principal that does not exist yet WAITS. It is not run, not
    recorded as a miss, and not lost.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import Hypothesis
from brukal.kali import ExecResult
from brukal.web import FakeWebCage, GovernedBrowser
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent.parent / "scope.crapi.json"
URL = "http://172.20.0.12/workshop/api/shop/orders"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession("172.20.0.12", ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, FakeWebCage(), audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed="http://172.20.0.12/")
    return s


def _needs_second():
    return Hypothesis(
        "POST /workshop/api/shop/orders observed in traffic", "high", "state_changed",
        {"url": URL, "method": "GET", "as": "self"},
        {"url": URL, "method": "GET", "as": "self"},
        "r", [], {"url": URL, "method": "POST", "as": "second"})


def _needs_nobody():
    return Hypothesis(
        "anonymous read", "medium", "unauthenticated_exposure",
        {"url": URL, "method": "GET", "as": "self"},
        {"url": URL, "method": "GET", "as": "anonymous"}, "r")


def test_an_experiment_needing_a_principal_that_does_not_exist_is_DEFERRED(tmp_path):
    s = _session(tmp_path)
    s._derived_hypotheses = [_needs_second()]
    ran = []
    s._run_one_round = lambda props, outcomes, shapes=None: (ran.extend(props) or 0)

    s.run_hypotheses(derived_only=True)
    assert ran == [], "it was run before the principal it names existed"
    assert s.derived_hypotheses(), "it was consumed and lost rather than deferred"


def test_it_RUNS_once_the_principal_exists(tmp_path):
    s = _session(tmp_path)
    s._derived_hypotheses = [_needs_second()]
    ran = []
    s._run_one_round = lambda props, outcomes, shapes=None: (ran.extend(props) or 0)

    s.run_hypotheses(derived_only=True)
    assert ran == []
    s._second_identity = {"user": "b@brukal.test"}      # established later, as in a real run
    s.run_hypotheses(derived_only=True)
    assert len(ran) == 1, "the deferred experiment never ran after the principal appeared"
    assert s.derived_hypotheses() == [], "it ran but was not drained"


def test_experiments_that_need_nobody_are_NOT_held_up(tmp_path):
    """BOUNDARY: deferring must not stall the experiments that could have run all along."""
    s = _session(tmp_path)
    s._derived_hypotheses = [_needs_second(), _needs_nobody()]
    ran = []
    s._run_one_round = lambda props, outcomes, shapes=None: (ran.extend(props) or 0)

    s.run_hypotheses(derived_only=True)
    assert [h.comparator for h in ran] == ["unauthenticated_exposure"]
    assert len(s.derived_hypotheses()) == 1


def test_the_MODEL_round_also_respects_readiness(tmp_path):
    """MEASURED: deferral was added to the derived-only drain, and the experiments were
    still spent — because `run_hypotheses()` (the MODEL round) ALSO drains the derived
    queue:

        _derived = self.derived_hypotheses()
        if _derived:
            self._derived_hypotheses = []      <- takes the deferred ones too
            proposals = _derived + list(proposals)

    Guarding one of two drains is not guarding. The readiness rule belongs to the QUEUE,
    not to one consumer of it, or the next consumer added inherits the bug."""
    s = _session(tmp_path)
    s._derived_hypotheses = [_needs_second()]
    ran = []
    s._run_one_round = lambda props, outcomes, shapes=None: (ran.extend(props) or 0)
    s.strategist = type("S", (), {"_llm": type("L", (), {
        "propose": staticmethod(lambda *a, **k: "[]"),
        "last_stop_reason": "end_turn", "last_block_kinds": []})()})()

    s.run_hypotheses()                         # the MODEL path, not derived_only
    assert not [h for h in ran if (h.act or {}).get("as") == "second"], (
        "the model round spent an experiment whose principal does not exist")
    assert s.derived_hypotheses(), "it was drained and lost by the model path"
