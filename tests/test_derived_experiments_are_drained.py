"""
test_derived_experiments_are_drained.py — a run must not end with the best question unasked.

THE MEASURED PROBLEM (CR1 run 3, 2026-09-18)
    The bridge worked: two `foreign_record` observations reached the ledger —
    `/workshop/api/shop/orders/1` and `/orders/2`, each returning a party that is not us
    — and each became a queued `a_denied_b_allowed` experiment.

    **Neither was ever asked.** The observations landed at ledger entries #476 and #479;
    the last experiment round closed at #399. `run_hypotheses` is a REFLEX that fires once,
    early, and the agent does its exploration afterwards — so the queue filled after the
    only consumer had already run, and the run ended with two well-evidenced questions
    sitting in memory.

    Same shape as the defect it was built to fix, one rung further out: the observation
    now survives, and nothing drains it.

THE FIX, and its cost
    The loop drains pending derived proposals each turn. `derived_only=True` skips the
    model call entirely — these proposals came from the target's own responses, so asking
    the model for more would be paying for imagination we did not need.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import from_foreign_record
from brukal.kali import ExecResult
from brukal.loop import GroundedLoop
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
ORDERS_2 = f"http://{TARGET}/workshop/api/shop/orders/2"
FOREIGN = json.dumps({"order": {"id": 2, "user": {"email": "pogba006@example.com"}}})


class _Model:
    last_stop_reason = "end_turn"
    def __init__(self):
        self.calls = 0
    def propose(self, *a, **k):
        self.calls += 1
        return "[]"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = _Model()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, type("C", (), {
                          "run": lambda self, a: WebResult(status=200, url=a.url, body="{}")})(),
                          audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    from brukal.webmap import AttackSurface
    s.surface = AttackSurface(seed=f"http://{TARGET}/")
    return s, llm, audit


def _queue_one(s):
    """An observation now yields TWO questions — BOLA and unauthenticated exposure —
    because it is compatible with two truths and the target decides which."""
    made = from_foreign_record(ORDERS_2, FOREIGN, {"us@brukal.test"})
    s._derived_hypotheses = list(made)
    return made[0]


def test_a_pending_derived_experiment_is_ASKED(tmp_path):
    """THE DEFECT: run 3 ended with two of these unasked."""
    s, _llm, _a = _session(tmp_path)
    _queue_one(s)
    seen = []
    s._run_one_round = lambda proposals, outcomes, shapes=None: (seen.extend(proposals) or 0)
    s.run_hypotheses(derived_only=True)
    assert seen and [h.comparator for h in seen] == ["a_denied_b_allowed",
                                                     "unauthenticated_exposure"]
    assert s.derived_hypotheses() == [], "asked but not drained — it will be asked again"


def test_draining_costs_NO_model_call(tmp_path):
    """These proposals came from the target's own responses. Paying for imagination we
    did not need would make the bridge cost a model call per observation."""
    s, llm, _a = _session(tmp_path)
    _queue_one(s)
    s._run_one_round = lambda proposals, outcomes, shapes=None: 0
    s.run_hypotheses(derived_only=True)
    assert llm.calls == 0, f"{llm.calls} model call(s) for an experiment we already had"


def test_with_nothing_pending_it_does_nothing(tmp_path):
    """BOUNDARY: no queue, no round, no cost — the ordinary turn is unchanged."""
    s, llm, _a = _session(tmp_path)
    called = []
    s._run_one_round = lambda proposals, outcomes, shapes=None: (called.append(1) or 0)
    assert s.run_hypotheses(derived_only=True) == 0
    assert called == [] and llm.calls == 0


def test_the_LOOP_drains_what_a_command_observed(tmp_path):
    """END TO END, run 3's exact sequence: the agent's command returns a foreign record
    mid-run, and the loop asks the question before the engagement ends."""
    s, _llm, audit = _session(tmp_path)
    asked = []
    s._run_one_round = lambda proposals, outcomes, shapes=None: (asked.extend(proposals) or 0)
    loop = GroundedLoop(s, max_steps=2)
    # the observation arrives the way it did in run 3 — from an executed command
    from brukal.gate import Decision
    cmd = f"curl -s {ORDERS_2}"
    s._absorb_shell(cmd, Decision(verdict="ALLOW", action=cmd, target=TARGET,
                                  agent="t", reason="t", layer="t"),
                    ExecResult(cmd, 0, FOREIGN, ""))
    assert s.derived_hypotheses(), "the observation never reached the queue"
    loop.run()
    assert asked, "the loop ended with a well-evidenced question unasked"
    # The OBSERVATION must be drained. The queue itself is no longer necessarily empty:
    # cross-principal experiments derived from captured traffic are DEFERRED until the
    # second principal exists rather than consumed and written off (see
    # test_cross_principal_experiments_wait.py), so anything left must be waiting on a
    # principal, never the foreign-record question this test is about.
    assert {h.comparator for h in asked} == {"a_denied_b_allowed", "unauthenticated_exposure"}, (
        "the foreign-record questions are what this test is about and they must be ASKED")
    for h in s.derived_hypotheses():
        names = {h.control.get("as"), h.variant.get("as"),
                 (h.act or {}).get("as") if h.act else None}
        assert "second" in names, f"something was left queued for no reason: {h.title}"


def test_the_model_path_is_unchanged(tmp_path):
    """BOUNDARY: a normal round still asks the model. The drain is an addition, not a
    replacement — the model's imagination is the point of the mechanism."""
    s, llm, _a = _session(tmp_path)
    s._run_one_round = lambda proposals, outcomes, shapes=None: 0
    s.run_hypotheses()
    assert llm.calls == 1
