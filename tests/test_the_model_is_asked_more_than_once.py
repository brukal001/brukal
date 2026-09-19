"""
test_the_model_is_asked_more_than_once.py — GAP #18: the imagination was consulted once.

THE MEASURED PROBLEM (CR1 run 18, 2026-09-19, $3.71)
    Run 18 was launched to measure whether the model would propose `state_changed`
    experiments once the prompt stopped forbidding them. It proposed none, and the run
    was written up as the MODEL's limit.

    The run's own vault says otherwise. Five times:

        [experiment] asking 2 experiment(s) derived from observed records (no model call)

    `run_hypotheses(derived_only=True)` returns before the LLM is ever fetched, and the
    loop calls it EVERY TURN. The model path sits inside REFLEX 0b, gated on
    `_confirmed_done`, which is set True on entry -- it "runs once". So across 70 steps
    the model was asked for experiments ONE time, capped at six proposals.

    An offline A/B on the same prompt (4 calls per arm) had the model proposing
    `state_changed` in 7 of 8 calls, every one carrying a valid `act`. The capability was
    never missing. **The pipeline asked once and the silence was read as an answer.**

THE PROPERTY
    A long run asks the model for experiments MORE THAN ONCE, on a bounded cadence, and
    the derived drain -- which costs no model call -- never stands in for a model round.
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
    """A strategist that keeps proposing real, distinct commands, so the loop takes
    STEPS instead of stalling out after four turns. Cadence is measured in steps, so a
    loop that never takes one cannot exercise it."""
    last_stop_reason = "end_turn"

    def __init__(self):
        self.calls = 0

    def propose(self, *a, **k):
        self.calls += 1
        return ("PHASE: recon\n"
                f"GOAL: probe {self.calls}\n"
                f"REASONING: enumerate step {self.calls}.\n"
                f"RUN: whatweb http://{TARGET}/p{self.calls}")


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


def _loop_that_counts_model_rounds(s, tmp_path, **kw):
    """Count MODEL rounds specifically: `run_hypotheses()` with derived_only False."""
    rounds = []
    real = s.run_hypotheses

    def counting(max_run: int = 4, derived_only: bool = False):
        if not derived_only:
            rounds.append(len(rounds) + 1)
            return 0
        return real(max_run=max_run, derived_only=True)

    s.run_hypotheses = counting
    s.probeable_surface = lambda: True
    return GroundedLoop(s, **kw), rounds


def test_a_long_run_asks_the_model_more_than_once(tmp_path):
    """THE DEFECT: one round per engagement, however long the engagement."""
    s, _llm, _a = _session(tmp_path)
    loop, rounds = _loop_that_counts_model_rounds(
        s, tmp_path, max_steps=40, hypothesis_every=4, max_hypothesis_rounds=6)
    loop.run()
    assert len(rounds) > 1, (
        f"the model was asked {len(rounds)} time(s) in a 40-step run — run 18's defect")


def test_the_derived_drain_does_not_stand_in_for_a_model_round(tmp_path):
    """Run 18's five 'no model call' rounds. A queue that refills every turn must not
    keep the model from ever being asked."""
    s, _llm, _a = _session(tmp_path)
    loop, rounds = _loop_that_counts_model_rounds(
        s, tmp_path, max_steps=30, hypothesis_every=4, max_hypothesis_rounds=6)
    # Keep a derived proposal pending on every turn, exactly as a live run does.
    s._derived_hypotheses = list(from_foreign_record(ORDERS_2, FOREIGN, {"us@brukal.test"}))
    s._run_one_round = lambda proposals, outcomes, shapes=None: 0
    loop.run()
    assert len(rounds) > 1, "the derived drain suppressed every model round"


def test_model_rounds_are_BOUNDED(tmp_path):
    """Asking more must not mean asking without limit: each round is model spend, and a
    run that asks fifty times is a different defect, not a fix."""
    s, _llm, _a = _session(tmp_path)
    loop, rounds = _loop_that_counts_model_rounds(
        s, tmp_path, max_steps=60, hypothesis_every=1, max_hypothesis_rounds=3)
    loop.run()
    # Both halves, so the guard cannot pass by the cadence being broken: it must ask
    # MORE than once and still stop at the ceiling.
    assert 1 < len(rounds) <= 3, f"{len(rounds)} rounds, cap was 3"


def test_the_cadence_is_respected_not_every_turn(tmp_path):
    """BOUNDARY. Without this, 'more than once' is satisfied by asking every single turn,
    which is the opposite failure and costs a model call per step."""
    s, _llm, _a = _session(tmp_path)
    loop, rounds = _loop_that_counts_model_rounds(
        s, tmp_path, max_steps=20, hypothesis_every=8, max_hypothesis_rounds=9)
    loop.run()
    assert 1 < len(rounds) <= 4, (
        f"{len(rounds)} rounds in 20 steps at a cadence of 8 — either the cadence is "
        f"ignored (too many) or it never fires again (too few)")
