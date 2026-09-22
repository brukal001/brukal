"""
test_a_run_ends_when_work_ends.py — the run should end when the WORK ends, not when the
model runs out of ideas.

THE MEASURED PROBLEM (five runs, 2026-09-21/22)
    Budget utilisation against a 70-step allowance:

        cr2b   5 cmds  exit=manual      recall 1/14
        c1     7 cmds  exit=done        recall 1/14
        c3    10 cmds  exit=manual      recall 1/14
        cr2a  14 cmds  exit=manual      recall 2/14
        c2    24 cmds  killed by an external timeout, still working   recall 2/14

    Recall tracks work done up to ~14 commands. Every run but one ended VOLUNTARILY at a
    fifth of its budget, through one of two doors: `done` (the model produced no action)
    and `manual` (three consecutive operator-steps). Fixing the manual door alone just
    moved the constraint to `done`.

THE FIX, AND WHY IT IS NOT "KEEP LOOPING"
    Ignoring the model's stop would spend budget on nothing. So an exit first asks whether
    WORK is pending; if it is, the run does that work and continues, and if it is not, the
    run ends — which is the honest meaning of "done".

    WHAT THE PENDING WORK ACTUALLY IS, measured rather than assumed. The first version of
    this test asserted that derived experiments sat queued at the exit. Reading the three
    runs' notes disproved that: every derived experiment had run, and the test only passed
    its premise because `run_hypotheses` returns 0 when `browser is None`, so the fixture
    could not drain a queue it also could not fill. That is GAP #12's lesson a third time
    — a unit fixture that cannot express the condition will happily agree with you.

    The real leftover is the model's OWN experiment rounds. `_maybe_ask_the_model_for_-
    experiments` is gated on an 8-step cadence with a ceiling of 6 rounds. All three runs
    announced exactly ONE round, because a run that stops at 7-24 steps never reaches the
    later cadences. At the exit, between one and five model rounds were unspent — and an
    exit is precisely the moment the cadence was waiting for.

    TERMINATION IS BY CONSTRUCTION, not by patience: each override CONSUMES one of the six
    rounds, so the door can be held open at most `max_hypothesis_rounds` times and then
    closes for good. There is no counter to get wrong.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import Hypothesis  # noqa: F401
from brukal.kali import ExecResult
from brukal.loop import GroundedLoop

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"


class _Done:
    """A model that immediately says it has nothing to do — c1's exact shape."""
    last_stop_reason = "end_turn"

    def propose(self, *a, **k):
        return "PHASE: recon\nGOAL: finished\nREASONING: nothing further to try."


def _loop(tmp_path, **kw):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {
        "run": lambda s, c: ExecResult(c, 0, "ok", "")})(), audit, approver=lambda d: True)
    s = AssistSession("10.10.10.5", ex, StrategistAgent(_Done()))
    from brukal.webmap import AttackSurface
    s.surface = AttackSurface(seed="http://10.10.10.5/")
    return GroundedLoop(s, max_steps=8, **kw), s


def _queued(url="http://10.10.10.5/x"):
    return Hypothesis("queued work", "medium", "unauthenticated_exposure",
                      {"url": url, "method": "GET", "as": "self"},
                      {"url": url, "method": "GET", "as": "anonymous"}, "r")


def test_a_done_exit_SPENDS_A_REMAINING_MODEL_ROUND_instead_of_ending(tmp_path):
    """THE DEFECT: c1 said 'finished' at 7 commands of a 70-step budget holding five
    unspent experiment rounds."""
    loop, s = _loop(tmp_path, autonomous=True)
    loop._confirmed_done = True                 # round one already belongs to REFLEX 0b
    s.probeable_surface = lambda: True
    rounds = []
    s.run_hypotheses = lambda *a, **k: (rounds.append(1) or 0)

    loop.run()
    assert rounds, "the run ended with model experiment rounds unspent"


def test_it_cannot_hold_the_door_open_past_the_round_ceiling(tmp_path):
    """The cost bound, and why no counter is needed: each override spends a round."""
    loop, s = _loop(tmp_path, autonomous=True, max_hypothesis_rounds=3)
    loop._confirmed_done = True
    s.probeable_surface = lambda: True
    rounds = []
    s.run_hypotheses = lambda *a, **k: (rounds.append(1) or 0)

    result = loop.run()
    assert len(rounds) == 3, f"spent {len(rounds)} rounds against a ceiling of 3"
    assert result.stop_reason in ("done", "stalled")


def test_a_manual_exit_spends_them_too(tmp_path):
    """Both doors, or the constraint just moves to the other one — which is exactly what
    happened when only `manual` was fixed."""
    class _Manual:
        last_stop_reason = "end_turn"
        def propose(self, *a, **k):
            return ("PHASE: recon\nGOAL: g\nMANUAL: read the source by hand\n"
                    "REASONING: operator step.")
    loop, s = _loop(tmp_path, autonomous=True)
    s.agent = StrategistAgent(_Manual())
    loop._confirmed_done = True
    s.probeable_surface = lambda: True
    rounds = []
    s.run_hypotheses = lambda *a, **k: (rounds.append(1) or 0)

    loop.run()
    assert rounds, "the manual door ended the run with rounds unspent"


def test_it_ends_once_there_is_genuinely_nothing_left(tmp_path):
    """BOUNDARY, and the cost bound: with no pending work, `done` still means done. A run
    that cannot stop is a worse defect than one that stops early."""
    loop, s = _loop(tmp_path, autonomous=True, max_hypothesis_rounds=0)
    result = loop.run()
    assert result.stop_reason in ("done", "stalled")
    assert len(loop.steps) <= 4, f"it spun for {len(loop.steps)} steps with no work"


def test_an_interactive_run_is_unchanged(tmp_path):
    """The autonomous gate holds here too: without --full-send the operator's stop stands."""
    loop, s = _loop(tmp_path, autonomous=False)
    loop._confirmed_done = True
    s.probeable_surface = lambda: True
    rounds = []
    s.run_hypotheses = lambda *a, **k: (rounds.append(1) or 0)
    loop.run()
    assert rounds == [], "an interactive run kept going past the operator's stop"
