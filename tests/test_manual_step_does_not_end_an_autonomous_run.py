"""
test_manual_step_does_not_end_an_autonomous_run.py — the runs were quitting, not finishing.

THE MEASURED PROBLEM (2026-09-21)
    Step-budget utilisation across the paid runs:

        CR1 run 18  sonnet-5  23 shell commands of a 70-step budget   stop=exhausted
        CR2 run 1   v4-pro    14                                      stop=MANUAL
        CR2 run 2   v4-pro     5                                      stop=MANUAL

    CR2 run 2 ended after FIVE commands — about 7% of its budget — because the model
    proposed one step it considered manual ("copy your JWT and forge a token at jwt.io")
    and the loop treats a manual suggestion as the end of the engagement. Recall is
    bounded by work done, so the best-performing model was doing a tenth of the available
    work and no amount of better reconnaissance can help a run that stops after five
    commands.

    The codebase already carries a scar from this class, recorded beside the very line:
    "Run CM1 ended here at step 16 of 70 with $2.93 of $4.00 unspent, and called itself
    'done'". That fix distinguished the CAUSES of an early ending; it kept ending.

THE PROPERTY
    In AUTONOMOUS mode — which `--full-send` exists to request — a manual suggestion is a
    recorded handoff note and the run CONTINUES. Interactive mode is unchanged: there, a
    manual step really is the operator's move. A run that only ever proposes manual steps
    still stops, after three, so it cannot spin.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.loop import GroundedLoop

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"


class _Model:
    """Proposes a MANUAL step first, then real commands — CR2 run 2's exact shape."""

    last_stop_reason = "end_turn"

    def __init__(self, manual_first=1):
        self.calls = 0
        self.manual_first = manual_first

    def propose(self, *a, **k):
        self.calls += 1
        if self.calls <= self.manual_first:
            return ("PHASE: exploitation\nGOAL: forge a token\n"
                    "REASONING: this needs a human.\n"
                    "MANUAL: copy your JWT from the browser and forge one at jwt.io")
        return ("PHASE: recon\nGOAL: enumerate\nREASONING: keep going.\n"
                f"RUN: whatweb http://10.10.10.5/p{self.calls}")


def _loop(tmp_path, model, **kw):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {
        "run": lambda s, c: ExecResult(c, 0, "ok", "")})(), audit, approver=lambda d: True)
    s = AssistSession("10.10.10.5", ex, StrategistAgent(model))
    return GroundedLoop(s, max_steps=8, **kw), s


def test_an_autonomous_run_CONTINUES_past_a_manual_step(tmp_path):
    """THE DEFECT: five commands of a seventy-step budget."""
    loop, _s = _loop(tmp_path, _Model(manual_first=1), autonomous=True)
    result = loop.run()
    assert result.stop_reason != "manual", "the run ended on the operator's move"
    assert len(loop.steps) > 1, f"it stopped after {len(loop.steps)} step(s)"


def test_the_manual_step_is_RECORDED_not_discarded(tmp_path):
    """Continuing must not lose it: the operator still needs to know what was suggested."""
    loop, s = _loop(tmp_path, _Model(manual_first=1), autonomous=True)
    loop.run()
    notes = " ".join(getattr(s, "notes", []) or [])
    assert "jwt.io" in notes or "manual" in notes.lower(), notes[:200]


def test_an_INTERACTIVE_run_still_stops(tmp_path):
    """BOUNDARY, and the reason this is gated: without --full-send a manual step really is
    the operator's move, and running on would take intrusive actions nobody authorised."""
    loop, _s = _loop(tmp_path, _Model(manual_first=1), autonomous=False)
    assert loop.run().stop_reason == "manual"


def test_a_run_that_ONLY_proposes_manual_steps_still_stops(tmp_path):
    """It must not spin. Three consecutive manual suggestions with no runnable action and
    the engagement ends — otherwise a model with nothing to offer burns the whole budget."""
    loop, _s = _loop(tmp_path, _Model(manual_first=99), autonomous=True)
    result = loop.run()
    assert result.stop_reason == "manual"
    assert len(loop.steps) <= 4, f"it spun for {len(loop.steps)} steps"
