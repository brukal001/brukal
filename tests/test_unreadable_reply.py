"""
test_unreadable_reply.py — a reply the loop could not UNDERSTAND is not a decision to stop.

THE PROPERTY, widened
    `test_truncated_reply.py` shipped "a reply that never FINISHED is not a decision",
    keyed on the backend's `finish_reason`. That is one cause of a missing action line.
    This file pins the general property: **the loop must never treat "we could not read
    the reply" and "there is nothing left to do" as the same state.** Truncation is one
    door into that state; an unparseable-but-complete reply is another, and it was not
    covered.

THE DEFECT THIS PINS (measured in run CM1, 2026-09-10)
    The engagement ended at step 16 of 70 with `stop_reason: "done"`, rendered to the
    operator as "nothing left to safely automate" and written into report.md as
    "Stopped because: done". $2.93 of a $4.00 budget went unspent. One line earlier:

        strategist: could not extract an action from model reply: "PHASE: exploitation
        GOAL: Fix the UNION-based SQLi against `/rest/products/search` — our first
        attempt threw a syntax error because the closing parens didn't match…"

    The model had proposed a next action. The reply FINISHED — so `_was_truncated()` was
    False, the retry never fired, every field parsed to None, and the loop read "no
    action" as "finished".

WHY IT IS WORSE THAN THE TRUNCATION CASE
    Truncation stopped the loop saying "nothing left to do". This stops it saying
    **"done"** — the most confident word available — on every surface a reader has. A run
    that abandons 77% of its budget must not be able to describe itself with the same
    word as a run that genuinely finished.

    `strategist.py` already knows: it warns ONLY when the reply clearly TRIED to propose
    an action (a RUN:/WEB:/MANUAL:/SESSION: marker or a code fence is present), staying
    quiet for a deliberate advice-only reply. That warning firing is the signal; nothing
    consumed it.
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
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"

# Both of these are REAL parse outcomes, confirmed against `_parse` on 2026-09-10:
# each leaves command/web/manual/session all None while the marker regex matches, which
# is exactly the state that fired the warning in CM1.
EMPTY_RUN = ("PHASE: exploitation\n"
             "GOAL: Fix the UNION-based SQLi against /rest/products/search\n"
             "REASONING: the closing parens did not match the app's WHERE nesting.\n"
             "RUN:\n")

PROSE_FENCE = ("PHASE: exploitation\n"
               "GOAL: Fix the UNION-based SQLi against /rest/products/search\n"
               "REASONING: the closing parens did not match the app's WHERE nesting.\n"
               "```\n<work out the correct nesting, then send it>\n```\n")

COMPLETE = ("PHASE: enumeration\n"
            "GOAL: Enumerate the API surface\n"
            "REASONING: We know the app answers on 3000.\n"
            f"RUN: curl -s http://{TARGET}:3000/rest/products\n")

# No marker, no fence: the model finished a sentence and offered nothing. A DECISION.
FINISHED_NO_ACTION = ("PHASE: looting\n"
                      "GOAL: Nothing further is safe to automate\n"
                      "REASONING: Every lead is exhausted and the rest needs a human.\n")


class _FakeLLM:
    """Scripted replies plus the finish reason a real backend reports."""

    def __init__(self, *replies_and_reasons):
        self._script = list(replies_and_reasons)
        self.calls: list[dict] = []
        self.last_stop_reason = ""

    def propose(self, system, user, max_tokens=1024):
        text, reason = self._script[min(len(self.calls), len(self._script) - 1)]
        self.calls.append({"max_tokens": max_tokens, "system": system})
        self.last_stop_reason = reason
        return text


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_an_unparseable_but_finished_reply_is_retried():
    """THE DEFECT. `end_turn` means the model said everything it meant to say — and we
    still could not read an action out of it. That is not the model deciding to stop."""
    llm = _FakeLLM((EMPTY_RUN, "end_turn"), (COMPLETE, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2, (
        "an unreadable reply was accepted as the model's decision — this is the CM1 "
        "stall that ended an engagement at step 16 of 70 with $2.93 unspent")
    assert s.command and "curl" in s.command, f"the retry's action was lost: {s!r}"
    assert not s.unreadable, "a successful retry must not stay flagged as unreadable"


def test_a_fenced_reply_with_no_runnable_command_is_retried_too():
    """The second real shape: the model answered inside a fence, with prose in it."""
    llm = _FakeLLM((PROSE_FENCE, "end_turn"), (COMPLETE, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2, "a fenced non-command reply was read as a decision"
    assert s.command and "curl" in s.command


def test_a_reply_unreadable_twice_is_flagged_rather_than_retried_forever():
    """One retry, then say so. A model that cannot land the template twice will not land
    it on a third call — but the loop must still not call it 'done'."""
    llm = _FakeLLM((EMPTY_RUN, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2, f"expected exactly one retry, got {len(llm.calls)}"
    assert s.unreadable, "a still-unreadable reply must be marked, not silently accepted"
    assert not s.command and not s.web


# --------------------------------------------------------------------------- #
# The boundary: a genuine "no action" is still a decision
# --------------------------------------------------------------------------- #

def test_a_finished_reply_with_no_marker_is_accepted_as_done():
    """THE BOUNDARY. No marker, no fence — the model finished and offered nothing. That
    IS a decision, and re-asking it would burn budget on a question already answered."""
    llm = _FakeLLM((FINISHED_NO_ACTION, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 1, "a deliberate advice-only reply was re-asked"
    assert not s.unreadable and not s.truncated
    assert not s.command and not s.web


def test_a_usable_reply_is_never_retried():
    llm = _FakeLLM((COMPLETE, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 1, "a usable reply was retried anyway"
    assert s.command and "curl" in s.command


# --------------------------------------------------------------------------- #
# The loop must not report the wrong ending
# --------------------------------------------------------------------------- #

class _InertKali:
    def run(self, command: str) -> ExecResult:
        return ExecResult(command, 0, "", "")


class _InertSite:
    def run(self, action):
        return WebResult(status=404, url=action.url, body="", headers={})


def _loop_result(reply_and_reason, tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _InertKali(), audit, approver=lambda d: True)
    sess = AssistSession(TARGET, ex, StrategistAgent(_FakeLLM(reply_and_reason)),
                         browser=GovernedBrowser(scope, _InertSite(), audit))
    return GroundedLoop(sess, max_steps=4).run()


def test_the_loop_does_not_report_done_when_the_reply_was_unreadable(tmp_path):
    """The word an operator reads must name what happened. 'done' about a reply we could
    not parse is the report being wrong in the most confident way available."""
    result = _loop_result((EMPTY_RUN, "end_turn"), tmp_path)

    assert result.stop_reason != "done", (
        "the loop reported a considered ending for a reply it could not read — CM1 "
        "printed exactly this, and report.md carried it as 'Stopped because: done'")
    assert result.stop_reason == "unreadable", result.stop_reason


def test_the_loop_still_reports_done_when_the_model_really_finished(tmp_path):
    """THE BOUNDARY, at the loop level."""
    result = _loop_result((FINISHED_NO_ACTION, "end_turn"), tmp_path)

    assert result.stop_reason == "done", result.stop_reason


# --------------------------------------------------------------------------- #
# The operator-facing text must agree with the ledger
# --------------------------------------------------------------------------- #

def test_every_stop_reason_the_loop_can_emit_has_its_own_operator_label():
    """STRUCTURAL, and it is the guard that would have caught this fix shipping half-done.
    `report.md` prints the raw `stop_reason`; the operator is shown `_STOP_LABELS[...]`.
    A reason with no label falls through to the bare word, and a reason someone forgets
    to add here would read as its own name while the report reads as something else."""
    import re

    from brukal.assist import _STOP_LABELS

    src = (Path(__file__).resolve().parents[1] / "brukal" / "loop.py").read_text()
    emitted = set(re.findall(r'_finish\(\s*"([a-z-]+)"', src))

    assert emitted, "no _finish() reasons found — the scan itself broke"
    missing = sorted(emitted - set(_STOP_LABELS))
    assert not missing, f"stop reasons the operator sees no sentence for: {missing}"


def test_the_unreadable_label_never_claims_there_was_nothing_left_to_do():
    from brukal.assist import _STOP_LABELS

    label = _STOP_LABELS["unreadable"]
    assert label != _STOP_LABELS["done"]
    # Not a naive substring check: the sentence is allowed to SAY "this is NOT 'nothing
    # left to do'". What it must never do is carry the finished-run sentence as its own.
    assert _STOP_LABELS["done"] not in label, (
        f"the unreadable ending describes itself as a finished one: {label!r}")
    assert "parse" in label.lower() or "read" in label.lower(), (
        f"the label does not say what actually happened: {label!r}")
