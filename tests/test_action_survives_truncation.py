"""
test_action_survives_truncation.py — the strategist's reply must not be the binding constraint.

THE MEASURED PROBLEM
    CM1 stopped at step 16 of 70. CM2 stopped at step 22 of 70. Both ended on a reply
    truncated TWICE — once at the 800-token allowance and again at the 4x retry (3,200) —
    with the action line never reached. CM2 left $10.55 of a $12.00 cap unspent.

    `37b3957` and `a1978af` made a truncated reply survivable: it is retried, and if it
    still has no action the loop says so instead of claiming it is done. Neither made it
    LESS LIKELY. The template puts the action line LAST, after 2-4 sentences of REASONING,
    so an overrun eats the answer and keeps the prose.

THE EXPIRED CONSTRAINT
    `docs/HARDENING_ROADMAP.md` recorded reordering as deliberately not done: it "would
    silently move every published metric". That constraint protected metrics the paper was
    to publish. The paper is deferred and those metrics are superseded by CM1 and CM2, so
    it no longer holds and is recorded as expired at the point of change.

TWO LEVERS, TESTED SEPARATELY ON PURPOSE
    (i)  ORDER — the action line is emitted BEFORE the reasoning, so truncation costs
         prose rather than the answer.
    (ii) ALLOWANCE — 800 -> 2,000, retry 3,200 -> 8,000, and the client streams at or
         above 8,000 so the SDK's non-streaming ceiling can never bite the retry.

    They are pinned by separate tests so the run data can say which one paid. Neither test
    proves the fix works against a live model; that is CM3's job. These prove the levers
    are actually in place and that nothing else moved.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.agents import StrategistAgent
from brukal.agents.strategist import STRATEGIST_SYSTEM, _parse

TARGET = "10.10.10.5"

# The new order: the action lands before the prose, so a cut in the prose costs prose.
ACTION_FIRST_CUT_IN_REASONING = (
    "PHASE: exploitation\n"
    "GOAL: Test the basket endpoint for object-level authorization\n"
    f"WEB: get http://{TARGET}:3000/rest/basket/2\n"
    "REASONING: The API exposes numeric basket ids and our own is 1, so asking for 2 as "
    "ourselves separates an ownership check from a mere existence check, and the answer "
    "tells us whether the object-level rule is enfor")

COMPLETE = ("PHASE: enumeration\n"
            "GOAL: Enumerate the API surface\n"
            f"RUN: curl -s http://{TARGET}:3000/rest/products\n"
            "REASONING: We know the app answers on 3000.\n")

FINISHED_NO_ACTION = ("PHASE: looting\n"
                      "GOAL: Nothing further is safe to automate\n"
                      "REASONING: Every lead is exhausted and the rest needs a human.\n")


class _FakeLLM:
    def __init__(self, *replies_and_reasons):
        self._script = list(replies_and_reasons)
        self.calls: list[dict] = []
        self.last_stop_reason = ""

    def propose(self, system, user, max_tokens=1024):
        text, reason = self._script[min(len(self.calls), len(self._script) - 1)]
        self.calls.append({"max_tokens": max_tokens})
        self.last_stop_reason = reason
        return text


# --------------------------------------------------------------------------- #
# LEVER (i) — ORDER
# --------------------------------------------------------------------------- #

def test_the_template_puts_the_action_line_before_the_reasoning():
    """LEVER (i), at the only place it can be pinned: what the model is ASKED for.

    The parser has always been order-independent, so no parser test can detect this
    change. The instruction is the fix."""
    first_action = min(STRATEGIST_SYSTEM.find(t) for t in ("RUN:", "WEB:", "MANUAL:", "SESSION:")
                       if STRATEGIST_SYSTEM.find(t) != -1)
    reasoning = STRATEGIST_SYSTEM.find("REASONING:")

    assert reasoning != -1 and first_action != -1
    assert first_action < reasoning, (
        "the action line is still requested after REASONING, so an overrun still eats "
        "the answer and keeps the prose — the shape that stopped CM1 at 16/70 and CM2 "
        "at 22/70")


def test_the_template_says_the_action_must_come_first():
    """Ordering the lines is not the same as saying why. A model that has been reasoning
    first for its whole training needs to be told the constraint explicitly."""
    text = STRATEGIST_SYSTEM.lower()

    assert "before" in text and ("truncat" in text or "cut off" in text), (
        "the template never explains that the action must precede the prose because a "
        "cut-off reply loses whatever came last")


def test_an_action_first_reply_cut_mid_reasoning_is_used_as_is():
    """LEVER (i)'s payoff, end to end: the exact shape that used to cost an engagement.

    NOTE: this passes before the change too — `_parse` never cared about order. It is
    here as the must-not-break half, not as evidence the fix works."""
    llm = _FakeLLM((ACTION_FIRST_CUT_IN_REASONING, "max_tokens"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 1, "a reply that HAD its action was retried anyway"
    assert s.web and "basket/2" in s.web, f"the action was lost: {s!r}"
    assert not s.truncated and not s.unreadable


# --------------------------------------------------------------------------- #
# LEVER (ii) — ALLOWANCE
# --------------------------------------------------------------------------- #

def test_the_first_call_asks_for_the_raised_allowance():
    """LEVER (ii). 800 was the number both CM1 and CM2 were cut at."""
    llm = _FakeLLM((COMPLETE, "end_turn"))
    StrategistAgent(llm).advise(TARGET, "findings")

    assert llm.calls[0]["max_tokens"] >= 2000, (
        f"still asking for {llm.calls[0]['max_tokens']} tokens; CM2 was truncated at 800 "
        f"and again at its 4x retry")


def test_the_retry_asks_for_more_than_the_allowance_that_already_failed():
    """CM2 was cut at 3,200 on the retry, so a retry at 3,200 is a known-failing number."""
    llm = _FakeLLM((ACTION_FIRST_CUT_IN_REASONING.split("WEB:")[0], "max_tokens"),
                   (COMPLETE, "end_turn"))
    StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2
    assert llm.calls[1]["max_tokens"] >= 8000, (
        f"retry asks for {llm.calls[1]['max_tokens']}; CM2 was already truncated at 3,200")


def test_a_large_request_streams():
    """The SDK refuses a non-streaming request whose max_tokens implies a long run, and
    that ceiling is model- and estimator-dependent. Streaming is decided by SIZE on the
    client, not by a per-call flag, so every caller inherits it and no test double has to
    grow a parameter it does not use."""
    from brukal.llm import _AnthropicBackend

    b = _AnthropicBackend.__new__(_AnthropicBackend)
    assert b._streams_at(8000) is True, "the raised retry does not stream"
    assert b._streams_at(800) is False, "an ordinary call started streaming — not asked for"


# --------------------------------------------------------------------------- #
# The boundaries: what must NOT change
# --------------------------------------------------------------------------- #

def test_the_reasoning_is_still_asked_for_and_still_recorded():
    """THE BOUNDARY THAT MATTERS. We are moving where the answer sits, not removing the
    thinking. A template that dropped REASONING would 'fix' truncation by making the model
    stop reasoning, which is a capability cut wearing a reliability fix."""
    assert "REASONING:" in STRATEGIST_SYSTEM

    s = _parse(ACTION_FIRST_CUT_IN_REASONING, TARGET)
    assert s.rationale and "numeric basket ids" in s.rationale, (
        f"the reasoning was not recorded: {s.rationale!r}")
    assert s.phase == "exploitation" and s.goal


def test_a_genuinely_actionless_reply_is_still_accepted_as_done():
    """THE BOUNDARY. No marker, no fence, finished — a decision, not a failure."""
    llm = _FakeLLM((FINISHED_NO_ACTION, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 1, "a deliberate advice-only reply was re-asked"
    assert not s.command and not s.web and not s.truncated and not s.unreadable


def test_the_stop_reason_and_the_operator_sentence_still_agree(tmp_path):
    """THE BOUNDARY. Fix 1's guarantee must survive the reordering."""
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.assist import AssistSession, _STOP_LABELS
    from brukal.kali import ExecResult
    from brukal.loop import GroundedLoop
    from brukal.web import GovernedBrowser, WebResult

    class _Kali:
        def run(self, command):
            return ExecResult(command, 0, "", "")

    class _Site:
        def run(self, action):
            return WebResult(status=404, url=action.url, body="", headers={})

    scope = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope_fast.json")
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    cut_before_action = "PHASE: exploitation\nGOAL: something\nREASONING: cut off mid-sent"
    sess = AssistSession(TARGET, ex,
                         StrategistAgent(_FakeLLM((cut_before_action, "max_tokens"))),
                         browser=GovernedBrowser(scope, _Site(), audit))
    result = GroundedLoop(sess, max_steps=4).run()

    assert result.stop_reason == "truncated", result.stop_reason
    assert _STOP_LABELS[result.stop_reason] != _STOP_LABELS["done"]
    assert "nothing left to safely automate" not in _STOP_LABELS[result.stop_reason]
