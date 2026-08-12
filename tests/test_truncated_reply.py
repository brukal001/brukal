"""
test_truncated_reply.py — a reply the model never finished is not a decision.

THE PROPERTY
    The loop ends autonomous work when `advise()` yields no `RUN:` / `WEB:` action. That
    is only a legitimate ending if the model actually FINISHED its reply. A reply cut off
    at the token ceiling carries no action line because it never got that far, and must
    be retried — never read as "nothing left to do".

THE DEFECT THIS PINS (measured in the Juice Shop 2B run, 2026-08-12)
    The strategist template puts the action line LAST, after 2-4 sentences of REASONING,
    and the call is made with max_tokens=800. Two of five calls in a live engagement ran
    out of allowance mid-REASONING:

        call 3: 262 chars, action lines: NONE, ends "…REASONING: We've fingerprinted th"
        call 5: 747 chars, action lines: NONE, ends "…fast next move and directly tests"

    Each one ended a segment with "nothing left to safely automate" — while the stop line
    printed the model's own GOAL, i.e. the loop announced it had nothing to do and quoted
    the thing it wanted to do next. 12 of 20 budgeted steps and $3.75 of a $4 cap went
    unused, and the engagement never reached the business-logic half of its methodology.

    An early return that looks like judgement is the worst kind of failure: it raises no
    error and appears nowhere in the output as a fault.

WHY THE EXISTING RETRY DID NOT COVER IT
    `_AnthropicBackend.propose` already retries once — but only when the reply is EMPTY
    because the whole allowance went on thinking. It explicitly returns a truncated reply
    that did emit text ("it answered and was cut off; not this case"). That is exactly
    this case, seen from the other side: text arrived, the ACTION did not.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.llm import _OpenAICompatBackend
from brukal.loop import GroundedLoop
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"

# A reply that ran out of allowance mid-sentence: no RUN:, no WEB:, no MANUAL:.
CUT_OFF = ("PHASE: exploitation\n"
           "GOAL: Attempt the classic login bypass on /rest/user/login\n"
           "REASONING: We've fingerprinted this as OWASP Juice Shop, whose login endpoint "
           "builds raw SQL, so a quote in the email field is the standard next move and dir")

COMPLETE = ("PHASE: enumeration\n"
            "GOAL: Enumerate the API surface\n"
            "REASONING: We know the app answers on 3000.\n"
            f"RUN: curl -s http://{TARGET}:3000/rest/products\n")

FINISHED_NO_ACTION = ("PHASE: looting\n"
                      "GOAL: Nothing further is safe to automate\n"
                      "REASONING: Every lead is exhausted and the rest needs a human.\n")


class _FakeLLM:
    """Returns scripted replies and reports how each one ended, like a real backend."""

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

def test_a_truncated_reply_with_no_action_is_retried():
    """THE DEFECT. The first reply died mid-REASONING; that is not an answer."""
    llm = _FakeLLM((CUT_OFF, "max_tokens"), (COMPLETE, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2, (
        "a reply cut off at the token ceiling was accepted as the model's decision — "
        "this is the live stall that ended two engagement segments")
    assert s.command and "curl" in s.command, f"the retry's action was lost: {s!r}"
    assert not s.truncated, "a successful retry must not stay flagged as truncated"


def test_the_retry_asks_for_a_bigger_allowance():
    """Retrying with the SAME ceiling would just truncate in the same place."""
    llm = _FakeLLM((CUT_OFF, "max_tokens"), (COMPLETE, "end_turn"))
    StrategistAgent(llm).advise(TARGET, "findings")

    first, second = llm.calls[0]["max_tokens"], llm.calls[1]["max_tokens"]
    assert second > first, f"retried with no more room: {first} -> {second}"


def test_an_openai_style_length_finish_counts_as_truncated():
    """The OpenAI convention names it 'length'; Anthropic's is 'max_tokens'. Both mean
    the same thing and a provider swap must not silently disable this."""
    llm = _FakeLLM((CUT_OFF, "length"), (COMPLETE, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2 and s.command, "a 'length' finish was not treated as truncation"


# --------------------------------------------------------------------------- #
# The boundary: what must NOT change
# --------------------------------------------------------------------------- #

def test_a_finished_reply_with_no_action_is_accepted_as_done():
    """A model that finished its sentence and offered no action HAS decided. Retrying
    that would burn budget re-asking a question already answered."""
    llm = _FakeLLM((FINISHED_NO_ACTION, "end_turn"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 1, "a completed reply was retried"
    assert not s.command and not s.web
    assert not s.truncated


def test_a_truncated_reply_that_still_carries_an_action_is_used_as_is():
    """Truncation only matters when it cost us the action line."""
    truncated_but_usable = COMPLETE + "\nREASONING continues and is cut off here mid-sent"
    llm = _FakeLLM((truncated_but_usable, "max_tokens"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 1, "a usable reply was retried anyway"
    assert s.command and "curl" in s.command


def test_a_reply_truncated_twice_is_flagged_rather_than_retried_forever():
    """One retry, then say so. A model truncating at 4x the allowance will not be fixed
    by a third call, but the loop must still not call it 'done'."""
    llm = _FakeLLM((CUT_OFF, "max_tokens"))
    s = StrategistAgent(llm).advise(TARGET, "findings")

    assert len(llm.calls) == 2, f"expected exactly one retry, got {len(llm.calls)} calls"
    assert s.truncated, "a still-truncated reply must be marked, not silently accepted"
    assert not s.command and not s.web


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


def test_the_loop_does_not_report_done_when_the_reply_was_truncated(tmp_path):
    """The stop reason an operator reads must say what happened. 'nothing left to safely
    automate' about a sentence that never finished is the report being wrong."""
    result = _loop_result((CUT_OFF, "max_tokens"), tmp_path)

    assert result.stop_reason != "done", (
        "the loop reported a considered ending for a reply the model never finished")
    assert result.stop_reason == "truncated", result.stop_reason


def test_the_loop_still_reports_done_when_the_model_really_finished(tmp_path):
    result = _loop_result((FINISHED_NO_ACTION, "end_turn"), tmp_path)

    assert result.stop_reason == "done", result.stop_reason


# --------------------------------------------------------------------------- #
# The signal itself has to arrive from every backend
# --------------------------------------------------------------------------- #

def test_the_openai_compatible_backend_records_its_finish_reason():
    """Without this the fix is Anthropic-only: the OpenAI-compatible backend never
    recorded a stop reason, so `--provider ollama/openrouter/deepseek` would keep
    treating a truncated plan as a decision."""
    b = _OpenAICompatBackend("m", "http://x/v1", "k")
    b._post = lambda body: {                      # noqa: SLF001 — the network is the point
        "choices": [{"finish_reason": "length",
                     "message": {"content": CUT_OFF}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    b.propose("sys", "user", 800)

    assert b.last_stop_reason == "length", (
        f"finish_reason never reached the client: {b.last_stop_reason!r}")
