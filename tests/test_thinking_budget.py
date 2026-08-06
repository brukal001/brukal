"""An answer spent entirely on thinking is not an absence of an answer.

Adaptive thinking is billed against the same max_tokens as the reply, so a model that
reasons at length can hit the ceiling before emitting a single text block. The call then
SUCCEEDS, costs full price, and returns "". A live run recorded exactly that as
"model returned no usable experiment (0 chars)", which read as a model with nothing to
say about the target. It had plenty to say; it never reached the part where it says it.

Observed directly against claude-sonnet-5:
    reply='', stop_reason='max_tokens', blocks=['thinking']

Every caller is exposed, not only the experiment mechanism: the strategist plans through
the same method, and an empty plan is indistinguishable from a finished engagement.
"""
from __future__ import annotations

from brukal.llm import _AnthropicBackend


class _Recorder(_AnthropicBackend):
    """Replays a scripted sequence of (stop_reason, block kinds, text)."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.last_stop_reason = ""
        self.last_block_kinds = []

    def _propose_once(self, system, user, max_tokens):
        self.calls.append(max_tokens)
        stop, kinds, text = self.script.pop(0)
        self.last_stop_reason, self.last_block_kinds = stop, list(kinds)
        return text


def test_a_reply_lost_to_thinking_is_retried_with_a_bigger_budget():
    b = _Recorder([("max_tokens", ["thinking"], ""),
                   ("end_turn", ["thinking", "text"], "ok")])
    assert b.propose("s", "u", 64) == "ok"
    assert b.calls == [64, 256], "the retry must ask for materially more room"


def test_a_genuine_truncation_is_not_retried():
    """It DID answer and was cut off mid-sentence. Retrying would pay twice for the same
    partial answer, and the salvage paths downstream already handle a truncated reply."""
    b = _Recorder([("max_tokens", ["text"], "[{\"title\": \"partial")])
    assert b.propose("s", "u", 64).startswith("[{")
    assert b.calls == [64]


def test_a_normal_reply_costs_one_call():
    b = _Recorder([("end_turn", ["text"], "fine")])
    assert b.propose("s", "u", 1000) == "fine"
    assert b.calls == [1000]


def test_an_empty_reply_for_some_other_reason_is_not_retried():
    """Only a max_tokens stop indicates the thinking-budget case. A refusal or a stop
    sequence is a real answer of 'nothing', and retrying it just spends money."""
    b = _Recorder([("end_turn", ["text"], "")])
    assert b.propose("s", "u", 1000) == ""
    assert b.calls == [1000]


def test_the_retry_is_bounded():
    """One retry, and never an unbounded budget: a model that thinks past four times the
    allowance will not answer on a third attempt either."""
    b = _Recorder([("max_tokens", ["thinking"], ""),
                   ("max_tokens", ["thinking"], "")])
    assert b.propose("s", "u", 16_000) == ""
    assert len(b.calls) == 2
    assert b.calls[1] <= _AnthropicBackend._THINKING_RETRY_CEILING
