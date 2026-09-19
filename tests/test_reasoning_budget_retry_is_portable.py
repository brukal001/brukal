"""
test_reasoning_budget_retry_is_portable.py — the thinking-budget retry stopped at Anthropic.

THE MEASURED PROBLEM (2026-09-19, OpenRouter pre-flight, ~$0.01)
    `deepseek/deepseek-v4-flash` is a reasoning model: it emits `reasoning` tokens that
    are billed against the SAME `max_tokens` as the answer. Probed at the live path's
    hardcoded 8000, **3 of 8 replies came back as 0 characters** — the call succeeded,
    cost full price, and returned nothing. Raising the budget to 20000 cut it to 1 of 8.

    The Anthropic backend already handles exactly this, and its own comment describes the
    symptom: "the call then succeeds, costs full price, and returns ''". A live run
    recorded it as "model returned no usable experiment (0 chars)", which reads as a model
    with nothing to say. It had plenty to say; it never reached the part where it says it.

    **That fix was never applied to the OpenAI-compatible backend** — the path EVERY open
    model uses (OpenRouter, DeepSeek, Groq, NVIDIA, Ollama, LM Studio). So the portability
    tally this project keeps is exactly right: a defect fixed at one provider and not the
    others is not fixed.

THE PROPERTY
    An empty reply that was CUT OFF is retried once with a bigger budget, on every
    provider. An empty reply that simply ended is not (it is an answer, and retrying it
    burns money for nothing).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.llm import _OpenAICompatBackend


class _FakeBackend(_OpenAICompatBackend):
    """Drives `propose` without a network: records the budgets it was asked for and
    replays a scripted sequence of (finish_reason, content)."""

    def __init__(self, script):
        self.model = "test/reasoner"
        self.url = "http://x/v1/chat/completions"
        self.key = "k"
        self.script = list(script)
        self.budgets = []
        self.last_usage = {}
        self.last_stop_reason = ""
        self.last_block_kinds = []

    def _post(self, body):
        import json
        self.budgets.append(json.loads(body)["max_tokens"])
        finish, content = self.script.pop(0)
        return {"choices": [{"finish_reason": finish,
                             "message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 10}}


def test_an_empty_reply_that_was_CUT_OFF_is_retried_with_more_budget():
    """The measured case: reasoning ate the whole allowance."""
    b = _FakeBackend([("length", ""), ("stop", '[{"title":"t"}]')])
    out = b.propose("sys", "usr", 8000)
    assert out == '[{"title":"t"}]', out
    assert len(b.budgets) == 2, b.budgets
    assert b.budgets[1] > b.budgets[0], b.budgets


def test_an_empty_reply_that_simply_ENDED_is_not_retried():
    """BOUNDARY, and it is a cost bound: a model that answered with nothing has answered.
    Retrying every empty reply would double the bill on every refusal."""
    b = _FakeBackend([("stop", "")])
    assert b.propose("sys", "usr", 8000) == ""
    assert len(b.budgets) == 1, b.budgets


def test_a_reply_that_arrived_is_never_retried():
    """POSITIVE CONTROL. Without it, 'retries when cut off' is also satisfied by a
    backend that retries everything."""
    b = _FakeBackend([("length", '[{"title":"partial"}]')])
    assert b.propose("sys", "usr", 8000) == '[{"title":"partial"}]'
    assert len(b.budgets) == 1, b.budgets


def test_the_retry_is_bounded_and_happens_at_most_once():
    b = _FakeBackend([("length", ""), ("length", "")])
    assert b.propose("sys", "usr", 8000) == ""
    assert len(b.budgets) == 2, "retried more than once"
    assert b.budgets[1] <= 32_000, b.budgets
