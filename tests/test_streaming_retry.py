"""test_streaming_retry.py — the retry built to break a silence must not be silent.

`_AnthropicBackend.propose` retries once when the whole allowance went on thinking. It
computes `bigger = min(max_tokens * 4, 32_000)` and re-issues the call NON-STREAMING —
and the SDK refuses before sending anything:

    ValueError: Streaming is required for operations that may take longer than 10 minutes.

Reproduced against anthropic 0.116.0 with no API call: 8,000 and 16,000 pass, the
ceiling is 21,333, and 32,000 always raises. `run_hypotheses` asks at 8,000, so the
retry is ALWAYS 32,000, so on this path the retry can never succeed. `assist.py`'s
`except Exception: return 0` then erased the ValueError, and REFLEX 0b is gated to fire
once — so one swallowed error removed model-proposed experiments from a whole live
engagement, leaving no trace on any surface.

It is worst where it matters most: the failure needs the model to burn 8,000 tokens
thinking, which happens when the surface is RICH. A three-route fixture succeeded; the
live 43-route crawl failed 3/3. A capability that degrades on rich input passes every
small test while disappearing on every target worth measuring.

Capping `bigger` under 21,333 would fix the instance. The ceiling is model- and
estimator-dependent — `claude-sonnet-5` is absent from the SDK's
`MODEL_NONSTREAMING_TOKENS`, so a generic ten-minute estimate applies and a different
model moves it. Streaming fixes the property.

Two boundaries this must not break, both bought by earlier P1s:
  * the stop reason still reaches the client (the truncation fix), on BOTH backends;
  * the prompt is still redacted (`LLMClient.propose` is redaction write site #3).
"""
from __future__ import annotations

import json

from brukal import redact
from brukal.llm import LLMClient, UsageMeter, _AnthropicBackend

# The real message, verbatim from anthropic 0.116.0.
_SDK_REFUSAL = ("Streaming is required for operations that may take longer than "
                "10 minutes. See https://github.com/anthropics/anthropic-sdk-python"
                "#long-requests for more details.")
# anthropic 0.116.0, claude-sonnet-5, generic estimator. Not a constant to code against
# — that is the whole point — but the number this suite reproduces the bug at.
_NONSTREAMING_CEILING = 21_333


# -- a stub SDK that behaves like the real one at the boundary ------------------

class _Usage:
    input_tokens, output_tokens = 100, 10
    cache_read_input_tokens, cache_creation_input_tokens = 0, 0


class _Block:
    def __init__(self, kind, text=""):
        self.type, self.text = kind, text


class _Msg:
    def __init__(self, stop_reason, blocks):
        self.stop_reason, self.content, self.usage = stop_reason, blocks, _Usage()


class _Stream:
    def __init__(self, msg, recorder):
        self._msg, self._rec = msg, recorder

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self._msg


class _FakeMessages:
    """Refuses a non-streaming call above the ceiling, exactly as the SDK does."""

    def __init__(self, client):
        self._c = client

    def create(self, **kw):
        self._c.calls.append(("create", kw.get("max_tokens"), bool(kw.get("stream"))))
        if kw.get("max_tokens", 0) > _NONSTREAMING_CEILING and not kw.get("stream"):
            raise ValueError(_SDK_REFUSAL)
        return self._c._next()

    def stream(self, **kw):
        self._c.calls.append(("stream", kw.get("max_tokens"), True))
        self._c.prompts.append(json.dumps(kw.get("messages", "")) + str(kw.get("system", "")))
        return _Stream(self._c._next(), self._c)


class _FakeClient:
    def __init__(self, script):
        self.script, self.calls, self.prompts = list(script), [], []
        self.messages = _FakeMessages(self)

    def _next(self):
        stop, kinds, text = self.script.pop(0)
        return _Msg(stop, [_Block(k, text if k == "text" else "") for k in kinds])


def _backend(script, model="claude-sonnet-5"):
    b = _AnthropicBackend.__new__(_AnthropicBackend)
    b._client = _FakeClient(script)
    b.model, b.last_usage = model, {}
    b.last_stop_reason, b.last_block_kinds = "", []
    return b


# -- 1. the defect itself -------------------------------------------------------

def test_a_retry_above_the_nonstreaming_ceiling_is_dispatched_rather_than_raising():
    """The named bug. First call spends 8,000 on thinking; the retry at 32,000 must
    reach the model instead of dying in the SDK before a request is sent."""
    b = _backend([("max_tokens", ["thinking"], ""),
                  ("end_turn", ["thinking", "text"], "[{\"title\": \"real\"}]")])
    assert b.propose("sys", "user", 8000) == "[{\"title\": \"real\"}]"
    assert len(b._client.calls) == 2, "the retry never happened"
    kind, size, streamed = b._client.calls[1]
    assert size > _NONSTREAMING_CEILING, "precondition: the retry is above the ceiling"
    assert streamed, f"the retry went out non-streaming at {size} and the SDK refuses that"


def test_the_retry_is_streamed_at_the_size_the_live_run_used():
    """run_hypotheses asks at 8,000, so the retry is always 32,000 — the exact pair that
    failed 3/3 against the live crawl.

    AMENDED 2026-09-11. This test was RIGHT when written: streaming was then a property of
    the RETRY, so the first call at 8,000 went unstreamed. `_STREAM_AT` made it a property
    of SIZE instead, because the strategist's raised retry (8,000) needed it and threading
    a per-call flag would have forced a parameter onto every test double in the suite. The
    guarantee this test exists for is unchanged and still asserted: the 32,000 retry
    streams. What moved is the first call beside it, deliberately."""
    b = _backend([("max_tokens", ["thinking"], ""), ("end_turn", ["text"], "ok")])
    b.propose("sys", "user", 8000)
    assert [(s, st) for _k, s, st in b._client.calls] == [(8000, True), (32_000, True)]


def test_capping_below_the_ceiling_is_not_what_fixes_this():
    """A cap fixes the instance. Streaming fixes the property: a retry must survive a
    ceiling this code does not control and cannot see."""
    b = _backend([("max_tokens", ["thinking"], ""), ("end_turn", ["text"], "ok")])
    b.propose("sys", "user", 8000)
    _kind, size, streamed = b._client.calls[1]
    assert streamed, "the retry must be streamed, not shrunk under the ceiling"
    assert size == min(8000 * _AnthropicBackend._THINKING_RETRY_FACTOR,
                       _AnthropicBackend._THINKING_RETRY_CEILING), (
        "the retry budget was reduced to dodge the ceiling instead of streaming past it")


# -- 2. the truncation fix must survive ------------------------------------------

def test_the_streamed_retry_still_records_its_stop_reason():
    """Regression guard for the truncation P1: a reply that ends for a reason must say
    so, or a truncated plan is indistinguishable from a finished engagement."""
    b = _backend([("max_tokens", ["thinking"], ""), ("max_tokens", ["text"], "part")])
    b.propose("sys", "user", 8000)
    assert b.last_stop_reason == "max_tokens", (
        f"the streamed path dropped the stop reason: {b.last_stop_reason!r}")
    assert b.last_block_kinds == ["text"]


def test_the_streamed_retry_still_records_its_usage():
    """Spend is metered off the same object. A streamed reply that reports no usage
    would silently understate the cost of every retry."""
    b = _backend([("max_tokens", ["thinking"], ""), ("end_turn", ["text"], "ok")])
    b.propose("sys", "user", 8000)
    assert b.last_usage.get("input") == 100 and b.last_usage.get("output") == 10


def test_the_openai_backend_still_records_finish_reason():
    """The other half of the same guard. Whatever changes on the Anthropic path, the
    provider-agnostic contract is that SOME stop reason reaches the client."""
    from brukal.llm import _OpenAICompatBackend
    b = _OpenAICompatBackend.__new__(_OpenAICompatBackend)
    b.model = "m"
    b._post = lambda body: {
        "choices": [{"finish_reason": "length", "message": {"content": "partial"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2}}
    assert b.propose("s", "u", 100) == "partial"
    assert b.last_stop_reason == "length"


# -- 3. redaction write site #3 must not be routed around -------------------------

_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJicnVrYWwtdGVzdC1zZXNzaW9uIn0."
        "s3cr3tS1gnatureThatMustNeverReachAProvider")


def test_the_streamed_retry_prompt_is_still_redacted():
    """`LLMClient.propose` redacts BEFORE handing the backend anything, so a new
    transport inside the backend inherits it — but only while the retry re-uses the
    text it was given. A retry that rebuilt the prompt would route around write site #3
    and post the session token to a provider, on the retry only, where nothing looks."""
    redact.clear()
    try:
        redact.register(_JWT)
        b = _backend([("max_tokens", ["thinking"], ""), ("end_turn", ["text"], "ok")])
        c = LLMClient.__new__(LLMClient)
        c.provider, c.model, c._backend, c.usage = "anthropic", "m", b, UsageMeter("m")
        c.propose("you are a strategist",
                  f"ALREADY TRIED:\n- curl -H 'Authorization: Bearer {_JWT}'")
        streamed = "\n".join(b._client.prompts)
        assert streamed, "precondition: the retry was streamed and its prompt captured"
        assert _JWT not in streamed, "the session token reached the provider on the retry"
        assert redact.placeholder_for(_JWT) in streamed
    finally:
        redact.clear()


# -- 6. boundary: what must not change --------------------------------------------

def test_an_ordinary_reply_is_unchanged_and_costs_one_call():
    b = _backend([("end_turn", ["text"], "fine")])
    assert b.propose("s", "u", 1000) == "fine"
    assert b._client.calls == [("create", 1000, False)], "a normal call must not stream"


def test_an_ordinary_sized_call_is_still_not_streamed():
    """THE BOUNDARY the amended rule still has to honour, restated at a size that is
    actually ordinary.

    Its predecessor asserted this at 8,000 and was right to: streaming was a property of
    the retry, and turning it on for every call to fix a case only the retry reaches would
    have been a change out of all proportion. `_STREAM_AT = 8_000` keeps that proportion —
    the strategist plans at 2,000 and the specialists below it ask for less, so the whole
    ordinary path is untouched, and the only callers at or above the threshold are the
    experiment proposal and a retry."""
    b = _backend([("max_tokens", ["thinking"], ""), ("end_turn", ["text"], "ok")])
    b.propose("s", "u", 2000)
    assert b._client.calls[0] == ("create", 2000, False)


def test_usage_is_recorded_on_a_STREAMED_FIRST_call_too():
    """Not assumed from the retry's test. Spend is metered off the returned message, and a
    first call that now streams must meter identically or the raised allowance would
    silently understate every engagement's cost."""
    b = _backend([("end_turn", ["text"], "ok")])
    b.propose("sys", "user", 8000)
    assert b._client.calls[0][2] is True, "precondition: this first call streamed"
    assert b.last_usage.get("input") == 100 and b.last_usage.get("output") == 10


def test_a_genuine_truncation_is_still_not_retried():
    """It answered and was cut off. Unchanged by this fix."""
    b = _backend([("max_tokens", ["text"], '[{"title": "partial')])
    assert b.propose("s", "u", 64).startswith("[{")
    assert len(b._client.calls) == 1


def test_a_reply_that_is_empty_for_another_reason_is_still_not_retried():
    b = _backend([("end_turn", ["text"], "")])
    assert b.propose("s", "u", 1000) == ""
    assert len(b._client.calls) == 1


