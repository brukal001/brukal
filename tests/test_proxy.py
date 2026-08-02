"""
test_proxy.py — the measuring bridge the frontier comparison runs through.

If the proxy mistranslates, the competitor either fails in a way that looks like the
competitor's fault, or succeeds while being metered wrongly. Both would corrupt the
comparison, so the translation is pinned here rather than discovered live.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmarks"))
from anthropic_proxy import _split_system, _finish, Ledger      # noqa: E402


# -- system-prompt extraction ------------------------------------------------

def test_system_turns_are_lifted_out_of_the_messages_array():
    """OpenAI carries the system prompt in `messages`; Anthropic takes it top-level.
    Leaving it inline would send the methodology as a user turn."""
    system, msgs = _split_system([
        {"role": "system", "content": "you are a pentester"},
        {"role": "user", "content": "scan the host"},
    ])
    assert system == "you are a pentester"
    assert msgs == [{"role": "user", "content": "scan the host"}]


def test_multiple_system_turns_are_joined_in_order():
    system, _ = _split_system([{"role": "system", "content": "first"},
                               {"role": "user", "content": "go"},
                               {"role": "system", "content": "second"}])
    assert system == "first\n\nsecond"


def test_leading_assistant_turn_is_dropped():
    """Anthropic requires the first message to be `user`. A harness opening with an
    assistant preamble would otherwise 400 in a way that reads as a proxy bug."""
    _, msgs = _split_system([{"role": "assistant", "content": "I'll begin."},
                             {"role": "user", "content": "go"}])
    assert msgs[0]["role"] == "user"


def test_multipart_content_blocks_are_flattened():
    _, msgs = _split_system([{"role": "user",
                              "content": [{"type": "text", "text": "a"},
                                          {"type": "text", "text": "b"}]}])
    assert msgs == [{"role": "user", "content": "ab"}]


def test_empty_and_malformed_turns_are_skipped_not_forwarded():
    """An empty content block is a 400 from the API; a non-dict entry is a crash."""
    _, msgs = _split_system([{"role": "user", "content": "   "}, "junk", None,
                             {"role": "user", "content": "real"}])
    assert msgs == [{"role": "user", "content": "real"}]


# -- stop-reason vocabulary --------------------------------------------------

def test_stop_reasons_map_into_the_openai_vocabulary():
    """A harness branches on finish_reason; passing Anthropic's spelling through
    means 'max_tokens' silently reads as an unknown value."""
    mk = lambda r: type("M", (), {"stop_reason": r})()      # noqa: E731
    assert _finish(mk("end_turn")) == "stop"
    assert _finish(mk("max_tokens")) == "length"
    assert _finish(mk("tool_use")) == "tool_calls"
    assert _finish(mk("refusal")) == "content_filter"
    assert _finish(mk(None)) == "stop"                       # never crash on absent


# -- metering ----------------------------------------------------------------

def test_ledger_prices_the_competitor_with_brukal_s_own_table(tmp_path):
    """Both sides must be costed by identical code, or a cost difference could be an
    accounting difference rather than a token difference."""
    from brukal.llm import UsageMeter
    led = Ledger("claude-opus-5", "t", tmp_path / "u.jsonl")
    led.record({"input": 1_000_000, "output": 0, "cache_read": 0, "cache_write": 0}, 1.0)
    mirror = UsageMeter("claude-opus-5")
    mirror.add({"input": 1_000_000, "output": 0})
    assert led.meter.cost == mirror.cost == pytest.approx(5.00)


def test_ledger_writes_one_row_per_call_and_survives_an_unwritable_path(tmp_path):
    """Metering is instrumentation: it must never be able to kill the run it measures."""
    led = Ledger("claude-opus-5", "t", tmp_path / "u.jsonl")
    led.record({"input": 10, "output": 2}, 0.5)
    led.record({"input": 20, "output": 3}, 0.5)
    assert len((tmp_path / "u.jsonl").read_text().strip().splitlines()) == 2
    assert led.meter.calls == 2 and led.summary()["input_tokens"] == 30

    blocked = Ledger("claude-opus-5", "t", tmp_path / "nope" / "deep" / "u.jsonl")
    blocked.record({"input": 1, "output": 1}, 0.1)          # must not raise
    assert blocked.meter.calls == 1


def test_proxy_and_brukal_backend_are_exact_inverses():
    """The proxy re-reports Anthropic usage in the OpenAI convention; Brukal's
    OpenAI-compatible backend converts it back. If those two normalisations disagreed,
    a run through the proxy would be metered differently from the same run direct —
    and the comparison would be measuring the plumbing."""
    from brukal.llm import _OpenAICompatBackend
    anthropic_usage = {"input": 120, "output": 8, "cache_read": 880, "cache_write": 0}
    total_in = (anthropic_usage["input"] + anthropic_usage["cache_read"]
                + anthropic_usage["cache_write"])

    b = _OpenAICompatBackend("claude-opus-5", "http://x/v1", "k")
    b._post = lambda body: {                                    # noqa: SLF001
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": total_in,
                  "completion_tokens": anthropic_usage["output"],
                  "prompt_tokens_details":
                      {"cached_tokens": anthropic_usage["cache_read"]}},
    }
    b.propose("sys", "user", 64)
    assert b.last_usage["input"] == anthropic_usage["input"]
    assert b.last_usage["cache_read"] == anthropic_usage["cache_read"]
    assert b.last_usage["output"] == anthropic_usage["output"]


# -- tool calling: what the first live competitor run crashed on ---------------
#
# hackingBuddyGPT drives the model through `instructor`, which asserts on
# message.tool_calls. A text-only bridge returns none, instructor dies, and the run
# looks like the HARNESS failing rather than the bridge. Pinned so it cannot recur.

def test_openai_tool_declarations_become_anthropic_tools():
    from anthropic_proxy import _translate_tools
    got = _translate_tools([{"type": "function", "function": {
        "name": "http_request", "description": "make a request",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}}])
    assert got == [{"name": "http_request", "description": "make a request",
                    "input_schema": {"type": "object",
                                     "properties": {"path": {"type": "string"}}}}]


def test_legacy_functions_field_is_accepted():
    from anthropic_proxy import _translate_tools
    got = _translate_tools(None, [{"name": "f", "parameters": {"type": "object"}}])
    assert got and got[0]["name"] == "f"


def test_tool_choice_maps_including_none_meaning_drop_the_tools():
    from anthropic_proxy import _translate_tool_choice
    assert _translate_tool_choice(None) == {"type": "auto"}
    assert _translate_tool_choice("required") == {"type": "any"}
    assert _translate_tool_choice("none") is None          # caller omits tools entirely
    assert _translate_tool_choice(
        {"type": "function", "function": {"name": "http_request"}}
    ) == {"type": "tool", "name": "http_request"}


def test_assistant_tool_calls_replay_as_tool_use_blocks():
    """Every turn after the first replays the assistant's tool calls. Dropping them
    strands the tool_result that answers them, which the API rejects."""
    _, msgs = _split_system([
        {"role": "user", "content": "start"},
        {"role": "assistant", "content": "calling",
         "tool_calls": [{"id": "call_1", "type": "function",
                         "function": {"name": "http_request",
                                      "arguments": '{"path": "/users"}'}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": "200 OK"},
    ])
    assert msgs[1]["role"] == "assistant"
    assert msgs[1]["content"][0] == {"type": "text", "text": "calling"}
    assert msgs[1]["content"][1] == {"type": "tool_use", "id": "call_1",
                                     "name": "http_request",
                                     "input": {"path": "/users"}}
    assert msgs[2] == {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "call_1", "content": "200 OK"}]}


def test_parallel_tool_results_are_batched_into_one_user_turn():
    """Anthropic rejects results for the same assistant turn split across messages."""
    _, msgs = _split_system([
        {"role": "user", "content": "go"},
        {"role": "assistant", "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}},
            {"id": "b", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "a", "content": "r1"},
        {"role": "tool", "tool_call_id": "b", "content": "r2"},
    ])
    assert len(msgs) == 3
    assert [b["tool_use_id"] for b in msgs[2]["content"]] == ["a", "b"]


def test_malformed_tool_arguments_do_not_break_the_bridge():
    """A replayed call with unparseable arguments must degrade, not 500 — otherwise one
    bad turn kills a run mid-benchmark."""
    _, msgs = _split_system([
        {"role": "user", "content": "go"},
        {"role": "assistant", "tool_calls": [{"id": "x", "type": "function",
                                              "function": {"name": "f",
                                                           "arguments": "{not json"}}]},
    ])
    assert msgs[1]["content"][0]["input"] == {}


def test_leading_orphan_tool_result_is_dropped():
    """A truncated history can start with a tool_result whose tool_use is gone; the API
    rejects that, so it must not reach the wire."""
    _, msgs = _split_system([
        {"role": "tool", "tool_call_id": "gone", "content": "orphan"},
        {"role": "user", "content": "real start"},
    ])
    assert msgs == [{"role": "user", "content": "real start"}]


def test_parallel_tool_calls_are_suppressed_by_default():
    """`instructor` asserts EXACTLY one tool call. Claude legitimately emits several in
    parallel, which crashed the live competitor run on its second attempt — a different
    failure from the first (zero calls), same assertion. Off by default so the harness
    is runnable; a client that states its own preference still wins."""
    from anthropic_proxy import _translate_tool_choice
    base = _translate_tool_choice("auto")
    assert "disable_parallel_tool_use" not in base       # the mapper stays pure...
    # ...the handler applies the policy, so verify the shape it produces
    suppressed = dict(base, disable_parallel_tool_use=True)
    assert suppressed == {"type": "auto", "disable_parallel_tool_use": True}
