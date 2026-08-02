"""
test_llm.py — PHASE 1: reliably hearing the model.

Covers the fragile model-I/O paths that made Brukal look brain-dead on thinking
models: <think> stripping, reasoning_content fallback, transient-error retries, and
salvage command extraction when the model didn't give a clean RUN: line.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from brukal.llm import _OpenAICompatBackend, _strip_think
from brukal.agents.strategist import StrategistAgent, _parse, _salvage_command


class _FakeResp:
    def __init__(self, payload: str):
        self._p = payload.encode()

    def read(self):
        return self._p

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _backend():
    return _OpenAICompatBackend("some-thinking-model", "http://x/v1", "k",
                                retries=3, backoff=0.0)


# -- <think> stripping -------------------------------------------------------

def test_strip_think_removes_reasoning_but_keeps_answer():
    t = "<think>\nlots of reasoning\n</think>\nPHASE: recon\nRUN: nmap -sV 10.10.10.5"
    assert _strip_think(t).startswith("PHASE: recon")
    assert "reasoning" not in _strip_think(t)


def test_strip_think_keeps_original_when_all_reasoning():
    # a reply that is ONLY a think block -> keep it (something beats nothing)
    assert _strip_think("<think>just thinking</think>") == "<think>just thinking</think>"


# -- reasoning_content fallback + think strip (the headline PHASE-1 case) -----

def test_thinking_response_still_yields_a_parseable_command(monkeypatch):
    # content is empty; the model put its answer (wrapped in <think>) in reasoning_content
    payload = json.dumps({
        "choices": [{"message": {
            "content": "",
            "reasoning_content": "<think>ssh+http open, scan services</think>\n"
                                 "PHASE: recon\nGOAL: enumerate\nRUN: nmap -sV 10.10.10.5",
        }}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    })
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _FakeResp(payload))

    text = _backend().propose("sys", "user", 800)
    assert "<think>" not in text and text.startswith("PHASE: recon")
    # and the strategist actually gets a command out of it
    assert _parse(text, "10.10.10.5").command == "nmap -sV 10.10.10.5"


# -- retries on transient errors ---------------------------------------------

def test_transient_urlopen_error_is_retried(monkeypatch):
    calls = {"n": 0}
    ok = json.dumps({"choices": [{"message": {"content": "RUN: nmap 10.10.10.5"}}]})

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:                       # fail twice, succeed on the third
            raise urllib.error.URLError("temporarily unreachable")
        return _FakeResp(ok)

    monkeypatch.setattr(urllib.request, "urlopen", flaky)
    text = _backend().propose("sys", "user", 500)
    assert calls["n"] == 3 and "nmap" in text     # retried and eventually succeeded


def test_client_error_is_not_retried(monkeypatch):
    calls = {"n": 0}

    def bad_key(*a, **k):
        calls["n"] += 1
        raise urllib.error.HTTPError("http://x/v1", 401, "Unauthorized", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", bad_key)
    with pytest.raises(RuntimeError):
        _backend().propose("sys", "user", 500)
    assert calls["n"] == 1                         # 4xx fails fast, no retry


# -- salvage extraction ------------------------------------------------------

def test_salvage_command_from_code_fence():
    reply = ("Here's what I'd run next:\n```bash\nnmap -sV -p 22,80 10.10.10.5\n```\n"
             "That should reveal the services.")
    assert _salvage_command(reply) == "nmap -sV -p 22,80 10.10.10.5"
    # end-to-end: _parse recovers it even with no RUN: line
    assert _parse(reply, "10.10.10.5").command == "nmap -sV -p 22,80 10.10.10.5"


def test_salvage_command_from_bare_shell_line():
    reply = "I think we should enumerate the web app.\ngobuster dir -u http://10.10.10.5/ -w list.txt"
    assert _salvage_command(reply) == "gobuster dir -u http://10.10.10.5/ -w list.txt"


def test_advice_only_reply_is_not_salvaged_into_a_command():
    s = _parse("Enumerate more before exploiting; we don't have enough yet.", "10.10.10.5")
    assert s.command is None and s.manual is None


# -- truncated-command repair (max_tokens cut a command mid-quote) ------------

def test_repair_balances_a_truncated_host_header_quote():
    from brukal.agents.strategist import _repair_command
    # the exact deepseek-chat failure: an unbalanced -H "Host: ... quote
    got = _repair_command('ffuf -u http://10.0.0.1/FUZZ -w list.txt -H "Host: nexus.htb')
    assert got == 'ffuf -u http://10.0.0.1/FUZZ -w list.txt -H "Host: nexus.htb"'
    import shlex
    shlex.split(got)                                   # now parseable
    # an already-clean command is returned unchanged
    assert _repair_command("nmap -sV 10.0.0.1") == "nmap -sV 10.0.0.1"
    assert _repair_command(None) is None and _repair_command("") == ""


def test_parse_repairs_a_truncated_command_so_it_is_runnable():
    reply = ('PHASE: enumeration\nGOAL: vhost dirs\n'
             'RUN: gobuster dir -u http://10.0.0.1/ -H "Host: nexus.htb')
    s = _parse(reply, "10.0.0.1")
    assert s.command == 'gobuster dir -u http://10.0.0.1/ -H "Host: nexus.htb"'
    import shlex
    shlex.split(s.command)                             # the gate's shlex will accept it


# -- spend metering: the numbers a cost cap and a benchmark both depend on ----
#
# Every bug pinned below only ever showed up against a live paid provider, which is
# exactly why they survived: the fake-cage suite never bills anything.

def test_every_current_frontier_model_has_a_price_on_file():
    """An unpriced model reports cost None, which used to disable the spend cap
    silently. The models most likely to be missing are the newest and dearest, so
    the price table is asserted rather than assumed."""
    from brukal.llm import _rate_for
    for model in ("claude-opus-5", "claude-sonnet-5", "claude-opus-4-8",
                  "claude-fable-5", "claude-haiku-4-5"):
        assert _rate_for(model) is not None, f"no price on file for {model}"


def test_anthropic_and_openai_cache_conventions_agree_on_billed_input():
    """The two providers report cached tokens the opposite way round. Both backends
    must hand the meter the same thing: tokens billed at the FULL rate."""
    from brukal.llm import UsageMeter
    # Anthropic: input_tokens EXCLUDES the 900 cached -> 100 billed full.
    anthropic = UsageMeter("claude-opus-5")
    anthropic.add({"input": 100, "output": 10, "cache_read": 900, "cache_write": 0})
    # OpenAI-compatible: prompt_tokens INCLUDES the 900 cached -> also 100 billed full.
    compat = UsageMeter("claude-opus-5")
    compat.add({"input": 1000 - 900, "output": 10, "cache_read": 900, "cache_write": 0})
    assert anthropic.input_tokens == compat.input_tokens == 100
    assert anthropic.cost == compat.cost
    assert anthropic.prompt_tokens == 1000        # what the context window saw


def test_openai_backend_subtracts_cached_tokens_from_the_total():
    """Regression: feeding prompt_tokens straight through double-counted the cached
    portion and overstated spend."""
    b = _backend()
    b._post = lambda body: {                      # noqa: SLF001 - test seam
        "choices": [{"message": {"content": "PHASE: recon"}}],
        "usage": {"prompt_tokens": 1000, "completion_tokens": 10,
                  "prompt_tokens_details": {"cached_tokens": 900}},
    }
    b.propose("sys", "user", 64)
    assert b.last_usage["input"] == 100 and b.last_usage["cache_read"] == 900


def test_cache_write_is_billed_above_the_full_rate_not_below():
    """A cache write costs ~1.25x, not 0.1x. Counting it as a read would understate
    the first turn of every engagement."""
    from brukal.llm import UsageMeter
    written = UsageMeter("claude-opus-5")
    written.add({"input": 0, "output": 0, "cache_read": 0, "cache_write": 1_000_000})
    plain = UsageMeter("claude-opus-5")
    plain.add({"input": 1_000_000, "output": 0})
    assert written.cost > plain.cost              # 1.25x input rate
    assert written.cost == pytest.approx(5.00 * 1.25)


def test_unpriced_model_with_a_spend_cap_fails_closed():
    """The headline bug: --max-cost against an unpriced model read as 'no cap'."""
    from brukal.budget import EngagementBudget
    b = EngagementBudget(max_cost=50.0).start()
    why = b.exceeded(cost=None, steps=1)
    assert why is not None and "cannot be enforced" in why
    # ...but an unmeasurable cost with NO cap set is fine — that's a local model.
    assert EngagementBudget(max_steps=10).start().exceeded(cost=None, steps=1) is None


def test_local_provider_reports_zero_spend_not_unknown_spend():
    """A local model is free BY CONSTRUCTION. Reporting None ('unknown') would trip the
    fail-closed cost check and refuse a run that genuinely cannot cost anything."""
    from brukal.llm import UsageMeter
    from brukal.budget import EngagementBudget
    local = UsageMeter("some-unlisted-local-model", free=True)
    local.add({"input": 500_000, "output": 100_000})
    assert local.cost == 0.0
    assert EngagementBudget(max_cost=1.0).start().exceeded(cost=local.cost) is None
    # ...whereas the same unlisted model on a PAID provider is unknown, and fails closed.
    paid = UsageMeter("some-unlisted-cloud-model", free=False)
    paid.add({"input": 500_000, "output": 100_000})
    assert paid.cost is None


# -- the Anthropic backend: the path the frontier comparison actually runs on ----
#
# Previously untested, because it needs a paid key. A fake client covers the request
# shape and the usage normalisation without spending anything.

class _FakeAnthropicMessages:
    def __init__(self, outer):
        self._outer = outer

    def create(self, **kw):
        self._outer.last_request = kw
        return type("Msg", (), {
            "content": [type("B", (), {"type": "text", "text": "PHASE: recon"})()],
            "usage": type("U", (), {"input_tokens": 100, "output_tokens": 10,
                                    "cache_read_input_tokens": 900,
                                    "cache_creation_input_tokens": 50})(),
        })()


class _FakeAnthropicClient:
    def __init__(self, *a, **kw):
        self.last_request = None
        self.messages = _FakeAnthropicMessages(self)


def _anthropic_backend(monkeypatch):
    import brukal.llm as llm_mod
    backend = llm_mod._AnthropicBackend.__new__(llm_mod._AnthropicBackend)
    backend._client = _FakeAnthropicClient()
    backend.model = "claude-opus-5"
    backend.last_usage = {}
    return backend


def test_anthropic_marks_the_system_prompt_cacheable(monkeypatch):
    """The system prompt is the stable prefix of every turn; leaving it unmarked
    re-bills it at the full rate on every call of a long hunt."""
    b = _anthropic_backend(monkeypatch)
    b.propose("frozen methodology", "what next?", 512)
    system = b._client.last_request["system"]
    assert isinstance(system, list) and system[0]["cache_control"] == {"type": "ephemeral"}
    assert system[0]["text"] == "frozen methodology"


def test_anthropic_usage_is_not_double_discounted(monkeypatch):
    """Anthropic's input_tokens ALREADY excludes cached tokens. Subtracting the cache
    read again (as the OpenAI-compatible path must) would understate spend."""
    b = _anthropic_backend(monkeypatch)
    b.propose("sys", "user", 512)
    assert b.last_usage == {"input": 100, "output": 10,
                            "cache_read": 900, "cache_write": 50}


def test_anthropic_empty_system_does_not_send_an_empty_cache_block(monkeypatch):
    """An empty cacheable block is below the minimum cacheable prefix and just noise."""
    b = _anthropic_backend(monkeypatch)
    b.propose("", "user", 512)
    assert b._client.last_request["system"] == ""
