"""
llm.py — the thin client the agents use to turn text into text.

The model does exactly one thing: take a system + user prompt and return text. It
has NO ability to execute anything — that is Wall 1 ("the agent emits only text"),
true by construction. Execution is done later by the gated executor, never here.

Two backends behind one `propose()` interface, so the rest of Brukal never cares
which model you use:

  * anthropic — Claude via the Anthropic SDK (needs `pip install "brukal[agents]"`
    and ANTHROPIC_API_KEY).
  * openai-compatible — ANY server that speaks the OpenAI chat API, over the
    standard library (no extra dependency): Ollama and LM Studio (free, local,
    no key), OpenAI, OpenRouter, Groq, Together, vLLM, ...

Pick with --provider / BRUKAL_PROVIDER. For a free local run:
    ollama pull qwen2.5
    brukal run <target> --provider ollama --model qwen2.5
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from . import redact

# Reasoning/thinking models wrap their private chain-of-thought in <think>...</think>
# (or leave the answer empty and put it in a separate `reasoning_content` field). We
# strip the think block and fall back to reasoning_content so the strategist parser
# always sees the real answer, whatever the provider does.
_THINK_RE = re.compile(r"<think\b[^>]*>.*?</think\s*>", re.I | re.S)
_LEAD_THINK_RE = re.compile(r"^\s*<think\b[^>]*>.*\Z", re.I | re.S)  # unclosed leading block


def _strip_think(text: str) -> str:
    """Remove <think>...</think> reasoning so only the model's actual answer remains.
    If stripping would empty the text (the whole reply was one think block), keep the
    original — something to parse beats nothing."""
    if not text or "<think" not in text.lower():
        return text or ""
    stripped = _THINK_RE.sub("", text)
    # an unclosed leading <think> (truncated reasoning) with no answer after it
    if "<think" in stripped.lower() and "</think" not in stripped.lower():
        stripped = _LEAD_THINK_RE.sub("", stripped)
    stripped = stripped.strip()
    return stripped or text.strip()


def _retryable(err) -> bool:
    """Transient network / server conditions worth retrying (not 4xx client errors)."""
    if isinstance(err, urllib.error.HTTPError):
        return err.code in (408, 409, 425, 429, 500, 502, 503, 504)
    return isinstance(err, (urllib.error.URLError, TimeoutError, ConnectionError))

# provider -> (base_url, api-key env var, default model). base_url None means the
# caller must supply --base-url (a generic OpenAI-compatible endpoint).
_PRESETS = {
    "openai":      ("https://api.openai.com/v1", "OPENAI_API_KEY", "gpt-4o-mini"),
    "ollama":      ("http://localhost:11434/v1", "OLLAMA_API_KEY", "llama3.1"),
    "lmstudio":    ("http://localhost:1234/v1", "LMSTUDIO_API_KEY", None),
    "openrouter":  ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY",
                    "z-ai/glm-4.6"),
    "groq":        ("https://api.groq.com/openai/v1", "GROQ_API_KEY",
                    "llama-3.1-8b-instant"),
    "zhipu":       ("https://api.z.ai/api/paas/v4", "ZHIPU_API_KEY", "glm-4.6"),
    "glm":         ("https://api.z.ai/api/paas/v4", "ZHIPU_API_KEY", "glm-4.6"),
    # NVIDIA NIM hosts third-party open weights behind an OpenAI-compatible API, so a
    # GLM/Llama/Nemotron id is reached with an `nvapi-...` key rather than the vendor's
    # own. Note the id is namespaced ("z-ai/glm-5.2"), not the bare vendor name.
    "nvidia":      ("https://integrate.api.nvidia.com/v1", "NVIDIA_API_KEY",
                    "z-ai/glm-5.2"),
    "deepseek":    ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "deepseek-chat"),
    "openai-compatible": (None, "OPENAI_API_KEY", None),
}
_ANTHROPIC_DEFAULT = "claude-sonnet-5"

# The stop reasons that mean "the model ran out of allowance", in both vocabularies:
# Anthropic says `max_tokens`, every OpenAI-compatible endpoint says `length`. A reply
# that ended this way is INCOMPLETE — a caller that could not parse what it needed out
# of one must retry rather than treat it as the model's answer.
TRUNCATED_STOP_REASONS = frozenset({"max_tokens", "length"})

# $ per 1M tokens (input, output). Substring-matched against the model id, longest
# key first, so "claude-opus-4-8" wins over a hypothetical "claude-opus". Models not
# listed here (local Ollama/LM Studio, or a provider we haven't priced) meter their
# tokens but report cost as unknown rather than guessing. Update as prices move.
#
# These are LIST prices. Promotional/introductory rates are deliberately NOT modelled:
# a discount has an expiry date, and a pricing table that silently flips on a hardcoded
# date is a time bomb. Quoting list means the number is an UPPER BOUND — the safe
# direction for a spend cap (you stop early, never late) and a defensible figure to
# publish in a benchmark.
_PRICING = {
    "claude-fable-5":    (10.00, 50.00),
    "claude-mythos-5":   (10.00, 50.00),
    "claude-opus-5":     (5.00, 25.00),
    "claude-opus-4-8":   (5.00, 25.00),
    "claude-opus-4-7":   (5.00, 25.00),
    "claude-opus-4-6":   (5.00, 25.00),
    "claude-sonnet-5":   (3.00, 15.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5":  (1.00, 5.00),
    # OpenAI-compatible clouds (approximate list prices; verify against your plan).
    # Substring match, so provider-prefixed ids like "deepseek/deepseek-chat" (via
    # OpenRouter) fall through to the bare key below automatically.
    "deepseek-reasoner": (0.55, 2.19),
    "deepseek-r1":       (0.55, 2.19),   # OpenRouter/other naming for the reasoner
    "deepseek-chat":     (0.27, 1.10),
    "deepseek":          (0.27, 1.10),   # fallback for any other deepseek-* id (approx)
    "glm-4.6":           (0.60, 2.20),
    "z-ai/glm-4.6":      (0.60, 2.20),
    "kimi-k2":           (0.60, 2.50),
    "gpt-4o-mini":       (0.15, 0.60),
    "gpt-4.1-mini":      (0.40, 1.60),
    "gpt-4o":            (2.50, 10.00),
    # Groq's hosted open models are free within the free tier -> priced at $0.
    "llama-3.1-8b-instant":     (0.0, 0.0),
    "llama-3.3-70b-versatile":  (0.0, 0.0),
    "openai/gpt-oss-120b":      (0.0, 0.0),
    "openai/gpt-oss-20b":       (0.0, 0.0),
}


# Providers that run on the operator's own hardware. Spend against these is $0 by
# construction, which is a DIFFERENT thing from "we have no price on file": one is a
# known-zero cost, the other is an unknown non-zero one. Collapsing the two is what let
# a spend cap silently evaporate on an unpriced cloud model, so they stay distinct.
_LOCAL_PROVIDERS = frozenset({"ollama", "lmstudio"})


def _rate_for(model: str):
    """(input, output) $/1M for a model id, or None if we have no price on file."""
    m = (model or "").lower()
    for key in sorted(_PRICING, key=len, reverse=True):
        if key in m:
            return _PRICING[key]
    return None


class UsageMeter:
    """Accumulates token usage across every propose() call and prices it. One meter
    per LLMClient, so `client.usage.summary()` is the per-hunt cost line.

    `input_tokens` here means tokens billed at the FULL input rate — cache reads and
    cache writes are counted separately because they bill differently (~0.1x and
    ~1.25x). Normalising to that meaning is each backend's job, because the two
    providers report it the opposite way round: Anthropic's `input_tokens` already
    EXCLUDES cached tokens, while an OpenAI-compatible `prompt_tokens` INCLUDES them.
    Getting that backwards silently understates spend on one provider and overstates
    it on the other, so the meter takes pre-normalised numbers and never guesses."""

    def __init__(self, model: str, free: bool = False):
        self.model = model
        self.free = free             # local provider: spend is $0, not merely unknown
        self.calls = 0
        self.input_tokens = 0        # billed at the full input rate
        self.output_tokens = 0
        self.cache_read_tokens = 0   # billed at ~0.1x input
        self.cache_write_tokens = 0  # billed at ~1.25x input (5-minute TTL)

    def add(self, usage: dict) -> None:
        if not usage:
            return
        self.calls += 1
        self.input_tokens += int(usage.get("input", 0) or 0)
        self.output_tokens += int(usage.get("output", 0) or 0)
        self.cache_read_tokens += int(usage.get("cache_read", 0) or 0)
        self.cache_write_tokens += int(usage.get("cache_write", 0) or 0)

    @property
    def prompt_tokens(self) -> int:
        """Every token sent, however it was billed — the number to compare against a
        context window, as opposed to the number to compare against a budget."""
        return self.input_tokens + self.cache_read_tokens + self.cache_write_tokens

    @property
    def cost(self):
        """USD spent so far. 0.0 for a local provider (free by construction), and None
        only when the spend is genuinely UNKNOWN — a paid provider whose model is not in
        the price table. A caller enforcing a cap must treat those two differently: 0.0
        can never breach a ceiling, None means the ceiling is unenforceable."""
        if self.free:
            return 0.0
        rate = _rate_for(self.model)
        if rate is None:
            return None
        in_rate, out_rate = rate
        return (self.input_tokens / 1e6) * in_rate \
            + (self.cache_read_tokens / 1e6) * in_rate * 0.1 \
            + (self.cache_write_tokens / 1e6) * in_rate * 1.25 \
            + (self.output_tokens / 1e6) * out_rate

    def as_dict(self) -> dict:
        """The machine-readable tally, for the run vault and the benchmark harness.
        Measured spend beats an estimate, so this is what a cost comparison cites."""
        return {
            "model": self.model,
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "prompt_tokens": self.prompt_tokens,
            "cost_usd": self.cost,
            "priced": self.free or _rate_for(self.model) is not None,
            "free": self.free,
        }

    def summary(self) -> str:
        toks = (f"{self.calls} call(s) · "
                f"{self.input_tokens:,} in / {self.output_tokens:,} out tokens")
        if self.cache_read_tokens or self.cache_write_tokens:
            toks += (f" (+{self.cache_read_tokens:,} cached read"
                     f", {self.cache_write_tokens:,} written)")
        cost = self.cost
        if cost is None:
            return f"{self.model}: {toks} · cost: n/a (no price on file — local/free?)"
        return f"{self.model}: {toks} · ~${cost:.4f}"


class _AnthropicBackend:
    def __init__(self, model: str, api_key: str | None):
        from anthropic import Anthropic   # lazy: core stays importable without the SDK
        self._client = Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model
        self.last_usage: dict = {}

    # How much bigger a second attempt gets when the first spent its whole allowance on
    # thinking, and the ceiling it may not pass. One retry, because a model that thinks
    # past twice the budget is not going to answer on a third try either.
    #
    # This ceiling is a COST bound and nothing else. It is deliberately ABOVE the SDK's
    # non-streaming limit (~21,333 for a model absent from `MODEL_NONSTREAMING_TOKENS`),
    # because the retry streams — see `propose`. Do not lower it to stay under that
    # limit: the limit is model- and estimator-dependent, so a number chosen to dodge it
    # fixes today's instance and silently rots when either moves.
    _THINKING_RETRY_FACTOR = 4
    _THINKING_RETRY_CEILING = 32_000

    def propose(self, system: str, user: str, max_tokens: int) -> str:
        """A reply, retried ONCE when the allowance was spent entirely on thinking.

        Adaptive thinking is billed against the same max_tokens as the answer, so a
        model that reasons at length can hit the ceiling before emitting a single text
        block — the call then succeeds, costs full price, and returns "". A live run
        recorded exactly that as "model returned no usable experiment (0 chars)", which
        looked like a model with nothing to say about the target. It had plenty to say;
        it never got to the part where it says it.

        Every caller is exposed to this, not just the experiment mechanism: the
        strategist plans through the same method, and an empty plan is indistinguishable
        from a finished engagement."""
        text = self._propose_once(system, user, max_tokens)
        if text or self.last_stop_reason != "max_tokens":
            return text
        if "text" in (self.last_block_kinds or []):
            return text                      # it answered and was cut off; not this case
        bigger = min(max_tokens * self._THINKING_RETRY_FACTOR,
                     self._THINKING_RETRY_CEILING)
        if bigger <= max_tokens:
            return text
        # STREAMED, and that is load-bearing. The SDK refuses a non-streaming request
        # whose max_tokens implies it could run past ten minutes — `ValueError: Streaming
        # is required...`, raised before anything is sent. `run_hypotheses` asks at 8,000,
        # so this retry is always 32,000, so on that path the retry could never succeed:
        # a live engagement lost model-proposed experiments entirely to it. The retry is
        # also the ONLY call that can cross the limit, so streaming it leaves every
        # ordinary call untouched.
        return self._propose_once(system, user, bigger, stream=True)

    # Requests at or above this size STREAM, decided by size on the client rather than by
    # a flag each caller has to remember. The SDK refuses a non-streaming request whose
    # max_tokens implies it could run past ten minutes, and that ceiling is model- and
    # estimator-dependent — so the safe rule is "large means streamed", not "this one
    # caller passes stream=True". Every caller inherits it, and no test double has to grow
    # a parameter it does not use.
    _STREAM_AT = 8_000

    def _streams_at(self, max_tokens: int) -> bool:
        return max_tokens >= self._STREAM_AT

    def _propose_once(self, system: str, user: str, max_tokens: int,
                      stream: bool = False) -> str:
        stream = stream or self._streams_at(max_tokens)
        # The system prompt is the stable prefix of every turn in an engagement — the
        # methodology, the schema, the rules — while only the user turn changes. Marking
        # it cacheable bills it at ~0.1x on every call after the first, which on a long
        # hunt is most of the input spend. Caching is a prefix match, so this is only
        # sound because the system prompt is frozen for the engagement's lifetime.
        system_blocks = [{"type": "text", "text": system,
                          "cache_control": {"type": "ephemeral"}}] if system else []
        request = dict(model=self.model, max_tokens=max_tokens,
                       system=system_blocks or system,
                       messages=[{"role": "user", "content": user}])
        # Same request either way — only the transport differs, so everything below
        # (usage, stop reason, block kinds, text) reads one shape and cannot drift
        # between the two paths.
        if stream:
            with self._client.messages.stream(**request) as streamed:
                msg = streamed.get_final_message()
        else:
            msg = self._client.messages.create(**request)
        u = getattr(msg, "usage", None)
        # Anthropic's `input_tokens` is the UNCACHED remainder — cache reads and writes
        # are reported separately and are NOT included in it. So it maps straight onto
        # the meter's "billed at full rate" with no subtraction. (The OpenAI-compatible
        # backend below has to subtract, because there the convention is inverted.)
        self.last_usage = {
            "input": getattr(u, "input_tokens", 0) or 0,
            "output": getattr(u, "output_tokens", 0) or 0,
            "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
            "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
        } if u is not None else {}
        # WHY a reply was empty, not merely that it was. "model returned no usable
        # experiment (0 chars)" appeared in a live coverage table and was undiagnosable:
        # an empty string is produced by a refusal, by a reply that spent its whole
        # allowance on thinking before emitting any text, and by a truncation, and those
        # need opposite responses. The stop reason and the block kinds distinguish them
        # and cost nothing to record.
        self.last_stop_reason = getattr(msg, "stop_reason", "") or ""
        self.last_block_kinds = [getattr(b, "type", "?") for b in (msg.content or [])]
        text = "".join(b.text for b in msg.content
                       if getattr(b, "type", None) == "text")
        return _strip_think(text)


class _OpenAICompatBackend:
    """Any OpenAI chat-completions endpoint, via urllib (no dependency)."""

    def __init__(self, model: str, base_url: str, api_key: str, timeout: int = 180,
                 retries: int = 3, backoff: float = 0.5):
        if not base_url:
            raise ValueError("no base_url — pass --base-url or BRUKAL_BASE_URL")
        if not model:
            raise ValueError("no model — pass --model or BRUKAL_MODEL")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = api_key or "not-needed"
        self.timeout = timeout
        self.retries = retries        # total attempts on transient failures
        self.backoff = backoff        # base seconds; exponential
        self.last_usage: dict = {}
        self.last_stop_reason: str = ""
        self.last_content_empty: bool = True

    def _post(self, body: bytes) -> dict:
        """POST once, retrying transient network/5xx/429 errors with backoff. A 4xx
        (bad key, bad request) fails fast — retrying won't help."""
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Accept": "application/json",
                     # A real User-Agent is required: some providers (Groq,
                     # OpenRouter) sit behind Cloudflare, which blocks the default
                     # "Python-urllib/x.y" signature with HTTP 403 (error 1010).
                     "User-Agent": "Brukal/1.0 (+https://github.com/sanjaygaire/brukal)",
                     "Authorization": f"Bearer {self.api_key}"})
        last = None
        for attempt in range(max(1, self.retries)):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                if _retryable(e) and attempt < self.retries - 1:
                    last = e; time.sleep(self.backoff * (2 ** attempt)); continue
                detail = e.read().decode(errors="replace")[:300]
                raise RuntimeError(f"{self.url} -> HTTP {e.code}: {detail}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < self.retries - 1:
                    last = e; time.sleep(self.backoff * (2 ** attempt)); continue
                reason = getattr(e, "reason", e)
                raise RuntimeError(f"cannot reach {self.url}: {reason}") from None
        # Loop exhausted without returning (shouldn't happen, but fail loud).
        raise RuntimeError(f"cannot reach {self.url}: {last}")

    @staticmethod
    def _message_text(message: dict) -> str:
        """The model's answer text. Falls back to reasoning_content when a thinking
        model leaves `content` empty and puts the answer in the reasoning field."""
        content = (message.get("content") or "").strip()
        if not content:
            content = (message.get("reasoning_content") or "").strip()
        return content

    def _propose_once(self, system: str, user: str, max_tokens: int) -> str:
        body = json.dumps({
            "model": self.model, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        data = self._post(body)
        u = data.get("usage") or {}
        # Inverted convention from Anthropic's: here `prompt_tokens` is the TOTAL and
        # `cached_tokens` is a subset of it, so the cached portion must be subtracted to
        # leave what is billed at the full rate. Feeding the raw total to the meter
        # would double-count the cached tokens and overstate spend.
        prompt = int(u.get("prompt_tokens", 0) or 0)
        cached = int((u.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0)
        cached = min(cached, prompt)          # a provider reporting nonsense can't go negative
        self.last_usage = {
            "input": prompt - cached,
            "output": int(u.get("completion_tokens", 0) or 0),
            "cache_read": cached,
            "cache_write": 0,                 # not separately billed/reported here
        }
        choice = (data.get("choices") or [{}])[0]
        # Same reason the Anthropic backend records it: WHY a reply ended decides what a
        # caller should do about it. `length` here is `max_tokens` there, and without it
        # a truncated plan is indistinguishable from a finished one on every non-Anthropic
        # provider.
        self.last_stop_reason = choice.get("finish_reason") or ""
        message = choice.get("message") or {}
        # Whether the ANSWER field (`content`) was empty — distinct from the reply TEXT,
        # which falls back to `reasoning_content`. A reasoning model can spend the whole
        # budget thinking and leave `content` empty while `reasoning_content` fills with a
        # truncated chain-of-thought; that reply LOOKS non-empty but never reached an answer.
        self.last_content_empty = not (message.get("content") or "").strip()
        return _strip_think(self._message_text(message))

    # The same COST bound as the Anthropic backend's, and for the same reason.
    _THINKING_RETRY_FACTOR = 4
    _THINKING_RETRY_CEILING = 32_000

    def propose(self, system: str, user: str, max_tokens: int) -> str:
        """A reply, retried ONCE when the allowance was spent entirely on reasoning.

        THE PORTABILITY DEFECT THIS CLOSES. The Anthropic backend has handled this since
        a live run lost its experiments to it; the OpenAI-compatible backend — the path
        EVERY open model uses (OpenRouter, DeepSeek, Groq, NVIDIA, Ollama, LM Studio) —
        never got it. A defect fixed at one provider and not the others is not fixed, and
        that is exactly what the portability tally exists to catch.

        MEASURED, 2026-09-19: `deepseek/deepseek-v4-flash` emits `reasoning` tokens billed
        against the same `max_tokens` as the answer. At the experiment path's hardcoded
        8000, **3 of 8 replies came back as 0 characters** — the call succeeded, cost full
        price, and returned nothing, which the run then recorded as "model returned no
        usable experiment (0 chars)". That reads as a model with nothing to say about the
        target. It had plenty to say; it never reached the part where it says it.

        Retried when the reply was CUT OFF (`finish_reason == "length"`) and produced no
        ANSWER content — either nothing at all, OR only reasoning that never reached the
        answer. The second case is `deepseek-v4-pro` (CR3, 2026-09-24): `content` empty,
        `reasoning_content` a truncated chain-of-thought, so the reply looks non-empty and
        the old empty-only check let it through as "cut off before it named an action",
        stalling the run. A truncated reply that DID produce answer content is left alone:
        `parse`/`_salvage` recover its complete objects, and retrying a usable partial would
        double the bill. An empty reply that simply ENDED (not `length`) is an answer, and
        retrying it would double the bill on every refusal."""
        text = self._propose_once(system, user, max_tokens)
        if self.last_stop_reason != "length" or not self.last_content_empty:
            return text
        bigger = min(max_tokens * self._THINKING_RETRY_FACTOR,
                     self._THINKING_RETRY_CEILING)
        if bigger <= max_tokens:
            return text
        return self._propose_once(system, user, bigger)


class LLMClient:
    """Provider-agnostic. Same propose() for Claude or any OpenAI-compatible model."""

    def __init__(self, model: str | None = None, api_key: str | None = None,
                 provider: str | None = None, base_url: str | None = None):
        self.provider = (provider or os.environ.get("BRUKAL_PROVIDER", "anthropic")).lower()
        env_model = os.environ.get("BRUKAL_MODEL")

        if self.provider == "anthropic":
            self.model = model or env_model or _ANTHROPIC_DEFAULT
            self._backend = _AnthropicBackend(self.model, api_key)
            self.usage = UsageMeter(self.model)
            return

        if self.provider not in _PRESETS:
            raise ValueError(
                f"unknown provider '{self.provider}'. Choose one of: "
                f"anthropic, {', '.join(_PRESETS)}.")
        preset_url, key_env, default_model = _PRESETS[self.provider]
        self.model = model or env_model or default_model
        url = base_url or os.environ.get("BRUKAL_BASE_URL") or preset_url
        key = api_key or os.environ.get(key_env) or os.environ.get("OPENAI_API_KEY", "")
        self._backend = _OpenAICompatBackend(self.model, url, key)
        self.usage = UsageMeter(self.model, free=self.provider in _LOCAL_PROVIDERS)

    def propose(self, system: str, user: str, max_tokens: int = 1024) -> str:
        # A prompt is a RECORD too — it is persisted by the provider and, in the 2B run,
        # was the widest surface of all (34 hits, every call, via the ALREADY TRIED and
        # RECENT ACTIVITY history blocks). The model has no use for the credential: the
        # real one is re-injected at execution by `_session_auth_for`, from the browser,
        # never from the model's reply. Redacting here covers every caller and every
        # backend at once. See redact.py.
        system, user = redact.text(system), redact.text(user)
        text = self._backend.propose(system, user, max_tokens)
        # Carried up from whichever backend answered, so callers can say WHY a reply was
        # unusable instead of only that it was.
        self.last_stop_reason = getattr(self._backend, "last_stop_reason", "")
        self.last_block_kinds = list(getattr(self._backend, "last_block_kinds", []))
        self.usage.add(getattr(self._backend, "last_usage", {}))
        return text
