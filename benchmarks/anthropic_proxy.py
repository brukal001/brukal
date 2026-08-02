"""
anthropic_proxy.py — a measuring bridge, so the comparison is fair AND citable.

Comparing Brukal against another LLM-driven pentest tool has two practical problems,
and one localhost proxy solves both.

**Fairness.** A comparison where the tools run different models measures the models,
not the tools. That is why the earlier PentestGPT result was thrown away rather than
published. Brukal speaks the Anthropic API natively; hackingBuddyGPT speaks only the
OpenAI chat API, and Anthropic does not serve one. Without a bridge the two literally
cannot be pointed at the same brain.

**Citability.** A cost claim is worth nothing unless it cites metered tokens. Brukal
meters itself (`UsageMeter`); a third-party harness does not report anything we can
read. Sitting in the request path is the only place to count its tokens without
patching it.

So: an OpenAI-compatible `/v1/chat/completions` endpoint that translates to the
Anthropic Messages API, meters every call, and writes a JSONL ledger plus a summary.

    export ANTHROPIC_API_KEY=sk-ant-...
    python benchmarks/anthropic_proxy.py --model claude-opus-5 --label pgpt-vampi-1

    # then point the harness at it
    wintermute SimpleWebAPITesting --llm.api_url=http://localhost:87f/v1 \
        --llm.api_key=unused --llm.model=claude-opus-5 --host=http://localhost:5000

Two deliberate choices keep the comparison honest:

  * **Pricing is Brukal's own `_rate_for`.** Both sides are costed by identical code,
    so a cost difference is a token difference and never an accounting difference.
  * **The system prompt is marked cacheable, exactly as Brukal marks its own.** Giving
    Brukal a caching discount the competitor does not get would manufacture a win.

This is a benchmark instrument. It is not a general-purpose gateway: it binds to
localhost, holds no credentials of its own beyond the environment, and does not belong
in front of anything but a lab harness on the same machine.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from brukal.llm import UsageMeter, _rate_for      # noqa: E402  (path set above)

_MAX_BODY = 32 * 1024 * 1024        # a long agent transcript is big; a hang is not


class Ledger:
    """Per-call token records plus a running meter, shared across handler threads."""

    def __init__(self, model: str, label: str, path: Path):
        self.meter = UsageMeter(model)
        self.label = label
        self.path = path
        self.started = time.time()
        self._lock = threading.Lock()

    def record(self, usage: dict, latency: float) -> None:
        with self._lock:
            self.meter.add(usage)
            row = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "label": self.label,
                "model": self.meter.model,
                "latency_s": round(latency, 3),
                **usage,
                "cumulative_cost_usd": self.meter.cost,
            }
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row) + "\n")
            except OSError:
                pass                     # metering must never take down the run
            calls = self.meter.calls
        cost = self.meter.cost
        shown = "n/a" if cost is None else f"${cost:.4f}"
        print(f"  call {calls:>3} · {usage.get('input', 0):>7,} in / "
              f"{usage.get('output', 0):>5,} out · {latency:5.1f}s · {shown}",
              flush=True)

    def summary(self) -> dict:
        d = self.meter.as_dict()
        d.update({"label": self.label,
                  "wall_seconds": round(time.time() - self.started, 1)})
        return d


class _Handler(BaseHTTPRequestHandler):
    ledger: Ledger = None            # type: ignore[assignment]
    client = None
    model: str = ""
    max_tokens: int = 4096

    def log_message(self, *a):       # quiet: the ledger is the interesting output
        pass

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                # some harnesses probe /v1/models on startup
        if self.path.rstrip("/").endswith("/models"):
            self._send(200, {"object": "list", "data": [
                {"id": self.model, "object": "model", "owned_by": "anthropic"}]})
        else:
            self._send(404, {"error": {"message": "not found"}})

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": {"message": f"no route {self.path}"}})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > _MAX_BODY:
            self._send(400, {"error": {"message": "bad or oversized body"}})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError:
            self._send(400, {"error": {"message": "body is not JSON"}})
            return

        system, messages = _split_system(req.get("messages") or [])
        started = time.monotonic()
        try:
            msg = self.client.messages.create(
                model=self.model,
                max_tokens=int(req.get("max_tokens") or self.max_tokens),
                # Same caching lever Brukal gives itself — withholding it here would
                # hand Brukal a discount the competitor never had, and that is a
                # manufactured win rather than a measured one.
                system=([{"type": "text", "text": system,
                          "cache_control": {"type": "ephemeral"}}] if system else []),
                messages=messages or [{"role": "user", "content": "continue"}],
            )
        except Exception as e:                       # surface upstream errors verbatim
            self._send(502, {"error": {"message": f"{type(e).__name__}: {e}"}})
            return
        latency = time.monotonic() - started

        u = getattr(msg, "usage", None)
        usage = {
            # Anthropic's input_tokens already EXCLUDES cached tokens; see brukal/llm.py.
            "input": getattr(u, "input_tokens", 0) or 0,
            "output": getattr(u, "output_tokens", 0) or 0,
            "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
            "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0,
        } if u is not None else {}
        self.ledger.record(usage, latency)

        text = "".join(b.text for b in msg.content
                       if getattr(b, "type", None) == "text")
        total_in = usage.get("input", 0) + usage.get("cache_read", 0) \
            + usage.get("cache_write", 0)
        self._send(200, {
            "id": getattr(msg, "id", "chatcmpl-proxy"),
            "object": "chat.completion",
            "created": int(time.time()),
            "model": self.model,
            "choices": [{"index": 0, "finish_reason": _finish(msg),
                         "message": {"role": "assistant", "content": text}}],
            # Reported in the OpenAI convention the caller expects: prompt_tokens is
            # the TOTAL, with the cached portion nested underneath it.
            "usage": {"prompt_tokens": total_in,
                      "completion_tokens": usage.get("output", 0),
                      "total_tokens": total_in + usage.get("output", 0),
                      "prompt_tokens_details":
                          {"cached_tokens": usage.get("cache_read", 0)}},
        })


def _finish(msg) -> str:
    """Anthropic stop reasons in the vocabulary an OpenAI client parses."""
    return {"end_turn": "stop", "stop_sequence": "stop", "max_tokens": "length",
            "tool_use": "tool_calls", "refusal": "content_filter"} \
        .get(getattr(msg, "stop_reason", "") or "", "stop")


def _split_system(messages):
    """OpenAI puts the system prompt in the messages array; Anthropic takes it as a
    separate top-level field. Several system turns are joined in order, and the rest
    are passed through with roles normalised.

    A leading assistant turn is dropped: Anthropic requires the first message to be
    `user`, and a harness that opens with an assistant preamble would otherwise get a
    400 that looks like a proxy bug rather than a shape mismatch."""
    system_parts, out = [], []
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = (m.get("role") or "user").lower()
        content = m.get("content")
        if isinstance(content, list):        # OpenAI multi-part content blocks
            content = "".join(p.get("text", "") for p in content
                              if isinstance(p, dict))
        content = (content or "").strip()
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
        else:
            out.append({"role": "assistant" if role == "assistant" else "user",
                        "content": content})
    while out and out[0]["role"] == "assistant":
        out.pop(0)
    return "\n\n".join(system_parts), out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--model", default="claude-opus-5",
                    help="Anthropic model both sides of the comparison will run")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--label", default="run",
                    help="tag for this run in the ledger (e.g. pgpt-vampi-1)")
    ap.add_argument("--ledger", default="benchmarks/results/proxy_usage.jsonl")
    ap.add_argument("--max-tokens", type=int, default=4096)
    args = ap.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set — refusing to start.", file=sys.stderr)
        return 2
    if _rate_for(args.model) is None:
        # The whole point is a citable cost. Starting without a price would produce a
        # ledger of tokens and a dash where the number should be.
        print(f"no price on file for '{args.model}' — cost could not be reported.\n"
              f"Add it to _PRICING in brukal/llm.py, or pick a priced model.",
              file=sys.stderr)
        return 2
    try:
        from anthropic import Anthropic
    except ImportError:
        print("pip install anthropic", file=sys.stderr)
        return 2

    ledger_path = Path(args.ledger)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    _Handler.ledger = Ledger(args.model, args.label, ledger_path)
    _Handler.client = Anthropic()
    _Handler.model = args.model
    _Handler.max_tokens = args.max_tokens

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    in_rate, out_rate = _rate_for(args.model)
    print(f"measuring proxy on http://127.0.0.1:{args.port}/v1  ->  {args.model}"
          f"  (${in_rate}/${out_rate} per 1M)\n"
          f"  label:  {args.label}\n"
          f"  ledger: {ledger_path}\n"
          f"  point the harness at --llm.api_url=http://localhost:{args.port}/v1\n"
          f"  ctrl-c to stop and print the run total\n", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        summary = _Handler.ledger.summary()
        print(f"\n  {_Handler.ledger.meter.summary()}"
              f"  ·  {summary['wall_seconds']}s wall")
        out = ledger_path.with_suffix(".summary.jsonl")
        try:
            with out.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(summary) + "\n")
            print(f"  run total appended to {out}")
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
