# Design — Chrome-CDP + full-capture web hunting (curl AND CDP, proxy on both)

- **Date:** 2026-09-30
- **Milestone:** operator-directed follow-up to Brukal's first authorized live external run
  (PortSwigger Academy SQLi lab, 2026-09-30). Closes the four gaps that run exposed.
- **Status:** design approved in chat 2026-09-30; awaiting written-spec review before the
  writing-plans handoff.
- **Discipline:** BUILD + SELF-TEST ONLY. No live pentest, no cage rebuild, no push from this
  session. Every one of the five safety invariants (CLAUDE.md) holds unchanged. Keep the full
  suite green (2028 at session start) and add tests for all new code.

---

## 1. Problem

Brukal's first live run solved a PortSwigger Apprentice SQLi lab autonomously but exposed four
gaps (NEXT.md → "FOLLOW-UPS from the first live run"):

1. **Web hunting barely used the browser.** `CompositeWebCage` routes `get`/`request` to the raw
   HTTP cage (`DockerHttpWebCage`, curl-equivalent); the browser was used only for
   `navigate`/`screenshot` via `DockerChromeCage` (a one-shot `docker exec chromium --dump-dom`
   subprocess). There is **no live CDP session** — the `CDPClient` the `chrome.py` docstring
   describes was never built; only `FakeCDP` (test-only) exists, wired to `ChromeCage` in tests.
2. **No live traffic capture.** The in-cage egress proxy logs only allow/deny **decisions**; for
   HTTPS it sees only the `CONNECT` host (path/body TLS-opaque). `--capture HAR` only **ingests**
   an externally recorded HAR. Brukal never records the request/response bodies of the traffic it
   itself drives.
3. **Finding-capture gap.** The run *performed* the solving exploit but recorded **0 findings** —
   nothing recognised the `is-solved` banner or the released-vs-unreleased differential.
4. **Exploit-as-manual.** (Related; addressed indirectly — a captured-traffic confirmation turns a
   rendered exploit into a recorded finding regardless of how the strategist framed it.)

### Two facts that shape the design (verified in code, 2026-09-30)

- **The single web door already sees decrypted traffic.** `GovernedBrowser.run()` holds both the
  request (`action`) and the fully-decrypted response (`result.body` + `result.headers`) for *both*
  transports (curl-in-cage prints plaintext; a CDP fetch returns the body). Capturing full
  request/response therefore needs **no TLS interception of the real target** — `tls_verify` stays
  intact and no cert check is disabled.
- **The capture store already has a `response` field.** `capture.CapturedRequest.response` (redacted,
  truncated to 4000 chars) exists and `capture._record(..., response=)` accepts it. The door's
  `_self_capture` simply never feeds it — it stores only `resp_bytes` (a length). Part A is mostly
  "feed what the door already has," plus draining CDP `Network.*` for browser-issued traffic.

---

## 2. Goals / Non-goals

**Goals**
- **A. Capture.** Record full request + response (headers + bodies), redacted and bounded, for the
  whole hunt, for BOTH the raw-HTTP path and the CDP path, without weakening containment.
- **B. Path selection.** Keep `DockerHttpWebCage` for fast raw fetch AND drive real Chrome over a
  live CDP session when JS/interaction/a real-browser request is needed. A prover can DEMAND the
  browser and get captured traffic back.
- **C. Register the win.** A deterministic, LLM-free prover over captured traffic that records a
  CONFIRMED finding for: the PortSwigger `is-solved` banner, a boolean-SQLi response-body
  differential, or a reflected value executed unescaped.
- **D. Invariants.** All five hold, unchanged. Never hand an agent the cage/`CDPClient`. Ship as a
  tested milestone; suite stays green + new tests.

**Non-goals**
- No live validation this session (human-gated: needs per-session authorization + SP-B approve +
  a fresh lab).
- No cage rebuild/recreate and no push (human-gated per NEXT.md).
- No mitmproxy-style TLS interception of the real target; no disabling cert verification.
- No change to `check_web`, `gate.py`, `executor.py`, `scope.py`, `audit.py`, or `kali.py` decision
  logic. Capability semantics unchanged.

---

## 3. Decisions (locked with the operator, 2026-09-30)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Milestone scope | **Full CDP build** — real `CDPClient` + persistent proxied chromium + live `Network.*` capture + live interactive actions, plus door-level raw capture, path selection, and finding-registration. |
| D2 | Capture source | **A2 — CDP-event drain.** CDP cage accumulates `Network.*` pairs; the door drains them into the same store via `capture._record` (scope + redaction re-applied). Raw path keeps door-level capture. |
| D3 | Default state | **Everything always-on** (both capture and finding-registration). No env flag. |
| D4 | Path-selection API | **`via` field on `WebAction`** (`auto`\|`raw`\|`browser`). The gate ignores it. |
| D5 | Docker wiring | **Included** (Dockerfile/entrypoint/compose + documented bring-up). Rebuild/recreate + live run remain **human-gated**. |

---

## 4. Architecture

### 4.1 New module `brukal/cdp.py` — the real CDP transport
Dependency-free CDP-over-WebSocket client (stdlib only: `socket`, `ssl` not needed for the
loopback control channel, `base64`, `hashlib`, `json`, `struct`), consistent with the project's
zero-third-party-dependency safety-core discipline.

Responsibilities:
- **Discover the target.** `GET http://<host>:9222/json` → pick the page target's
  `webSocketDebuggerUrl`.
- **Handshake.** RFC 6455 client Upgrade (`Sec-WebSocket-Key` random 16-byte b64; verify
  `Sec-WebSocket-Accept == b64(sha1(key + GUID))`).
- **Framing.** Client→server frames are **masked** (RFC 6455 §5.3); handle text frames, ping/pong,
  close, and fragmentation. Fail closed on a malformed/oversized frame (drop + raise a bounded
  error the cage swallows).
- **`call(method, params) -> dict`.** Monotonic id; match the response by id; demux interleaved
  `Network.*` events into a capture buffer keyed by `requestId`.
- **Capture accumulator.** On `Network.responseReceived` + `Network.loadingFinished`, fetch the body
  with `Network.getResponseBody` and assemble a `{method,url,req_headers,req_body,status,
  resp_headers,resp_body}` pair. Exposed to the cage via `drain() -> list[pair]`.

Testing: an in-process loopback WebSocket server (a tiny `socketserver`) exercises handshake +
framing + call-matching; canned `Network.*` frames exercise the accumulator. No browser, no Docker.

### 4.2 `brukal/chrome.py` — cage changes
- `ChromeCage.__init__` optionally enables `Page`, `Network`, and `Runtime` on the transport.
- `ChromeCage.drain_capture() -> list[pair]` delegates to the transport's `drain()` (empty for a
  transport without one, e.g. a bare `FakeCDP` in an older test).
- Interactive actions (`click`/`fill`/`eval`/`request`/`intercept`) already map to CDP calls here;
  no behaviour change — they simply become reachable live once a real transport is wired.
- `FakeCDP` extended to emit canned `Network.requestWillBeSent` / `responseReceived` /
  return a `getResponseBody`, so `drain_capture()` is asserted deterministically.
- `DockerChromeCage` unchanged — it stays the **CDP-down fallback** for navigate/screenshot.

### 4.3 `brukal/web.py` — door + routing changes
- **`WebAction`** gains `via: str = "auto"`. `describe()` may note a non-auto engine (audit
  legibility) but the gate reads only the URL.
- **`parse_web_action`** accepts an optional leading `via:browser` / `via:raw` token.
- **`CompositeWebCage.run(action)`** honors `via`:
  - `via == "browser"` → route `get`/`request` (and interactive kinds) to the CDP render cage.
  - `via == "raw"` → route `get`/`request` to the HTTP cage.
  - `via == "auto"` (default) → today's routing (`get`/`request` → HTTP cage;
    `navigate`/`screenshot` → render cage).
  - Interactive kinds (`click`/`fill`/`eval`/`intercept`) → the CDP render cage (was an
    explanatory note). If the CDP cage is unavailable, `navigate`/`screenshot` fall back to
    `DockerChromeCage`; interactive kinds return the existing explanatory note (fail-closed, never
    an ungated request).
  - `set_tls_verify` still fans out to both halves.
- **`GovernedBrowser.run(action, agent)`** — unchanged gate/rate/cookie/TLS/audit flow, then:
  1. Door capture enriched: pass `response=result.body` (and `resp_headers=result.headers`) to
     `_self_capture` → `capture._record(..., response=..., resp_headers=...)` (raw path now stores
     the body it already returned). This adds an optional `resp_headers: dict` field to
     `CapturedRequest` and `_record`; `write_har` fills its currently-empty response-headers list
     from it, and the writer/reader round-trip test is extended to keep them in agreement.
  2. If `getattr(self._cage, "drain_capture", None)` exists, drain it and fold each pair into the
     store via `capture._record(...)` — **the same constructor**, so scope (`contains_host`) and
     redaction are re-applied to every browser-issued sub-request. Out-of-scope/static/malformed
     pairs are dropped exactly as HAR ingest drops them.
  3. Bounded by the existing `_SELF_CAPTURE_MAX` (raise from 25 with justification, or keep and
     document — see §7).

`check_web` is **not touched**.

### 4.4 New module `brukal/capture_confirm.py` — register the win
`confirm_from_capture(caps, findings, scope) -> int` (count recorded). LLM-free. Reads
`GovernedBrowser.captured()` (now carrying response bodies). Provers:
- **Lab-solved banner.** A response body matching the PortSwigger solved marker
  (`is-solved` / `Congratulations, you solved the lab` / status widget class) → CONFIRMED finding,
  category from the reached endpoint, HIGH.
- **Boolean-SQLi differential.** Two captured pairs to the same endpoint whose only difference is a
  truthy vs falsy injection and whose **response bodies diverge** in the result set (row count /
  length band / presence of released-vs-unreleased rows) → CONFIRMED. Requires a working control
  (a benign request that returned 200) — **positive-control law**: recorded only on a clean
  differential; a comparator that raises records nothing.
- **Reflected value executed.** A unique marker sent in a request that returns **unescaped** in an
  HTML/JS sink in the response body → CONFIRMED reflected-XSS candidate at minimum; escalated only
  on an execution signal, never on mere reflection.
- Every recorded finding carries the captured request/response as evidence and is deduped by the
  existing `Finding.signature()`; recording goes through `FindingStore.add`.

Wired into the confirm reflex (the `assist_confirm` / loop finding path) after a hunt round,
always-on. It never proposes or issues a request; it only reads what the gated door already
captured.

### 4.5 `docker/` — persistent proxied chromium (written; deploy human-gated)
- **Dockerfile.kali / entrypoint:** launch, in the background, as **`brukalop`** (a non-proxy uid):
  `chromium --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage
  --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0
  --proxy-server=http://127.0.0.1:<PROXY_PORT> --proxy-bypass-list="<-loopback>"`. No
  `--ignore-certificate-errors` — cert verification stays on; a tls_verify=false scope is the only
  thing that may relax it, handled on the Brukal side, not baked into the image.
- **Rationale (containment):** the `--proxy-server` flag *tells* chromium to use the proxy;
  **nftables is the enforcement.** Under SP-C slice-2 only the `brukalproxy` uid egresses;
  `brukalop` gets lo+DNS only, so even a chromium that tried a direct connection would be dropped —
  it **cannot reach the target except through the scope-enforcing in-cage proxy**, gated exactly
  like curl's. CDP control on `:9222` is loopback — but chromium's *default* behaviour is to bypass
  its configured proxy for loopback destinations, and that default is **not** harmless here: a
  malicious page loaded in the browser could run page-JS that reaches `127.0.0.1:9222` directly,
  bypassing the proxy entirely, and from there drive the devtools protocol itself — an SSRF-into-CDP
  path handing a hostile target control of the browser session. The launch **MUST** pass
  `--proxy-bypass-list="<-loopback>"` to remove that implicit bypass, so even a page's
  loopback-targeted request is routed through `127.0.0.1:<PROXY_PORT>`, whose egress guard denies
  loopback/private destinations outright, closing the hole.
- **compose:** publish `127.0.0.1:9222:9222` (host-loopback only) so Brukal on the host can drive
  CDP; the control channel is not target egress.
- **Bring-up recipe** documented alongside the existing domain-lab recipe in NEXT.md / a HANDOFF.

---

## 5. Data flow (per-need)

```
prover → WebAction(kind=get, via=browser, url)
      → GovernedBrowser.run
          → check_web  (re-reads URL; ALLOW/DENY; ignores `via`)
          → rate limit
          → CompositeWebCage.run  (via=browser → CDP render cage)
              → ChromeCage → CDPClient → in-cage chromium
                  (egress ONLY via in-cage proxy; scope-enforced on the wire)
          ← WebResult + drain_capture() pairs
      → door folds result + all in-scope drained pairs into capture store (_record: scope+redact)
      → capture_confirm reads store → records CONFIRMED findings (LLM-free, positive-control)
      → report
```

---

## 6. Invariant analysis (the five, each checked)

1. **No LLM inside the gate.** `check_web` unchanged; `via` never reaches it; capture and
   registration are deterministic and entirely post-gate.
2. **Fail-closed.** CDP endpoint down → fallback (navigate/screenshot) or explanatory note
   (interactive), never an ungated request. Malformed CDP frame → dropped. `_record` drops
   out-of-scope/static/malformed captured pairs.
3. **Never trust an agent's self-report.** Captured `Network.*` data is observation for the record
   only; it authorizes nothing. `_record` re-applies `scope.contains_host` to every drained pair.
   A hostile rendered page cannot reach `:9222` — `egress.py` blocks loopback/private IPs, so the
   renderer (proxy-gated) cannot connect to the cage's own debug port.
4. **One execution path.** Everything still flows through `GovernedBrowser.run`. Agents receive the
   `GovernedBrowser`, never the cage, `ChromeCage`, or `CDPClient`.
5. **Immutable scope, append-only audit.** Capture never widens scope. `web_decision` /
   `web_result` audit records are unchanged; the hash chain still verifies.

---

## 7. Risks / tradeoffs

- **Always-on registration shifts the recall baseline** (accepted, D3). It fires only when captured
  traffic with bodies exists; `run_experiments.py` runs on `FakeKali`/fake cages, so the four-metric
  benchmark should be unaffected. **Verification step:** run `python run_experiments.py` before and
  after and confirm the metrics are identical; if they move, gate the registration prover behind a
  flag after all and record the reversal here.
- **Publishing `:9222` to host loopback** is a control-plane exposure. Mitigated by loopback-only
  publish + isolated cage network + the egress guard blocking a page from reaching it. Flagged for
  the whole-branch review.
- **Hand-rolled WebSocket** is the largest new surface. Contained in `cdp.py`, stdlib-only, fully
  unit-tested (handshake, masking, fragmentation, malformed-frame fail-closed). No third-party dep.
- **Capture volume.** Draining every sub-resource can be large. Keep `_record`'s static-asset drop,
  the 4000-char response truncation, and a per-run cap (`_SELF_CAPTURE_MAX`); raise the cap only
  with a stated number and a memory bound.

---

## 8. Testing (all self-testable; no Docker, no browser, no network)

- **`cdp.py`:** handshake + client-mask framing + `call` id-matching against an in-process loopback
  WS server; ping/pong; fragmented text; malformed/oversized frame → fail-closed; `/json` target
  selection; `drain()` assembles pairs from canned `Network.*` frames.
- **`chrome.py`:** `ChromeCage.drain_capture()` via extended `FakeCDP`; existing ChromeCage action
  mapping regressions preserved.
- **`web.py`:** `via` routing (auto/raw/browser) in `CompositeWebCage`; capability unchanged and
  the gate re-reads the URL regardless of `via`; door capture stores response body/headers (raw);
  CDP drain folds pairs; an out-of-scope drained pair is dropped by `_record`; interactive-with-CDP
  works while interactive-without-CDP still returns the note.
- **`capture_confirm.py`:** positive (is-solved banner / SQLi body differential / reflected marker)
  + false-positive controls (no differential, escaped reflection, 404/404) + positive-control law
  (a comparator that raises records nothing) + dedup via `Finding.signature`.
- **docker config:** a shape/lint test — the launch argv contains `--proxy-server` and runs as a
  non-proxy uid, and contains no `--ignore-certificate-errors`; compose publishes `127.0.0.1:9222`.
- **whole suite:** `python -m pytest` green (2028 + additions); `run_experiments.py` metrics
  unchanged.

---

## 9. Out of scope / follow-ups
- Live validation (fresh PortSwigger lab, real CDP run, `Network.*` capture end-to-end) — separate,
  human-gated, needs SP-B approve + per-session authorization.
- Cage rebuild/recreate + push — human-gated.
- Exploit-agent "translate identified payload into a governed request" (NEXT.md gap 4) — partially
  addressed by registration; a full fix is its own milestone.
