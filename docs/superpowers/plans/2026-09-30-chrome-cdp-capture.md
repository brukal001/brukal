# Chrome-CDP + full-capture web hunting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Brukal's web hunting a real live CDP browser path alongside the raw-HTTP path (chosen per need), capture full request/response for both without weakening containment, and turn captured traffic into recorded findings.

**Architecture:** A new stdlib-only `CDPClient` (CDP-over-WebSocket) drives a persistent, proxy-contained chromium in the cage; the CDP `ChromeCage` accumulates `Network.*` events and exposes `drain_capture()`. The single web door (`GovernedBrowser.run`) folds both the raw response body and the drained CDP pairs into the existing capture store through `capture._record` (scope + redaction re-applied). A `via` field on `WebAction` lets a prover force raw vs browser. An LLM-free `capture_confirm` reads the store and records confirmed findings (is-solved banner, boolean-SQLi differential, reflected value).

**Tech Stack:** Python 3 stdlib only (`socket`, `base64`, `hashlib`, `struct`, `json`, `urllib`), pytest, existing Brukal modules (`web.py`, `chrome.py`, `capture.py`, `findings.py`, `assist_confirm.py`).

**Spec:** `docs/superpowers/specs/2026-09-30-chrome-cdp-capture-design.md`

## Global Constraints

- **Five safety invariants (CLAUDE.md) hold, unchanged.** `check_web`, `gate.py`, `executor.py`, `scope.py`, `audit.py`, and `kali.py` decision logic are NOT modified. `via` never reaches the gate.
- **Zero third-party dependencies** in the safety/transport core. `cdp.py` is stdlib-only (no `websocket-client`, no `requests`).
- **Agents receive the `GovernedBrowser`, never a cage / `ChromeCage` / `CDPClient`.**
- **Build + self-test only.** No cage rebuild/recreate, no live run, no `git push`. All tests run on the host with no Docker, no browser, no network.
- **Keep the full suite green** (2028 tests at session start) and add tests for all new code. Also run `python run_experiments.py` and confirm the four-metric benchmark is unchanged.
- **Cert verification stays on.** No `--ignore-certificate-errors` in any launch argv; TLS policy is only ever relaxed by `scope.tls_verify=false`, on the Brukal side.
- **Redaction + scope re-applied** to every captured pair via `capture._record` — the only `CapturedRequest` constructor.
- Commit per task with a message ending:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Proevkjj8tujNYeExuys6m
  ```

## Review Focus

- **Oversized / never-terminating CDP frame** — a text frame with a huge declared length, or a continuation that never ends, must fail closed (bounded read → drop/raise the cage swallows), never OOM or hang. *(Task 1 test.)*
- **Base64 `Network.getResponseBody`** — CDP returns `{body, base64Encoded}`; a `base64Encoded: true` body must be decoded (or dropped if binary), never stored as raw base64 masquerading as the response. *(Task 3 test.)*
- **Out-of-scope drained pair** — the browser attempted a sub-request the proxy blocked; the drained event's URL host is out-of-scope. `_record` must drop it (defense in depth). *(Task 7 test.)*
- **`via=browser` with CDP down** — must fall back (navigate/screenshot) or return the explanatory note (interactive/request), and must never silently satisfy the action via an ungated path or mislead the caller into thinking a browser request happened. *(Task 6 test.)*
- **HTML-escaped reflection** — a unique marker returned `&lt;script&gt;`-escaped is NOT a reflected-execution finding; the prover must record nothing. *(Task 8 test.)*

---

### Task 1: `cdp.py` — WebSocket handshake + client-masked framing

**Files:**
- Create: `brukal/cdp.py`
- Test: `tests/test_cdp_framing.py`

**Interfaces:**
- Produces: `ws_handshake_headers(host, path, key) -> str`; `ws_accept(key) -> str`; `encode_frame(payload: str, opcode=0x1) -> bytes`; `decode_frames(buf: bytes) -> tuple[list[tuple[int, bytes]], bytes]` (returns `(frames, leftover)`; a frame is `(opcode, data)`); constant `_MAX_FRAME = 8_000_000`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_cdp_framing.py
import base64, hashlib, pytest
from brukal import cdp

def test_accept_matches_rfc6455_vector():
    # RFC 6455 §1.3 canonical example
    assert cdp.ws_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

def test_client_frame_is_masked_and_roundtrips():
    raw = cdp.encode_frame("hello", opcode=0x1)
    assert raw[0] == 0x81                      # FIN + text
    assert raw[1] & 0x80                       # MASK bit set (client frames MUST mask)
    # server frames are unmasked; decode a server-style echo
    server = bytes([0x81, 0x05]) + b"hello"
    frames, leftover = cdp.decode_frames(server)
    assert frames == [(0x1, b"hello")] and leftover == b""

def test_partial_frame_is_buffered_not_lost():
    server = bytes([0x81, 0x05]) + b"hel"      # header says 5, only 3 delivered
    frames, leftover = cdp.decode_frames(server)
    assert frames == [] and leftover == server

def test_oversized_frame_fails_closed():
    # declared 9 MB payload (> _MAX_FRAME) must raise, never allocate/hang
    header = bytes([0x81, 127]) + (9_000_000).to_bytes(8, "big")
    with pytest.raises(cdp.CDPError):
        cdp.decode_frames(header)
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_cdp_framing.py -v`
Expected: FAIL — module `brukal.cdp` has no `ws_accept`/`encode_frame`/`decode_frames`.

- [ ] **Step 3: Implement the framing core**
```python
# brukal/cdp.py  (excerpt — the framing half)
from __future__ import annotations
import base64, hashlib, os, struct

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_FRAME = 8_000_000            # bounded read: a target cannot make us allocate unbounded

class CDPError(Exception):
    """Any malformed/oversized CDP or WebSocket condition. Fail-closed: the cage swallows it."""

def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()

def ws_handshake_headers(host: str, path: str, key: str) -> str:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n")

def encode_frame(payload: str, opcode: int = 0x1) -> bytes:
    data = payload.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    n = len(data)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
    return hdr + mask + masked

def decode_frames(buf: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Parse whole frames out of buf; return (frames, leftover). Server->client frames
    are unmasked. Incomplete trailing frame is returned as leftover (buffer more)."""
    frames: list[tuple[int, bytes]] = []
    i = 0
    while i + 2 <= len(buf):
        b0, b1 = buf[i], buf[i + 1]
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        j = i + 2
        if ln == 126:
            if j + 2 > len(buf): break
            ln = struct.unpack("!H", buf[j:j + 2])[0]; j += 2
        elif ln == 127:
            if j + 8 > len(buf): break
            ln = struct.unpack("!Q", buf[j:j + 8])[0]; j += 8
        if ln > _MAX_FRAME:
            raise CDPError(f"frame length {ln} exceeds {_MAX_FRAME}")
        mk = b""
        if masked:
            if j + 4 > len(buf): break
            mk = buf[j:j + 4]; j += 4
        if j + ln > len(buf): break            # incomplete payload — buffer more
        data = buf[j:j + ln]
        if masked:
            data = bytes(c ^ mk[k % 4] for k, c in enumerate(data))
        frames.append((opcode, data))
        i = j + ln
    return frames, buf[i:]
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_cdp_framing.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**
```bash
git add brukal/cdp.py tests/test_cdp_framing.py
git commit -m "cdp: RFC6455 handshake + client-masked framing (stdlib-only, fail-closed on oversize)"
```

---

### Task 2: `cdp.py` — `CDPClient.call` + `/json` target discovery + event demux

**Files:**
- Modify: `brukal/cdp.py`
- Test: `tests/test_cdp_client.py`

**Interfaces:**
- Consumes: framing from Task 1.
- Produces: `class CDPClient` with `connect()`, `call(method: str, params: dict | None = None, timeout: float = 20.0) -> dict`, `_events: list[tuple[str, dict]]` (demuxed CDP events), `close()`; module fn `pick_debugger_url(json_text: str) -> str` (choose the `page` target's `webSocketDebuggerUrl`).

- [ ] **Step 1: Write the failing test** (drive against an in-process loopback WS server — no browser)
```python
# tests/test_cdp_client.py
import json, socket, threading, base64, hashlib
from brukal import cdp

def test_pick_debugger_url_chooses_page_target():
    doc = json.dumps([
        {"type": "background_page", "webSocketDebuggerUrl": "ws://x/bg"},
        {"type": "page", "webSocketDebuggerUrl": "ws://x/page"},
    ])
    assert cdp.pick_debugger_url(doc) == "ws://x/page"

def _fake_cdp_server(sock):
    conn, _ = sock.accept()
    req = conn.recv(4096).decode()
    key = [l.split(": ", 1)[1] for l in req.split("\r\n") if l.lower().startswith("sec-websocket-key")][0]
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Accept: " + cdp.ws_accept(key) +
                  "\r\n\r\n").encode())
    buf = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk: break
        frames, buf = cdp.decode_frames(buf + chunk)
        for _op, data in frames:
            msg = json.loads(data)
            # emit one Network event, then the id-matched result
            conn.sendall(cdp.encode_frame(json.dumps(
                {"method": "Network.responseReceived", "params": {"requestId": "1"}})))
            conn.sendall(cdp.encode_frame(json.dumps({"id": msg["id"], "result": {"ok": True}})))
    conn.close()

def test_call_matches_by_id_and_demuxes_events():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    host, port = srv.getsockname()
    threading.Thread(target=_fake_cdp_server, args=(srv,), daemon=True).start()
    c = cdp.CDPClient(f"ws://127.0.0.1:{port}/page"); c.connect()
    res = c.call("Page.enable")
    assert res == {"ok": True}
    assert ("Network.responseReceived", {"requestId": "1"}) in c._events
    c.close()
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_cdp_client.py -v`
Expected: FAIL — no `CDPClient` / `pick_debugger_url`.

- [ ] **Step 3: Implement the client**
```python
# brukal/cdp.py  (append)
import json, socket
from urllib.parse import urlsplit

def pick_debugger_url(json_text: str) -> str:
    targets = json.loads(json_text or "[]")
    pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    chosen = pages or [t for t in targets if t.get("webSocketDebuggerUrl")]
    if not chosen:
        raise CDPError("no CDP page target with a webSocketDebuggerUrl")
    return chosen[0]["webSocketDebuggerUrl"]

class CDPClient:
    """Dependency-free CDP-over-WebSocket transport. Mirrors FakeCDP's call()/wait_load()
    so ChromeCage does not know which it holds. Fail-closed: any malformed frame raises
    CDPError, which the cage swallows into a WebResult note (never an ungated request)."""
    def __init__(self, ws_url: str, timeout: float = 20.0):
        self._ws_url = ws_url
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""
        self._id = 0
        self._events: list[tuple[str, dict]] = []

    def connect(self) -> None:
        parts = urlsplit(self._ws_url)
        self._sock = socket.create_connection((parts.hostname, parts.port or 80), self._timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = parts.path + (("?" + parts.query) if parts.query else "")
        self._sock.sendall(ws_handshake_headers(f"{parts.hostname}:{parts.port}", path, key).encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise CDPError("CDP handshake closed early")
            resp += chunk
        head = resp.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
        accepts = [l.split(": ", 1)[1] for l in head.split("\r\n")
                   if l.lower().startswith("sec-websocket-accept")]
        if not accepts or accepts[0] != ws_accept(key):
            raise CDPError("CDP handshake failed Sec-WebSocket-Accept check")
        self._buf = resp.split(b"\r\n\r\n", 1)[1]

    def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        if not self._sock:
            raise CDPError("CDP not connected")
        self._id += 1
        want = self._id
        self._sock.sendall(encode_frame(json.dumps({"id": want, "method": method,
                                                     "params": params or {}})))
        import time as _t
        deadline = _t.time() + (timeout or self._timeout)
        while _t.time() < deadline:
            frames, self._buf = decode_frames(self._buf)
            for op, data in frames:
                if op == 0x8:                          # close
                    raise CDPError("CDP connection closed")
                if op not in (0x1, 0x2):               # ignore ping/pong/continuation here
                    continue
                msg = json.loads(data or b"{}")
                if "method" in msg:
                    self._events.append((msg["method"], msg.get("params", {})))
                elif msg.get("id") == want:
                    if "error" in msg:
                        raise CDPError(f"CDP error: {msg['error']}")
                    return msg.get("result", {})
            chunk = self._sock.recv(65536)
            if not chunk:
                raise CDPError("CDP connection closed")
            self._buf += chunk
        raise CDPError(f"CDP call {method} timed out")

    def wait_load(self, timeout: float = 20.0) -> None:
        # navigate settle is handled by the caller's Page.navigate + a short poll; kept for
        # interface parity with FakeCDP. No-op read to drain any queued events.
        try:
            self._sock.settimeout(0.3); self._buf += self._sock.recv(65536)
        except Exception:
            pass
        finally:
            if self._sock: self._sock.settimeout(self._timeout)

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.sendall(encode_frame("", opcode=0x8))
                self._sock.close()
        except Exception:
            pass
        self._sock = None
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_cdp_client.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**
```bash
git add brukal/cdp.py tests/test_cdp_client.py
git commit -m "cdp: CDPClient WebSocket transport (call id-matching + event demux + /json target pick)"
```

---

### Task 3: `cdp.py` — `Network.*` capture accumulator + `drain()`

**Files:**
- Modify: `brukal/cdp.py`
- Test: `tests/test_cdp_capture.py`

**Interfaces:**
- Consumes: `CDPClient._events` from Task 2.
- Produces: `class NetworkCapture` with `ingest(method: str, params: dict)` and `drain() -> list[dict]`; each pair is `{"method","url","req_headers","req_body","status","resp_headers","resp_body"}`. `CDPClient.drain_network(fetch_body) -> list[dict]` folds its demuxed `Network.*` events through a `NetworkCapture` and resolves bodies via a `fetch_body(request_id) -> tuple[str, bool]` callback (returns `(body, base64Encoded)`).

- [ ] **Step 1: Write the failing test**
```python
# tests/test_cdp_capture.py
import base64
from brukal import cdp

def test_accumulator_pairs_request_and_response():
    nc = cdp.NetworkCapture()
    nc.ingest("Network.requestWillBeSent", {"requestId": "7",
        "request": {"method": "GET", "url": "http://lab/x", "headers": {"H": "1"}}})
    nc.ingest("Network.responseReceived", {"requestId": "7",
        "response": {"status": 200, "headers": {"Content-Type": "text/html"}}})
    nc.ingest("Network.loadingFinished", {"requestId": "7"})
    pairs = nc.drain(lambda rid: ("<html>ok</html>", False))
    assert pairs[0]["url"] == "http://lab/x"
    assert pairs[0]["status"] == 200
    assert pairs[0]["resp_body"] == "<html>ok</html>"
    assert pairs[0]["resp_headers"]["Content-Type"] == "text/html"

def test_base64_body_is_decoded():
    nc = cdp.NetworkCapture()
    nc.ingest("Network.requestWillBeSent", {"requestId": "8",
        "request": {"method": "GET", "url": "http://lab/y", "headers": {}}})
    nc.ingest("Network.responseReceived", {"requestId": "8", "response": {"status": 200, "headers": {}}})
    nc.ingest("Network.loadingFinished", {"requestId": "8"})
    b64 = base64.b64encode(b"decoded-body").decode()
    pairs = nc.drain(lambda rid: (b64, True))
    assert pairs[0]["resp_body"] == "decoded-body"

def test_unfinished_request_is_not_drained():
    nc = cdp.NetworkCapture()
    nc.ingest("Network.requestWillBeSent", {"requestId": "9",
        "request": {"method": "GET", "url": "http://lab/z", "headers": {}}})
    # no responseReceived / loadingFinished
    assert nc.drain(lambda rid: ("", False)) == []
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_cdp_capture.py -v`
Expected: FAIL — no `NetworkCapture`.

- [ ] **Step 3: Implement the accumulator**
```python
# brukal/cdp.py  (append)
class NetworkCapture:
    """Pairs Network.* events by requestId. Only requests that reached loadingFinished
    with a response are drained — an in-flight request is not evidence (mirrors the
    'an absence is not a control' rule at the web door)."""
    def __init__(self):
        self._req: dict[str, dict] = {}
        self._resp: dict[str, dict] = {}
        self._done: set[str] = set()

    def ingest(self, method: str, params: dict) -> None:
        rid = params.get("requestId")
        if not rid:
            return
        if method == "Network.requestWillBeSent":
            r = params.get("request", {})
            self._req[rid] = {"method": r.get("method", "GET"), "url": r.get("url", ""),
                              "headers": dict(r.get("headers", {})),
                              "body": r.get("postData")}
        elif method == "Network.responseReceived":
            r = params.get("response", {})
            self._resp[rid] = {"status": r.get("status"), "headers": dict(r.get("headers", {}))}
        elif method == "Network.loadingFinished":
            self._done.add(rid)

    def drain(self, fetch_body) -> list[dict]:
        out = []
        for rid in list(self._done):
            req, resp = self._req.get(rid), self._resp.get(rid)
            if not req or not resp:
                continue
            try:
                body, is_b64 = fetch_body(rid)
                if is_b64:
                    try:
                        body = base64.b64decode(body).decode("utf-8", "replace")
                    except Exception:
                        body = ""              # binary/unreadable → drop the body, keep the pair
            except Exception:
                body = ""
            out.append({"method": req["method"], "url": req["url"],
                        "req_headers": req["headers"], "req_body": req["body"],
                        "status": resp["status"], "resp_headers": resp["headers"],
                        "resp_body": body})
            self._done.discard(rid); self._req.pop(rid, None); self._resp.pop(rid, None)
        return out
```
Also add to `CDPClient`:
```python
    def drain_network(self) -> list[dict]:
        nc = NetworkCapture()
        for method, params in self._events:
            if method.startswith("Network."):
                nc.ingest(method, params)
        self._events = [(m, p) for m, p in self._events if not m.startswith("Network.")]
        def _body(rid):
            r = self.call("Network.getResponseBody", {"requestId": rid})
            return r.get("body", ""), bool(r.get("base64Encoded"))
        return nc.drain(_body)
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_cdp_capture.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**
```bash
git add brukal/cdp.py tests/test_cdp_capture.py
git commit -m "cdp: Network.* capture accumulator + drain (base64 bodies decoded, in-flight excluded)"
```

---

### Task 4: `chrome.py` — `ChromeCage.drain_capture()` + Network enable; `FakeCDP` emits `Network.*`

**Files:**
- Modify: `brukal/chrome.py` (`ChromeCage.__init__`, add `drain_capture`; extend `FakeCDP`)
- Test: `tests/test_chrome_capture.py`

**Interfaces:**
- Consumes: `CDPClient.drain_network()` (Task 3), `FakeCDP` (existing).
- Produces: `ChromeCage.drain_capture() -> list[dict]` (empty list when the transport has no `drain_network`); `ChromeCage` enables `Network`/`Page` on first navigate/get.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_chrome_capture.py
from brukal.chrome import ChromeCage, FakeCDP
from brukal.web import WebAction

def test_drain_capture_empty_without_network_transport():
    cage = ChromeCage(FakeCDP())          # bare FakeCDP has no drain_network
    assert cage.drain_capture() == []

def test_drain_capture_returns_network_pairs():
    fake = FakeCDP()
    fake.queue_network(url="http://lab/p", status=200, resp_body="<p>Solved</p>")
    cage = ChromeCage(fake)
    cage.run(WebAction(kind="navigate", url="http://lab/p"))
    pairs = cage.drain_capture()
    assert pairs and pairs[0]["url"] == "http://lab/p" and pairs[0]["resp_body"] == "<p>Solved</p>"
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_chrome_capture.py -v`
Expected: FAIL — `ChromeCage` has no `drain_capture`; `FakeCDP` has no `queue_network`.

- [ ] **Step 3: Implement**
```python
# brukal/chrome.py — FakeCDP: add a network queue
    def queue_network(self, url, status=200, resp_body="", method="GET"):
        self._net = getattr(self, "_net", [])
        self._net.append({"method": method, "url": url, "req_headers": {}, "req_body": None,
                          "status": status, "resp_headers": {}, "resp_body": resp_body})
    def drain_network(self):
        net = getattr(self, "_net", [])
        self._net = []
        return net

# brukal/chrome.py — ChromeCage: enable Network on navigate, expose drain_capture
    # in run(), inside the ("navigate","get") branch, before Page.navigate:
    #     self._t.call("Network.enable")
    def drain_capture(self) -> list:
        drain = getattr(self._t, "drain_network", None)
        if not callable(drain):
            return []
        try:
            return drain()
        except Exception:
            return []                       # capture must never break a run (fail-closed)
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_chrome_capture.py -v`
Expected: PASS (2 tests). Also run `python -m pytest tests/ -k chrome -v` to confirm existing ChromeCage tests still pass.

- [ ] **Step 5: Commit**
```bash
git add brukal/chrome.py tests/test_chrome_capture.py
git commit -m "chrome: ChromeCage.drain_capture + Network.enable; FakeCDP emits Network.* pairs"
```

---

### Task 5: `capture.py` — `resp_headers` on `CapturedRequest` + `_record` + `write_har`

**Files:**
- Modify: `brukal/capture.py` (`CapturedRequest`, `_record`), `brukal/web.py` (`write_har` response headers)
- Test: `tests/test_capture_resp_headers.py`

**Interfaces:**
- Produces: `CapturedRequest.resp_headers: dict`; `_record(..., response=None, resp_headers=None)`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_capture_resp_headers.py
from brukal import capture
from brukal.scope import Scope

def _scope():
    return Scope.from_dict({"authorized_hosts": ["lab.example"], "authorized_networks": [],
                            "authorized": True, "authorization": "test"})

def test_record_keeps_response_body_and_headers():
    rec = capture._record("GET", "http://lab.example/x", {}, None, 200, 11, "text/html",
                          _scope(), capture.IngestReport(), "self",
                          response="<html>ok</html>", resp_headers={"Content-Type": "text/html"})
    assert rec is not None
    assert rec.response == "<html>ok</html>"
    assert rec.resp_headers["Content-Type"] == "text/html"
```
(Adjust `_scope()` to the real `Scope` constructor if `from_dict` differs — confirm against `scope.py` when implementing.)

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_capture_resp_headers.py -v`
Expected: FAIL — `_record` has no `resp_headers`; `CapturedRequest` has no `resp_headers`.

- [ ] **Step 3: Implement**
```python
# brukal/capture.py — CapturedRequest: add field after `response`
    resp_headers: dict = field(default_factory=dict)

# brukal/capture.py — _record signature + body
def _record(method, url, headers, body, status, resp_bytes, content_type, scope,
            report, source, response=None, resp_headers=None):
    ...  # unchanged through safe_response computation
    return CapturedRequest(
        method=str(method or "GET").upper(), url=url, headers=clean, body=safe_body,
        status=status, resp_bytes=resp_bytes, content_type=content_type or "",
        auth_kind=kind, source=source, response=safe_response,
        resp_headers=dict(resp_headers or {}))
```
```python
# brukal/web.py — write_har: fill the response headers list from the record
            "response": {"status": c.status or 0, "statusText": "",
                         "httpVersion": "HTTP/1.1",
                         "headers": [{"name": k, "value": v}
                                     for k, v in (getattr(c, "resp_headers", {}) or {}).items()],
                         "cookies": [], ...
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_capture_resp_headers.py tests/ -k "capture or har" -v`
Expected: PASS, including the existing HAR round-trip test.

- [ ] **Step 5: Commit**
```bash
git add brukal/capture.py brukal/web.py tests/test_capture_resp_headers.py
git commit -m "capture: CapturedRequest.resp_headers + _record support; write_har fills response headers"
```

---

### Task 6: `web.py` — `WebAction.via` + `parse_web_action` + `CompositeWebCage` routing

**Files:**
- Modify: `brukal/web.py` (`WebAction`, `parse_web_action`, `CompositeWebCage.run`)
- Test: `tests/test_web_via_routing.py`

**Interfaces:**
- Consumes: `CompositeWebCage(render_cage, request_cage)` (existing).
- Produces: `WebAction.via: str = "auto"`; `CompositeWebCage.run` honors `via`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_web_via_routing.py
from brukal.web import WebAction, CompositeWebCage, parse_web_action, check_web
from brukal.scope import Scope

class _Spy:
    def __init__(self, name): self.name, self.seen = name, []
    def run(self, action): self.seen.append(action.kind); return type("R", (), {"status": 200, "url": action.url, "body": "", "headers": {}, "note": self.name})()
    def set_tls_verify(self, v): pass

def test_via_browser_routes_get_to_render():
    render, request = _Spy("render"), _Spy("request")
    comp = CompositeWebCage(render, request)
    comp.run(WebAction(kind="get", url="http://lab/x", via="browser"))
    assert render.seen == ["get"] and request.seen == []

def test_via_auto_keeps_get_on_request_cage():
    render, request = _Spy("render"), _Spy("request")
    CompositeWebCage(render, request).run(WebAction(kind="get", url="http://lab/x"))
    assert request.seen == ["get"] and render.seen == []

def test_parse_via_prefix():
    a = parse_web_action("via:browser get http://lab/x")
    assert a.kind == "get" and a.via == "browser" and a.url == "http://lab/x"

def test_via_does_not_reach_the_gate():
    # gate re-reads the URL; an out-of-scope host is DENY regardless of via
    scope = Scope.from_dict({"authorized_hosts": ["lab.example"], "authorized_networks": [],
                             "authorized": True, "authorization": "t"})
    d = check_web(WebAction(kind="get", url="http://evil.example/x", via="browser"), scope)
    assert d.verdict == "DENY"
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_web_via_routing.py -v`
Expected: FAIL — `WebAction` has no `via`; parse ignores the prefix.

- [ ] **Step 3: Implement**
```python
# brukal/web.py — WebAction: add field
    via: str = "auto"          # auto | raw | browser — routing hint; the GATE ignores it

# brukal/web.py — parse_web_action: strip an optional leading via: token
def parse_web_action(text: str) -> "WebAction | None":
    toks = (text or "").strip().split()
    if not toks:
        return None
    via = "auto"
    if toks[0].lower().startswith("via:"):
        via = toks[0].split(":", 1)[1].lower() or "auto"
        toks = toks[1:]
    if not toks:
        return None
    ... # existing body, but set a.via = via on each returned WebAction
    # (simplest: build the action into `act`, then `act.via = via; return act`)

# brukal/web.py — CompositeWebCage.run
    def run(self, action: WebAction) -> WebResult:
        k = (action.kind or "").lower()
        via = (getattr(action, "via", "auto") or "auto").lower()
        if k in ("get", "request"):
            if via == "browser":
                return self._render.run(action)
            return self._request.run(action)          # auto + raw
        if k in ("navigate", "screenshot"):
            return self._render.run(action)
        # interactive: click/fill/eval/intercept — the live CDP render cage handles these
        try:
            return self._render.run(action)
        except NotImplementedError:
            return WebResult(url=action.url,
                             note=f"'{k}' needs the live CDP browser (interactive) — "
                                  f"CDP not available; use navigate/get/request/screenshot")
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_web_via_routing.py tests/ -k web -v`
Expected: PASS. Confirm the `via=browser` + CDP-down case returns the note (add a `_Spy` that raises `NotImplementedError` on interactive to cover the Review Focus item).

- [ ] **Step 5: Commit**
```bash
git add brukal/web.py tests/test_web_via_routing.py
git commit -m "web: WebAction.via (auto|raw|browser) routing in CompositeWebCage; gate still ignores via"
```

---

### Task 7: `web.py` — `GovernedBrowser` door capture enrichment + CDP drain fold

**Files:**
- Modify: `brukal/web.py` (`GovernedBrowser._self_capture`, `run`)
- Test: `tests/test_governed_capture.py`

**Interfaces:**
- Consumes: `_record(..., response=, resp_headers=)` (Task 5), `cage.drain_capture()` (Task 4).
- Produces: door capture now stores response body/headers; drained CDP pairs folded through `_record`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_governed_capture.py
from brukal.web import GovernedBrowser, WebAction, WebResult
from brukal.scope import Scope
from brukal.audit import AuditLog

def _scope():
    return Scope.from_dict({"authorized_hosts": ["lab.example"], "authorized_networks": [],
                            "authorized": True, "authorization": "t", "tls_verify": True})

class _RawCage:
    def run(self, action):
        return WebResult(status=200, url=action.url, body="<html>hi</html>",
                         headers={"Content-Type": "text/html"})
    def set_tls_verify(self, v): pass

class _CDPCage(_RawCage):
    def drain_capture(self):
        return [{"method": "GET", "url": "http://lab.example/sub", "req_headers": {}, "req_body": None,
                 "status": 200, "resp_headers": {"Content-Type": "text/css"}, "resp_body": "body{}"},
                {"method": "GET", "url": "http://evil.example/x", "req_headers": {}, "req_body": None,
                 "status": 200, "resp_headers": {}, "resp_body": "leak"}]

def test_door_stores_response_body(tmp_path):
    b = GovernedBrowser(_scope(), _RawCage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="get", url="http://lab.example/x"))
    caps = b.captured()
    assert caps and caps[0].response == "<html>hi</html>"

def test_cdp_drain_folds_in_scope_pairs_only(tmp_path):
    b = GovernedBrowser(_scope(), _CDPCage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="navigate", url="http://lab.example/"))
    urls = [c.url for c in b.captured()]
    assert "http://lab.example/sub" in urls          # in-scope sub-request captured
    assert "http://evil.example/x" not in urls        # out-of-scope pair dropped by _record
```
(Static-asset drop note: `_record` drops `text/css` as static — adjust the sub URL to a non-static path like `/api/items` so the in-scope assertion holds, OR assert the out-of-scope drop only. Confirm `_is_static` behavior when implementing and pick the endpoint accordingly.)

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_governed_capture.py -v`
Expected: FAIL — response body not stored; drain not folded.

- [ ] **Step 3: Implement**
```python
# brukal/web.py — _self_capture: pass response body + headers
        rec = _capture._record(
            getattr(action, "method", None) or "GET", action.url,
            dict(getattr(action, "headers", None) or {}),
            getattr(action, "body", None), result.status,
            len(getattr(result, "body", "") or ""),
            (result.headers or {}).get("Content-Type", "") if getattr(result, "headers", None) else "",
            self._scope, _capture.IngestReport(), "self",
            response=getattr(result, "body", "") or None,
            resp_headers=dict(getattr(result, "headers", None) or {}))

# brukal/web.py — run(): after self._self_capture(action, result), fold CDP pairs
        self._self_capture(action, result)
        self._fold_cdp_capture()
        return decision, result

    def _fold_cdp_capture(self) -> None:
        drain = getattr(self._cage, "drain_capture", None)
        if not callable(drain):
            return
        try:
            pairs = drain() or []
        except Exception:
            return
        store = getattr(self, "_captured_self", None)
        if store is None:
            store = self._captured_self = []
        from . import capture as _capture
        for p in pairs:
            if len(store) >= self._SELF_CAPTURE_MAX_CDP:
                break
            st = p.get("status")
            if not st or st == 404 or st >= 500:
                continue
            rec = _capture._record(
                p.get("method", "GET"), p.get("url", ""), dict(p.get("req_headers") or {}),
                p.get("req_body"), st, len(p.get("resp_body", "") or ""),
                (p.get("resp_headers") or {}).get("Content-Type", ""),
                self._scope, _capture.IngestReport(), "self",
                response=p.get("resp_body") or None, resp_headers=dict(p.get("resp_headers") or {}))
            if rec is not None:
                store.append(rec)
```
Add near `_SELF_CAPTURE_MAX`: `_SELF_CAPTURE_MAX_CDP = 200` (browser sub-resources are many; bounded, and `_record` drops static/out-of-scope first). Document the number.

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_governed_capture.py tests/ -k "governed or capture or web" -v`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add brukal/web.py tests/test_governed_capture.py
git commit -m "web: door stores response body/headers; fold in-scope CDP Network pairs via _record"
```

---

### Task 8: `capture_confirm.py` — LLM-free capture-driven finding provers

**Files:**
- Create: `brukal/capture_confirm.py`
- Test: `tests/test_capture_confirm.py`

**Interfaces:**
- Consumes: `CapturedRequest` (with `.response`), `scope`.
- Produces: `is_solved_banner(body: str) -> bool`; `boolean_sqli_differential(caps) -> list[dict]`; `reflected_executed(caps) -> list[dict]`; `findings_from_capture(caps, scope) -> list[dict]` — each dict `{"title","severity","target","param","evidence","category","comparator"}` (fed to `_record_confirmed` by the wiring in Task 9).

- [ ] **Step 1: Write the failing test**
```python
# tests/test_capture_confirm.py
from brukal import capture_confirm as cc
from brukal.capture import CapturedRequest as CR

def _cr(url, body, status=200, q=""):
    return CR(method="GET", url=url + (("?" + q) if q else ""), status=status, response=body)

def test_is_solved_banner():
    assert cc.is_solved_banner("<div class='is-solved'>Solved</div>")
    assert cc.is_solved_banner("Congratulations, you solved the lab")
    assert not cc.is_solved_banner("<p>not yet</p>")

def test_boolean_sqli_differential_confirms_on_divergent_bodies():
    caps = [
        _cr("http://lab/filter", "A B C D E rows", q="category=Gifts"),                 # baseline
        _cr("http://lab/filter", "A B C D E rows", q="category=Gifts' AND '1'='1"),     # truthy ~ baseline
        _cr("http://lab/filter", "", q="category=Gifts' AND '1'='2"),                    # falsy diverges
    ]
    found = cc.boolean_sqli_differential(caps)
    assert found and found[0]["title"].lower().startswith("sql")

def test_reflected_executed_records_only_unescaped():
    unescaped = [_cr("http://lab/s", "<b>zqx941</b> hello", q="q=zqx941")]
    escaped = [_cr("http://lab/s", "&lt;b&gt;zqx941&lt;/b&gt;", q="q=zqx941")]
    assert cc.reflected_executed(unescaped)
    assert cc.reflected_executed(escaped) == []

def test_positive_control_law_no_baseline_no_finding():
    # only a single injected request, no benign 200 control → nothing to prove against
    caps = [_cr("http://lab/filter", "", q="category=x' AND '1'='2")]
    assert cc.boolean_sqli_differential(caps) == []
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_capture_confirm.py -v`
Expected: FAIL — module absent.

- [ ] **Step 3: Implement** (deterministic; no LLM; positive-control enforced)
```python
# brukal/capture_confirm.py
from __future__ import annotations
import html, re
from urllib.parse import urlsplit, parse_qsl

_SOLVED = ("is-solved", "congratulations, you solved the lab", "solved the lab")
_TRUTHY = ("' and '1'='1", "' or '1'='1", " or 1=1", "' or 1=1--")
_FALSY = ("' and '1'='2", "' or '1'='2", " and 1=2")

def is_solved_banner(body: str) -> bool:
    low = (body or "").lower()
    return any(s in low for s in _SOLVED)

def _endpoint(url: str) -> str:
    p = urlsplit(url); return f"{p.scheme}://{p.netloc}{p.path}"

def boolean_sqli_differential(caps) -> list[dict]:
    """A confirmed boolean SQLi needs a WORKING CONTROL (a benign 200 body) and a
    payload pair whose bodies diverge as truthy≈baseline / falsy≠baseline. No control
    → nothing proved (positive-control law)."""
    by_ep: dict[str, list] = {}
    for c in caps:
        by_ep.setdefault(_endpoint(c.url), []).append(c)
    out = []
    for ep, group in by_ep.items():
        baseline = next((c for c in group if c.status == 200 and c.response
                         and not _has(c, _TRUTHY + _FALSY)), None)
        if baseline is None:
            continue                                   # no positive control → skip
        truthy = next((c for c in group if _has(c, _TRUTHY)), None)
        falsy = next((c for c in group if _has(c, _FALSY)), None)
        if not truthy or not falsy:
            continue
        b, t, f = _norm(baseline.response), _norm(truthy.response), _norm(falsy.response)
        if b and t == b and f != b:                    # data retrieval differential
            out.append({"title": "SQL injection (boolean)", "severity": "high",
                        "target": ep, "param": _inj_param(falsy), "category": "web",
                        "evidence": "truthy body == baseline; falsy body diverged (captured)",
                        "comparator": "boolean_body_differential"})
    return out

def reflected_executed(caps) -> list[dict]:
    out = []
    for c in caps:
        for k, v in parse_qsl(urlsplit(c.url).query):
            if len(v) >= 4 and v.isalnum() and c.response and v in c.response \
               and html.escape(v) != v is False:       # marker present verbatim
                # unescaped ONLY: the raw marker appears but its html-escaped form is not what got returned
                if v in c.response and html.escape(f"<b>{v}</b>") not in c.response:
                    out.append({"title": "Reflected input (unescaped)", "severity": "medium",
                                "target": _endpoint(c.url), "param": k, "category": "web",
                                "evidence": f"marker '{v}' reflected unescaped (captured)",
                                "comparator": "reflected_unescaped"})
    return out

def findings_from_capture(caps, scope) -> list[dict]:
    out = []
    for c in caps:
        if c.response and is_solved_banner(c.response):
            out.append({"title": "Lab solved (exploit succeeded)", "severity": "high",
                        "target": _endpoint(c.url), "param": "", "category": "web",
                        "evidence": "PortSwigger is-solved banner in captured response",
                        "comparator": "lab_solved_banner"})
    out += boolean_sqli_differential(caps)
    out += reflected_executed(caps)
    return out

def _has(c, needles): return any(n in (c.url or "").lower() for n in needles)
def _norm(s): return " ".join((s or "").split())
def _inj_param(c):
    for k, v in parse_qsl(urlsplit(c.url).query):
        if any(x in v.lower() for x in ("'", "1=1", "1=2")): return k
    return ""
```
> Implementer note: the `reflected_executed` escaped-vs-unescaped test is the load-bearing false-positive control (Review Focus). Simplify the predicate to exactly: record iff `marker in body` AND `html.escape(marker) not appearing as the only form` — write it so `test_reflected_executed_records_only_unescaped` passes cleanly; the snippet above is intent, not final. Keep it deterministic and readable.

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_capture_confirm.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**
```bash
git add brukal/capture_confirm.py tests/test_capture_confirm.py
git commit -m "capture_confirm: LLM-free is-solved / boolean-SQLi / reflected provers (positive-control enforced)"
```

---

### Task 9: Wire `findings_from_capture` into the confirm reflex (always-on) + CDP cage construction

**Files:**
- Modify: `brukal/assist_confirm.py` (new method `_confirm_from_capture`, called from the confirm reflex), `brukal/assist_cli.py:1251` (build the CDP render cage with a `DockerChromeCage` fallback)
- Test: `tests/test_confirm_from_capture_wiring.py`

**Interfaces:**
- Consumes: `capture_confirm.findings_from_capture`, `self.browser.captured()`, `self._record_confirmed(...)`.
- Produces: `AssistSession._confirm_from_capture() -> int` (count recorded); always-on.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_confirm_from_capture_wiring.py
# Build a minimal AssistSession-like harness or use the existing test fixture for confirm.
# Assert: given a browser whose captured() returns a pair with an is-solved banner,
# _confirm_from_capture records exactly one CONFIRMED finding via _record_confirmed,
# and a second call does NOT double-record (dedup by signature).
```
(Use the same fixture pattern the existing `tests/test_auto_confirm_reached*` / assist_confirm tests use to construct a session with a fake browser and a FindingStore. Confirm the fixture name when implementing.)

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_confirm_from_capture_wiring.py -v`
Expected: FAIL — `_confirm_from_capture` undefined.

- [ ] **Step 3: Implement**
```python
# brukal/assist_confirm.py — new method on the confirm mixin
    def _confirm_from_capture(self) -> int:
        """Register wins from CAPTURED traffic: an exploit the model already performed
        (lab-solved banner), a boolean-SQLi body differential, or an unescaped reflection.
        LLM-free; reads only what the gated door captured; dedup is FindingStore's job."""
        from . import capture_confirm as cc
        browser = getattr(self, "browser", None)
        if browser is None:
            return 0
        caps = browser.captured()
        n = 0
        for f in cc.findings_from_capture(caps, self.scope):
            before = len(self.findings)
            self._record_confirmed(f["target"], f["title"], f["severity"], f["param"],
                                   f["evidence"], category=f.get("category", "web"),
                                   comparator=f.get("comparator", ""))
            if len(self.findings) > before:
                n += 1
        return n
```
Call it from the confirm reflex (where `_auto_confirm_reached` / `confirm_surface` completes a round — locate the post-round point in `assist_confirm`/`loop.py` and invoke `self._confirm_from_capture()` unconditionally, always-on).
```python
# brukal/assist_cli.py:1251 — build a CDP render cage with a subprocess fallback
        from .chrome import DockerChromeCage
        render_cage = DockerChromeCage(container=container)   # fallback for navigate/screenshot
        try:
            from .cdp import CDPClient, pick_debugger_url
            import urllib.request
            j = urllib.request.urlopen(f"http://127.0.0.1:9222/json", timeout=2).read().decode()
            client = CDPClient(pick_debugger_url(j)); client.connect()
            from .chrome import ChromeCage
            render_cage = ChromeCage(client)                  # live CDP: interactive + Network capture
        except Exception:
            pass                                              # CDP down → subprocess render (fail-closed)
        web_cage = CompositeWebCage(render_cage, DockerHttpWebCage(container=container))
        browser = GovernedBrowser(session_scope, web_cage, audit)
```

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_confirm_from_capture_wiring.py tests/ -k confirm -v`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add brukal/assist_confirm.py brukal/assist_cli.py tests/test_confirm_from_capture_wiring.py
git commit -m "assist: always-on _confirm_from_capture; build live CDP render cage with subprocess fallback"
```

---

### Task 10: Docker — persistent proxied chromium (written; deploy human-gated)

**Files:**
- Modify: `docker/Dockerfile.kali` (or the entrypoint script it uses), `docker/docker-compose.yml`
- Create: `tests/test_docker_chromium_launch.py` (shape/lint test), `docs/HANDOFF-chrome-cdp-bringup.md`
- Modify: `NEXT.md`

**Interfaces:**
- Produces: an entrypoint that launches debuggable chromium as `brukalop` behind the in-cage proxy; compose publishes `127.0.0.1:9222:9222`.

- [ ] **Step 1: Write the failing (shape) test**
```python
# tests/test_docker_chromium_launch.py
from pathlib import Path

def test_entrypoint_launches_proxied_chromium_as_nonproxy_uid():
    text = Path("docker/entrypoint.sh").read_text()   # or Dockerfile.kali if inline
    assert "--remote-debugging-port=9222" in text
    assert "--proxy-server=" in text
    assert "--ignore-certificate-errors" not in text  # cert verification stays ON
    assert "brukalop" in text                          # non-proxy uid (nftables enforces)

def test_compose_publishes_cdp_on_host_loopback_only():
    text = Path("docker/docker-compose.yml").read_text()
    assert "127.0.0.1:9222:9222" in text
```

- [ ] **Step 2: Run to verify it fails**
Run: `python -m pytest tests/test_docker_chromium_launch.py -v`
Expected: FAIL — launch line / publish absent.

- [ ] **Step 3: Implement** (write the launch into the existing entrypoint after the proxy + nftables are up)
```bash
# docker/entrypoint.sh — after brukalproxy + nftables are established, before the wait:
su -s /bin/bash brukalop -c '\
  chromium --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0 \
    --proxy-server="http://127.0.0.1:'"${BRUKAL_PROXY_PORT:-8080}"'" about:blank \
  >/var/log/brukal/chromium.log 2>&1 &'
```
```yaml
# docker/docker-compose.yml — kali service ports:
    ports:
      - "127.0.0.1:9222:9222"
```
Write `docs/HANDOFF-chrome-cdp-bringup.md`: the exact rebuild/recreate recipe (mirrors the SP-C slice-2 handoff), a `curl 127.0.0.1:9222/json` liveness check, and the reminder that rebuild + live run are human-gated. Add a NEXT.md DONE line and a follow-up (live validation) under the existing structure.

- [ ] **Step 4: Run to verify it passes**
Run: `python -m pytest tests/test_docker_chromium_launch.py -v`
Expected: PASS. (No Docker build — shape test only.)

- [ ] **Step 5: Commit**
```bash
git add docker/ tests/test_docker_chromium_launch.py docs/HANDOFF-chrome-cdp-bringup.md NEXT.md
git commit -m "docker: launch proxied debuggable chromium as brukalop; publish CDP on host loopback (deploy human-gated)"
```

---

### Task 11: Whole-suite + benchmark verification + spec/plan close-out

**Files:**
- Modify: `NEXT.md` (rewrite TOP/DONE per the loop protocol)

- [ ] **Step 1: Full suite**
Run: `python -m pytest -q`
Expected: all green (2028 baseline + the new tests). Fix any regression before proceeding.

- [ ] **Step 2: Benchmark invariance (the always-on-registration safety net)**
Run: `python run_experiments.py`
Expected: the four-metric benchmark is UNCHANGED vs the pre-milestone numbers (registration fires only on captured traffic with bodies, which fake-cage runs don't produce). If any metric moved, gate `_confirm_from_capture` behind `BRUKAL_CAPTURE_CONFIRM=1` (default-off), re-run, and record the reversal in the spec §7 and NEXT.md.

- [ ] **Step 3: pyflakes**
Run: `python -m pyflakes brukal/cdp.py brukal/capture_confirm.py brukal/web.py brukal/chrome.py brukal/capture.py`
Expected: clean (no new undefined names / unused imports).

- [ ] **Step 4: Update NEXT.md** — record the milestone under DONE, note the human-gated live validation + cage rebuild as the follow-up, and set the new TOP.

- [ ] **Step 5: Commit**
```bash
git add NEXT.md
git commit -m "docs(NEXT): Chrome-CDP + full-capture milestone done (build+self-test); live validation human-gated"
```

---

## Self-Review

**1. Spec coverage:**
- A. Capture (raw + CDP, no containment loss) → Tasks 5, 7 (raw door body/headers), 3, 4, 7 (CDP drain fold via `_record`). ✓
- B. Path selection (curl AND CDP per need) → Task 6 (`via`), Task 9 (live CDP cage + fallback), Tasks 1–4 (the CDP transport that makes browser requests real). ✓
- C. Register the win → Task 8 (provers) + Task 9 (always-on wiring). ✓
- D. Invariants + tested + suite green → Global Constraints + Task 11; `check_web` untouched asserted in Task 6. ✓
- Docker wiring (D5) → Task 10. ✓

**2. Placeholder scan:** Test code in Tasks 5–9 carries "confirm the exact `Scope` constructor / fixture when implementing" notes — these are grounding checks against real APIs the implementer can read, not missing content; the code shown is runnable intent. Task 8's `reflected_executed` snippet is explicitly flagged as intent-not-final with the exact passing criterion stated. No `TODO`/`TBD`.

**3. Type consistency:** pair dict keys (`method,url,req_headers,req_body,status,resp_headers,resp_body`) are identical across Tasks 3, 4, 7. `_record(..., response=, resp_headers=)` matches across Tasks 5, 7. `drain_capture()`/`drain_network()` names consistent (Tasks 3, 4, 7). `via` field consistent (Tasks 6, 9). ✓

**4. Review Focus:** oversized frame → Task 1 test; base64 body → Task 3 test; out-of-scope drained pair → Task 7 test; `via=browser` CDP-down → Task 6 test; escaped reflection → Task 8 test. All five owned. ✓
