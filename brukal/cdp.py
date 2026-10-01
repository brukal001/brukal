"""brukal/cdp.py — Chrome DevTools Protocol over WebSocket, stdlib-only.

Task 1 (of 3): RFC 6455 WebSocket handshake helpers + client-masked frame
encoding / decoding. This is transport framing ONLY — no socket I/O, no CDP
session/client logic, no Network-domain capture.

Task 2 (of 3): CDPClient — the WebSocket transport built on Task 1's framing:
connect() does the real handshake, call() sends an id-tagged CDP command and
blocks for its id-matched result while demuxing unsolicited CDP events into
_events, and pick_debugger_url() picks a page target out of a `/json` listing.
Task 3 (later) adds Network.* capture on top of this client.

Zero third-party dependencies: base64, hashlib, json, os, socket, struct,
time, urllib.parse only.
"""
from __future__ import annotations
import base64, hashlib, json, os, socket, struct, time
from urllib.parse import urlsplit

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_FRAME = 8_000_000            # bounded read: a target cannot make us allocate unbounded
# Aggregate cap on a REASSEMBLED (fragmented) message. _MAX_FRAME bounds a single frame;
# this bounds the sum of a message's continuation frames, so splitting a large
# Network.getResponseBody across many under-_MAX_FRAME frames cannot grow _frag_buf
# without limit (invariant 2: a target cannot make us allocate unbounded memory).
_MAX_MESSAGE = 4 * _MAX_FRAME


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


# ---------------------------------------------------------------------------
# Task 2: CDPClient transport + /json target discovery
# ---------------------------------------------------------------------------

def pick_debugger_url(json_text: str) -> str:
    """Pick a webSocketDebuggerUrl out of a Chrome `/json` target listing.
    Prefers a `page` target; falls back to any target that has a debugger URL.
    Fail-closed: raises CDPError if none is found or the JSON is malformed."""
    try:
        targets = json.loads(json_text or "[]")
    except ValueError as e:
        raise CDPError(f"malformed /json target listing: {e}") from e
    pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    chosen = pages or [t for t in targets if t.get("webSocketDebuggerUrl")]
    if not chosen:
        raise CDPError("no CDP page target with a webSocketDebuggerUrl")
    return chosen[0]["webSocketDebuggerUrl"]


class CDPClient:
    """Dependency-free CDP-over-WebSocket transport. Mirrors FakeCDP's call()/wait_load()
    so ChromeCage does not know which it holds. Fail-closed: any malformed frame raises
    CDPError, which the cage swallows into a WebResult note (never an ungated request).

    Fragmented-message reassembly: Chrome may split a large CDP message across an
    initial text frame (opcode 0x1, FIN=0) and one or more continuation frames
    (opcode 0x0), ending at a frame with FIN set. Task 1's decode_frames() returns
    (opcode, data) without exposing the FIN bit, so reassembly happens here: an
    opcode-0x1/0x2 frame starts a pending message buffer, each following opcode-0x0
    frame appends to it, and after every append we try json.loads() on the
    accumulated bytes — a ValueError means the message is still incomplete (keep
    buffering), success means it is a complete message (dispatch it, clear the
    buffer). A single unfragmented text frame is just the n=1 case of this loop, so
    the brief's plain single-frame behaviour keeps working unchanged.
    """

    def __init__(self, ws_url: str, timeout: float = 20.0, connect_timeout: float | None = None):
        self._ws_url = ws_url
        self._timeout = timeout               # per-call deadline for every session call()
        self._connect_timeout = connect_timeout   # short fail-fast probe deadline, connect() only
        self._sock: socket.socket | None = None
        self._buf = b""
        self._id = 0
        self._events: list[tuple[str, dict]] = []
        self._frag_buf: bytes | None = None   # pending (possibly incomplete) message bytes

    def connect(self) -> None:
        parts = urlsplit(self._ws_url)
        ct = self._connect_timeout if self._connect_timeout is not None else self._timeout
        self._sock = socket.create_connection((parts.hostname, parts.port or 80), ct)
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
        # The handshake connection may have used a short connect_timeout; reset the
        # socket's blocking timeout to the normal per-call deadline now that we're
        # connected, so the probe deadline never leaks into call()'s recv()s.
        self._sock.settimeout(self._timeout)

    def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        if not self._sock:
            raise CDPError("CDP not connected")
        self._id += 1
        want = self._id
        self._sock.sendall(encode_frame(json.dumps({"id": want, "method": method,
                                                     "params": params or {}})))
        deadline = time.time() + (timeout or self._timeout)
        while time.time() < deadline:
            frames, self._buf = decode_frames(self._buf)
            for op, data in frames:
                if op == 0x8:                          # close
                    raise CDPError("CDP connection closed")
                if op in (0x9, 0xA):                    # ping/pong — not a message
                    continue
                if op in (0x1, 0x2):                    # initial text/binary frame
                    self._frag_buf = data
                elif op == 0x0:                         # continuation frame
                    if self._frag_buf is None:
                        raise CDPError("CDP continuation frame with no initial frame")
                    if len(self._frag_buf) + len(data) > _MAX_MESSAGE:
                        self._frag_buf = None           # drop the partial buffer, fail closed
                        raise CDPError(
                            f"reassembled CDP message exceeds {_MAX_MESSAGE} bytes")
                    self._frag_buf += data
                else:
                    continue
                try:
                    msg = json.loads(self._frag_buf)
                except ValueError:
                    continue                            # message still incomplete — buffer more
                self._frag_buf = None
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

    def drain_network(self) -> list[dict]:
        """Fold demuxed Network.* events through a NetworkCapture and resolve each
        drained pair's response body via Network.getResponseBody. Consumed events are
        removed from self._events; non-Network events are left for the caller."""
        nc = NetworkCapture()
        for method, params in self._events:
            if method.startswith("Network."):
                nc.ingest(method, params)
        self._events = [(m, p) for m, p in self._events if not m.startswith("Network.")]

        def _body(rid):
            r = self.call("Network.getResponseBody", {"requestId": rid})
            return r.get("body", ""), bool(r.get("base64Encoded"))

        return nc.drain(_body)


# ---------------------------------------------------------------------------
# Task 3: Network.* capture accumulator + drain()
# ---------------------------------------------------------------------------

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
                        body = ""              # binary/unreadable — drop the body, keep the pair
            except Exception:
                body = ""
            out.append({"method": req["method"], "url": req["url"],
                        "req_headers": req["headers"], "req_body": req["body"],
                        "status": resp["status"], "resp_headers": resp["headers"],
                        "resp_body": body})
            self._done.discard(rid); self._req.pop(rid, None); self._resp.pop(rid, None)
        return out
