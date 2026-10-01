"""tests/test_cdp_client.py — Task 2: CDPClient WebSocket transport.

Drives against an in-process loopback WS server (no real browser). Exercises the
real RFC 6455 handshake (via Task 1's ws_accept) + framing (via Task 1's
encode_frame/decode_frames), then CDPClient's call() id-matching, event demux,
and /json target-picking.
"""
import json
import socket
import struct
import threading

import pytest

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
        if not chunk:
            break
        frames, buf = cdp.decode_frames(buf + chunk)
        for op, data in frames:
            if op != 0x1:      # ignore the client's close frame etc.
                continue
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


def _server_frame(data: bytes, opcode: int, fin: bool) -> bytes:
    """Build a raw, UNMASKED server->client frame with explicit FIN control.
    Task 1's encode_frame always sets FIN=1, so fragmentation tests need this
    separate low-level constructor (mirrors encode_frame's length-prefix logic,
    but server->client frames are legitimately unmasked per RFC 6455)."""
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(data)
    if n < 126:
        hdr = struct.pack("!BB", b0, n)
    elif n < 65536:
        hdr = struct.pack("!BBH", b0, 126, n)
    else:
        hdr = struct.pack("!BBQ", b0, 127, n)
    return hdr + data


def _fake_fragmenting_server(sock):
    conn, _ = sock.accept()
    req = conn.recv(4096).decode()
    key = [l.split(": ", 1)[1] for l in req.split("\r\n") if l.lower().startswith("sec-websocket-key")][0]
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Accept: " + cdp.ws_accept(key) +
                  "\r\n\r\n").encode())
    buf = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        frames, buf = cdp.decode_frames(buf + chunk)
        for op, data in frames:
            if op != 0x1:      # ignore the client's close frame etc.
                continue
            msg = json.loads(data)
            body = json.dumps({"id": msg["id"], "result": {"ok": True, "big": "x" * 5000}}).encode()
            mid = len(body) // 2
            # message split across an initial text frame (FIN=0) and a single
            # continuation frame (FIN=1) — the fragmentation case the brief requires
            conn.sendall(_server_frame(body[:mid], opcode=0x1, fin=False))
            conn.sendall(_server_frame(body[mid:], opcode=0x0, fin=True))
    conn.close()


def test_call_reassembles_fragmented_message():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    host, port = srv.getsockname()
    threading.Thread(target=_fake_fragmenting_server, args=(srv,), daemon=True).start()
    c = cdp.CDPClient(f"ws://127.0.0.1:{port}/page"); c.connect()
    res = c.call("Page.enable")
    assert res == {"ok": True, "big": "x" * 5000}
    c.close()


# ---------------------------------------------------------------------------
# Finding 2: the short connect() probe timeout must not leak into call()'s
# recv()s for the rest of the session.
# ---------------------------------------------------------------------------

def test_connect_timeout_does_not_leak_into_session_calls():
    # connect() is given a very short connect_timeout (a fail-fast probe); every
    # call() afterwards must use the normal, longer per-call timeout — not the
    # probe value the socket would otherwise be left with after create_connection.
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    host, port = srv.getsockname()
    threading.Thread(target=_fake_cdp_server, args=(srv,), daemon=True).start()
    c = cdp.CDPClient(f"ws://127.0.0.1:{port}/page", timeout=5.0, connect_timeout=0.05)
    c.connect()
    assert c._sock.gettimeout() == 5.0            # reset to the normal deadline, not 0.05s
    res = c.call("Page.enable")                    # would need > 0.05s of wall time on a slow box
    assert res == {"ok": True}
    c.close()


def test_session_client_constructed_like_prepare_session_keeps_normal_timeout():
    # mirrors _prepare_session's construction: timeout=20 governs every session
    # call(); connect_timeout=2 bounds only the initial probe/connect.
    c = cdp.CDPClient("ws://127.0.0.1:1/page", timeout=20, connect_timeout=2)
    assert c._timeout == 20
    assert c._connect_timeout == 2
    assert c._timeout != 2, "the 2s probe deadline must not become the session's call timeout"


# ---------------------------------------------------------------------------
# Finding 3: aggregate cap on fragmented-message reassembly (_frag_buf).
# ---------------------------------------------------------------------------

class _NullSocket:
    """Enough of a socket for CDPClient.call() when the frames to parse are
    already sitting in `_buf` — sendall() is the only method call() needs before
    its first decode_frames() pass finds them."""
    def sendall(self, data):
        pass


def test_fragment_reassembly_rejects_aggregate_over_cap(monkeypatch):
    # _MAX_FRAME bounds a single frame; this proves the AGGREGATE across
    # continuation frames is bounded too — a target fragmenting a large
    # Network.getResponseBody into many under-_MAX_FRAME pieces must still fail
    # closed, not grow _frag_buf without limit. Shrink the cap so the test is
    # fast and deterministic (mirrors test_oversized_frame_fails_closed's style,
    # applied at the reassembly layer instead of decode_frames).
    monkeypatch.setattr(cdp, "_MAX_MESSAGE", 20)
    c = cdp.CDPClient("ws://127.0.0.1:1/page")
    first = _server_frame(b"x" * 15, opcode=0x1, fin=False)   # initial frame, 15 <= cap
    second = _server_frame(b"y" * 15, opcode=0x0, fin=True)   # continuation -> 30 > 20
    c._buf = first + second
    c._sock = _NullSocket()
    with pytest.raises(cdp.CDPError):
        c.call("Page.enable")
