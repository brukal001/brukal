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
