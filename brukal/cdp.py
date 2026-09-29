"""brukal/cdp.py — Chrome DevTools Protocol over WebSocket, stdlib-only.

Task 1 (of 3): RFC 6455 WebSocket handshake helpers + client-masked frame
encoding / decoding. This is transport framing ONLY — no socket I/O, no CDP
session/client logic, no Network-domain capture. Those are Tasks 2 and 3.

Zero third-party dependencies: base64, hashlib, os, struct only.
"""
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
