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
