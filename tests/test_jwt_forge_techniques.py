"""
test_jwt_forge_techniques.py — the forge variants beyond weak-secret cracking.

Until now `confirm_jwt_forgery` gave up the moment a token's HMAC secret was not weak, so
every RS256 target (crAPI, and most real APIs) was a guaranteed miss. These are the
OFFLINE, deterministic building blocks of the two forge techniques that reach those
targets: the `none`-algorithm forge (crAPI challenge 15) and the RS256->HS256 confusion
forge, both pure-Python with no `cryptography` dependency.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import jwtscan


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _tok(alg: str, payload: dict, sig: bytes = b"sig") -> str:
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = _b64(json.dumps(payload).encode())
    return f"{h}.{p}.{_b64(sig)}"


# --------------------------------------------------------------------------- #
# alg:none forge
# --------------------------------------------------------------------------- #

def test_none_token_is_unsigned_and_alg_none():
    t = jwtscan.none_token({"alg": "RS256", "typ": "JWT"}, {"sub": "x", "role": "admin"})
    assert t.endswith("."), "the signature segment must be empty"
    header, payload, _si, sig = jwtscan.decode(t)
    assert header["alg"] == "none"
    assert payload["role"] == "admin"        # claims are carried, forgeable by the caller
    assert sig == b""


def test_alg_none_variant_preserves_claims():
    t = jwtscan.alg_none_variant(_tok("RS256", {"sub": "u@x", "role": "user"}))
    header, payload, _si, _sig = jwtscan.decode(t)
    assert header["alg"] == "none" and payload["sub"] == "u@x"


# --------------------------------------------------------------------------- #
# RS256 -> HS256 confusion forge
# --------------------------------------------------------------------------- #

def test_jwk_to_pems_returns_both_encodings():
    # A tiny but valid (n, e) — the encoding is what is under test, not the key size.
    jwk = {"n": _b64((0xC0FFEE1234567).to_bytes(7, "big")), "e": _b64((65537).to_bytes(3, "big"))}
    pems = jwtscan.jwk_to_pems(jwk)
    assert len(pems) == 2
    assert pems[0].startswith("-----BEGIN PUBLIC KEY-----")        # SPKI
    assert pems[1].startswith("-----BEGIN RSA PUBLIC KEY-----")    # PKCS#1
    assert all(p.endswith("-----\n") for p in pems)


def test_a_confusion_token_is_HS256_signed_with_the_public_key():
    pem = jwtscan.jwk_to_pems(
        {"n": _b64((0xABCDEF).to_bytes(3, "big")), "e": _b64((65537).to_bytes(3, "big"))})[0]
    rs = _tok("RS256", {"sub": "a@b", "role": "user"})
    forged = jwtscan.confusion_tokens(rs, [pem])
    assert len(forged) == 1
    used_pem, tok = forged[0]
    assert used_pem == pem
    header, payload, _si, _sig = jwtscan.decode(tok)
    assert header["alg"] == "HS256"                 # downgraded to symmetric
    # ...and the HMAC really uses the PEM as the secret (verifiable offline).
    assert jwtscan.crack_hmac_secret(tok, extra_secrets=(pem,)) == pem
    assert payload["exp"] > 0                        # a fresh, unexpired forgery


def test_confusion_is_refused_on_a_symmetric_token():
    # An HS256 token is already symmetric — there is nothing to confuse, and forging one
    # with the "public key" would be meaningless. Fail closed.
    assert jwtscan.confusion_tokens(_tok("HS256", {"sub": "a"}), ["-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n"]) == []


def test_a_garbage_jwk_yields_no_pems():
    assert jwtscan.jwk_to_pems({"n": "!!!notb64!!!", "e": "AQAB"}) == []
    assert jwtscan.jwk_to_pems({}) == []
