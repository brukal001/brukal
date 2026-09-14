"""
redact.py — the redaction boundary: session material never reaches a RECORD.

Found live on Juice Shop (docs/CASE_STUDY_JUICESHOP_2B.md): a real JWT session carried
by the governed browser appeared in cleartext on 5 of 6 artifact surfaces. Juice Shop's
JWT payload is the user row, so what leaked was an account id, an email, a role and a
password HASH — PII plus a credential to crack. An organisation will not run a tool that
writes its users' credentials to disk in cleartext, whatever else the tool guarantees.

WHERE THE FIX IS NOT
--------------------
NOT at the point of injection. `AssistSession._session_auth_for` appends the bearer
header (or cookie) to a shell command BEFORE the gate, and that must stay: the gate has
to judge the bytes that will really execute, and the cage has to run them (invariant 3).
Redacting there would make the gate rule on a command that never runs.

WHERE THE FIX IS
----------------
At every point of RECORD. The executor still runs the real bytes; the audit log, the
checkpoint, the model prompts, the findings and the blackboard all record the redacted
form. Each application site is a single funnel that every caller already routes through,
so a future writer inherits the boundary instead of having to remember it.

WHAT COUNTS AS A SECRET
-----------------------
Not a guess. There are TWO sources of truth, and neither is a pattern match.

1. **Credentials we INJECT.** The set this engagement actually used, registered by
   `_session_auth_for` at the moment it reads it off the GovernedBrowser.
2. **Credentials the TARGET DISCLOSES.** `observe()` below, and this half was missing.
   Run 2C4 captured a live admin JWT out of a response body and wrote it in cleartext
   across ten artifact files, because the registry only ever knew about (1). A
   credential nobody injected was, by construction, not a secret.

It masks the VALUE, never the structure: an audit line still reads

    nuclei -u http://host/x -H 'Authorization: Bearer [REDACTED:1f3a9c02]'

so the record stays meaningful and the gate's decision stays auditable.

DISCOVERY IS A DECODE, NOT A REGEX
----------------------------------
The rule above — no regex trusted to recognise a token — still holds, and `observe` is
not an exception to it. A JWT is SELF-DESCRIBING: it either splits into three base64url
segments whose first two decode to JSON objects, or it is not a JWT. That is a parse
with a yes/no answer, the same standard `jwtscan` already applies before analysing one,
so a value that merely *looks* tokenish is left strictly alone and an ordinary record
stays byte-identical.

The limit is exactly as sharp: an OPAQUE credential — a session cookie, an API key, a
bearer value with no internal structure — cannot be recognised this way and is NOT
covered. The contract is closed for self-describing credentials only.

WHY DISCOVERY LIVES IN THE FUNNEL, NOT AT THE CAPTURE SITE
----------------------------------------------------------
Because the ordering is the defect, and a hook at a capture site cannot fix it. On the
shell path `Executor.run` appends the `execution` record — stdout included — and only
then returns to `AssistSession._absorb_shell`; any session-level registration therefore
runs AFTER the audit already holds the credential, and that entry is hash-chained. There
is no second chance: masking it later changes its bytes, breaks the chain from there on,
and destroys the tamper-evidence the record exists to provide.

Registering inside `text()` means the FIRST write of a credential registers it and masks
it in the same call, and every present and future writer inherits that without having to
remember. `text()` is therefore deliberately not pure — it is the boundary, not a helper.

No LLM is involved (invariant 1) — this is a decode, a dict lookup and a string replace.
"""
from __future__ import annotations

import hashlib
import json
import re

# secret value -> stable placeholder. Process-global because the writers that need it
# (AuditLog.append deep inside the executor, the LLM client) are constructed long before
# a login happens and have no path to the session object.
_SECRETS: dict[str, str] = {}

# Below this length a value is not a credential, and redacting it would shred every
# ordinary record it happens to appear in. A session id or token is far longer.
_MIN_SECRET_LEN = 8

# The shape `placeholder_for` emits. Used to recognise a marker that has come BACK
# round from a record into an action — see `has_placeholder`.
_PLACEHOLDER_RE = re.compile(r"\[REDACTED:[0-9a-f]{8}\]")


def placeholder_for(value: str) -> str:
    """The stable stand-in for one secret. Keyed on a hash of the value, so the same
    credential reads the same everywhere in the ledger (an operator can still correlate
    two records as "the same session") while the value itself is unrecoverable.

    ASCII delimiters on purpose. Every surface here is written with `json.dumps` at its
    default `ensure_ascii=True`, which escapes a decorative «…» into `\\u00ab…\\u00bb` —
    the mark survives but stops being greppable, which is the one thing an operator
    checking an artifact for leakage needs it to be."""
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    return f"[REDACTED:{digest}]"


def register(*values) -> None:
    """Add engagement credential material to the redaction set. Idempotent. Anything
    empty, non-string or too short to be a credential is ignored."""
    for v in values:
        if isinstance(v, str) and len(v) >= _MIN_SECRET_LEN and v not in _SECRETS:
            _SECRETS[v] = placeholder_for(v)


def register_auth_header(header: str) -> None:
    """Register the CREDENTIAL out of an `Authorization` header value, not the whole
    header: "Bearer <jwt>" registers the jwt alone, so records keep the scheme name and
    lose only the secret."""
    if not isinstance(header, str):
        return
    parts = header.strip().split(" ", 1)
    register(parts[1].strip() if len(parts) == 2 else header.strip())


# How many distinct self-describing credentials to take out of any ONE value. A body
# echoing a token table should not be able to fill the registry, and the replace loop
# below is linear in it.
_MAX_DISCOVERED_PER_VALUE = 8


# Keys a TARGET RESPONSE itself uses to name a secret. Deliberately the same discipline
# as `hypothesis._ID_KEY_RE`, pointed the other way: a value is a credential because the
# RESPONSE CALLED IT ONE, never because of what its characters look like.
#
# WHY THIS EXISTS. `observe()` below closed the discovered-credential class for
# SELF-DESCRIBING values — a string that actually decodes as a JWT. An MD5 password hash
# describes nothing, so three consecutive bundles (CM3, CM4, CM5) were unpublishable for
# the same reason: the agent recovered `0192023a7bbd73250516f069df18b500` from a SQLi
# dump and then typed it into `md5sum` and `hashcat`. Runs CM4 and CM5 both measured ZERO
# credential-like values in captured response bodies and the admin credential present in
# the agent's own command records — the exposure is the COMMAND surface.
#
# Recognition by SHAPE was refused: a rule that masked 32-hex strings would also mask the
# resource identifiers `cross_account_resource` matches ownership against, and a rule that
# did not would have missed this hash. Reading the target's own key does neither.
_SECRET_KEY_RE = re.compile(
    r"^(?:password|passwd|pwd|secret|token|apikey|api_key|access_key|secret_key|"
    r"private_key|client_secret|refresh_token|access_token|sessionid|session_id|"
    r"auth|authorization|credential|credentials|hash|salt|otp|pin|seed|passphrase|"
    r"[A-Za-z][A-Za-z0-9]*(?:Password|Passwd|Secret|Token|Hash|Salt|ApiKey|Key))$",
    re.IGNORECASE)

# Bounds, announced rather than silent: a response is untrusted data of unknown size, and
# an unbounded walk over a hostile body is a denial of service on our own recorder.
_SECRET_SCAN_MAX_DEPTH = 6
_SECRET_SCAN_MAX_VALUES = 32


def observe_response(body) -> None:
    """Register credentials a TARGET RESPONSE labelled as such, before it is recorded.

    Called ONLY where target output enters the record — the cage's stdout/stderr and a
    captured experiment body. Deliberately NOT called from `text()`, which also sees the
    agent's own command text: registering there would mask the values the agent INVENTED
    (its password guesses), destroying the record of what it tried, and those are not
    discovered credentials.

    Once registered, the ordinary funnel masks the value on every surface from that
    moment — the record that disclosed it, every later command that carries it, the vault
    and the report — with no second redaction implementation and no new boundary.

    WHAT THIS CANNOT COVER, recorded rather than widened into recognition-by-shape:
      * a secret returned under a NON-DESCRIPTIVE key, or as a bare body;
      * a secret the agent DERIVES rather than recovers — CM5 cracked the hash to
        `admin123` and used the plaintext, which never appeared in any response and is
        therefore not attributable from the record;
      * a secret arriving through a channel whose body is not recorded — `web_result`
        stores {status, url, note, bytes} and no body;
      * a value shorter than `_MIN_SECRET_LEN`, because masking a short common string
        would corrupt every unrelated record that happens to contain it.
    """
    if not isinstance(body, str) or not body:
        return
    try:
        doc = json.loads(body)
    except Exception:
        return                       # not JSON: no key to read, and we do not guess
    found: list = []

    def walk(node, depth: int):
        if len(found) >= _SECRET_SCAN_MAX_VALUES or depth > _SECRET_SCAN_MAX_DEPTH:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and _SECRET_KEY_RE.match(str(k)):
                    found.append(v)
                elif isinstance(v, (dict, list)):
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for v in node[:_SECRET_SCAN_MAX_VALUES]:
                walk(v, depth + 1)

    walk(doc, 1)
    register(*found)


def observe(value) -> None:
    """Register any SELF-DESCRIBING credential `value` carries, before it is recorded.

    Deterministic and offline: `jwtscan.find_tokens` yields only strings that actually
    DECODE as a JWT — three base64url segments whose header and payload are JSON objects
    — so this recognises a credential rather than guessing at one. A lookalike that does
    not decode registers nothing and is recorded unchanged.

    Called from `text()` so it runs inside the write funnel itself. See the module
    docstring: the ordering is the whole defect, and only the funnel is early enough."""
    if not isinstance(value, str) or "eyJ" not in value:
        return                       # every JWT header begins `{"` -> `eyJ`; cheap gate
    from . import jwtscan            # local: jwtscan must not import redact back
    register(*jwtscan.find_tokens(value, limit=_MAX_DISCOVERED_PER_VALUE))


def has_placeholder(value) -> bool:
    """True if `value` carries a redaction marker — i.e. a RECORD artifact has looped
    back round into somewhere it is about to be USED.

    Matched by SHAPE, not against the registry, and deliberately so: a placeholder
    restored from an old checkpoint belongs to an engagement whose credential set is long
    gone, and it is no more a usable credential for being unrecognised. Deterministic
    string matching, no LLM (invariant 1).

    The caller that matters is authentication. A masked token is not a credential, and
    sending one where a real session was expected fails OPEN in the worst way — the
    request simply goes out unauthenticated, with no denial and no error to notice."""
    return isinstance(value, str) and bool(_PLACEHOLDER_RE.search(value))


def known() -> tuple:
    """The registered credential values — for tests and for an operator asking what
    this run considers secret."""
    return tuple(_SECRETS)


def clear() -> None:
    """Forget the credential set (end of engagement, or test isolation)."""
    _SECRETS.clear()


def text(value):
    """Redact one string. Non-strings and strings holding no secret are returned
    unchanged — identity, not a rewrite.

    A credential the TARGET disclosed is registered here, on its way past, so the very
    record that first carries it is also the first record to mask it."""
    if not isinstance(value, str) or not value:
        return value
    observe(value)                   # may register; must run BEFORE the replace below
    if not _SECRETS:
        return value
    # Longest first: a credential that contains another (a cookie jar string built from
    # several values) must not be half-replaced by the shorter one.
    for secret in sorted(_SECRETS, key=len, reverse=True):
        if secret in value:
            value = value.replace(secret, _SECRETS[secret])
    return value


def data(obj):
    """Redact every string inside a nested dict/list/tuple structure — used where the
    record is an object rather than a line (the audit log writes whole dataclasses, so a
    token can ride in `action`, in captured stdout, or in a field added later).

    There is deliberately NO empty-registry short-circuit here. It used to return `obj`
    untouched whenever nothing was registered, which is exactly the state an engagement
    is in when the target first hands it a credential — the record carrying it would
    have been waved straight through. Every string reaches `text()`, which does its own
    early-out after observing."""
    if isinstance(obj, str):
        return text(obj)
    if isinstance(obj, dict):
        return {k: data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [data(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(data(v) for v in obj)
    return obj
