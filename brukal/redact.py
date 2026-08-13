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
Not a guess. There is ONE source of truth — the credential set this engagement actually
injected, registered by `_session_auth_for` at the moment it reads it off the
GovernedBrowser. The redactor replaces those exact values and nothing else, so ordinary
content is recorded byte-identical and no regex has to be trusted to recognise a token.
It masks the VALUE, never the structure: an audit line still reads

    nuclei -u http://host/x -H 'Authorization: Bearer [REDACTED:1f3a9c02]'

so the record stays meaningful and the gate's decision stays auditable.

No LLM is involved (invariant 1) — this is a dict lookup and a string replace.
"""
from __future__ import annotations

import hashlib
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
    """Redact one string. Non-strings and strings holding no registered secret are
    returned unchanged — identity, not a rewrite."""
    if not isinstance(value, str) or not _SECRETS or not value:
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
    token can ride in `action`, in captured stdout, or in a field added later)."""
    if not _SECRETS:
        return obj
    if isinstance(obj, str):
        return text(obj)
    if isinstance(obj, dict):
        return {k: data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [data(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(data(v) for v in obj)
    return obj
