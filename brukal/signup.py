"""
signup.py — read what a registration endpoint says it wants, instead of guessing.

THE MEASURED PROBLEM (crAPI, CR1 pre-flight 2026-09-17)
    `_register_account_json` posted a fixed body — {email, password, passwordRepeat,
    username} — confirmed live against Juice Shop in August 2026. crAPI's
    `POST /identity/api/auth/signup` also requires `name` and `number`, so the second
    principal could not be created on the target chosen *because* both principals can be
    verified there.

WHY NOT SIMPLY ADD THE TWO FIELDS
    The next application requires a third. A hardcoded field list IS the assumption that
    broke; lengthening it moves the break one target further out. The endpoint already
    answers the question — crAPI's own refusal names both fields:

        Field error in object 'signUpForm' on field 'number': rejected value [null];
        ... default message [must not be blank]

    So the payload is built from what the application SAID. Deterministic string work
    over the refusal body: no model anywhere near it (invariant 1 is about the gate, but
    the same reasoning applies — a hostile body must not be able to talk us into posting
    something we did not intend, which is why the field NAMES are constrained to a strict
    identifier shape and the VALUES are synthesised here, never taken from the response).

FAIL-CLOSED
    An endpoint whose refusal names nothing usable gets no guess. The caller records why
    and gives up — a missing second principal that says so is worth more than an account
    created by brute-forcing field names at somebody's registration endpoint.
"""
from __future__ import annotations

import json
import re

# A field name we are willing to post. Deliberately strict: it comes out of a body the
# TARGET controls, and it becomes a key in a request we send.
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,39}$")

# Spring / Java bean validation — the shape crAPI answers with.
_SPRING = re.compile(r"on field '([A-Za-z][A-Za-z0-9_.\-]{0,39})'")
# "name is required", "field 'dob' must not be blank", "Missing required field: x"
_PROSE = (
    re.compile(r"missing (?:required )?(?:field|parameter)s?[:\s]+['\"]?"
               r"([A-Za-z][A-Za-z0-9_.\-]{0,39})", re.I),
    re.compile(r"['\"]?([A-Za-z][A-Za-z0-9_.\-]{0,39})['\"]?\s+(?:is|are|must)\s+"
               r"(?:a\s+)?(?:required|not be blank|not be null|mandatory)", re.I),
    re.compile(r"field\s+['\"]([A-Za-z][A-Za-z0-9_.\-]{0,39})['\"]", re.I),
)
# Words that look like field names in these messages but are not.
_STOP = {"field", "fields", "value", "values", "object", "error", "errors", "request",
         "body", "parameter", "parameters", "message", "details", "data", "this", "it"}
# A refusal keyed BY field name ({"number": ["This field is required."]}) is only read as
# such when the value complains about absence — otherwise every key of every error object
# would become a field we post.
_REQUIRED = re.compile(r"required|must not be (?:blank|null|empty)|mandatory|"
                       r"cannot be (?:blank|null|empty)|may not be (?:blank|null|empty)|"
                       r"is missing", re.I)


def _from_mapping(obj, out: list) -> None:
    """Keys of an error mapping whose value complains about absence."""
    if not isinstance(obj, dict):
        return
    for key, val in obj.items():
        if key in ("errors", "error", "details", "fieldErrors", "validationErrors"):
            _from_mapping(val, out)
            continue
        if not _NAME.match(str(key)) or str(key).lower() in _STOP:
            continue
        blob = json.dumps(val) if not isinstance(val, str) else val
        if _REQUIRED.search(blob or ""):
            out.append(str(key))


def missing_fields(body: str, already: set | None = None) -> list:
    """Field names this endpoint says are missing, in the order found, deduplicated.

    `already` is what the request already carried: a field we sent and that is still
    named is NOT re-proposed, because re-adding it would spin the caller's retry loop
    against an endpoint refusing for some other reason entirely.
    """
    text = body or ""
    already = {a.lower() for a in (already or set())}
    out: list = []

    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        _from_mapping(parsed, out)

    for m in _SPRING.finditer(text):
        out.append(m.group(1))
    if not out:                       # prose only when nothing structural was found
        for rx in _PROSE:
            for m in rx.finditer(text):
                out.append(m.group(1))

    seen, clean = set(), []
    for name in out:
        low = name.lower()
        if low in seen or low in already or low in _STOP or not _NAME.match(name):
            continue
        seen.add(low)
        clean.append(name)
    return clean


# What a field NAME implies about the value it wants. crAPI validates `number` as a phone
# number, so a word there is refused exactly as `null` was; the point of reading the
# refusal is lost if the value we add is the wrong shape.
_DIGITS = ("number", "phone", "mobile", "tel", "msisdn", "contact")
_EMAIL = ("email", "mail")


def synth_value(field: str, tag: str) -> str:
    """A safe, deterministic value for a discovered field. Never taken from the target's
    response — the target names the field; we choose what goes in it."""
    low = (field or "").lower()
    if any(k in low for k in _EMAIL):
        return f"brk{tag}@brukal.test"
    if any(k in low for k in _DIGITS):
        return "9" + "".join(c for c in tag if c.isdigit()).ljust(9, "7")[:9]
    if "date" in low or low in ("dob", "birthday"):
        return "1990-01-01"
    if "url" in low or "site" in low:
        return "http://brukal.test/"
    return f"brk{tag}"
