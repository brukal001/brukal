"""
calibrate.py — learn what THIS application's answers mean, instead of assuming.

Brukal's detectors were written against two applications, and it shows: eighteen
hardcoded status-code comparisons and nineteen hardcoded English phrases decide whether
a response counts as a refusal, a miss or a success. Every one of those is a sentence
about VAmPI or DVNA masquerading as a sentence about the web. The cost is paid on every
unfamiliar target, one bug at a time:

  * `a_denied_b_allowed` required 401 or 403, so an application that refuses a stranger
    with a redirect to /login — which is most of the server-rendered web — could not
    produce an authorization finding at all. A perfect experiment was discarded.
  * `login()` decided success by the ABSENCE of a password field, and was wrong three
    separate ways: for a redirect, for a 400, and for any 200 that simply was not the
    login page.
  * The route miner recognised endpoints by a fixed list of first path segments, so an
    application mounting its routes under `/app/` was invisible to it.

The pattern is always the same. A constant encodes one application's dialect, and the
tool is then blind on every application that speaks differently. Adding another constant
to the list fixes one target and leaves the next one broken.

So this module asks the target instead. Before probing begins it spends a handful of
gated requests establishing what this application does when it says yes, when it says
"no such thing", and when it says no — then every later comparison is made against those
observed baselines rather than against a number somebody hardcoded in 2025.

Deterministic and content-blind: it compares status codes, body sizes and structural
fingerprints. It never reads the target's prose for meaning, because a hostile target
controls that text and invariant 1 forbids trusting it. A page saying "Access denied"
proves nothing; a page that matches what this application returned for a resource we
KNOW is protected is evidence.

No LLM, no egress of its own — every request goes through the same governed browser and
the same scope gate as everything else.
"""
from __future__ import annotations

import re

# Body-length bands. Comparing exact lengths would make every dynamic page look unique
# (timestamps, CSRF tokens, item counts), and comparing nothing would make every page
# look alike. Bands are the compromise: a difference has to be substantial to register.
_BAND_RATIO = 0.25

_WS_RE = re.compile(r"\s+")
# Volatile substrings that differ between two renderings of the SAME page. Stripped
# before fingerprinting so a CSRF token or a timestamp does not make a page look like a
# different one every time it is fetched.
_VOLATILE_RE = re.compile(
    r"(?:[0-9a-f]{16,}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?|"
    r"\b\d{9,}\b|csrf[^\"'<>]{0,8}[\"'][^\"']{8,}[\"'])", re.I)


def _fingerprint(body: str) -> str:
    """A structural signature of a response body.

    Tag skeleton rather than text: two renderings of the same template differ in their
    content and agree in their shape, which is exactly the distinction needed to tell
    "the same page again" from "a different page". Prose is deliberately discarded —
    the target writes it and must never be read for meaning."""
    text = _VOLATILE_RE.sub("", body or "")
    tags = re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9]{0,14})", text)
    if tags:
        return ">".join(tags[:60]).lower()
    # Not HTML: fall back to the shape of a JSON document — its keys, not its values.
    keys = re.findall(r'"([A-Za-z_][A-Za-z0-9_]{0,30})"\s*:', text)
    if keys:
        return "{" + ",".join(sorted(set(keys))[:40]) + "}"
    return _WS_RE.sub(" ", text)[:120]


class Sample:
    """One observed response, reduced to what can be compared."""

    __slots__ = ("status", "length", "fingerprint", "location", "url")

    def __init__(self, result, url: str = ""):
        self.status = getattr(result, "status", None)
        body = getattr(result, "body", "") or ""
        self.length = len(body)
        self.fingerprint = _fingerprint(body)
        headers = getattr(result, "headers", None) or {}
        self.location = (headers.get("location") or headers.get("Location") or "")
        self.url = url

    def resembles(self, other) -> bool:
        """Whether two responses are the same KIND of answer.

        Not equality: a listing with three rows and one with four are the same kind of
        answer. Status must match, and then either the structure or the size band."""
        if other is None or self.status != other.status:
            return False
        if self.status in (301, 302, 303, 307, 308):
            # For a redirect the destination IS the answer.
            return _same_destination(self.location, other.location)
        # Structure decides when both responses have one. Falling through to the size
        # band here made two entirely different small pages — a table and a form —
        # count as the same kind of answer merely because they were a similar length,
        # which is precisely the confusion this class exists to prevent.
        if self.fingerprint and other.fingerprint:
            return self.fingerprint == other.fingerprint
        # No structure to compare (an empty body, a plain-text answer): size is all
        # that is left, and a difference has to be substantial to register.
        bigger = max(self.length, other.length) or 1
        return abs(self.length - other.length) / bigger <= _BAND_RATIO

    def describe(self) -> str:
        loc = f" -> {self.location}" if self.location else ""
        return f"HTTP {self.status}{loc} ({self.length}B)"


def _same_destination(a: str, b: str) -> bool:
    """Two redirect targets that mean the same thing. Compared by PATH: a login
    redirect commonly carries a `?next=` of wherever we were going, and that query
    differs between two refusals of two different resources while meaning the same."""
    from urllib.parse import urlsplit
    try:
        return (urlsplit(a or "").path or a or "") == (urlsplit(b or "").path or b or "")
    except ValueError:
        return (a or "") == (b or "")


class TargetProfile:
    """What this application's answers mean, learned from a few gated requests.

    Every baseline is optional. A profile that could not establish one simply declines
    to classify against it, and callers fall back to their previous hardcoded rule —
    calibration may only ever ADD certainty, never remove it, because a wrong baseline
    would silently reclassify every later comparison."""

    def __init__(self):
        self.ok: Sample | None = None
        self.missing: Sample | None = None
        self.denied: Sample | None = None
        self.notes: list = []

    # -- learning ---------------------------------------------------------------- #

    def learn_ok(self, result, url: str = "") -> None:
        if getattr(result, "status", None) is not None:
            self.ok = Sample(result, url)
            self.notes.append(f"ok = {self.ok.describe()} at {url}")

    def learn_missing(self, result, url: str = "") -> None:
        """The shape of "no such thing" — DISCARDED when it cannot discriminate.

        An application with a catch-all route answers a nonexistent path exactly as it
        answers a real one: a single-page app serves its shell for everything, and some
        APIs return the same envelope regardless. The baseline is then not merely
        useless but actively harmful, because every substantive response resembles it
        and `is_substantive` starts answering False for real content. A live suite run
        caught precisely this — a fixture answering 200 with the same body to every
        request made an injection finding disappear.

        A baseline that cannot tell two different things apart is not a baseline."""
        if getattr(result, "status", None) is None:
            return
        sample = Sample(result, url)
        if self.ok is not None and sample.resembles(self.ok):
            self.notes.append(
                f"missing = INDISTINGUISHABLE from a real page ({sample.describe()}) — "
                f"this host answers catch-all, so the baseline is discarded rather than "
                f"used to call real content empty")
            self.missing = None
            return
        self.missing = sample
        self.notes.append(f"missing = {self.missing.describe()} at {url}")

    def learn_denied(self, result, url: str = "") -> None:
        """The shape of a refusal, taken from a resource we KNOW needs authentication
        asked WITHOUT a session. This is the baseline that matters most: it is the one
        that was hardcoded to 401/403 and silently excluded most of the web."""
        if getattr(result, "status", None) is not None:
            self.denied = Sample(result, url)
            self.notes.append(f"denied = {self.denied.describe()} at {url}")

    # -- using ------------------------------------------------------------------- #

    @property
    def calibrated(self) -> bool:
        return self.denied is not None or self.missing is not None

    def is_denied(self, result) -> bool | None:
        """True/False when the profile can decide, None when it cannot.

        None is not "no" — it means the caller must fall back to its own rule. Conflating
        the two would turn an uncalibrated run into one that reports nothing."""
        if self.denied is None or getattr(result, "status", None) is None:
            return None
        return Sample(result).resembles(self.denied)

    def is_missing(self, result) -> bool | None:
        if self.missing is None or getattr(result, "status", None) is None:
            return None
        return Sample(result).resembles(self.missing)

    def is_substantive(self, result) -> bool | None:
        """Whether a response actually carries content, as this application measures it.

        `len(body) > 0` is the usual test and it is wrong on any app that renders a full
        template around an empty result set: the 'nothing here' page is 4KB. Compared
        against the MISSING baseline instead, so 'substantive' means 'more than this app
        returns when there is nothing to return'."""
        if getattr(result, "status", None) is None:
            return None
        if self.missing is None:
            return None
        sample = Sample(result)
        if sample.resembles(self.missing):
            return False
        return sample.length > self.missing.length

    def summary(self) -> str:
        if not self.notes:
            return ""
        return "[calibration] " + "; ".join(self.notes)
