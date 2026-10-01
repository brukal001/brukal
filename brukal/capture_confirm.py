"""
capture_confirm.py — turn CAPTURED traffic into confirmed-finding candidates.

WHY THIS EXISTS (Task 8, "register the win")
    `GovernedBrowser.captured()` can hand back a transcript where Brukal demonstrably
    solved a lab or triggered a bug, and the run still records zero findings — because
    nothing downstream ever looked at the captured bodies and decided "this is proof."
    This module is that decision layer. It is deliberately NOT an LLM: a confirmed
    finding must survive on string comparison and set membership alone, the same
    discipline the gate itself uses (see CLAUDE.md invariant 1), so a hostile or merely
    noisy target cannot talk a judge into recording something unproven.

THREE DETERMINISTIC PROVERS
    1. `is_solved_banner`    — the target app said so itself (PortSwigger-style banner).
    2. `boolean_sqli_differential` — classic boolean-blind SQLi, confirmed only against
       a WORKING POSITIVE CONTROL (see below).
    3. `reflected_executed`  — a request-supplied marker came back as live markup
       instead of escaped text.

THE POSITIVE-CONTROL LAW
    A single "the falsy payload returned an empty page" observation proves nothing — an
    endpoint that 500s on garbage input looks identical whether or not SQL is being
    concatenated into a query. Recording that as a finding is exactly the false-positive
    this module exists to prevent. `boolean_sqli_differential` therefore requires a
    BENIGN request to the same endpoint that is known to work (HTTP 200, non-empty body,
    and itself free of any truthy/falsy marker) before it will consider the truthy and
    falsy pair diagnostic. No control, no finding — full stop.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

# Markers are matched against a LOWERED, decoded query value — so "Gifts' AND '1'='1"
# and "gifts' AND '1'='1" are both seen as the truthy pattern they are.
_SOLVED_MARKERS = ("is-solved", "congratulations, you solved the lab", "solved the lab")
_TRUTHY_MARKERS = ("' and '1'='1", "' or '1'='1", " or 1=1", "' or 1=1--")
_FALSY_MARKERS = ("' and '1'='2", "' or '1'='2", " and 1=2")

_RAW_TAG_CHARS = ("<", ">")


def is_solved_banner(body: str) -> bool:
    """True if `body` contains a PortSwigger-style solved marker, case-insensitive."""
    low = (body or "").lower()
    return any(marker in low for marker in _SOLVED_MARKERS)


def _endpoint(url: str) -> str:
    """scheme://netloc+path — the identity an endpoint keeps across different query
    payloads, which is exactly the granularity a differential needs to group on."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _query_values(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlsplit(url).query)


def _matches_any(value: str, markers: tuple[str, ...]) -> bool:
    low = value.lower()
    return any(marker in low for marker in markers)


def _is_truthy(cap) -> bool:
    return any(_matches_any(v, _TRUTHY_MARKERS) for _, v in _query_values(cap.url))


def _is_falsy(cap) -> bool:
    return any(_matches_any(v, _FALSY_MARKERS) for _, v in _query_values(cap.url))


def _injected_param(cap) -> str:
    """The query param carrying the SQLi payload on this capture, or '' if none."""
    for key, value in _query_values(cap.url):
        if _matches_any(value, _TRUTHY_MARKERS) or _matches_any(value, _FALSY_MARKERS):
            return key
    return ""


def _normalize(body: str | None) -> str:
    """Collapse whitespace so cosmetic differences (a trailing newline, re-wrapped
    text) don't masquerade as a data-retrieval differential."""
    return " ".join((body or "").split())


def boolean_sqli_differential(caps) -> list[dict]:
    """Group captures by endpoint; confirm boolean-blind SQLi only where a working
    positive control exists. See the module docstring for why the control is mandatory.

    Confirmed when, for one endpoint:
      - a BASELINE request exists: status 200, non-empty body, no truthy/falsy marker
        in its own query (it is genuinely benign, not itself a payload that happened
        to 200);
      - a TRUTHY request's (normalized) body equals the baseline's;
      - a FALSY request's (normalized) body differs from the baseline's.
    That shape — true condition returns the same rows as no condition, false condition
    returns different rows — is the data-retrieval differential that makes boolean-blind
    SQLi provable without ever seeing the database.
    """
    by_endpoint: dict[str, list] = {}
    for cap in caps:
        by_endpoint.setdefault(_endpoint(cap.url), []).append(cap)

    out: list[dict] = []
    for endpoint, group in by_endpoint.items():
        baseline = next(
            (
                c
                for c in group
                if c.status == 200
                and c.response
                and not _is_truthy(c)
                and not _is_falsy(c)
            ),
            None,
        )
        if baseline is None:
            continue  # no positive control → nothing to prove against, record nothing

        truthy = next((c for c in group if _is_truthy(c)), None)
        falsy = next((c for c in group if _is_falsy(c)), None)
        if truthy is None or falsy is None:
            continue

        baseline_body = _normalize(baseline.response)
        truthy_body = _normalize(truthy.response)
        falsy_body = _normalize(falsy.response)

        if baseline_body and truthy_body == baseline_body and falsy_body != baseline_body:
            out.append(
                {
                    "title": "SQL injection (boolean)",
                    "severity": "high",
                    "target": endpoint,
                    "param": _injected_param(falsy),
                    "category": "web",
                    "evidence": (
                        "positive control confirmed working (200, non-empty baseline); "
                        "truthy payload body matched baseline, falsy payload body "
                        "diverged — data-retrieval differential (captured)"
                    ),
                    "comparator": "boolean_body_differential",
                }
            )
    return out


def _nearest_non_space(body: str, start: int, step: int) -> str:
    """Walk from `start` in direction `step` (+1 or -1), skipping whitespace, and
    return the first non-whitespace character found — or "" if the walk runs off
    either end of the string. Skipping whitespace lets `<div>  MARKER  </div>` still
    see its real neighbor (`>` / `<`) past incidental padding, without widening the
    search into unrelated page chrome the way a fixed-width window did."""
    i = start
    n = len(body)
    while 0 <= i < n and body[i].isspace():
        i += step
    return body[i] if 0 <= i < n else ""


def _reflected_unescaped(body: str, marker: str) -> bool:
    """True if ANY occurrence of `marker` in `body` sits with a literal, unescaped
    `<` or `>` as its immediate (whitespace-skipped) neighbor — i.e. that occurrence
    was rendered as live markup rather than text.

    Why not just `marker in body`: an HTML-escaped reflection (`&lt;b&gt;MARKER&lt;/b&gt;`)
    still contains the literal marker substring verbatim, because escaping rewrites `<`
    and `>`, not the alphanumeric marker itself. Presence of the marker alone proves
    nothing about escaping either way.

    Why not a fixed-width window around the first occurrence (the first cut of this
    predicate): two failure modes, both execution-verified —
      - FALSE POSITIVE: an escaped reflection sitting inside ordinary page chrome,
        e.g. `<p>Your search: &lt;b&gt;zqx941&lt;/b&gt;</p>` — the window around the
        marker still contains the real `<p>`/`</p>` tags, which are unrelated to
        whether the MARKER's own reflection was escaped, so a window-based "does `<`
        or `>` appear anywhere nearby" check wrongly fires.
      - FALSE NEGATIVE: `body.find(marker)` only ever inspects the FIRST occurrence.
        A marker reflected twice — once escaped, once later as raw, executable
        markup (`<script>MARKER</script>`) — was judged purely on the first (escaped)
        occurrence and the real, later finding was missed entirely.

    The fix anchors on the marker's OWN immediate neighbor character (skipping
    incidental whitespace), checked at EVERY occurrence, not a window of surrounding
    page content:
      - raw markup: the character touching the marker is a literal `<` or `>`
        (`<b>MARKER</b>` → `>` immediately before, `<` immediately after).
      - escaped markup: the character touching the marker is always part of an HTML
        ENTITY's text, never a bare bracket — `&lt;b&gt;MARKER&lt;/b&gt;` → `;`
        immediately before (end of `&gt;`) and `&` immediately after (start of
        `&lt;/b&gt;`). HTML escaping rewrites every literal `<`/`>` into multi-char
        entity text ending in `;` or starting with `&`; it can never leave a bare
        `<`/`>` character adjacent to the thing it escaped. That asymmetry — raw
        markup always touches the marker with a bare bracket, escaped markup never
        does — is what makes the single-neighbor check correct rather than
        coincidental.
    """
    pos = 0
    marker_len = len(marker)
    while True:
        idx = body.find(marker, pos)
        if idx == -1:
            return False
        before = _nearest_non_space(body, idx - 1, step=-1)
        after = _nearest_non_space(body, idx + marker_len, step=1)
        if before in _RAW_TAG_CHARS or after in _RAW_TAG_CHARS:
            return True
        pos = idx + 1  # advance past this occurrence (by 1, not marker_len, so
        # adjacent/overlapping repeats of the marker are still each inspected)


def reflected_executed(caps) -> list[dict]:
    """For each captured request, for each query param value that is a distinct marker
    (alphanumeric, length >= 4), record a finding only if that marker comes back as
    unescaped markup. A marker reflected only inside HTML-escaped text records nothing.
    """
    out: list[dict] = []
    for cap in caps:
        body = cap.response or ""
        if not body:
            continue
        for key, value in _query_values(cap.url):
            if len(value) < 4 or not value.isalnum():
                continue
            if _reflected_unescaped(body, value):
                out.append(
                    {
                        "title": "Reflected input (unescaped)",
                        "severity": "medium",
                        "target": _endpoint(cap.url),
                        "param": key,
                        "category": "web",
                        "evidence": f"marker '{value}' reflected as unescaped markup (captured)",
                        "comparator": "reflected_unescaped",
                    }
                )
    return out


def findings_from_capture(caps, scope) -> list[dict]:
    """The Task 9 entry point: everything this module can prove from a capture set,
    in one list ready for `_record_confirmed`. `scope` is accepted for interface
    symmetry with the rest of the confirm reflex; every cap already passed scope at
    ingest (see capture.py's `_record`), so it is not re-checked here.
    """
    out: list[dict] = []
    for cap in caps:
        if cap.response and is_solved_banner(cap.response):
            out.append(
                {
                    "title": "Lab solved (exploit succeeded)",
                    "severity": "high",
                    "target": _endpoint(cap.url),
                    "param": "",
                    "category": "web",
                    "evidence": "PortSwigger is-solved banner present in captured response",
                    "comparator": "lab_solved_banner",
                }
            )
    out.extend(boolean_sqli_differential(caps))
    out.extend(reflected_executed(caps))
    return out
