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

FOUR DETERMINISTIC PROVERS
    1. `is_solved_banner`    — the target app said so itself (PortSwigger-style banner).
    2. `boolean_sqli_differential` — classic boolean-blind SQLi, confirmed only against
       a WORKING POSITIVE CONTROL (see below).
    3. `reflected_executed`  — a request-supplied marker came back as live markup
       instead of escaped text.
    4. `credential_disclosure_login` — a password the TARGET disclosed was then used in
       a login that SUCCEEDED (the exploit chain's payoff: dump creds -> log in).

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

import json
import re
from urllib.parse import parse_qsl, unquote_plus, urlsplit

# Markers are matched against a LOWERED, decoded query value — so "Gifts' AND '1'='1"
# and "gifts' AND '1'='1" are both seen as the truthy pattern they are.
_SOLVED_MARKERS = ("is-solved", "congratulations, you solved the lab", "solved the lab")
# ` and 1=1` is the truthy twin of the ` and 1=2` falsy marker — the most common
# numeric boolean pair; without it that pair could never register (SEC-007 review).
_TRUTHY_MARKERS = ("' and '1'='1", "' or '1'='1", " or 1=1", "' or 1=1--", " and 1=1")
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


def _normalize(body: str | None) -> str:
    """Collapse whitespace so cosmetic differences (a trailing newline, re-wrapped
    text) don't masquerade as a data-retrieval differential."""
    return " ".join((body or "").split())


def _all_params(cap) -> list[tuple[str, str]]:
    return parse_qsl(urlsplit(cap.url).query, keep_blank_values=True)


def _first_marker(low: str, markers: tuple[str, ...]) -> str:
    return next((m for m in markers if m in low), "")


def _probe(cap, param: str) -> tuple[str, str] | None:
    """How `cap` probes `param`: ("truthy" | "falsy", residual) where `residual` is the
    lowered value with the boolean condition removed (`Gifts' AND '1'='1` -> `gifts`) —
    i.e. the rest of the probe, which a truthy/falsy PAIR must share. None when the
    param is absent, repeated (ambiguous), carries no marker, or carries BOTH kinds."""
    values = [v for k, v in _all_params(cap) if k == param]
    if len(values) != 1:
        return None
    low = values[0].lower()
    t, f = _first_marker(low, _TRUTHY_MARKERS), _first_marker(low, _FALSY_MARKERS)
    if bool(t) == bool(f):
        return None
    return ("truthy" if t else "falsy", low.replace(t or f, "", 1))


def _held_constant(cap, param: str) -> tuple:
    """Everything about the request EXCEPT `param`: method + every other query param.
    Two captures with equal keys differ only in `param`."""
    others = sorted((k, v) for k, v in _all_params(cap) if k != param)
    return ((cap.method or "").upper(), tuple(others))


def boolean_sqli_differential(caps) -> list[dict]:
    """Confirm boolean-blind SQLi only from a CORRELATED triple on ONE parameter, with a
    working positive control. See the module docstring for why the control is mandatory.

    SCOPE NOTE: this reads QUERY-STRING params only. POST-body SQLi — a payload in a
    form/JSON body rather than the URL — is not inspected here; that is a known
    follow-up, out of this milestone's scope.

    Confirmed for (endpoint, param P) when there exist:
      - a TRUTHY and a FALSY capture that probe P with the SAME residual (the same probe
        with only the condition flipped) and hold everything else constant (method and
        every other param identical);
      - a BASELINE: status 200, non-empty body, no truthy/falsy marker anywhere in its
        query, and identical to that pair in everything except P;
      - the baseline is STABLE: no other capture of the exact same benign request
        returned a different (normalized) body — on a page that varies by itself,
        "falsy differs" proves nothing;
      - truthy body == baseline body, and falsy body != baseline body.
    That shape — true condition returns the same rows as no condition, false condition
    returns different rows, and nothing else changed — is the data-retrieval
    differential that makes boolean-blind SQLi provable without seeing the database.

    SEC-007: this used to take the FIRST truthy and FIRST falsy capture anywhere on the
    endpoint, so an ignored param (truthy) and an unrelated param that legitimately
    changes the page (falsy) fabricated a confirmed finding. Every candidate triple is
    now examined, which also finds genuine pairs that sat behind unrelated captures and
    reports EACH injectable param of an endpoint (one finding per endpoint+param).
    """
    by_endpoint: dict[str, list] = {}
    for cap in caps:
        by_endpoint.setdefault(_endpoint(cap.url), []).append(cap)

    out: list[dict] = []
    for endpoint, group in by_endpoint.items():
        baselines = [c for c in group
                     if c.status == 200 and c.response
                     and not _is_truthy(c) and not _is_falsy(c)]
        if not baselines:
            continue  # no positive control → nothing to prove against, record nothing

        # A benign request whose repeats disagree is unstable — never a control.
        bodies_by_request: dict[tuple, set] = {}
        for b in baselines:
            key = ((b.method or "").upper(), b.url)
            bodies_by_request.setdefault(key, set()).add(_normalize(b.response))
        stable = [b for b in baselines
                  if len(bodies_by_request[((b.method or "").upper(), b.url)]) == 1]

        params: list[str] = []
        for c in group:
            for k, _ in _all_params(c):
                if k not in params and _probe(c, k) is not None:
                    params.append(k)

        for param in params:
            hit = _correlated_triple(group, stable, param)
            if hit is None:
                continue
            _b, truthy, falsy = hit
            t_val = dict(_all_params(truthy))[param]
            f_val = dict(_all_params(falsy))[param]
            out.append(
                {
                    "title": "SQL injection (boolean)",
                    "severity": "high",
                    "target": endpoint,
                    "param": param,
                    "category": "web",
                    "evidence": (
                        f"param '{param}': positive control confirmed working (200, "
                        "non-empty, stable baseline differing only in this param); "
                        f"truthy {t_val!r} body matched baseline, falsy {f_val!r} body "
                        "diverged, all else held constant — correlated data-retrieval "
                        "differential (captured)"
                    ),
                    "comparator": "boolean_body_differential",
                }
            )
    return out


def _correlated_triple(group, baselines, param: str):
    """The first (baseline, truthy, falsy) satisfying every condition in
    `boolean_sqli_differential`'s docstring for `param`, or None."""
    truthies, falsies = [], []
    for c in group:
        pr = _probe(c, param)
        if pr is not None:
            (truthies if pr[0] == "truthy" else falsies).append((c, pr[1]))
    for t, t_res in truthies:
        t_key = _held_constant(t, param)
        t_body = _normalize(t.response)
        for f, f_res in falsies:
            if f_res != t_res or _held_constant(f, param) != t_key:
                continue
            f_body = _normalize(f.response)
            for b in baselines:
                if _held_constant(b, param) != t_key:
                    continue
                b_body = _normalize(b.response)
                if b_body and t_body == b_body and f_body != b_body:
                    return b, t, f
    return None


_MAX_PAD_SKIP = 2  # at most this many plain spaces/tabs between the marker and its
# "neighbor" tag delimiter still count as tight adjacency (`<div>  MARKER  </div>`).
# Never widened further, and never crosses a newline — see _nearest_non_space.


def _nearest_non_space(body: str, start: int, step: int) -> str:
    """Walk from `start` in direction `step` (+1 or -1), skipping at most
    `_MAX_PAD_SKIP` plain space/tab characters, and return the first non-whitespace
    character found that way — or "" if a newline is hit, the skip budget runs out
    while still on whitespace, or the walk runs off either end of the string.

    The skip is deliberately TIGHT, not "skip all whitespace": an earlier version
    skipped whitespace with no distance bound at all, which let a marker reflected as
    plain text, followed by a long run of newlines, then some wholly unrelated tag far
    down the page, get misread as the marker's own neighbor (execution-verified false
    positive — see `_reflected_unescaped`'s docstring). A bare `<div>  MARKER  </div>`
    still needs a couple of spaces of slack to see its real tag past incidental
    padding; a marker separated from the next tag by 200 characters of whitespace does
    not, and treating that gap as "the same neighbor" is exactly the defect this bound
    rules out. Stopping at the first newline, specifically, means a tag on a different
    LINE from the marker is never read as its neighbor, regardless of the skip count.
    """
    i = start
    n = len(body)
    skipped = 0
    while 0 <= i < n:
        ch = body[i]
        if ch == "\n":
            return ""
        if ch in (" ", "\t"):
            if skipped >= _MAX_PAD_SKIP:
                return ""
            skipped += 1
            i += step
            continue
        return ch
    return ""


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

    # KNOWN RESIDUAL (accepted, not fixed): a bare literal `<`/`>` sitting in ordinary
    # PLAIN TEXT within `_MAX_PAD_SKIP` of the marker — e.g. "Reflected: MARK <3 users"
    # — reads as the marker's "raw tag" neighbor and over-reports, the mirror image of
    # the documented newline-split under-report above. Accepted because (a) the
    # finding this feeds is medium-severity and framed as a CANDIDATE, not a proven
    # exploit, and (b) it is the safe direction: paired with the newline-split
    # under-report, erring toward reporting a candidate that needs a human glance beats
    # silently dropping a real unescaped reflection.


def reflected_executed(caps) -> list[dict]:
    """For each captured request, for each query param value that is a distinct marker
    (alphanumeric, length >= 4), record a finding only if that marker comes back as
    unescaped markup. A marker reflected only inside HTML-escaped text records nothing.

    SCOPE NOTE: markers are read from `_query_values(cap.url)` — QUERY-STRING params
    only. Reflected input carried in a POST body is not inspected here; that is a
    known follow-up, out of this milestone's scope.
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


# --------------------------------------------------------------------------------- #
# 4. Credential disclosure -> successful login.
#
# A login is NOT a finding: Brukal logs in with the operator's own accounts constantly.
# What makes one a finding is PROVENANCE — the password was handed out by the target
# earlier in the same capture, and using it worked. Every step below is a string/set
# check over already-captured, already-redacted text (no LLM, no request issued). A
# redacted secret correlates exactly like a raw one: `redact.placeholder_for` is a
# stable hash, so the same value reads as the same `[REDACTED:…]` everywhere.
# --------------------------------------------------------------------------------- #

_PASSWORD_KEY_RE = re.compile(r"^(?:pass|passwd|pwd|pword|password|[a-z_]*password)$", re.I)
_USER_KEY_RE = re.compile(
    r"^(?:user|username|user_name|uname|login|email|mail|userid|user_id|account|name)$",
    re.I)
_MIN_CRED_LEN = 6        # shorter values recur incidentally ("admin"); never correlated
_REDIRECTS = {301, 302, 303, 307, 308}
_LOGINISH_PATH_RE = re.compile(
    r"log-?in|sign-?in|logon|error|fail|denied|invalid|unauthori", re.I)
_FAIL_TEXT_RE = re.compile(
    r"invalid|incorrect|wrong (?:user|pass)|failed|denied|try again|unauthori", re.I)
_PASSWORD_INPUT_RE = re.compile(r"""type\s*=\s*["']?password""", re.I)
_AUTHED_MARKER_RE = re.compile(r"log\s?-?out|sign\s?-?out|my[- ]account", re.I)
_TOKEN_KEY_RE = re.compile(
    r"^(?:token|access_token|accesstoken|jwt|id_token|authentication|session|sessionid)$",
    re.I)


def _login_fields(cap) -> tuple[str, str, str] | None:
    """(user_key, user, password) from a POST body (form or JSON object), or None."""
    if (cap.method or "").upper() != "POST" or not cap.body:
        return None
    body = str(cap.body)
    pairs: list = []
    try:
        doc = json.loads(body)
        if isinstance(doc, dict):
            pairs = [(str(k), v) for k, v in doc.items() if isinstance(v, str)]
    except ValueError:
        pairs = parse_qsl(body, keep_blank_values=True)
    pw = next((v for k, v in pairs if _PASSWORD_KEY_RE.match(k)), None)
    user = next(((k, v) for k, v in pairs if _USER_KEY_RE.match(k)), None)
    if not pw or not user or not user[1]:
        return None
    return user[0], user[1], pw


def _has_token_key(node, depth=0) -> bool:
    if depth > 4:
        return False
    if isinstance(node, dict):
        return any((_TOKEN_KEY_RE.match(str(k)) and v) or _has_token_key(v, depth + 1)
                   for k, v in node.items())
    if isinstance(node, list):
        return any(_has_token_key(v, depth + 1) for v in node[:16])
    return False


def _login_succeeded(cap) -> bool:
    """Deterministic success signal for a login response. Strict on purpose: an
    ambiguous response is NOT a success."""
    headers = {str(k).lower(): str(v) for k, v in (cap.resp_headers or {}).items()}
    if cap.status in _REDIRECTS:
        loc = headers.get("location", "")
        return bool(loc) and not _LOGINISH_PATH_RE.search(urlsplit(loc).path + "?"
                                                          + urlsplit(loc).query)
    if cap.status != 200 or not cap.response:
        return False
    body = str(cap.response)
    try:
        doc = json.loads(body)
    except ValueError:
        doc = None
    if isinstance(doc, (dict, list)):
        if isinstance(doc, dict) and doc.get("error"):
            return False
        return _has_token_key(doc)
    return (not _PASSWORD_INPUT_RE.search(body) and not _FAIL_TEXT_RE.search(body)
            and bool(_AUTHED_MARKER_RE.search(body)))


def _whole(value: str, text: str) -> bool:
    return bool(re.search(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])",
                          text or ""))


def credential_disclosure_login(caps, own_handles=()) -> list[dict]:
    """Confirm "a password the target disclosed was used in a login that succeeded".

    For each successful login (`_login_succeeded`) whose password is >= 6 chars and whose
    username is not one of `own_handles` (the session's own principals): find an EARLIER
    capture whose response contains that password as a whole token, and whose own
    request (URL + body, decoded) did NOT carry it — so the target produced the value
    rather than echoing our input. One finding per (login endpoint, username). The
    password itself is never written into the finding."""
    caps = list(caps)
    own = {str(h).lower() for h in own_handles if h}
    out: list[dict] = []
    seen: set = set()
    for i, cap in enumerate(caps):
        fields = _login_fields(cap)
        if fields is None:
            continue
        user_key, user, pw = fields
        if len(pw) < _MIN_CRED_LEN or user.lower() in own or not _login_succeeded(cap):
            continue
        key = (_endpoint(cap.url), user.lower())
        if key in seen:
            continue
        for src in caps[:i]:
            sent = unquote_plus(src.url or "") + " " + unquote_plus(str(src.body or ""))
            if src.response and _whole(pw, str(src.response)) and pw not in sent:
                seen.add(key)
                out.append({
                    "title": "Account takeover via disclosed credential",
                    "severity": "high",
                    "target": _endpoint(cap.url),
                    "param": user_key,
                    "category": "web",
                    "evidence": (
                        f"the password used to log in as '{user}' at {_endpoint(cap.url)} "
                        f"was disclosed earlier by the target in the response to "
                        f"{src.method} {_endpoint(src.url)} (not an echo of our input); "
                        f"the login succeeded (HTTP {cap.status}"
                        + (f" -> {dict((str(k).lower(), v) for k, v in (cap.resp_headers or {}).items()).get('location', '')}"
                           if cap.status in _REDIRECTS else "")
                        + ") — captured, value withheld"),
                    "comparator": "credential_disclosure_login",
                })
                break
    return out


def findings_from_capture(caps, scope, own_handles=()) -> list[dict]:
    """The Task 9 entry point: everything this module can prove from a capture set,
    in one list ready for `_record_confirmed`. `scope` is accepted for interface
    symmetry with the rest of the confirm reflex; every cap already passed scope at
    ingest (see capture.py's `_record`), so it is not re-checked here.
    """
    out: list[dict] = []
    # ONCE PER RUN, not once per endpoint. The is-solved banner is injected into the
    # page chrome, so once a lab is solved it appears on EVERY subsequent captured
    # page (the nav bar, every follow-on GET) — without the break below this loop
    # emitted a separate "Lab solved" finding for each captured endpoint that
    # happened to carry it, which is the same fact recorded N times, not N facts.
    # The other two provers stay per-endpoint on purpose: each boolean-SQLi /
    # reflected-XSS confirmation IS a distinct endpoint-scoped claim.
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
            break
    out.extend(boolean_sqli_differential(caps))
    out.extend(reflected_executed(caps))
    out.extend(credential_disclosure_login(caps, own_handles))
    return out
