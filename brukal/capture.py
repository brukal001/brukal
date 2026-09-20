"""
capture.py — the surface, learned from traffic that actually happened.

WHY THIS EXISTS (cold target 1, DVWA, 2026-09-20)
    Of 30 URLs the harness fetched against an unfamiliar application, two were real paths
    and nineteen were API-shaped guesses inherited from the previous two targets:
    `/api/v1/coupon/apply`, `/coupons`, `/swagger.json`, `/graphql/console`. `/setup.php`
    answers 200 and was never requested. There is no content discovery anywhere in the
    harness. Recon was a memorised wishlist, and on a target that did not match the
    memory it found one login page.

    A captured request is evidence a wordlist cannot produce: it happened, and the target
    answered it. This module turns a capture into the two things the harness needs — an
    understanding of the application's shape, and experiments whose CONTROL is already
    known to work.

THE SEAM
    Every producer — `parse_har` today, a live mitmproxy transport later — funnels through
    `_record()`, which is the ONLY constructor of a `CapturedRequest`. Both safety
    guarantees live there, so they are checked once rather than repeated per caller and a
    later producer cannot forget one:

      1. SCOPE AT INGEST. Filtered with the scope's own `contains_host`, never a
         reimplementation. An out-of-scope host cannot enter the surface, so it can never
         become an experiment. A real capture always contains a CDN, usually analytics,
         and sometimes ANOTHER ENGAGEMENT'S TARGET.
      2. CREDENTIALS STRIPPED. A capture carries the operator's live session. The auth
         SHAPE is kept (`auth_kind`) because "this route expects a bearer token" is
         exactly what the grounding never knew; the value is dropped because holding it is
         exactly what the harness must never do.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

# Header names that carry a credential. Compared case-insensitively.
_CREDENTIAL_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-access-token", "x-csrf-token", "proxy-authorization",
})

# Response types that are page furniture. They are the bulk of any real capture and
# contribute no surface, so they are dropped before anything else looks at them.
_STATIC_TYPES = ("image/", "font/", "video/", "audio/", "text/css",
                 "application/javascript", "text/javascript", "application/font")
_STATIC_SUFFIXES = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                    ".woff", ".woff2", ".ttf", ".map", ".mp4")

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class CapturedRequest:
    """One request/response pair, in scope and carrying no secret."""

    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None
    status: int | None = None
    resp_bytes: int | None = None
    content_type: str = ""
    auth_kind: str = "none"          # bearer | cookie | apikey | none — SHAPE, not value
    source: str = "har"              # har | mitm
    # The response BODY, redacted and truncated. Kept because a value the target HANDED
    # BACK and the client later SENT is a reference, and that link is the only way to see
    # the application's grammar — that `return_order.order_id` refers to what `orders`
    # returned. Redacted because a response body is exactly where a discovered credential
    # lives, which is why `redact.observe_response` exists at the web plane's own door.
    response: str | None = None

    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    def is_write(self) -> bool:
        return self.method.upper() in _WRITE_METHODS

    def param_names(self) -> list:
        """Parameter names from BOTH the query and a form/JSON body.

        Real names, per endpoint. The harness has never had these: `surface.params` was
        populated only from HTML forms the crawl happened to reach."""
        names = [k for k, _v in parse_qsl(urlsplit(self.url).query, keep_blank_values=True)]
        body = (self.body or "").strip()
        if body.startswith("{"):
            try:
                doc = json.loads(body)
                if isinstance(doc, dict):
                    names.extend(str(k) for k in doc)
            except ValueError:
                pass
        elif body:
            names.extend(k for k, _v in parse_qsl(body, keep_blank_values=True))
        out, seen = [], set()
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out


@dataclass
class IngestReport:
    """What came in, and what did not.

    `ingested` alone is a trap: "12 of 900" must never be read as "the application has 12
    endpoints", which is the same confusion GAP #16 exists to prevent one layer up."""

    ingested: int = 0
    dropped_out_of_scope: int = 0
    dropped_static: int = 0
    dropped_malformed: int = 0

    def summary(self) -> str:
        return (f"ingested {self.ingested}; dropped "
                f"{self.dropped_out_of_scope} out-of-scope, "
                f"{self.dropped_static} static, "
                f"{self.dropped_malformed} malformed")


def _auth_kind(headers: dict) -> str:
    """The SHAPE of the credential this route expects, from the headers it was sent with."""
    low = {k.lower(): str(v) for k, v in headers.items()}
    auth = low.get("authorization", "")
    if auth.lower().startswith("bearer"):
        return "bearer"
    if auth:
        return "apikey"
    if low.get("x-api-key") or low.get("x-auth-token") or low.get("x-access-token"):
        return "apikey"
    if low.get("cookie"):
        return "cookie"
    return "none"


def _is_static(url: str, content_type: str) -> bool:
    if any(content_type.lower().startswith(t) for t in _STATIC_TYPES):
        return True
    return urlsplit(url).path.lower().endswith(_STATIC_SUFFIXES)


_MAX_RESPONSE_KEPT = 4000


def _record(method, url, headers, body, status, resp_bytes, content_type, scope,
            report, source, response=None):
    """THE ONLY CONSTRUCTOR. Both guarantees are enforced here, once."""
    host = urlsplit(url).hostname
    # GUARANTEE 1 — the scope's own predicate, so ingest and the gate cannot disagree.
    if not host or not scope.contains_host(host):
        report.dropped_out_of_scope += 1
        return None
    if _is_static(url, content_type):
        report.dropped_static += 1
        return None
    kind = _auth_kind(headers)
    # GUARANTEE 2 — the value never reaches the record. `_auth_kind` has already taken
    # the only thing worth keeping.
    clean = {k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
    try:
        from . import redact
        safe_body = redact.text(body) if body else body
    except Exception:
        safe_body = body
    report.ingested += 1
    safe_response = None
    if response:
        try:
            from . import redact
            safe_response = redact.text(str(response))[:_MAX_RESPONSE_KEPT]
        except Exception:
            safe_response = str(response)[:_MAX_RESPONSE_KEPT]
    return CapturedRequest(
        method=str(method or "GET").upper(), url=url, headers=clean, body=safe_body,
        status=status, resp_bytes=resp_bytes, content_type=content_type or "",
        auth_kind=kind, source=source, response=safe_response)


def parse_har(text: str, scope, max_entries: int = 2000) -> tuple:
    """Captured requests from a HAR, in scope and stripped of credentials.

    HAR is the one format every capture tool already exports — Burp, ZAP, mitmproxy,
    Chrome DevTools — so supporting it means supporting all of them without a line of
    tool-specific code. A malformed file yields an empty list and a COUNTED report rather
    than an exception or, worse, a partial surface treated as complete."""
    report = IngestReport()
    try:
        doc = json.loads(text)
        entries = (((doc or {}).get("log") or {}).get("entries")) or []
    except Exception:
        report.dropped_malformed += 1
        return [], report
    if not isinstance(entries, list):
        report.dropped_malformed += 1
        return [], report

    out = []
    for entry in entries[:max_entries]:
        try:
            req = entry["request"]
            url = str(req["url"])
            headers = {str(h.get("name", "")): str(h.get("value", ""))
                       for h in (req.get("headers") or [])}
            body = ((req.get("postData") or {}).get("text")) or None
            resp = entry.get("response") or {}
            content = resp.get("content") or {}
            rec = _record(req.get("method"), url, headers, body,
                          resp.get("status"), content.get("size"),
                          str(content.get("mimeType") or ""), scope, report, "har",
                          response=(content.get("text") or None))
        except Exception:
            report.dropped_malformed += 1
            continue
        if rec is not None:
            out.append(rec)
    return out, report


# --------------------------------------------------------------------------- #
# CONSUMER 1 — the application's shape, from traffic instead of guesses.
# --------------------------------------------------------------------------- #

def apply_to_surface(caps, surface) -> int:
    """Fold captured traffic into the AttackSurface.

    The cold run on DVWA mapped ONE page while `/setup.php` answered 200 unasked, because
    the crawl follows links and DVWA redirects every path to a login page. A capture does
    not care: it records what was actually reached, with the method that reached it and
    the parameters it carried.

    CANDIDATES, NOT CONFIRMED. Routes go into `api_routes` (the unverified tier), never
    `confirmed_routes`. This codebase's law is that nothing derived is acted on until one
    gated request has confirmed it against the target, and a capture is an observation
    from the OPERATOR's session at an EARLIER time — the route may be gone, or may answer
    differently to us. The capture's real contribution is that the method and parameters
    are now known, so the one confirming request actually lands instead of guessing GET
    at a POST-only endpoint."""
    learned = 0
    for c in caps:
        path = c.path()
        if path not in surface.api_routes:
            surface.api_routes.append(path)
            learned += 1
        # The METHOD that actually worked. `route_methods` previously held only the
        # "[not-GET]" marker inferred from a 405.
        if c.method != "GET":
            surface.route_methods[path] = c.method
        names = c.param_names()
        if names:
            surface.params.setdefault(path, set()).update(names)
        if c.is_write():
            entry = (c.method, path)
            if entry not in surface.write_operations:
                surface.write_operations.append(entry)
        # WHICH routes expect a credential, and by what mechanism — the app's own
        # contract, observed rather than declared.
        if c.auth_kind != "none":
            entry = (c.method, path)
            if entry not in surface.protected_routes:
                surface.protected_routes.append(entry)
    return learned


# --------------------------------------------------------------------------- #
# CONSUMER 2 — every captured request is an experiment whose control already works.
# --------------------------------------------------------------------------- #

_ID_IN_PATH = __import__("re").compile(r"/(\d+)(?:/|$)")

# Endpoints that MINT OR DESTROY a session rather than address a resource somebody owns.
# Replaying them proves nothing — a login does not change another account's state, it
# creates a session — and it risks re-authenticating or locking the very accounts the run
# depends on. A live crAPI run derived 13 state_changed experiments and every one was
# `POST /identity/api/auth/login`: the harness's own login, replayed at itself.
# Same lesson as /logout in content discovery: "it was captured" and "it is worth
# replaying" are different questions.
_NOT_WORTH_REPLAYING = ("/auth/", "/login", "/logout", "/signup", "/register",
                        "/token", "/refresh", "/oauth", "/session")


def _worth_replaying(path: str) -> bool:
    low = (path or "").lower()
    return not any(n in low for n in _NOT_WORTH_REPLAYING)


def hypotheses_from(caps, max_hypotheses: int = 6, severity: str = "medium") -> list:
    """Turn captured traffic into experiments the comparators can judge.

    THE FAILURE THIS TARGETS. `state_changed` was proposed ZERO times across every run of
    both series, including one where the same model on the same prompt produced it in 4 of
    4 offline calls. The model can build the construction and does not, in the live
    grounding, reach for it. A captured write does not need to be imagined: the request
    happened, the target accepted it, and its shape is known.

    READ  -> control and variant are the same URL, differing only in WHO asks.
    WRITE -> `state_changed`: the two sides are the SAME read and `act` is the captured
             write performed between them. Exactly the shape the prompt describes and the
             model never produced.

    No captured credential travels with these: `as` selects the principal and the governed
    browser attaches whatever that principal holds. A replay carrying the captured session
    would re-issue the request as the SAME principal and prove nothing."""
    from .hypothesis import Hypothesis

    # WRITES FIRST. A real session records reads before the write they lead to — a crAPI
    # session went login, dashboard, vehicles, products, then the purchase — so a cap
    # applied in capture order spends every slot on reads. Worse, the next turn re-derives
    # the same ones, dedup discards them as seen, and the queue never advances past the
    # cap: the writes become unreachable however long the run lasts. They are also the
    # only source of `state_changed`, the comparator no model in either series proposed.
    ordered = sorted(caps, key=lambda c: 0 if c.is_write() else 1)

    out = []
    for c in ordered:
        if len(out) >= max_hypotheses:
            break
        url, path = c.url, c.path()
        if not _worth_replaying(path):
            continue
        if c.is_write():
            # The read that shows the effect. Best effort: the collection the write
            # addresses, which is the same URL without its query.
            read = url.split("?")[0]
            out.append(Hypothesis(
                title=f"{c.method} {path} observed in traffic — does it change another "
                      f"account's state?",
                severity=severity, comparator="state_changed",
                control={"url": read, "method": "GET", "as": "self"},
                variant={"url": read, "method": "GET", "as": "self"},
                rationale=f"captured {c.method} {path} answered {c.status}; if the write "
                          f"is accepted for a resource we do not own, the same read "
                          f"changes around it",
                setup=None,
                act={"url": url, "method": c.method, "body": c.body, "as": "second"}))
            continue
        # A read. Who else can do it?
        comparator = ("cross_account_resource" if _ID_IN_PATH.search(path)
                      else ("unauthenticated_exposure" if c.auth_kind != "none"
                            else "a_denied_b_allowed"))
        variant_as = "anonymous" if comparator == "unauthenticated_exposure" else "second"
        out.append(Hypothesis(
            title=f"{path} observed in traffic — reachable by another principal?",
            severity=severity, comparator=comparator,
            control={"url": url, "method": c.method, "as": "self"},
            variant={"url": url, "method": c.method, "as": variant_as},
            rationale=f"captured {c.method} {path} answered {c.status} "
                      f"({c.resp_bytes}B) for the operator's own session"))
    return out


def hold_for_surface(session, caps) -> int:
    """Keep parsed captures on the session until a surface exists to receive them.

    Parsing at start-up is right: a bad path or an empty capture should be visible before
    a run spends anything. APPLYING at start-up is not — `session.surface` is None until
    the crawl builds it, and the first version of this wiring did exactly that, died with
    `AttributeError: 'NoneType' object has no attribute 'api_routes'`, and had the whole
    feature swallowed by a broad `except` into a one-line warning. The run then built its
    surface from guesses precisely as before, which is the failure this module exists to
    remove."""
    session._captured = list(caps or [])
    return len(session._captured)


def drain_onto_surface(session) -> int:
    """Fold held captures into the surface, once, as soon as there is one.

    Idempotent: draining twice must not double-apply, because the surface is confirmed
    repeatedly during a run and this is called from that path."""
    caps = getattr(session, "_captured", None)
    surface = getattr(session, "surface", None)
    if not caps or surface is None:
        return 0
    learned = apply_to_surface(caps, surface)
    # The GRAMMAR, alongside the nouns and verbs. Derived once, here, because this is
    # where the captures and the surface are both in hand.
    try:
        links = link_fields(caps)
        if links:
            surface.field_links = list(getattr(surface, "field_links", []) or []) + links
    except Exception:
        pass
    # KEEP THEM FOR REPLAY. Consumer 1 (the surface) is done with these; consumer 2 is
    # not, and clearing the only reference meant an operator's HAR enriched the map and
    # produced no experiments. A recorded crAPI session with five real writes — a
    # purchase, a coupon validated, a coupon applied — ingested cleanly and yielded ZERO
    # state_changed, because the writes were dropped here before replay ever saw them.
    session._captured_for_replay = list(
        getattr(session, "_captured_for_replay", []) or []) + list(caps)
    session._captured = []
    return learned


def parse_curl(command: str, scope, status, resp_bytes: int = 0, source: str = "shell"):
    """A `curl` command line as a CapturedRequest, or None.

    THE GAP THIS CLOSES. Self-capture hooks the web plane's single door, but agents also
    reach the target with `curl` through the SHELL plane. In CR2 run 1, four of eleven
    shell commands were HTTP requests against the target — each a control that answered,
    none of them a replay candidate.

    IT DECLINES RATHER THAN GUESSES. This reads `-X`, `-H`, `-d` and the URL; anything
    else it does not understand it refuses, because a MISREAD command would put a URL
    nobody issued into the surface, and a fabricated route is worse than a missing one.
    It is not a shell parser and must not become one."""
    import shlex

    text = (command or "").strip()
    if not text.startswith("curl"):
        return None
    if not status or int(status) == 404 or int(status) >= 500:
        return None                        # an absence is not a control (same web floor)
    try:
        argv = shlex.split(text)
    except ValueError:
        return None

    url, method, body, headers = None, None, None, {}
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in ("-X", "--request") and i + 1 < len(argv):
            method = argv[i + 1].upper(); i += 2; continue
        if tok in ("-H", "--header") and i + 1 < len(argv):
            raw = argv[i + 1]
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2; continue
        if tok in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(argv):
            body = argv[i + 1]; i += 2; continue
        if tok.startswith(("http://", "https://")):
            if url is not None:
                return None                # two URLs: not a shape we read confidently
            url = tok; i += 1; continue
        if tok.startswith("-"):
            i += 1; continue               # a flag we do not need
        i += 1
    if not url:
        return None
    # curl's own rule: data implies POST unless told otherwise. Reading it as GET would
    # file a write as a read, and the write surface is the interesting one.
    if method is None:
        method = "POST" if body else "GET"
    return _record(method, url, headers, body, int(status), int(resp_bytes or 0),
                   "", scope, IngestReport(), source)


# --------------------------------------------------------------------------- #
# RELATIONAL RECON — the grammar, not just the nouns and verbs.
# --------------------------------------------------------------------------- #
#
# From a captured session Brukal derives the services, the state-changing surface, the
# auth model and the real parameter names. It does NOT know that `order_id` in
# return_order refers to the `id` that `orders` returned, that the workflow is
# browse -> buy -> return, or that a coupon code has a lifecycle. Nouns and verbs, no
# grammar.
#
# That limit explains the results: every experiment derived so far is "same request,
# different principal", which is all a structural map supports. The classes never reached
# — coupon reuse, price tampering, workflow bypass — need the grammar. And the A/B/C
# measurement showed the model will not supply it: zero `state_changed` proposals across
# three model families in twenty-three runs.
#
# The link is derivable without a model. A value the target HANDED BACK and the client
# later SENT is a reference, and the traffic shows it.

# Values that collide by chance constantly. A link built on one is noise, and noise here
# becomes a fabricated experiment aimed at a relationship the application does not have.
_TRIVIAL = frozenset({"0", "1", "-1", "true", "false", "null", "none", "", "2"})

# A SHORT value is only a reference when the field NAME says so. `order_id: 6` is a
# reference; `quantity: 6` is a quantity, and linking it would invent a relationship the
# application does not have. A long value (a code, a token, a uuid) needs no such help —
# it does not collide by accident.
_REFERENCE_NAME = ("_id", "id", "code", "token", "ref", "uuid", "guid", "key", "number")
_LONG_ENOUGH_ALONE = 4


def _is_reference(field: str, value: str) -> bool:
    if value.lower() in _TRIVIAL or not value:
        return False
    if len(value) >= _LONG_ENOUGH_ALONE:
        return True
    low = (field or "").lower()
    return any(low == n or low.endswith(n) for n in _REFERENCE_NAME)


def _flatten(doc, prefix=""):
    """(field, value) for every scalar in a JSON document, nested included."""
    out = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.extend(_flatten(v, str(k)))
    elif isinstance(doc, list):
        for item in doc:
            out.extend(_flatten(item, prefix))
    elif doc is not None and not isinstance(doc, bool):
        out.append((prefix, str(doc)))
    return out


def link_fields(caps, max_links: int = 24) -> list:
    """References the application itself demonstrated: response gave it, request sent it.

    CAUSAL BY CONSTRUCTION — a request can only consume a value from a response that came
    BEFORE it. Reversing that would invent a dependency out of a coincidence.

    Returns dicts of source_path / source_field / consumer_path / consumer_field / value,
    which is enough to say "return_order.order_id is whatever orders.id returned" and to
    build an experiment that REUSES a value the target has already spent."""
    seen_values = {}          # value -> (path, field) of the response that first gave it
    links, keyed = [], set()

    for c in (caps or []):
        # 1) does THIS request send a value some EARLIER response handed back?
        for field, value in _flatten(_parse_json(c.body)):
            if not _is_reference(field, value):
                continue
            origin = seen_values.get(value)
            if origin and origin[0] != c.path():
                key = (origin[0], origin[1], c.path(), field)
                if key not in keyed:
                    keyed.add(key)
                    links.append({"source_path": origin[0], "source_field": origin[1],
                                  "consumer_path": c.path(), "consumer_field": field,
                                  "value": value, "consumer_method": c.method})
                    if len(links) >= max_links:
                        return links
        # 2) then record what this response GAVE, for the requests that follow it.
        for field, value in _flatten(_parse_json(c.response)):
            if not _is_reference(field, value):
                continue
            seen_values.setdefault(value, (c.path(), field))
    return links


def _parse_json(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def reuse_experiments(links, caps, base: str = "", max_hypotheses: int = 4) -> list:
    """Was a value the application ITSELF handed back accepted a second time?

    This is the question a structural map cannot pose. Knowing that
    `apply_coupon.coupon_code` is whatever `validate-coupon` returned is what makes
    "apply it again" a meaningful experiment rather than a random repeat — and crAPI's
    coupon lifecycle crosses TWO SERVICES, so nothing short of the link would connect them.

    SAME PRINCIPAL, deliberately. Reuse is about one account using a value twice; changing
    the principal asks a different question (cross-account access) that the existing
    comparators already cover.

    FAIL CLOSED: the replay sends the body the OPERATOR actually sent, taken from the
    capture. With no captured body there is nothing faithful to replay, and inventing one
    would put a request nobody made on the wire."""
    from .hypothesis import Hypothesis

    by_path = {}
    for c in (caps or []):
        if c.is_write() and c.body:
            by_path.setdefault(c.path(), c)

    out = []
    for link in (links or []):
        if len(out) >= max_hypotheses:
            break
        if str(link.get("consumer_method", "")).upper() not in _WRITE_METHODS:
            continue                       # reading twice is not reuse
        original = by_path.get(link.get("consumer_path"))
        if original is None:
            continue                       # nothing faithful to replay
        url = f"{base.rstrip('/')}{link['consumer_path']}"
        spec = {"url": url, "method": original.method, "body": original.body, "as": "self"}
        out.append(Hypothesis(
            title=(f"{link['consumer_path']} accepted "
                   f"{link['consumer_field']}={link['value']} which "
                   f"{link['source_path']} issued — is it accepted again?"),
            severity="medium", comparator="repeat_accepted",
            control=dict(spec), variant=dict(spec),
            rationale=(f"the application returned {link['source_field']}="
                       f"{link['value']} from {link['source_path']} and then accepted it "
                       f"at {link['consumer_path']}; if it accepts it repeatedly the "
                       f"value was never consumed")))
    return out
