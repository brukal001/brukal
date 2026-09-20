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


def _record(method, url, headers, body, status, resp_bytes, content_type, scope,
            report, source):
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
    return CapturedRequest(
        method=str(method or "GET").upper(), url=url, headers=clean, body=safe_body,
        status=status, resp_bytes=resp_bytes, content_type=content_type or "",
        auth_kind=kind, source=source)


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
                          str(content.get("mimeType") or ""), scope, report, "har")
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

    out = []
    for c in caps:
        if len(out) >= max_hypotheses:
            break
        url, path = c.url, c.path()
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
    session._captured = []
    return learned
