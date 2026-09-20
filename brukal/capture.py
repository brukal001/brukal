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
