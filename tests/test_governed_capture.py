"""
test_governed_capture.py — the single web door (`GovernedBrowser`) captures full
request/response for BOTH transports: the raw HTTP path (`_self_capture`) and the
CDP browser path (`_fold_cdp_capture`, draining `cage.drain_capture()`).

`_self_capture` already called `capture._record(...)` but dropped the response body
(it passed only `len(result.body)` as `resp_bytes`). `_record` now accepts
`response=`/`resp_headers=` (and strips/redacts credential response headers itself),
so the door's job is just to hand both over — not to re-implement any of
`_record`'s scope/static/credential guarantees.

Scope is built with the REAL dataclass constructor (see `scope.py` and
`tests/test_capture_resp_headers.py`) — there is no `Scope.from_dict`.

`_is_static` (capture.py) drops a response whose Content-Type starts with
`text/css` (among others) or whose URL path ends in a static suffix — so the
in-scope CDP sub-request below uses a NON-static endpoint (`/api/items`,
`application/json`), while the out-of-scope one is free to be anything because it
is dropped earlier, on the scope check.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.audit import AuditLog
from brukal.chrome import ChromeCage, FakeCDP
from brukal.scope import Scope
from brukal.web import CompositeWebCage, GovernedBrowser, WebAction, WebResult


def _scope():
    return Scope("t", (), frozenset({"*"}), 60,
                 authorized_hosts=frozenset({"lab.example"}), authorization="test")


class _RawCage:
    """No `drain_capture` at all — the plain HTTP/fake-web backend."""

    def run(self, action):
        return WebResult(status=200, url=action.url, body="<html>hi</html>",
                         headers={"Content-Type": "text/html"})

    def set_tls_verify(self, v):
        pass


class _CDPCage(_RawCage):
    """A CDP-backed cage: the door's own `run()` result is for the top-level
    navigate, and `drain_capture()` additionally hands back whatever sub-requests
    Chrome's Network domain observed during that navigation — some in scope, some
    not (a page can embed a request to a third-party host the proxy never gated)."""

    def drain_capture(self):
        return [
            {"method": "GET", "url": "http://lab.example/api/items", "req_headers": {},
             "req_body": None, "status": 200,
             "resp_headers": {"Content-Type": "application/json"}, "resp_body": '{"ok":true}'},
            {"method": "GET", "url": "http://evil.example/x", "req_headers": {},
             "req_body": None, "status": 200, "resp_headers": {}, "resp_body": "leak"},
        ]


def test_door_stores_response_body_and_headers(tmp_path):
    """The RAW path now keeps what it already fetched: Task 5's `_record` can hold
    the body/headers, but nothing at the call site passed them in."""
    b = GovernedBrowser(_scope(), _RawCage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="get", url="http://lab.example/x"))
    caps = b.captured()
    assert caps, "the request was not captured at all"
    assert caps[0].response == "<html>hi</html>"
    assert caps[0].resp_headers.get("Content-Type") == "text/html"


def test_cdp_drain_folds_in_scope_pairs_only(tmp_path):
    """Named risk: a drained sub-request to an out-of-scope host (the browser loaded
    something the proxy would have blocked) must be DROPPED by `_record`'s own scope
    guarantee, never appended to the capture store by the fold."""
    b = GovernedBrowser(_scope(), _CDPCage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="navigate", url="http://lab.example/"))
    caps = b.captured()
    urls = [c.url for c in caps]
    assert "http://lab.example/api/items" in urls, "in-scope sub-request was not folded"
    assert "http://evil.example/x" not in urls, "out-of-scope pair leaked into the capture"
    item = next(c for c in caps if c.url == "http://lab.example/api/items")
    assert item.response == '{"ok":true}'
    assert item.resp_headers.get("Content-Type") == "application/json"


def test_cdp_sub_resource_flood_does_not_starve_later_door_captures(tmp_path):
    """IMPORTANT #2 — door captures (`_self_capture`) and CDP-fold captures used to
    share ONE list with asymmetric caps (25 vs 200): once a page folded more than 24
    sub-resources, every LATER top-level door capture was silently dropped because
    the shared list was already past 25. Door and CDP-fold captures must now live in
    SEPARATE bounded lists so a flood of one kind can never evict the other."""

    class _FloodingCDPCage(_RawCage):
        """Folds 30 in-scope, non-static sub-resources on every navigate — more than
        `_SELF_CAPTURE_MAX` (25), which is exactly what used to starve the door."""

        def drain_capture(self):
            return [
                {"method": "GET", "url": f"http://lab.example/api/item{i}",
                 "req_headers": {}, "req_body": None, "status": 200,
                 "resp_headers": {"Content-Type": "application/json"},
                 "resp_body": '{"ok":true}'}
                for i in range(30)
            ]

    b = GovernedBrowser(_scope(), _FloodingCDPCage(), AuditLog(tmp_path / "a.jsonl"))
    # One navigate already folds 30 sub-resources — more than _SELF_CAPTURE_MAX.
    b.run(WebAction(kind="navigate", url="http://lab.example/"))
    # A later top-level door capture (a plain get/request) must still be kept.
    b.run(WebAction(kind="get", url="http://lab.example/door-page"))
    urls = [c.url for c in b.captured()]
    assert "http://lab.example/door-page" in urls, (
        "a later door capture was starved out by CDP sub-resource fold volume")


def test_cdp_drain_is_a_noop_when_the_cage_has_no_drain_capture(tmp_path):
    """The raw/fake cages never grow a `drain_capture` method — the fold must not
    assume it exists."""
    b = GovernedBrowser(_scope(), _RawCage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="get", url="http://lab.example/x"))
    assert len(b.captured()) == 1


def test_composite_cage_forwards_drain_capture_to_render_cage(tmp_path):
    """CRITICAL #1 — the production stack is `GovernedBrowser -> CompositeWebCage
    (render, request) -> ChromeCage`. `GovernedBrowser._fold_cdp_capture` does
    `getattr(self._cage, "drain_capture", None)` where `self._cage` is the
    COMPOSITE, not the render cage — so without `CompositeWebCage.drain_capture`
    forwarding to the render half, this returns None and the CDP fold silently
    no-ops in the real stack, even though it is fully wired against a bare
    `ChromeCage` elsewhere in this file. This test builds the REAL composition (no
    shortcuts) and must FAIL before `CompositeWebCage.drain_capture` exists and
    PASS after."""
    cdp = FakeCDP()
    cdp.queue_network("http://lab.example/api/items", status=200,
                      resp_body='{"ok":true}', method="GET")
    render = ChromeCage(cdp)
    request = _RawCage()  # not exercised by a navigate; stands in for the raw/HTTP half
    cage = CompositeWebCage(render, request)

    b = GovernedBrowser(_scope(), cage, AuditLog(tmp_path / "a.jsonl"))
    decision, result = b.run(WebAction(kind="navigate", url="http://lab.example/"))
    assert decision.verdict == "ALLOW"

    caps = b.captured()
    urls = [c.url for c in caps]
    assert "http://lab.example/api/items" in urls, (
        "the folded in-scope Network pair did not reach GovernedBrowser.captured() "
        "through the composite cage — drain_capture() is not being forwarded")
    item = next(c for c in caps if c.url == "http://lab.example/api/items")
    assert item.response == '{"ok":true}'


def test_cdp_drain_never_breaks_a_run_if_draining_raises(tmp_path):
    """Capture must never break a run — a drain that raises is swallowed."""
    class _BoomCage(_RawCage):
        def drain_capture(self):
            raise RuntimeError("cdp pipe closed")

    b = GovernedBrowser(_scope(), _BoomCage(), AuditLog(tmp_path / "a.jsonl"))
    decision, result = b.run(WebAction(kind="get", url="http://lab.example/x"))
    assert decision.verdict == "ALLOW" and result is not None
    # the door's own capture of the top-level request still happened
    assert len(b.captured()) == 1
