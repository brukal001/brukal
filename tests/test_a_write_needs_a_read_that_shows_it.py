"""
test_a_write_needs_a_read_that_shows_it.py — GAP #29.

THE DEFECT, measured on the CR2 runs. `hypotheses_from` builds a `state_changed`
experiment by pairing a captured write with "the read that shows the effect", derived by
stripping the query off the write's own URL. That is right for a COLLECTION write
(`POST /workshop/api/shop/orders` -> `GET .../orders`) and wrong for an ACTION endpoint,
which is not readable at all:

    [experiment] not confirmed [state_changed]: POST /workshop/api/shop/orders/return_order
                 -- control HTTP 405 (40B) vs variant HTTP 405 (40B)

Two 405s were recorded `not_confirmed`, which reads as "the write changed nothing". It is
a FALSE NEGATIVE: the experiment never observed the resource the write touches. The same
shape covers `/apply_coupon`. This is not one bad row -- `state_changed` is the comparator
that has never confirmed in EITHER model series, and crAPI's state-changing challenges
live on exactly these action endpoints.

TWO HALVES, because either alone still lies:
  (a) AIM BETTER -- derive the read from the collection the session ACTUALLY READ, walking
      up the write's own path. Grounded in observed traffic, not guessed from the URL's
      shape: the capture set already holds every GET the session made.
  (b) FAIL HONESTLY -- when both sides answer 405 the URL is not readable, so there is
      nothing to compare. That is the `both_sides_absent` floor one status class over, and
      it must not be reported as a judged negative.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.capture import CapturedRequest, hypotheses_from
from brukal.hypothesis import Hypothesis, attribution
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

TARGET = "10.10.10.5"
SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
SCOPE_CRAPI = Path(__file__).resolve().parents[1] / "scope.crapi.json"


def _session_answering_405(tmp_path):
    """crAPI's real answer on an action endpoint: it exists, it just is not readable."""
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {
        "run": lambda s, c: ExecResult(c, 0, "", "")})(), audit, approver=lambda d: True)

    class _Cage:
        def run(self, a):
            return WebResult(status=405, url=a.url, body='{"detail":"Method not allowed"}')

    s = AssistSession(TARGET, ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, _Cage(), audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    from brukal.webmap import AttackSurface
    s.surface = AttackSurface(seed=f"http://{TARGET}/")
    return s, audit


def _write_hypothesis():
    """The exact shape the CR2 runs produced, aimed at the action endpoint."""
    read = f"http://{TARGET}/workshop/api/shop/orders/return_order"
    return Hypothesis(
        "POST /workshop/api/shop/orders/return_order observed in traffic — does it "
        "change another account's state?", "high", "state_changed",
        {"url": read, "method": "GET", "as": "self"},
        {"url": read, "method": "GET", "as": "self"}, "r", [],
        {"url": read, "method": "POST", "as": "self"})

BASE = "http://172.20.0.12"


def _cap(method, path, status=200, body=None):
    return CapturedRequest(method=method, url=f"{BASE}{path}", headers={}, body=body,
                           status=status, resp_bytes=120, content_type="application/json",
                           auth_kind="bearer", source="har")


def _state_changed(hs):
    return [h for h in hs if h.comparator == "state_changed"]


def test_an_action_write_reads_the_collection_the_session_ACTUALLY_READ(tmp_path=None):
    """THE DEFECT. The read must be `/orders`, which answered 200, not
    `/orders/return_order`, which is POST-only and answers 405 to both sides."""
    caps = [
        _cap("GET", "/workshop/api/shop/orders", 200),
        _cap("POST", "/workshop/api/shop/orders/return_order", 200, body='{"order_id":1}'),
    ]
    h = _state_changed(hypotheses_from(caps))
    assert h, "no state_changed experiment was derived from a captured write"
    read = h[0].control["url"]
    assert read == f"{BASE}/workshop/api/shop/orders", read
    assert h[0].control["method"] == "GET"
    # The write itself is untouched: it is still the ACT, with its own method and body.
    assert h[0].act["method"] == "POST"
    assert h[0].act["url"].endswith("/orders/return_order")


def test_a_collection_write_is_unchanged():
    """BOUNDARY: the case that already worked must keep working."""
    caps = [_cap("GET", "/workshop/api/shop/orders", 200),
            _cap("POST", "/workshop/api/shop/orders", 200, body='{"x":1}')]
    h = _state_changed(hypotheses_from(caps))
    assert h and h[0].control["url"] == f"{BASE}/workshop/api/shop/orders"


def test_it_uses_the_NEAREST_read_not_the_shortest():
    """Walking up must stop at the first thing observed, or every write on a deep API
    collapses onto the root and compares the wrong resource."""
    caps = [_cap("GET", "/workshop/api", 200),
            _cap("GET", "/workshop/api/shop/orders", 200),
            _cap("POST", "/workshop/api/shop/orders/return_order", 200, body="{}")]
    h = _state_changed(hypotheses_from(caps))
    assert h and h[0].control["url"] == f"{BASE}/workshop/api/shop/orders"


def test_an_ancestor_that_was_never_READABLE_is_not_used():
    """GROUNDING, not guessing. A 404 in the capture set is evidence AGAINST that read."""
    caps = [_cap("GET", "/workshop/api/shop/orders", 404),
            _cap("POST", "/workshop/api/shop/orders/return_order", 200, body="{}")]
    h = _state_changed(hypotheses_from(caps))
    assert h, "the experiment should still be proposed"
    assert h[0].control["url"] != f"{BASE}/workshop/api/shop/orders", \
        "aimed at a path the capture set shows does not answer"


def test_405_ON_BOTH_SIDES_IS_NOT_A_JUDGED_NEGATIVE(tmp_path):
    """(b) THE FLOOR, THROUGH THE REAL COMPARATOR PATH. Aiming better is not enough on its
    own: when the aim is still wrong the run must say so rather than score a negative.

    Asserting the attribution TABLE alone would have been worthless here -- `attribution()`
    falls back to HARNESS-LIMIT for any unknown string, so that assertion passes for a
    name nothing ever records. This drives the request through `_run_one_round`."""
    s, audit = _session_answering_405(tmp_path)
    s._run_one_round([_write_hypothesis()], [], [])
    outs = [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l).get("kind") == "experiment_outcome"]
    assert outs, "no outcome recorded at all"
    assert outs[0]["outcome"] == "both_sides_unreadable", outs[0]
    assert outs[0]["outcome"] != "not_confirmed", \
        "two 405s were filed as the write having changed nothing -- the GAP #29 defect"
    assert outs[0]["attribution"] == "HARNESS-LIMIT", outs[0]


def test_the_new_outcome_is_declared_as_dispatched_but_unresolved():
    """A comparator outcome that gains a meaning gains a bound in the same edit -- and is
    DECLARED, not merely caught by the attribution default."""
    from brukal.hypothesis import _ATTRIBUTION, _DISPATCHED_NOT_RESOLVED, _JUDGED
    assert "both_sides_unreadable" in _DISPATCHED_NOT_RESOLVED
    assert "both_sides_unreadable" not in _JUDGED
    assert "both_sides_unreadable" in _ATTRIBUTION, "relying on the fallback is not a bound"
    assert attribution("both_sides_unreadable") == "HARNESS-LIMIT"


# --------------------------------------------------------------------------- #
# THE REGRESSION THAT CAUGHT THE FIRST FIX BEING INERT.
# --------------------------------------------------------------------------- #

def test_ON_THE_REAL_CAPTURE_the_action_write_reads_the_orders_COLLECTION():
    """The first version of this fix walked the write's path UPWARD for an ancestor the
    session had read. It passed every hand-written test above and changed NOTHING on the
    real HAR: crAPI's session never reads `/workshop/api/shop/orders` itself, it reads
    `/orders/all` and `/orders/9` — DESCENDANTS of the collection, not ancestors of the
    write. A rule correct in the abstract and inert on the data it was written for is not
    a fix, and only running it against the capture showed that.

    This test is the guard: it asserts the OUTCOME on the recorded traffic, so the rule
    cannot quietly go inert again."""
    from brukal.capture import parse_har
    from brukal.scope import load_scope
    har = (Path(__file__).resolve().parent / "fixtures" / "crapi_shop_capture.har")
    caps = parse_har(har.read_text(), load_scope(SCOPE_CRAPI))[0]
    reads = {h.act["url"].rsplit("/12", 1)[-1]: h.control["url"]
             for h in hypotheses_from(caps, max_hypotheses=10)
             if h.comparator == "state_changed"}
    orders_all = "http://172.20.0.12/workshop/api/shop/orders/all"
    # THE DEFECT ITSELF: the action endpoint, which answers 405 to a read.
    ret = [v for k, v in reads.items() if k.endswith("return_order")]
    assert ret and ret[0] == orders_all, f"return_order still reads {ret}"
    # And the collection write improves too: it used to read `/orders`, which this session
    # never read and which answered 500 in the live run.
    coll = [v for k, v in reads.items() if k.endswith("/shop/orders")]
    assert coll and coll[0] == orders_all, f"collection write reads {coll}"


def test_a_sibling_read_SAYS_SO_in_its_rationale():
    """THE RESIDUAL LIMIT, recorded rather than hidden. `apply_coupon`'s effect lands on
    the identity dashboard, which shares no path with the write, so no path rule can find
    it. The nearest sibling is used — a real read and a narrow measurement — and the
    rationale says it is a sibling, so a reader is not told the resource was observed."""
    from brukal.capture import parse_har
    from brukal.scope import load_scope
    har = (Path(__file__).resolve().parent / "fixtures" / "crapi_shop_capture.har")
    caps = parse_har(har.read_text(), load_scope(SCOPE_CRAPI))[0]
    coupon = [h for h in hypotheses_from(caps, max_hypotheses=10)
              if h.comparator == "state_changed" and "apply_coupon" in h.act["url"]]
    assert coupon, "no experiment derived for apply_coupon"
    assert "SIBLING" in coupon[0].rationale, coupon[0].rationale
