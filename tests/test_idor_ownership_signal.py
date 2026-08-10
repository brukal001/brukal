"""
test_idor_ownership_signal.py — an access-control differential is about PRINCIPALS,
not about byte distance.

PROPERTY UNDER TEST
    Two records rendered through one template are near-identical BY CONSTRUCTION. The
    signal that separates "I read another user's record" from "I re-read my own" is not
    how much the two responses differ — it is WHOSE record each one is.

DEFECT THIS CLOSES (case-study defect #2, measured twice)
    `confirm_idor` gated the finding on a similarity WINDOW, `0.3 < sim < 0.98`. On HTB
    Cap the two records came back at sim ~0.9997 (17,144 vs 17,147 bytes) and the upper
    bound discarded a real hit — on 10.129.100.21 (2026-08-09, keyed re-run) and again on
    10.129.100.61 (2026-08-09, 21:59:54, `/data/0` → 200/17,146B, no finding raised).

WHY THE CEILING CANNOT SIMPLY BE RAISED
    `test_the_same_record_refetched_...` is the reason. Re-fetching your OWN record also
    lands at sim ~0.999 when the page carries a nonce or a timestamp. Deleting the upper
    bound turns every nonce-bearing page into a false IDOR. The ceiling is not a bad
    threshold, it is the wrong QUESTION — so these tests are written against the
    ownership difference and not against any number.

Invariant 1 holds: the owner comparison is a structural field extraction (regex over
key/value shapes), never a language model and never a prose judgement over target text.
"""
from __future__ import annotations

import difflib
import re
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
BASE = "http://127.0.0.1:5000"

# Enough shared bulk that two records differing in one field land above the old 0.98
# ceiling — the Cap geometry, reproduced.
_FILLER = "<tr><td>10.0.0.4</td><td>10.0.0.9</td><td>tcp</td><td>443</td></tr>" * 220

_RECORD = ("<html><body><h1>Security Snapshot</h1>"
           "<table>" + _FILLER + "</table>"
           "<p>owner={owner}</p>"
           "</body></html>")


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession("127.0.0.1", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))


def _sim(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


# --------------------------------------------------------------------------- #
# A — the true positive the ceiling was throwing away
# --------------------------------------------------------------------------- #

def test_a_near_identical_pair_differing_only_in_owner_confirms():
    """THE DEFECT. Two users' records through one template: sim ~0.999, one field apart.
    This is what a real IDOR looks like, and the old window rejected it."""
    mine = _RECORD.format(owner="alice")
    theirs = _RECORD.format(owner="bob")
    # Pin the geometry, so this test keeps testing the thing it was written for.
    assert _sim(mine, theirs) > 0.98, "fixture no longer reproduces the defect geometry"

    class _App:
        def __init__(self):
            self.seen: list[str] = []

        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            m = re.search(r"/data/(\d+)", url)
            n = int(m.group(1)) if m else -1
            if n == 1:
                return WebResult(status=200, url=url, body=mine)
            if n == 0:
                return WebResult(status=200, url=url, body=theirs)
            return WebResult(status=404, url=url, body="not found")

    sess = _session(_App())
    assert sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH") is True, \
        "a near-identical record belonging to ANOTHER owner was not confirmed"
    assert any("IDOR" in f.title for f in sess.findings.all())


# --------------------------------------------------------------------------- #
# B — the guard that forbids the lazy fix
# --------------------------------------------------------------------------- #

def test_the_same_record_refetched_with_a_fresh_nonce_does_not_confirm():
    """FALSE-POSITIVE GUARD. Same owner, same record, fresh CSRF nonce and timestamp on
    every render: sim ~0.999 and the bytes differ. Raising or deleting the ceiling makes
    this a false IDOR. Ownership is unchanged, so there is no finding."""

    class _NonceApp:
        def __init__(self):
            self.seen: list[str] = []
            self.n = 0

        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            self.n += 1
            # Every id maps to the SAME record — only the volatile fields move.
            body = ("<html><head>"
                    f'<meta name="csrf-token" content="tok{self.n:08d}a{self.n:04d}">'
                    "</head><body><h1>Security Snapshot</h1>"
                    "<table>" + _FILLER + "</table>"
                    "<p>owner=alice</p>"
                    f"<p>generated=2026-08-10T12:00:{self.n:02d}Z</p>"
                    "</body></html>")
            return WebResult(status=200, url=url, body=body)

    app = _NonceApp()
    sess = _session(app)
    result = sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH")
    assert result is False, \
        "a re-fetch of the caller's OWN record was reported as an IDOR"
    assert not any("IDOR" in f.title for f in sess.findings.all())


# --------------------------------------------------------------------------- #
# Adversarial
# --------------------------------------------------------------------------- #

def test_owner_difference_confirms_even_when_padding_destroys_similarity():
    """A target that pads one record cannot hide the ownership difference behind a LOW
    similarity score either — the finding does not depend on byte distance at all."""

    class _PaddedApp:
        def __init__(self):
            self.seen: list[str] = []

        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            m = re.search(r"/data/(\d+)", url)
            n = int(m.group(1)) if m else -1
            if n == 1:
                return WebResult(status=200, url=url, body=_RECORD.format(owner="alice"))
            if n == 0:
                return WebResult(
                    status=200, url=url,
                    body="<html><body><h1>Security Snapshot</h1><p>owner=bob</p>"
                         + ("<p>" + "q" * 60 + "</p>") * 400 + "</body></html>")
            return WebResult(status=404, url=url, body="not found")

    app = _PaddedApp()
    sess = _session(app)
    assert sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH") is True, \
        "ownership difference was lost when similarity dropped below the old floor"


def test_a_record_with_no_discernible_owner_fails_closed():
    """FAIL-CLOSED (invariant 2). Near-identical pages with no ownership field anywhere:
    the differential cannot tell whose record it read, so it does NOT confirm. Silence
    is the correct answer here, not a guess."""

    class _AnonApp:
        def __init__(self):
            self.seen: list[str] = []

        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            m = re.search(r"/data/(\d+)", url)
            n = int(m.group(1)) if m else -1
            if n < 0 or n > 2:
                return WebResult(status=404, url=url, body="not found")
            # No owner, no user, no email — only an impersonal counter moves.
            return WebResult(status=200, url=url,
                             body="<html><body><h1>Security Snapshot</h1>"
                                  "<table>" + _FILLER + "</table>"
                                  f"<p>packets={4000 + n}</p></body></html>")

    app = _AnonApp()
    sess = _session(app)
    assert sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH") is False, \
        "confirmed an IDOR without any evidence of a second principal"


# --------------------------------------------------------------------------- #
# The extractor itself
# --------------------------------------------------------------------------- #

def test_principal_tokens_are_extracted_structurally_from_common_shapes():
    """The signal is a STRUCTURAL field read — no model, no prose judgement (invariant 1).
    Volatile fields must never be mistaken for a principal."""
    A = AssistSession
    assert hasattr(A, "principal_tokens"), "no structural owner-field extraction exists"

    assert "alice" in A.principal_tokens("<p>owner=alice</p>")
    assert "alice" in A.principal_tokens('{"username": "alice", "n": 3}')
    assert "alice" in A.principal_tokens("<th>Owner</th><td>alice</td>")
    assert "alice@corp.local" in A.principal_tokens("<p>contact alice@corp.local</p>")

    # A nonce, a CSRF token, a session id and a timestamp are NOT principals.
    volatile = A.principal_tokens(
        '<meta name="csrf-token" content="abc123">'
        '<p>session_id=9f8e7d</p><p>generated=2026-08-10T12:00:00Z</p>'
        '<p>request_token=zzz</p>')
    assert not volatile, f"volatile fields leaked into the principal set: {volatile}"
