"""
test_finding_body_capture.py — a finding-worthy response keeps the answer it got.

On the 2026-08-16 Juice Shop run the loop sent `PUT /api/BasketItems/1
{"quantity":-100}` and the target answered 200. That is a real business-logic flaw, and
it evaporated: the finding record kept `ALLOW:  status=200 (154B)` and nothing else, so
the model had a status line to reason over and no content. Three steps later the
repeat-suppressor told it not to try again, and the hit was gone for the rest of the run.

`self.notes` did carry the body, but notes are an in-memory rolling window; the finding
record is what `_load_memory` reads back, what the per-agent transcript shows, and what
survives a checkpoint. A result that only exists in the window is a result the engagement
loses.

The captured body crosses a record boundary, so the second half of this file is the
redaction check: capturing more must not capture the session credential.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from brukal import redact


class _Cage:
    def __init__(self, mapping):
        self.mapping, self.seen = mapping, []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.mapping.get(action.url, (404, ""))
        return WebResult(status=status, url=action.url, body=body)


class _FakeLLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


def _session(cage):
    """A session with a REAL blackboard, so the assertions read the record that is
    actually written to disk rather than an in-memory convenience copy."""
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.blackboard = Blackboard(root / "vault", scope)
    return sess


def _run(sess, web_text):
    sess.run_web(web_text)
    return sess.blackboard.all_findings("127.0.0.1")


# -- the named acceptance case -------------------------------------------------

NEGATIVE_QTY_BODY = ('{"status":"success","data":{"id":1,"quantity":-100,'
                     '"ProductId":1,"BasketId":1}}')


def test_the_negative_quantity_hit_is_recorded_with_the_body_it_answered_with():
    """The exact request the last run threw away. A quantity of -100 accepted with 200
    is the finding; `status=200 (154B)` is not enough to see that, and the model cannot
    escalate what it cannot read."""
    url = "http://127.0.0.1:5000/api/BasketItems/1"
    sess = _session(_Cage({url: (200, NEGATIVE_QTY_BODY)}))
    recs = _run(sess, f'request PUT {url} {{"quantity":-100}}')
    blob = " ".join(str(r.get("summary", "")) for r in recs)
    assert '"quantity":-100' in blob, "the response body was not kept in the finding"
    assert "200" in blob


def test_a_body_is_kept_even_when_no_highlight_pattern_matched_it():
    """Highlights are a fitted detector list. A body nothing in that list recognises is
    exactly the body worth keeping — it is the case no detector was written for, which
    is the whole reason the model is in the loop."""
    url = "http://127.0.0.1:5000/api/Widgets/9"
    body = '{"acceptedDiscount":250,"orderTotal":-40}'
    sess = _session(_Cage({url: (200, body)}))
    recs = _run(sess, f"request GET {url}")
    from brukal.assist import highlight_findings
    assert not highlight_findings(body), "fixture no longer exercises the no-highlight path"
    assert "orderTotal" in " ".join(str(r.get("summary", "")) for r in recs)


def test_the_captured_body_is_bounded():
    """A record is a digest, not a dump — blackboard.py exists so huge output never
    accumulates in anyone's context."""
    url = "http://127.0.0.1:5000/api/Big"
    sess = _session(_Cage({url: (200, "A" * 40000)}))
    recs = _run(sess, f"request GET {url}")
    assert recs and all(len(str(r.get("summary", ""))) < 2000 for r in recs)


def test_a_response_that_was_not_executed_records_no_body():
    """No result, nothing to capture — and no invented one."""
    url = "http://127.0.0.1:5000/api/Nope"
    sess = _session(_Cage({}))
    recs = _run(sess, f"request GET {url}")
    assert recs and all("(no output)" not in str(r.get("summary", "")) for r in recs)


# -- capturing more must not capture the credential ---------------------------

@pytest.fixture(autouse=True)
def _clean_registry():
    redact.clear()
    yield
    redact.clear()


def test_a_session_token_reflected_in_the_captured_body_is_masked_in_the_record():
    """The body is target-controlled text on a record surface. An application that
    echoes the Authorization header back — a debug route, a /whoami, a verbose error —
    would put the live credential into the finding stream through the new capture."""
    token = "eyJhbGciOiJIUzI1NiJ9.QUJDREVGR0hJSktMTU5PUFFS.c2lnbmF0dXJlLXZhbHVl"
    redact.register_auth_header(f"Bearer {token}")
    url = "http://127.0.0.1:5000/rest/user/whoami"
    sess = _session(_Cage({url: (200, '{"echo":"Authorization: Bearer ' + token + '"}')}))
    recs = _run(sess, f"request GET {url}")
    blob = " ".join(str(r) for r in recs)
    assert token not in blob, "the captured body leaked the session token"
    assert "REDACTED" in blob


def test_a_session_cookie_reflected_in_the_captured_body_is_masked_in_the_record():
    secret = "s%3A9fL2kQvT7xN4bZ.aGVsbG8td29ybGQtc2VjcmV0LXZhbHVl"
    redact.register(secret)
    url = "http://127.0.0.1:5000/debug/echo"
    sess = _session(_Cage({url: (200, '{"cookie":"token=' + secret + '"}')}))
    recs = _run(sess, f"request GET {url}")
    blob = " ".join(str(r) for r in recs)
    assert secret not in blob
    assert "REDACTED" in blob
