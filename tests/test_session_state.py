"""
test_session_state.py — one object for who we are.

The facts of a session were spread over six attributes on two objects. `has_session()`
exists because code kept asking `if self.last_jwt` when it meant "am I logged in" —
five defects traced to that one substitution. Consolidating the state is how that stops
being possible; the properties keep every existing call site working.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.auth import SessionState
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult


class _Cage:
    def run(self, action):
        return WebResult(status=200, url=action.url, body="")


def _session():
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession("127.0.0.1", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, _Cage(), audit))


def test_the_properties_read_and_write_through_to_session_state():
    s = _session()
    s.identity = "alice"
    s.authenticated = True
    s.last_jwt = "eyJ.a.b"
    assert s.session.identity == "alice"
    assert s.session.authenticated is True
    assert s.session.last_jwt == "eyJ.a.b"


def test_writing_session_state_is_visible_through_the_properties():
    s = _session()
    s.session.identity = "bob"
    assert s.identity == "bob"


def test_snapshot_and_restore_round_trip():
    """_separate_identity depends on this: act as somebody else, then be ourselves
    again. An earlier hand-rolled version forgot `identity`, so proving a takeover
    quietly renamed US to the VICTIM."""
    s = _session()
    s.identity = "alice"
    s.authenticated = True
    s._login_password = "pw1"
    snap = s.session.snapshot()

    s.identity = "victim"
    s.authenticated = False
    s._login_password = "pw2"

    s.session.restore(snap)
    assert s.identity == "alice"
    assert s.authenticated is True
    assert s._login_password == "pw1"


def test_a_fresh_session_state_is_empty_not_none():
    st = SessionState()
    assert st.identity == ""
    assert st.authenticated is False
    assert st.last_jwt == ""
