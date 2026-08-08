"""
test_principal.py — one object for who we are.

The facts of a session were spread over six attributes on two objects. `has_session()`
exists because code kept asking `if self.last_jwt` when it meant "am I logged in" —
five defects traced to that one substitution. Consolidating the state is how that stops
being possible; the properties keep every existing call site working.

Named `Principal`, not `SessionState`: `brukal.sessions` already defines a different,
package-exported `SessionState` (the mirrored state of a live shell session), and the
two must never be confused — this object answers "who are we", that one answers
"what is happening on session N".
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.auth import Principal
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


def test_the_properties_read_and_write_through_to_principal():
    s = _session()
    s.identity = "alice"
    s.authenticated = True
    s.last_jwt = "eyJ.a.b"
    assert s.principal.identity == "alice"
    assert s.principal.authenticated is True
    assert s.principal.last_jwt == "eyJ.a.b"


def test_writing_principal_is_visible_through_the_properties():
    s = _session()
    s.principal.identity = "bob"
    assert s.identity == "bob"


def test_snapshot_and_restore_round_trip():
    """_separate_identity depends on this: act as somebody else, then be ourselves
    again. An earlier hand-rolled version forgot `identity`, so proving a takeover
    quietly renamed US to the VICTIM. All seven fields are asserted here — the whole
    point of this test is that a hand-rolled save/restore can silently forget one."""
    s = _session()
    s.identity = "alice"
    s.authenticated = True
    s.last_jwt = "eyJ.a.b"
    s._login_url = "https://t/login"
    s._login_type = "form"
    s._login_password = "pw1"
    s.principal.strategy = "form"
    snap = s.principal.snapshot()

    s.identity = "victim"
    s.authenticated = False
    s.last_jwt = "eyJ.v.v"
    s._login_url = "https://t/other-login"
    s._login_type = "json"
    s._login_password = "pw2"
    s.principal.strategy = "json"

    s.principal.restore(snap)
    assert s.identity == "alice"
    assert s.authenticated is True
    assert s.last_jwt == "eyJ.a.b"
    assert s._login_url == "https://t/login"
    assert s._login_type == "form"
    assert s._login_password == "pw1"
    assert s.principal.strategy == "form"


def test_a_fresh_principal_is_empty_not_none():
    p = Principal()
    assert p.identity == ""
    assert p.authenticated is False
    assert p.last_jwt == ""


def test_new_bypassed_construction_still_gets_an_empty_principal():
    """tests/test_specmining.py builds AssistSession via `AssistSession.__new__
    (AssistSession)`, skipping __init__ entirely, then assigns `sess.last_jwt =
    "tok"` directly. That only works because `_ensure_principal()` lazily creates
    the Principal on first property touch instead of requiring __init__ to have
    run. Pinning it here so a future "restore the brief" pass that inlines the
    Principal() assignment back into __init__ fails loudly, with a name that
    points at the mechanism, rather than failing three unrelated spec-mining
    tests with no clue why."""
    sess = AssistSession.__new__(AssistSession)
    assert sess.identity == ""
    assert sess.authenticated is False
    sess.last_jwt = "tok"
    assert sess.last_jwt == "tok"
