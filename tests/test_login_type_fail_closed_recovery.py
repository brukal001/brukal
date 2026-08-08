"""
test_login_type_fail_closed_recovery.py — a refused login type must not stick.

login()'s fail-closed branch used to record `_login_type` BEFORE the strategy
lookup, so a call like `login(..., login_type="oauth2")` that gets correctly
refused still left `_login_type == "oauth2"` on the Principal. Everything reading
that field afterwards assumed it named a strategy `login()` actually knows —
confirm_default_credentials calls `getattr(self, "_login_type", "form") or
"form"`, and "oauth2" is truthy, so the fallback to "form" never fired. The
detector was then handed a login_type it also refuses, fails closed on every
attempt, and still emits a coverage row claiming it ran — a coverage lie, not
merely a wrong default.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

LOGIN = "http://127.0.0.1:5000/login"


class _CookieApp:
    def __init__(self):
        self._cookies = {}
        self.auth_header = ""

    def run(self, action):
        if (getattr(action, "method", "") or "GET").upper() == "POST":
            self._cookies["sid"] = "authed"
            return WebResult(status=302, url=action.url, body="",
                             headers={"Location": "/home",
                                      "Set-Cookie": "sid=authed"})
        return WebResult(status=200, url=action.url,
                         body='<input type="password" name="password">')


def _session(cage):
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession("127.0.0.1", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))


def test_a_refused_login_type_does_not_stick_on_the_principal():
    s = _session(_CookieApp())
    assert s.login(LOGIN, "u", "p", login_type="oauth2") is False
    # The refused type must not be recorded: it must not survive to poison the
    # `getattr(self, "_login_type", "form") or "form"` fallback that
    # confirm_default_credentials and the BFLA proof both rely on.
    assert getattr(s, "_login_type", "") == ""


def test_a_refused_login_type_leaves_the_default_credentials_fallback_recoverable():
    s = _session(_CookieApp())
    s.login(LOGIN, "u", "p", login_type="oauth2")
    # This is the exact expression confirm_default_credentials is called with in
    # the autonomous path (assist.py). Before the fix it evaluated to "oauth2" —
    # a type login() itself refuses — so the detector could never fire while still
    # claiming coverage. After the fix it recovers to "form".
    assert (getattr(s, "_login_type", "form") or "form") == "form"


def test_a_resolved_login_type_still_sticks_for_a_later_refused_call():
    """A previously successful, resolved type must survive a later refused call —
    only the refused call's own type must never be recorded."""
    s = _session(_CookieApp())
    assert s.login(LOGIN, "u", "p", login_type="json") is False  # _CookieApp has no token
    assert s._login_type == "json"
    assert s.login(LOGIN, "u", "p", login_type="madeup") is False
    assert s._login_type == "json"
