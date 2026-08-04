"""A session is a session, however it is carried.

Five separate defects this session traced to one substitution: code asking
`if self.last_jwt` when it meant "am I logged in". That is not the same question — it is
"am I logged in to a JSON API that issues bearer tokens" — and on a cookie-session
application the answer was always no. The BFLA targeting, the BOLA sweep, the model's
authentication briefing and the comparator that judges denial all silently did nothing,
each while a coverage row claimed it had run.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000"


class _Cage:
    def __init__(self, mode="cookie"):
        self.mode = mode

    def run(self, action):
        if action.method == "POST":
            if self.mode == "cookie":
                return WebResult(status=302, url=action.url, body="",
                                 headers={"Location": "/app", "Set-Cookie": "sid=abc"})
            return WebResult(status=200, url=action.url,
                             body='{"auth_token": "tok-s3ss10nvalue"}', headers={})
        return WebResult(status=200, url=action.url, headers={},
                         body='<form><input name="password" type="password"></form>')


def _sess(mode="cookie"):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, _Cage(mode), audit))


def test_a_cookie_login_is_a_session():
    s = _sess("cookie")
    assert s.has_session() is False
    assert s.login(f"{ROOT}/login", "u", "p")
    assert s.has_session() is True
    assert s.session_token() == "", "a cookie session has no bearer token"


def test_a_token_login_is_a_session():
    s = _sess("token")
    assert s.login(f"{ROOT}/login", "u", "p", login_type="json")
    assert s.has_session() is True
    assert s.session_token(), "a token session must expose its token"


def test_authz_targeting_no_longer_requires_a_token():
    """`bfla_targets` returned None the moment last_jwt was empty, so the whole
    authorization family was unreachable on any cookie-session application."""
    from brukal import webmap
    s = _sess("cookie")
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.add_routes(["/users/{username}/password"])
    s.surface.write_operations.append(("PUT", "/users/{username}/password"))
    assert s.bfla_targets() is None, "no session yet: nothing to target"
    assert s.login(f"{ROOT}/login", "u", "p")
    # With a cookie session it may now proceed as far as the victim search, which is
    # exactly the step that never ran before.
    assert s.has_session() is True


def test_an_error_status_is_never_a_successful_login():
    """The third distinct way login() claimed a session it did not have. All three were
    the same mistake: inferring success from the ABSENCE of a password field rather than
    from evidence of a session."""
    class _Rejects:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=400, url=action.url,
                                 body='{"message":"malformed"}', headers={})
            return WebResult(status=200, url=action.url, headers={},
                             body='<form><input name="password" type="password"></form>')
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Rejects(), audit))
    assert s.login(f"{ROOT}/login", "u", "p") is False
    assert s.has_session() is False


def test_acting_as_another_principal_does_not_rename_us():
    """login() adopts the first username it authenticates when `identity` is empty, so
    proving a takeover could quietly rename US to the VICTIM — and every later check
    asking "whose objects are ours" would reason about the wrong account."""
    s = _sess("cookie")
    assert s.login(f"{ROOT}/login", "me", "p")
    assert s.identity == "me"
    with s._separate_identity():
        s.login(f"{ROOT}/login", "victim", "p")
    assert s.identity == "me"


def test_a_200_that_is_not_the_login_page_is_not_a_session():
    """The fourth face of the same mistake. "The answer no longer shows a password
    field" is true of a redirect, of a 400, and of any 200 that simply is not the login
    page — "your account is locked" has no password field either. A login that worked
    hands back a credential; requiring that is the difference between observing success
    and failing to observe failure."""
    class _Locked:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=200, url=action.url, headers={},
                                 body="<h1>Your account is locked.</h1>")
            return WebResult(status=200, url=action.url, headers={},
                             body='<form><input name="password" type="password"></form>')
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Locked(), audit))
    assert s.login(f"{ROOT}/login", "u", "p") is False
    assert s.has_session() is False


def test_a_200_that_issues_a_cookie_is_a_session():
    """The other direction must keep working: plenty of apps answer 200 and set the
    session cookie without redirecting."""
    class _SetsCookie:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=200, url=action.url,
                                 headers={"Set-Cookie": "sid=xyz; Path=/"},
                                 body="<h1>Welcome back</h1>")
            return WebResult(status=200, url=action.url, headers={},
                             body='<form><input name="password" type="password"></form>')
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _SetsCookie(), audit))
    assert s.login(f"{ROOT}/login", "u", "p") is True
