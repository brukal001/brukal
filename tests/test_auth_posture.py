"""Authentication-posture classes a competitor found and Brukal had no check for.

Session fixation, enumeration via the RECOVERY endpoint (a different handler from the
login, usually written with less care and reachable with no credential at all), and the
absence of any server-side password policy.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import parse_qs

from brukal import AuditLog, Executor, Gate, load_scope, webmap
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000"


def _sess(cage, intrusive=True):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = intrusive
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    return s


# --- session fixation ----------------------------------------------------------------

class _Login:
    """`rotates` decides whether a new session id is issued when privilege changes."""

    def __init__(self, rotates: bool):
        self.rotates = rotates
        self.n = 0

    def run(self, action):
        if action.method == "POST":
            if self.rotates:
                self.n += 1
                return WebResult(status=302, url=action.url, body="",
                                 headers={"Location": "/app",
                                          "Set-Cookie": f"sid=rotated{self.n}; Path=/"})
            # The flaw: authenticated, same identifier the stranger was handed.
            return WebResult(status=302, url=action.url, body="",
                             headers={"Location": "/app"})
        return WebResult(status=200, url=action.url,
                         headers={"Set-Cookie": "sid=anonymous-value-1234; Path=/"},
                         body='<form><input name="password" type="password"></form>')


def test_an_unrotated_session_identifier_is_confirmed():
    s = _sess(_Login(rotates=False))
    assert s.confirm_session_fixation(f"{ROOT}/login", "u", "p") is True
    f = s.findings.all()[0]
    assert f.confirmed and f.severity == "high"
    assert "still the session identifier" in f.evidence


def test_an_app_that_rotates_yields_nothing():
    s = _sess(_Login(rotates=True))
    assert s.confirm_session_fixation(f"{ROOT}/login", "u", "p") is False
    assert not s.findings.all()


def test_fixation_does_not_disturb_our_own_session():
    """It logs in as somebody to compare identifiers; our own must survive."""
    s = _sess(_Login(rotates=False))
    s.browser._cookies = {"sid": "ours"}
    s.identity = "me"
    s.confirm_session_fixation(f"{ROOT}/login", "u", "p")
    assert s.browser._cookies == {"sid": "ours"} and s.identity == "me"


# --- enumeration via the recovery endpoint -------------------------------------------

class _Recovery:
    def __init__(self, leaks: bool):
        self.leaks = leaks

    def run(self, action):
        who = (parse_qs(action.body or "").get("login") or [""])[0]
        if self.leaks and who == "realuser":
            return WebResult(status=302, url=action.url, body="",
                             headers={"Location": "/forgotpw?sent=1"})
        return WebResult(status=302, url=action.url, body="",
                         headers={"Location": "/forgotpw?error=nouser"})


def test_a_recovery_endpoint_that_answers_differently_is_confirmed():
    s = _sess(_Recovery(leaks=True))
    assert s.confirm_recovery_enumeration(f"{ROOT}/forgotpw", "realuser") is True
    f = s.findings.all()[0]
    assert f.confirmed and "stranger can test any address" in f.evidence


def test_a_uniform_recovery_endpoint_yields_nothing():
    s = _sess(_Recovery(leaks=False))
    assert s.confirm_recovery_enumeration(f"{ROOT}/forgotpw", "realuser") is False


def test_an_echoing_recovery_endpoint_cannot_fake_it():
    """The submitted address is removed from both bodies before they are compared —
    otherwise any endpoint that repeats what it was given proves enumeration."""
    class _Echoes:
        def run(self, action):
            who = (parse_qs(action.body or "").get("login") or [""])[0]
            return WebResult(status=200, url=action.url, headers={},
                             body=f"<p>If {who} exists we sent a link.</p>")
    s = _sess(_Echoes())
    assert s.confirm_recovery_enumeration(f"{ROOT}/forgotpw", "realuser") is False


def test_recovery_endpoints_are_found_from_the_crawl():
    s = _sess(_Recovery(leaks=True))
    s.surface.forms.append(webmap.Form(action=f"{ROOT}/forgotpw", method="POST",
                                       inputs=(("login", "text"),)))
    assert (f"{ROOT}/forgotpw", "login") in s.recovery_endpoints()


# --- password policy ------------------------------------------------------------------

class _Signup:
    """`enforces` decides whether a one-character password is refused."""

    def __init__(self, enforces: bool):
        self.enforces, self.accounts = enforces, {}

    def run(self, action):
        body = parse_qs(action.body or "")
        one = lambda k: (body.get(k) or [""])[0]
        if action.url.endswith("/register") and action.method == "POST":
            if self.enforces and len(one("password")) < 8:
                return WebResult(status=200, url=action.url, headers={},
                                 body="<p>Password too short</p>"
                                      '<input name="password" type="password">')
            self.accounts[one("username")] = one("password")
            return WebResult(status=302, url=action.url, body="",
                             headers={"Location": "/app", "Set-Cookie": "sid=new1"})
        if action.url.endswith("/login") and action.method == "POST":
            if self.accounts.get(one("username")) == one("password"):
                return WebResult(status=302, url=action.url, body="",
                                 headers={"Location": "/app", "Set-Cookie": "sid=li1"})
            return WebResult(status=302, url=action.url, body="bad",
                             headers={"Location": "/login"})
        return WebResult(status=200, url=action.url, headers={},
                         body='<form><input name="password" type="password"></form>')


def _with_signup(s):
    s.surface.forms.append(webmap.Form(
        action=f"{ROOT}/register", method="POST",
        inputs=(("username", "text"), ("password", "password"))))
    s.surface.add_routes(["/login"])
    return s


def test_a_one_character_password_that_works_is_confirmed():
    s = _with_signup(_sess(_Signup(enforces=False)))
    assert s.confirm_weak_password_policy() is True
    f = s.findings.all()[0]
    assert f.confirmed and "authenticated with it" in f.evidence


def test_an_app_that_enforces_a_policy_yields_nothing():
    s = _with_signup(_sess(_Signup(enforces=True)))
    assert s.confirm_weak_password_policy() is False
    assert not s.findings.all()


def test_the_policy_check_needs_intrusive_consent():
    """It creates a real account."""
    s = _with_signup(_sess(_Signup(enforces=False), intrusive=False))
    assert s.confirm_weak_password_policy() is False
