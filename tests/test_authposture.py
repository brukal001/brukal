"""
test_authposture.py — the three gaps a competing tool found and Brukal did not.

Measured on VAmPI: PentestGPT reported an exposed debug console, username enumeration
and unthrottled login, all with real evidence, where Brukal reported nothing. These are
the detectors that close that gap — and every one of them is a DIFFERENTIAL, because a
single observation cannot tell "the app leaked something" from "that is just how it
answers everyone".
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession, _norm_body
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
TARGET = "127.0.0.1"
B = "http://127.0.0.1:5000"
LOGIN = B + "/users/v1/login"


def _session(cage, intrusive: bool = True):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))
    sess.allow_intrusive = intrusive
    sess.identity = "realuser"
    return sess


# -- interactive debug console ------------------------------------------------

class _Console:
    def __init__(self, body): self.body = body
    def run(self, action):
        return WebResult(status=200, url=action.url, body=self.body)


def test_werkzeug_console_is_critical_not_an_info_leak():
    body = ('<title>Console // Werkzeug Debugger</title>'
            '<script src="?__debugger__=yes&cmd=resource&f=debugger.js"></script>'
            'SECRET = "qxdVlduNAf0ujknuvhbi";')
    sess = _session(_Console(body))
    assert sess.confirm_debug_console(B) is True
    f = sess.findings.all()[0]
    assert f.severity == "critical"          # a remote REPL, not an information leak
    assert "SECRET=qxdVlduNAf" in f.evidence


def test_an_ordinary_200_is_not_a_debug_console():
    """Plenty of apps serve something at /console. Only the framework's own debugger
    markers count."""
    sess = _session(_Console("<h1>Admin console</h1><p>Please sign in.</p>"))
    assert sess.confirm_debug_console(B) is False
    assert not sess.findings.all()


# -- username enumeration -----------------------------------------------------

class _Login:
    """`distinct` decides whether the app answers differently for a missing account.
    `echo` makes it repeat the submitted username, which is the false-positive trap."""

    def __init__(self, distinct: bool, echo: bool = False, ok_password: str = ""):
        self.distinct, self.echo, self.ok_password = distinct, echo, ok_password
        self.calls = 0

    def run(self, action):
        self.calls += 1
        body = json.loads(action.body or "{}")
        user, pw = body.get("username", ""), body.get("password", "")
        if self.ok_password and pw == self.ok_password:
            return WebResult(status=200, url=action.url,
                             body=json.dumps({"auth_token": "t"}))
        exists = user == "realuser"
        if self.distinct and not exists:
            msg = f"Username {user} does not exist" if self.echo else "Username does not exist"
            return WebResult(status=404, url=action.url,
                             body=json.dumps({"message": msg}))
        msg = f"Password is not correct for {user}" if self.echo else "Password is not correct"
        return WebResult(status=401, url=action.url, body=json.dumps({"message": msg}))


def test_distinct_answers_confirm_an_enumeration_oracle():
    sess = _session(_Login(distinct=True))
    assert sess.confirm_user_enumeration(LOGIN, "realuser") is True
    assert sess.findings.all()[0].severity == "medium"


def test_identical_answers_are_the_correct_behaviour_and_yield_nothing():
    sess = _session(_Login(distinct=False))
    assert sess.confirm_user_enumeration(LOGIN, "realuser") is False
    assert not sess.findings.all()


def test_an_app_that_merely_echoes_the_username_is_not_an_oracle():
    """The false positive this check would otherwise always produce: the bodies differ
    only because they contain the different names WE submitted."""
    sess = _session(_Login(distinct=False, echo=True))
    assert sess.confirm_user_enumeration(LOGIN, "realuser") is False
    assert not sess.findings.all()


def test_norm_body_removes_our_own_input():
    assert _norm_body("no such user: bob", "bob") == _norm_body("no such user: amy", "amy")


# -- missing rate limiting ----------------------------------------------------

class _Throttler:
    def __init__(self, throttle_after: int | None):
        self.throttle_after, self.calls = throttle_after, 0

    def run(self, action):
        self.calls += 1
        if self.throttle_after is not None and self.calls > self.throttle_after:
            return WebResult(status=429, url=action.url,
                             body='{"message":"Too many requests"}')
        return WebResult(status=401, url=action.url, body='{"message":"bad"}')


def test_unthrottled_login_is_confirmed():
    sess = _session(_Throttler(throttle_after=None))
    assert sess.confirm_missing_rate_limit(LOGIN, "realuser", attempts=6) is True
    assert "6 consecutive failed logins" in sess.findings.all()[0].evidence


def test_a_throttling_app_yields_no_finding():
    sess = _session(_Throttler(throttle_after=3))
    assert sess.confirm_missing_rate_limit(LOGIN, "realuser", attempts=8) is False
    assert not sess.findings.all()


def test_brute_force_probe_needs_authorisation_because_it_can_lock_an_account():
    api = _Throttler(throttle_after=None)
    sess = _session(api, intrusive=False)
    assert sess.confirm_missing_rate_limit(LOGIN, "realuser") is False
    assert api.calls == 0


# -- wiring: the lesson from confirm_mass_assignment --------------------------

def _surface(routes):
    from brukal.webmap import AttackSurface
    s = AttackSurface(seed=B + "/")
    s.add_routes(list(routes))
    return s


class _Quiet:
    def run(self, action):
        return WebResult(status=404, url=action.url, body="{}")


def test_confirm_surface_invokes_all_three_new_checks():
    """A detector the autonomous path never calls is worth nothing — the exact defect
    that left mass-assignment unfound across three live runs."""
    sess = _session(_Quiet())
    sess.surface = _surface(["/users/v1", "/users/v1/login"])
    sess.last_jwt = "tok"
    called = set()
    sess.confirm_debug_console = lambda *a, **k: called.add("debug") is None and False
    sess.confirm_user_enumeration = lambda *a, **k: called.add("enum") is None and False
    sess.confirm_missing_rate_limit = lambda *a, **k: called.add("rate") is None and False
    sess.confirm_surface()
    assert called == {"debug", "enum", "rate"}


def test_rate_limit_probe_is_skipped_without_authorisation():
    sess = _session(_Quiet(), intrusive=False)
    sess.surface = _surface(["/users/v1", "/users/v1/login"])
    called = set()
    sess.confirm_missing_rate_limit = lambda *a, **k: called.add("rate") is None and False
    sess.confirm_user_enumeration = lambda *a, **k: called.add("enum") is None and False
    sess.confirm_surface()
    assert "rate" not in called and "enum" in called   # read-only one still runs


# -- the live-run regression: a 200 is not a successful login ------------------

class _AlwaysTwoHundred:
    """VAmPI's real shape: HTTP 200 for BOTH failure modes, differing only in the
    message. The first version of this check assumed 200 meant a successful login and
    so skipped every API that answers this way — nine green unit tests missed it
    because the fixture returned 401/404, which was self-consistent but not
    reality-consistent."""

    def run(self, action):
        user = json.loads(action.body or "{}").get("username", "")
        msg = ("Password is not correct for the given username."
               if user == "realuser" else "Username does not exist")
        return WebResult(status=200, url=action.url,
                         body=json.dumps({"status": "fail", "message": msg}))


def test_enumeration_is_found_when_failures_answer_http_200():
    sess = _session(_AlwaysTwoHundred())
    assert sess.confirm_user_enumeration(LOGIN, "realuser") is True
    assert "does not exist" in sess.findings.all()[0].evidence


class _RealLogin:
    """Answers 200 WITH a token — the password was not wrong after all."""

    def run(self, action):
        return WebResult(status=200, url=action.url,
                         body=json.dumps({"auth_token": "eyJhbGciOi.payload.signature"}))


def test_a_response_carrying_a_session_is_not_treated_as_a_failed_login():
    sess = _session(_RealLogin())
    assert sess.confirm_user_enumeration(LOGIN, "realuser") is False
    assert not sess.findings.all()
