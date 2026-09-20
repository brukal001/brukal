"""
test_bfla.py — broken FUNCTION level authorization (OWASP API5).

BOLA is unauthorized reading; this is the write. A competing tool proved an admin
account takeover on a target where Brukal reported nothing, because Brukal only had the
read-side check. The flaw is strictly worse than BOLA — it ends with the attacker
holding a session for somebody else.

The load-bearing property under test is what counts as proof: a 200 from the change
endpoint means the server ACCEPTED the request, not that the credential moved. Only a
successful login as the victim, with a password we chose, settles it.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_destructive.json"  # this file PUTs another account's password (GAP #15)
TARGET = "127.0.0.1"
B = "http://127.0.0.1:5000"
CHANGE = B + "/users/v1/{username}/password"
LOGIN = B + "/users/v1/login"


class _Api:
    """A VAmPI-shaped API. `enforces` decides whether it checks that the caller owns
    the account whose password is being changed."""

    def __init__(self, enforces: bool = False, accepts_but_ignores: bool = False):
        self.enforces = enforces
        self.accepts_but_ignores = accepts_but_ignores
        self.passwords = {"victim": "originalpw", "attacker": "attackerpw"}
        self.writes = 0

    def run(self, action):
        url, method = action.url, (action.method or "GET").upper()
        # A JSON API answers 400 to a body it cannot parse; it does not raise. The
        # prover legitimately tries a urlencoded login as well as a JSON one, because it
        # cannot know which shape an unfamiliar app wants, and a fixture that explodes
        # on the second attempt is testing its own brittleness rather than the prover.
        try:
            body = json.loads(action.body or "{}") if action.body else {}
        except ValueError:
            return WebResult(status=400, url=url, body='{"message":"malformed"}')
        if url == LOGIN and method == "POST":
            u, p = body.get("username"), body.get("password")
            if self.passwords.get(u) == p:
                # Long enough to look like a real bearer token: the extractor requires
                # >= 12 characters, and no API issues a ten-character session token.
                return WebResult(status=200, url=url,
                                 body=json.dumps({"auth_token": f"tok-{u}-s3ss10nvalue"}))
            return WebResult(status=401, url=url, body='{"message":"bad creds"}')
        if url.endswith("/password") and method == "PUT":
            who = url.rsplit("/", 2)[-2]
            caller = ((action.headers or {}).get("Authorization", "")
                      .replace("Bearer tok-", "").split("-")[0])
            if self.enforces and who != caller:
                return WebResult(status=403, url=url, body='{"message":"forbidden"}')
            self.writes += 1
            if not self.accepts_but_ignores:
                self.passwords[who] = body.get("password")
            return WebResult(status=200, url=url, body='{"status":"success"}')
        return WebResult(status=404, url=url, body="{}")


def _session(cage, intrusive: bool = True, scope_path: str = SCOPE):
    scope = load_scope(scope_path)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))
    sess.allow_intrusive = intrusive
    sess.identity = "attacker"
    return sess


def _run(sess):
    return sess.confirm_bfla_password_takeover(CHANGE, LOGIN, "victim", "tok-attacker")


def test_takeover_is_confirmed_when_the_app_does_not_check_the_owner():
    sess = _session(_Api(enforces=False))
    assert _run(sess) is True
    f = sess.findings.all()[0]
    assert f.confirmed and f.severity == "critical"
    assert "logging in as 'victim'" in f.evidence


def test_no_finding_when_the_app_enforces_ownership():
    sess = _session(_Api(enforces=True))
    assert _run(sess) is False
    assert not sess.findings.all()


def test_a_200_that_did_not_actually_change_the_password_is_not_proof():
    """The whole point. An endpoint can accept the write and ignore it; without the
    confirming login this would be reported as a critical takeover that isn't real."""
    api = _Api(enforces=False, accepts_but_ignores=True)
    sess = _session(api)
    assert _run(sess) is False
    assert api.writes == 1                      # it did accept the write...
    assert not sess.findings.all()               # ...and we still refused to claim it


def test_nothing_is_written_without_authorisation():
    """This proof destroys a credential it cannot restore, so it must never run
    unasked."""
    api = _Api(enforces=False)
    sess = _session(api, intrusive=False)
    assert _run(sess) is False
    assert api.writes == 0


def test_a_target_where_our_password_already_works_is_not_claimed():
    """Control: if the chosen password already authenticates the victim, a later
    success proves nothing about our write."""
    api = _Api(enforces=False)
    api.passwords["victim"] = "Brukal-BFLA-Pr00f!"
    sess = _session(api)
    assert _run(sess) is False
    assert api.writes == 0                       # refused before writing anything


def test_untemplated_url_is_refused():
    sess = _session(_Api())
    assert sess.confirm_bfla_password_takeover(
        B + "/users/v1/victim/password", LOGIN, "victim", "tok-attacker") is False


# -- discovery + wiring -------------------------------------------------------

def _surface(routes, seed=B + "/"):
    from brukal.webmap import AttackSurface
    s = AttackSurface(seed=seed)
    s.add_routes(list(routes))
    return s


class _Listing:
    """Serves the user collection the victim is chosen from."""

    def run(self, action):
        return WebResult(status=200, url=action.url, body=json.dumps(
            {"users": [{"username": "attacker"}, {"username": "victim"}]}))


def test_victim_is_read_from_the_app_not_guessed():
    sess = _session(_Listing())
    sess.surface = _surface(["/users/v1", "/users/v1/login",
                             "/users/v1/{username}/password"])
    sess.last_jwt = "tok-attacker"
    change, login, victim = sess.bfla_targets()
    assert change == B + "/users/v1/{username}/password"
    assert login == B + "/users/v1/login"
    assert victim == "victim"          # NOT 'attacker' — acting on ourselves proves nothing


def test_no_targets_without_a_templated_state_changing_route():
    sess = _session(_Listing())
    sess.surface = _surface(["/users/v1", "/users/v1/login"])
    sess.last_jwt = "tok-attacker"
    assert sess.bfla_targets() is None


def test_no_targets_without_a_session():
    sess = _session(_Listing())
    sess.surface = _surface(["/users/v1", "/users/v1/login",
                             "/users/v1/{username}/password"])
    sess.last_jwt = ""
    assert sess.bfla_targets() is None


def test_confirm_surface_invokes_the_bfla_check():
    """The mass-assignment lesson: a detector the loop never calls is worth nothing.

    Uses the high-rate-limit scope: the intrusive passes are deliberately skipped once
    the scope limiter trips, so the default fixture's 30/min would make this test pass
    for the wrong reason (nothing ran at all)."""
    sess = _session(_Listing(), scope_path="tests/fixtures/scope_destructive.json")
    sess.surface = _surface(["/users/v1", "/users/v1/login",
                             "/users/v1/{username}/password"])
    sess.last_jwt = "tok-attacker"
    sess.allow_intrusive = True
    called = {}
    sess.confirm_bfla_password_takeover = \
        lambda *a, **k: called.setdefault("args", a) is None
    sess.confirm_surface()
    assert called.get("args") == (B + "/users/v1/{username}/password",
                                  B + "/users/v1/login", "victim", "tok-attacker")
