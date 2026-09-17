"""
test_signup_proof_of_account.py — proof that an account exists, not proof of one FORM of it.

THE MEASURED PROBLEM (CR1 pre-flight 3, crAPI, 2026-09-17 — GAP #5)
    Everything worked until the last step. The resolver found `/identity/api/auth/signup`,
    the field-discovery fix read crAPI's 400 and supplied `name` and `number`, and crAPI
    created the account:

        #152  POST /identity/api/auth/signup {minimal}       -> 400 (names name, number)
        #154  POST /identity/api/auth/signup {+name,+number} -> 200, 70 bytes
        #445/#447  the same pair again later in the run      -> 400 then 200

    crAPI answers `{"message":"User registered successfully! Please Login.","status":200}`.
    `_register_account_json` required the reply to ECHO THE EMAIL as proof, so both real
    accounts were discarded and the ledger recorded "self-registration did not yield an
    account" — false in a specific and damaging way: the accounts exist.

    Juice Shop's `POST /api/Users` returns the created user object. An echo was available
    there, and availability quietly became the DEFINITION of proof.

THE FIX
    The guard is right that a 2xx alone proves nothing — an SPA catch-all answers 200 to
    everything. It is wrong to demand one FORM of evidence. So the evidence is a ladder,
    cheapest first, and the strongest rung was already one line away in the caller:

        1. the reply NAMES the account            (no extra request)
        2. LOGGING IN as it succeeds              (one request, and decisive)

    Nothing else is accepted. A cheerful message with no echo and no working login is not
    an account, and still returns None with the reason recorded.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
SIGNUP = "/identity/api/auth/signup"
LOGIN = "/identity/api/auth/login"

# crAPI's real reply, verbatim.
CRAPI_OK = json.dumps({"message": "User registered successfully! Please Login.",
                       "status": 200})


class _CrapiSignup:
    """crAPI: signup answers a MESSAGE, and the account it made can log in."""

    def __init__(self, login_works=True, echo=False):
        self.accounts: dict = {}
        self.login_works = login_works
        self.echo = echo
        self.posts: list = []
        self.logins: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        path, method = urlsplit(action.url).path, (action.method or "GET").upper()
        body = {}
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            pass
        if path == SIGNUP and method == "POST":
            self.posts.append(body)
            missing = {"name", "number"} - set(body)
            if missing:
                det = "\n".join(f"Field error in object 'signUpForm' on field '{m}': "
                                f"default message [must not be blank]" for m in sorted(missing))
                return WebResult(status=400, url=action.url,
                                 body=json.dumps({"message": "Validation failed",
                                                  "details": det}))
            self.accounts[body.get("email", "")] = body.get("password", "")
            return WebResult(status=200, url=action.url,
                             body=json.dumps(body) if self.echo else CRAPI_OK)
        if path == LOGIN and method == "POST":
            email = body.get("email") or body.get("username") or ""
            self.logins.append(email)
            if self.login_works and self.accounts.get(email) == body.get("password"):
                return WebResult(status=200, url=action.url,
                                 body=json.dumps({"token": "eyJhbGciOiJSUzI1NiJ9.new.sig"}))
            return WebResult(status=401, url=action.url, body='{"message":"bad"}')
        return WebResult(status=404, url=action.url, body='{"message":"nope"}')


class _CheerfulLiar:
    """Answers 200 with a friendly message to everything and honours no login. The SPA
    catch-all the original guard existed for."""

    def __init__(self):
        self.posts: list = []

    def run(self, action):
        if (action.method or "GET").upper() == "POST":
            self.posts.append(action.url)
        return WebResult(status=200, url=action.url, body=CRAPI_OK)


def _session(tmp_path, cage, routes=(SIGNUP, LOGIN)):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(routes))
    s.surface = surface
    s._login_url = f"{BASE}{LOGIN}"
    return s, audit


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_crAPIs_message_only_reply_still_yields_the_account(tmp_path):
    """THE DEFECT, with crAPI's real reply. The account exists; the harness must keep it."""
    cage = _CrapiSignup()
    s, _ = _session(tmp_path, cage)
    made = s._register_account_json()
    assert made is not None, "a real account was discarded because the reply did not echo"
    email, password = made
    assert cage.accounts.get(email) == password


def test_the_echo_path_is_unchanged_and_costs_no_extra_request(tmp_path):
    """BOUNDARY — Juice Shop's shape. An echo still proves it, with no login."""
    cage = _CrapiSignup(echo=True)
    s, _ = _session(tmp_path, cage)
    assert s._register_account_json() is not None
    assert cage.logins == [], "the cheapest rung was skipped when it was available"


def test_a_cheerful_200_that_cannot_LOG_IN_is_not_an_account(tmp_path):
    """The reason the guard exists, preserved. A catch-all that says 'registered!' to
    everything and honours no session yields nothing, with the reason recorded."""
    s, _ = _session(tmp_path, _CheerfulLiar())
    assert s._register_account_json() is None
    assert getattr(s, "signup_refusal", ""), "it failed without recording why"


def test_a_signup_that_works_but_whose_login_is_refused_yields_nothing(tmp_path):
    """Fail-closed: an account we cannot USE is not a second principal, and claiming one
    would put a false premise under every cross-account experiment."""
    s, _ = _session(tmp_path, _CrapiSignup(login_works=False))
    assert s._register_account_json() is None
    assert "could not log in" in (getattr(s, "signup_refusal", "") or "").lower()


def test_the_proof_is_recorded_so_a_reader_knows_WHICH_rung(tmp_path):
    """Two accounts proved different ways are different strengths of evidence, and the
    record says which — an echo is the application naming it, a login is us using it."""
    s, _ = _session(tmp_path, _CrapiSignup())
    s._register_account_json()
    assert any("proved by login" in n for n in s.notes), s.notes[-3:]
    s2, _ = _session(tmp_path / "b", _CrapiSignup(echo=True))
    s2._register_account_json()
    assert any("named by the application" in n for n in s2.notes), s2.notes[-3:]


def test_an_HTML_answer_is_still_refused_without_spending_a_login(tmp_path):
    """BOUNDARY: an SPA index page answering a JSON POST is not a signup, and must not
    cost a login request to find that out."""
    class _Html:
        def __init__(self): self.n = 0
        def run(self, action):
            self.n += 1
            return WebResult(status=200, url=action.url, body="<html><body>app</body></html>")
    cage = _Html()
    s, _ = _session(tmp_path, cage)
    assert s._register_account_json() is None
    assert cage.n <= 2, "it tried to log in against an HTML catch-all"


def test_the_second_principal_reaches_the_EXPERIMENTS(tmp_path):
    """End to end, the whole of B3: establish_second_identity returns a usable handle that
    is distinct from the first principal's."""
    s, _ = _session(tmp_path, _CrapiSignup())
    s.identity = "first@brukal.test"
    got = s.establish_second_identity()
    assert got and got != s.identity, got
    assert getattr(s, "_second_identity", None), "nothing was stored for `as: second`"
