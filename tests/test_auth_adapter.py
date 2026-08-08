"""
test_auth_adapter.py — login() still does everything it used to.

The adapter is where behaviour could change silently, so the side effects are pinned
individually rather than trusted to "the suite is green".
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
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
       ".eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWhlcmU")


class _TokenApi:
    _cookies: dict = {}
    auth_header = ""

    def run(self, action):
        if (getattr(action, "method", "") or "GET").upper() == "POST":
            return WebResult(status=200, url=action.url,
                             body='{"access_token":"%s"}' % JWT)
        return WebResult(status=200, url=action.url, body="{}")


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


def test_a_token_login_sets_the_bearer_header_and_identity():
    s = _session(_TokenApi())
    assert s.login(LOGIN, "alice", "pw", login_type="json") is True
    assert s.browser.auth_header == f"Bearer {JWT}"
    assert s.identity == "alice"
    assert s.last_jwt == JWT
    assert s.has_session() is True


def test_a_cookie_login_sets_identity_too():
    """This was once broken: identity was set only in the token branch, so every
    authz check asking 'whose objects are ours' never ran on a form-login app."""
    s = _session(_CookieApp())
    assert s.login(LOGIN, "bob", "pw") is True
    assert s.identity == "bob"
    assert s.has_session() is True


def test_the_login_url_is_remembered_for_later_cross_account_proofs():
    s = _session(_CookieApp())
    s.login(LOGIN, "bob", "pw")
    assert s._login_url == LOGIN


def test_the_login_note_never_contains_the_password():
    s = _session(_CookieApp())
    s.login(LOGIN, "bob", "hunter2SECRET")
    assert not any("hunter2SECRET" in n for n in s.notes)
    assert any("[login]" in n for n in s.notes)


def test_basic_auth_needs_no_request():
    s = _session(_TokenApi())
    assert s.login(LOGIN, "u", "p", login_type="basic") is True
    assert s.browser.auth_header.startswith("Basic ")


def test_basic_auth_currently_leaves_identity_empty():
    """CHARACTERISATION, not endorsement. This pins a KNOWN LATENT BUG so that A1
    cannot fix it by accident and A2 cannot regress it by accident.

    Leaving `identity` empty is the same defect that silently disabled five checks on
    cookie-session apps: every authz test that asks "whose objects are ours" reads
    it. On a Basic-auth target those tests reason about the wrong principal.

    A2 will invert this assertion together with the fix. If you are reading this
    because it failed, check whether you MEANT to fix it — and if so, change the
    assertion deliberately rather than deleting the test."""
    s = _session(_TokenApi())
    s.login(LOGIN, "u", "p", login_type="basic")
    assert s.identity == ""
    assert any("HTTP Basic as u" in n for n in s.notes)


def test_a_failed_login_leaves_no_session():
    class _Reject:
        _cookies: dict = {}
        auth_header = ""

        def run(self, action):
            return WebResult(status=401, url=action.url, body="Unauthorized")

    s = _session(_Reject())
    assert s.login(LOGIN, "u", "bad") is False
    assert s.authenticated is False


def test_a_rejected_token_still_sets_identity_and_password():
    """CHARACTERISATION of a latent bug, restored deliberately after the adapter
    briefly lost it. Old login()'s token branch set `identity`/`_login_password`
    UNCONDITIONALLY, before the oracle's final ok verdict — so a response carrying
    a token-shaped string but a >=400 status still set identity, even though the
    login is correctly reported as failed. Do not 'fix' this here: the phase
    contract is zero behaviour change, and the underlying bug gets its own
    deliberate fix and its own test later, same treatment as the Basic-auth
    identity gap."""
    class _TokenButRejected:
        _cookies: dict = {}
        auth_header = ""

        def run(self, action):
            if (getattr(action, "method", "") or "GET").upper() == "POST":
                return WebResult(status=401, url=action.url,
                                 body='{"access_token":"%s"}' % JWT)
            return WebResult(status=200, url=action.url, body="{}")

    s = _session(_TokenButRejected())
    assert s.login(LOGIN, "dave", "pw", login_type="json") is False
    assert s.identity == "dave"
    assert s._login_password == "pw"


def test_a_form_login_with_a_token_shaped_body_sets_the_bearer_header():
    """CHARACTERISATION of a second latent-bug restoration. Old login() set
    `auth_header` for every non-basic type, form included, whenever a token-shaped
    string turned up anywhere in the response body (extract_token's regex
    fallback matches `token: "<16+ chars>"` with no JSON required). Plenty of
    server-rendered pages embed exactly that in inline JS. Not fixed here for the
    same reason as the sibling test above."""
    TOKEN = "abcdefghijklmnopqrst"

    class _FormTokenLeak:
        def __init__(self):
            self._cookies = {}
            self.auth_header = ""

        def run(self, action):
            if (getattr(action, "method", "") or "GET").upper() == "POST":
                return WebResult(
                    status=302, url=action.url,
                    body='<script>var config = {token: "%s"};</script>' % TOKEN,
                    headers={"Location": "/home"})
            return WebResult(status=200, url=action.url, body="<form></form>")

    s = _session(_FormTokenLeak())
    s.login(LOGIN, "carol", "pw")   # default login_type="form"
    assert s.browser.auth_header == f"Bearer {TOKEN}"


def test_extract_token_is_still_a_staticmethod_on_the_session():
    """tests/test_auth_scan.py calls AssistSession._extract_token directly."""
    assert AssistSession._extract_token('{"token":"abcdefghijklmnop"}') == \
        "abcdefghijklmnop"
