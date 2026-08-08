"""
test_auth_adapter.py — login() still does everything it used to.

The adapter is where behaviour could change silently, so the side effects are pinned
individually rather than trusted to "the suite is green".
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

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
    class _CountingCage:
        def __init__(self):
            self._cookies = {}
            self.auth_header = ""
            self.calls = 0

        def run(self, action):
            self.calls += 1
            return WebResult(status=200, url=action.url, body="{}")

    cage = _CountingCage()
    s = _session(cage)
    assert s.login(LOGIN, "u", "p", login_type="basic") is True
    assert s.browser.auth_header.startswith("Basic ")
    assert cage.calls == 0


def test_basic_auth_sets_identity_like_every_other_strategy():
    """Was a latent bug, pinned during the A1 refactor and fixed here deliberately.

    Every authz check that asks "whose objects are ours" reads `identity`. Basic auth
    left it empty, so on a Basic-auth target those checks reasoned about the wrong
    principal — the same defect class that once disabled five checks on
    cookie-session apps, which is why has_session() exists."""
    s = _session(_TokenApi())
    s.login(LOGIN, "u", "p", login_type="basic")
    assert s.identity == "u"
    assert s._login_password == "p"
    # the distinct note is preserved; only the identity gap is closed
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
    deliberate fix and its own test in a later phase."""
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
    # The header is the more dangerous half: it rides on every later gated
    # request, so a rejected token still arming it is the part worth pinning.
    assert s.browser.auth_header == f"Bearer {JWT}"


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


def test_an_unrecognised_login_type_fails_closed():
    """MAINTAINER RULING: fail closed (CLAUDE.md invariant 2 — anything ambiguous
    is DENIED). The OLD code let an unrecognised login_type through with form
    encoding but gated the cookie/redirect success heuristics on `lt == "form"`
    exactly, so an unknown type could only ever succeed on a token. Routing
    unknown types to FormAuth instead (as the adapter briefly did) applies those
    heuristics unconditionally — reproduced: 18/140 measured old-vs-new cases
    flipped a FAILED login to AUTHENTICATED, the unsafe direction, and
    confirm_default_credentials builds on that verdict. Refusing to guess removes
    that direction entirely."""
    s = _session(_CookieApp())
    assert s.login(LOGIN, "u", "p", login_type="post") is False
    assert s.authenticated is False
    assert any("unrecognised login type" in n and "post" in n for n in s.notes)


def test_a_strategy_exception_propagates_instead_of_being_reported_as_bad_creds():
    """MAINTAINER RULING: remove the blanket except. The adapter briefly turned
    ANY strategy exception into `AuthAttempt(responded=False)`, so a read timeout
    reported identically to wrong credentials ('login may have FAILED — check
    creds') — erasing exactly the distinction this phase exists to provide.
    A strategy exception must propagate, as it did before the port."""
    class _Timeout:
        _cookies: dict = {}
        auth_header = ""

        def run(self, action):
            if (getattr(action, "method", "") or "GET").upper() == "POST":
                raise TimeoutError("target unreachable")
            return WebResult(status=200, url=action.url, body="<form></form>")

    s = _session(_Timeout())
    with pytest.raises(TimeoutError):
        s.login(LOGIN, "u", "p")


def test_extract_token_is_still_a_staticmethod_on_the_session():
    """tests/test_auth_scan.py calls AssistSession._extract_token directly."""
    assert AssistSession._extract_token('{"token":"abcdefghijklmnop"}') == \
        "abcdefghijklmnop"
