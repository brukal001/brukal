# Authentication Generality — Phase A1 (Extract) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Brukal's authentication logic out of `assist.py` into a new `brukal/auth.py` built around a single extracted `SessionOracle` and an `AuthStrategy` registry, with **zero behaviour change**.

**Architecture:** `AssistSession.login()` becomes a thin adapter over `brukal/auth.py`. The hardened "did we actually get a session?" logic — currently fused to the form branch of `login()` — becomes `SessionOracle`, the one thing that can confirm a session, so every present and future strategy is judged by it. Today's three auth types port across as `FormAuth`, `JsonAuth`, `BasicAuth`. `SessionState` consolidates the six scattered session fields, exposed through delegating properties so no existing call site changes.

**Tech Stack:** Python 3.11+, stdlib only (`re`, `dataclasses`, `urllib.parse`, `base64`, `json`), pytest.

## Global Constraints

- **Zero behaviour change.** The entire existing suite must pass **unchanged** — no test edits, no assertion loosening. If a test needs changing, the port is wrong.
- **`AssistSession.login()` keeps its exact signature:** `login(self, login_url, username, password, user_field="username", pass_field="password", extra_fields=None, login_type="form") -> bool`. It has 8 internal call sites (`assist.py` lines 2558, 3188, 3316, 4224, 4347, 4440, 4561, 4585) and 3 test files depend on it.
- **`AssistSession._extract_token` stays a staticmethod** on `AssistSession` — `tests/test_auth_scan.py:202` calls `AssistSession._extract_token` directly, and `assist.py:2247` uses it outside login.
- **Five safety invariants hold** (see `CLAUDE.md`). Strategies receive the `GovernedBrowser` only — never a cage, never the `kali` object. No LLM anywhere in this phase.
- **Run tests with `/home/brute/brukal-venv/bin/python -m pytest`** from the repo root. The repo `.venv` lacks pytest.
- **Baseline is 774 passing tests** at commit `fa2f744`. Every task must end at 774 + the tests that task added.
- **Verify every new test FAILS when its fix is reverted.** A test that passes against broken code is worse than no test.

---

### Task 1: `SessionOracle` — the single session-confirmation authority

**Files:**
- Create: `brukal/auth.py`
- Test: `tests/test_auth_oracle.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `LoginProbe`, `AuthAttempt`, `SessionOracle` in `brukal/auth.py`
  - `AuthAttempt(strategy: str, token: str = "", gained_cookie: bool = False, responded: bool = False, status: int | None = None, headers: dict | None = None, body: str = "", pass_field: str = "password", cookie_login: bool = False)`
  - `SessionOracle().judge(attempt: AuthAttempt) -> bool`
  - `LoginProbe(url: str, status: int | None, headers: dict, body: str, cookies_set: dict, inputs: tuple)`

**Context for the implementer:** the logic being moved lives in `brukal/assist.py` lines 1654–1706. It has been wrong three separate ways in this codebase's history, and each wrong version shipped. All three were the same mistake: inferring success from the *absence* of a login form instead of positive evidence of a session. Port it exactly; do not "clean it up".

The one deliberate generalization: the original guards the fallback with `lt == "form"`. That condition really means "this is a cookie-carried login, not a token login", so it becomes the `cookie_login` flag. `FormAuth` will pass `True`, `JsonAuth` `False`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_oracle.py`:

```python
"""
test_auth_oracle.py — the one thing allowed to say "we have a session".

This logic has been wrong three times in this codebase, and every wrong version
shipped. Each was the same mistake: reading the ABSENCE of a login form as success.
A 302 bounced back to /login, a 4xx whose body has no password field, and an
"account locked" 200 all have no password field, and all three were once read as
AUTHENTICATED. Extracting the oracle is exactly the moment those lessons get lost,
so they are pinned here.
"""
from __future__ import annotations

from brukal.auth import AuthAttempt, SessionOracle


def _form(**kw):
    base = dict(strategy="form", responded=True, cookie_login=True,
                pass_field="password")
    base.update(kw)
    return AuthAttempt(**base)


def test_a_token_is_positive_evidence():
    assert SessionOracle().judge(
        AuthAttempt(strategy="json", token="eyJhbGciOi.abc.def", responded=True)) is True


def test_a_new_cookie_on_a_clean_200_is_a_session():
    assert SessionOracle().judge(
        _form(status=200, gained_cookie=True, body="<html>Dashboard</html>")) is True


def test_redirect_away_from_login_is_a_session():
    assert SessionOracle().judge(
        _form(status=302, headers={"Location": "/dashboard"}, body="")) is True


def test_redirect_back_to_login_is_not_a_session():
    """False positive #1. A 302 carries no body, so 'no password field in the
    response' is vacuously true — a failed login bounced to /login read as success."""
    assert SessionOracle().judge(
        _form(status=302, headers={"Location": "/login?err=1"}, body="")) is False


def test_an_error_status_is_never_a_session():
    """False positive #2. A JSON API answering 400 {"message":"malformed"} has no
    password field either."""
    assert SessionOracle().judge(
        _form(status=400, gained_cookie=True,
              body='{"message":"malformed"}')) is False


def test_a_locked_account_page_is_not_a_session():
    """False positive #3. 'Your account is locked' is a 200 with no password field
    and no new cookie."""
    assert SessionOracle().judge(
        _form(status=200, gained_cookie=False,
              body="<html>Your account is locked.</html>")) is False


def test_an_explicit_error_outranks_a_missing_form():
    assert SessionOracle().judge(
        _form(status=200, gained_cookie=True,
              body='{"status":"fail"}')) is False


def test_unauthorized_wording_outranks_a_missing_form():
    assert SessionOracle().judge(
        _form(status=200, gained_cookie=True,
              body="<html>Access denied</html>")) is False


def test_the_cookie_fallback_does_not_apply_to_a_token_login():
    """The guard that made this safe: a JSON API rejecting credentials answers
    {"status":"fail"} — which contains no password field — so the cookie heuristic
    would declare every failed API login a success."""
    assert SessionOracle().judge(
        AuthAttempt(strategy="json", token="", responded=True, cookie_login=False,
                    status=200, body='{"result":"nope"}')) is False


def test_last_resort_hint_only_when_nothing_else_is_available():
    """No new cookie at all, no error, and the form is gone: the only honest signal
    left is that the app replaced it with something that looks logged in."""
    assert SessionOracle().judge(
        _form(status=200, gained_cookie=False,
              body="<html>Welcome back — Log out</html>")) is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_oracle.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'brukal.auth'`

- [ ] **Step 3: Create `brukal/auth.py` with the oracle**

```python
"""
auth.py — how Brukal gets a session, and how it knows it has one.

Authentication used to be a single 145-line function inside assist.py with three
hard-coded branches, and the logic that decides whether a login WORKED was fused to
the form branch. That fusion is why this module exists: any new auth type added in
place would have re-derived the success test and re-made its mistakes, and that test
has already been wrong three times.

`SessionOracle` is the only thing allowed to confirm a session. Strategies attempt
authentication and return EVIDENCE; they never return a verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class LoginProbe:
    """One read of the login surface — the raw material every strategy scores."""
    url: str = ""
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: str = ""
    cookies_set: dict = field(default_factory=dict)
    inputs: tuple = ()          # tuple of (name, type) from the login form


@dataclass(frozen=True)
class AuthAttempt:
    """What a strategy OBSERVED. Deliberately not a verdict — only the oracle judges.

    `cookie_login` marks a session carried by a cookie jar rather than a token. The
    body heuristics below are only meaningful for those; applied to a token login
    they read every failed API login as a success.
    """
    strategy: str
    token: str = ""
    gained_cookie: bool = False
    responded: bool = False
    status: int | None = None
    headers: dict | None = None
    body: str = ""
    pass_field: str = "password"
    cookie_login: bool = False


class SessionOracle:
    """Does this attempt prove we hold a session?

    Ported verbatim from assist.py login() lines 1654-1706. Three shipped versions of
    this were wrong, all in the same way: inferring success from the ABSENCE of a
    login form rather than from positive evidence of a session. Do not simplify.
    """

    _REDIRECT = (301, 302, 303, 307, 308)
    _AUTH_ERROR_RE = re.compile(
        r"(?i)\b(?:unauthori[sz]ed|forbidden|access denied|not authenticated|"
        r"authentication (?:required|failed)|no authorization token|missing token|"
        r"invalid token|token (?:is )?(?:expired|missing)|login required|"
        r"permission denied)\b")
    _FAIL_JSON_RE = re.compile(r'"status"\s*:\s*"(?:fail|error)"', re.I)
    _LOGGED_IN_RE = re.compile(
        r"(?i)log ?out|sign ?out|welcome|dashboard|my account|profile")

    def judge(self, a: AuthAttempt) -> bool:
        # A token handed back by the app is unambiguous positive evidence.
        ok = bool(a.token)

        if not ok and a.responded and a.cookie_login:
            hdrs = a.headers or {}
            loc = hdrs.get("Location", "") or hdrs.get("location", "")
            body = a.body or ""
            redirected_away = (a.status in self._REDIRECT
                               and "login" not in loc.lower())
            no_login_form = bool(body) and a.pass_field not in body
            # An explicit failure in the body outranks the absence of a form.
            failed = bool(self._AUTH_ERROR_RE.search(body[:2000])
                          or self._FAIL_JSON_RE.search(body[:2000]))

            if a.status in self._REDIRECT:
                # A REDIRECT is decided by its DESTINATION, not by its body. A 302
                # carries little or no body, so "no password field" is vacuously
                # true for it, and a failed login bounced back to /login was read
                # as AUTHENTICATED.
                ok = bool(redirected_away and not failed)
            else:
                # POSITIVE evidence of a session, not merely the absence of a form.
                ok = bool(a.gained_cookie and not failed)
                if not ok and no_login_form and not failed and a.gained_cookie is False:
                    # No new cookie at all: the only remaining honest signal is that
                    # the app replaced the form with something that is not an error.
                    ok = bool(self._LOGGED_IN_RE.search(body[:4000]))

        # An error status is never a successful login, whatever the body looks like.
        if a.responded and (a.status or 0) >= 400:
            ok = False
        return ok
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_oracle.py -q`
Expected: PASS (10 tests)

- [ ] **Step 5: Verify the regression tests are real**

Temporarily change `ok = bool(redirected_away and not failed)` to `ok = True`.
Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_oracle.py -q`
Expected: `test_redirect_back_to_login_is_not_a_session` FAILS. Revert the change.

- [ ] **Step 6: Confirm nothing else broke and commit**

```bash
/home/brute/brukal-venv/bin/python -m pytest -q   # expect 784 passed
git add brukal/auth.py tests/test_auth_oracle.py
git commit -m "auth: one authority on whether a session exists"
```

---

### Task 2: `AuthStrategy` protocol and `FormAuth`

**Files:**
- Modify: `brukal/auth.py`
- Test: `tests/test_auth_strategies.py`

**Interfaces:**
- Consumes: `LoginProbe`, `AuthAttempt`, `SessionOracle` from Task 1
- Produces:
  - `Credentials(username: str, password: str, user_field: str = "username", pass_field: str = "password", extra_fields: dict | None = None)`
  - `AuthStrategy` protocol: `name: str`, `detect(probe: LoginProbe) -> float`, `authenticate(browser, url: str, creds: Credentials) -> AuthAttempt`
  - `extract_token(body: str) -> str`
  - `FormAuth`

**Context:** the form branch being ported is `assist.py` lines 1609–1637. It GETs the login page to seed a cookie session and collect hidden/submit inputs (CSRF tokens), then POSTs urlencoded. `gained_cookie` compares the jar before and after — that comparison is the positive evidence the oracle relies on, so it must be preserved exactly.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_strategies.py`:

```python
"""
test_auth_strategies.py — each way in, proven on its own.

A strategy returns EVIDENCE, never a verdict. These tests assert the evidence is
gathered correctly; whether it amounts to a session is SessionOracle's job and is
tested in test_auth_oracle.py.
"""
from __future__ import annotations

from brukal.auth import Credentials, FormAuth, LoginProbe, extract_token
from brukal.web import WebResult

LOGIN = "http://127.0.0.1:5000/login"


class _FormApp:
    """A cookie-session form login. Issues a CSRF token on GET and requires it back."""

    def __init__(self):
        self.seen: list = []
        self._cookies = {}
        self.auth_header = ""

    def run(self, action):
        self.seen.append(action)
        method = (getattr(action, "method", "") or "GET").upper()
        if getattr(action, "kind", "") == "get" or method == "GET":
            self._cookies["sid"] = "anon"
            return WebResult(
                status=200, url=action.url,
                body='<form method="post">'
                     '<input type="hidden" name="csrf" value="TOK1">'
                     '<input name="username"><input type="password" name="password">'
                     '</form>',
                headers={"Set-Cookie": "sid=anon; Path=/"})
        if "csrf=TOK1" not in (action.body or ""):
            return WebResult(status=403, url=action.url, body="bad csrf")
        self._cookies["sid"] = "authed"
        return WebResult(status=302, url=action.url, body="",
                         headers={"Location": "/dashboard",
                                  "Set-Cookie": "sid=authed; Path=/"})


def test_form_auth_recognises_a_password_form():
    probe = LoginProbe(url=LOGIN, status=200,
                       inputs=(("username", "text"), ("password", "password")))
    assert FormAuth().detect(probe) > 0.5


def test_form_auth_declines_a_page_with_no_password_field():
    probe = LoginProbe(url=LOGIN, status=200, inputs=(("q", "text"),))
    assert FormAuth().detect(probe) == 0.0


def test_form_auth_echoes_the_csrf_token_back():
    app = _FormApp()
    attempt = FormAuth().authenticate(
        app, LOGIN, Credentials(username="u", password="p"))
    posted = [a for a in app.seen if (getattr(a, "method", "") or "").upper() == "POST"]
    assert posted and "csrf=TOK1" in posted[0].body
    assert attempt.status == 302


def test_form_auth_reports_the_cookie_it_gained():
    app = _FormApp()
    attempt = FormAuth().authenticate(
        app, LOGIN, Credentials(username="u", password="p"))
    assert attempt.gained_cookie is True
    assert attempt.cookie_login is True
    assert attempt.responded is True


def test_form_auth_carries_the_pass_field_name_for_the_oracle():
    app = _FormApp()
    attempt = FormAuth().authenticate(
        app, LOGIN, Credentials(username="u", password="p", pass_field="pw"))
    assert attempt.pass_field == "pw"


def test_extract_token_handles_nested_json():
    assert extract_token('{"data":{"access_token":"abcdefghijklmno"}}') == "abcdefghijklmno"


def test_extract_token_ignores_a_short_value():
    assert extract_token('{"token":"short"}') == ""
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_strategies.py -q`
Expected: FAIL — `ImportError: cannot import name 'Credentials' from 'brukal.auth'`

- [ ] **Step 3: Add the protocol, `extract_token` and `FormAuth` to `brukal/auth.py`**

Append to `brukal/auth.py`:

```python
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str
    user_field: str = "username"
    pass_field: str = "password"
    extra_fields: dict | None = None


@runtime_checkable
class AuthStrategy(Protocol):
    """One way into an application.

    `detect` is DETERMINISTIC and evidence-based — never a guess from names, and
    never a model call. `authenticate` returns evidence; only SessionOracle judges.
    """
    name: str

    def detect(self, probe: LoginProbe) -> float: ...

    def authenticate(self, browser, url: str, creds: Credentials) -> AuthAttempt: ...


def extract_token(body: str) -> str:
    """Pull a bearer/JWT/session token out of a login response body — how token
    (non-cookie) APIs authenticate. Handles a top-level or one-level-nested JSON
    token field, with a regex fallback for non-JSON bodies. Real-world key names."""
    if not body:
        return ""
    keys = ("access_token", "accessToken", "id_token", "idToken", "token",
            "jwt", "authToken", "auth_token", "session_token", "sessionToken")
    try:
        import json as _json
        d = _json.loads(body)
        stack = [d]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                for k in keys:
                    v = cur.get(k)
                    if isinstance(v, str) and len(v) >= 12:
                        return v
                stack.extend(v for v in cur.values() if isinstance(v, dict))
    except Exception:
        pass
    m = re.search(r'"?(?:access_?token|id_?token|token|jwt)"?\s*[:=]\s*"?'
                  r'([A-Za-z0-9._~+/-]{16,})"?', body, re.I)
    return m.group(1) if m else ""


def _jar(browser) -> dict:
    return dict(getattr(browser, "_cookies", {}) or {})


class FormAuth:
    """HTML form login carrying a cookie session.

    GETs the login page first: that seeds the cookie session AND collects the hidden
    and submit inputs (CSRF tokens) the app will require back. Omitting them is a 403
    on any framework with CSRF enabled, which is most of them.
    """

    name = "form"

    def detect(self, probe: LoginProbe) -> float:
        if any(t.lower() == "password" for _n, t in probe.inputs):
            return 0.9
        return 0.0

    def authenticate(self, browser, url: str, creds: Credentials) -> AuthAttempt:
        from urllib.parse import urlencode

        from .web import WebAction

        _d, res = browser.run(WebAction("request", url=url, method="GET"))
        carried: dict = {}
        if res is not None and res.body:
            for tag in re.finditer(r"<input\b[^>]*>", res.body, re.I):
                t = tag.group(0)
                typ = (re.search(r'type=["\']?([\w-]+)', t, re.I)
                       or [None, "text"])[1].lower()
                nm = re.search(r'name=["\']([^"\']+)["\']', t, re.I)
                vl = re.search(r'value=["\']([^"\']*)["\']', t, re.I)
                if nm and typ in ("hidden", "submit") and \
                        nm.group(1) not in (creds.user_field, creds.pass_field):
                    carried[nm.group(1)] = vl.group(1) if vl else ""

        form = {creds.user_field: creds.username, creds.pass_field: creds.password,
                **carried, **(creds.extra_fields or {})}
        # What the jar held BEFORE the credentials went in. A login that works hands
        # back something new; comparing tells us so positively, instead of inferring it.
        before = set(_jar(browser).items())
        _d2, res2 = browser.run(WebAction(
            "request", url=url, method="POST", body=urlencode(form),
            headers={"Content-Type": "application/x-www-form-urlencoded"}))
        gained = bool(set(_jar(browser).items()) - before)

        return AuthAttempt(
            strategy=self.name,
            token=extract_token(res2.body if res2 is not None else ""),
            gained_cookie=gained,
            responded=res2 is not None,
            status=res2.status if res2 is not None else None,
            headers=(res2.headers or {}) if res2 is not None else {},
            body=(res2.body or "") if res2 is not None else "",
            pass_field=creds.pass_field,
            cookie_login=True)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_strategies.py -q`
Expected: PASS (7 tests)

- [ ] **Step 5: Verify the CSRF test is real**

Temporarily delete the `carried` inputs from the posted `form` dict (use only user/pass).
Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_strategies.py -q`
Expected: `test_form_auth_echoes_the_csrf_token_back` FAILS. Revert.

- [ ] **Step 6: Commit**

```bash
/home/brute/brukal-venv/bin/python -m pytest -q   # expect 791 passed
git add brukal/auth.py tests/test_auth_strategies.py
git commit -m "auth: a strategy gathers evidence, it does not render a verdict"
```

---

### Task 3: `JsonAuth` and `BasicAuth`

**Files:**
- Modify: `brukal/auth.py`
- Modify: `tests/test_auth_strategies.py`

**Interfaces:**
- Consumes: everything from Tasks 1–2
- Produces: `JsonAuth`, `BasicAuth`

**Context:** ported from `assist.py` lines 1602–1607 (basic) and 1622–1628 (json). `BasicAuth` makes **no request at all** — it sets the header and reports success; that is why it passes `responded=False`, which keeps the oracle's `>= 400` and cookie clauses inert. `JsonAuth` must pass `cookie_login=False`: this is the guard that stopped a JSON API's `{"status":"fail"}` from reading as authenticated.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth_strategies.py`:

```python
from brukal.auth import BasicAuth, JsonAuth, SessionOracle


class _JsonApi:
    def __init__(self, ok=True):
        self.ok = ok
        self.seen: list = []
        self._cookies = {}
        self.auth_header = ""

    def run(self, action):
        self.seen.append(action)
        if (getattr(action, "method", "") or "GET").upper() != "POST":
            return WebResult(status=404, url=action.url, body="")
        if self.ok:
            return WebResult(
                status=200, url=action.url,
                body='{"access_token":"eyJhbGciOiJIUzI1NiJ9.payload.sig"}')
        return WebResult(status=200, url=action.url, body='{"status":"fail"}')


def test_json_auth_posts_a_json_body_and_returns_the_token():
    api = _JsonApi(ok=True)
    attempt = JsonAuth().authenticate(
        api, LOGIN, Credentials(username="u", password="p", user_field="email"))
    posted = api.seen[-1]
    assert posted.headers["Content-Type"] == "application/json"
    assert '"email": "u"' in posted.body or '"email":"u"' in posted.body
    assert attempt.token.startswith("eyJ")
    assert SessionOracle().judge(attempt) is True


def test_json_auth_failure_is_not_a_session():
    """The guard that matters: {"status":"fail"} contains no password field, so a
    cookie-style heuristic would have called this a successful login."""
    api = _JsonApi(ok=False)
    attempt = JsonAuth().authenticate(
        api, LOGIN, Credentials(username="u", password="p"))
    assert attempt.cookie_login is False
    assert SessionOracle().judge(attempt) is False


def test_basic_auth_sets_the_header_without_making_a_request():
    class _NoCalls:
        _cookies: dict = {}
        auth_header = ""

        def run(self, action):
            raise AssertionError("basic auth must not make a request")

    b = _NoCalls()
    attempt = BasicAuth().authenticate(b, LOGIN, Credentials(username="u", password="p"))
    assert b.auth_header == "Basic dTpw"
    assert SessionOracle().judge(attempt) is True


def test_basic_auth_recognises_a_www_authenticate_challenge():
    probe = LoginProbe(url=LOGIN, status=401,
                       headers={"WWW-Authenticate": 'Basic realm="x"'})
    assert BasicAuth().detect(probe) > 0.5
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_strategies.py -q`
Expected: FAIL — `ImportError: cannot import name 'BasicAuth'`

- [ ] **Step 3: Add both strategies to `brukal/auth.py`**

```python
class JsonAuth:
    """API login that answers with a bearer/JWT token.

    `cookie_login=False` is load-bearing. The cookie heuristics read the ABSENCE of a
    password field as success, and a JSON API rejecting credentials answers
    {"status":"fail"} — which has no password field either. Applying them here once
    declared every failed API login a success.
    """

    name = "json"

    def detect(self, probe: LoginProbe) -> float:
        ctype = ""
        for k, v in (probe.headers or {}).items():
            if k.lower() == "content-type":
                ctype = (v or "").lower()
        if "json" in ctype:
            return 0.7
        if probe.inputs:
            return 0.1          # an HTML form is present; FormAuth fits better
        return 0.4

    def authenticate(self, browser, url: str, creds: Credentials) -> AuthAttempt:
        import json as _json

        from .web import WebAction

        # The seeding GET is NOT optional. The old login() issued it for every
        # non-basic type before posting credentials, and some APIs hand back an
        # anti-CSRF or session cookie there. Dropping it would change the request
        # count, the cookie jar, and the rate-limit accounting — a behaviour change
        # disguised as a tidy-up.
        browser.run(WebAction("request", url=url, method="GET"))

        body = _json.dumps({creds.user_field: creds.username,
                            creds.pass_field: creds.password,
                            **(creds.extra_fields or {})})
        # Measured AFTER the seeding GET, exactly as the original did — otherwise the
        # cookie the GET set would be miscounted as one the login earned.
        before = set(_jar(browser).items())
        _d, res = browser.run(WebAction(
            "request", url=url, method="POST", body=body,
            headers={"Content-Type": "application/json"}))
        gained = bool(set(_jar(browser).items()) - before)
        token = extract_token(res.body if res is not None else "")
        if token:
            browser.auth_header = f"Bearer {token}"
        return AuthAttempt(
            strategy=self.name,
            token=token,
            gained_cookie=gained,
            responded=res is not None,
            status=res.status if res is not None else None,
            headers=(res.headers or {}) if res is not None else {},
            body=(res.body or "") if res is not None else "",
            pass_field=creds.pass_field,
            cookie_login=False)


class BasicAuth:
    """HTTP Basic. Makes NO request — there is nothing to negotiate, the header simply
    accompanies every later request. `responded=False` keeps the oracle's status and
    cookie clauses inert; the header itself is the evidence."""

    name = "basic"

    def detect(self, probe: LoginProbe) -> float:
        for k, v in (probe.headers or {}).items():
            if k.lower() == "www-authenticate" and "basic" in (v or "").lower():
                return 0.95
        return 0.0

    def authenticate(self, browser, url: str, creds: Credentials) -> AuthAttempt:
        import base64
        tok = base64.b64encode(
            f"{creds.username}:{creds.password}".encode()).decode()
        browser.auth_header = f"Basic {tok}"
        return AuthAttempt(strategy=self.name, token=tok, responded=False)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_strategies.py -q`
Expected: PASS (11 tests)

- [ ] **Step 5: Verify the JSON guard is real**

Temporarily set `cookie_login=True` in `JsonAuth.authenticate`.
Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_strategies.py -q`
Expected: `test_json_auth_failure_is_not_a_session` FAILS. Revert.

- [ ] **Step 6: Commit**

```bash
/home/brute/brukal-venv/bin/python -m pytest -q   # expect 795 passed
git add brukal/auth.py tests/test_auth_strategies.py
git commit -m "auth: port the json and basic ways in, guard intact"
```

---

### Task 4: `SessionState` with delegating properties

**Files:**
- Modify: `brukal/auth.py`
- Modify: `brukal/assist.py` (AssistSession `__init__` and new properties)
- Test: `tests/test_session_state.py`

**Interfaces:**
- Consumes: everything above
- Produces: `SessionState` with fields `identity: str`, `authenticated: bool`, `last_jwt: str`, `login_url: str`, `login_type: str`, `login_password: str`, `strategy: str`; methods `snapshot() -> dict`, `restore(snap: dict) -> None`

**Context:** `assist.py` currently spreads session facts across `self.identity` (21 references), `self.authenticated` (10), `self.last_jwt` (10), `self._login_url`, `self._login_type`, `self._login_password`. Consolidating them by rewriting 40+ call sites would be a large, risky diff. Instead `SessionState` owns the values and `AssistSession` exposes **properties** with the same names, so every existing reference and test keeps working untouched.

Cookies and `auth_header` stay on `GovernedBrowser` — that is where the transport needs them. `SessionState` is about *who we are*, not *how the request is stamped*.

- [ ] **Step 1: Write the failing test**

Create `tests/test_session_state.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_session_state.py -q`
Expected: FAIL — `ImportError: cannot import name 'SessionState'`

- [ ] **Step 3: Add `SessionState` to `brukal/auth.py`**

```python
@dataclass
class SessionState:
    """Who we are and how we got in — one object instead of six attributes.

    Cookies and the Authorization header stay on GovernedBrowser: that is transport.
    This is identity. Keeping them apart is what lets `_separate_identity` swap one
    without disturbing the other.
    """
    identity: str = ""
    authenticated: bool = False
    last_jwt: str = ""
    login_url: str = ""
    login_type: str = ""
    login_password: str = ""
    strategy: str = ""

    def snapshot(self) -> dict:
        return dict(self.__dict__)

    def restore(self, snap: dict) -> None:
        self.__dict__.update(snap)
```

- [ ] **Step 4: Wire it into `AssistSession`**

In `brukal/assist.py`, `AssistSession.__init__` currently initialises **four** of the
six fields, in two non-contiguous places:

```
line 368:  self.last_jwt: str = ""         # most recent JWT seen — the forgery proof needs one
line 369:  self.identity: str = ""         # the principal we authenticated as (authz tests)
line 370:  self._login_password: str = ""  # that principal's password (session-revocation check)
line 391:  self.authenticated = False      # True once a form login has succeeded (auth scanning)
```

`_login_url` and `_login_type` are **never** initialised — they only come into
existence inside `login()`, which is why callers reach them through
`getattr(self, "_login_url", "")`. After this change the properties always exist and
return `""`, which is strictly safer; leave those `getattr` calls alone regardless.

`self._seen_jwts` (line 367) is **not** a `SessionState` field — it is an analysis
cache, not an identity. Leave it exactly where it is.

Delete lines 368, 369, 370 and 391, and insert **immediately before line 367**:

```python
        from .auth import SessionState
        # Session identity lives in one object. This MUST be assigned before anything
        # sets identity/authenticated/last_jwt, because those are now properties that
        # write through to it.
        self.session = SessionState()
```

Ordering matters: the property setters dereference `self.session`, so assigning it
after any of them would raise `AttributeError` during construction.

Then add these properties to the `AssistSession` class body (place them immediately
before `def has_session`):

```python
    # Session facts live on `self.session`; these keep the 40+ existing call sites
    # and their tests working unchanged. Adding a new session fact means adding it
    # to SessionState, not adding a seventh attribute here.
    @property
    def identity(self) -> str:
        return self.session.identity

    @identity.setter
    def identity(self, v: str) -> None:
        self.session.identity = v or ""

    @property
    def authenticated(self) -> bool:
        return self.session.authenticated

    @authenticated.setter
    def authenticated(self, v) -> None:
        self.session.authenticated = bool(v)

    @property
    def last_jwt(self) -> str:
        return self.session.last_jwt

    @last_jwt.setter
    def last_jwt(self, v: str) -> None:
        self.session.last_jwt = v or ""

    @property
    def _login_url(self) -> str:
        return self.session.login_url

    @_login_url.setter
    def _login_url(self, v: str) -> None:
        self.session.login_url = v or ""

    @property
    def _login_type(self) -> str:
        return self.session.login_type

    @_login_type.setter
    def _login_type(self, v: str) -> None:
        self.session.login_type = v or ""

    @property
    def _login_password(self) -> str:
        return self.session.login_password

    @_login_password.setter
    def _login_password(self, v: str) -> None:
        self.session.login_password = v or ""
```

**Watch for:** any place that did `getattr(self, "_login_password", "")` still works,
because the property always exists and returns `""`. Any place doing
`self.__dict__["identity"]` would break — grep to confirm there are none:
`grep -n '__dict__\[' brukal/assist.py`

- [ ] **Step 5: Run the tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_session_state.py -q`
Expected: PASS (4 tests)

- [ ] **Step 6: Run the whole suite — this is the real gate for this task**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: 799 passed. **If any pre-existing test fails, the property wiring is wrong —
fix the wiring, do not edit the test.**

- [ ] **Step 7: Commit**

```bash
git add brukal/auth.py brukal/assist.py tests/test_session_state.py
git commit -m "auth: one object for who we are, six attributes retired"
```

---

### Task 5: `login()` becomes an adapter

**Files:**
- Modify: `brukal/assist.py` (`login`, lines 1575–1719; `_extract_token`, lines 1548–1573)
- Test: `tests/test_auth_adapter.py`

**Interfaces:**
- Consumes: everything above
- Produces: no new public names. `AssistSession.login` keeps its exact signature and return type.

**Context:** this is the task where behaviour could silently change. The adapter must map `login_type` to a strategy, run it, judge with the oracle, and reproduce every side effect the old function had:

1. `self._login_url` / `self._login_type` set **before** any request (an authenticated crawl cannot rediscover the login page).
2. On a token: `browser.auth_header = f"Bearer {token}"`, `self.identity = username`, `self._login_password = password`, add to `_seen_jwts`, set `last_jwt`, call `scan_jwt(token, source=login_url)` **inside a try/except that can never break authentication**.
3. On success with empty `identity`: adopt `username` and `_login_password`.
4. Append the same `[login] ...` note, printing only the username and cookie count — never the password.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_adapter.py`:

```python
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


def test_extract_token_is_still_a_staticmethod_on_the_session():
    """tests/test_auth_scan.py calls AssistSession._extract_token directly."""
    assert AssistSession._extract_token('{"token":"abcdefghijklmnop"}') == \
        "abcdefghijklmnop"
```

- [ ] **Step 2: Run the tests to verify they pass against the OLD code**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_adapter.py -q`
Expected: PASS (8 tests) — these describe *current* behaviour, so they must pass
**before** the refactor. That is the point: they are the contract the refactor must not
break. If any fails now, fix the test to match reality before continuing.

- [ ] **Step 3: Commit the characterisation tests on their own**

```bash
git add tests/test_auth_adapter.py
git commit -m "auth: pin login()'s side effects before moving it"
```

- [ ] **Step 4: Replace the body of `login()` with the adapter**

In `brukal/assist.py`, replace lines 1589–1719 (the body after the docstring) with:

```python
        from .auth import (AuthAttempt, BasicAuth, Credentials, FormAuth,
                           JsonAuth, SessionOracle)
        if self.browser is None:
            self.notes.append("[login] no governed browser wired — cannot authenticate.")
            return False

        lt = (login_type or "form").lower()
        # Remember it BEFORE authenticating: an authenticated crawl cannot rediscover
        # the login page, and every cross-account proof needs somewhere to authenticate
        # a second principal.
        self._login_url = login_url
        self._login_type = lt

        strategy = {"basic": BasicAuth(), "json": JsonAuth()}.get(lt, FormAuth())
        creds = Credentials(username=username, password=password,
                            user_field=user_field, pass_field=pass_field,
                            extra_fields=extra_fields)
        try:
            attempt = strategy.authenticate(self.browser, login_url, creds)
        except Exception:
            attempt = AuthAttempt(strategy=strategy.name, responded=False)

        ok = SessionOracle().judge(attempt)

        if attempt.token and strategy.name != "basic":
            # The token the app just handed us is itself evidence: its header names
            # the algorithm and its signature exposes a weak key. Reading it costs
            # nothing and needs no further request.
            try:
                self._seen_jwts.add(attempt.token)
                self.last_jwt = attempt.token
                self.scan_jwt(attempt.token, source=login_url)
            except Exception:
                pass                  # analysis must never break authentication

        self.authenticated = ok
        self.session.strategy = strategy.name

        if strategy.name == "basic":
            # Preserved EXACTLY as the old early-return branch behaved: a distinct
            # note, and `identity` deliberately left alone.
            #
            # KNOWN LATENT BUG, DEFERRED TO A2 ON PURPOSE. Leaving `identity` empty
            # is the same defect that cost five checks on cookie-session apps — every
            # authz test that asks "whose objects are ours" reads it, so on a
            # Basic-auth target those tests reason about the wrong principal or do
            # not run. It is NOT fixed here because this phase's contract is zero
            # behaviour change, and a refactor that quietly also fixes things is a
            # refactor whose regressions have two possible causes. A2 fixes it with
            # its own failing test.
            self.notes.append(
                f"[login] HTTP Basic as {username} → Authorization header set")
            return ok

        if ok and not self.identity:
            # Who we are was once set ONLY in the token branch, so a cookie-session
            # login left `identity` empty — and every authz check that asks "whose
            # objects are ours" reads it. Those checks simply never ran.
            self.identity = username
            self._login_password = password

        jar = len(getattr(self.browser, "_cookies", {}) or {})
        how = "bearer token" if attempt.token else f"{jar} cookie(s)"
        self.notes.append(
            f"[login] {login_url} as {username} ({lt}) → "
            f"{'AUTHENTICATED via ' + how if ok else 'login may have FAILED — check creds/field names/type'}")
        return ok
```

- [ ] **Step 5: Reduce `_extract_token` to a delegate**

Replace the body of the `_extract_token` staticmethod (lines 1548–1573) with:

```python
    @staticmethod
    def _extract_token(body: str) -> str:
        """Kept on the session because tests and assist.py:2247 call it directly.
        The implementation now lives with the strategies that need it."""
        from .auth import extract_token
        return extract_token(body)
```

- [ ] **Step 6: Run the adapter tests, then the whole suite**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_adapter.py -q`
Expected: PASS (8 tests) — same tests, same results, new implementation.

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: **807 passed.** Any pre-existing failure means the port changed behaviour.
Fix `brukal/auth.py`; do not edit the failing test.

- [ ] **Step 7: Live parity check — the gate the suite cannot give you**

A green suite has already failed to catch this class of defect in this codebase. Run
the real thing against the real targets.

```bash
docker start dvna juice-shop brukal-kali
/home/brute/brukal-venv/bin/python - <<'PY'
import sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import DockerKali
from brukal.web import GovernedBrowser, HttpWebCage

CASES = [
    ("runs/dvna.json",  "172.20.0.10", "http://172.20.0.10:9090/login",
     "brkeval", "BrkEval1!", "form", "username", "password"),
    ("runs/juice.json", "172.20.0.4",  "http://172.20.0.4:3000/rest/user/login",
     "brk@eval.local", "BrkEval1!", "json", "email", "password"),
]
for scope_f, target, url, user, pw, lt, uf, pf in CASES:
    scope = load_scope(scope_f)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), DockerKali("brukal-kali"), audit)
    s = AssistSession(target, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, HttpWebCage(), audit))
    ok = s.login(url, user, pw, login_type=lt, user_field=uf, pass_field=pf)
    print(f"{lt:5} {target:13} login={ok} session={s.has_session()} "
          f"identity={s.identity!r} jwt={bool(s.last_jwt)}")
PY
```

Expected, matching pre-refactor behaviour exactly:
```
form  172.20.0.10   login=True session=True identity='brkeval' jwt=False
json  172.20.0.4    login=True session=True identity='brk@eval.local' jwt=True
```

If `runs/juice.json` does not exist or its CIDR is stale, check the container IP with
`docker inspect juice-shop` first — container IPs drift between sessions, and
`runs/dvwa.json` was already found pointing at the cage.

- [ ] **Step 8: Commit**

```bash
git add brukal/assist.py
git commit -m "auth: login() is an adapter now, and the oracle is the only judge"
```

---

## Definition of done for Phase A1

- `brukal/auth.py` exists with `SessionOracle`, `AuthStrategy`, `FormAuth`, `JsonAuth`, `BasicAuth`, `SessionState`, `Credentials`, `extract_token`.
- `AssistSession.login()` is an adapter; its signature and every side effect are unchanged.
- **807 tests pass.** None edited to accommodate the *refactor* (Tasks 1–5); Task 6
  changes exactly one test, deliberately, together with the behaviour it asserts.
- Live logins against DVNA (form) and Juice Shop (json) behave exactly as before.
- Basic auth sets `identity`, closing a latent authz-targeting bug (Task 6).
- No new CLI flags. A2 is what removes the tuning flags.

---

### Task 6: Fix the Basic-auth identity bug (deliberate behaviour change)

**Files:**
- Modify: `brukal/assist.py` (the adapter written in Task 5)
- Modify: `tests/test_auth_adapter.py`

**Interfaces:**
- Consumes: the adapter from Task 5
- Produces: no new names. `login(..., login_type="basic")` now sets `identity` and
  `_login_password`, like every other strategy.

**Context — read this before starting.** Tasks 1–5 are a pure refactor: *any* test
failure there means the port is wrong. **Task 6 is the opposite** — it changes
behaviour on purpose. If a pre-existing test fails here, it may legitimately need
updating, because it may be asserting the bug. Judge each one; do not blanket-edit.

The bug: the old `basic` branch returned early and never set `identity`. Every authz
check that asks "whose objects are ours" reads `identity`, so on a Basic-auth target
those checks reason about the wrong principal or never run. This is the same defect
class that once silently disabled five checks on cookie-session apps — the reason
`has_session()` exists at all.

- [ ] **Step 1: Flip the characterisation test**

In `tests/test_auth_adapter.py`, **replace** `test_basic_auth_currently_leaves_identity_empty`
entirely with:

```python
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_adapter.py -q`
Expected: FAIL — `assert '' == 'u'`

- [ ] **Step 3: Fix the adapter**

In `brukal/assist.py`, in the adapter body from Task 5, **replace** this block:

```python
        if strategy.name == "basic":
            # Preserved EXACTLY as the old early-return branch behaved: a distinct
            # note, and `identity` deliberately left alone.
            ...
            self.notes.append(
                f"[login] HTTP Basic as {username} → Authorization header set")
            return ok

        if ok and not self.identity:
```

with:

```python
        if ok and not self.identity:
```

and then, immediately AFTER the `self.identity = username` /
`self._login_password = password` block, insert:

```python
        if strategy.name == "basic":
            # Basic auth makes no request, so there is no cookie count or token to
            # describe — hence its own note. It DOES set identity above, like every
            # other strategy: leaving that empty made authz checks reason about the
            # wrong principal on Basic-auth targets.
            self.notes.append(
                f"[login] HTTP Basic as {username} → Authorization header set")
            return ok
```

The ordering is the whole fix: identity is now assigned before the Basic-auth early
return, instead of being skipped by it.

- [ ] **Step 4: Run it to verify it passes**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_adapter.py -q`
Expected: PASS (8 tests)

- [ ] **Step 5: Verify the fix is real**

Move the `if strategy.name == "basic": ... return ok` block back above the identity
assignment.
Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_auth_adapter.py -q`
Expected: `test_basic_auth_sets_identity_like_every_other_strategy` FAILS. Revert.

- [ ] **Step 6: Run the whole suite and judge any failure on its merits**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: 807 passed.

If a pre-existing test fails, decide which case it is:
- it asserted `identity == ""` after a Basic login → it was pinning the bug; update it
- it fails for any other reason → the fix is wrong; fix the code

Report which happened rather than silently editing.

- [ ] **Step 7: Commit**

```bash
git add brukal/assist.py tests/test_auth_adapter.py
git commit -m "auth: basic auth knows who it logged in as"
```

---

## Self-review notes

Checked against the spec's A1 definition of done:
- "Move `SessionOracle` out verbatim" → Task 1, with the three historical false positives pinned.
- "Add the `AuthStrategy` protocol" → Task 2.
- "Port Form/Json/Basic as behaviour-preserving" → Tasks 2–3.
- "Introduce `SessionState`" → Task 4, via delegating properties so no call site churns.
- "Reduce `login()` to an adapter" → Task 5.
- "Entire existing suite passes unchanged" → gated in Tasks 4, 5.
- "Live login against DVNA, DVWA and Juice Shop identical" → Task 5 Step 7 covers DVNA and Juice Shop. **DVWA is not covered**: it publishes no port, so it is unreachable from WSL without the socat forwarder described in the project memory. Add DVWA to the parity check only if the forwarder is up; otherwise A2 covers it, since DVWA is a plain form login already exercised by DVNA.
