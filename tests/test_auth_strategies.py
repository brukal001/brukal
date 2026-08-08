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
            return (None, WebResult(
                status=200, url=action.url,
                body='<form method="post">'
                     '<input type="hidden" name="csrf" value="TOK1">'
                     '<input name="username"><input type="password" name="password">'
                     '</form>',
                headers={"Set-Cookie": "sid=anon; Path=/"}))
        if "csrf=TOK1" not in (action.body or ""):
            return (None, WebResult(status=403, url=action.url, body="bad csrf"))
        self._cookies["sid"] = "authed"
        return (None, WebResult(status=302, url=action.url, body="",
                         headers={"Location": "/dashboard",
                                  "Set-Cookie": "sid=authed; Path="}))


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


from brukal.auth import BasicAuth, JsonAuth, SessionOracle


class _JsonApi:
    """Stands in for the GovernedBrowser, so `run` returns the (decision, result)
    TUPLE that GovernedBrowser.run returns — not a bare WebResult. A double that
    returns the wrong shape raises on unpacking inside the strategy, which reads as
    "the strategy is broken" when the double is what is wrong."""

    def __init__(self, ok=True):
        self.ok = ok
        self.seen: list = []
        self._cookies = {}
        self.auth_header = ""

    def run(self, action):
        self.seen.append(action)
        if (getattr(action, "method", "") or "GET").upper() != "POST":
            return None, WebResult(status=404, url=action.url, body="")
        if self.ok:
            return None, WebResult(
                status=200, url=action.url,
                body='{"access_token":"eyJhbGciOiJIUzI1NiJ9.payload.sig"}')
        return None, WebResult(status=200, url=action.url, body='{"status":"fail"}')


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


def test_json_auth_guards_against_false_login_heuristic():
    """The cookie_login=False guard stops a successful body parse from being
    misread as a login. A body with no error keywords and matching _LOGGED_IN_RE
    ("welcome") but no password field would be flagged as authenticated by
    SessionOracle's last-resort cookie heuristic, EXCEPT that cookie_login=False
    stops that heuristic from ever being entered in the first place."""

    class _LoginPageLike:
        """Returns a 200 with body that bypasses _FAIL_JSON_RE and _AUTH_ERROR_RE
        but would match _LOGGED_IN_RE, fooling the cookie heuristic if applied."""

        def __init__(self):
            self.seen: list = []
            self._cookies = {}
            self.auth_header = ""

        def run(self, action):
            self.seen.append(action)
            method = (getattr(action, "method", "") or "GET").upper()
            if method == "GET":
                return None, WebResult(status=200, url=action.url, body="")
            return None, WebResult(status=200, url=action.url,
                            body='{"result":"welcome back"}')

    api = _LoginPageLike()
    attempt = JsonAuth().authenticate(
        api, LOGIN, Credentials(username="u", password="p"))
    assert attempt.cookie_login is False
    assert SessionOracle().judge(attempt) is False


def test_json_auth_seeding_get_is_load_bearing():
    """The seeding GET is not optional: it seeds cookies/CSRF tokens and the
    snapshot must be taken AFTER it, not before. This test verifies both by using
    a double that sets a cookie on GET (not POST): the cookie came from the GET,
    so it must NOT be counted as gained by the login."""

    class _GetSetsCookie:
        def __init__(self):
            self.seen: list = []
            self._cookies = {}
            self.auth_header = ""

        def run(self, action):
            self.seen.append(action)
            method = (getattr(action, "method", "") or "GET").upper()
            if method == "GET":
                # The seeding GET sets a cookie (CSRF token, session, etc.)
                self._cookies["csrf_token"] = "tok123"
                return None, WebResult(status=200, url=action.url, body="")
            # POST returns token but NO new cookies
            return None, WebResult(
                status=200, url=action.url,
                body='{"access_token":"eyJhbGciOiJIUzI1NiJ9.payload.sig"}')

    api = _GetSetsCookie()
    attempt = JsonAuth().authenticate(
        api, LOGIN, Credentials(username="u", password="p"))
    # Verify the GET was actually issued
    assert len(api.seen) >= 2, "seeding GET must be issued before POST"
    assert (getattr(api.seen[0], "method", "") or "GET").upper() == "GET"
    # The cookie from the GET is not "gained" by the login (snapshot was after GET)
    assert attempt.gained_cookie is False


def test_form_auth_does_not_count_a_cookie_set_by_the_seeding_get():
    """Mirrors test_json_auth_seeding_get_is_load_bearing above: the existing
    FormAuth cookie tests pass whether the `before` snapshot is taken above or
    below the seeding GET, because their double only ever sets a cookie on the
    POST. A double that sets a cookie on the GET and NONE on the POST is the only
    way to distinguish the two orderings — if the snapshot were taken before the
    GET, that GET-issued cookie would be miscounted as gained by the login."""

    class _GetSetsCookieNoNewOneOnPost:
        def __init__(self):
            self.seen: list = []
            self._cookies = {}
            self.auth_header = ""

        def run(self, action):
            self.seen.append(action)
            method = (getattr(action, "method", "") or "GET").upper()
            if method == "GET":
                self._cookies["sid"] = "anon"
                return None, WebResult(status=200, url=action.url, body="")
            # POST succeeds (redirect away) but sets no NEW cookie.
            return None, WebResult(status=302, url=action.url, body="",
                            headers={"Location": "/dashboard"})

    app = _GetSetsCookieNoNewOneOnPost()
    attempt = FormAuth().authenticate(
        app, LOGIN, Credentials(username="u", password="p"))
    assert len(app.seen) >= 2, "the seeding GET must be issued before the POST"
    assert (getattr(app.seen[0], "method", "") or "GET").upper() == "GET"
    assert attempt.gained_cookie is False


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
