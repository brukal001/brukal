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
from typing import Protocol, runtime_checkable


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


# An authentication failure the app itself describes — used to tell "the endpoint
# refused me" apart from "the endpoint served me data". Owned HERE, not duplicated:
# assist.py imports this name rather than re-compiling its own copy, so a phrase
# added to one can never silently fail to reach the other. The unsafe drift
# direction is real — a phrase added only to a caller's copy makes the oracle LESS
# able to see an explicit failure, which is the exact failure mode this module was
# extracted to prevent.
AUTH_ERROR_RE = re.compile(
    r"(?i)\b(?:unauthori[sz]ed|forbidden|access denied|not authenticated|"
    r"authentication (?:required|failed)|no authorization token|missing token|"
    r"invalid token|token (?:is )?(?:expired|missing)|login required|"
    r"permission denied)\b")


class SessionOracle:
    """Does this attempt prove we hold a session?

    Ported verbatim from assist.py login() lines 1654-1706. Three shipped versions of
    this were wrong, all in the same way: inferring success from the ABSENCE of a
    login form rather than from positive evidence of a session. Do not simplify.
    """

    _REDIRECT = (301, 302, 303, 307, 308)
    _AUTH_ERROR_RE = AUTH_ERROR_RE
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
        # Do NOT write browser.auth_header here. This strategy returns EVIDENCE; the
        # adapter (assist.py login()) is what arms transport state, and only after
        # the oracle has judged the attempt a success. Writing it here too was a
        # no-op while only one strategy ever runs, but it becomes a trap once a
        # negotiator tries strategies in order (phase A2): a rejected JSON attempt
        # could arm a Bearer header from a token-shaped string in its body, be
        # judged a failure, and then leave that stale header riding on every
        # request after a DIFFERENT strategy succeeds on cookies.
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
        # Unlike JsonAuth, THIS write is not redundant with the adapter: Basic makes
        # no request and has no oracle-judged verdict to wait for (there is nothing
        # to negotiate — see the class docstring), and the adapter deliberately
        # skips arming the header for the "basic" strategy. This is the only place
        # it happens, so it stays.
        browser.auth_header = f"Basic {tok}"
        return AuthAttempt(strategy=self.name, token=tok, responded=False)


@dataclass
class Principal:
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
        # Filtered to the dataclass's own fields — an unfiltered __dict__.update
        # would let any foreign dict graft arbitrary attributes onto a live
        # Principal. `snap` is normally this object's own prior snapshot(), but the
        # method's contract should not depend on that being the only caller.
        known = self.__dataclass_fields__
        for k, v in snap.items():
            if k in known:
                setattr(self, k, v)
