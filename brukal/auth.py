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
