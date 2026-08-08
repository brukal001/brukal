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
    """The guard that made this safe: a JSON API rejecting credentials answers a
    body with no password field AND no explicit error/fail wording — e.g.
    {"result":"welcome back"} — which matches _LOGGED_IN_RE and would be read as
    an authenticated session by the cookie heuristic. cookie_login=False stops the
    heuristic from ever being entered, regardless of what the body says."""
    assert SessionOracle().judge(
        AuthAttempt(strategy="json", token="", responded=True, cookie_login=False,
                    status=200, body='{"result":"welcome back"}')) is False


def test_last_resort_hint_only_when_nothing_else_is_available():
    """No new cookie at all, no error, and the form is gone: the only honest signal
    left is that the app replaced it with something that looks logged in."""
    assert SessionOracle().judge(
        _form(status=200, gained_cookie=False,
              body="<html>Welcome back — Log out</html>")) is True
