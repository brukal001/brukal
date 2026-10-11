"""
test_capture_auth_success.py — the credential-disclosure → successful-login prover.

WHY (NEXT.md TOP, from the 2026-10-01 live run): Brukal dumped a PortSwigger lab's users
table with a UNION injection, logged in as `administrator` with the dumped password, got
`302 /my-account?id=administrator`, solved the lab — and registered 0 findings, because
no prover recognised an authentication success.

A login is NOT a finding by itself: Brukal logs in with the operator's own test accounts
all the time. What makes it one is PROVENANCE — the password used was handed out by the
target earlier in the same capture. So this prover confirms only when, deterministically:
  1. a login request (POST with a password field) SUCCEEDED (redirect away from login/
     error pages; or 200 with no login form and no failure text; or a JSON token);
  2. that exact password (raw, or as the same stable redaction placeholder) appeared, as
     a whole token of >= 6 chars, in an EARLIER captured response;
  3. the disclosing request did not itself carry the password (not an echo);
  4. the username is not one of the session's own principals.
Both directions are pinned below.
"""
from __future__ import annotations

import json

from brukal import capture_confirm as cc
from brukal.capture import CapturedRequest

B = "https://lab.example"
PW = "s3cr3tpassw0rd123"


def cap(url, method="GET", body=None, status=200, response="", headers=None):
    return CapturedRequest(method=method, url=url, body=body, status=status,
                           response=response, resp_headers=headers or {})


def _dump(pw=PW, user="administrator"):
    return cap(f"{B}/filter?category=x'+UNION+SELECT+username,password+FROM+users--",
               response=f"<table><tr><td>{user}</td><td>{pw}</td></tr></table>")


def _login(user="administrator", pw=PW, status=302, location="/my-account?id=administrator",
           response=""):
    return cap(f"{B}/login", method="POST", body=f"csrf=abc&username={user}&password={pw}",
               status=status, response=response,
               headers={"Location": location} if location else {})


# ---------------------------------------------------------------- confirms -----------

def test_union_dump_then_admin_login_redirect_confirms():
    out = cc.credential_disclosure_login([_dump(), _login()])
    assert len(out) == 1
    f = out[0]
    assert f["target"] == f"{B}/login" and f["param"] == "username"
    assert "administrator" in f["evidence"]
    assert PW not in f["evidence"]                     # the secret never enters the record
    assert f["comparator"] == "credential_disclosure_login"


def test_redacted_placeholder_correlates_like_the_raw_value():
    ph = "[REDACTED:1a2b3c4d]"
    dump = cap(f"{B}/api/Users", response=json.dumps([{"email": "admin@lab", "password": ph}]))
    login = cap(f"{B}/rest/user/login", method="POST",
                body=json.dumps({"email": "admin@lab", "password": ph}), status=200,
                response=json.dumps({"authentication": {"token": "[REDACTED:99999999]"}}))
    out = cc.credential_disclosure_login([dump, login])
    assert [f["param"] for f in out] == ["email"]


def test_200_authenticated_page_without_login_form_confirms():
    login = _login(status=200, location=None,
                   response="<h1>My account</h1><a href='/logout'>Log out</a>")
    assert len(cc.credential_disclosure_login([_dump(), login])) == 1


def test_wired_into_findings_from_capture():
    titles = [f["title"] for f in cc.findings_from_capture([_dump(), _login()], None)]
    assert any("disclosed credential" in t.lower() for t in titles), titles


# ------------------------------------------------------------ must NOT confirm --------

def test_own_principal_login_is_not_a_finding():
    out = cc.credential_disclosure_login([_dump(user="wiener"), _login(user="wiener")],
                                         own_handles={"wiener"})
    assert out == []


def test_password_never_disclosed_is_not_this_finding():
    assert cc.credential_disclosure_login([_login()]) == []
    assert cc.credential_disclosure_login([_dump(pw="otherpassword99"), _login()]) == []


def test_echo_of_our_own_input_is_not_disclosure():
    echo = cap(f"{B}/search?q={PW}", response=f"No results for {PW}")
    assert cc.credential_disclosure_login([echo, _login()]) == []


def test_failed_logins_do_not_confirm():
    for login in (
        _login(location="/login?error=1"),
        _login(location="/signin"),
        _login(status=200, location=None,
               response="<p>Invalid username or password</p><input type=password>"),
        _login(status=200, location=None, response="<form><input type='password'></form>"),
        _login(status=401, location=None, response="no"),
    ):
        assert cc.credential_disclosure_login([_dump(), login]) == [], login


def test_disclosure_after_the_login_does_not_count():
    assert cc.credential_disclosure_login([_login(), _dump()]) == []


def test_short_or_embedded_password_does_not_correlate():
    short = "admin"
    assert cc.credential_disclosure_login([_dump(pw=short), _login(pw=short)]) == []
    embedded = cap(f"{B}/x", response="token xs3cr3tpassw0rd1234 here")
    assert cc.credential_disclosure_login([embedded, _login()]) == []


def test_get_request_with_password_param_is_not_a_login():
    get = cap(f"{B}/login?username=administrator&password={PW}", status=302,
              headers={"Location": "/my-account"})
    assert cc.credential_disclosure_login([_dump(), get]) == []


def test_end_to_end_through_confirm_from_capture_respects_own_principals():
    """Through the REAL _ConfirmMixin._confirm_from_capture -> FindingStore path: the
    administrator login registers one CONFIRMED finding; the same shape for the
    session's own principal registers nothing."""
    from brukal.assist_confirm import _ConfirmMixin
    from brukal.findings import FindingStore

    class _B:
        def __init__(self, caps):
            self._c = caps

        def captured(self):
            return self._c

    class _S(_ConfirmMixin):
        def __init__(self, caps, handles):
            self.scope, self.browser = None, _B(caps)
            self.findings, self.highlights, self.notes = FindingStore(), [], []
            self._principal_handles = handles

    s = _S([_dump(), _login()], {"self": "wiener"})
    assert s._confirm_from_capture() == 1
    (f,) = s.findings.confirmed()
    assert f.title == "Account takeover via disclosed credential" and f.confirmed
    assert PW not in " ".join(s.notes)

    own = _S([_dump(user="wiener"), _login(user="wiener")], {"self": "wiener"})
    assert own._confirm_from_capture() == 0
