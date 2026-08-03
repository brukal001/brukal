"""Authorization testing on a COOKIE-SESSION application.

Brukal's authorization family — BOLA, BFLA, mass assignment — was built against a JSON
API with a JWT and templated routes, and is structurally blind to anything else:
`bfla_targets` returns None the moment `last_jwt` is empty, and the BOLA sweep needs a
`{param}` in a mined route. A cold run against DVNA, a server-rendered Express app with
a cookie session and form POSTs, probed twelve classes and not one was an authorization
class. A competing tool found six there, two critical; both of the ones checked by hand
were real.

Every case below is taken from that run.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult
from brukal import webmap

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000"


def _sess(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    return s


# --- 1. a reset token that is a digest of the username -------------------------------

class _ResetCage:
    """DVNA's shape: /resetpw accepts md5(login) and refuses anything else."""

    def __init__(self):
        self.seen = []

    def run(self, action):
        self.seen.append(action.url)
        if "/resetpw" in action.url:
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(action.url).query)
            login = (q.get("login") or [""])[0]
            token = (q.get("token") or [""])[0]
            good = hashlib.md5(login.encode()).hexdigest()
            if token == good:
                return WebResult(status=200, url=action.url, headers={},
                                 body="<form>new password</form>")
            return WebResult(status=302, url=action.url, headers={"Location": "/login"},
                             body="")
        return WebResult(status=404, url=action.url, headers={}, body="")


def test_a_reset_token_derived_from_the_username_is_confirmed():
    cage = _ResetCage()
    s = _sess(cage)
    assert s.confirm_predictable_reset_token(f"{ROOT}/resetpw", "login", "token", "brkeval")
    f = s.findings.all()[0]
    assert f.confirmed and f.severity == "critical"
    assert hashlib.md5(b"brkeval").hexdigest() in f.evidence


def test_an_unguessable_reset_token_yields_nothing():
    class _Random(_ResetCage):
        def run(self, action):
            self.seen.append(action.url)
            return WebResult(status=302, url=action.url,
                             headers={"Location": "/login"}, body="")
    s = _sess(_Random())
    assert not s.confirm_predictable_reset_token(f"{ROOT}/resetpw", "login", "token", "u")
    assert not s.findings.all()


def test_the_reset_endpoint_is_found_from_the_crawled_parameter_map():
    s = _sess(_ResetCage())
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.params[f"{ROOT}/resetpw"] = {"login", "token"}
    assert (f"{ROOT}/resetpw", "login", "token") in s.reset_token_targets()


# --- 2. an admin endpoint reachable by an account anyone can create ------------------

class _AdminCage:
    """Anonymous is bounced to /login; ANY logged-in user reads the admin API. The only
    access check is 'somebody is logged in' — DVNA's /app/admin/usersapi exactly."""

    def __init__(self, anon_status=302):
        self.seen, self.anon_status, self.accounts = [], anon_status, set()

    def run(self, action):
        self.seen.append(f"{action.method} {action.url}")
        cookie = (action.headers or {}).get("Cookie", "")
        if "/register" in action.url:
            self.accounts.add("new")
            return WebResult(status=302, url=action.url,
                             headers={"Location": "/learn",
                                      "Set-Cookie": "sid=fresh; Path=/"}, body="")
        if "/login" in action.url and action.method == "POST":
            return WebResult(status=302, url=action.url,
                             headers={"Location": "/learn",
                                      "Set-Cookie": "sid=loggedin; Path=/"}, body="")
        if "/admin" in action.url:
            dump = '{"users":[' + '{"login":"a","password":"$2a$x"},' * 20 + ']}'
            if "sid=" in cookie:
                return WebResult(status=200, url=action.url, headers={}, body=dump)
            if self.anon_status == 200:
                # A stranger genuinely reads it — the SAME disclosure, not an empty 200.
                return WebResult(status=200, url=action.url, headers={}, body=dump)
            return WebResult(status=self.anon_status, url=action.url,
                             headers={"Location": "/login"}, body="")
        return WebResult(status=200, url=action.url,
                         headers={"content-type": "text/html"}, body="<html></html>")


def _with_signup(s):
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.forms.append(webmap.Form(
        action=f"{ROOT}/register", method="POST",
        inputs=(("name", "text"), ("username", "text"), ("email", "email"),
                ("password", "password"), ("cpassword", "password"))))
    s.surface.add_routes(["/app/admin/usersapi"])
    return s


def test_an_admin_endpoint_open_to_any_signup_is_confirmed():
    cage = _AdminCage()
    s = _with_signup(_sess(cage))
    assert s.confirm_privileged_route_via_signup(f"{ROOT}/app/admin/usersapi")
    f = s.findings.all()[0]
    assert f.confirmed and f.severity == "critical"
    assert "anonymous was refused" in f.evidence


def test_it_declines_when_a_stranger_already_reads_it():
    """That is unauthenticated exposure — a finding Brukal already makes elsewhere.
    Reporting it here as a privilege flaw would double-count it and misname it."""
    cage = _AdminCage(anon_status=200)
    s = _with_signup(_sess(cage))
    assert not s.confirm_privileged_route_via_signup(f"{ROOT}/app/admin/usersapi")


def test_privileged_routes_are_picked_out_of_the_crawl():
    s = _sess(_AdminCage())
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.add_routes(["/app/admin/usersapi", "/products", "/app/manage/keys"])
    got = s.privileged_route_targets()
    assert any("admin" in u for u in got) and any("manage" in u for u in got)
    assert not any("/products" in u for u in got)


# --- 3. the primitive both of them need ----------------------------------------------

def test_acting_as_another_identity_does_not_destroy_our_session():
    """Token auth holds two principals at once; a cookie jar cannot. Without this,
    registering a second user absorbs their Set-Cookie over ours and every later probe
    in the run silently becomes that other user."""
    s = _sess(_AdminCage())
    s.browser._cookies = {"sid": "ours"}
    s.browser.auth_header = "Bearer mine"
    with s._separate_identity():
        assert s.browser._cookies == {} and s.browser.auth_header == ""
        s.browser._cookies["sid"] = "theirs"
    assert s.browser._cookies == {"sid": "ours"}
    assert s.browser.auth_header == "Bearer mine"


def test_a_cookie_login_records_who_we_are():
    """`identity` was set only in the token branch, so a form login left it empty — and
    every authz check that asks 'whose objects are ours' reads it."""
    s = _sess(_AdminCage())
    assert s.login(f"{ROOT}/login", "brkeval", "BrkEval1!")
    assert s.identity == "brkeval"


def test_crawled_pages_outrank_mined_route_fragments():
    """The route miner recovers fragments from text and JS and loses the prefix the app
    mounts them under. DVNA's admin API is /app/admin/usersapi and was mined as
    /admin/usersapi, which 404s — four probes went to paths that do not exist while
    /app/admin/users, crawled and returning 200, sat in the page map unexamined."""
    s = _sess(_AdminCage())
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.add_routes(["/admin/usersapi", "/admin"])          # mined, wrong prefix
    s.surface.add_page(f"{ROOT}/app/admin/users", set(), [], {})  # actually fetched
    got = s.privileged_route_targets()
    assert got and "/app/admin/users" in got[0], got
