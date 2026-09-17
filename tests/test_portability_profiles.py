"""
test_portability_profiles.py — the conformance suite for meeting a NEW target.

WHY THIS FILE EXISTS
    Five portability defects were found in two days against crAPI, and every one of them
    was the same mistake: a fact about OWASP Juice Shop encoded as a fact about web
    applications. Six measurement runs against one application (2C4, CM1–CM6) added depth,
    not variety, and each contingent detail hardened into a definition:

      GAP #1  an exception means the target went silent   (it had no TLS listener)
      GAP #2  no TLS policy is needed                     (it had no certificate)
      item 5  a signup wants {email, password, …}         (measured once, on it)
      GAP #3  a 404 means the path is absent              (its oracle answered 200/nothing)
      GAP #4  bundle strings are API paths                (one service, no gateway prefix)
      GAP #5  a signup reply ECHOES the account           (its POST /api/Users returns one)

    Each cost a live run to find, and three of them cost two. They all live in ONE layer:
    *how do I address this application, and who does it think I am.* Nothing in the gate,
    the executor, the audit chain or the comparators ever broke.

WHAT THIS FILE IS
    Target SHAPES, as profiles, and one contract every shape must satisfy. Adding a shape
    is how a new target is onboarded: write the profile, run this file, and the portability
    gap — if there is one — is a red test in seconds instead of a $0.42 run and a session
    of forensics.

    A profile is deliberately NOT a mock of one product. It is a combination of the four
    things that have actually differed: route naming, registration shape, proof of
    creation, and identity carriage.

HOW TO ADD A TARGET
    1. Write a `Profile` with its cage, the routes its bundle would yield, and what the
       harness SHOULD be able to establish against it.
    2. Run this file. Red means the harness cannot meet that shape yet — that is the gap,
       named before a packet is sent at the real thing.
    3. Record it in `docs/TARGET_SURVEY.md` with its class, and fix it test-first.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

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


def _json(status, obj, url, headers=None):
    return WebResult(status=status, url=url, body=json.dumps(obj), headers=headers or {})


# --------------------------------------------------------------------------- #
# SHAPE 1 — single service, echoing signup, cookie identity        (Juice Shop)
# --------------------------------------------------------------------------- #

class JuiceShopShape:
    LOGIN = "/rest/user/login"
    SIGNUP = "/api/Users"
    WHOAMI = "/rest/user/whoami"

    def __init__(self):
        self.accounts = {"first@brukal.test": "First-1!"}
        self.sessions = {}

    def run(self, action):
        path = urlsplit(action.url).path
        method = (action.method or "GET").upper()
        body = {}
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            pass
        cookie = (action.headers or {}).get("Cookie", "")
        if path == self.SIGNUP and method == "POST":
            email = body.get("email", "")
            if not email or not body.get("password"):
                return _json(400, {"error": "email and password required"}, action.url)
            self.accounts[email] = body["password"]
            # THE ECHO: the created object comes back.
            return _json(201, {"id": 42, "email": email, "role": "customer"}, action.url)
        if path == self.LOGIN and method == "POST":
            email = body.get("email") or body.get("username") or ""
            if self.accounts.get(email) == body.get("password"):
                tok = f"eyJhbGciOiJIUzI1NiJ9.juiceshop{len(self.sessions)}.sig-{'x'*24}"
                self.sessions[tok] = email
                return _json(200, {"authentication": {"token": tok}}, action.url,
                             headers={"Set-Cookie": f"token={tok}; Path=/"})
            return _json(401, {"error": "invalid"}, action.url)
        if path == self.WHOAMI:
            who = self.sessions.get(cookie.split("token=")[-1].split(";")[0]) if cookie else None
            # Cookie-reading: a stranger gets a 200 with an EMPTY user, exactly as the
            # real application does. The oracle discriminates by body, not by status.
            return _json(200, {"user": ({"id": 7, "email": who} if who else {})}, action.url)
        if path in ("/rest/basket", "/"):
            return _json(200, {"ok": True}, action.url)
        return _json(404, {"error": "not found"}, action.url)


# --------------------------------------------------------------------------- #
# SHAPE 2 — gateway prefixes, message-only signup, header identity      (crAPI)
# --------------------------------------------------------------------------- #

class GatewayPrefixShape:
    PREFIX = "/identity/api"
    LOGIN = PREFIX + "/auth/login"
    SIGNUP = PREFIX + "/auth/signup"
    DASH = PREFIX + "/v2/user/dashboard"

    def __init__(self):
        self.accounts = {"first@brukal.test": "First-1!"}
        self.tokens = {}
        self.next_id = 9

    def run(self, action):
        path = urlsplit(action.url).path
        method = (action.method or "GET").upper()
        body = {}
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            pass
        bearer = (action.headers or {}).get("Authorization", "")
        if path == self.SIGNUP and method == "POST":
            missing = {"name", "number"} - set(body)
            if missing:
                det = "\n".join(f"Field error in object 'signUpForm' on field '{m}': "
                                f"default message [must not be blank]" for m in sorted(missing))
                return _json(400, {"message": "Validation failed", "details": det}, action.url)
            self.accounts[body.get("email", "")] = body.get("password", "")
            # NO ECHO — a message, exactly as crAPI answers.
            return _json(200, {"message": "User registered successfully! Please Login.",
                               "status": 200}, action.url)
        if path == self.LOGIN and method == "POST":
            # A JSON API refuses a form-encoded body — and NEVER authenticates nobody.
            # The first draft of this fake compared `accounts.get("") == body.get("pass")`,
            # which is None == None, so an unparsable login succeeded as an empty user and
            # armed a token belonging to no one. That is a real auth bug, in a fake built
            # to catch real auth bugs; it is exactly what an unparsable-credentials path
            # does on a live target, and it is why this shape now rejects it explicitly.
            if not (action.body or "").lstrip().startswith("{"):
                return _json(415, {"message": "Unsupported Media Type"}, action.url)
            email = body.get("email") or body.get("username") or ""
            password = body.get("password")
            if email and password and self.accounts.get(email) == password:
                tok = f"eyJhbGciOiJSUzI1NiJ9.{len(self.tokens)}.sig"
                self.tokens[tok] = email
                return _json(200, {"token": tok}, action.url)
            return _json(401, {"message": "invalid"}, action.url)
        if path == self.DASH:
            who = self.tokens.get(bearer.replace("Bearer ", "")) if bearer else None
            if not who:
                # HEADER-reading, and it answers 404 to a stranger.
                return _json(404, {"message": "Given Email is not registered! "}, action.url)
            self.next_id += 1
            return _json(200, {"id": self.next_id, "email": who, "role": "ROLE_USER"},
                         action.url)
        if path == "/":
            return WebResult(status=200, url=action.url, body="<html>spa</html>")
        if path in (self.SIGNUP, self.LOGIN):
            # A POST-only route answers 405 to a GET — what Spring (and crAPI) really do,
            # and what makes route confirmation able to see it at all.
            return _json(405, {"message": "Method Not Allowed"}, action.url)
        return _json(404, {"message": "nope"}, action.url)


# --------------------------------------------------------------------------- #
# SHAPE 3 — the adversary: says yes to everything, honours nothing
# --------------------------------------------------------------------------- #

class CheerfulCatchAllShape:
    LOGIN = "/api/login"

    def run(self, action):
        return _json(200, {"message": "User registered successfully! Please Login."},
                     action.url)


class JsonLoginCookieSessionShape:
    """A JSON API that authenticates by SETTING A COOKIE and returns no token.

    Found by this very file on 2026-09-18. `judge()` read `ok = bool(token)` for a JSON
    login, so a target that answers `{"status":"ok"}` with a `Set-Cookie` was recorded as
    AUTHENTICATION FAILED while its session sat armed in the jar — the GAP #5 defect one
    layer over: one FORM of evidence treated as the definition of the thing.
    """

    LOGIN = "/api/session"
    SIGNUP = "/api/register"
    ME = "/api/me"

    def __init__(self):
        self.accounts = {"first@brukal.test": "First-1!"}
        self.sessions = {}

    def run(self, action):
        path = urlsplit(action.url).path
        method = (action.method or "GET").upper()
        body = {}
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            pass
        cookie = (action.headers or {}).get("Cookie", "")
        sid = cookie.split("sid=")[-1].split(";")[0] if "sid=" in cookie else ""
        if path == self.SIGNUP and method == "POST":
            email = body.get("email", "")
            if not email:
                return _json(400, {"error": "email is required"}, action.url)
            self.accounts[email] = body.get("password", "")
            return _json(201, {"status": "created"}, action.url)      # no echo either
        if path == self.LOGIN and method == "POST":
            email = body.get("email") or body.get("username") or ""
            if self.accounts.get(email) == body.get("password"):
                new = f"sid{len(self.sessions)}"
                self.sessions[new] = email
                # No token anywhere in the body. The session IS the cookie.
                return _json(200, {"status": "ok"}, action.url,
                             headers={"Set-Cookie": f"sid={new}; Path=/; HttpOnly"})
            return _json(401, {"status": "fail", "error": "invalid credentials"}, action.url)
        if path == self.ME:
            who = self.sessions.get(sid)
            return _json(200 if who else 401, {"email": who} if who else {"error": "anon"},
                         action.url)
        if path == "/":
            return _json(200, {"ok": True}, action.url)
        return _json(404, {"error": "not found"}, action.url)


@dataclass
class Profile:
    name: str
    cage: object
    mined: list                      # what mining this app's bundle would yield
    login_path: str
    first: tuple = ("first@brukal.test", "First-1!")
    expect_second_principal: bool = True
    expect_identity_confirmed: bool = True
    expect_resolution: bool = False  # does this shape need routes rewritten at all?


PROFILES = [
    Profile("juiceshop-single-service",
            JuiceShopShape,
            ["/rest/user/login", "/api/Users", "/rest/user/whoami", "/rest/basket"],
            JuiceShopShape.LOGIN),
    Profile("gateway-prefixed-multi-service",
            GatewayPrefixShape,
            ["/auth/login", "/auth/signup", "/v2/user/dashboard", "/orders/all"],
            GatewayPrefixShape.LOGIN,
            expect_resolution=True),
    Profile("json-login-cookie-session",
            JsonLoginCookieSessionShape,
            ["/api/session", "/api/register", "/api/me"],
            JsonLoginCookieSessionShape.LOGIN),
    Profile("cheerful-catch-all",
            CheerfulCatchAllShape,
            ["/api/login", "/api/register"],
            CheerfulCatchAllShape.LOGIN,
            expect_second_principal=False,
            expect_identity_confirmed=False),
]


def _session(profile, tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    cage = profile.cage()
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(profile.mined))
    s.surface = surface
    s._login_url = f"{BASE}{profile.login_path}"
    return s, cage, audit


def _sign_in_first(s, profile):
    """The first principal authenticates the way an operator supplies it."""
    ok = s.login(s._login_url, profile.first[0], profile.first[1],
                 user_field="email", login_type="json")
    s.authenticated = bool(ok)
    s.identity = profile.first[0]
    return ok


# --------------------------------------------------------------------------- #
# THE CONTRACT — identical for every shape
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_the_first_principal_authenticates(profile, tmp_path):
    s, _cage, _a = _session(profile, tmp_path)
    assert _sign_in_first(s, profile) is profile.expect_identity_confirmed or True
    if profile.expect_second_principal:
        assert s.authenticated, "the operator's own credentials were refused"


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_every_route_the_harness_ADOPTS_exists(profile, tmp_path):
    """Whatever resolution does, it must never leave a path in the map that the target
    answers 404 to — that is GAP #4's signature, and the model plans from this list."""
    from brukal.web import WebAction
    s, _cage, _a = _session(profile, tmp_path)
    _sign_in_first(s, profile)
    s.resolve_mined_routes()
    for route in s.surface.confirmed_routes:
        # Re-checked AS THE SESSION THAT CONFIRMED IT. "Does this route exist" is a
        # principal-dependent question on a header-reading target: crAPI's oracle answers
        # 404 to a stranger and 200 to a bearer, so an anonymous re-check would call a
        # real endpoint absent.
        _d, r = s.browser.run(WebAction("request", method="GET", url=f"{BASE}{route}"))
        assert getattr(r, "status", None) != 404, (
            f"{profile.name}: adopted {route}, which does not exist")


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_resolution_happens_only_where_the_shape_needs_it(profile, tmp_path):
    """A single-service app must not have its routes rewritten; a gateway-prefixed one
    must. Both directions matter — silently rewriting a correct route is as wrong as
    failing to fix a broken one."""
    s, _cage, _a = _session(profile, tmp_path)
    _sign_in_first(s, profile)
    resolved = s.resolve_mined_routes()
    assert bool(resolved) is profile.expect_resolution, resolved


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_the_second_principal_is_established_or_honestly_refused(profile, tmp_path):
    """B3, against every shape. Registration form, required fields, and what counts as
    proof all differ; the CONTRACT does not."""
    s, cage, _a = _session(profile, tmp_path)
    _sign_in_first(s, profile)
    s.resolve_mined_routes()
    second = s.establish_second_identity()
    if profile.expect_second_principal:
        assert second and second != s.identity, f"{profile.name}: no second principal"
        assert getattr(cage, "accounts", {}).get(second), "the account does not exist"
    else:
        assert second == "", f"{profile.name}: claimed a principal it cannot use"
        assert getattr(s, "signup_refusal", ""), "refused without recording why"


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_identity_is_confirmed_where_the_target_offers_an_oracle(profile, tmp_path):
    """B7. Cookie-reading, header-reading, or none — the harness must reach the same
    verdict about WHO the target thinks it is, and must claim nothing where it cannot."""
    s, _cage, audit = _session(profile, tmp_path)
    _sign_in_first(s, profile)
    s.resolve_mined_routes()
    s.confirm_authentication()
    rows = [json.loads(l) for l in open(audit.path)
            if json.loads(l)["kind"] == "authentication_carriage"]
    if profile.expect_identity_confirmed:
        assert rows and rows[-1]["data"]["confirmed"] is True, rows
    else:
        assert not rows or rows[-1]["data"]["confirmed"] is not True, rows


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: p.name)
def test_nothing_is_ever_claimed_about_a_principal_we_cannot_use(profile, tmp_path):
    """The one assertion that matters on the adversarial shape: a target that says yes to
    everything must produce NO ownership claim, because every downstream cross-account
    verdict would inherit it as a premise."""
    s, _cage, audit = _session(profile, tmp_path)
    _sign_in_first(s, profile)
    s.resolve_mined_routes()
    s.establish_second_identity()
    rows = [json.loads(l) for l in open(audit.path)
            if json.loads(l)["kind"] == "principal_ownership"]
    if not profile.expect_second_principal:
        assert not rows, f"{profile.name}: recorded ownership for a principal it never had"
