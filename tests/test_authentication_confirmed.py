"""
test_authentication_confirmed.py — after authenticating, the harness CONFIRMS it is
authenticated, and refuses to run authenticated experiments when it cannot.

THE PROPERTY
    `login()` returning True means "the login endpoint accepted our credentials and we
    stored something". It does NOT mean the thing we stored is honoured by the endpoints
    we are about to reason about. Those are two different claims and the harness has only
    ever checked the first.

THE DEFECT THIS PINS (measured in run CM1, 2026-09-10)
    A JSON login stores the token as `Authorization: Bearer …` and nothing else. Juice
    Shop v20.2.0's `/rest/user/whoami` reads ONLY the `token` cookie. Measured from
    inside the cage, one token throughout:

        whoami + Authorization: Bearer …   ->  {"user":{}}
        whoami + Cookie: token=…           ->  {"user":{"id":25,"email":…}}
        whoami anonymous                   ->  {"user":{}}
        /api/Users/25 + Authorization      ->  200

    So the session IS held and IS honoured — by every endpoint except the one that says
    who you are. **The authenticated answer and the anonymous answer are byte-identical**,
    which is the same collapse `c829482` closed for a missing second principal, arriving
    this time from the target's side.

    Two of CM1's seven experiments chose `whoami` as their setup, got `{"user":{}}`, and
    died at `no field 'id' in the setup response`. Any cross-account comparison built on
    that setup would have compared a stranger with a stranger and been judged.

WHY A COOKIE IS NOT SIMPLY SYNTHESISED AND FORGOTTEN
    Because "we set a cookie and carried on" is the same unchecked claim one layer down.
    The property is CONFIRMATION: probe identity, compare against an anonymous control,
    and record which carriage actually worked. If none does, an authenticated experiment
    is unconstructible and must be refused — never judged — exactly as
    `SecondPrincipalUnavailable` refuses one whose second principal does not exist.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal import redact
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"
LOGIN = f"{BASE}/rest/user/login"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MjV9.s1gn4tur3-not-a-real-key"
USER, PASSWORD = "a@brukal.test", "Pw-A-1!"

AUTHED_BODY = json.dumps({"user": {"id": 25, "email": USER}})
ANON_BODY = json.dumps({"user": {}})


class _Target:
    """A faithful double: it decides from the REQUEST HEADERS, the way a real app does.

    `mode` picks which carriage the identity endpoint honours — the whole point of the
    fix is that these three targets must be told apart, so a double that answered the
    same way for all three would let the fix pass without doing anything.
    """

    def __init__(self, mode: str, echo_token: bool = False):
        self.mode = mode                  # "cookie" | "header" | "neither"
        self.echo_token = echo_token      # answer with the credential in the body
        self.seen: list = []

    @staticmethod
    def _cookies(headers: dict) -> dict:
        raw = ""
        for k, v in (headers or {}).items():
            if k.lower() == "cookie":
                raw = v or ""
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _bearer(headers: dict) -> str:
        for k, v in (headers or {}).items():
            if k.lower() == "authorization":
                return (v or "")[7:] if (v or "").lower().startswith("bearer ") else ""
        return ""

    def _is_authed(self, headers: dict) -> bool:
        if self.mode == "cookie":
            return self._cookies(headers).get("token") == TOKEN
        if self.mode == "header":
            return self._bearer(headers) == TOKEN
        return False

    def run(self, action):
        self.seen.append((action.method, action.url, dict(action.headers or {})))
        path = action.url.split(TARGET, 1)[-1].split("/", 1)[-1]
        path = "/" + path.split("?", 1)[0].lstrip("/")
        if action.url.rstrip("/").endswith("/rest/user/login"):
            if action.method == "POST":
                return WebResult(status=200, url=action.url, headers={},
                                 body=json.dumps({"authentication": {"token": TOKEN}}))
            return WebResult(status=500, url=action.url, headers={}, body="")
        if path in ("/rest/user/whoami", "/api/me", "/me"):
            authed = self._is_authed(action.headers or {})
            body = AUTHED_BODY if authed else ANON_BODY
            if authed and self.echo_token:
                body = json.dumps({"user": {"id": 25, "email": USER}, "token": TOKEN})
            return WebResult(status=200, url=action.url, headers={}, body=body)
        return WebResult(status=404, url=action.url, headers={}, body="not found")


class _InertKali:
    def run(self, command: str) -> ExecResult:
        return ExecResult(command, 0, "", "")


class _FakeLLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return ""


def _session(tmp_path, target):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _InertKali(), audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(_FakeLLM()),
                      browser=GovernedBrowser(scope, target, audit))
    s.allow_intrusive = True
    return s, audit


def _audit_kinds(audit_path, kind):
    out = []
    for line in Path(audit_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("kind") == kind:
            out.append(str(rec.get("data", "")))
    return out


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_a_cookie_reading_target_is_authenticated_once_confirmed(tmp_path):
    """THE DEFECT. Juice Shop's shape: the token is real, the header is ignored by the
    endpoint that reports identity. Before the fix the harness carried on believing it
    was authenticated while every identity probe read as a stranger.

    Confirmation is deliberately NOT done inside `login()` — see
    `test_confirmation_is_not_paid_on_every_login` below for why — so it is asked for
    here the way the experiment path asks for it."""
    target = _Target("cookie")
    s, _ = _session(tmp_path, target)

    assert s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    s.confirm_authentication()

    from brukal.web import WebAction
    _d, r = s.browser.run(WebAction("request", method="GET",
                                    url=f"{BASE}/rest/user/whoami"))
    assert json.loads(r.body)["user"].get("id") == 25, (
        "the identity endpoint still sees a stranger after a successful login — this is "
        "the CM1 defect: authenticated and anonymous answers are byte-identical")
    assert s.auth_carriage.startswith("cookie:"), s.auth_carriage
    assert s.auth_confirmed is True


def test_a_header_reading_target_is_unchanged(tmp_path):
    """THE BOUNDARY that matters most: the common case must be byte-identical. A fix that
    starts posting cookies at targets that never needed them changes every existing run."""
    target = _Target("header")
    s, _ = _session(tmp_path, target)

    assert s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    s.confirm_authentication()

    assert s.auth_carriage == "header", s.auth_carriage
    assert s.auth_confirmed is True
    assert not (getattr(s.browser, "_cookies", {}) or {}), (
        "a cookie was set on a target whose header carriage already worked")


def test_a_target_honouring_neither_refuses_to_run_authenticated_experiments(tmp_path):
    """No carriage authenticates -> an authenticated experiment is UNCONSTRUCTIBLE. It
    must be refused in the same shape as SecondPrincipalUnavailable, never judged: a
    comparison between two strangers is a claim about Brukal wearing a verdict."""
    from brukal import hypothesis as hyp

    target = _Target("neither")
    s, _ = _session(tmp_path, target)
    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    s.confirm_authentication()

    assert s.auth_confirmed is False, s.auth_carriage

    h = hyp.Hypothesis(
        title="cross-account read", severity="high", comparator="a_denied_b_allowed",
        setup=[], control={"method": "GET", "url": f"{BASE}/api/me", "as": "anonymous"},
        variant={"method": "GET", "url": f"{BASE}/api/me", "as": "self"})
    outcomes: list = []
    confirmed = s._run_one_round([h], outcomes)

    assert confirmed == 0
    assert outcomes and "NOT AUTHENTICATED" in outcomes[0], outcomes
    assert "this is not a result" in outcomes[0].lower(), outcomes


def test_the_refusal_is_its_own_named_exception(tmp_path):
    """Caught BEFORE the generic handler, like SecondPrincipalUnavailable — otherwise it
    becomes 'ERRORED before reaching the target' and reads as a transport problem."""
    from brukal import hypothesis as hyp

    assert issubclass(hyp.PrincipalNotAuthenticated, Exception)
    assert hyp.PrincipalNotAuthenticated is not hyp.SecondPrincipalUnavailable

    target = _Target("neither")
    s, _ = _session(tmp_path, target)
    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    # No explicit confirm(): `_as_identity` owes it and pays it lazily, which is the
    # behaviour the experiment path actually depends on.
    with pytest.raises(hyp.PrincipalNotAuthenticated):
        with s._as_identity("self", "control", f"{BASE}/api/me"):
            pass


# --------------------------------------------------------------------------- #
# The ledger has to carry which carriage worked
# --------------------------------------------------------------------------- #

def test_the_carriage_is_recorded_per_principal(tmp_path):
    """A cross-account claim rests on which principal saw what. 'authenticated' with no
    record of HOW is the same unprovable shape the provenance work (2fdbc7f) closed."""
    target = _Target("cookie")
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    s.confirm_authentication()

    recs = _audit_kinds(audit.path, "authentication_carriage")
    assert recs, "no carriage record on the ledger"
    assert any("cookie:" in r for r in recs), recs
    assert any(USER in r or "self" in r for r in recs), recs


def test_the_second_principal_goes_through_the_same_path(tmp_path):
    """THE BOUNDARY. establish_second_identity() logs in through login(), so the second
    principal must inherit confirmation rather than needing its own copy of it."""
    target = _Target("cookie")
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    s.confirm_authentication()
    before = len(_audit_kinds(audit.path, "authentication_carriage"))

    with s._separate_identity():
        s.login(LOGIN, "b@brukal.test", "Pw-B-1!", user_field="email", login_type="json")
        s.confirm_authentication()
        assert s.auth_confirmed is True
        assert s.auth_carriage.startswith("cookie:")

    after = len(_audit_kinds(audit.path, "authentication_carriage"))
    assert after > before, "the second principal's carriage was never recorded"


# --------------------------------------------------------------------------- #
# The new credential must not leak
# --------------------------------------------------------------------------- #

def test_the_synthesised_cookie_is_registered_with_the_redactor(tmp_path):
    """A cookie we SET is a credential we injected, and every record surface downstream
    of it must mask it. Verified against a target that ECHOES the token back in its own
    body, because that is the path a record actually takes — not assumed."""
    target = _Target("cookie", echo_token=True)
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    s.confirm_authentication()

    assert s.auth_carriage.startswith("cookie:")
    assert redact.text(TOKEN) != TOKEN, "the cookie value was never registered"

    from brukal.web import WebAction
    _d, r = s.browser.run(WebAction("request", method="GET", url=f"{BASE}/api/me"))
    assert TOKEN in r.body, "the double did not echo the token — the test proves nothing"

    ledger = Path(audit.path).read_text(encoding="utf-8")
    assert TOKEN not in ledger, "the injected cookie reached the audit log in cleartext"


# --------------------------------------------------------------------------- #
# What confirmation must NOT cost
# --------------------------------------------------------------------------- #

def test_confirmation_is_not_paid_on_every_login(tmp_path):
    """THE GUARD, and it caught a real regression in this very fix.

    Roughly five detectors call `login()` per engagement. The first cut of this change
    probed inside `login()`, which put an identity sweep on every one of them — the exact
    expense `13bc501` closed — and perturbed the detectors that reason about login's own
    request sequence (session fixation compares the identifier across that boundary).
    Confirmation is owed at login and PAID at first authenticated use."""
    target = _Target("cookie")
    s, _ = _session(tmp_path, target)

    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    after_login = len(target.seen)
    for _ in range(4):
        s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")
    after_five = len(target.seen)

    per_login = (after_five - after_login) / 4
    assert per_login <= 2, (
        f"login() costs {per_login} requests each — confirmation leaked back into it")
    assert s.auth_confirmed is None, "confirmation was taken before it was needed"


def test_confirmation_is_probed_once_across_a_round_of_experiments(tmp_path):
    """`_as_identity` is entered for every setup, control and variant. Probing per entry
    would multiply an identity sweep by the size of the round."""
    from brukal import hypothesis as hyp

    target = _Target("cookie")
    s, _ = _session(tmp_path, target)
    s.login(LOGIN, USER, PASSWORD, user_field="email", login_type="json")

    h = hyp.Hypothesis(
        title="t", severity="low", comparator="status_differs", setup=[],
        control={"method": "GET", "url": f"{BASE}/api/me", "as": "self"},
        variant={"method": "GET", "url": f"{BASE}/me", "as": "self"})
    before = len(target.seen)
    s._run_one_round([h, h, h], [])
    probes = [u for _m, u, _h in target.seen[before:] if "/whoami" in u]

    # ONE sweep on this target is exactly four probes: anonymous twice (the stability
    # control), the carriage we hold once, then the first cookie name that proves itself.
    # Three experiments enter `_as_identity` twice each, so an unmemoised confirmation
    # would be six sweeps — the number this guard exists to keep at one.
    assert s.auth_confirmed is True
    assert len(probes) == 4, (
        f"the identity endpoint was swept {len(probes)} times for one round — one sweep "
        f"is 4 probes, so the memo is not holding")
