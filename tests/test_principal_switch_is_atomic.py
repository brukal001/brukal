"""
test_principal_switch_is_atomic.py — switching principals must switch ALL of a principal.

THE MEASURED PROBLEM (run CM4, 2026-09-14)
    `login()` sets `last_jwt` on EVERY login, including the second principal's inside
    `establish_second_identity`. `_separate_identity` restored the browser's `auth_header`
    and cookie jar and six `Principal` fields — and NOT `last_jwt`.

    `confirm_authentication` reads `token = self.session_token()`, which returns `last_jwt`
    FIRST. So, run late, it took the SECOND principal's token, installed it as a cookie,
    probed the identity oracle, got the SECOND principal back, and then
      (1) recorded that id as `self`'s — crossing the ownership map,
      (2) settled the carriage as confirmed for the FIRST principal, and
      (3) returned leaving the second principal's token in the jar.
    Every later request issued `as: self` carried the second principal's session. CM4's one
    cross-account confirmation was therefore the second principal reading its OWN basket.

WHY THE EXISTING GUARD DID NOT CATCH IT
    `test_principal_identifier_disclosure.py::test_the_ids_are_per_principal_and_never_crossed`
    was green throughout. Its double has **no `last_jwt` to leak** and its identity oracle
    reads the Authorization header, so the failing path does not exist inside it.

    **A guard that only runs against a double is not a guard for a defect living in state
    the double lacks.** The fixture here deliberately carries the FULL session state and
    honours the COOKIE — the way the live target does — so the defect is reachable.

THE TWO PROPERTIES
    1. A principal's session switches ATOMICALLY: every field that constitutes it.
    2. A confirmation proves THIS principal's session is honoured — not that *a* session is.
       The oracle's answer is checked against the handles we know, and an answer naming a
       DIFFERENT principal is a recorded failure, never a confirmation.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope, redact
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.auth import Principal
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"
LOGIN = f"{BASE}/rest/user/login"
MAIL_A, PASS_A = "a@brukal.test", "Pw-A-1!"
TOK_A, TOK_B = "tok-AAAA-1111", "tok-BBBB-2222"


class _CookieTarget:
    """Juice Shop's shape, which is what makes the defect reachable.

    The identity oracle reads the COOKIE ONLY — a bearer header alone answers anonymously,
    exactly as `/rest/user/whoami` did in CM4. That is what drives `confirm_authentication`
    into its cookie branch, where it installs `session_token()` — and `session_token()`
    returns `last_jwt` first.
    """

    ACCOUNTS = {MAIL_A: {"token": TOK_A, "id": 25, "bid": 6}}

    def __init__(self, oracle: bool = True):
        self.oracle = oracle
        self.registered: dict = {}

    def _all(self):
        return {**self.ACCOUNTS, **self.registered}

    def _by_cookie(self, headers):
        raw = ""
        for k, v in (headers or {}).items():
            if k.lower() == "cookie":
                raw = v or ""
        for part in raw.split(";"):
            if "=" in part:
                _k, _, val = part.partition("=")
                for mail, acc in self._all().items():
                    if acc["token"] == val.strip():
                        return mail, acc
        return "", None

    def run(self, action):
        url, body = action.url, action.body or ""
        if url.endswith("/rest/user/login"):
            try:
                sent = json.loads(body or "{}")
            except Exception:
                sent = {}
            acc = self._all().get(sent.get("email", ""))
            if not acc:
                return WebResult(status=401, url=url, headers={}, body='{"error":"no"}')
            return WebResult(status=200, url=url, headers={}, body=json.dumps(
                {"authentication": {"token": acc["token"], "umail": sent["email"],
                                    "bid": acc["bid"]}}))
        if url.endswith("/api/Users") and action.method == "POST":
            try:
                sent = json.loads(body)
            except Exception:
                return WebResult(status=400, url=url, headers={}, body='{"error":"json"}')
            if not sent.get("email"):
                return WebResult(status=400, url=url, headers={}, body='{"error":"no"}')
            n = 40 + len(self.registered)
            self.registered[sent["email"]] = {"token": TOK_B, "id": n, "bid": n + 1}
            return WebResult(status=201, url=url, headers={}, body=json.dumps(
                {"status": "success", "data": {"id": n, "email": sent["email"]}}))
        if url.endswith("/rest/user/whoami"):
            if not self.oracle:
                return WebResult(status=404, url=url, headers={}, body="nope")
            mail, acc = self._by_cookie(action.headers)     # COOKIE ONLY, as in CM4
            if acc is None:
                return WebResult(status=200, url=url, headers={}, body='{"user":{}}')
            return WebResult(status=200, url=url, headers={}, body=json.dumps(
                {"user": {"id": acc["id"], "email": mail}}))
        if url.rstrip("/") in (BASE, f"http://{TARGET}:3000"):
            return WebResult(status=200, url=url, headers={"Content-Type": "text/html"},
                             body='<html><body><script>fetch("/api/Users");'
                                  'fetch("/rest/user/whoami");</script></body></html>')
        return WebResult(status=404, url=url, headers={}, body="nope")


class _Kali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _LLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return "[]"


def _session(tmp_path, target):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(_LLM()),
                      browser=GovernedBrowser(scope, target, audit))
    s.allow_intrusive = True
    return s, audit


def _records(audit_path, kind):
    out = []
    for line in Path(audit_path).read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("kind") == kind:
            out.append(e.get("data", {}))
    return out


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# PART 2 — the confirmation must prove the RIGHT principal
# --------------------------------------------------------------------------- #

def test_confirming_A_after_B_is_established_still_probes_as_A(tmp_path):
    """THE CM4 SEQUENCE, and the reason the run's only confirmation was false.

    Nothing here is unusual: the loop pays the confirmation lazily, at first authenticated
    use, which in CM4 put it 300 seconds after the second principal existed."""
    target = _CookieTarget()
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    second = s.establish_second_identity()
    assert second and second != MAIL_A

    s.confirm_authentication()          # LATE, the CM4 order

    ids = s.principal_identifiers()
    self_ids = {str(v) for v in ids.get("self", {}).values()}
    second_ids = {str(v) for v in ids.get("second", {}).values()}
    assert "25" in self_ids, (
        f"the oracle answered as somebody else and it was filed under self: {ids}")
    assert not (self_ids & second_ids), f"the ownership map is crossed: {ids}"


def test_a_probe_naming_another_principal_is_a_recorded_failure(tmp_path):
    """Never filed under the requesting principal. A confirmation that proves SOMEBODY is
    logged in proves nothing the cross-account claim needs."""
    target = _CookieTarget()
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    second = s.establish_second_identity()

    # Force exactly CM4's corrupted state: our own transport, somebody else's token.
    s.last_jwt = TOK_B
    s._carriage_memo = None
    s.confirm_authentication()

    carriage = _records(audit.path, "authentication_carriage")
    confirmed_as_a = [c for c in carriage
                      if c.get("principal") == MAIL_A and c.get("confirmed") is True]
    assert not confirmed_as_a, (
        f"a probe that returned another principal was recorded as A's confirmation: "
        f"{confirmed_as_a}")

    mism = _records(audit.path, "authentication_mismatch")
    assert mism, "the mismatch was not recorded anywhere"
    assert mism[0].get("requested_as") == MAIL_A, mism[0]
    assert mism[0].get("answered_as") == second, mism[0]


def test_the_second_principals_own_confirmation_is_recorded_as_the_second(tmp_path):
    """BOUNDARY. The mismatch check must not make a legitimate second-principal
    confirmation impossible — asking as B and being told B is correct."""
    target = _CookieTarget()
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    second = s.establish_second_identity()
    assert second

    ids = s.principal_identifiers()
    assert ids.get("second"), f"the second principal recorded nothing of its own: {ids}"
    own = {str(v) for v in ids["second"].values()}
    assert not (own & {str(v) for v in ids.get("self", {}).values()}), ids


# --------------------------------------------------------------------------- #
# PART 1 — the switch is atomic
# --------------------------------------------------------------------------- #

def test_every_principal_field_is_restored_by_the_switch(tmp_path):
    """ENUMERATED, so a field added to `Principal` later cannot quietly go unswitched.

    Each field is set to a sentinel INSIDE the context; all must be back outside it. A
    field-by-field restore that forgets one fails here — which is exactly how `last_jwt`
    was lost."""
    s, _ = _session(tmp_path, _CookieTarget())
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")

    before = dict(s._ensure_principal().__dict__)
    fields = [f.name for f in dataclasses.fields(Principal)]
    assert len(fields) >= 9, fields

    with s._separate_identity():
        p = s._ensure_principal()
        for name in fields:
            cur = getattr(p, name)
            setattr(p, name, "SENTINEL" if isinstance(cur, str) else (not cur))

    after = dict(s._ensure_principal().__dict__)
    for name in fields:
        assert after[name] == before[name], (
            f"`Principal.{name}` was NOT restored by _separate_identity "
            f"({before[name]!r} -> {after[name]!r}). Every field that constitutes a "
            f"principal's session must switch with it.")


def test_last_jwt_specifically_does_not_leak(tmp_path):
    """The CM4 field, named on its own so a regression says so in one line."""
    target = _CookieTarget()
    s, _ = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    assert s.last_jwt == TOK_A
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    s.establish_second_identity()
    assert s.last_jwt == TOK_A, (
        f"last_jwt still holds the second principal's token: {s.last_jwt!r}")
    assert s.session_token() == TOK_A


def test_the_session_in_effect_is_that_principals_field_by_field(tmp_path):
    """After the switch, what is ON THE WIRE is the principal we asked for."""
    target = _CookieTarget()
    s, _ = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    second = s.establish_second_identity()
    assert second

    from brukal.web import WebAction
    s.confirm_authentication()

    # `self` is checked AGAINST THE TARGET, because that is the CM4 regression: the app
    # itself must name A.
    with s._as_identity("self", "probe", f"{BASE}/rest/user/whoami"):
        _d, r = s.browser.run(WebAction("request", method="GET",
                                        url=f"{BASE}/rest/user/whoami"))
    assert MAIL_A in (r.body or ""), f"'self' was not A on the wire: {r.body!r}"

    # `second` is checked FIELD BY FIELD on the transport, deliberately, and not against
    # the oracle. This double's login issues a bearer token and no Set-Cookie, so the
    # second principal holds a header and an empty jar — and this oracle reads the cookie
    # only. That the app then answers anonymously is CM2's recorded P1 ("the second
    # principal is anonymous to half the application"), a separate open defect. Asserting
    # the oracle here would test that defect rather than this fix.
    second_auth = (s._second_identity or {}).get("auth", "")
    assert second_auth and TOK_B in second_auth, s._second_identity
    with s._as_identity("second", "probe", f"{BASE}/rest/user/whoami"):
        assert s.browser.auth_header == second_auth, s.browser.auth_header
        assert TOK_A not in (s.browser.auth_header or ""), "A's token leaked into `second`"
        assert TOK_A not in json.dumps(s.browser._cookies or {}), "A's cookie leaked"

    # And back out, `self` is A again — the switch restores as well as it sets.
    assert s.session_token() == TOK_A
    with s._as_identity("self", "probe", f"{BASE}/rest/user/whoami"):
        _d, r3 = s.browser.run(WebAction("request", method="GET",
                                         url=f"{BASE}/rest/user/whoami"))
    assert MAIL_A in (r3.body or ""), f"'self' was not A after the switch: {r3.body!r}"


# --------------------------------------------------------------------------- #
# BOUNDARY — the single-principal path is untouched
# --------------------------------------------------------------------------- #

def test_the_single_principal_path_still_confirms(tmp_path):
    """BOUNDARY. No second principal anywhere; the ordinary case must be unchanged."""
    target = _CookieTarget()
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    carriage = s.confirm_authentication()
    assert carriage.startswith("cookie:"), carriage
    assert s.auth_confirmed is True
    rec = _records(audit.path, "authentication_carriage")
    assert rec and rec[0]["principal"] == MAIL_A and rec[0]["confirmed"] is True, rec


def test_no_oracle_still_degrades_quietly(tmp_path):
    """BOUNDARY. Most targets expose no identity endpoint; `None` is not a refusal."""
    target = _CookieTarget(oracle=False)
    s, audit = _session(tmp_path, target)
    s.login(LOGIN, MAIL_A, PASS_A, user_field="email", login_type="json")
    s.confirm_authentication()
    assert s.auth_confirmed is None, s.auth_confirmed
    assert not _records(audit.path, "authentication_mismatch"), (
        "a missing oracle was reported as a mismatch")
