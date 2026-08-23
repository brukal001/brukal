"""test_login_seed_get_cost.py — a probe that yielded nothing is not repeated 25 times.

`JsonAuth.authenticate` issues a seeding GET on the login URL before every POST. The
comment defending it is right in general: some APIs hand back an anti-CSRF or session
cookie there, and dropping it unconditionally would change the cookie jar and break those
targets silently.

On a POST-only login it is pure waste. Juice Shop answers **500** to `GET
/rest/user/login`, sets nothing, and the request still costs a rate slot. Nothing retries
— the cost is that roughly five detectors each call `login()` (default credentials, BFLA,
session management, password policy, and `establish_second_identity`), and each call is
two requests.

Measured across three runs:

| run | duration | web decisions | login decisions | hard:web-rate | density |
|---|---|---|---|---|---|
| 2C   | 18.3 min | 109 | 34 (31%) |  1 |  6.0/min |
| 2C2  | 49.8 min | 106 | 32 (30%) |  2 |  2.1/min |
| 2C3 pre-flight | 2.3 min | 88 | **51 (58%)** | **26** | **37.5/min** |

Invisible for two full engagements, then decisive: the denied requests included the
second principal's registration POST, so a P3 efficiency issue directly caused a P1
evidence problem by exhausting a budget at the wrong moment.

So the GET is made **conditional on evidence**, never deleted: if it answers 5xx or sets
no cookie, that fact is recorded for that endpoint and the GET is skipped on subsequent
logins in the same engagement. The skip is recorded, not silent — a reader must be able to
see why a request that used to be there is gone.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path


class _Cage:
    """A login endpoint whose GET behaviour is configurable."""

    def __init__(self, *, get_status=500, get_sets_cookie=False):
        self.seen, self.get_status = [], get_status
        self.get_sets_cookie = get_sets_cookie

    def run(self, action):
        from brukal.web import WebResult
        method = (getattr(action, "method", "") or "GET").upper()
        self.seen.append((method, action.url))
        if method == "GET":
            headers = ({"Set-Cookie": "seed=abc123def456; Path=/"}
                       if self.get_sets_cookie else {})
            return WebResult(status=self.get_status, url=action.url,
                             body="" if self.get_status >= 500 else "<html></html>",
                             headers=headers)
        return WebResult(status=200, url=action.url,
                         body=json.dumps({"authentication": {"token": "t" * 40}}))


def _session(cage):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser

    class _LLM:
        def propose(self, system, user, max_tokens=1024):
            return "[]"

    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_LLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess._audit_path = root / "a.jsonl"
    return sess


_URL = "http://127.0.0.1:5000/rest/user/login"


def _login(sess, n=1):
    for i in range(n):
        sess.login(_URL, f"u{i}@x.test", "pw", user_field="email", login_type="json")


def _counts(cage):
    g = sum(1 for m, _ in cage.seen if m == "GET")
    p = sum(1 for m, _ in cage.seen if m == "POST")
    return g, p


def _audit_kinds(sess):
    return [json.loads(l)["kind"]
            for l in Path(sess._audit_path).read_text(encoding="utf-8").splitlines() if l.strip()]


# -- the boundary the existing comment defends -----------------------------------------

def test_a_login_get_that_seeds_a_cookie_is_issued_every_time():
    """The case the comment is right about. An API that hands back a CSRF or session
    cookie on the GET must keep getting it — dropping that would break the target
    silently, which is worse than the waste it saves."""
    cage = _Cage(get_status=200, get_sets_cookie=True)
    sess = _session(cage)
    _login(sess, 4)
    gets, posts = _counts(cage)
    assert posts == 4
    assert gets == 4, f"the seeding GET was skipped on a target that seeds a cookie: {gets}"


def test_a_login_get_that_is_useful_is_never_recorded_as_skippable():
    cage = _Cage(get_status=200, get_sets_cookie=True)
    sess = _session(cage)
    _login(sess, 2)
    assert "login_seed_skipped" not in _audit_kinds(sess)


# -- the waste -----------------------------------------------------------------------------

def test_a_login_get_that_500s_is_issued_once_and_never_again():
    """Juice Shop's exact behaviour. Learn it from one observation, then stop paying."""
    cage = _Cage(get_status=500)
    sess = _session(cage)
    _login(sess, 5)
    gets, posts = _counts(cage)
    assert posts == 5, "the logins themselves must still happen"
    assert gets == 1, f"the useless seeding GET was issued {gets} times, not once"


def test_a_login_get_that_sets_no_cookie_is_also_learned():
    """A 200 that seeds nothing is just as useless as a 500 — the test is what it
    YIELDED, not what it returned."""
    cage = _Cage(get_status=200, get_sets_cookie=False)
    sess = _session(cage)
    _login(sess, 4)
    gets, _ = _counts(cage)
    assert gets == 1, f"a cookie-less seeding GET kept being issued: {gets}"


def test_the_skip_is_recorded_not_silent():
    """A request that used to be there and is now gone must be explainable from the
    ledger alone. A silent optimisation is indistinguishable from a bug."""
    cage = _Cage(get_status=500)
    sess = _session(cage)
    _login(sess, 3)
    kinds = _audit_kinds(sess)
    assert "login_seed_skipped" in kinds, f"the skip left no trace: {set(kinds)}"


def test_the_saving_scales_with_the_number_of_detector_logins():
    """The measured shape: ~5 detectors each call login(). Before, that was 10 requests
    on this target and half of them were 500s."""
    cage = _Cage(get_status=500)
    sess = _session(cage)
    _login(sess, 5)
    gets, posts = _counts(cage)
    total = gets + posts
    assert total == 6, f"5 logins should now cost 6 requests, not 10: {total}"
    assert total < 10


# -- nothing else changes --------------------------------------------------------------------

def test_the_login_still_authenticates_after_the_skip():
    """The saving must not cost the session."""
    cage = _Cage(get_status=500)
    sess = _session(cage)
    _login(sess, 1)
    assert sess.authenticated, "precondition: the first login worked"
    _login(sess, 1)
    assert sess.authenticated, "a login that skipped its seeding GET stopped working"


def test_two_different_login_endpoints_are_learned_independently():
    """The memo is per endpoint. A useless GET at one URL says nothing about another."""
    cage = _Cage(get_status=500)
    sess = _session(cage)
    _login(sess, 3)
    other = "http://127.0.0.1:5000/api/v2/login"
    sess.login(other, "u@x.test", "pw", user_field="email", login_type="json")
    gets = [u for m, u in cage.seen if m == "GET"]
    assert gets.count(_URL) == 1
    assert other in gets, "a second endpoint inherited the first one's verdict"
