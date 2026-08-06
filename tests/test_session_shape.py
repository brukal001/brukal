"""A session is a session, however it is carried.

Five separate defects this session traced to one substitution: code asking
`if self.last_jwt` when it meant "am I logged in". That is not the same question — it is
"am I logged in to a JSON API that issues bearer tokens" — and on a cookie-session
application the answer was always no. The BFLA targeting, the BOLA sweep, the model's
authentication briefing and the comparator that judges denial all silently did nothing,
each while a coverage row claimed it had run.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000"


class _Cage:
    def __init__(self, mode="cookie"):
        self.mode = mode

    def run(self, action):
        if action.method == "POST":
            if self.mode == "cookie":
                return WebResult(status=302, url=action.url, body="",
                                 headers={"Location": "/app", "Set-Cookie": "sid=abc"})
            return WebResult(status=200, url=action.url,
                             body='{"auth_token": "tok-s3ss10nvalue"}', headers={})
        return WebResult(status=200, url=action.url, headers={},
                         body='<form><input name="password" type="password"></form>')


def _sess(mode="cookie"):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, _Cage(mode), audit))


def test_a_cookie_login_is_a_session():
    s = _sess("cookie")
    assert s.has_session() is False
    assert s.login(f"{ROOT}/login", "u", "p")
    assert s.has_session() is True
    assert s.session_token() == "", "a cookie session has no bearer token"


def test_a_token_login_is_a_session():
    s = _sess("token")
    assert s.login(f"{ROOT}/login", "u", "p", login_type="json")
    assert s.has_session() is True
    assert s.session_token(), "a token session must expose its token"


def test_authz_targeting_no_longer_requires_a_token():
    """`bfla_targets` returned None the moment last_jwt was empty, so the whole
    authorization family was unreachable on any cookie-session application."""
    from brukal import webmap
    s = _sess("cookie")
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.add_routes(["/users/{username}/password"])
    s.surface.write_operations.append(("PUT", "/users/{username}/password"))
    assert s.bfla_targets() is None, "no session yet: nothing to target"
    assert s.login(f"{ROOT}/login", "u", "p")
    # With a cookie session it may now proceed as far as the victim search, which is
    # exactly the step that never ran before.
    assert s.has_session() is True


def test_an_error_status_is_never_a_successful_login():
    """The third distinct way login() claimed a session it did not have. All three were
    the same mistake: inferring success from the ABSENCE of a password field rather than
    from evidence of a session."""
    class _Rejects:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=400, url=action.url,
                                 body='{"message":"malformed"}', headers={})
            return WebResult(status=200, url=action.url, headers={},
                             body='<form><input name="password" type="password"></form>')
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Rejects(), audit))
    assert s.login(f"{ROOT}/login", "u", "p") is False
    assert s.has_session() is False


def test_acting_as_another_principal_does_not_rename_us():
    """login() adopts the first username it authenticates when `identity` is empty, so
    proving a takeover could quietly rename US to the VICTIM — and every later check
    asking "whose objects are ours" would reason about the wrong account."""
    s = _sess("cookie")
    assert s.login(f"{ROOT}/login", "me", "p")
    assert s.identity == "me"
    with s._separate_identity():
        s.login(f"{ROOT}/login", "victim", "p")
    assert s.identity == "me"


def test_a_200_that_is_not_the_login_page_is_not_a_session():
    """The fourth face of the same mistake. "The answer no longer shows a password
    field" is true of a redirect, of a 400, and of any 200 that simply is not the login
    page — "your account is locked" has no password field either. A login that worked
    hands back a credential; requiring that is the difference between observing success
    and failing to observe failure."""
    class _Locked:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=200, url=action.url, headers={},
                                 body="<h1>Your account is locked.</h1>")
            return WebResult(status=200, url=action.url, headers={},
                             body='<form><input name="password" type="password"></form>')
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Locked(), audit))
    assert s.login(f"{ROOT}/login", "u", "p") is False
    assert s.has_session() is False


def test_a_200_that_issues_a_cookie_is_a_session():
    """The other direction must keep working: plenty of apps answer 200 and set the
    session cookie without redirecting."""
    class _SetsCookie:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=200, url=action.url,
                                 headers={"Set-Cookie": "sid=xyz; Path=/"},
                                 body="<h1>Welcome back</h1>")
            return WebResult(status=200, url=action.url, headers={},
                             body='<form><input name="password" type="password"></form>')
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _SetsCookie(), audit))
    assert s.login(f"{ROOT}/login", "u", "p") is True


def test_preflight_refuses_to_start_against_an_unreachable_target():
    """A run once spent $0.46 and thirty-two model calls against a target it could not
    touch: the cage had failed to start on a stale bind mount, so every request died at
    the source. The health monitor reported it honestly — "none of 13 requests were
    answered" — but only afterwards, once the budget was gone.

    The abort now requires a KNOWN origin. This test used to omit one, asserting a hard
    stop from a silent port 80 — which blocked two healthy engagements on applications
    listening elsewhere before recon had a chance to find the port."""
    from brukal.assist import _preflight

    class _Dead:
        def run(self, action):
            raise OSError("connection refused")

    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Dead(), audit))
    s._login_url = "http://127.0.0.1:9090/login"      # we were told where it lives
    assert _preflight(s) is False
    assert any("PREFLIGHT FAILED" in n for n in s.notes)


def test_preflight_passes_when_the_target_answers_at_all():
    """A 404 or a 500 is an answer: the question is whether the path works, not whether
    the target likes us."""
    from brukal.assist import _preflight

    class _Answers:
        def run(self, action):
            return WebResult(status=404, url=action.url, headers={}, body="nope")

    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Answers(), audit))
    assert _preflight(s) is True


def test_preflight_probes_the_origin_the_run_will_use():
    """The first version assumed http://{target}/ — port 80 — and blocked a healthy
    engagement whose application was on :9090, one line after the login to that same
    port had succeeded. A guard that fails closed is right; one that fails closed for
    the wrong reason costs a run and teaches the operator to ignore it."""
    from brukal.assist import _preflight

    class _OnlyOn9090:
        def __init__(self):
            self.seen = []

        def run(self, action):
            self.seen.append(action.url)
            if ":9090" in action.url:
                return WebResult(status=302, url=action.url, headers={}, body="")
            raise OSError("connection refused")

    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    cage = _OnlyOn9090()
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, cage, audit))
    s._login_url = "http://127.0.0.1:9090/login"
    assert _preflight(s) is True, f"probed {cage.seen}"
    assert any(":9090" in u for u in cage.seen)


def test_preflight_does_not_abort_when_it_never_knew_the_port():
    """A failure is only evidence of a dead target when we knew where to knock. With no
    operator-supplied URL there is no port but 80, and recon has not run yet — so an app
    on :5013 answers nothing on 80 and that proves nothing. This guard blocked two
    healthy engagements; it has cost more runs than it saved."""
    from brukal.assist import _preflight

    class _Dead:
        def run(self, action):
            raise OSError("connection refused")

    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Dead(), audit))
    assert _preflight(s) is True, "aborted on a port it was never told about"
    assert any("could not reach" in n for n in s.notes)


def test_preflight_still_aborts_when_the_origin_was_known():
    """The case it exists for: we were told exactly where the application is, and
    nothing answered."""
    from brukal.assist import _preflight

    class _Dead:
        def run(self, action):
            raise OSError("connection refused")

    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _Dead(), audit))
    s._login_url = "http://127.0.0.1:9090/login"
    assert _preflight(s) is False
