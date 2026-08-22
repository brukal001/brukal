"""test_second_identity_json_signup.py — a second principal on a form-less target.

`_register_account` posts the application's own server-rendered `<form>`, which is the
right thing when one exists: an account created through the public signup form is, by
construction, whatever the app grants a stranger, and that is what makes a privilege
claim sound. An Angular SPA serves no such form, so `_signup_form()` returned None,
`establish_second_identity()` returned "", and the whole cross-account class was
unreachable on most modern targets.

Confirmed live against OWASP Juice Shop v20.2.0 on 2026-08-22 before any of this was
written: `/`, `/register` and `/rest/user/register` serve **zero** `<form>` tags, while
`POST /api/Users {"email","password"}` answers **201** with `role: customer`, and that
account then logs in at `/rest/user/login` for a token. The premise is a real endpoint on
a real target, not a guess.

Three things this must not do, each a constraint the project has paid for before:

  * **One execution path.** Registration is a governed web action like any other —
    through the browser, gated, audited. Not a raw urllib call that skips the gate.
  * **Register the credential the moment it is obtained.** `_session_auth_for` does this
    for the first identity. The second identity's session was never registered at all,
    even on the existing form path, so it could reach a record surface unmasked.
  * **The fail-safe stays.** A target with neither a form nor a JSON endpoint must still
    raise `SecondPrincipalUnavailable`, so cross-account experiments are recorded NOT RUN
    rather than silently degraded.

Candidates come from what the CRAWL observed, filtered by an explicit allowlist of
registration path shapes — the discipline of `schema._NO_RESOLVE_FLAGS`, not a hardcoded
`/api/Users` that happens to fit one target.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import redact

_SPA = "<!doctype html><html><body><app-root></app-root></body></html>"   # no <form>
_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.SECOND-PRINCIPAL-TOKEN-VALUE-do-not-leak"
_FIRST = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.FIRST-PRINCIPAL-TOKEN-VALUE-do-not-leak"


class _FakeLLM:
    reply = "[]"

    def propose(self, system, user, max_tokens=1024):
        return _FakeLLM.reply


class _SpaCage:
    """A form-less SPA with a JSON signup and a JSON login — Juice Shop's shape."""

    def __init__(self, *, signup="/api/Users", with_signup=True, with_form=False):
        self.seen, self.signup, self.with_signup = [], signup, with_signup
        self.with_form = with_form
        self.created: list = []

    def run(self, action):
        from brukal.web import WebResult
        url, method = action.url, (getattr(action, "method", "") or "GET").upper()
        self.seen.append((method, url))
        if method == "POST" and self.with_signup and url.endswith(self.signup):
            body = {}
            try:
                body = json.loads(getattr(action, "body", "") or "{}")
            except Exception:
                return WebResult(status=400, url=url, body="not json")
            if not body.get("email") or not body.get("password"):
                return WebResult(status=400, url=url, body='{"error":"missing"}')
            self.created.append(body)
            return WebResult(status=201, url=url, body=json.dumps(
                {"status": "success",
                 "data": {"id": 25, "email": body["email"], "role": "customer"}}))
        if method == "POST" and url.endswith("/rest/user/login"):
            # Authenticates by EMAIL, as Juice Shop does. The default `username` field
            # 401s — confirmed live on 2026-08-22, where registration returned 201 and
            # the login that followed it was refused for exactly this reason.
            try:
                sent = json.loads(getattr(action, "body", "") or "{}")
            except Exception:
                sent = {}
            # The SPA shape authenticates by email; the form shape by username. Two
            # real app shapes, not one fixture bent to fit both.
            wanted = "email" if self.with_signup else "username"
            if not sent.get(wanted) and not (
                    wanted == "username" and "username=" in (getattr(action, "body", "") or "")):
                return WebResult(status=401, url=url,
                                 body='{"error":"Invalid %s"}' % wanted)
            return WebResult(status=200, url=url, body=json.dumps(
                {"authentication": {"token": _TOKEN, "umail": "x"}}))
        if self.with_form and url.rstrip("/").endswith("/register"):
            if method == "POST":
                # A signup that WORKED stops showing the form — the real
                # `_register_account` treats a re-rendered form as a failed validation,
                # which is the behaviour that check exists for.
                self.created.append({"form": True})
                return WebResult(status=302, url=url, body="")
            return WebResult(status=200, url=url, body=(
                '<html><form action="/register" method="POST">'
                '<input name="username" type="text">'
                '<input name="password" type="password"></form></html>'))
        return WebResult(status=200, url=url, body=_SPA)


def _session(cage, *, routes=("/api/Users", "/rest/user/login")):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.blackboard = Blackboard(root / "vault", scope)
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.surface.api_routes = list(routes)      # what the crawl observed
    sess.allow_intrusive = True
    sess._audit_path = root / "a.jsonl"
    sess._root = root
    return sess


def _audit(sess, kind=None):
    out = []
    for line in Path(sess._audit_path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            if kind is None or rec.get("kind") == kind:
                out.append(rec)
    return out


# -- 1. the capability itself --------------------------------------------------------

def test_a_second_principal_is_established_on_a_form_less_target():
    """The named gap. No `<form>` anywhere, so the existing path cannot work; the JSON
    endpoint the crawl saw is what makes the principal reachable."""
    cage = _SpaCage()
    sess = _session(cage)
    user = sess.establish_second_identity()
    assert user, "no second principal was established on a form-less target"
    assert cage.created, "nothing was ever registered"
    assert sess._second_identity.get("user") == user


def test_the_registration_body_is_what_the_endpoint_actually_requires():
    """Confirmed live: `{email, password}` is the minimum Juice Shop accepts. A body
    missing either is a 400, and the fixture enforces that rather than accepting
    anything posted at it."""
    cage = _SpaCage()
    sess = _session(cage)
    assert sess.establish_second_identity()
    body = cage.created[0]
    assert body.get("email") and body.get("password")


# -- 2. it is a DISTINCT principal, and the ledger says so ----------------------------

def test_the_second_principal_is_distinct_and_the_ledger_records_two_handles():
    """The provenance work of `1f531af` is what makes this checkable: two experiment
    requests issued as different principals must carry two different handles, or the
    cross-account claim is unauditable however real it is."""
    cage = _SpaCage()
    sess = _session(cage)
    sess.browser.auth_header = f"Bearer {_FIRST}"
    assert sess.establish_second_identity()
    assert sess._second_identity.get("auth") != f"Bearer {_FIRST}", (
        "the second principal is holding the first principal's session")
    _FakeLLM.reply = json.dumps([{
        "title": "cross-account", "severity": "high", "comparator": "status_differs",
        "control": {"url": "http://127.0.0.1:5000/api/Users/1", "method": "GET",
                    "as": "self"},
        "variant": {"url": "http://127.0.0.1:5000/api/Users/2", "method": "GET",
                    "as": "second"}}])
    sess.run_hypotheses()
    recs = {r["data"]["role"]: r["data"] for r in _audit(sess, "experiment_principal")}
    assert "control" in recs and "variant" in recs
    assert recs["control"]["session"] != recs["variant"]["session"], (
        f"both sides recorded the same session handle: {recs}")


# -- 3. the credential is registered with redact AT THE MOMENT it is obtained ---------

def test_the_second_principals_credential_is_registered_with_redact():
    """`_session_auth_for` registers the first identity's credential the moment it reads
    it off the browser. The second identity's was never registered at all — not even on
    the existing form path — so it could reach a record surface unmasked."""
    redact.clear()
    try:
        cage = _SpaCage()
        sess = _session(cage)
        assert sess.establish_second_identity()
        assert _TOKEN in redact.known() or any(_TOKEN in k for k in redact.known()), (
            "the second principal's token was never registered for redaction")
    finally:
        redact.clear()


def test_the_second_principals_token_is_not_in_cleartext_on_any_surface():
    """Checked per surface against a target that hands the token back, the same bar the
    body-capture tests hold the first identity to."""
    redact.clear()
    try:
        cage = _SpaCage()
        sess = _session(cage)
        sess.browser.auth_header = f"Bearer {_FIRST}"
        redact.register(_FIRST)
        assert sess.establish_second_identity()
        _FakeLLM.reply = json.dumps([{
            "title": "cross-account", "severity": "high",
            "comparator": "status_differs",
            "control": {"url": "http://127.0.0.1:5000/api/Users/1", "method": "GET",
                        "as": "self"},
            "variant": {"url": "http://127.0.0.1:5000/api/Users/2", "method": "GET",
                        "as": "second"}}])
        sess.run_hypotheses()
        surfaces = {"audit": Path(sess._audit_path).read_text(encoding="utf-8")}
        for p in sorted((sess._root / "vault").rglob("*")):
            if p.is_file():
                surfaces[str(p.relative_to(sess._root))] = p.read_text(
                    encoding="utf-8", errors="replace")
        assert len(surfaces) > 1, "precondition: records were written"
        for name, text in surfaces.items():
            assert _TOKEN not in text, f"second principal's token in cleartext on {name}"
            assert _FIRST not in text, f"first principal's token in cleartext on {name}"
    finally:
        redact.clear()


# -- 4. one execution path: gated and audited ------------------------------------------

def test_registration_goes_through_the_gate_and_is_audited():
    """C1. A raw urllib call would create the account just as well and would be
    invisible to the gate and absent from the ledger — which is the one thing this
    system exists not to allow."""
    cage = _SpaCage()
    sess = _session(cage)
    assert sess.establish_second_identity()
    posts = [r for r in _audit(sess, "web_decision")
             if "/api/Users" in (r["data"].get("action") or "")]
    assert posts, "the registration request never reached the gate"
    assert all(r["data"]["verdict"] == "ALLOW" for r in posts)


# -- 5 & 6. boundaries -------------------------------------------------------------------

def test_a_target_with_a_real_signup_form_still_uses_the_form_path():
    """Unchanged behaviour where the form exists: it is the sounder basis, because the
    account is demonstrably what the app grants a stranger through its own front door."""
    cage = _SpaCage(with_signup=False, with_form=True)
    sess = _session(cage, routes=())
    sess._login_url = "http://127.0.0.1:5000/rest/user/login"
    user = sess.establish_second_identity()
    assert user, "the form path stopped working"
    assert cage.created == [{"form": True}], (
        f"it did not go through the form: {cage.created}")
    assert any(m == "POST" and u.endswith("/register") for m, u in cage.seen)


def test_a_target_with_neither_form_nor_json_endpoint_still_fails_closed():
    """The fail-safe from `c829482` is not touched. No principal, no experiment, and
    cross-account is recorded NOT RUN rather than silently degraded to anonymous."""
    cage = _SpaCage(with_signup=False)
    sess = _session(cage, routes=())
    assert sess.establish_second_identity() == ""
    _FakeLLM.reply = json.dumps([{
        "title": "cross-account", "severity": "high",
        "comparator": "a_denied_b_allowed",
        "control": {"url": "http://127.0.0.1:5000/api/Users/1", "method": "GET",
                    "as": "self"},
        "variant": {"url": "http://127.0.0.1:5000/api/Users/2", "method": "GET",
                    "as": "second"}}])
    assert sess.run_hypotheses() == 0
    assert "SECOND PRINCIPAL UNAVAILABLE" in "\n".join(sess.notes)


# -- C4: an allowlist, not a hardcoded target path ---------------------------------------

def test_the_candidate_paths_are_an_explicit_documented_allowlist():
    """The same discipline as `schema._NO_RESOLVE_FLAGS`: a small, explicit, reviewable
    set rather than a regex that grows by accident, and candidates drawn from what the
    crawl saw rather than from what one target happens to use."""
    from brukal.assist import _JSON_SIGNUP_PATHS
    assert isinstance(_JSON_SIGNUP_PATHS, (tuple, frozenset))
    assert 3 <= len(_JSON_SIGNUP_PATHS) <= 20, "an allowlist, not a catch-all"
    assert any("register" in p for p in _JSON_SIGNUP_PATHS)


def test_an_unrelated_crawled_route_is_never_posted_to():
    """The allowlist is what stops a signup attempt being fired at every route the crawl
    happened to mine — which on a real surface is dozens of endpoints, some destructive."""
    cage = _SpaCage(signup="/api/Users")
    sess = _session(cage, routes=("/api/Orders", "/rest/basket", "/api/Users",
                                  "/rest/user/login"))
    assert sess.establish_second_identity()
    posted = {u for m, u in cage.seen if m == "POST"}
    assert not any("Orders" in u or "basket" in u for u in posted), (
        f"the signup was fired at unrelated crawled routes: {posted}")
