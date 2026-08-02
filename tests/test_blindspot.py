"""
test_blindspot.py — the coverage a safety guard was costing, recovered safely.

Brukal once wiped its own test target by fetching /createdb as an ordinary listing, and
the fix made `confirm_unauth_access` refuse every destructive-looking path. Correct, and
it created a blind spot: a competing tool reported "unauthenticated database reset" on
the same host while Brukal — which had the route in its map throughout — said nothing.

The recovery must never invoke the endpoint. OPTIONS is dispatched by the routing layer
before the handler runs; HEAD is NOT usable, because Flask satisfies it by running the
view and discarding the body. A bare 200 on OPTIONS proves nothing either, since most
apps never authenticate preflight — so the finding is a DIFFERENTIAL against a route the
app itself declares protected.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
B = "http://127.0.0.1:5000"
DESTRUCTIVE = B + "/createdb"
PROTECTED = B + "/me"


class _Api:
    """`guards_options` decides whether the protected route refuses anonymous OPTIONS.
    Records every method seen so the test can prove the endpoint was never invoked."""

    def __init__(self, guards_options: bool = True, destructive_status: int = 200):
        self.guards_options = guards_options
        self.destructive_status = destructive_status
        self.seen: list[tuple[str, str]] = []

    def run(self, action):
        method = (action.method or "GET").upper()
        self.seen.append((method, action.url))
        if action.url == PROTECTED:
            if method == "OPTIONS" and self.guards_options:
                return WebResult(status=401, url=action.url, body="")
            return WebResult(status=200, url=action.url, body="{}")
        if action.url == DESTRUCTIVE:
            return WebResult(status=self.destructive_status, url=action.url, body="")
        return WebResult(status=404, url=action.url, body="{}")


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession("127.0.0.1", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))


def test_exposed_destructive_endpoint_is_confirmed():
    api = _Api(guards_options=True)
    sess = _session(api)
    assert sess.confirm_destructive_endpoint_exposed(DESTRUCTIVE, PROTECTED) is True
    f = sess.findings.all()[0]
    assert f.severity == "high" and f.confirmed
    assert "NOT invoked" in f.evidence


def test_the_endpoint_is_never_invoked():
    """The whole point. Only OPTIONS may ever reach a destructive path — a GET, POST or
    even HEAD would run the handler and reinitialise the database."""
    api = _Api(guards_options=True)
    sess = _session(api)
    sess.confirm_destructive_endpoint_exposed(DESTRUCTIVE, PROTECTED)
    methods = {m for m, u in api.seen if u == DESTRUCTIVE}
    assert methods == {"OPTIONS"}, f"destructive path touched with {methods}"


def test_no_finding_when_the_app_never_guards_options():
    """Without a refused baseline the comparison says nothing about authorization, so
    the correct answer is silence rather than a guess."""
    api = _Api(guards_options=False)
    sess = _session(api)
    assert sess.confirm_destructive_endpoint_exposed(DESTRUCTIVE, PROTECTED) is False
    assert not sess.findings.all()


def test_no_finding_when_the_destructive_route_is_also_refused():
    api = _Api(guards_options=True, destructive_status=403)
    sess = _session(api)
    assert sess.confirm_destructive_endpoint_exposed(DESTRUCTIVE, PROTECTED) is False


def test_ordinary_routes_are_left_to_the_normal_unauth_check():
    """This path exists only for endpoints the destructive guard blocks; anything else
    must go through confirm_unauth_access, which proves far more."""
    sess = _session(_Api())
    assert sess.confirm_destructive_endpoint_exposed(B + "/users/v1", PROTECTED) is False
