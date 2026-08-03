"""
test_redirect.py — the blind spot the cold head-to-head found.

Brukal scored zero on a target it had never seen, and the reason was not detection: DVNA
answers `/` with a 302 to `/login`, and the crawl stopped there. One page, no links, no
forms, no routes, nothing to probe.

The web layer is right not to auto-follow — the destination has to go back through the
scope gate rather than be trusted because the target's own Location header named it —
and its note says "resubmit as a new gated action to re-check scope". Nothing ever did.
Most login-gated applications present exactly this shape, so the tool was blind to a
large share of real targets while passing every test.
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
ROOT = "http://127.0.0.1:5000/"


class _Redirector:
    """Answers the root with a 302 and serves a real page at the destination."""

    def __init__(self, location="/login", loop=False):
        self.location, self.loop, self.seen = location, loop, []

    def run(self, action):
        self.seen.append(action.url)
        if action.url.endswith("/login") and not self.loop:
            return WebResult(status=200, url=action.url, headers={},
                             body='<form action="/login" method="post">'
                                  '<input name="email"><input name="pass"></form>')
        return WebResult(status=302, url=action.url, body="",
                         headers={"Location": self.location},
                         note="redirect NOT followed -> resubmit as a new gated action")


def _sess(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_a_redirecting_entry_point_no_longer_yields_an_empty_surface():
    cage = _Redirector()
    surface = _sess(cage).crawl(seeds=[ROOT], max_pages=5)
    assert any(u.endswith("/login") for u in cage.seen), cage.seen
    assert surface.forms, "the form behind the redirect was never reached"


def test_the_destination_goes_back_through_the_gate_rather_than_being_trusted():
    """An off-scope Location must not become a request. The whole reason the web layer
    refuses to auto-follow is that a target could otherwise redirect the tool anywhere."""
    cage = _Redirector(location="http://169.254.169.254/latest/meta-data/")
    _sess(cage).crawl(seeds=[ROOT], max_pages=5)
    assert not any("169.254.169.254" in u for u in cage.seen)


def test_a_redirect_loop_terminates():
    """A page redirecting to itself must not be re-queued forever. Counted on the ROOT
    specifically — the crawl also issues soft-404 and API-spec probes, and totalling all
    requests measured those instead of the thing under test."""
    cage = _Redirector(location="/", loop=True)
    _sess(cage).crawl(seeds=[ROOT], max_pages=5)
    assert sum(1 for u in cage.seen if u == ROOT) == 1


def test_a_logout_destination_is_still_refused():
    """Following a redirect must not throw away the existing session."""
    cage = _Redirector(location="/logout")
    _sess(cage).crawl(seeds=[ROOT], max_pages=5)
    assert not any(u.endswith("/logout") for u in cage.seen)
