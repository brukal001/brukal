"""A crawl must be read-only in EFFECT, not merely in method.

On a live cold run against DVGA, Brukal followed `GET /difficulty/hard` — an ordinary
link with no destructive word in it — and switched the application from easy mode to
hard mode, disabling GraphQL introspection PARTWAY THROUGH its own assessment. The
finding made before that request was true; the verification afterwards failed. They were
made against two different applications.

Three things are wrong with that, in rising order of seriousness: the run is not
reproducible, it is not internally consistent, and on a real engagement Brukal would
have altered a client's security posture without being asked.

The doctrine — "read-only is a property of the METHOD, not the endpoint" — was already
written in this codebase, after Brukal wiped its own test target through a GET. The
crawl simply never applied it.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession, _changes_target_state
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000/"


def test_a_link_that_sets_a_configuration_value_is_refused():
    for url in ("/difficulty/hard", "/difficulty/easy", "/settings/theme/dark",
                "/mode/debug", "/config/level/verbose", "/feature-flags/beta"):
        assert _changes_target_state(url), url


def test_ordinary_pages_are_still_followed():
    """Refusing the configuration NOUN alone would skip `/settings`, an ordinary page
    worth reading, and `/products/new`, which is a form and the main attack surface."""
    for url in ("/settings", "/config", "/products/new", "/app/useredit",
                "/learn/vulnerability/a1_injection", "/api/Users"):
        assert not _changes_target_state(url), url


class _Cage:
    """A landing page linking the application AND two state-changing links."""

    def __init__(self):
        self.seen = []

    def run(self, action):
        self.seen.append(action.url)
        if action.url.rstrip("/").endswith("5000"):
            body = ('<a href="/app/products">p</a><a href="/app/useredit">e</a>'
                    '<a href="/difficulty/hard">harden me</a>'
                    '<a href="/admin/reset">reset</a>'
                    '<a href="/logout">out</a>')
            return WebResult(status=200, url=action.url,
                             headers={"content-type": "text/html"}, body=f"<html>{body}</html>")
        return WebResult(status=200, url=action.url,
                         headers={"content-type": "text/html"}, body="<html>ok</html>")


def _sess(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_the_crawl_never_requests_a_state_changing_link():
    cage = _Cage()
    s = _sess(cage)
    s.crawl(seeds=[ROOT], max_pages=10)
    assert not [u for u in cage.seen if "difficulty" in u], \
        f"the crawl reconfigured the target: {cage.seen}"
    assert not [u for u in cage.seen if "/admin/reset" in u], \
        f"the crawl requested an irreversible path: {cage.seen}"
    assert not [u for u in cage.seen if "/logout" in u]


def test_the_application_is_still_crawled():
    """The guard must not cost coverage: refusing too much is its own failure."""
    cage = _Cage()
    s = _sess(cage)
    s.crawl(seeds=[ROOT], max_pages=10)
    assert any("/app/products" in u for u in cage.seen)
    assert any("/app/useredit" in u for u in cage.seen)


def test_the_operator_is_told_what_was_refused():
    """"Brukal declined to touch this" is information a human needs — silently dropping
    a link looks identical to never having found it."""
    cage = _Cage()
    s = _sess(cage)
    s.crawl(seeds=[ROOT], max_pages=10)
    assert any("did NOT follow" in n and "difficulty" in n for n in s.notes), s.notes
