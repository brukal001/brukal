"""
test_idor_path_ids.py — a concrete numeric path segment IS an object identifier.

PROPERTY UNDER TEST
    Given an id-addressed endpoint whose non-owned record sits at a BOUNDARY id rather
    than at observed+1, the access-control differential reaches that record and flags the
    shape difference — independent of which direction the id moves.

Cap (HTB, 2026-08-09) is one instance of the property, not the property itself. Its
`/data/<id>` endpoint returns the caller's own capture at id 1, a redirect at id 2, and
ANOTHER USER'S capture at id 0. The live run reached the endpoint and reported nothing.

The cause was NOT enumeration direction — `confirm_idor` already probes `n-1`. The cause
is that a concrete crawled URL like `/data/1` was never recognised as id-addressed at
all: the queue only enqueues query parameters, form fields, and TEMPLATED `{id}` routes
mined from a spec (`_PATH_PARAM_RE` matches `{...}`, not `1`). With no spec and no query
string, nothing ever handed the endpoint to the differential, so the class was silent
while the coverage table counted the endpoint as seen.

These tests are written against the property. `test_the_neighbourhood_is_bounded` exists
so the fix cannot become an unbounded id sweep on a crafted endpoint.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
BASE = "http://127.0.0.1:5000"

# Distinct, same-shaped records. Same template, different content — what a real
# id-addressed store returns for two different owners.
_TEMPLATE = ("<html><body><h1>Capture report</h1>"
             "<table><tr><th>src</th><th>dst</th><th>proto</th></tr>"
             + ("<tr><td>10.0.0.4</td><td>10.0.0.9</td><td>tcp</td></tr>" * 12)
             + "</table><p>owner={owner}</p><p>note={note}</p></body></html>")
_MINE = _TEMPLATE.format(owner="me", note="my own capture session")
_THEIRS = _TEMPLATE.format(owner="someone-else", note="a different user's capture")


class _BoundaryIdApp:
    """`/data/<id>`: our record at 1, NOTHING at 2, another user's record at 0.

    The record that proves the flaw sits at the BOUNDARY, below the observed id — so a
    differential that only walks upward sees a redirect and concludes 'no finding'.
    """

    def __init__(self):
        self.seen: list[str] = []

    def run(self, action):
        url = getattr(action, "url", "") or ""
        self.seen.append(url)
        m = re.search(r"/data/(\d+)", url)
        if not m:
            return WebResult(status=200, url=url,
                             body='<html><a href="/data/1">my capture</a></html>')
        n = int(m.group(1))
        if n == 1:
            return WebResult(status=200, url=url, body=_MINE)
        if n == 0:
            return WebResult(status=200, url=url, body=_THEIRS)
        return WebResult(status=302, url=url, body="",
                         headers={"Location": "/"})


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession("127.0.0.1", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))


def _ids_probed(app) -> set[int]:
    out = set()
    for u in app.seen:
        m = re.search(r"/data/(\d+)", u)
        if m:
            out.add(int(m.group(1)))
    return out


# --------------------------------------------------------------------------- #
# The property
# --------------------------------------------------------------------------- #

def test_a_concrete_numeric_path_segment_is_treated_as_an_object_id():
    """The recognition step. Without this the differential is never handed the
    endpoint, and the class stays silent while the endpoint counts as 'seen'."""
    from brukal.assist import AssistSession as A
    assert hasattr(A, "id_addressed_endpoints"), \
        "no way to recognise a concrete /path/<n> endpoint as id-addressed"
    found = A.id_addressed_endpoints([f"{BASE}/data/1", f"{BASE}/about",
                                      f"{BASE}/static/app.js"])
    assert found, "a concrete /data/1 URL was not recognised as id-addressed"
    template, param, observed = found[0]
    assert "/data/" in template and param in template
    assert observed == 1


def test_the_differential_reaches_a_boundary_record_below_the_observed_id():
    """THE PROPERTY. The non-owned record is at id 0; observed is 1; id 2 is a dead
    redirect. A differential that only walks upward finds nothing."""
    app = _BoundaryIdApp()
    sess = _session(app)
    hit = sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH")
    assert 0 in _ids_probed(app), f"id 0 was never requested; probed {_ids_probed(app)}"
    assert hit is True, "the boundary record was reached but no finding was flagged"
    assert any("IDOR" in f.title for f in sess.findings.all())


def test_the_dead_upward_neighbour_alone_does_not_produce_a_finding():
    """Guards against the opposite error — flagging a redirect as an object."""
    class _OnlyUpwardDead(_BoundaryIdApp):
        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            m = re.search(r"/data/(\d+)", url)
            if m and int(m.group(1)) == 1:
                return WebResult(status=200, url=url, body=_MINE)
            return WebResult(status=302, url=url, body="", headers={"Location": "/"})

    app = _OnlyUpwardDead()
    sess = _session(app)
    assert sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH") is False


def test_the_neighbourhood_is_bounded():
    """ADVERSARIAL: a crafted endpoint that answers 200 with fresh content for EVERY id
    must not turn the differential into an unbounded enumeration."""
    class _AlwaysDistinct:
        def __init__(self):
            self.seen: list[str] = []

        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            m = re.search(r"/data/(\d+)", url)
            n = int(m.group(1)) if m else 0
            return WebResult(status=200, url=url,
                             body=f"<html><h1>Capture report</h1><p>id={n}</p>"
                                  + ("z" * 400) + "</html>")

    app = _AlwaysDistinct()
    sess = _session(app)
    sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH")
    assert len(app.seen) <= 8, f"unbounded id sweep: {len(app.seen)} requests"


def test_the_observed_id_is_read_from_the_path_not_assumed():
    """A high observed id must still probe its own neighbourhood AND the boundary."""
    class _HighId(_BoundaryIdApp):
        def run(self, action):
            url = getattr(action, "url", "") or ""
            self.seen.append(url)
            m = re.search(r"/data/(\d+)", url)
            n = int(m.group(1)) if m else -1
            if n == 57:
                return WebResult(status=200, url=url, body=_MINE)
            if n == 0:
                return WebResult(status=200, url=url, body=_THEIRS)
            return WebResult(status=404, url=url, body="not found")

    app = _HighId()
    sess = _session(app)
    sess.confirm_idor(f"{BASE}/data/{{id}}", "{id}", method="PATH", observed=57)
    ids = _ids_probed(app)
    assert 57 in ids, f"the observed id was not used as the baseline; probed {ids}"
    assert 0 in ids, f"the boundary id was not probed; probed {ids}"
