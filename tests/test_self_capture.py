"""
test_self_capture.py — Brukal records its own traffic.

`--capture` was consume-only: the operator ran Burp or mitmproxy, exported a HAR, and
handed it over. Brukal never saw a request it had not itself decided to make, which is
precisely why it is weak on a target it knows nothing about.

Self-capture closes the cheaper half. Every web action already passes through ONE door —
`GovernedBrowser.run` — so recording there needs no new plumbing and inherits the gate:
a request that was denied never happened and must never appear in a capture.

WHAT IT IS FOR. Surface enrichment is redundant (we already fetched those URLs). The value
is the REPLAY consumer: a request Brukal made as `self` becomes an experiment whose control
provably worked, re-issued as `second` or `anonymous`. The replay machinery has existed
since this morning and has never been fed without an operator handing over a file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, load_scope
from brukal.capture import parse_har
from brukal.web import FakeWebCage, GovernedBrowser, WebAction

SCOPE = Path(__file__).resolve().parent.parent / "scope.dvwa.json"
BASE = "http://172.20.0.2"


def _browser(tmp_path):
    scope = load_scope(SCOPE)
    return GovernedBrowser(scope, FakeWebCage(), AuditLog(tmp_path / "a.jsonl"))


def test_a_request_brukal_makes_is_captured(tmp_path):
    b = _browser(tmp_path)
    b.run(WebAction(kind="get", url=f"{BASE}/vulnerabilities/sqli/?id=1"), agent="recon")
    caps = b.captured()
    assert len(caps) == 1
    assert caps[0].path() == "/vulnerabilities/sqli/"
    assert caps[0].param_names() == ["id"]
    assert caps[0].source == "self"


def test_a_DENIED_request_is_never_captured(tmp_path):
    """It never reached the target. A capture of it would be a record of something that
    did not happen, and would put an out-of-scope host into the surface by the back door."""
    b = _browser(tmp_path)
    dec, res = b.run(WebAction(kind="get", url="http://172.20.0.12/identity/api/v2/user/dashboard"),
                     agent="recon")
    assert dec.verdict == "DENY" and res is None
    assert b.captured() == []


def test_our_own_session_does_not_survive_into_the_capture(tmp_path):
    """Our requests carry OUR credential. Stripping is still right: a replay that carries
    it re-issues as the SAME principal and proves nothing."""
    b = _browser(tmp_path)
    b.run(WebAction(kind="request", url=f"{BASE}/login.php", method="POST",
                    headers={"Cookie": "PHPSESSID=deadbeefcafe", "X-Api-Key": "secret123"},
                    body="username=admin&password=password"), agent="exploit")
    blob = json.dumps([{"h": c.headers, "b": c.body} for c in b.captured()])
    assert "deadbeefcafe" not in blob and "secret123" not in blob
    assert b.captured()[0].auth_kind in ("cookie", "apikey")


def test_capture_is_bounded(tmp_path):
    b = _browser(tmp_path)
    for i in range(60):
        b.run(WebAction(kind="get", url=f"{BASE}/p{i}"), agent="recon")
    assert len(b.captured()) <= 25, "an unbounded self-capture grows with the run"


def test_the_written_HAR_round_trips_through_our_own_parser(tmp_path):
    """If the writer and the reader disagree, one of them is wrong — and the reader is the
    one already carrying the scope and credential guarantees."""
    b = _browser(tmp_path)
    b.run(WebAction(kind="get", url=f"{BASE}/setup.php"), agent="recon")
    b.run(WebAction(kind="request", url=f"{BASE}/vulnerabilities/exec/", method="POST",
                    body="ip=127.0.0.1"), agent="exploit")
    out = tmp_path / "capture.har"
    n = b.write_har(out)
    assert n == 2 and out.exists()

    caps, report = parse_har(out.read_text(), load_scope(SCOPE))
    assert report.dropped_malformed == 0, "our own HAR did not parse"
    paths = {c.path() for c in caps}
    assert {"/setup.php", "/vulnerabilities/exec/"} <= paths, paths
    assert any(c.method == "POST" for c in caps)


def test_self_captures_become_replay_experiments(tmp_path):
    """THE POINT: the replay consumer finally gets fed without an operator handing over
    a file."""
    from brukal.capture import hypotheses_from
    b = _browser(tmp_path)
    b.run(WebAction(kind="get", url=f"{BASE}/vulnerabilities/sqli/?id=1"), agent="recon")
    b.run(WebAction(kind="request", url=f"{BASE}/vulnerabilities/exec/", method="POST",
                    body="ip=127.0.0.1"), agent="exploit")
    hyps = hypotheses_from(b.captured())
    assert hyps
    assert any(h.comparator == "state_changed" and h.act for h in hyps), (
        "a POST we made ourselves did not become a state-changing experiment")


def test_the_session_turns_self_captures_into_QUEUED_experiments(tmp_path):
    """Wiring, not just capability. The replay consumer existed all day and nothing ever
    called it in a live run; a capability nothing calls changes nothing, which is the
    exact failure the --capture wiring already made twice today."""
    from brukal import Executor, Gate
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import ExecResult

    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession("172.20.0.2", ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, FakeWebCage(), audit))

    s.browser.run(WebAction(kind="request", url=f"{BASE}/vulnerabilities/exec/",
                            method="POST", body="ip=127.0.0.1"), agent="exploit")
    queued = s.queue_self_capture_experiments()
    assert queued > 0, "a request Brukal made itself produced no experiment"
    assert s.derived_hypotheses(), "the experiments never reached the queue the loop drains"
    assert any(h.comparator == "state_changed" for h in s.derived_hypotheses())


def test_a_404_we_received_is_NOT_captured_as_a_known_good_control(tmp_path):
    """MEASURED on a live cold run: 10 experiments came back `both_sides_absent` because
    self-capture recorded anything with a status — including 404 — and each became an
    experiment whose "control that provably worked" was the target saying NO SUCH THING.

    This is GAP #19's lesson one layer earlier. There the floor stopped a 404/404
    comparison being FILED as evidence; here it stops one being MANUFACTURED."""
    class _Cage:
        def run(self, a):
            from brukal.web import WebResult
            missing = "/nope" in a.url
            return WebResult(status=404 if missing else 200, url=a.url,
                             body="" if missing else "ok")

    scope = load_scope(SCOPE)
    b = GovernedBrowser(scope, _Cage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="get", url=f"{BASE}/setup.php"), agent="recon")
    b.run(WebAction(kind="get", url=f"{BASE}/nope-does-not-exist"), agent="recon")
    paths = {c.path() for c in b.captured()}
    assert "/setup.php" in paths
    assert "/nope-does-not-exist" not in paths, "an absence became a 'known-good control'"


def test_a_403_IS_captured_because_it_is_a_real_answer(tmp_path):
    """BOUNDARY. A refusal is not an absence: the resource EXISTS and we were denied it,
    which is the most interesting control there is — another principal may be allowed."""
    class _Cage:
        def run(self, a):
            from brukal.web import WebResult
            return WebResult(status=403, url=a.url, body="forbidden")

    b = GovernedBrowser(load_scope(SCOPE), _Cage(), AuditLog(tmp_path / "a.jsonl"))
    b.run(WebAction(kind="get", url=f"{BASE}/admin.php"), agent="recon")
    assert [c.path() for c in b.captured()] == ["/admin.php"]
