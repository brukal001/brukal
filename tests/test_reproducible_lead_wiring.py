"""
test_reproducible_lead_wiring.py — Idea #3 wired into the discard path (3b).

When a comparator confirms nothing but the controlled input STABLY changes the answer, the
result is kept as an INFO lead instead of discarded. Driven through the real
`_run_one_round`:
  - a stable control + a differing variant -> an INFO lead (confirmed=False), outcome
    `reproducible_lead`, and exactly one EXTRA control read;
  - a drifting control -> no lead (the baseline is not stable), recorded not_confirmed;
  - identical sides -> no re-read at all (nothing to reproduce).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.hypothesis import Hypothesis

X = "http://127.0.0.1:5000/x"     # control
Y = "http://127.0.0.1:5000/y"     # variant


class _Cage:
    def __init__(self, responses):
        self.responses = responses
        self.seen: list = []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        r = self.responses.get(action.url, (404, ""))
        status, body = r() if callable(r) else r
        return WebResult(status=status, url=action.url, body=body)


def _session(cage):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface

    class _LLM:
        def propose(self, system, user, max_tokens=1024):
            return "[]"
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_LLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.blackboard = Blackboard(root / "vault", scope)
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    sess._root, sess._audit_path = root, root / "a.jsonl"
    sess.browser.auth_header = "Bearer self-token"
    return sess, audit


def _h():
    # status_differs will NOT confirm (both sides 200), but the bodies differ.
    return Hypothesis("do the two sides differ in a way nothing names?", "medium",
                      "status_differs",
                      {"url": X, "method": "GET", "as": "self"},
                      {"url": Y, "method": "GET", "as": "self"}, setup=[])


def _outcomes(audit):
    return [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l).get("kind") == "experiment_outcome"]


def test_a_reproducible_effect_is_kept_as_an_info_lead():
    cage = _Cage({X: (200, "AAAA"), Y: (200, "BBBB")})
    sess, audit = _session(cage)
    confirmed = sess._run_one_round([_h()], [], [])
    assert confirmed == 0, "status_differs must not confirm two 200s"
    outs = _outcomes(audit)
    assert outs and outs[0]["outcome"] == "reproducible_lead", outs
    assert outs[0]["attribution"] == "MEASURED"
    leads = [f for f in sess.findings.all()
             if f.severity == "info" and not f.confirmed]
    assert len(leads) == 1
    assert leads[0].evidence_class == ""          # not proved by a comparator
    assert "Reproducible input-dependent" in leads[0].title
    # exactly one EXTRA control read: control dispatched once, re-read once; variant once.
    assert cage.seen.count(X) == 2 and cage.seen.count(Y) == 1, cage.seen


def test_a_drifting_control_yields_no_lead():
    counter = {"n": 0}

    def drifting():
        counter["n"] += 1
        return (200, f"nonce={counter['n']}")     # a different body every read

    cage = _Cage({X: drifting, Y: (200, "BBBB")})
    sess, audit = _session(cage)
    sess._run_one_round([_h()], [], [])
    outs = _outcomes(audit)
    assert outs and outs[0]["outcome"] == "not_confirmed", outs
    assert [f for f in sess.findings.all() if not f.confirmed] == []


def test_identical_sides_are_not_re_read():
    cage = _Cage({X: (200, "SAME"), Y: (200, "SAME")})
    sess, audit = _session(cage)
    sess._run_one_round([_h()], [], [])
    outs = _outcomes(audit)
    assert outs and outs[0]["outcome"] == "not_confirmed", outs
    # no reproduction re-read: the two sides were identical, so control is read just once.
    assert cage.seen.count(X) == 1, cage.seen
