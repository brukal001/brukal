"""
test_two_404s_are_not_a_measurement.py — a comparison of two absent paths proves nothing.

THE MEASURED PROBLEM (CR1 run 19, 2026-09-19)
    Run 19 produced the thing four sessions had been trying to get: the model built a
    correctly-shaped `state_changed` experiment -- control and variant the SAME read, as
    the second principal, change carried in setup.

    It was aimed at `http://172.20.0.12/orders/40`. crAPI mounts orders at
    `/workshop/api/shop/orders/40`, and that mount had never been proven when the
    proposal was made, so repair had no prefix to apply. Both sides returned 404:

        result: .../orders/40  status 404  role control
        result: .../orders/40  status 404  role variant
        OUTCOME: not_confirmed, stage judged, attribution MEASURED

    **`MEASURED` means "the comparator read both answers and the claim did not hold" --
    evidence about the TARGET.** Two 404s from a path that does not exist are evidence
    about our aim. The series' best experiment was filed as a fact about crAPI.

    This is the same floor the 5xx rule already establishes ("a difference between two
    server errors is not evidence about the application"), one status class over: a
    difference between two absences is not evidence either.

THE PROPERTY
    Both sides absent => NOT judged, and attributed to us, never to the target.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import Hypothesis, attribution
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
ABSENT = f"http://{TARGET}/orders/40"          # run 19's URL: the mount was never proven
REAL = f"http://{TARGET}/workshop/api/shop/orders/40"


def _session(tmp_path, statuses):
    """`statuses` maps a url substring -> status, so a test can make a path ABSENT on both
    sides or present on one."""
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)

    class _Cage:
        def run(self, a):
            for frag, st in statuses.items():
                if frag in a.url:
                    return WebResult(status=st, url=a.url,
                                     body=("" if st == 404 else '{"order":{"id":40}}'))
            return WebResult(status=404, url=a.url, body="")

    s = AssistSession(TARGET, ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, _Cage(), audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    from brukal.webmap import AttackSurface
    s.surface = AttackSurface(seed=f"http://{TARGET}/")
    return s, audit


def _outcomes(audit):
    return [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l).get("kind") == "experiment_outcome"]


def _hyp(url_a, url_b, comparator="state_changed"):
    return Hypothesis("Return-order abuse on another account's order", "high", comparator,
                      {"url": url_a, "method": "GET", "as": "self"},
                      {"url": url_b, "method": "GET", "as": "self"},
                      "r", [], {"url": url_a, "method": "POST", "as": "self"})


def test_two_404s_are_NOT_judged_and_NOT_attributed_to_the_target(tmp_path):
    """RUN 19's EXACT SHAPE. Both sides absent -> the comparator must not read them."""
    s, audit = _session(tmp_path, {"/orders/40": 404})
    s._run_one_round([_hyp(ABSENT, ABSENT)], [], [])
    outs = _outcomes(audit)
    assert outs, "no outcome recorded at all"
    assert outs[0]["outcome"] == "both_sides_absent", outs[0]
    assert outs[0]["attribution"] != "MEASURED", (
        "two 404s from a path that does not exist were filed as evidence about the target")
    assert attribution(outs[0]["outcome"]) == "HARNESS-LIMIT"


def test_a_REAL_experiment_on_an_existing_path_is_still_judged(tmp_path):
    """POSITIVE CONTROL. Without it, 'never filed as MEASURED' is also satisfied by a
    floor that eats every experiment — which would silently end the whole measurement."""
    s, audit = _session(tmp_path, {"/workshop/api/shop/orders/40": 200})
    s._run_one_round([_hyp(REAL, REAL)], [], [])
    outs = _outcomes(audit)
    assert outs and outs[0]["outcome"] in ("confirmed", "not_confirmed"), outs
    assert outs[0]["attribution"] == "MEASURED"


def test_a_ONE_sided_404_is_still_a_real_result(tmp_path):
    """BOUNDARY, and the one that matters most: 404 on one side only is often the whole
    finding — a stranger refused where we are served. The floor must not eat it."""
    s, audit = _session(tmp_path, {"/workshop/api/shop/orders/40": 200,
                                   "/orders/40": 404})
    s._run_one_round([_hyp(REAL, ABSENT, comparator="status_differs")], [], [])
    outs = _outcomes(audit)
    assert outs and outs[0]["outcome"] in ("confirmed", "not_confirmed"), outs
    assert outs[0]["attribution"] == "MEASURED"
