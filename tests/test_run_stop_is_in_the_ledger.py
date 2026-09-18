"""
test_run_stop_is_in_the_ledger.py — how a run ENDED must be readable from the ledger alone.

THE MEASURED PROBLEM (the CR1 measurement run, 2026-09-18 — GAP #7)
    CR1 stopped at step ~60 of 70 because the Anthropic credit balance ran out. The
    message went to STDOUT. The ledger's last entry is an ordinary `web_decision`, no
    `report.md` was written, and `checkpoint.json` carried 0 findings — the one confirmed
    cross-account result survived only as raw `experiment_outcome` / `ownership_match`
    rows. Nothing anywhere in the artifacts said the run had ended, let alone why.

    Looking for the fix showed the defect is wider than the abort: `_finish` emits `stop`
    to the DISPLAY (`_emit` calls the observer), not to the audit log, so **no run records
    its stop reason in the ledger** — a clean 70-step run no more than a crashed one. The
    report carried it, and on the abort path there is no report.

WHY IT MATTERS MORE THAN IT LOOKS
    CR1's definition of done, committed before any of this, requires that a run "completes,
    or stops for a named reason RECORDED IN THE LEDGER". So this clause was unmeetable by
    construction. And without it, "found nothing" and "died before it could look" are
    indistinguishable in the bundle — which is the exact failure the health monitor exists
    to prevent for targets, one level up.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession, record_engagement_stop
from brukal.kali import ExecResult
from brukal.loop import GroundedLoop

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"


def _session(tmp_path, llm=None):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = llm or type("L", (), {"last_stop_reason": "end_turn",
                                "propose": lambda s, *a, **k: "[]"})()
    return AssistSession(TARGET, ex, StrategistAgent(llm)), audit


def _stops(audit):
    return [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == "engagement_stop"]


def test_a_run_that_FINISHES_records_its_stop_in_the_ledger(tmp_path):
    """Every ordinary end — exhausted, budget, target-unhealthy, solved — is a named
    reason, and the ledger is where a reader looks for it."""
    s, audit = _session(tmp_path)
    loop = GroundedLoop(s, max_steps=1)
    loop.run()
    rows = _stops(audit)
    assert rows, "the run ended and the ledger does not say so"
    assert rows[-1]["reason"], rows[-1]
    assert "steps" in rows[-1]


def test_an_ABORT_records_the_reason_that_killed_it(tmp_path):
    """CR1's case: the model refused mid-run. The cause must be IN the ledger, named, and
    attributed to us rather than to the target."""
    s, audit = _session(tmp_path)
    record_engagement_stop(audit, "aborted", "model/cage error: credit balance is too low",
                           steps=60)
    rows = _stops(audit)
    assert rows and rows[-1]["reason"] == "aborted"
    assert "credit balance" in rows[-1]["detail"]
    assert rows[-1]["attribution"] == "HARNESS-LIMIT", (
        "a run killed by our own model access is not the target's refusal")
    assert rows[-1]["steps"] == 60


def test_the_stop_entry_keeps_the_chain_intact(tmp_path):
    """BOUNDARY: it is an ordinary append, so the hash chain still verifies."""
    s, audit = _session(tmp_path)
    record_engagement_stop(audit, "exhausted", "reached the step budget", steps=70)
    assert audit.verify()


def test_recording_a_stop_can_never_kill_a_run(tmp_path):
    """BOUNDARY, and the rule this file is an instance of: instrumentation must not be
    able to end an engagement. A broken audit sink is swallowed."""
    class _Broken:
        path = "/nonexistent/x.jsonl"
        def append(self, *a, **k):
            raise OSError("disk full")
    record_engagement_stop(_Broken(), "aborted", "whatever", steps=1)   # must not raise


def test_an_abort_is_distinguishable_from_a_clean_end(tmp_path):
    """The point of the record: "found nothing" and "died before it could look" must not
    read the same in a bundle."""
    s, audit = _session(tmp_path)
    record_engagement_stop(audit, "exhausted", "reached the step budget", steps=70)
    record_engagement_stop(audit, "aborted", "model/cage error: boom", steps=12)
    rows = _stops(audit)
    assert [r["reason"] for r in rows] == ["exhausted", "aborted"]
    assert rows[0]["attribution"] == "MEASURED"
    assert rows[1]["attribution"] == "HARNESS-LIMIT"
