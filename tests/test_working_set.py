"""
test_working_set.py — the OPT-IN working-set planning aid (§1.3 of the capability
roadmap; GAP #28, runs that stall at ~1/5 of budget).

The safety story is that this is PURE assembly over state Brukal already holds — the
coverage ledger and the findings store — so it can only help the model choose its next
move; it reaches no host, invents nothing, and the gate still rules every command.

The experiment story is that it is DEFAULT OFF: with the flag off, plan_context() is
byte-identical to before, so an existing benchmark baseline is untouched until the
maintainer enables it and measures.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.findings import Finding

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"


class _SeqLLM:
    def __init__(self, replies):
        self._r = list(replies)

    def propose(self, *a, **k):
        return self._r.pop(0) if self._r else ""

    advise = propose


def _session(**kw):
    tmp = tempfile.mkdtemp()
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    sess = AssistSession(TARGET, ex, StrategistAgent(_SeqLLM(["MANUAL: your move"])), **kw)
    return sess, tmp


def test_default_is_off_and_plan_context_is_unchanged():
    sess, tmp = _session()
    try:
        assert sess.context_working_set is False           # opt-in, baseline-safe
        ctx = sess.plan_context()
        assert "NOT YET TESTED" not in ctx and "OPEN LEADS" not in ctx
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_working_set_lists_untested_classes_and_hides_covered_ones():
    sess, tmp = _session()
    try:
        sess._covered("SQL injection", probes=3)            # this one is now exercised
        ws = sess.working_set_text()
        assert "NOT YET TESTED" in ws
        # a class that was never probed is surfaced; the covered one is not
        assert "SSRF" in ws
        untested_block = ws.split("OPEN LEADS")[0]
        # "- SQL injection" as its own row is gone; "- NoSQL injection" (a different,
        # still-untested class) legitimately remains and must not trip this check.
        assert "- SQL injection" not in untested_block
        assert "- NoSQL injection" in untested_block
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_working_set_surfaces_unconfirmed_leads_only():
    sess, tmp = _session()
    try:
        sess.findings.add(Finding(title="IDOR", severity="medium",
                                  target="http://10.10.10.5/api/orders/7",
                                  param="id", category="web", confirmed=False))
        sess.findings.add(Finding(title="SQL injection (sqlmap-confirmed)", severity="high",
                                  target="http://10.10.10.5/s", param="q",
                                  category="web", confirmed=True))
        ws = sess.working_set_text()
        assert "OPEN LEADS" in ws
        leads = ws.split("OPEN LEADS")[1]
        assert "IDOR" in leads                              # the unconfirmed candidate
        assert "sqlmap-confirmed" not in leads              # a confirmed finding is not a lead
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_flag_on_injects_the_working_set_into_plan_context():
    sess, tmp = _session()
    try:
        sess.context_working_set = True
        ctx = sess.plan_context()
        assert "NOT YET TESTED" in ctx                      # opted in -> the model sees it
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
