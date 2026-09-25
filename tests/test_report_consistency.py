"""
test_report_consistency.py — the runtime self-contradiction guard (roadmap §2.3).

A finding whose title maps to no coverage class makes the report contradict itself: it is
listed while the coverage table shows every class 'none found'. That shipped three times.
test_coverage_consistency guards SOURCE-literal titles; this guards the ones built at run
time, and makes build_report FLAG the contradiction instead of silently emitting it.
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
from brukal.findings import Finding, FindingStore
from brukal.report import build_report

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"


def _session():
    tmp = tempfile.mkdtemp()
    ex = Executor(Gate(load_scope(SCOPE)), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
    return AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})())), tmp


def test_coverage_contradictions_finds_orphans_only():
    sess, tmp = _session()
    try:
        sess.findings.add(Finding(title="Undocumented widget bypass", severity="high",
                                  target="http://10.10.10.5/x", category="web"))
        sess.findings.add(Finding(title="SQL injection (boolean-based)", severity="critical",
                                  target="http://10.10.10.5/s", category="web"))
        sess.findings.add(Finding(title="A model-named experiment result", severity="high",
                                  target="http://10.10.10.5/e", category="logic"))
        contra = sess.coverage_contradictions()
        titles = {t[0] for t in contra}
        assert "Undocumented widget bypass" in titles     # maps to no class -> orphan
        assert "SQL injection (boolean-based)" not in titles   # maps to SQL injection
        assert "A model-named experiment result" not in titles  # logic -> represented
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _meta(contradictions):
    return {"target": TARGET, "engagement": "t", "cage": "fake", "stop_reason": "manual",
            "audit_intact": True, "steps": 1, "executed": 1, "contradictions": contradictions}


def test_build_report_flags_a_contradiction():
    store = FindingStore()
    store.add(Finding("Undocumented widget bypass", "high", "http://10.10.10.5/x",
                      confirmed=True))
    md = build_report(store, _meta([("Undocumented widget bypass", "high",
                                     "http://10.10.10.5/x")]))
    assert "Consistency warning" in md and "Undocumented widget bypass" in md


def test_build_report_is_clean_when_consistent():
    store = FindingStore()
    store.add(Finding("SQL injection", "high", "http://10.10.10.5/s", confirmed=True))
    md = build_report(store, _meta([]))
    assert "Consistency warning" not in md
