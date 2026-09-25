"""
test_impact_gate.py — impact vs mechanism (roadmap §2.2).

40% of the project's filed reports were closed RTFS for proving a mechanism and not the
impact. impact_verdict() labels each confirmed finding, the report splits and reminds, and
the machine format carries it. Conservative by construction: a candidate is never 'impact',
and anything not clearly a completed outcome stays 'mechanism' (under-claiming is safe).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.findings import Finding, FindingStore
from brukal.report import build_report, impact_verdict, report_json


def _f(title, confirmed=True, evidence_class="", category="web", severity="high"):
    return Finding(title=title, severity=severity, target="http://10.10.10.5/x",
                   category=category, confirmed=confirmed, evidence_class=evidence_class)


def test_completed_outcomes_are_impact():
    assert impact_verdict(_f("OS command injection")) == "impact"
    assert impact_verdict(_f("Unauthenticated exposure of credentials")) == "impact"
    assert impact_verdict(_f("Default credentials accepted")) == "impact"
    assert impact_verdict(_f("Insecure deserialization (remote code execution)")) == "impact"


def test_boundary_crossing_comparators_are_impact():
    assert impact_verdict(_f("Cross-account read", evidence_class="cross_account_resource")) == "impact"
    assert impact_verdict(_f("Anon refused, user allowed", evidence_class="a_denied_b_allowed")) == "impact"
    assert impact_verdict(_f("SSRF", evidence_class="oob_callback")) == "impact"


def test_mechanisms_stay_mechanism():
    assert impact_verdict(_f("SQL injection (boolean-based)")) == "mechanism"
    assert impact_verdict(_f("Reflected XSS")) == "mechanism"
    assert impact_verdict(_f("Server-side template injection")) == "mechanism"
    assert impact_verdict(_f("bodies differ", evidence_class="bodies_differ")) == "mechanism"


def test_a_candidate_is_never_impact():
    # even a title that would be impact if confirmed is 'mechanism' while unconfirmed
    assert impact_verdict(_f("OS command injection", confirmed=False)) == "mechanism"


def _meta():
    return {"target": "10.10.10.5", "engagement": "t", "cage": "fake",
            "stop_reason": "manual", "audit_intact": True, "steps": 1, "executed": 1}


def test_report_splits_impact_from_mechanism_and_reminds():
    store = FindingStore()
    store.add(_f("OS command injection"))                 # impact
    store.add(_f("SQL injection (boolean-based)"))         # mechanism
    md = build_report(store, _meta())
    assert "impact demonstrated" in md.lower()
    assert "mechanism proven" in md.lower()
    assert "attacker's start position" in md              # the RTFS reminder
    js = report_json(store, _meta())
    verdicts = {f["title"]: f["impact"] for f in js["findings"]}
    assert verdicts["OS command injection"] == "impact"
    assert verdicts["SQL injection (boolean-based)"] == "mechanism"
