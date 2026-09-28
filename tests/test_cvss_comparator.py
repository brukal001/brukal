"""
test_cvss_comparator.py — evidence-based CVSS 3.1 scoring, graded on what a confirmed
differential ACTUALLY proved rather than the finding's class/title. Covers the base-
score formula against the CVSS 3.1 canonical vectors, the comparator table, the
load-bearing anti-overclaim ordering (a status-only SQLi must score strictly below a
full-read/RCE/boolean-SQLi/mass-assignment proof), the deterministic `facts`
modifiers, the class-based fallback for an unmapped comparator, and the emission +
backward-compat hooks in `_record_confirmed`.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, FakeKali, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal import cvss

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"

CANONICAL_VECTORS = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


def _session():
    audit_path = Path(tempfile.mkdtemp()) / "a.jsonl"
    audit = AuditLog(audit_path)
    s = AssistSession("127.0.0.1",
                      Executor(Gate(load_scope(SCOPE)), FakeKali(), audit, approver=lambda d: True),
                      StrategistAgent(type("L", (), {"propose": lambda s, *a, **k: ""})()))
    return s, audit_path


def _rows(audit_path):
    if not Path(audit_path).exists():
        return []
    return [json.loads(l) for l in open(audit_path) if l.strip()]


# --- 1. score_from_vector against every CVSS 3.1 canonical vector ----------

def test_canonical_vectors_score_exactly():
    for vector, expected in CANONICAL_VECTORS:
        assert cvss.score_from_vector(vector) == expected, vector


# --- 2. every table comparator is parseable and scores in (0, 10] ----------

def test_every_comparator_has_a_parseable_vector_and_scores_in_range():
    for comparator in cvss.COMPARATOR_CVSS:
        g = cvss.grade(comparator)
        assert 0 < g["cvss"] <= 10, (comparator, g)
        assert g["vector"], comparator


# --- 3. anti-overclaim (load-bearing) ---------------------------------------

def test_status_only_sqli_grades_strictly_below_full_impact_comparators():
    status_only = cvss.grade("sqli_error_status_differential")["cvss"]
    assert status_only < cvss.grade("os_command_injection_differential")["cvss"]
    assert status_only < cvss.grade("sqli_boolean_differential")["cvss"]
    assert status_only < cvss.grade("mass_assignment_differential")["cvss"]


def test_status_only_sqli_basis_says_not_demonstrated():
    # the table text (verbatim from the brief) says "NOT demonstrated" — match
    # case-insensitively rather than dictate the table's capitalisation.
    assert "not demonstrated" in cvss.grade("sqli_error_status_differential")["basis"].lower()


# --- 4. facts modifiers ------------------------------------------------------

def test_auth_required_false_raises_pr_to_none_and_the_score():
    baseline = cvss.grade("bola_cross_account")["cvss"]
    raised = cvss.grade("bola_cross_account", {"auth_required": False})["cvss"]
    assert raised > baseline


def test_credentials_leaked_sets_confidentiality_high():
    g = cvss.grade("bola_cross_account", {"credentials_leaked": True})
    assert "C:H" in g["vector"]


def test_cross_scope_sets_scope_changed():
    g = cvss.grade("ssrf_differential", {"cross_scope": True})  # already S:C — stays S:C
    assert "S:C" in g["vector"]
    g2 = cvss.grade("bola_cross_account", {"cross_scope": True})  # table is S:U — flips
    assert "S:C" in g2["vector"]


# --- 5. fallback to knowledge.enrich for an unmapped comparator -------------

def test_unmapped_comparator_falls_back_to_class_based_knowledge():
    from brukal import knowledge
    kb = knowledge.enrich("SQL injection", "critical")
    g = cvss.grade("some_unknown_comparator", title="SQL injection", severity="critical")
    assert g["cvss"] == kb["cvss"]
    assert g["vector"] == kb["vector"]
    assert "class-based" in g["basis"]


def test_grade_never_crashes_on_garbage_input():
    g = cvss.grade("", title="", severity="")
    assert isinstance(g["cvss"], float)


# --- 6. emission: _record_confirmed(comparator=...) stamps the Finding AND --
#    the emitted experiment_outcome with cvss / cvss_vector / cvss_basis -----

def test_record_confirmed_with_comparator_stamps_cvss_on_finding_and_outcome():
    s, ap = _session()
    s._record_confirmed(
        "http://127.0.0.1/community/api/v2/coupon/validate-coupon",
        "SQL injection (error-based, status differential)", "critical", "coupon_code",
        "evidence", category="api", comparator="sqli_error_status_differential")

    findings = [f for f in s.findings.all()
                if f.title == "SQL injection (error-based, status differential)"]
    assert len(findings) == 1
    f = findings[0]
    assert f.cvss is not None
    assert f.cvss_vector
    assert f.cvss_basis

    expected = cvss.grade("sqli_error_status_differential",
                          title=f.title, severity="critical")
    assert f.cvss == expected["cvss"]
    assert f.cvss_vector == expected["vector"]
    assert f.cvss_basis == expected["basis"]

    rows = _rows(ap)
    outcomes = [r for r in rows if r.get("kind") == "experiment_outcome"]
    assert len(outcomes) == 1
    o = outcomes[0]["data"]
    assert o["cvss"] == expected["cvss"]
    assert o["cvss_vector"] == expected["vector"]
    assert o["cvss_basis"] == expected["basis"]


# --- 7. backward-compat: no comparator -> no CVSS, finding still recorded --

def test_record_confirmed_without_comparator_attaches_no_cvss():
    s, ap = _session()
    s._record_confirmed("http://127.0.0.1/", "Missing security header: x-frame-options",
                        "low", "", "header absent")           # no comparator

    findings = [f for f in s.findings.all()
                if f.title.startswith("Missing security header")]
    assert len(findings) == 1
    f = findings[0]
    assert f.cvss is None
    assert f.cvss_vector == ""
    assert f.cvss_basis == ""

    rows = _rows(ap)
    assert not [r for r in rows if r.get("kind") in ("experiment_result", "experiment_outcome")]
