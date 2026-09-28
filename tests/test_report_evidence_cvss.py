"""
test_report_evidence_cvss.py — report.py renders the evidence CVSS, not just the class one.

`_finding_md` prefers a finding's OWN evidence CVSS (score/vector graded by the confirming
comparator in cvss.py) over the title-keyed class number from knowledge.enrich, and prints a
"Demonstrated impact:" line describing what the differential actually proved. A finding with no
comparator (cvss is None) must fall back to the class CVSS exactly as before, with no
"Demonstrated impact:" line. This guards that coverage gap (noted in the CVSS review): the
evidence-CVSS wiring exists in the Finding model and in _finding_md, but nothing pinned the
rendering, so a regression to "always class CVSS" would have passed silently.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.findings import Finding
from brukal.knowledge import enrich
from brukal.report import _finding_md

# A distinctive evidence CVSS that differs from the class number for this title, so a test
# that sees the evidence value cannot be passing on the fallback by accident.
_EVIDENCE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
_EVIDENCE_BASIS = "cross-account order read confirmed via IDOR comparator"


def test_evidence_cvss_and_basis_render_and_override_the_class_number():
    kb = enrich("SQL injection", "critical")
    assert kb["cvss"] == 9.8, "test fixture assumes the known class number for this title"

    f = Finding(title="SQL injection", severity="critical",
                target="http://10.10.10.5/s", confirmed=True,
                cvss=9.9, cvss_vector=_EVIDENCE_VECTOR, cvss_basis=_EVIDENCE_BASIS)
    md = _finding_md(f)

    # The evidence score + vector are what render...
    assert "CVSS 9.9" in md
    assert _EVIDENCE_VECTOR in md
    # ...NOT the title-keyed class number.
    assert "CVSS 9.8" not in md
    # And the differential's basis is spelled out.
    assert f"**Demonstrated impact:** {_EVIDENCE_BASIS}" in md


def test_no_evidence_cvss_falls_back_to_class_cvss_and_omits_demonstrated_impact():
    kb = enrich("SQL injection", "critical")
    f = Finding(title="SQL injection", severity="critical",
                target="http://10.10.10.5/s", confirmed=True)  # cvss defaults to None
    md = _finding_md(f)

    assert f"CVSS {kb['cvss']:.1f}" in md          # the class number
    assert f"({kb['vector']})" in md               # the class vector
    assert "Demonstrated impact:" not in md         # no evidence -> no such line


def test_demonstrated_impact_line_requires_a_basis_even_with_an_evidence_score():
    # Evidence CVSS present but no basis string: the score still renders, but there is
    # nothing to demonstrate, so the line is suppressed (both conditions are required).
    f = Finding(title="SQL injection", severity="critical",
                target="http://10.10.10.5/s", confirmed=True,
                cvss=8.1, cvss_vector=_EVIDENCE_VECTOR, cvss_basis="")
    md = _finding_md(f)

    assert "CVSS 8.1" in md
    assert "Demonstrated impact:" not in md
