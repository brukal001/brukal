"""
test_coverage.py — silence is not a clean result.

Brukal already insists that a rate-limited sweep declare its own incompleteness, then
said nothing at all about the classes it probed and cleared. A reader cannot tell an
absent finding from an absent CHECK, and the competing tool that read as more thorough
was partly earning that by stating "XSS and SSRF were assessed and found to have no
exploitable attack surface". Same duty, other side of it.
"""
from __future__ import annotations

from brukal.report import build_report
from brukal.findings import Finding, FindingStore


class _Sess:
    """Minimal stand-in exercising the ledger's own logic."""

    def __init__(self, findings=()):
        from brukal.assist import AssistSession
        self.coverage = {}
        self.findings = FindingStore()
        for f in findings:
            self.findings.add(f)
        self._covered = AssistSession._covered.__get__(self)
        self.coverage_summary = AssistSession.coverage_summary.__get__(self)


def _f(title):
    return Finding(title=title, severity="high", category="api", target="http://t/",
                   param="", evidence="e", confirmed=True)


def test_probes_are_counted_not_findings():
    """'Asked 14 times and nothing answered' is evidence of absence in a way that
    silence is not."""
    s = _Sess()
    s._covered("Cross-site scripting", probes=9)
    s._covered("Cross-site scripting", probes=5)
    row = dict((k, (p, n, f)) for k, p, n, f in s.coverage_summary())
    assert row["Cross-site scripting"][0] == 14
    assert row["Cross-site scripting"][2] is False        # probed, nothing found


def test_a_class_with_a_finding_is_marked_as_such():
    s = _Sess([_f("SQL injection (error-based)")])
    s._covered("SQL injection", probes=3)
    assert dict((k, f) for k, _p, _n, f in s.coverage_summary())["SQL injection"] is True


def test_report_distinguishes_probed_and_clean_from_never_tested():
    store = FindingStore()
    store.add(_f("SQL injection (error-based)"))
    md = build_report(store, {"target": "t", "coverage": [
        ("SQL injection", 3, "quote-balance differential", True),
        ("Cross-site scripting", 9, "reflection probe", False),
    ]})
    assert "## Coverage — what was assessed" in md
    assert "| Cross-site scripting | 9 | none found |" in md
    assert "silence is not a clean result" in md


def test_no_coverage_table_when_nothing_was_recorded():
    """An empty table would itself be a false statement about what ran."""
    md = build_report(FindingStore(), {"target": "t"})
    assert "## Coverage" not in md
