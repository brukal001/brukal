"""A login that was requested and refused must reach the REPORT.

Regression from a live DVNA run: credentials were rejected, the crawl never left the
login page, and the report listed three low-severity header findings with nothing to
distinguish it from a clean authenticated assessment. The only trace was one line in
the engagement log.
"""
from brukal.findings import FindingStore
from brukal.report import build_report


def _store(tmp_path):
    return FindingStore(tmp_path / "f.jsonl")


def test_failed_login_is_stated_before_the_findings(tmp_path):
    md = build_report(_store(tmp_path), {
        "target": "172.20.0.10",
        "login_status": ["failed", "http://172.20.0.10:9090/login"],
    })
    assert "AUTHENTICATION FAILED" in md
    assert "http://172.20.0.10:9090/login" in md
    # It must land ahead of the finding list, not in a footnote after it.
    assert md.index("AUTHENTICATION FAILED") < md.index("## Methodology")


def test_successful_login_adds_no_warning(tmp_path):
    md = build_report(_store(tmp_path), {
        "target": "172.20.0.10",
        "login_status": ["authenticated", "http://172.20.0.10:9090/login"],
    })
    assert "AUTHENTICATION FAILED" not in md


def test_no_login_requested_adds_no_warning(tmp_path):
    md = build_report(_store(tmp_path), {"target": "172.20.0.10"})
    assert "AUTHENTICATION FAILED" not in md
