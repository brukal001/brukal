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


def test_every_class_that_produced_a_finding_appears_in_the_table():
    """The report's own footnote says a class absent from the table was not reached.
    The first live run broke that promise: it listed JWT forgery, BOLA and
    unauthenticated-exposure findings while none of those classes appeared, because only
    some probe sites were instrumented. A report that contradicts itself is worse than
    one that says less."""
    import json as _json
    from pathlib import Path
    from brukal.assist import _COVERAGE_WORDS
    doc = _json.loads(Path("runs/vault-wb/172.20.0.5/findings.json").read_text())
    classes_with_findings = set()
    for f in doc["findings"]:
        title = f["title"].lower()
        for klass, words in _COVERAGE_WORDS.items():
            if any(w in title for w in words):
                classes_with_findings.add(klass)
    # every class Brukal can produce a finding for must have an instrumented probe site
    import brukal.assist as _a
    src = Path(_a.__file__).read_text()
    for klass in classes_with_findings:
        assert f'self._covered("{klass}"' in src, \
            f"{klass} produces findings but no probe site records coverage for it"


# -- route parameter discovery: the SPA gap ------------------------------------

class _Spa:
    """An API route that honours `q` and ignores everything else — the shape a
    single-page app presents, where the crawl finds no forms and no query params."""

    def __init__(self):
        self.seen = []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        if "q=" in action.url:
            return WebResult(status=200, url=action.url, body='{"results":["match"]}')
        return WebResult(status=200, url=action.url, body='{"results":[]}')


def _sess(cage):
    import tempfile
    from pathlib import Path
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.assist import AssistSession
    from brukal.agents.strategist import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_a_parameter_the_route_honours_is_discovered():
    """Guessing a name is cheap and usually wrong, so a guess only counts when it
    measurably CHANGES the response against a control."""
    sess = _sess(_Spa())
    assert "q" in sess.discover_params("http://127.0.0.1:5000/rest/products/search")


def test_parameters_the_route_ignores_are_not_reported():
    sess = _sess(_Spa())
    found = sess.discover_params("http://127.0.0.1:5000/rest/products/search")
    assert found == ["q"]          # every other candidate left the body unchanged


def test_discovery_is_skipped_for_urls_that_already_carry_parameters():
    sess = _sess(_Spa())
    assert sess.discover_params("http://127.0.0.1:5000/x?already=1") == []
