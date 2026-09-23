"""
test_lead_mining_report.py — Idea #4b: read a run's reproducible leads, write a drafts sheet.

End-to-end and offline: drive real experiments that produce reproducible leads, then read
the structured facts the run recorded, mine the recurring shape, and format a human-review
report. Plus unit coverage for the audit reader (skips malformed lines) and the formatter.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import lead_mining as lm
from brukal.hypothesis import Hypothesis


class _Cage:
    def __init__(self, responses):
        self.responses = responses
        self.seen: list = []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.responses.get(action.url, (404, ""))
        return WebResult(status=status, url=action.url, body=body)


def _session(cage):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface

    class _LLM:
        def propose(self, system, user, max_tokens=1024):
            return "[]"
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_LLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.blackboard = Blackboard(root / "vault", scope)
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    sess._root = root
    sess.browser.auth_header = "Bearer self-token"
    return sess


def _h(control_url, variant_url):
    # status_differs will not confirm two 200s; the reproducibility gate keeps the lead.
    return Hypothesis("does the input change the answer?", "medium", "status_differs",
                      {"url": control_url, "method": "GET", "as": "self"},
                      {"url": variant_url, "method": "GET", "as": "self"}, setup=[])


def test_two_runs_at_one_family_produce_a_reviewable_draft_report():
    B = "http://127.0.0.1:5000"
    cage = _Cage({
        f"{B}/c1": (200, "s" * 100), f"{B}/api/orders/1": (200, "L" * 500),
        f"{B}/c2": (200, "s" * 100), f"{B}/api/orders/2": (200, "L" * 500)})
    sess = _session(cage)
    sess._run_one_round([_h(f"{B}/c1", f"{B}/api/orders/1"),
                         _h(f"{B}/c2", f"{B}/api/orders/2")], [], [])

    report = sess.mined_lead_report()
    assert "REVIEW REQUIRED" in report
    assert "/api/orders" in report              # the clustered family
    assert "draft_" in report                    # a drafted comparator name
    assert "support: 2" in report                # both leads recurred


def test_leads_from_audit_reads_facts_and_skips_noise(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join([
        json.dumps({"kind": "reproducible_lead_facts", "data": {
            "endpoint": "http://t/api/x/1", "status_baseline": 200, "status_varied": 200,
            "size_baseline": 100, "size_varied": 500, "comparator": "status_differs"}}),
        "this is not json",
        json.dumps({"kind": "something_else", "data": {"endpoint": "ignore"}}),
        json.dumps({"kind": "reproducible_lead_facts", "data": {
            "endpoint": "http://t/api/x/2", "status_baseline": 200, "status_varied": 200,
            "size_baseline": 100, "size_varied": 500}}),
    ]) + "\n")
    leads = lm.leads_from_audit(str(p))
    assert len(leads) == 2
    assert {l.endpoint for l in leads} == {"http://t/api/x/1", "http://t/api/x/2"}


def test_leads_from_a_missing_file_is_empty_not_an_error():
    assert lm.leads_from_audit("/no/such/audit.jsonl") == []


def test_format_report_of_nothing_is_explicit():
    assert "nothing" in lm.format_report([]).lower() or \
        "no recurring" in lm.format_report([]).lower()
