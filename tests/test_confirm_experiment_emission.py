"""
test_confirm_experiment_emission.py — a confirm_* prover files a confirmed FINDING, but the
crAPI recall scorer only reads confirmed EXPERIMENTS (`experiment_outcome`). A/B run CR3
proved crAPI #11 (SSRF) and #12 (NoSQL) live yet scored MEASURED-NOT-CONFIRMED, because the
proof was written in the wrong ledger channel. `_record_confirmed(..., comparator=...)` now
emits the same experiment pair the model's own experiments leave, so the differential is
counted as what it already is — opt-in, so config-shaped confirmations (a missing header)
emit nothing and cannot forge a credit.
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

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"


def _session():
    audit_path = Path(tempfile.mkdtemp()) / "a.jsonl"
    audit = AuditLog(audit_path)
    s = AssistSession("127.0.0.1",
                      Executor(Gate(load_scope(SCOPE)), FakeKali(), audit, approver=lambda d: True),
                      StrategistAgent(type("L", (), {"propose": lambda s, *a, **k: ""})()))
    return s, audit_path


def _rows(audit_path):
    # A no-comparator confirm writes NOTHING to the audit, so the log may not exist yet —
    # that absence is itself the evidence the "emits nothing experimental" test wants.
    if not Path(audit_path).exists():
        return []
    return [json.loads(l) for l in open(audit_path) if l.strip()]


def test_comparator_emits_a_confirmed_experiment_pair():
    s, ap = _session()
    s._record_confirmed("http://127.0.0.1/community/api/v2/coupon/validate-coupon",
                        "NoSQL injection (operator)", "critical", "coupon_code",
                        "benign refused, operator accepted", category="api",
                        comparator="nosql_operator_differential")
    rows = _rows(ap)
    results = [r for r in rows if r.get("kind") == "experiment_result"]
    outcomes = [r for r in rows if r.get("kind") == "experiment_outcome"]
    assert any("validate-coupon" in (r["data"].get("url") or "") for r in results)
    assert len(outcomes) == 1
    o = outcomes[0]["data"]
    assert o["outcome"] == "confirmed" and o["comparator"] == "nosql_operator_differential"
    assert o["stage"] == "judged"


def test_no_comparator_emits_nothing_experimental():
    """A config-shaped confirmation (missing header, CORS) passes no comparator, so it must
    leave no experiment record — otherwise it could forge a challenge credit."""
    s, ap = _session()
    s._record_confirmed("http://127.0.0.1/", "Missing security header: x-frame-options",
                        "low", "", "header absent")           # no comparator
    rows = _rows(ap)
    assert not [r for r in rows if r.get("kind") in ("experiment_result", "experiment_outcome")]
    # the finding is still filed — only the experiment channel is silent
    assert any(f.title.startswith("Missing security header") for f in s.findings.all())


def test_recall_credits_12_from_the_emitted_experiment_and_not_13():
    """The whole point: the emitted pair makes the recall scorer see #12, and the gate fix
    keeps a NoSQL finding from also crediting #13 (a SQL-injection challenge)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "crapi_recall", Path(__file__).resolve().parents[1] / "benchmarks" / "crapi_recall.py")
    cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)

    s, ap = _session()
    s._record_confirmed("http://127.0.0.1/community/api/v2/coupon/validate-coupon",
                        "NoSQL injection (operator)", "critical", "coupon_code",
                        "benign refused ({}), operator {'$ne': None} accepted", category="api",
                        comparator="nosql_operator_differential")
    res = {r["id"]: r for r in cr.measure(ap)["results"]}
    assert res[12]["state"] == "FOUND", res[12]
    assert res[13]["state"] != "FOUND", res[13]          # NoSQL must not credit the SQL challenge


def _cr():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "crapi_recall", Path(__file__).resolve().parents[1] / "benchmarks" / "crapi_recall.py")
    cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)
    return cr


def test_an_ssrf_on_contact_mechanic_does_not_credit_ch2():
    """An SSRF confirmation on /merchant/contact_mechanic is challenge 11, not 'access
    mechanic reports of other users' (ch2, a BOLA) — even though ch2's signature contains
    that path. This is the false credit the emission fix would otherwise introduce."""
    cr = _cr()
    ssrf = {"title": "Blind SSRF (out-of-band)", "comparator": "ssrf_out_of_band",
            "urls": ["http://127.0.0.1/workshop/api/merchant/contact_mechanic"]}
    assert cr._gate_mechanic_reports(ssrf) is False


def test_a_real_mechanic_report_bola_still_credits_ch2():
    cr = _cr()
    bola = {"title": "Broken object-level authorization (BOLA/IDOR)",
            "comparator": "bola_cross_account",
            "urls": ["http://127.0.0.1/workshop/api/mechanic/mechanic_report?report_id=2"]}
    assert cr._gate_mechanic_reports(bola) is True


def test_gate_coupon_sqli_still_credits_a_real_sql_finding():
    """The gate fix must not throw out an actual SQL injection on the coupon (that IS #13)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "crapi_recall", Path(__file__).resolve().parents[1] / "benchmarks" / "crapi_recall.py")
    cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)
    e = {"title": "SQL injection (boolean-based)", "comparator": "sqli_boolean_differential",
         "urls": ["http://127.0.0.1/community/api/v2/coupon/validate-coupon"]}
    assert cr._gate_coupon_sqli(e) is True
