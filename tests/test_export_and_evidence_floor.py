"""test_export_and_evidence_floor.py — two recording gaps found in the 2C3b pre-flight.

**2a. The published summary dropped the provenance.** `findings.jsonl` — the append-only
ledger — carries `evidence_class`, `agent_claim` and `agent_severity`, so an overclaim
rate is computable from it. `findings.json`, which `export.to_json` builds field by field,
did not: it enumerates an explicit dict and silently omits anything added to `Finding`
later. The overclaim rate is a headline measurement for this project, and it has to be
computable from the PUBLISHED artifact rather than only from the raw ledger.

**2b. `bodies_differ` has no floor.** In the 2C3b pre-flight it confirmed on
`GET /api/Addresses/1` vs `/api/Addresses/2` where both sides answered **500 with 2432
bytes** — two identical-length server errors whose bodies differed only in an echoed id.
The application failed both times, so the difference says nothing whatsoever about its
behaviour; it is the error handler's output, not the application's.

The floor is principled rather than numeric: **when both sides are 5xx the application
did not behave, it broke, and a comparator cannot read behaviour out of a crash.** It is
recorded as not-a-result in the same shape as `UNRESOLVED REFERENCE` and
`SECOND PRINCIPAL UNAVAILABLE` — never as a finding and never as a clean negative.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

_A1 = "http://127.0.0.1:5000/api/Addresses/1"
_A2 = "http://127.0.0.1:5000/api/Addresses/2"
_B1 = "http://127.0.0.1:5000/rest/basket/1"
_B2 = "http://127.0.0.1:5000/rest/basket/2"


class _FakeLLM:
    reply = "[]"

    def propose(self, system, user, max_tokens=1024):
        return _FakeLLM.reply


class _Cage:
    def __init__(self, mapping):
        self.mapping, self.seen = mapping, []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.mapping.get(action.url, (404, ""))
        return WebResult(status=status, url=action.url, body=body)


def _session(cage):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    return sess


def _hyp(c_url, v_url, comparator="bodies_differ", title="claimed IDOR", sev="high"):
    return json.dumps([{
        "title": title, "severity": sev, "comparator": comparator,
        "control": {"url": c_url, "method": "GET", "as": "self"},
        "variant": {"url": v_url, "method": "GET", "as": "self"}}])


def _logic(sess):
    return [f for f in sess.findings.all() if f.confirmed and f.category == "logic"]


# -- 2a. the published summary carries the provenance ----------------------------------

def test_the_published_findings_json_carries_the_derived_and_agent_claims():
    """`export.to_json` enumerates its dict field by field, so anything added to Finding
    is dropped unless it is added here too. The ledger had it; the published artifact
    did not."""
    from brukal import export
    from brukal.findings import Finding
    f = Finding(title="Different response bodies for /a vs /b — same principal (self)",
                severity="low", category="logic", confirmed=True,
                target=_A2, evidence="[evidence: bodies_differ] ...",
                evidence_class="bodies_differ",
                agent_claim="Cross-user address disclosure (IDOR)",
                agent_severity="high")
    doc = export.to_json([f])
    item = doc["findings"][0]
    for k in ("evidence_class", "agent_claim", "agent_severity"):
        assert k in item, f"the published summary drops {k}"
    assert item["evidence_class"] == "bodies_differ"
    assert item["agent_severity"] == "high"


def test_the_overclaim_rate_is_computable_from_findings_json_alone():
    """The measurement this exists for: a reader holding only the published artifact
    must be able to count where the model claimed more than the evidence supported."""
    from brukal import export
    from brukal.findings import Finding
    fs = [
        Finding(title="derived a", severity="low", category="logic", confirmed=True,
                evidence_class="bodies_differ", agent_claim="IDOR!", agent_severity="high"),
        Finding(title="derived b", severity="low", category="logic", confirmed=True,
                evidence_class="bodies_differ", agent_claim="IDOR!", agent_severity="medium"),
        Finding(title="a real one", severity="high", category="logic", confirmed=True,
                evidence_class="a_denied_b_allowed", agent_claim="authz", agent_severity="high"),
    ]
    items = export.to_json(fs)["findings"]
    experiments = [i for i in items if i.get("evidence_class")]
    over = [i for i in experiments
            if i["agent_severity"] in ("high", "critical")
            and i["severity"] in ("info", "low", "medium")]
    assert len(experiments) == 3
    assert len(over) == 1, f"the overclaim rate is not computable: {over}"


def test_a_non_experiment_finding_exports_empty_provenance_not_missing_keys():
    """A stable schema: the keys are always there, empty on findings that were not
    proved by a comparator. A consumer should not have to guess."""
    from brukal import export
    from brukal.findings import Finding
    item = export.to_json([Finding(title="SQL injection", severity="critical",
                                   confirmed=True)])["findings"][0]
    assert item["evidence_class"] == "" and item["agent_claim"] == ""


# -- 2b. the 5xx floor -----------------------------------------------------------------

def test_two_server_errors_are_not_a_confirmation():
    """The live case: /api/Addresses/1 vs /2, both 500, both 2432B, bodies differing only
    in an echoed id. The application broke twice; that is not behaviour to compare."""
    _FakeLLM.reply = _hyp(_A1, _A2)
    sess = _session(_Cage({_A1: (500, "err id=1" + "x" * 2400),
                           _A2: (500, "err id=2" + "x" * 2400)}))
    assert sess.run_hypotheses() == 0, "a pair of 500s was published as a finding"
    assert not _logic(sess)


def test_a_pair_of_server_errors_is_recorded_as_not_a_result():
    """Same shape as UNRESOLVED REFERENCE: it did not run as a comparison, and that is
    not the same as a clean negative."""
    _FakeLLM.reply = _hyp(_A1, _A2)
    sess = _session(_Cage({_A1: (500, "err id=1"), _A2: (500, "err id=2")}))
    sess.run_hypotheses()
    notes = "\n".join(sess.notes)
    assert "BOTH SIDES FAILED" in notes or "both sides" in notes.lower(), (
        f"nothing said why it was not judged: {notes!r}")
    assert "not confirmed" not in notes.lower(), (
        "a broken application was filed as a clean negative")


def test_a_200_versus_500_pair_is_still_judged_normally():
    """The boundary. One side working and the other breaking IS a real signal — it is
    exactly what b_errors_a_does_not exists for — and must not be swept up."""
    _FakeLLM.reply = _hyp(_B1, _B2, comparator="b_errors_a_does_not")
    sess = _session(_Cage({_B1: (200, "fine"), _B2: (500, "boom")}))
    assert sess.run_hypotheses() == 1, "a genuine 200-vs-500 result was suppressed"


def test_a_200_versus_200_pair_is_unaffected():
    _FakeLLM.reply = _hyp(_B1, _B2)
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}))
    assert sess.run_hypotheses() == 1


def test_the_floor_applies_to_every_comparator_not_just_bodies_differ():
    """A crash is a crash. `status_differs` between 500 and 503 is two different
    failures, not two different behaviours."""
    _FakeLLM.reply = _hyp(_A1, _A2, comparator="status_differs")
    sess = _session(_Cage({_A1: (500, "a"), _A2: (503, "b")}))
    assert sess.run_hypotheses() == 0
