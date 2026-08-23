"""test_derived_claim_detail.py — the derived claim must be readable, and the model's
claim must survive next to it so overreach can be counted.

`1940f09` stopped a finding claiming more than its comparator earned. It did so with a
generic title — "Observed difference [bodies_differ] — the same principal (self) on both
sides at /rest/basket/2" — which is honest and nearly unreadable, and it dropped the
model's assertion entirely.

Two things follow.

**The title should be built from what the ledger already holds.** Endpoints, which value
differed, the observed statuses and body sizes are all facts on the record; assembling
them is still fully derived and still has no model prose in it. A reader should be able
to tell two findings apart without opening the evidence.

**The model's claim should persist beside the derived one, labelled.** Not rendered as
the finding — that is the defect this closed — but kept as structured data, because the
gap between what the model asserted and what the evidence supported is itself a
measurement. An overclaim rate is a number this project should be able to publish:
"the model claimed cross-account impact on N findings; the evidence supported
difference-only on M of them" is a far stronger statement about governed autonomy than
any assurance that it does not happen.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import redact
from brukal.hypothesis import derive_claim

_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjbGFpbS1kZXRhaWwifQ."
        "s1gnatureThatMustNotReachAnyRecordSurfaceAtAll")

_B1 = "http://127.0.0.1:5000/rest/basket/1"
_B2 = "http://127.0.0.1:5000/rest/basket/2"
_U1 = "http://127.0.0.1:5000/api/Users/1"
_U2 = "http://127.0.0.1:5000/api/Users/2"


class _FakeLLM:
    reply = "[]"

    def propose(self, system, user, max_tokens=1024):
        return _FakeLLM.reply


class _Cage:
    def __init__(self, mapping, browser_ref=None):
        self.mapping, self.seen = mapping, []
        self.browser_ref = browser_ref

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.mapping.get(action.url, (404, ""))
        b = self.browser_ref[0] if self.browser_ref else None
        if b is not None:
            body = f"{body} auth={getattr(b, 'auth_header', '')}"
        return WebResult(status=status, url=action.url, body=body)


def _session(cage):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    browser = GovernedBrowser(scope, cage, audit)
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()), browser=browser)
    sess.blackboard = Blackboard(root / "vault", scope)
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    sess._root, sess._audit_path = root, root / "a.jsonl"
    if getattr(cage, "browser_ref", None) is not None:
        cage.browser_ref[0] = browser
    return sess


def _logic(sess):
    return [f for f in sess.findings.all() if f.confirmed and f.category == "logic"]


def _hyp_json(title, sev, comparator, c_url, v_url, c_as="self", v_as="self", rationale=""):
    return json.dumps([{
        "title": title, "severity": sev, "comparator": comparator,
        "rationale": rationale,
        "control": {"url": c_url, "method": "GET", "as": c_as},
        "variant": {"url": v_url, "method": "GET", "as": v_as}}])


# -- 1a. a title assembled from ledger facts -------------------------------------------

def test_the_title_names_both_endpoints_and_the_observed_difference():
    """A reader should learn what happened from the title alone: which two things were
    compared, and how the answers differed."""
    _FakeLLM.reply = _hyp_json("Basket IDOR - another user's basket", "high",
                               "bodies_differ", _B1, _B2)
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}))
    assert sess.run_hypotheses() == 1
    t = _logic(sess)[0].title
    assert "/rest/basket/1" in t and "/rest/basket/2" in t, f"endpoints missing: {t!r}"
    assert "200" in t, f"observed status missing: {t!r}"
    assert "1310" in t and "557" in t, f"observed sizes missing: {t!r}"
    assert "same principal" in t.lower(), f"principal relation missing: {t!r}"


def test_the_title_still_asserts_no_ownership_authorization_or_impact():
    """The readability gain must not smuggle the claim back in."""
    _FakeLLM.reply = _hyp_json("Basket IDOR - any user reads another user's basket",
                               "critical", "bodies_differ", _B1, _B2)
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}))
    sess.run_hypotheses()
    t = _logic(sess)[0].title.lower()
    for banned in ("another user", "idor", "unauthorised", "unauthorized",
                   "privilege", "leak", "disclosure", "any authenticated"):
        assert banned not in t, f"the title asserts impact it did not earn: {banned!r} in {t!r}"


def test_two_findings_at_different_endpoints_get_distinguishable_titles():
    """The generic label made every bodies_differ finding read the same, which is a
    reporting failure of its own — a reader cannot triage a list of identical rows."""
    _FakeLLM.reply = json.dumps([
        {"title": "a", "severity": "high", "comparator": "bodies_differ",
         "control": {"url": _B1, "method": "GET", "as": "self"},
         "variant": {"url": _B2, "method": "GET", "as": "self"}},
        {"title": "b", "severity": "high", "comparator": "bodies_differ",
         "control": {"url": _U1, "method": "GET", "as": "self"},
         "variant": {"url": _U2, "method": "GET", "as": "self"}}])
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557),
                           _U1: (200, "a" * 301), _U2: (200, "b" * 297)}))
    sess.run_hypotheses()
    titles = {f.title for f in _logic(sess)}
    assert len(titles) == 2, f"two different endpoints produced indistinguishable titles: {titles}"


def test_derive_claim_is_still_a_pure_function_of_ledger_facts():
    """No session, no model, no I/O — the same inputs give the same sentence."""
    a = derive_claim("bodies_differ", "self", "self",
                     control={"url": _B1, "status": 200, "size": 1310},
                     variant={"url": _B2, "status": 200, "size": 557})
    b = derive_claim("bodies_differ", "self", "self",
                     control={"url": _B1, "status": 200, "size": 1310},
                     variant={"url": _B2, "status": 200, "size": 557})
    assert a == b and a["title"] and a["evidence_class"] == "bodies_differ"


# -- 1b. the model's claim persists, labelled and machine-readable -----------------------

def test_the_models_title_and_severity_survive_on_the_record():
    """Kept as data so the gap between assertion and evidence can be counted."""
    _FakeLLM.reply = _hyp_json("Basket IDOR - reads another user's basket", "critical",
                               "bodies_differ", _B1, _B2)
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}))
    sess.run_hypotheses()
    f = _logic(sess)[0]
    assert getattr(f, "agent_claim", "") == "Basket IDOR - reads another user's basket"
    assert getattr(f, "agent_severity", "") == "critical"


def test_the_models_claim_is_never_the_findings_claim_or_severity():
    _FakeLLM.reply = _hyp_json("Basket IDOR - reads another user's basket", "critical",
                               "bodies_differ", _B1, _B2)
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}))
    sess.run_hypotheses()
    f = _logic(sess)[0]
    assert f.title != f.agent_claim
    assert f.severity != f.agent_severity
    assert f.severity in ("info", "low", "medium")


def test_the_overclaim_pair_is_machine_readable_from_the_record():
    """The point of keeping it: a later pass counts overclaims without parsing prose."""
    _FakeLLM.reply = _hyp_json("Basket IDOR - another user's basket", "critical",
                               "bodies_differ", _B1, _B2)
    sess = _session(_Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}))
    sess.run_hypotheses()
    d = _logic(sess)[0].to_dict()
    assert "agent_claim" in d and "agent_severity" in d and "evidence_class" in d
    overclaimed = [x for x in [d]
                   if x["agent_severity"] in ("high", "critical")
                   and x["severity"] in ("info", "low", "medium")]
    assert overclaimed, "an overclaim is not computable from the record"
    assert d["evidence_class"] == "bodies_differ"


def test_redaction_holds_on_the_new_agent_claim_field():
    """A model can put anything in a title, including something it read off the target.
    New field, new record surface — checked, not assumed."""
    redact.clear()
    try:
        redact.register(_JWT)
        _FakeLLM.reply = _hyp_json(f"leaky title {_JWT}", "critical", "bodies_differ",
                                   _B1, _B2, rationale=f"and the rationale too {_JWT}")
        cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}, browser_ref=[None])
        sess = _session(cage)
        sess.browser.auth_header = f"Bearer {_JWT}"
        sess.run_hypotheses()
        f = _logic(sess)[0]
        assert _JWT not in f.agent_claim, "the token reached the agent_claim field"
        assert redact.placeholder_for(_JWT) in f.agent_claim
        surfaces = {"audit": Path(sess._audit_path).read_text(encoding="utf-8")}
        for p in sorted((sess._root / "vault").rglob("*")):
            if p.is_file():
                surfaces[str(p)] = p.read_text(encoding="utf-8", errors="replace")
        for name, text in surfaces.items():
            assert _JWT not in text, f"session token in cleartext on {name}"
    finally:
        redact.clear()


# -- 1c. the cap is experiment-path only ---------------------------------------------------

def test_the_severity_cap_applies_only_to_the_experiment_path():
    """DELIBERATE, and pinned because getting it wrong is a silent regression: a
    confirmed SQLi, command injection or foothold is proved by its own detector against
    an explicit signal, not by a two-request comparator, and must keep its severity. The
    ceiling belongs to the differential evidence classes alone."""
    import inspect

    from brukal import assist
    src = inspect.getsource(assist)
    assert src.count("cap_severity(") == 1, (
        "the severity ceiling reached a second construction site — a non-experiment "
        "finding is now being capped, which would silently downgrade a confirmed SQLi")
    # and it lives in the experiment runner, not in a shared helper
    runner = inspect.getsource(assist.AssistSession._run_one_round)
    assert "cap_severity(" in runner


def test_a_non_experiment_confirmed_finding_keeps_its_full_severity():
    """The behavioural half of the same guarantee."""
    from brukal.findings import Finding
    f = Finding(title="SQL injection", severity="critical", category="web",
                target="http://127.0.0.1:5000/x", confirmed=True,
                evidence="boolean-based differential confirmed")
    assert f.severity == "critical", "a detector-proved finding was capped"
    assert getattr(f, "evidence_class", "") == "", (
        "a non-experiment finding should carry no comparator evidence class")
