"""
test_hypothesis.py — the model proposes, a fixed comparator disposes.

Brukal's narrowest limitation was that it finds only what a detector was written for:
15 findings on the target its detectors were fitted to, 2 on an unfamiliar one, and
every gap a competitor exposed had to be hand-built afterwards. This is the mechanism
that lets it reach a flaw class nobody enumerated.

The entire difficulty is doing that WITHOUT letting the model declare anything true, so
almost every test below is about what a proposal is not allowed to do.
"""
from __future__ import annotations

import json

from brukal import hypothesis as hyp


class _R:
    def __init__(self, status, body=""):
        self.status, self.body = status, body


def _prop(**kw):
    base = {"title": "t", "severity": "high", "comparator": "status_differs",
            "control": {"url": "http://t/a", "method": "GET"},
            "variant": {"url": "http://t/b", "method": "GET"}}
    base.update(kw)
    return json.dumps([base])


# -- parsing: what a proposal may and may not carry ---------------------------

def test_a_well_formed_proposal_parses():
    got = hyp.parse(_prop())
    assert len(got) == 1 and got[0].comparator == "status_differs"


def test_an_unknown_comparator_is_refused_not_defaulted():
    """Defaulting would let a vague proposal borrow the authority of a strict one."""
    assert hyp.parse(_prop(comparator="looks_dodgy")) == []
    assert hyp.parse(_prop(comparator="")) == []


def test_a_predicate_expression_is_not_accepted_as_a_comparator():
    """The comparator is a NAME from a closed set, never model-supplied logic. Anything
    else would have to be evaluated to be useful, and eval over target-influenced text
    is the same mistake as putting an LLM inside the gate."""
    assert hyp.parse(_prop(comparator="a.status != b.status")) == []
    assert hyp.parse(_prop(comparator="__import__('os').system('id')")) == []


def test_non_http_urls_are_refused():
    assert hyp.parse(_prop(control={"url": "file:///etc/passwd", "method": "GET"})) == []
    assert hyp.parse(_prop(variant={"url": "gopher://x/", "method": "GET"})) == []


def test_unknown_request_fields_are_dropped_not_forwarded():
    """A proposal must not be able to smuggle a field into the web layer."""
    got = hyp.parse(_prop(variant={"url": "http://t/b", "method": "GET",
                                   "verify": False, "proxies": {"http": "http://evil"},
                                   "timeout": 9999}))
    assert set(got[0].variant) <= {"url", "method", "body", "headers"}


def test_a_differential_against_itself_is_refused():
    same = {"url": "http://t/a", "method": "GET"}
    assert hyp.parse(_prop(control=same, variant=dict(same))) == []


def test_malformed_input_yields_nothing_rather_than_guessing():
    for junk in ("", "not json", "{}", "[1,2,3]", '[{"title":"x"}]', "```json\n[\n```"):
        assert hyp.parse(junk) == []


def test_a_fenced_array_is_accepted_because_models_emit_them():
    assert len(hyp.parse(f"Here you go:\n```json\n{_prop()}\n```\nhope that helps")) == 1


# -- judging: the only place a proposal becomes a finding ----------------------

def test_the_comparator_decides_not_the_proposal():
    h = hyp.parse(_prop(comparator="a_denied_b_allowed"))[0]
    holds, meaning = hyp.judge(h, _R(403), _R(200, "data"))
    assert holds and "refused" in meaning
    # the same proposal, evidence that does not support it
    assert hyp.judge(h, _R(403), _R(403))[0] is False


def test_a_missing_response_is_not_a_pass():
    """An unreachable target proves nothing. Treating silence as a result is how a
    scanner invents vulnerabilities."""
    h = hyp.parse(_prop())[0]
    assert hyp.judge(h, None, _R(200))[0] is False
    assert hyp.judge(h, _R(200), None)[0] is False
    assert hyp.judge(h, None, None)[0] is False


def test_status_differs_needs_both_sides_to_have_answered():
    h = hyp.parse(_prop(comparator="status_differs"))[0]
    assert hyp.judge(h, _R(None), _R(200))[0] is False


def test_b_reveals_more_requires_a_material_difference():
    h = hyp.parse(_prop(comparator="b_reveals_more"))[0]
    assert hyp.judge(h, _R(200, "x" * 100), _R(200, "x" * 150))[0] is False  # noise
    assert hyp.judge(h, _R(200, "x" * 100), _R(200, "x" * 900))[0] is True


def test_bodies_differ_ignores_whitespace_only_changes():
    h = hyp.parse(_prop(comparator="bodies_differ"))[0]
    assert hyp.judge(h, _R(200, "a  b\n"), _R(200, "a b"))[0] is False


def test_a_comparator_that_raises_does_not_confirm():
    h = hyp.parse(_prop())[0]
    broken = type("X", (), {"status": property(lambda s: 1 / 0), "body": ""})()
    assert hyp.judge(h, broken, _R(200))[0] is False


def test_the_prompt_names_only_real_comparators():
    prompt = hyp.PROMPT.format(comparators=", ".join(hyp.comparator_names()))
    for name in hyp.comparator_names():
        assert name in prompt
    assert "cannot declare anything true" in prompt


# -- the runner: gate and governance still apply -------------------------------

def _session(cage, leads=()):
    import tempfile
    from pathlib import Path
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.assist import AssistSession
    from brukal.agents.strategist import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.source_leads = list(leads)
    return sess


class _FakeLLM:
    """Returns whatever proposal the test set on the class."""
    reply = "[]"

    def propose(self, system, user, max_tokens=1024):
        _FakeLLM.last_user = user
        return _FakeLLM.reply


class _Cage:
    def __init__(self, mapping):
        self.mapping, self.seen = mapping, []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.mapping.get(action.url, (404, ""))
        return WebResult(status=status, url=action.url, body=body)


def test_a_supported_hypothesis_becomes_a_confirmed_finding():
    _FakeLLM.reply = json.dumps([{
        "title": "Order total accepts a negative quantity",
        "severity": "high", "comparator": "a_denied_b_allowed",
        "control": {"url": "http://127.0.0.1:5000/order?qty=1", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/order?qty=-1", "method": "GET"},
        "rationale": "a negative quantity should be rejected"}])
    sess = _session(_Cage({"http://127.0.0.1:5000/order?qty=1": (403, ""),
                           "http://127.0.0.1:5000/order?qty=-1": (200, "ok")}))
    assert sess.run_hypotheses() == 1
    f = sess.findings.all()[0]
    assert f.confirmed and f.severity == "high" and f.category == "logic"
    assert "control" in f.evidence and "variant" in f.evidence


def test_an_unsupported_hypothesis_is_discarded_not_recorded_as_a_lead():
    """An unproven guess from a model is not a lead — it is noise. The candidate tier
    only means something while candidates are things a human could actually verify."""
    _FakeLLM.reply = json.dumps([{
        "title": "Speculative flaw", "severity": "critical",
        "comparator": "a_denied_b_allowed",
        "control": {"url": "http://127.0.0.1:5000/a", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/b", "method": "GET"}}])
    sess = _session(_Cage({"http://127.0.0.1:5000/a": (200, "x"),
                           "http://127.0.0.1:5000/b": (200, "x")}))
    assert sess.run_hypotheses() == 0
    assert sess.findings.all() == []


def test_a_destructive_proposal_is_refused_by_code_not_only_by_the_prompt():
    """The prompt forbids it; the prompt is not a control."""
    _FakeLLM.reply = json.dumps([{
        "title": "Wipe it", "severity": "critical", "comparator": "status_differs",
        "control": {"url": "http://127.0.0.1:5000/health", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/createdb", "method": "GET"}}])
    cage = _Cage({"http://127.0.0.1:5000/health": (200, "ok"),
                  "http://127.0.0.1:5000/createdb": (200, "wiped")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0
    assert not any("createdb" in u for u in cage.seen)     # never requested at all


def test_source_observations_reach_the_model_marked_unverified():
    """Reasoning ABOUT code, not pattern-matching it — while the source still proves
    nothing on its own."""
    _FakeLLM.reply = "[]"
    sess = _session(_Cage({}), leads=[{"kind": "signing-secret", "value": "random",
                                       "where": "config.py", "hint": "h"}])
    sess.run_hypotheses()
    assert "signing-secret" in _FakeLLM.last_user
    assert "UNVERIFIED" in _FakeLLM.last_user


def test_no_model_means_no_hypotheses_rather_than_an_error():
    sess = _session(_Cage({}))
    sess.strategist = None
    assert sess.run_hypotheses() == 0
