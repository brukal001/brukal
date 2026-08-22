"""
test_experiment_setup_refs.py — an experiment may USE what its setup created.

`setup` exists so a stateful flaw is reachable: create a basket, then interrogate it.
But a setup response was executed and thrown away, and the model was given no syntax for
referring to it — so on the 2026-08-16 Juice Shop run it invented `{{setup.0.BasketId}}`,
nothing substituted it, and all four IDOR experiments went out with the literal braces in
the path. Both sides answered 401 identically, the comparator said "not confirmed", and a
missing data-flow was recorded as evidence about the application.

Two properties, and the second matters more than the first: a reference RESOLVES, and a
reference that CANNOT resolve stops the experiment instead of going out as text. A
substitution gap must never again be indistinguishable from a negative result.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from brukal import hypothesis as hyp


# -- the resolver itself: deterministic template resolve, no model in the path ---

class _Res:
    def __init__(self, status, body=""):
        self.status, self.body = status, body


def test_a_reference_is_replaced_by_the_value_the_setup_response_carried():
    spec = {"url": "http://t/rest/basket/{{setup.0.BasketId}}", "method": "GET"}
    out = hyp.resolve_setup_refs(spec, [_Res(201, '{"BasketId": 7}')])
    assert out["url"] == "http://t/rest/basket/7"


def test_a_dotted_path_walks_nested_objects_and_arrays():
    """Real APIs wrap the id — `{"data": {"items": [{"id": 42}]}}` is the common shape,
    and a resolver that only reads top-level keys would send the braces out on it."""
    body = '{"data": {"items": [{"id": 42}, {"id": 43}]}}'
    spec = {"url": "http://t/x/{{setup.0.data.items.0.id}}", "method": "GET"}
    assert hyp.resolve_setup_refs(spec, [_Res(200, body)])["url"] == "http://t/x/42"


def test_references_resolve_in_the_body_and_headers_too():
    spec = {"url": "http://t/x", "method": "PUT",
            "body": '{"BasketId": "{{setup.0.BasketId}}"}',
            "headers": {"X-Basket": "{{setup.0.BasketId}}"}}
    out = hyp.resolve_setup_refs(spec, [_Res(201, '{"BasketId": 7}')])
    assert out["body"] == '{"BasketId": "7"}'
    assert out["headers"]["X-Basket"] == "7"


def test_a_spec_with_no_references_is_returned_untouched():
    spec = {"url": "http://t/x", "method": "GET", "body": "{}"}
    assert hyp.resolve_setup_refs(spec, []) == spec


@pytest.mark.parametrize("url, why", [
    ("http://t/x/{{setup.0.BasketId}}", "no setup response at that index"),
    ("http://t/x/{{setup.5.BasketId}}", "index past the end of the setup list"),
    ("http://t/x/{{setup.0.NoSuchField}}", "the field is absent from the response"),
    ("http://t/x/{{setup.0.data}}", "the value is an object, not something inlinable"),
])
def test_a_reference_nothing_can_satisfy_raises_rather_than_resolving_to_text(url, why):
    """Fail SAFE. Leaving the braces in place is the failure this module exists to stop:
    it produces a request that runs, answers, and gets judged as a negative."""
    results = [] if "setup.0" not in url or "5" in url else [
        _Res(201, '{"data": {"x": 1}}')]
    with pytest.raises(hyp.UnresolvedReference):
        hyp.resolve_setup_refs({"url": url, "method": "GET"}, results)


def test_a_setup_response_that_is_not_json_cannot_satisfy_a_reference():
    """An HTML error page is not a value store. Guessing at one would be invention."""
    with pytest.raises(hyp.UnresolvedReference):
        hyp.resolve_setup_refs({"url": "http://t/x/{{setup.0.id}}", "method": "GET"},
                               [_Res(500, "<html>server error</html>")])


def test_the_prompt_documents_the_reference_syntax():
    """The model invented `{{setup.0.BasketId}}` because it was told setup establishes
    state and never told how to USE it. A syntax the model has to guess is not a
    contract."""
    comparators = ", ".join(hyp.comparator_names())
    for template in (hyp.PROMPT, hyp.REFINE_PROMPT):
        prompt = template.format(comparators=comparators)   # as the model receives it
        assert "{{setup.<i>.<field>}}" in prompt
        assert "{{setup.0.BasketId}}" in prompt


# -- end to end, through the governed browser -----------------------------------

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


def _session(cage, intrusive=True):
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
    sess.allow_intrusive = intrusive
    return sess


def test_a_control_referencing_a_setup_response_is_dispatched_with_the_real_value():
    """The named case from the run this fixes: create a basket, then read it back by the
    id the creation returned."""
    _FakeLLM.reply = json.dumps([{
        "title": "Basket IDOR — a stranger reads a basket they do not own",
        "severity": "high", "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/api/Baskets", "method": "POST"}],
        "control": {"url": "http://127.0.0.1:5000/rest/basket/{{setup.0.BasketId}}",
                    "method": "GET", "as": "self"},
        "variant": {"url": "http://127.0.0.1:5000/rest/basket/{{setup.0.BasketId}}",
                    "method": "GET", "as": "anonymous"}}])
    cage = _Cage({"http://127.0.0.1:5000/api/Baskets": (201, '{"BasketId": 7}'),
                  "http://127.0.0.1:5000/rest/basket/7": (200, '{"items": []}')})
    sess = _session(cage)
    sess.run_hypotheses()
    assert "http://127.0.0.1:5000/rest/basket/7" in cage.seen
    assert not any("{{" in u for u in cage.seen), "a placeholder reached the target"


def test_a_setup_step_may_reference_an_earlier_setup_response():
    """Setup is a SEQUENCE — create a basket, then add an item to it. Resolving only the
    judged pair would leave the identical silent failure one step upstream."""
    _FakeLLM.reply = json.dumps([{
        "title": "x", "severity": "high", "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/api/Baskets", "method": "POST"},
                  {"url": "http://127.0.0.1:5000/api/BasketItems/{{setup.0.BasketId}}",
                   "method": "POST"}],
        "control": {"url": "http://127.0.0.1:5000/a", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/b", "method": "GET"}}])
    cage = _Cage({"http://127.0.0.1:5000/api/Baskets": (201, '{"BasketId": 7}'),
                  "http://127.0.0.1:5000/api/BasketItems/7": (201, "ok"),
                  "http://127.0.0.1:5000/a": (200, "a"),
                  "http://127.0.0.1:5000/b": (500, "b")})
    sess = _session(cage)
    sess.run_hypotheses()
    assert "http://127.0.0.1:5000/api/BasketItems/7" in cage.seen
    assert not any("{{" in u for u in cage.seen)


def test_an_unresolvable_reference_errors_the_experiment_rather_than_being_judged():
    """The whole point. The old behaviour sent the braces, got a real answer, and filed
    it as `not confirmed` — a harness gap wearing the costume of a clean negative."""
    _FakeLLM.reply = json.dumps([{
        "title": "Basket IDOR", "severity": "high", "comparator": "a_denied_b_allowed",
        "setup": [{"url": "http://127.0.0.1:5000/api/Baskets", "method": "POST"}],
        "control": {"url": "http://127.0.0.1:5000/rest/basket/{{setup.0.NoSuchField}}",
                    "method": "GET", "as": "anonymous"},
        "variant": {"url": "http://127.0.0.1:5000/rest/basket/{{setup.0.NoSuchField}}",
                    "method": "GET", "as": "self"}}])
    cage = _Cage({"http://127.0.0.1:5000/api/Baskets": (201, '{"BasketId": 7}')})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0
    assert not any("{{" in u for u in cage.seen), "a placeholder reached the target"
    notes = "\n".join(sess.notes)
    assert "UNRESOLVED REFERENCE" in notes
    assert "not confirmed" not in notes, "a substitution gap was filed as a negative"
