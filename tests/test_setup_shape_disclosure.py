"""
test_setup_shape_disclosure.py — the model is shown the SHAPE of what setup returned.

Run 2C4 (2026-08-23): 9 of 9 model-proposed experiments died at

    UNRESOLVED REFERENCE, not run: ... ({{setup.0.id}}: no field 'id' in the setup
    response)

The setup was well chosen — `GET /rest/user/whoami` as both principals, which is exactly
how you identify two accounts before comparing them. Juice Shop answers
`{"user": {"id": 25, ...}}`, so the path is `user.id`. The model wrote `id`.

That is a CONTRACT gap, not a reasoning failure. `SETUP_REF_SYNTAX` documents the
reference GRAMMAR and nothing documents the SCHEMA of the response being referenced, so
the model is asked to name a field it has never been shown — while the harness is holding
the response body at `assist.py`'s `setup_results.append(rs)` and throwing it away.

The property: after setup responses are captured, the next round is shown the resolved
KEY PATHS of those responses. STRUCTURE, NEVER VALUES — a setup response is target data
and may carry a session token, an email, a password hash. Paths only, bounded, and when
the bound bites it is said out loud on both the record and the prompt.

The fail-safe is NOT relaxed by any of this. An unresolvable reference still raises
`UnresolvedReference`, is still not dispatched and still not judged; showing the model
the paths removes the REASON to guess, it does not make guessing safe.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from brukal import hypothesis as hyp
from brukal import redact


class _Res:
    def __init__(self, status, body=""):
        self.status, self.body = status, body


# -- the extractor itself: deterministic, no model, no eval ---------------------

def test_the_key_paths_of_a_wrapped_response_are_the_paths_not_the_leaf_names():
    """The named 2C4 body. `id` is what the model guessed; `user.id` is the truth."""
    paths, trunc = hyp.key_paths('{"user": {"id": 25, "email": "a@b.test"}}')
    assert paths == ["user.id", "user.email"]
    assert trunc == ""


def test_array_elements_are_addressed_by_index():
    """The syntax already supports `{{setup.0.data.items.0.id}}`; the disclosure has to
    speak the same language or it points the model at a path that cannot resolve."""
    body = '{"user": {"addresses": [{"id": 7}, {"id": 8}]}}'
    assert "user.addresses.0.id" in hyp.key_paths(body)[0]


@pytest.mark.parametrize("body", [
    '{"user": {"id": 25, "email": "a@b.test", "ok": true, "score": 1.5}}',
    '{"data": {"items": [{"id": 42}, {"id": 43}]}, "bid": 7}',
    '{"a": {"b": {"c": {"d": "deep"}}}}',
])
def test_every_listed_path_actually_resolves(body):
    """The disclosure must not be able to name a field the resolver then refuses. This
    is the whole contract in one assertion: what the model is shown IS what it may use.

    It also pins the exclusions — a `null`, an object, an empty array are all
    `UnresolvedReference` in `_lookup`, so none of them may appear in the list."""
    for path in hyp.key_paths(body)[0]:
        spec = {"url": "http://t/x/{{setup.0." + path + "}}", "method": "GET"}
        hyp.resolve_setup_refs(spec, [_Res(200, body)])       # must not raise


def test_a_value_that_could_not_be_inlined_is_never_listed():
    body = '{"obj": {"n": 1}, "nil": null, "empty": [], "s": "x"}'
    paths, _ = hyp.key_paths(body)
    assert paths == ["obj.n", "s"]
    for absent in ("nil", "empty", "obj"):
        assert absent not in paths


def test_a_body_that_is_not_json_yields_no_paths_rather_than_a_guess():
    assert hyp.key_paths("<html>server error</html>") == ([], "")


# -- the bound, and the bound saying so ----------------------------------------

def test_the_path_list_is_bounded_by_count_and_says_so():
    body = json.dumps({f"f{i}": i for i in range(200)})
    paths, trunc = hyp.key_paths(body, max_paths=10)
    assert len(paths) == 10
    assert paths == [f"f{i}" for i in range(10)], "the bound must be deterministic"
    assert "10 of 200" in trunc


def test_the_path_list_is_bounded_by_depth_and_says_so():
    body = '{"a": {"b": {"c": {"d": {"e": "too deep"}}}}}'
    paths, trunc = hyp.key_paths(body, max_depth=3)
    assert paths == []
    assert "3" in trunc and "deeper" in trunc.lower()


def test_a_list_that_fits_reports_no_truncation():
    """A fix for a silent failure must not fail silently — and it must not cry wolf
    either, or the marker stops meaning anything."""
    assert hyp.key_paths('{"a": 1, "b": 2}')[1] == ""


# -- end to end, through the governed browser and the real round loop ----------

class _ScriptedLLM:
    """Answers each `propose` from a script and keeps every prompt it was given."""

    def __init__(self, *replies):
        self._replies = list(replies)
        self.seen: list[str] = []
        self.last_stop_reason = ""
        self.last_block_kinds: list[str] = []

    def propose(self, system, user, max_tokens=1024):
        self.seen.append(system + "\n" + user)
        return self._replies.pop(0) if self._replies else "[]"


class _Cage:
    def __init__(self, mapping):
        self.mapping, self.seen = mapping, []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.mapping.get(action.url, (404, ""))
        return WebResult(status=status, url=action.url, body=body)


def _session(cage, llm, intrusive=True):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(llm),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = intrusive
    return sess


WHOAMI = "http://127.0.0.1:5000/rest/user/whoami"


def _round_one(ref="{{setup.0.id}}", body=None):
    """The 2C4 proposal verbatim in shape: a whoami setup, then a reference to a field
    the response does not carry at the top level."""
    return json.dumps([{
        "title": "User IDOR", "severity": "high", "comparator": "a_denied_b_allowed",
        "setup": [{"url": WHOAMI, "method": "GET", "as": "self"}],
        "control": {"url": f"http://127.0.0.1:5000/rest/user/{ref}",
                    "method": "GET", "as": "self"},
        "variant": {"url": f"http://127.0.0.1:5000/rest/user/{ref}",
                    "method": "GET", "as": "anonymous"}}])


def test_the_next_round_is_shown_the_key_paths_of_the_setup_response():
    """Property 1. `user.id` and its siblings, not the literal `id`."""
    body = '{"user": {"id": 25, "email": "a@b.test", "role": "customer"}}'
    llm = _ScriptedLLM(_round_one(), "[]")
    cage = _Cage({WHOAMI: (200, body)})
    sess = _session(cage, llm)
    sess.run_hypotheses()
    assert len(llm.seen) >= 2, "no refine round happened, so nothing could be shown"
    refine = llm.seen[1]
    assert "user.id, user.email, user.role" in refine
    assert WHOAMI in refine, "the paths are useless without the request that returned them"


def test_the_disclosure_carries_paths_and_never_values():
    """Property 2. A setup response is TARGET DATA. It may carry a session token, an
    email, a password hash — the model is told the shape and never the contents."""
    token = "eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbb"
    body = json.dumps({"user": {"id": 25, "email": "victim@t.test"}, "token": token})
    llm = _ScriptedLLM(_round_one(), "[]")
    cage = _Cage({WHOAMI: (200, body)})
    sess = _session(cage, llm)
    sess.run_hypotheses()
    refine = llm.seen[1]
    assert "user.token" in refine or "token" in refine, "the path itself is fine to show"
    assert token not in refine
    assert "victim@t.test" not in refine
    notes = "\n".join(sess.notes)
    assert token not in notes and "victim@t.test" not in notes


def test_the_live_2c4_failure_is_fixed_shown_the_paths_the_reference_dispatches():
    """Property 3, and the reason this exists. Round one guesses `{{setup.0.id}}` and is
    refused. Round two — having been SHOWN `user.id` — writes `{{setup.0.user.id}}`, and
    that request has to actually reach the target."""
    body = '{"user": {"id": 25, "email": "a@b.test"}}'
    llm = _ScriptedLLM(_round_one(), _round_one("{{setup.0.user.id}}"))
    cage = _Cage({WHOAMI: (200, body),
                  "http://127.0.0.1:5000/rest/user/25": (200, '{"ok": 1}')})
    sess = _session(cage, llm)
    sess.run_hypotheses()
    assert "user.id" in llm.seen[1], "round two was not shown the path it then used"
    assert "http://127.0.0.1:5000/rest/user/25" in cage.seen, \
        "the informed reference never dispatched"
    assert not any("{{" in u for u in cage.seen), "a placeholder reached the target"


def test_an_array_path_is_disclosed_and_dispatches():
    """Property 4. The syntax supports indices; so must the disclosure, end to end."""
    body = '{"user": {"addresses": [{"id": 7}]}}'
    llm = _ScriptedLLM(_round_one(), _round_one("{{setup.0.user.addresses.0.id}}"))
    cage = _Cage({WHOAMI: (200, body),
                  "http://127.0.0.1:5000/rest/user/7": (200, '{"ok": 1}')})
    sess = _session(cage, llm)
    sess.run_hypotheses()
    assert "user.addresses.0.id" in llm.seen[1]
    assert "http://127.0.0.1:5000/rest/user/7" in cage.seen


def test_a_truncated_disclosure_is_recorded_and_shown():
    """Property 5. A fix for a silent failure must not be able to fail silently itself:
    if the model is shown a partial list, it is told the list is partial — on the RECORD
    surface (the note) and on the PROMPT surface (what it is asked to reason from)."""
    body = json.dumps({f"f{i}": i for i in range(200)})
    llm = _ScriptedLLM(_round_one(), "[]")
    cage = _Cage({WHOAMI: (200, body)})
    sess = _session(cage, llm)
    sess.run_hypotheses()
    assert "TRUNCATED" in llm.seen[1], "the prompt hid that the list was cut"
    assert "TRUNCATED" in "\n".join(sess.notes), "the record hid that the list was cut"


def test_an_already_correct_reference_resolves_exactly_as_before():
    """Boundary 6. The named case from the fix this one builds on must be untouched."""
    llm = _ScriptedLLM(json.dumps([{
        "title": "Basket IDOR", "severity": "high", "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/api/Baskets", "method": "POST"}],
        "control": {"url": "http://127.0.0.1:5000/rest/basket/{{setup.0.BasketId}}",
                    "method": "GET", "as": "self"},
        "variant": {"url": "http://127.0.0.1:5000/rest/basket/{{setup.0.BasketId}}",
                    "method": "GET", "as": "anonymous"}}]), "[]")
    cage = _Cage({"http://127.0.0.1:5000/api/Baskets": (201, '{"BasketId": 7}'),
                  "http://127.0.0.1:5000/rest/basket/7": (200, '{"items": []}')})
    sess = _session(cage, llm)
    sess.run_hypotheses()
    assert "http://127.0.0.1:5000/rest/basket/7" in cage.seen
    assert not any("{{" in u for u in cage.seen)


def test_an_unresolvable_reference_is_still_refused_rather_than_judged():
    """Boundary 7. The fail-safe is NOT weakened. Showing the paths removes the reason
    to guess; it must not make a wrong guess survivable. `{{setup.0.nope}}` is absent
    from the disclosure AND still aborts the experiment, unjudged and unfiled."""
    body = '{"user": {"id": 25}}'
    llm = _ScriptedLLM(_round_one("{{setup.0.nope}}"), "[]")
    cage = _Cage({WHOAMI: (200, body)})
    sess = _session(cage, llm)
    assert sess.run_hypotheses() == 0
    assert not any("{{" in u for u in cage.seen), "a placeholder reached the target"
    notes = "\n".join(sess.notes)
    assert "UNRESOLVED REFERENCE" in notes
    assert "not confirmed" not in notes, "a substitution gap was filed as a negative"
    assert "user.id" in llm.seen[1], "the refine round should still get the shape"


def test_redaction_holds_on_the_disclosure_when_a_credential_is_a_KEY():
    """Property 8, driven at the one shape where 'paths, not values' is not enough.

    A response keyed BY a credential — `{"sessions": {"<jwt>": {...}}}` — puts the secret
    in the PATH, so the paths-only rule leaks it on its own. Verified rather than assumed,
    through the real `LLMClient.propose`, which is the funnel the prompt already passes."""
    from brukal.llm import LLMClient, UsageMeter

    token = "eyJhbGciOiJIUzI1NiJ9.cccccccccccccccccccccccc.dddddddddddd"

    class _Backend:
        def __init__(self):
            self.seen: list[str] = []
            self.last_usage: dict = {}
            self.last_stop_reason = ""
            self.last_block_kinds: list[str] = []
            self._replies = [_round_one(), "[]"]

        def propose(self, system, user, max_tokens):
            self.seen.append(system + "\n" + user)
            return self._replies.pop(0) if self._replies else "[]"

    backend = _Backend()
    client = LLMClient.__new__(LLMClient)
    client.provider, client.model = "anthropic", "m"
    client._backend, client.usage = backend, UsageMeter("m")

    body = json.dumps({"sessions": {token: {"id": 25}}})
    cage = _Cage({WHOAMI: (200, body)})
    redact.clear()
    try:
        redact.register(token)
        sess = _session(cage, client)
        sess.run_hypotheses()
        assert len(backend.seen) >= 2, "no refine round reached the backend"
        refine = backend.seen[1]
        assert token not in refine, "a credential rode out to the model inside a PATH"
        assert redact.placeholder_for(token) in refine, \
            "the path was dropped instead of redacted — structure must survive"
    finally:
        redact.clear()
