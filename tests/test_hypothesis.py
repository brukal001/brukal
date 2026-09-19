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
    assert set(got[0].variant) <= {"url", "method", "body", "headers", "as"}


def test_an_unknown_principal_falls_back_to_self():
    """`as` names a principal from a closed set — the same discipline as the
    comparators. A proposal may SELECT a credential that already exists; it may never
    describe one."""
    got = hyp.parse(_prop(variant={"url": "http://t/b", "method": "GET",
                                   "as": "administrator"}))
    assert got[0].variant["as"] == "self"


def test_the_named_principals_are_carried_through():
    got = hyp.parse(_prop(control={"url": "http://t/a", "method": "GET",
                                   "as": "anonymous"},
                          variant={"url": "http://t/a", "method": "GET",
                                   "as": "second"}))
    assert got[0].control["as"] == "anonymous" and got[0].variant["as"] == "second"


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
    prompt = hyp.experiment_prompt()
    for name in hyp.comparator_names():
        assert name in prompt
    assert "cannot declare anything true" in prompt


# -- the runner: gate and governance still apply -------------------------------

def _session(cage, leads=(), intrusive=True):
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
    sess.allow_intrusive = intrusive
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
    # Severity is CAPPED, not quoted: `a_denied_b_allowed` fired here between the SAME
    # principal on two different urls, which shows an input was refused and another
    # accepted — real, but not an authorization result, so the model's "high" is held to
    # the evidence class's ceiling. See hypothesis._EVIDENCE_CLASS.
    assert f.confirmed and f.severity == "medium" and f.category == "logic"
    assert "control" in f.evidence and "variant" in f.evidence
    assert "[evidence: a_denied_b_allowed]" in f.evidence
    assert "a negative quantity should be rejected" in f.evidence, (
        "the model's reasoning must survive, labelled")
    assert "UNVERIFIED" in f.evidence


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


def test_hypotheses_are_reachable_on_a_wide_surface():
    """The regression that made the whole mechanism dead on arrival. Placed inside
    confirm_surface's 120-request allowance, hypotheses were unreachable on exactly the
    targets they exist for: Juice Shop spent 60 probes on exposure checks alone and the
    sweep returned before ever asking for one. Live run: 2 findings, and no
    'Model-proposed experiments' row in the coverage table."""
    from pathlib import Path
    import brukal.loop as _loop, brukal.assist as _assist
    loop_src = Path(_loop.__file__).read_text()
    assist_src = Path(_assist.__file__).read_text()
    # the loop invokes it...
    assert "self.session.run_hypotheses()" in loop_src
    # ...and the sweep does not, so it cannot be starved by the reflex budget
    body = assist_src[assist_src.index("def confirm_surface"):]
    body = body[:body.index("\n    def ", 10)]
    assert "run_hypotheses" not in body


def test_a_truncated_reply_still_yields_its_intact_experiments():
    """The defect that made the first live run produce nothing. A model with adaptive
    thinking spends part of its output allowance before emitting any JSON, so a reply
    cut mid-array is the NORMAL case — and the guard looking for a closing bracket
    returned empty before the salvage could recover the complete objects before the cut."""
    truncated = ('[{"title":"A","severity":"high","comparator":"status_differs",'
                 '"control":{"url":"http://t/a","method":"GET"},'
                 '"variant":{"url":"http://t/b","method":"GET"}},'
                 '{"title":"B","severity":"high","comparator":"a_denied_b')
    got = hyp.parse(truncated)
    assert [h.title for h in got] == ["A"]      # the intact one, not the half-written one


def test_a_half_written_request_is_dropped_never_repaired():
    """Guessing at half a request spec is the invention this module exists to prevent."""
    truncated = ('[{"title":"A","severity":"high","comparator":"status_differs",'
                 '"control":{"url":"http://t/a","method":"GET"},"variant":{"url":"http')
    assert hyp.parse(truncated) == []


def test_the_model_is_given_the_base_url_not_the_bare_target():
    """The first live run handed the model '172.20.0.2' while the app was on :3000, so
    every proposed URL went to port 80, every request missed, and six sound experiments
    were judged against nothing. A hypothesis aimed at the wrong port is not a failed
    hypothesis, it is a failed prompt."""
    _FakeLLM.reply = "[]"
    sess = _session(_Cage({}))
    sess.surface.seed = "http://127.0.0.1:5000/"
    sess.run_hypotheses()
    assert "http://127.0.0.1:5000" in _FakeLLM.last_user


def test_the_model_is_told_auth_is_automatic_rather_than_handed_the_token():
    """RESTATED, not weakened — same subject, corrected mechanism.

    The original property stands: an authenticated experiment must really be
    authenticated (the model once wrote `Bearer <userA_token>` literally, the target
    rejected it, and every experiment tested nothing). What changed is HOW that is
    guaranteed. This test used to pin the fix of handing the model the real token, and
    that mechanism was later shown to CAUSE the same failure it was preventing: once the
    token was masked at the record boundary the model copied `Bearer [REDACTED:...]`
    instead, and `_apply_cookies` withholds the real session whenever the request already
    carries an Authorization header — so the experiment ran logged out, silently.

    The token was never needed. `_as_identity` swaps the principal for
    "as": self/second/anonymous and the governed browser attaches whatever it holds, so a
    model-set header defeats that machinery even when the value is real. The other half of
    the original property — that the request really does go out authenticated — is pinned
    end to end by
    test_auth_not_placeholder.py::test_the_real_credential_reaches_the_network_through_the_governed_path.
    """
    _FakeLLM.reply = "[]"
    sess = _session(_Cage({}))
    sess.last_jwt = "eyJhbGciOi.real.token"
    sess.identity = "brk"
    sess.run_hypotheses()
    assert "eyJhbGciOi.real.token" not in _FakeLLM.last_user
    assert "Never write a placeholder" not in _FakeLLM.last_user
    assert "automatically" in _FakeLLM.last_user
    assert "do not set a cookie or authorization header" in _FakeLLM.last_user.lower()


def test_the_attempt_is_recorded_even_when_nothing_parses():
    """'Asked the model and got nothing usable' is a result. The first live run left no
    coverage row at all, which is the exact ambiguity that table exists to remove."""
    _FakeLLM.reply = "total nonsense, no json here"
    sess = _session(_Cage({}))
    assert sess.run_hypotheses() == 0
    rows = dict((k, (p, n)) for k, p, n, _f in sess.coverage_summary())
    assert "Model-proposed experiments" in rows
    assert "no usable experiment" in rows["Model-proposed experiments"][1]


def test_bodies_differ_ignores_an_endpoint_merely_echoing_its_input():
    """The live false positive. Two registrations with different usernames always
    produce different bodies — the echoed name and id differ — so this comparator
    reported mass-assignment role escalation on a 2-byte difference that demonstrated
    nothing. What we submitted is stripped before comparing, as the enumeration check
    already does."""
    h = hyp.parse(json.dumps([{
        "title": "t", "severity": "high", "comparator": "bodies_differ",
        "control": {"url": "http://t/api/Users", "method": "POST",
                    "body": {"email": "aaa@x.io", "password": "Pw1"}},
        "variant": {"url": "http://t/api/Users", "method": "POST",
                    "body": {"email": "bbb@x.io", "password": "Pw1", "role": "admin"}}}]))[0]
    echo_a = _R(201, '{"id":1,"email":"aaa@x.io","role":"customer"}')
    echo_b = _R(201, '{"id":1,"email":"bbb@x.io","role":"customer"}')
    assert hyp.judge(h, echo_a, echo_b)[0] is False       # only the echo differed

    # ...but a genuine difference in what the SERVER chose still counts
    real_a = _R(201, '{"id":1,"email":"aaa@x.io","role":"customer"}')
    real_b = _R(201, '{"id":1,"email":"bbb@x.io","role":"admin"}')
    assert hyp.judge(h, real_a, real_b)[0] is True


# -- stateful setup and a second round ----------------------------------------

def test_setup_requests_run_before_the_experiment_and_are_not_judged():
    """A two-request differential can only interrogate a stateless endpoint. The flaws
    that cost money — workflow bypass, a price recalculated after approval, a coupon
    reused — only exist partway through a sequence."""
    _FakeLLM.reply = json.dumps([{
        "title": "Coupon reusable after order is placed", "severity": "high",
        "comparator": "a_denied_b_allowed",
        "setup": [{"url": "http://127.0.0.1:5000/cart/add", "method": "POST"},
                  {"url": "http://127.0.0.1:5000/coupon?c=X", "method": "POST"}],
        "control": {"url": "http://127.0.0.1:5000/coupon?c=X", "method": "POST"},
        "variant": {"url": "http://127.0.0.1:5000/coupon?c=X&force=1", "method": "POST"}}])
    cage = _Cage({"http://127.0.0.1:5000/cart/add": (200, "ok"),
                  "http://127.0.0.1:5000/coupon?c=X": (403, ""),
                  "http://127.0.0.1:5000/coupon?c=X&force=1": (200, "applied")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 1
    # Setup ran before the judged pair. Asserted RELATIVE to the experiment rather than
    # at index 0: establishing the second principal issues its own requests first, and
    # pinning an absolute index would make this test fail for a reason it does not care
    # about.
    first_setup = next(i for i, u in enumerate(cage.seen) if u.endswith("/cart/add"))
    first_judged = next(i for i, u in enumerate(cage.seen) if "/coupon" in u)
    assert first_setup < first_judged
    assert "after 2 setup request(s)" in sess.findings.all()[0].source


def test_state_changing_setup_needs_the_same_authorisation_as_any_other_write():
    """Setup creating state is the point, but it is still a write, and it is governed by
    the same flag as every other proof that writes."""
    _FakeLLM.reply = json.dumps([{
        "title": "x", "severity": "high", "comparator": "a_denied_b_allowed",
        "setup": [{"url": "http://127.0.0.1:5000/cart/add", "method": "POST"}],
        "control": {"url": "http://127.0.0.1:5000/a", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/b", "method": "GET"}}])
    cage = _Cage({"http://127.0.0.1:5000/cart/add": (200, "ok"),
                  "http://127.0.0.1:5000/a": (403, ""),
                  "http://127.0.0.1:5000/b": (200, "y")})
    sess = _session(cage, intrusive=False)
    assert sess.run_hypotheses() == 0
    assert cage.seen == []


def test_an_irreversible_setup_step_is_refused_even_when_writes_are_authorised():
    """Creation can be authorised; destruction cannot, because nothing here can undo
    it. Setup is also the easiest place to smuggle harm past a comparator that never
    sees it."""
    _FakeLLM.reply = json.dumps([{
        "title": "x", "severity": "high", "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/createdb", "method": "GET"}],
        "control": {"url": "http://127.0.0.1:5000/a", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/b", "method": "GET"}}])
    cage = _Cage({"http://127.0.0.1:5000/a": (200, "x"),
                  "http://127.0.0.1:5000/b": (500, "y")})
    sess = _session(cage, intrusive=True)          # authorised, and still refused
    assert sess.run_hypotheses() == 0
    assert not any("createdb" in u for u in cage.seen)


def test_a_destructive_setup_step_aborts_the_whole_experiment():
    """Setup is the easiest place to smuggle harm past a comparator that never sees it."""
    _FakeLLM.reply = json.dumps([{
        "title": "x", "severity": "high", "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/createdb", "method": "GET"}],
        "control": {"url": "http://127.0.0.1:5000/a", "method": "GET"},
        "variant": {"url": "http://127.0.0.1:5000/b", "method": "GET"}}])
    cage = _Cage({"http://127.0.0.1:5000/a": (200, "x"),
                  "http://127.0.0.1:5000/b": (500, "y")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0
    assert not any("createdb" in u for u in cage.seen)


def test_a_failed_round_feeds_its_observations_into_a_second_attempt():
    """Without the outcomes a refinement is just another guess. The point of a second
    round is that it has seen what the first one actually got back."""
    first = json.dumps([{"title": "A", "severity": "high",
                         "comparator": "a_denied_b_allowed",
                         "control": {"url": "http://127.0.0.1:5000/a", "method": "GET"},
                         "variant": {"url": "http://127.0.0.1:5000/b", "method": "GET"}}])
    second = json.dumps([{"title": "B refined", "severity": "high",
                          "comparator": "status_differs",
                          "control": {"url": "http://127.0.0.1:5000/c", "method": "GET"},
                          "variant": {"url": "http://127.0.0.1:5000/d", "method": "GET"}}])
    replies = iter([first, second])

    class _TwoShot:
        def propose(self, system, user, max_tokens=1024):
            _TwoShot.last_user = user
            return next(replies)

    sess = _session(_Cage({"http://127.0.0.1:5000/a": (200, "x"),
                           "http://127.0.0.1:5000/b": (200, "x"),
                           "http://127.0.0.1:5000/c": (404, ""),
                           "http://127.0.0.1:5000/d": (200, "found")}))
    sess.strategist = type("S", (), {"_llm": _TwoShot()})()
    assert sess.run_hypotheses() == 1
    assert "NOT CONFIRMED" in _TwoShot.last_user      # the refinement saw the failure
    # The published finding is the SECOND round's, pinned by the url it actually hit
    # rather than by the model's title — titles are now derived from the evidence class,
    # so a model-authored string is no longer the thing to assert on. Same subject,
    # tighter: /d could only have been reached by the refined proposal.
    published = sess.findings.all()[0]
    assert published.target.endswith("/d")
    assert "[evidence: status_differs]" in published.evidence


def test_refinement_is_skipped_when_nothing_was_observed():
    """Every experiment erroring before reaching the target means a second round would
    repeat the same misdirected guesses at the cost of another model call."""
    calls = []

    class _Counting:
        def propose(self, system, user, max_tokens=1024):
            calls.append(1)
            return json.dumps([{"title": "x", "severity": "high",
                                "comparator": "status_differs",
                                "control": {"url": "http://10.0.0.99/a", "method": "GET"},
                                "variant": {"url": "http://10.0.0.99/b", "method": "GET"}}])

    sess = _session(_Cage({}))                # out of scope -> gate refuses, no outcome
    sess.strategist = type("S", (), {"_llm": _Counting()})()
    sess.run_hypotheses()
    assert len(calls) == 1                    # asked once, did not ask again


def test_rounds_are_bounded():
    """An unbounded refine loop is an agent with a budget hole in it."""
    calls = []

    class _Never:
        def propose(self, system, user, max_tokens=1024):
            calls.append(1)
            return json.dumps([{"title": f"t{len(calls)}", "severity": "low",
                                "comparator": "a_denied_b_allowed",
                                "control": {"url": "http://127.0.0.1:5000/a",
                                            "method": "GET"},
                                "variant": {"url": "http://127.0.0.1:5000/b",
                                            "method": "GET"}}])

    sess = _session(_Cage({"http://127.0.0.1:5000/a": (200, "x"),
                           "http://127.0.0.1:5000/b": (200, "x")}))
    sess.strategist = type("S", (), {"_llm": _Never()})()
    assert sess.run_hypotheses() == 0
    assert len(calls) <= 2


def test_the_refine_prompt_restates_the_schema():
    """A refined round that answered with "name" and "type" instead of "title" and
    "comparator" was discarded in full, so the second round contributed nothing and the
    first round's observations were wasted. "Same format as before" was not enough."""
    text = hyp.refine_prompt()
    for key in ("title", "severity", "comparator", "control", "variant", "as"):
        assert key in text, f"the refine prompt never names {key!r}"
    assert "a_denied_b_allowed" in text, "the comparator set is not restated"


# --- denial is not only 401/403 -------------------------------------------------------
class _R:
    def __init__(self, status, body="", headers=None):
        self.status, self.body, self.headers = status, body, headers or {}


def _judge(comparator, a, b):
    h = hyp.Hypothesis("t", "high", comparator,
                       {"url": "http://t/x", "method": "GET"},
                       {"url": "http://t/x", "method": "GET"})
    return hyp.judge(h, a, b)[0]


def test_a_redirect_to_login_counts_as_a_refusal():
    """The live miss. The model proposed exactly the right experiment against
    /app/admin/usersapi — anonymous versus a non-admin account — and it executed
    perfectly: the stranger got 302 to /login, the account got 200 with 9,978 bytes of
    the user table. The comparator said no, because 302 is not 401."""
    anon = _R(302, "", {"Location": "/login"})
    member = _R(200, "x" * 9978)
    assert _judge("a_denied_b_allowed", anon, member) is True


def test_a_redirect_somewhere_else_is_not_a_refusal():
    """A 302 to /dashboard after a successful action is not a denial. Treating every
    redirect as one would confirm a flaw on any endpoint that redirects at all."""
    ok = _R(302, "", {"Location": "/dashboard"})
    assert _judge("a_denied_b_allowed", ok, _R(200, "y" * 500)) is False


def test_401_and_403_still_count():
    for status in (401, 403):
        assert _judge("a_denied_b_allowed", _R(status), _R(200, "z" * 100)) is True


def test_an_empty_200_does_not_count_as_allowed():
    assert _judge("a_denied_b_allowed", _R(403), _R(200, "")) is False
