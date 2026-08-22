"""test_second_principal_fail_safe.py — a principal that does not exist is not anonymous.

`_as_identity` resolves the three names an experiment may issue as. For `second` it read
`self._second_identity` and, when registration never established one, found `{}`:

    elif who == "second":
        second = getattr(self, "_second_identity", None) or {}
        browser._cookies = dict(second.get("cookies") or {})   # -> {}
        browser.auth_header = second.get("auth", "")           # -> ""

Those are the exact bytes of the `anonymous` branch two lines above. So `as: second`
silently BECAME `as: anonymous`, the request was dispatched to the target, and the
comparator judged it — producing a record that reads as evidence about the application
and is really evidence about Brukal.

Both directions are wrong, and the second is worse:

  * control `self` / variant `second→anonymous` under `a_denied_b_allowed` — the
    authenticated side is allowed and the "second" side is refused, so the comparator
    says NOT CONFIRMED. A false negative wearing a clean verdict.
  * control `second→anonymous` / variant `self` — the anonymous side IS denied and the
    authenticated side IS 200 and substantive, so the comparator HOLDS and files a
    CONFIRMED finding whose meaning is "the control was refused and the variant was
    accepted". That sentence is true of every authenticated endpoint on the web. A
    false positive, in the project whose headline claim is that it structurally cannot
    produce them.

`establish_second_identity()` returns "" on an Angular SPA (`_signup_form()` needs a
server-rendered <form>), while `hypothesis.PROMPT` offers `"as": "second"`
unconditionally — so the model is invited to name a principal this target cannot supply,
and did on the 2026-08-20 run.

This file pins the FAIL-SAFE only, mirroring `UnresolvedReference`: the experiment
errors, is never dispatched, is never judged, and says so to the next round. It does NOT
make registration work on an SPA — the cross-account class remains untestable there, and
that is the honest structural limit, recorded as such.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import hypothesis as hyp


class _FakeLLM:
    reply = "[]"
    prompts: list = []          # every user turn the model was handed, in order

    def propose(self, system, user, max_tokens=1024):
        _FakeLLM.prompts.append(user)
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


_A = "http://127.0.0.1:5000/api/Users/1"
_B = "http://127.0.0.1:5000/api/Users/2"


def _cross_account(comparator="a_denied_b_allowed", control_as="self", variant_as="second"):
    return json.dumps([{
        "title": "Cross-account read of another user's record",
        "severity": "high", "comparator": comparator,
        "control": {"url": _A, "method": "GET", "as": control_as},
        "variant": {"url": _B, "method": "GET", "as": variant_as}}])


# -- 1 & 2. not dispatched, and not judged ---------------------------------------

def test_an_experiment_naming_second_with_no_second_principal_is_not_dispatched():
    """The degraded request must never reach the target. Once it is on the wire the
    application has answered something, and an answer is very hard not to score."""
    _FakeLLM.reply = _cross_account()
    cage = _Cage({_A: (200, "mine"), _B: (401, "")})
    sess = _session(cage)
    assert not getattr(sess, "_second_identity", None), "precondition: no second principal"
    sess.run_hypotheses()
    assert _B not in cage.seen, (
        f"the variant was dispatched as an unauthenticated stranger: {cage.seen}")


def test_an_unrunnable_cross_account_experiment_is_never_judged():
    """THE core property. A comparator verdict is a claim about the APPLICATION. When
    the principal it needs was never constructed, any verdict it reaches is a claim
    about Brukal wearing the application's clothes — which is precisely the failure
    class `UnresolvedReference` was built to end."""
    _FakeLLM.reply = _cross_account()
    cage = _Cage({_A: (200, "mine"), _B: (401, "")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0
    notes = "\n".join(sess.notes)
    assert "not confirmed" not in notes, (
        f"an unconstructible comparator produced a verdict: {notes!r}")
    assert "NOT CONFIRMED" not in notes


# -- 3. the comparator built for authorization ------------------------------------

def test_a_denied_b_allowed_errors_rather_than_comparing_self_to_anonymous():
    """`a_denied_b_allowed` is the comparator the whole second-principal mechanism
    exists for. With no second principal it was silently answering a different, trivial
    question: is a stranger refused where a logged-in user is not."""
    _FakeLLM.reply = _cross_account(comparator="a_denied_b_allowed")
    cage = _Cage({_A: (401, ""), _B: (200, "someone else's data")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0
    assert "SECOND PRINCIPAL UNAVAILABLE" in "\n".join(sess.notes)


def test_second_as_the_control_cannot_manufacture_a_confirmed_finding():
    """The false-POSITIVE direction, and the reason this is not merely a tidiness fix.

    control `second`→anonymous is denied, variant `self` is 200 and substantive, so
    `a_denied_b_allowed` HOLDS and files a confirmed high. Its meaning — 'the control
    was refused and the variant was accepted' — is true of every authenticated endpoint
    in existence. Precision is this project's headline claim; a fabricated confirmation
    costs more than a missed one."""
    _FakeLLM.reply = _cross_account(control_as="second", variant_as="self")
    cage = _Cage({_A: (401, ""), _B: (200, "a substantial body of real data")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0, "a confirmed finding was manufactured from a missing principal"
    assert not any("confirmed" in n.lower() and "not" not in n.lower()
                   for n in sess.notes), f"a finding was recorded: {sess.notes!r}"


# -- 4. the next round is told, in the established shape ---------------------------

def test_the_next_round_is_told_the_principal_was_unavailable():
    """Same shape as UNRESOLVED REFERENCE: the words 'NOT run' and 'not a result' do the
    work, because the next round reasons over these strings.

    Asserted against the prompt the refine round actually RECEIVES, not against the note
    surface. The note is for a human reading the transcript; the outcome string is the
    only thing that reaches the model, and 'the next round is told' is a claim about the
    latter."""
    _FakeLLM.reply = _cross_account()
    _FakeLLM.prompts = []
    cage = _Cage({_A: (200, "mine"), _B: (401, "")})
    sess = _session(cage)
    sess.run_hypotheses()
    refine = "\n".join(_FakeLLM.prompts[1:])     # everything after the first ask
    assert refine, "precondition: a refine round happened"
    assert "SECOND PRINCIPAL UNAVAILABLE" in refine, (
        f"the next round was not told: {refine[-400:]!r}")
    assert "NOT run" in refine
    assert "this is not a result" in refine
    assert "NOT CONFIRMED" not in refine, "it was fed back as a negative result"
    # and the human-facing surface says it too
    assert "SECOND PRINCIPAL UNAVAILABLE" in "\n".join(sess.notes)


# -- 5. the engagement survives it -------------------------------------------------

def test_one_unrunnable_experiment_does_not_end_the_run():
    """It is one proposal of several. The runnable ones must still run — an engagement
    that stops at the first unconstructible principal loses everything after it."""
    _FakeLLM.reply = json.dumps([
        {"title": "needs a second principal", "severity": "high",
         "comparator": "a_denied_b_allowed",
         "control": {"url": _A, "method": "GET", "as": "self"},
         "variant": {"url": _B, "method": "GET", "as": "second"}},
        {"title": "self versus a stranger — runnable", "severity": "high",
         "comparator": "status_differs",
         "control": {"url": _A, "method": "GET", "as": "self"},
         "variant": {"url": _A, "method": "GET", "as": "anonymous"}}])
    cage = _Cage({_A: (200, "mine"), _B: (401, "")})
    sess = _session(cage)
    sess.run_hypotheses()
    assert cage.seen.count(_A) >= 2, (
        f"the runnable experiment never ran: {cage.seen}")
    assert "SECOND PRINCIPAL UNAVAILABLE" in "\n".join(sess.notes)


# -- 6 & 7. boundaries: nothing else changes ---------------------------------------

def test_with_a_second_principal_established_the_experiment_runs_as_before():
    """The fail-safe must be invisible when the principal exists. Same dispatch, same
    judgement, same verdict."""
    _FakeLLM.reply = _cross_account()
    cage = _Cage({_A: (401, ""), _B: (200, "another user's record, substantial")})
    sess = _session(cage)
    sess._second_identity = {"user": "brk2", "password": "x",
                             "cookies": {"session": "second-cookie"}, "auth": ""}
    confirmed = sess.run_hypotheses()
    assert _B in cage.seen, "the variant was not dispatched as the second principal"
    assert confirmed == 1, "a real cross-account finding stopped being confirmed"
    assert "SECOND PRINCIPAL UNAVAILABLE" not in "\n".join(sess.notes)


def test_a_second_principal_request_carries_that_principals_session():
    """Not merely dispatched — dispatched AS the second account. A fail-safe that let
    the request through with the wrong cookies would restore the original defect."""
    seen_cookies = []

    class _Recording(_Cage):
        def run(self, action):
            seen_cookies.append(dict(getattr(self.browser, "_cookies", {}) or {}))
            return super().run(action)

    cage = _Recording({_A: (401, ""), _B: (200, "data")})
    _FakeLLM.reply = _cross_account()
    sess = _session(cage)
    cage.browser = sess.browser
    sess._second_identity = {"user": "brk2", "password": "x",
                             "cookies": {"session": "second-cookie"}, "auth": ""}
    sess.run_hypotheses()
    assert {"session": "second-cookie"} in seen_cookies, (
        f"the second principal's session never reached the wire: {seen_cookies}")


def test_self_only_experiments_are_untouched():
    _FakeLLM.reply = json.dumps([{
        "title": "self only", "severity": "medium", "comparator": "status_differs",
        "control": {"url": _A, "method": "GET"},
        "variant": {"url": _B, "method": "GET"}}])
    cage = _Cage({_A: (200, "a"), _B: (404, "")})
    sess = _session(cage)
    sess.run_hypotheses()
    assert _A in cage.seen and _B in cage.seen
    assert "SECOND PRINCIPAL UNAVAILABLE" not in "\n".join(sess.notes)


def test_anonymous_experiments_are_untouched():
    """`anonymous` needs nothing established, so it must keep working on exactly the
    targets where `second` cannot be built — it is the only cross-principal question
    still askable on an SPA."""
    _FakeLLM.reply = json.dumps([{
        "title": "stranger versus me", "severity": "high",
        "comparator": "a_denied_b_allowed",
        "control": {"url": _A, "method": "GET", "as": "anonymous"},
        "variant": {"url": _A, "method": "GET", "as": "self"}}])
    cage = _Cage({_A: (200, "substantial data for the logged-in user")})
    sess = _session(cage)
    sess.run_hypotheses()
    # >= 2, not == 2: nothing confirms here, so the runner buys a refine round and the
    # pair is issued again. The subject is that both sides were issued at all.
    assert cage.seen.count(_A) >= 2
    assert "SECOND PRINCIPAL UNAVAILABLE" not in "\n".join(sess.notes)


# -- the exception is a sibling of the one this mirrors -----------------------------

def test_the_error_is_a_named_exception_beside_unresolved_reference():
    """Named, in hypothesis.py, next to UnresolvedReference — so the runner can catch it
    ahead of the generic handler and no caller has to string-match a message."""
    assert issubclass(hyp.SecondPrincipalUnavailable, Exception)
    assert hyp.SecondPrincipalUnavailable is not hyp.UnresolvedReference


def test_a_setup_step_naming_second_is_also_caught():
    """`as` is legal on setup steps too, and setup runs through the same
    `_as_identity`. Covering only the judged pair would leave a degraded request going
    out during setup — unjudged, but on the wire and changing state as the wrong
    principal, which is worse than a bad verdict."""
    _FakeLLM.reply = json.dumps([{
        "title": "setup names a principal that does not exist", "severity": "high",
        "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/api/Baskets", "method": "POST",
                   "as": "second"}],
        "control": {"url": _A, "method": "GET"},
        "variant": {"url": _B, "method": "GET"}}])
    cage = _Cage({"http://127.0.0.1:5000/api/Baskets": (201, '{"id": 1}'),
                  _A: (200, "a"), _B: (404, "")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 0
    assert "http://127.0.0.1:5000/api/Baskets" not in cage.seen, (
        f"a setup request went out as the wrong principal: {cage.seen}")
    assert "SECOND PRINCIPAL UNAVAILABLE" in "\n".join(sess.notes)
