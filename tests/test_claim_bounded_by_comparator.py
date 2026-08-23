"""test_claim_bounded_by_comparator.py — a finding may not claim more than it proved.

On the 2026-08-22 pre-flight, `bodies_differ` confirmed twice and both findings were
published as HIGH cross-account reads:

    "Basket IDOR - any authenticated user can read another user's basket by ID"
    "User PII IDOR - any authenticated user can read another user's profile via /api/Users/{id}"

**Both verdicts were sound. Both titles were not.** Every request on both sides was
issued by ONE principal — the ledger shows `self` six times over, one handle
`[REDACTED:5759af35]` — so what was actually observed is that two different ids return
two different bodies. Nothing established that either object belonged to another user;
the tenant-to-object mapping existed only in the operator's head and appears in no
artifact. `a_denied_b_allowed`, the comparator built for authorization, was never used,
because no second principal existed.

So the model chose the weaker comparator (correctly — it was the only one available) and
then wrote the stronger claim anyway, and `title` and `severity` went onto the record
verbatim with nothing in between. That is the defect: **the verdict is derived and the
claim is not.**

This is the third false-result class in a week, and the pattern is worth naming: it is
not that the harness lies, it is that a true measurement gets published under a sentence
nobody verified. A reader holding only the artifacts cannot tell the difference.

The fix is a bound, not a filter. A real cross-account finding — `a_denied_b_allowed`
with two genuinely distinct recorded principals — must still publish the authorization
claim in full, or the control has traded one kind of blindness for another.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import redact

_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjbGFpbS1ib3VuZC10ZXN0In0."
        "s1gnatureThatMustNeverReachARecordSurfaceEver")

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
        if b is not None:                      # echo the caller's credentials back
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


def _second(sess):
    sess._second_identity = {"user": "brk2", "password": "x",
                             "cookies": {"session": "second-principal-session"},
                             "auth": "Bearer second-principal-token"}
    return sess


def _finding(sess):
    return next(f for f in sess.findings.all() if f.confirmed and f.category == "logic")


# -- 1 & 2. the two live cases, verbatim ---------------------------------------------

def test_bodies_differ_from_one_principal_cannot_claim_a_cross_account_read():
    """The live case. One principal, two basket ids, different bodies — a true
    observation that says nothing about ownership."""
    _FakeLLM.reply = json.dumps([{
        "title": "Basket IDOR - any authenticated user can read another user's basket by ID",
        "severity": "high", "comparator": "bodies_differ",
        "control": {"url": _B1, "method": "GET", "as": "self"},
        "variant": {"url": _B2, "method": "GET", "as": "self"}}])
    cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)})
    sess = _session(cage)
    assert sess.run_hypotheses() == 1, "precondition: it still confirms"
    f = _finding(sess)
    published = f"{f.title} {f.evidence}"
    lo = published.lower()
    assert "another user" not in lo, (
        f"the published claim still asserts cross-account access: {f.title!r}")
    assert "idor" not in f.title.lower(), (
        f"IDOR is an authorization claim this comparator did not earn: {f.title!r}")
    assert "different bodies" in lo or "differ" in lo, (
        f"the derived claim should say what WAS observed: {published!r}")


def test_bodies_differ_cannot_claim_pii_disclosure_to_arbitrary_users():
    """The second live case, same shape."""
    _FakeLLM.reply = json.dumps([{
        "title": "User PII IDOR - any authenticated user can read another user's profile via /api/Users/{id}",
        "severity": "high", "comparator": "bodies_differ",
        "control": {"url": _U1, "method": "GET", "as": "self"},
        "variant": {"url": _U2, "method": "GET", "as": "self"}}])
    cage = _Cage({_U1: (200, "a" * 301), _U2: (200, "b" * 297)})
    sess = _session(cage)
    assert sess.run_hypotheses() == 1
    f = _finding(sess)
    lo = f"{f.title} {f.evidence}".lower()
    assert "another user" not in lo
    assert "arbitrary account data" not in lo


# -- 3. THE BOUNDARY: a real cross-account finding must survive intact ----------------

def test_a_denied_b_allowed_with_two_distinct_principals_keeps_the_authorization_claim():
    """The control must bound overreach without flattening the real thing. Two recorded
    principals, the authorization comparator, a genuine refusal-then-acceptance: this is
    exactly the finding the whole second-principal effort exists to produce, and it must
    publish its claim in full."""
    _FakeLLM.reply = json.dumps([{
        "title": "Cross-account basket read", "severity": "high",
        "comparator": "a_denied_b_allowed",
        "control": {"url": _B1, "method": "GET", "as": "anonymous"},
        "variant": {"url": _B1, "method": "GET", "as": "second"}}])
    cage = _Cage({_B1: (401, "")})
    sess = _second(_session(cage))
    # the variant must be allowed and substantive; the control refused
    cage.mapping = {_B1: (401, "")}

    class _TwoState(_Cage):
        def run(self, action):
            from brukal.web import WebResult
            self.seen.append(action.url)
            anon = not (getattr(self.browser, "auth_header", "") or "")
            if anon:
                return WebResult(status=401, url=action.url, body="")
            return WebResult(status=200, url=action.url, body="z" * 900)

    cage2 = _TwoState({}, None)
    cage2.browser = sess.browser
    sess.browser._cage = cage2
    assert sess.run_hypotheses() == 1, "a real cross-account finding was flattened"
    f = _finding(sess)
    lo = f"{f.title} {f.evidence}".lower()
    assert "refused" in lo and "accepted" in lo, f"the authorization claim was lost: {lo}"
    assert "authorization" in lo or "authorisation" in lo or "principal" in lo


# -- 4. the model's prose survives, labelled -------------------------------------------

def test_the_models_prose_is_kept_but_labelled_as_interpretation():
    """Throwing the rationale away would lose the most useful sentence in the record —
    what the model thought it was testing. Keeping it unlabelled is what caused this.
    It stays, marked as the agent's unverified reading."""
    _FakeLLM.reply = json.dumps([{
        "title": "Basket IDOR - reads another user's basket", "severity": "high",
        "comparator": "bodies_differ",
        "control": {"url": _B1, "method": "GET", "as": "self"},
        "variant": {"url": _B2, "method": "GET", "as": "self"},
        "rationale": "If both ids return 200 with distinct contents it proves no ownership check"}])
    cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)})
    sess = _session(cage)
    sess.run_hypotheses()
    f = _finding(sess)
    assert "no ownership check" in f.evidence, "the model's reading was discarded"
    assert "UNVERIFIED" in f.evidence or "unverified" in f.evidence, (
        f"the model's prose is not marked as interpretation: {f.evidence!r}")


# -- 5. severity derives from the evidence class ----------------------------------------

def test_severity_comes_from_the_evidence_class_not_from_model_text():
    """The model asked for `critical` on a comparator that establishes only that two
    responses differ. Severity is a claim too."""
    _FakeLLM.reply = json.dumps([{
        "title": "differing bodies", "severity": "critical",
        "comparator": "bodies_differ",
        "control": {"url": _B1, "method": "GET", "as": "self"},
        "variant": {"url": _B2, "method": "GET", "as": "self"}}])
    cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)})
    sess = _session(cage)
    sess.run_hypotheses()
    f = _finding(sess)
    assert f.severity != "critical", (
        "the model's severity was published unchecked on a weak evidence class")
    assert f.severity in ("low", "medium", "info")


# -- 6. the claim names the principals compared ------------------------------------------

def test_the_derived_claim_names_which_principals_were_compared():
    """A reader holding only the artifacts must be able to tell self-vs-self from
    self-vs-second. That distinction is the whole difference between the two live
    findings and a real IDOR."""
    _FakeLLM.reply = json.dumps([{
        "title": "differing bodies", "severity": "high", "comparator": "bodies_differ",
        "control": {"url": _B1, "method": "GET", "as": "self"},
        "variant": {"url": _B2, "method": "GET", "as": "self"}}])
    cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)})
    sess = _session(cage)
    sess.run_hypotheses()
    f = _finding(sess)
    assert "same principal" in f.evidence.lower() or "self" in f.evidence, (
        f"the claim does not say who was compared: {f.evidence!r}")


# -- 7. redaction still holds on the new text ---------------------------------------------

def test_the_derived_claim_does_not_leak_the_session_credential():
    """New text on a record surface, so it is checked rather than assumed — against a
    target that echoes the token straight back."""
    redact.clear()
    try:
        redact.register(_JWT)
        _FakeLLM.reply = json.dumps([{
            "title": "differing bodies", "severity": "high", "comparator": "bodies_differ",
            "control": {"url": _B1, "method": "GET", "as": "self"},
            "variant": {"url": _B2, "method": "GET", "as": "self"}}])
        cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557)}, browser_ref=[None])
        sess = _session(cage)
        sess.browser.auth_header = f"Bearer {_JWT}"
        sess.run_hypotheses()
        surfaces = {"audit": Path(sess._audit_path).read_text(encoding="utf-8")}
        for p in sorted((sess._root / "vault").rglob("*")):
            if p.is_file():
                surfaces[str(p)] = p.read_text(encoding="utf-8", errors="replace")
        for name, text in surfaces.items():
            assert _JWT not in text, f"session token in cleartext on {name}"
            assert "eyJhbGciOi" not in text, f"a JWT-shaped string on {name}"
    finally:
        redact.clear()


# -- 8. dispatch-point guard ----------------------------------------------------------------

def test_every_published_experiment_finding_carries_a_derived_claim_and_evidence_class():
    """The guard that stops a fourth path. Whatever builds a finding on the experiment
    route, it must carry the comparator it rests on and a claim derived from it — so a
    new call site cannot reintroduce an unbounded title."""
    _FakeLLM.reply = json.dumps([
        {"title": "one", "severity": "high", "comparator": "bodies_differ",
         "control": {"url": _B1, "method": "GET", "as": "self"},
         "variant": {"url": _B2, "method": "GET", "as": "self"}},
        {"title": "two", "severity": "high", "comparator": "status_differs",
         "control": {"url": _U1, "method": "GET", "as": "self"},
         "variant": {"url": _U2, "method": "GET", "as": "self"}}])
    cage = _Cage({_B1: (200, "x" * 1310), _B2: (200, "y" * 557),
                  _U1: (200, "a" * 301), _U2: (404, "")})
    sess = _session(cage)
    sess.run_hypotheses()
    published = [f for f in sess.findings.all() if f.confirmed and f.category == "logic"]
    assert published, "precondition: something was published"
    for f in published:
        assert "[evidence:" in f.evidence, (
            f"no evidence class on a published experiment finding: {f.evidence!r}")
        assert any(c in f.evidence for c in
                   ("bodies_differ", "status_differs", "a_denied_b_allowed",
                    "b_reveals_more", "b_errors_a_does_not")), (
            f"the finding does not name the comparator it rests on: {f.evidence!r}")
