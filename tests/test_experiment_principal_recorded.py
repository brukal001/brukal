"""test_experiment_principal_recorded.py — a verdict must carry who issued each side.

A cross-account finding's entire claim is *which principal saw what*. Until now the
ledger could not answer it: `grep -rl '"as"' runs/` returned zero files across ~87 run
vaults. `_as_identity` swapped the browser's cookies and auth header around a request and
restored them afterwards, and nothing wrote down which of the three principals was in
force — not the audit entry, not the finding, not the note.

The consequence is the shape this project treats as its worst: **the artifacts of a sound
finding and of a manufactured one are byte-identical.** The single confirmed experiment
finding in the project's history (`vault-dvna18`, 2026-08-06) is checkable only because
the model happened to write its intent into the hypothesis prose. That is a narrative
accident, not a governance property, and it does not repeat.

`c829482` stopped a missing principal from silently becoming `anonymous`, so no FUTURE
finding can be manufactured that way — but a future cross-account finding that legitimately
runs would still be recorded with exactly as little provenance as dvna18's. This file
closes that.

Two constraints shape the fix and are pinned here:

  * **Identify, never credential.** The record names the principal and carries a stable
    handle derived from its session material — `redact.placeholder_for`'s sha256[:8], the
    same handle redaction itself emits — so two records can be correlated as the same
    principal while the value stays unrecoverable. Redaction exists to keep session
    material off exactly these surfaces; a provenance field must not be the hole in it.
  * **Requested AND resolved.** Recording only what the model asked for would leave a
    future silent degradation invisible again; recording only what was used would hide
    the ask. The pair is what makes a substitution auditable.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import redact

# A target that ECHOES the session back, as the body-capture tests do: the strongest
# available check that a new record surface did not become a leak.
_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJicnVrYWwtcHJpbmNpcGFsLXRlc3QifQ."
        "s1gnatureThatMustNeverAppearInAnyRecordSurface")
_COOKIE = "brukal-session-cookie-value-that-is-also-secret"

_A = "http://127.0.0.1:5000/api/Users/1"
_B = "http://127.0.0.1:5000/api/Users/2"


class _FakeLLM:
    reply = "[]"

    def propose(self, system, user, max_tokens=1024):
        return _FakeLLM.reply


class _EchoCage:
    """Answers with the caller's own credentials reflected in the body."""

    def __init__(self, mapping, browser_ref=None):
        self.mapping, self.seen = mapping, []
        self.browser_ref = browser_ref

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        status, body = self.mapping.get(action.url, (404, ""))
        b = self.browser_ref[0] if self.browser_ref else None
        if b is not None:
            body = (f"{body} echo auth={getattr(b, 'auth_header', '')} "
                    f"cookies={json.dumps(getattr(b, '_cookies', {}) or {})}")
        return WebResult(status=status, url=action.url, body=body)


def _session(cage, *, root=None):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = root or Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    browser = GovernedBrowser(scope, cage, audit)
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()), browser=browser)
    sess.blackboard = Blackboard(root / "vault", scope)
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    sess._audit_path = root / "a.jsonl"
    sess._root = root
    if getattr(cage, "browser_ref", None) is not None:
        cage.browser_ref[0] = browser
    return sess


def _principal_records(sess):
    """Every principal record the ledger holds, in order."""
    out = []
    for line in Path(sess._audit_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("kind") == "experiment_principal":
            out.append(rec["data"])
    return out


def _cross_account(control_as="self", variant_as="second", comparator="a_denied_b_allowed"):
    return json.dumps([{
        "title": "Cross-account read of another user's record",
        "severity": "high", "comparator": comparator,
        "control": {"url": _A, "method": "GET", "as": control_as},
        "variant": {"url": _B, "method": "GET", "as": variant_as}}])


def _with_second(sess):
    sess._second_identity = {"user": "brk2", "password": "x",
                             "cookies": {"session": "second-principal-session-value"},
                             "auth": "Bearer second-principal-token-value"}
    return sess


# -- 1 & 2. each side, requested AND resolved -------------------------------------

def test_a_confirmed_cross_account_finding_records_the_principal_of_each_side():
    """The central claim of such a finding is who saw what. The ledger must answer it
    without anyone reading the model's prose."""
    _FakeLLM.reply = _cross_account()
    cage = _EchoCage({_A: (401, ""), _B: (200, "another user's record, substantial")})
    sess = _with_second(_session(cage))
    assert sess.run_hypotheses() == 1, "precondition: the experiment confirmed"
    recs = _principal_records(sess)
    roles = {r["role"]: r for r in recs}
    assert "control" in roles and "variant" in roles, (
        f"the ledger does not say who issued each side: {recs}")
    assert roles["control"]["resolved"] == "self"
    assert roles["variant"]["resolved"] == "second"


def test_both_the_requested_and_the_resolved_principal_are_recorded():
    """Recording only one of the two would leave a future silent substitution invisible
    in the ledger and inferable only by reading the code of the day."""
    _FakeLLM.reply = _cross_account()
    cage = _EchoCage({_A: (401, ""), _B: (200, "data")})
    sess = _with_second(_session(cage))
    sess.run_hypotheses()
    for r in _principal_records(sess):
        assert "requested" in r and "resolved" in r, f"incomplete provenance: {r}"
    variant = next(r for r in _principal_records(sess) if r["role"] == "variant")
    assert variant["requested"] == "second" and variant["resolved"] == "second"


# -- 3. redaction holds on the new surface ------------------------------------------

def test_no_credential_reaches_any_surface_through_the_principal_record():
    """The handle is derived from session material, so this record is exactly the kind
    of thing redaction exists to police. Checked per surface, against a target that
    echoes the credentials straight back."""
    redact.clear()
    try:
        redact.register(_JWT, _COOKIE)
        _FakeLLM.reply = _cross_account()
        cage = _EchoCage({_A: (401, ""), _B: (200, "data")}, browser_ref=[None])
        sess = _session(cage)
        sess.browser.auth_header = f"Bearer {_JWT}"
        sess.browser._cookies = {"session": _COOKIE}
        _with_second(sess)
        sess.run_hypotheses()

        surfaces = {"audit": Path(sess._audit_path).read_text(encoding="utf-8")}
        for p in sorted(Path(sess._root / "vault").rglob("*")):
            if p.is_file():
                surfaces[str(p.relative_to(sess._root))] = p.read_text(
                    encoding="utf-8", errors="replace")
        assert len(surfaces) > 1, "precondition: records were actually written"
        for name, text in surfaces.items():
            assert _JWT not in text, f"session token in cleartext on {name}"
            assert _COOKIE not in text, f"session cookie in cleartext on {name}"
            assert "eyJhbGciOi" not in text, f"a JWT-shaped string on {name}"
    finally:
        redact.clear()


# -- 4. a stable, unrecoverable handle -----------------------------------------------

def test_the_principal_handle_is_stable_across_records_and_not_reversible():
    """Two records must be correlatable as the same principal. That is the whole point
    of a handle: `self` in one record and `self` in another are the same session, and an
    operator can say so without the value being recoverable from either."""
    redact.clear()
    try:
        redact.register(_JWT, _COOKIE)
        _FakeLLM.reply = json.dumps([{
            "title": "two self-issued requests", "severity": "medium",
            "comparator": "status_differs",
            "control": {"url": _A, "method": "GET", "as": "self"},
            "variant": {"url": _B, "method": "GET", "as": "self"}}])
        cage = _EchoCage({_A: (200, "a"), _B: (404, "")}, browser_ref=[None])
        sess = _session(cage)
        sess.browser.auth_header = f"Bearer {_JWT}"
        sess.browser._cookies = {"session": _COOKIE}
        sess.run_hypotheses()
        handles = {r["session"] for r in _principal_records(sess)
                   if r["resolved"] == "self"}
        assert len(handles) == 1, f"the same principal got different handles: {handles}"
        h = handles.pop()
        assert _JWT not in h and _COOKIE not in h, "the handle carries the credential"
        assert h.startswith("[REDACTED:"), (
            f"the handle should be redaction's own stable form so it correlates with "
            f"every other surface: {h!r}")
    finally:
        redact.clear()


# -- 5. anonymous is explicit, never absent -------------------------------------------

def test_anonymous_is_recorded_explicitly_rather_than_as_an_absent_field():
    """Absence is exactly what made five past runs permanently unresolvable. A field
    that is missing cannot be distinguished from a field nobody wrote."""
    _FakeLLM.reply = _cross_account(control_as="anonymous", variant_as="self",
                                    comparator="status_differs")
    cage = _EchoCage({_A: (401, ""), _B: (200, "data")})
    sess = _session(cage)
    sess.run_hypotheses()
    control = next(r for r in _principal_records(sess) if r["role"] == "control")
    assert control["resolved"] == "anonymous", f"not explicit: {control}"
    assert "session" in control, "the field must be present even with no session"
    assert control["session"] in ("", None) or control["session"] == "anonymous", (
        f"an anonymous caller has no session handle to give: {control}")


# -- 6. boundary: nothing else changes -------------------------------------------------

def test_a_self_only_experiment_still_runs_and_judges_exactly_as_before():
    _FakeLLM.reply = json.dumps([{
        "title": "self only", "severity": "medium", "comparator": "status_differs",
        "control": {"url": _A, "method": "GET"},
        "variant": {"url": _B, "method": "GET"}}])
    cage = _EchoCage({_A: (200, "a"), _B: (404, "")})
    sess = _session(cage)
    assert sess.run_hypotheses() == 1
    assert _A in cage.seen and _B in cage.seen
    assert all(r["resolved"] == "self" for r in _principal_records(sess))


def test_an_experiment_that_cannot_run_records_no_principal_for_the_missing_side():
    """The fail-safe from c829482 still wins: an unavailable principal errors before the
    browser is touched, so there is no dispatch to attribute."""
    _FakeLLM.reply = _cross_account()
    cage = _EchoCage({_A: (401, ""), _B: (200, "data")})
    sess = _session(cage)                      # no second identity
    assert sess.run_hypotheses() == 0
    assert not any(r["resolved"] == "second" for r in _principal_records(sess))
    assert "SECOND PRINCIPAL UNAVAILABLE" in "\n".join(sess.notes)


# -- 7. the dispatch-point guard: this is what stops a fourth site ----------------------

def test_every_experiment_request_dispatched_carries_a_principal_record():
    """Modelled on test_recon_no_resolve's dispatch-point guard, and there for the same
    reason: an assertion at each known call site protects those sites, while an assertion
    at the point requests reach the cage protects the ones nobody has written yet.

    Setup, control and variant are three separate dispatch sites today. A fourth would
    slip past a per-site test and be caught here."""
    _FakeLLM.reply = json.dumps([{
        "title": "setup, control and variant all dispatch", "severity": "high",
        "comparator": "status_differs",
        "setup": [{"url": "http://127.0.0.1:5000/api/Baskets", "method": "POST",
                   "as": "self"}],
        "control": {"url": _A, "method": "GET", "as": "self"},
        "variant": {"url": _B, "method": "GET", "as": "second"}}])
    cage = _EchoCage({"http://127.0.0.1:5000/api/Baskets": (201, '{"id": 1}'),
                      _A: (200, "a"), _B: (404, "")})
    sess = _with_second(_session(cage))
    sess.run_hypotheses()
    dispatched = len(cage.seen)
    recorded = len(_principal_records(sess))
    assert dispatched > 0, "precondition: something was dispatched"
    assert recorded == dispatched, (
        f"{dispatched} experiment request(s) reached the cage but only {recorded} "
        f"carry a principal record — a dispatch site is unattributed")
    assert {r["role"] for r in _principal_records(sess)} == {"setup", "control", "variant"}


# -- the finding surface itself, not only the audit ------------------------------------

def test_the_confirmed_finding_carries_the_principals_in_its_own_evidence():
    """The audit answers the question for anyone holding the ledger. The FINDING has to
    answer it for everyone else — `report.md`, `report.json` and the SARIF export are
    generated from the finding, and a reviewer reading a cross-account claim there
    should not have to go and correlate an audit file to learn who issued which side.

    Deterministic, harness-written text, and redacted by `Finding.__post_init__` like
    every other field on that record."""
    _FakeLLM.reply = _cross_account()
    cage = _EchoCage({_A: (401, ""), _B: (200, "another user's record, substantial")})
    sess = _with_second(_session(cage))
    assert sess.run_hypotheses() == 1
    f = next(f for f in sess.findings.all() if "Cross-account" in f.title)
    assert "issued as" in f.evidence, (
        f"the finding does not say who issued each side: {f.evidence!r}")
    assert "control issued as self" in f.evidence
    assert "variant issued as second" in f.evidence
