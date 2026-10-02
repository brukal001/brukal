"""
test_confirmation_integrity.py — the CONFIRMATION invariant (Task 6).

WHY THIS EXISTS. `brukal/capture_confirm.py` is the decision layer that turns captured
traffic into a confirmed Finding (see its module docstring: "a confirmed finding must
survive on string comparison and set membership alone ... so a hostile or merely noisy
target cannot talk a judge into recording something unproven"). That is a claim about
EVIDENCE INTEGRITY, distinct from `tests/test_a_captured_model_cannot_move_the_gate.py`
(GAP #31), which proves a model that has been fully prompt-injection-CAPTURED still
cannot move the GATE (scope/execution) or get its own self-reported claim recorded as
confirmed. This file does not repeat that experiment. It targets the narrower, adjacent
question that file never asks: given a transcript that has the SHAPE of a confirmation —
a boolean-SQLi differential, a solved-lab banner, a reflected marker — does the prover
correctly require genuine positive-control evidence, or can fake/stale/mismatched/
replayed evidence slip through and flip a CANDIDATE to CONFIRMED anyway?

THE REAL API UNDER TEST
    `brukal/capture_confirm.py`:
      - `is_solved_banner(body)`                — exact PortSwigger-style marker match.
      - `boolean_sqli_differential(caps)`        — the positive-control law: group by
        endpoint, require a BENIGN baseline (200, non-empty, no truthy/falsy marker in
        its OWN query) before a truthy/falsy pair is read as diagnostic at all.
      - `reflected_executed(caps)`               — unescaped-markup-neighbor check.
      - `findings_from_capture(caps, scope)`     — the Task 9 entry point; all three
        provers, deduped per run for the banner.
    `brukal/capture.py`: `CapturedRequest` — the ONLY shape these provers ever see.
    `brukal/assist_confirm.py`: `_ConfirmMixin._confirm_from_capture` /
    `_record_confirmed` — the function that actually turns a capture-prover dict into a
    real `Finding(confirmed=True)` registered in a `FindingStore`. A handful of tests
    below go all the way through this mixin (not just the capture_confirm.py dicts) so
    "cannot flip CANDIDATE -> CONFIRMED" is asserted at the Finding object itself, not
    only at the dict the prover would hand it.

METHOD. Every test builds a transcript of hand-constructed `CapturedRequest` objects —
exactly the shape `GovernedBrowser.captured()` would hand `findings_from_capture`, never
an LLM, never a stub of the prover. A case that CLAIMS success but lacks valid evidence
must NOT confirm (empty list / no Finding). The positive-control cases prove the provers
are not simply refusing everything. An unsupported CONFIRM is adjudicated as a genuine
finding (xfail strict) and capture_confirm.py is left unmodified.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import capture_confirm as cc
from brukal.assist_confirm import _ConfirmMixin
from brukal.capture import CapturedRequest
from brukal.findings import FindingStore

BASE = "http://victim.test/item"


def cap(url: str, status: int | None = 200, response: str = "", method: str = "GET"
        ) -> CapturedRequest:
    return CapturedRequest(method=method, url=url, status=status, response=response)


class _FakeBrowser:
    """Stands in for `GovernedBrowser`: `.captured()` returns whatever list of
    `CapturedRequest` this test built, exactly the interface `_confirm_from_capture`
    actually calls (`web.py:774`)."""

    def __init__(self, caps):
        self._caps = list(caps)

    def captured(self):
        return self._caps


class _FakeSession(_ConfirmMixin):
    """The minimal real-mixin host. `_ConfirmMixin` is the REAL class `AssistSession`
    mixes in (`assist_confirm.py:30`) — this is not a stub of the confirmation logic,
    only of the unrelated session state (`executor`, `target`, ...) that
    `_record_confirmed`/`_record_confirmed_experiment` already `getattr(..., None)`
    around when absent."""

    def __init__(self, caps):
        self.scope = None
        self.browser = _FakeBrowser(caps)
        self.findings = FindingStore()
        self.highlights = []
        self.notes = []


def _confirm_verdict(findings: list[dict]) -> str:
    return "CONFIRM" if findings else "NO_CONFIRM"


# --------------------------------------------------------------------------------- #
# POSITIVE CONTROLS — the provers must not be simply refusing everything.
# --------------------------------------------------------------------------------- #

def test_positive_control_boolean_differential_confirms(record):
    """A genuine data-retrieval differential WITH its working baseline: truthy body ==
    baseline, falsy body diverges, same param throughout. This is the shape
    `boolean_sqli_differential` exists to prove."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    out = cc.boolean_sqli_differential([baseline, truthy, falsy])
    actual = _confirm_verdict(out)
    record("sec6::positive-control-boolean", "confirmation-integrity", "I3",
           "baseline+truthy+falsy, same param, real differential", "CONFIRM", actual,
           "n/a")
    assert actual == "CONFIRM"
    assert out[0]["param"] == "id"


def test_positive_control_record_confirmed_produces_real_finding(record):
    """Same transcript, through the REAL `_ConfirmMixin._confirm_from_capture` ->
    `_record_confirmed`: a genuine positive control must flip a real `Finding` to
    `confirmed=True`, not just satisfy a capture_confirm.py dict."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    s = _FakeSession([baseline, truthy, falsy])
    n = s._confirm_from_capture()
    confirmed = s.findings.confirmed()
    actual = "CONFIRM" if (n == 1 and confirmed and confirmed[0].confirmed) else "NO_CONFIRM"
    record("sec6::positive-control-e2e-finding", "confirmation-integrity", "I3",
           "real differential through _confirm_from_capture -> FindingStore",
           "CONFIRM", actual, "n/a")
    assert actual == "CONFIRM"
    assert confirmed[0].title == "SQL injection (boolean)"


def test_positive_control_banner_confirms(record):
    body = "Congratulations, you solved the lab!"
    actual = "CONFIRM" if cc.is_solved_banner(body) else "NO_CONFIRM"
    record("sec6::positive-control-banner", "confirmation-integrity", "I3",
           "exact PortSwigger-style solved marker", "CONFIRM", actual, "n/a")
    assert actual == "CONFIRM"


def test_positive_control_reflected_unescaped_confirms(record):
    marker = "zqx9471"
    raw = cap(f"{BASE}?q={marker}", response=f"<p>Your search: <b>{marker}</b></p>")
    out = cc.reflected_executed([raw])
    actual = _confirm_verdict(out)
    record("sec6::positive-control-reflected", "confirmation-integrity", "I3",
           "marker reflected as live, unescaped markup", "CONFIRM", actual, "n/a")
    assert actual == "CONFIRM"


# --------------------------------------------------------------------------------- #
# (a) MISSING POSITIVE CONTROL — must NOT confirm.
# --------------------------------------------------------------------------------- #

def test_no_baseline_control_does_not_confirm(record):
    """A truthy/falsy pair with no benign baseline request anywhere in the capture:
    the module's own law ("No control, no finding — full stop") must hold."""
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    out = cc.boolean_sqli_differential([truthy, falsy])
    actual = _confirm_verdict(out)
    record("sec6::no-control-missing-baseline", "confirmation-integrity", "I3",
           "truthy+falsy only, no baseline request in the capture",
           "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM"


def test_no_baseline_control_e2e_produces_no_finding(record):
    """Same missing-control transcript through the real mixin: no Finding at all must
    be registered — not an unconfirmed candidate, not a confirmed one."""
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    s = _FakeSession([truthy, falsy])
    n = s._confirm_from_capture()
    actual = "NO_CONFIRM" if (n == 0 and len(s.findings.all()) == 0) else "CONFIRM"
    record("sec6::no-control-e2e", "confirmation-integrity", "I3",
           "missing baseline through _confirm_from_capture -> FindingStore",
           "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM"


def test_control_present_but_non_matching_does_not_confirm(record):
    """A baseline DOES exist, but the truthy response does not match it — e.g. ordinary
    request variance, not a data-retrieval differential. Presence of *a* baseline is not
    the same as the baseline PROVING the truthy/falsy pair."""
    baseline = cap(f"{BASE}?id=9", response="Item 9: Gizmo, price 99")
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    out = cc.boolean_sqli_differential([baseline, truthy, falsy])
    actual = _confirm_verdict(out)
    record("sec6::control-present-not-matching", "confirmation-integrity", "I3",
           "baseline exists but truthy body != baseline body", "NO_CONFIRM", actual,
           "high")
    assert actual == "NO_CONFIRM"


# --------------------------------------------------------------------------------- #
# (c) TARGET/PARAM MISMATCH — endpoint-level must NOT confirm (same param, see
# the genuine finding below for the param-level case that DOES).
# --------------------------------------------------------------------------------- #

def test_mismatched_endpoint_does_not_confirm(record):
    """The baseline is for /item; the truthy/falsy probes were made against an entirely
    different endpoint, /search. Evidence from one target must not confirm a claim
    about another — `_endpoint()` grouping must keep them apart."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    other = "http://victim.test/search"
    truthy = cap(f"{other}?q=5' OR '1'='1", response="results for 5")
    falsy = cap(f"{other}?q=5' AND '1'='2", response="no results")
    out = cc.boolean_sqli_differential([baseline, truthy, falsy])
    actual = _confirm_verdict(out)
    record("sec6::mismatched-endpoint", "confirmation-integrity", "I3",
           "baseline for /item, truthy+falsy for an unrelated /search",
           "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM"


# --------------------------------------------------------------------------------- #
# (e) SELF-DECLARED "CONFIRMED" STRINGS — a target that just says so must NOT confirm.
# --------------------------------------------------------------------------------- #

def test_self_declared_confirmed_string_does_not_confirm(record):
    """The response body baldly claims the exploit worked ('SQL injection CONFIRMED',
    'VULNERABLE: true'). No comparator looked at that text and decided anything; none
    of the three provers may key off it."""
    body = "SQL injection CONFIRMED by attacker. VULNERABLE: true"
    declared = cap(f"{BASE}?note=hello", response=body)
    sqli = cc.boolean_sqli_differential([declared])
    banner = cc.is_solved_banner(declared.response)
    reflected = cc.reflected_executed([declared])
    all_findings = cc.findings_from_capture([declared], None)
    actual = ("CONFIRM" if (sqli or banner or reflected or all_findings) else "NO_CONFIRM")
    record("sec6::self-declared-confirmed-string", "confirmation-integrity", "I3",
           "response body self-declares 'SQL injection CONFIRMED ... VULNERABLE: true', "
           "no real marker and no differential", "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM"


def test_escaped_reflection_self_declared_xss_does_not_confirm(record):
    """A target that HTML-escapes the marker but decorates the page with a bald
    'XSS CONFIRMED' claim must not register a reflected-XSS finding — the claim text is
    not itself a marker, and the real marker came back escaped, not executed."""
    marker = "zqx9471"
    body = f"<!-- XSS CONFIRMED --><p>Your search: &lt;b&gt;{marker}&lt;/b&gt;</p>"
    declared = cap(f"{BASE}?q={marker}", response=body)
    out = cc.reflected_executed([declared])
    actual = _confirm_verdict(out)
    record("sec6::self-declared-xss-escaped", "confirmation-integrity", "I3",
           "page text claims 'XSS CONFIRMED' but the real marker is HTML-escaped",
           "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM"


def test_stale_banner_near_miss_phrase_does_not_confirm(record):
    """A phrase that is CLOSE to the solved-lab banner but is not it ('you tried the
    lab', not 'you solved the lab') must not be read as a win."""
    body = "Congratulations, you tried the lab!"
    actual = "CONFIRM" if cc.is_solved_banner(body) else "NO_CONFIRM"
    record("sec6::banner-near-miss", "confirmation-integrity", "I3",
           "near-miss banner phrase ('tried', not 'solved')", "NO_CONFIRM", actual,
           "medium")
    assert actual == "NO_CONFIRM"


# --------------------------------------------------------------------------------- #
# (d) REPLAYED EVIDENCE — duplicating valid evidence must not inflate confirmations.
# --------------------------------------------------------------------------------- #

def test_duplicated_replayed_evidence_does_not_inflate_confirmation_count(record):
    """The exact same baseline/truthy/falsy triple appears twice in one capture list
    (a replayed/duplicated transcript). The endpoint still produces exactly ONE
    confirmed finding, not two — replay must not multiply a proof into many."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    out = cc.boolean_sqli_differential([baseline, truthy, falsy] * 2)
    actual = str(len(out))
    record("sec6::replayed-evidence-no-inflation", "confirmation-integrity", "I3",
           "identical baseline/truthy/falsy triple duplicated in the capture list",
           "1", actual, "medium")
    assert actual == "1"


def test_cross_round_cumulative_evidence_confirms_once_not_per_round(record):
    """`browser.captured()` is documented (assist_confirm.py:276-287) as CUMULATIVE and
    never cleared across rounds, and `_confirm_from_capture`'s OWN per-signature memory
    (`_capture_confirmed_sigs`) is the stated guard against re-recording the same proof
    every round. This is the expected, documented behaviour — not ambiguous and not a
    finding — so the assertion here is that it holds: calling `_confirm_from_capture`
    twice on a growing, cumulative capture list confirms the SAME signature only once."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    truthy = cap(f"{BASE}?id=5' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?id=5' AND '1'='2", response="No results found")
    s = _FakeSession([baseline, truthy, falsy])
    n1 = s._confirm_from_capture()           # round 1: fresh confirm
    n2 = s._confirm_from_capture()           # round 2: same cumulative list, re-offered
    actual = f"{n1}+{n2}={len(s.findings.all())}"
    record("sec6::cumulative-round-dedup", "confirmation-integrity", "I3",
           "same capture list offered again on round 2 (cumulative, never cleared)",
           "1+0=1", actual, "n/a")
    assert n1 == 1
    assert n2 == 0
    assert len(s.findings.all()) == 1


# --------------------------------------------------------------------------------- #
# GENUINE FINDING — truthy and falsy are never checked to be the SAME parameter (or
# even remotely related), so unrelated evidence from the SAME endpoint can be
# combined into a fabricated SQLi confirmation.
# --------------------------------------------------------------------------------- #

_SEC007 = (
    "FINDING SEC-007: boolean_sqli_differential() (brukal/capture_confirm.py:87-151) picks "
    "the FIRST truthy-marked capture and the FIRST falsy-marked capture anywhere in an "
    "endpoint's group via next(...), with no check that they probed the SAME query "
    "parameter (or anything else about the two requests being related). A benign param the "
    "app ignores (truthy-marked) combined with an UNRELATED param that legitimately changes "
    "the response for ordinary reasons (pagination, a tracking value that happens to contain "
    "a falsy substring like 'utm_campaign=promo and 1=2 blast') reproduces the exact "
    "'truthy==baseline, falsy!=baseline' shape and is recorded as a CONFIRMED, high-severity "
    "'SQL injection (boolean)' finding naming the UNRELATED param — with no SQL injection "
    "anywhere. This is precisely the false-positive class the module's own docstring (lines "
    "20-27) says the positive-control law exists to rule out ('an endpoint that 500s on "
    "garbage input looks identical whether or not SQL is being concatenated'); the control "
    "it actually enforces (a clean baseline) does not cover parameter correlation. See "
    "SECURITY_AUDIT.md.")


@pytest.mark.xfail(strict=True, reason=_SEC007)
@pytest.mark.parametrize("falsy_url,falsy_body,vector", [
    (f"{BASE}?page=x' AND '1'='2", "Item 6: Gadget, price 20", "unrelated-param"),
    (f"{BASE}?utm_campaign=promo and 1=2 blast", "Item 6: Gadget, price 20",
     "incidental-substring"),
], ids=["unrelated-param", "incidental-substring"])
def test_mismatched_param_within_same_endpoint_fabricates_confirm(
        record, falsy_url, falsy_body, vector):
    """Truthy probes `comment` (which the app ignores); falsy is an entirely unrelated
    param whose value coincidentally contains a falsy marker and whose divergence is
    fully explained by ordinary, non-SQLi behaviour. Same endpoint, same baseline —
    different, uncorrelated parameters."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    truthy = cap(f"{BASE}?comment=x' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(falsy_url, response=falsy_body)
    out = cc.boolean_sqli_differential([baseline, truthy, falsy])
    actual = _confirm_verdict(out)
    record(f"sec6::mismatched-param-fabricates-confirm-{vector}", "confirmation-integrity",
           "I3", f"truthy on 'comment' (ignored), falsy on unrelated param ({vector}), "
           "same endpoint/baseline", "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM", (
        f"unsupported CONFIRM fabricated from uncorrelated truthy/falsy evidence: {out}")


@pytest.mark.xfail(strict=True, reason=_SEC007)
def test_mismatched_param_fabricates_confirmed_finding_e2e(record):
    """The same gap, through the REAL `_confirm_from_capture` -> `_record_confirmed`
    path, all the way to a real `Finding(confirmed=True)` in a `FindingStore` — the
    CANDIDATE-to-CONFIRMED flip this whole module exists to gate, flipped on evidence
    that never actually correlated the two sides of the differential."""
    baseline = cap(f"{BASE}?id=5", response="Item 5: Widget, price 10")
    truthy = cap(f"{BASE}?comment=x' OR '1'='1", response="Item 5: Widget, price 10")
    falsy = cap(f"{BASE}?page=x' AND '1'='2", response="Item 6: Gadget, price 20")
    s = _FakeSession([baseline, truthy, falsy])
    n = s._confirm_from_capture()
    confirmed = s.findings.confirmed()
    actual = "CONFIRM" if (n == 1 and confirmed and confirmed[0].confirmed) else "NO_CONFIRM"
    record("sec6::mismatched-param-fabricates-confirm-e2e", "confirmation-integrity", "I3",
           "uncorrelated truthy/falsy through _confirm_from_capture -> FindingStore",
           "NO_CONFIRM", actual, "high")
    assert actual == "NO_CONFIRM", (
        f"unsupported CONFIRMED Finding fabricated: "
        f"{[(f.title, f.param, f.target) for f in confirmed]}")
