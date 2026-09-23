"""
reproducibility.py — keep the reproducible signal a comparator could not name.

An experiment no comparator confirms is discarded as noise. Some of it is not noise: the
model aimed at something real that no named comparator fits, and deleting it loses a lead
and, worse, lets a repeat-suppressor lock the endpoint out of a later round (the 2026-08-17
lockout). This is the deterministic gate that separates a reproducible EFFECT from
flakiness, so such a result can be KEPT as an INFO lead for a human instead of thrown away.

It confirms nothing about impact. It answers only the metamorphic minimum — "does the
controlled input deterministically change the answer?" — and a lead it produces is INFO,
never a finding's severity, with the model nowhere in the decision. The discipline is the
identity oracle's: two identical reads make a stable baseline, and only a DIFFERENCE from
that stable baseline counts; anything unstable is noise and FAILS CLOSED to no lead.
"""
from __future__ import annotations


def _fingerprint(result):
    """(status, whitespace-normalised body) — the pair that decides 'the same answer'.

    None for a missing response, which fails every check below: an experiment that did not
    answer proves nothing, exactly as `judge` treats a missing side."""
    if result is None:
        return None
    from .hypothesis import _norm
    return (getattr(result, "status", None), _norm(getattr(result, "body", "")))


def stable(runs) -> bool:
    """True when every run answered and all answers are identical.

    Needs at least TWO runs — a single observation cannot be shown stable — and FAILS
    CLOSED on any missing response or any difference. An endpoint that drifts on its own
    (timestamps, nonces, counters) is not a stable baseline, and calling it one is how a
    self-moving endpoint becomes a phantom finding."""
    fps = [_fingerprint(r) for r in (runs or [])]
    if len(fps) < 2 or any(fp is None for fp in fps):
        return False
    return all(fp == fps[0] for fp in fps)


def input_dependent(baseline_runs, varied_runs) -> bool:
    """True when the baseline is STABLE and every varied run DIFFERS from it.

    The whole claim, and no more: changing the controlled input deterministically changes
    the answer. The baseline must be stable (>= 2 identical reads); each varied run must
    have answered and must differ from that stable baseline. Any instability, any missing
    response, or a varied run that matches the baseline yields False — an effect that does
    not repeat, or does not depend on the input, is not kept."""
    if not stable(baseline_runs):
        return False
    varied = [_fingerprint(r) for r in (varied_runs or [])]
    if not varied or any(fp is None for fp in varied):
        return False
    base = _fingerprint(baseline_runs[0])
    return all(fp != base for fp in varied)


# The bound a lead from here may carry — INFO, never more, and never an authorization
# claim. A reproducible input-dependent effect is a QUESTION for a human, not a
# demonstrated impact, so it must not borrow a comparator's severity.
LEAD_SEVERITY = "info"


def reproducible_lead(baseline_runs, varied_runs) -> tuple:
    """(keep, reason).

    `keep` is True only for a stable, input-dependent effect; `reason` is a short
    human-facing sentence when kept and '' otherwise. The reason is built from the
    fingerprints alone — statuses and normalised sizes — never from model text, so it is
    the same evidence a reader can reconstruct from the ledger."""
    if not input_dependent(baseline_runs, varied_runs):
        return False, ""
    base = _fingerprint(baseline_runs[0])
    var = _fingerprint(varied_runs[0])
    return True, (
        f"reproducible input-dependent effect, no comparator names it: baseline HTTP "
        f"{base[0]} ({len(base[1])} chars normalised), stable across "
        f"{len(baseline_runs)} reads; varied input -> HTTP {var[0]} ({len(var[1])} "
        f"chars). A lead for a human to interpret, not a demonstrated impact.")
