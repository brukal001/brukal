"""
test_recall_attribution_names_the_mechanism.py — GAP #16.

THE MEASURED PROBLEM (found while interpreting CR1 run 18, 2026-09-19)
    `crapi_recall.py` assigned a miss MODEL-LIMIT whenever no experiment was attempted
    and no DENY string happened to match the challenge's signature:

        elif _any(denied):  HARNESS-LIMIT
        else:               MODEL-LIMIT

    So HARNESS-LIMIT and MODEL-LIMIT BOTH meant "no experiment was attempted", separated
    only by incidental bookkeeping about blocked shell commands. Run 17 -> 18 kept totals
    of 6/4/3 while two challenges moved each way purely on which curl the gate happened
    to refuse.

    Worse, MODEL-LIMIT was read as "the model had its chance and failed". It was assigned
    on runs where the model had been asked for experiments exactly ONCE in 70 steps
    (GAP #18). The metric blamed the model for silence the pipeline caused.

THE PROPERTY
    An attribution NAMES THE MECHANISM that stopped the attempt, or it does not claim
    one. No bucket may say "the model" unless the model was actually asked.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.crapi_recall import measure

VEHICLE = "http://t/identity/api/v2/vehicle/resend_email"     # challenge 1
COUPON = "http://t/community/api/v2/coupon/validate-coupon"   # challenge 13


def _ledger(tmp_path, rows):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


def _rounds(n, source="model"):
    return [{"kind": "experiment_round", "data": {"source": source, "proposals": 6}}
            for _ in range(n)]


def _of(m, cid):
    return [r for r in m["results"] if r["id"] == cid][0]


def test_a_surface_NEVER_REACHED_is_not_blamed_on_the_model(tmp_path):
    """Nothing touched it, nothing was denied on it, nothing was proposed. That is a
    statement about where the run went, not about the model's imagination."""
    m = measure(_ledger(tmp_path, _rounds(5)))
    assert _of(m, 1)["attribution"] == "NEVER-REACHED"


def test_a_surface_REACHED_but_never_proposed_against_says_exactly_that(tmp_path):
    """The run's own requests went there and no experiment was ever aimed at it. That is
    a different fact from never having gone there, and the old metric merged them."""
    rows = _rounds(5) + [{"kind": "web_decision",
                          "data": {"verdict": "ALLOW", "action": f"get {VEHICLE}"}}]
    m = measure(_ledger(tmp_path, rows))
    assert _of(m, 1)["attribution"] == "REACHED-NOT-PROPOSED"


def test_a_proposal_we_DISCARDED_is_ours_not_the_models(tmp_path):
    """The model DID ask about this surface and validation threw it away (GAP #17/#18).
    Filing that as the model's limit inverts the responsibility completely."""
    rows = _rounds(5) + [{
        "kind": "experiment_proposal_dropped",
        "data": {"round": "propose", "count": 1,
                 "by_comparator": {"state_changed": 1},
                 "drops": [{"reason": "cap_truncated", "comparator": "state_changed",
                            "title": "coupon twice", "urls": [COUPON]}]}}]
    m = measure(_ledger(tmp_path, rows))
    assert _of(m, 13)["attribution"] == "PROPOSED-THEN-DISCARDED"


def test_NO_MISS_IS_ATTRIBUTED_TO_THE_MODEL_WHEN_IT_WAS_BARELY_ASKED(tmp_path):
    """THE CORE OF GAP #16. Run 18 asked the model once in 70 steps and the metric
    scored four challenges MODEL-LIMIT. With too few rounds, every not-proposed verdict
    is confounded and the measurement must SAY SO instead of naming a culprit."""
    rows = _rounds(1) + [{"kind": "web_decision",
                          "data": {"verdict": "ALLOW", "action": f"get {VEHICLE}"}}]
    m = measure(_ledger(tmp_path, rows))
    assert m["model_rounds"] == 1
    assert m["attribution_confounded"] is True
    assert _of(m, 1)["attribution"] == "INCONCLUSIVE-UNDER-ASKED"
    assert "MODEL" not in str(m["misses"]), (
        "a run that asked the model once may not blame the model for anything")


def test_with_enough_rounds_the_verdict_is_allowed_to_stand(tmp_path):
    """BOUNDARY: the guard must not make attribution impossible forever, or it replaces
    one unreadable metric with another."""
    rows = _rounds(6) + [{"kind": "web_decision",
                          "data": {"verdict": "ALLOW", "action": f"get {VEHICLE}"}}]
    m = measure(_ledger(tmp_path, rows))
    assert m["attribution_confounded"] is False
    assert _of(m, 1)["attribution"] == "REACHED-NOT-PROPOSED"


def test_derived_rounds_are_NOT_model_rounds(tmp_path):
    """The drain makes no model call by design. Counting it as the model having been
    asked is precisely how run 18 looked like a fair test of the model."""
    rows = _rounds(6, source="derived") + [
        {"kind": "web_decision", "data": {"verdict": "ALLOW", "action": f"get {VEHICLE}"}}]
    m = measure(_ledger(tmp_path, rows))
    assert m["model_rounds"] == 0
    assert m["attribution_confounded"] is True
