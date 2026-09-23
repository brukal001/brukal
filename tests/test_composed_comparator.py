"""
test_composed_comparator.py — the grammar wired in (2b) and bounded (2c).

`composed` lets the model build the predicate itself from the closed grammar; the code
still evaluates it and still owns the verdict. Two things must hold together:
  - 2b WIRING: a composed hypothesis is judged by evaluating its AST, and a missing or
    UNSAFE tree fails closed — at proposal time (parse refuses it) and at judge time.
  - 2c BOUND: a composed confirmation can never claim more than LOW, however severe the
    model called it. A predicate the model designed does not get to earn its own severity.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp

# `succeeded(a) AND status(b) >= 500` — `b_errors_a_does_not`, rebuilt as a tree.
HOLDS = {"op": "and", "args": [
    {"obs": "succeeded", "of": "a"},
    {"op": "ge", "args": [{"obs": "status", "of": "b"}, {"lit": 500}]}]}

UNSAFE = {"op": "__import__", "args": [{"lit": "os"}]}


class _R:
    def __init__(self, status=None, body=""):
        self.status = status
        self.body = body


def _h(predicate=HOLDS, comparator="composed", url="http://t:3000/x"):
    return hyp.Hypothesis(
        "composed: variant errors where control succeeds", "critical", comparator,
        {"method": "GET", "url": url}, {"method": "GET", "url": url},
        predicate=predicate)


# --------------------------------------------------------------------------- #
# 2b — the AST is evaluated, and every unsafe path fails closed
# --------------------------------------------------------------------------- #

def test_a_composed_predicate_that_holds_confirms():
    holds, meaning = hyp.judge(_h(), _R(200), _R(500))
    assert holds is True
    assert meaning


def test_a_composed_predicate_that_does_not_hold_is_not_confirmed():
    holds, _ = hyp.judge(_h(), _R(200), _R(200))
    assert holds is False


def test_a_missing_predicate_fails_closed():
    holds, _ = hyp.judge(_h(predicate=None), _R(200), _R(500))
    assert holds is False


def test_an_unsafe_predicate_fails_closed_at_judge_without_raising():
    # Even if an unsafe tree somehow reached a hypothesis, judge must not run it.
    holds, _ = hyp.judge(_h(predicate=UNSAFE), _R(200), _R(500))
    assert holds is False


def test_a_missing_response_never_confirms():
    holds, _ = hyp.judge(_h(), None, _R(500))
    assert holds is False


# --------------------------------------------------------------------------- #
# 2c — a composed confirmation is capped LOW and carries no authorization claim
# --------------------------------------------------------------------------- #

def test_composed_is_bounded_low_and_caps_the_models_severity():
    claim = hyp.derive_claim("composed", "self", "self",
                             {"url": "http://t/x", "status": 200, "size": 3},
                             {"url": "http://t/x", "status": 500, "size": 3})
    assert claim["severity_cap"] == "low"
    assert claim["authz"] is False
    # The model asked for critical; the class caps it at low.
    assert hyp.cap_severity("critical", claim["severity_cap"]) == "low"
    assert hyp.cap_severity("high", claim["severity_cap"]) == "low"
    assert hyp.cap_severity("info", claim["severity_cap"]) == "info"


# --------------------------------------------------------------------------- #
# proposal path — parse validates the AST and refuses an unsafe or absent one
# --------------------------------------------------------------------------- #

def _reply(predicate, severity="critical", same_sides=True):
    control = {"url": "http://t:3000/x", "method": "GET"}
    variant = dict(control) if same_sides else {"url": "http://t:3000/y", "method": "GET"}
    item = {"title": "composed probe", "severity": severity, "comparator": "composed",
            "control": control, "variant": variant}
    if predicate is not None:
        item["predicate"] = predicate
    return json.dumps([item])


def test_parse_accepts_a_composed_entry_and_attaches_its_validated_ast():
    out = hyp.parse(_reply(HOLDS))
    assert len(out) == 1
    h = out[0]
    assert h.comparator == "composed"
    assert h.predicate == HOLDS
    # And it survives round-trip to a real verdict.
    assert hyp.judge(h, _R(200), _R(500))[0] is True


def test_parse_refuses_a_composed_entry_with_an_unsafe_predicate():
    drops: list = []
    out = hyp.parse(_reply(UNSAFE), drops=drops)
    assert out == []
    assert any(d["reason"] == "unsafe_or_missing_predicate" for d in drops), drops


def test_parse_refuses_a_composed_entry_with_no_predicate():
    drops: list = []
    out = hyp.parse(_reply(None), drops=drops)
    assert out == []
    assert any(d["reason"] == "unsafe_or_missing_predicate" for d in drops), drops


def test_composed_is_exempt_from_the_identical_sides_drop():
    # A header/status check on ONE response is a valid composed shape; identical control
    # and variant must not be discarded the way a bare differential would be.
    out = hyp.parse(_reply(HOLDS, same_sides=True))
    assert len(out) == 1 and out[0].comparator == "composed"


# --------------------------------------------------------------------------- #
# drift guard — the new comparator is registered everywhere, bounds in lockstep
# --------------------------------------------------------------------------- #

def test_composed_is_registered_with_a_bound_and_as_a_context_comparator():
    assert "composed" in hyp._COMPARATORS
    assert "composed" in hyp._EVIDENCE_CLASS
    assert "composed" in hyp._CONTEXT_COMPARATORS
    assert set(hyp._COMPARATORS) == set(hyp._EVIDENCE_CLASS)


def test_composed_is_judged_but_not_yet_advertised_to_the_model():
    # The boundary between this milestone (evaluate + bound) and the next (teach the model
    # to emit trees): composed is a valid comparator but must not appear in the prompt
    # menu until the grammar is documented there, or the model proposes it blindly.
    assert "composed" not in hyp.comparator_names()
    assert "composed" not in hyp.experiment_prompt()
