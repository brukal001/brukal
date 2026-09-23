"""
test_reproducibility.py — keep the reproducible signal, drop the noise.

The oracle answers one deterministic question — does the controlled input reproducibly
change the answer? — so a result no comparator confirmed can be kept as an INFO lead
instead of discarded. It must be strict in both directions: a real input-dependent effect
is KEPT, and anything flaky, missing, or input-independent is REFUSED (fail closed).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import reproducibility as rep


class _R:
    def __init__(self, status=None, body=""):
        self.status = status
        self.body = body


# --------------------------------------------------------------------------- #
# stable() — a baseline is only a baseline if it repeats
# --------------------------------------------------------------------------- #

def test_identical_reads_are_stable():
    assert rep.stable([_R(200, "same"), _R(200, "same"), _R(200, "same")]) is True


def test_whitespace_only_differences_are_still_stable():
    assert rep.stable([_R(200, "a  b"), _R(200, "a b")]) is True


def test_a_single_read_cannot_be_shown_stable():
    assert rep.stable([_R(200, "x")]) is False


def test_a_drifting_endpoint_is_not_stable():
    assert rep.stable([_R(200, "t=1"), _R(200, "t=2")]) is False


def test_a_missing_read_breaks_stability():
    assert rep.stable([_R(200, "x"), None]) is False


# --------------------------------------------------------------------------- #
# input_dependent() — a stable baseline the varied input reproducibly moves
# --------------------------------------------------------------------------- #

def test_a_stable_baseline_and_a_differing_varied_run_is_input_dependent():
    base = [_R(200, "balance=10"), _R(200, "balance=10")]
    varied = [_R(200, "balance=999")]
    assert rep.input_dependent(base, varied) is True


def test_an_unstable_baseline_is_never_input_dependent():
    base = [_R(200, "t=1"), _R(200, "t=2")]     # noisy endpoint
    varied = [_R(200, "anything")]
    assert rep.input_dependent(base, varied) is False


def test_a_varied_run_equal_to_the_baseline_is_not_an_effect():
    base = [_R(200, "same"), _R(200, "same")]
    varied = [_R(200, "same")]
    assert rep.input_dependent(base, varied) is False


def test_a_missing_varied_run_fails_closed():
    base = [_R(200, "x"), _R(200, "x")]
    assert rep.input_dependent(base, [None]) is False
    assert rep.input_dependent(base, []) is False


def test_a_status_only_difference_counts():
    base = [_R(200, "body"), _R(200, "body")]
    varied = [_R(500, "body")]
    assert rep.input_dependent(base, varied) is True


def test_every_varied_run_must_differ_from_the_baseline():
    base = [_R(200, "b"), _R(200, "b")]
    # one varied run differs, one matches the baseline -> not a clean effect
    assert rep.input_dependent(base, [_R(200, "changed"), _R(200, "b")]) is False


# --------------------------------------------------------------------------- #
# reproducible_lead() — kept at INFO, with reconstructable evidence
# --------------------------------------------------------------------------- #

def test_a_reproducible_effect_is_kept_with_a_reason():
    base = [_R(200, "balance=10"), _R(200, "balance=10")]
    varied = [_R(200, "balance=999")]
    keep, reason = rep.reproducible_lead(base, varied)
    assert keep is True
    assert "reproducible input-dependent effect" in reason
    assert "200" in reason


def test_noise_is_not_kept_and_carries_no_reason():
    base = [_R(200, "t=1"), _R(200, "t=2")]
    keep, reason = rep.reproducible_lead(base, [_R(200, "x")])
    assert keep is False
    assert reason == ""


def test_a_lead_is_bounded_info_never_higher():
    assert rep.LEAD_SEVERITY == "info"
