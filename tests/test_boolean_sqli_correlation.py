"""
test_boolean_sqli_correlation.py — SEC-007 regressions for
`capture_confirm.boolean_sqli_differential`.

SEC-007: the prover took the FIRST truthy-marked and the FIRST falsy-marked capture
anywhere on an endpoint, never checking they probed the SAME parameter, so an ignored
param (truthy) plus an unrelated param that legitimately changes the page (falsy) was
recorded as a CONFIRMED high-severity SQLi with no SQL injection anywhere.

Both directions are pinned, because Brukal must neither record a false finding NOR
lose a real one:
  * uncorrelated / unstable evidence never confirms;
  * genuine differentials still confirm — including two the first-match logic
    MISSED (a genuine pair hidden behind earlier unrelated captures, and a second
    injectable parameter on the same endpoint).
"""
from __future__ import annotations

from brukal import capture_confirm as cc
from brukal.capture import CapturedRequest as CR

E = "http://lab/filter"


def _c(q, body, status=200, method="GET"):
    return CR(method=method, url=f"{E}?{q}" if q else E, status=status, response=body)


ROWS = "Gift A, Gift B, Gift C"


# ---------------------------------------------------------------- must NOT confirm --

def test_truthy_and_falsy_on_different_params_do_not_confirm():
    caps = [_c("category=Gifts", ROWS),
            _c("comment=x' OR '1'='1&category=Gifts", ROWS),
            _c("page=x' AND '1'='2&category=Gifts", "page 2 rows")]
    assert cc.boolean_sqli_differential(caps) == []


def test_incidental_falsy_substring_in_tracking_value_does_not_confirm():
    caps = [_c("id=5", ROWS),
            _c("comment=x' OR '1'='1&id=5", ROWS),
            _c("utm_campaign=promo and 1=2 blast&id=5", "promo banner " + ROWS)]
    assert cc.boolean_sqli_differential(caps) == []


def test_pair_whose_other_params_differ_does_not_confirm():
    # Same injected param, but the falsy request ALSO changed `page` — the divergence
    # is explained by the page change, not the condition.
    caps = [_c("category=Gifts&page=1", ROWS),
            _c("category=Gifts' AND '1'='1&page=1", ROWS),
            _c("category=Gifts' AND '1'='2&page=2", "page 2 rows")]
    assert cc.boolean_sqli_differential(caps) == []


def test_pair_with_different_payload_bases_does_not_confirm():
    # Not the same probe with the condition flipped: different original values.
    caps = [_c("category=Gifts", ROWS),
            _c("category=Gifts' AND '1'='1", ROWS),
            _c("category=Pets' AND '1'='2", "Pet A")]
    assert cc.boolean_sqli_differential(caps) == []


def test_baseline_differing_in_another_param_is_not_a_control():
    caps = [_c("category=Gifts&sort=price", ROWS),
            _c("category=Gifts' AND '1'='1&sort=name", ROWS),
            _c("category=Gifts' AND '1'='2&sort=name", "")]
    assert cc.boolean_sqli_differential(caps) == []


def test_unstable_endpoint_is_not_diagnostic():
    # The SAME benign request returned two different bodies: the page varies on its
    # own, so "falsy differs from baseline" proves nothing.
    caps = [_c("category=Gifts", ROWS),
            _c("category=Gifts", "Gift A, Gift C, Gift B (shuffled)"),
            _c("category=Gifts' AND '1'='1", ROWS),
            _c("category=Gifts' AND '1'='2", "")]
    assert cc.boolean_sqli_differential(caps) == []


def test_method_mismatch_is_not_paired():
    caps = [_c("category=Gifts", ROWS),
            _c("category=Gifts' AND '1'='1", ROWS),
            _c("category=Gifts' AND '1'='2", "", method="POST")]
    assert cc.boolean_sqli_differential(caps) == []


# --------------------------------------------------------- must STILL confirm -------

def test_classic_same_param_differential_confirms_and_names_the_param():
    caps = [_c("category=Gifts", ROWS),
            _c("category=Gifts' AND '1'='1", ROWS),
            _c("category=Gifts' AND '1'='2", "")]
    out = cc.boolean_sqli_differential(caps)
    assert len(out) == 1
    assert out[0]["param"] == "category"
    assert out[0]["target"] == E
    assert "category" in out[0]["evidence"]


def test_or_truthy_and_falsy_with_same_base_confirms():
    caps = [_c("id=5", "Item 5"),
            _c("id=5' OR '1'='1", "Item 5"),
            _c("id=5' AND '1'='2", "No results")]
    assert len(cc.boolean_sqli_differential(caps)) == 1


def test_other_params_held_constant_still_confirms():
    caps = [_c("category=Gifts&page=1", ROWS),
            _c("category=Gifts' AND '1'='1&page=1", ROWS),
            _c("category=Gifts' AND '1'='2&page=1", "")]
    out = cc.boolean_sqli_differential(caps)
    assert [f["param"] for f in out] == ["category"]


def test_genuine_pair_behind_earlier_unrelated_captures_is_found():
    # CAPABILITY: the old first-match logic grabbed the unrelated `comment` truthy and
    # `page` falsy first and never looked at the genuine `category` pair behind them.
    caps = [_c("category=Gifts", ROWS),
            _c("comment=x' OR '1'='1&category=Gifts", "Gift Z"),
            _c("page=x' AND '1'='2&category=Gifts", ROWS),
            _c("category=Gifts' AND '1'='1", ROWS),
            _c("category=Gifts' AND '1'='2", "")]
    out = cc.boolean_sqli_differential(caps)
    assert [f["param"] for f in out] == ["category"]


def test_two_injectable_params_on_one_endpoint_both_confirm():
    # CAPABILITY: the old code emitted at most one finding per endpoint.
    caps = [_c("category=Gifts&sort=name", ROWS),
            _c("category=Gifts' AND '1'='1&sort=name", ROWS),
            _c("category=Gifts' AND '1'='2&sort=name", ""),
            _c("category=Gifts&sort=name' AND '1'='1", ROWS),
            _c("category=Gifts&sort=name' AND '1'='2", "error-free empty")]
    out = cc.boolean_sqli_differential(caps)
    assert sorted(f["param"] for f in out) == ["category", "sort"]


def test_numeric_and_1_equals_1_truthy_is_recognised():
    # CAPABILITY: ` and 1=2` was a falsy marker but its truthy twin ` and 1=1` was not,
    # so the most common numeric boolean pair never registered.
    caps = [_c("id=5", "Item 5"),
            _c("id=5 AND 1=1", "Item 5"),
            _c("id=5 AND 1=2", "No results")]
    out = cc.boolean_sqli_differential(caps)
    assert [f["param"] for f in out] == ["id"]


def test_repeated_identical_baselines_are_stable_and_still_confirm():
    caps = [_c("category=Gifts", ROWS), _c("category=Gifts", ROWS + "  "),
            _c("category=Gifts' AND '1'='1", ROWS),
            _c("category=Gifts' AND '1'='2", "")]
    assert len(cc.boolean_sqli_differential(caps)) == 1
