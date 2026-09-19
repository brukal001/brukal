"""
test_crapi_recall.py — the recall measurement must not repeat the lie it measures.

CR1 reports "found N of 18". The FIRST version of `benchmarks/crapi_recall.py` asked "did
any confirmation happen in this run, and does this challenge's path appear in any
experiment URL" — and reported **6 of 14 on a run with exactly one confirmed experiment**,
because coverage of an endpoint was being rendered as a finding on it.

That is the failure this project has a law about, committed by the very tool built to
measure it, and it would have gone into a paper as a 6x overstatement. The grouping — each
confirmation tied to the URLs of ITS OWN experiment — is the correctness of the number,
and these tests are what hold it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.crapi_recall import CHALLENGES, group_experiments, measure

VEHICLE = "http://t/identity/api/v2/vehicle/resend_email"
VIDEOS = "http://t/identity/api/v2/user/videos"
DASH = "http://t/identity/api/v2/user/dashboard"


def _ledger(tmp_path, rows):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


def _exp(urls, outcome, title="t"):
    out = [{"kind": "experiment_result", "data": {"url": u}} for u in urls]
    out.append({"kind": "experiment_outcome",
                "data": {"title": title, "outcome": outcome,
                         "stage": "judged" if outcome in ("confirmed", "not_confirmed")
                         else "refused",
                         "attribution": "MEASURED"}})
    return out


def test_a_confirmation_counts_only_for_ITS_OWN_surface(tmp_path):
    """THE REGRESSION. One confirmed experiment on the vehicle endpoint, two unconfirmed
    ones elsewhere. Exactly one challenge may be FOUND."""
    rows = (_exp([VEHICLE, VEHICLE], "confirmed", "vehicle idor")
            + _exp([VIDEOS, VIDEOS], "not_confirmed", "videos")
            + _exp([DASH, DASH], "not_confirmed", "dashboard"))
    m = measure(_ledger(tmp_path, rows))
    assert m["found"] == 1, [r for r in m["results"] if r["state"] == "FOUND"]
    found = [r["id"] for r in m["results"] if r["state"] == "FOUND"]
    assert found == [1], found


def test_COVERAGE_IS_NOT_A_FINDING(tmp_path):
    """Requests that touched every endpoint, and no experiment anywhere. Recall is zero.

    UPDATED 2026-09-19 (GAP #16). This test used to assert `misses == {"MODEL-LIMIT"}`
    and its docstring said "every miss is the model's — it never proposed anything". That
    is the defect, written down as intent: the ledger here records NO model round at all,
    so "the model never proposed anything" and "the model was never asked" are the same
    evidence. The metric may not pick one. Its real property — coverage is not a finding —
    is unchanged and still asserted."""
    rows = [{"kind": "web_decision", "data": {"action": f"get {u}", "verdict": "ALLOW"}}
            for u in (VEHICLE, VIDEOS, DASH)]
    m = measure(_ledger(tmp_path, rows))
    assert m["found"] == 0
    assert set(m["misses"]) == {"INCONCLUSIVE-UNDER-ASKED"}
    assert m["covered_not_attempted"] >= 1


def test_COVERAGE_IS_NOT_A_FINDING_when_the_model_WAS_asked(tmp_path):
    """The same run with the model properly consulted. Recall is still zero and the
    misses now say what was observed — reached, never proposed against — without
    claiming to know why."""
    rows = [{"kind": "experiment_round", "data": {"source": "model", "proposals": 6}}
            for _ in range(4)]
    rows += [{"kind": "web_decision", "data": {"action": f"get {u}", "verdict": "ALLOW"}}
             for u in (VEHICLE, VIDEOS, DASH)]
    m = measure(_ledger(tmp_path, rows))
    assert m["found"] == 0
    assert m["attribution_confounded"] is False
    assert "REACHED-NOT-PROPOSED" in set(m["misses"])


def test_an_attempted_but_unconfirmed_challenge_is_a_MEASURED_miss(tmp_path):
    """Asked with a comparator and it did not hold. That is evidence about the target, and
    must not be filed as a limit of ours."""
    m = measure(_ledger(tmp_path, _exp([VIDEOS, VIDEOS], "not_confirmed")))
    videos = [r for r in m["results"] if r["id"] == 5][0]
    assert videos["state"] == "MISS"
    assert videos["attribution"] == "MEASURED-NOT-CONFIRMED"


def test_a_refused_experiment_attributes_to_the_HARNESS(tmp_path):
    """A gate or rate-limit denial on a challenge's surface is our limit, not a miss the
    target earned."""
    rows = [{"kind": "web_decision",
             "data": {"verdict": "DENY", "layer": "hard:web-rate",
                      "action": f"get {VEHICLE}"}}]
    m = measure(_ledger(tmp_path, rows))
    v = [r for r in m["results"] if r["id"] == 1][0]
    assert v["attribution"] == "HARNESS-LIMIT"


def test_unreachable_challenges_are_neither_found_nor_blamed_on_anyone(tmp_path):
    """The chatbot needs an LLM key this lab does not supply, and challenge 6 is excluded
    by the scope's own disclosed rate limit. Reporting them as misses would blame the
    model for not reaching something nothing could reach."""
    m = measure(_ledger(tmp_path, _exp([VEHICLE], "confirmed")))
    unreachable = {r["id"] for r in m["unreachable"]}
    assert unreachable == {6, 16, 17, 18}, unreachable
    assert m["denominator_measurable"] == 14
    assert all(r["attribution"] is None for r in m["unreachable"])
    assert all(r["unreachable"] for r in m["unreachable"])


def test_the_denominator_is_the_DOCUMENTED_eighteen(tmp_path):
    """The number that makes crAPI worth the port. It comes from OWASP/crAPI's own
    docs/challenges.md, not from what the run happened to try."""
    assert len(CHALLENGES) == 18
    assert {c[0] for c in CHALLENGES} == set(range(1, 19))


def test_the_grouping_attaches_urls_to_the_outcome_that_closes_them(tmp_path):
    groups = group_experiments(_exp([VEHICLE], "confirmed", "a") + _exp([VIDEOS], "not_confirmed", "b"))
    assert [g["title"] for g in groups] == ["a", "b"]
    assert groups[0]["urls"] == [VEHICLE] and groups[1]["urls"] == [VIDEOS]


def test_a_garbage_or_empty_ledger_measures_zero_without_crashing(tmp_path):
    p = tmp_path / "junk.jsonl"
    p.write_text("not json\n{\"kind\": \"nonsense\"}\n")
    m = measure(p)
    assert m["found"] == 0 and m["denominator_measurable"] == 14
