"""
test_outcome_attribution.py — CR1's definition of done, made measurable.

THE PROBLEM
    CR1 (crAPI) is done only when EVERY experiment outcome is attributable to a named
    cause — TARGET-REFUSED / HARNESS-LIMIT / MODEL-LIMIT — with none unaccounted, and
    when each MISS against crAPI's 18 documented challenges carries one of those three.
    Nothing in the record carried that field, so the definition of done was unmeasurable:
    a reader could see `not_confirmed` and `errored` in the ledger and had to guess which
    of them meant "the application held" and which meant "we could not ask".

    The CR1 pre-flight showed what that costs. Ten TLS failures we caused were written
    into the ledger as the target's silence, and only a container's own access log
    disproved it.

THE RULE
    Attribution is DERIVED from the terminal state, deterministically, in one table. No
    model, no post-hoc judgement, no per-run interpretation — the same terminal always
    attributes the same way, so two runs are comparable and a reader can recompute every
    number from `audit.jsonl` alone.

WHY THERE IS A FOURTH VALUE
    `MEASURED`. A judged negative is EVIDENCE — the comparator read both answers and the
    claim did not hold. Forcing it into one of the three miss-causes would label the
    project's most valuable output a failure of something, which is precisely the
    confusion this field exists to remove. The three causes explain outcomes that
    produced NO measurement; MEASURED marks the ones that did.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp
from brukal.hypothesis import (_DISPATCHED_NOT_RESOLVED, _JUDGED,
                               _REFUSED_BEFORE_DISPATCH, attribution, funnel)

ALL_TERMINALS = tuple(_REFUSED_BEFORE_DISPATCH) + tuple(_DISPATCHED_NOT_RESOLVED) + tuple(_JUDGED)


def test_the_recorded_terminals_are_all_attributed_and_this_test_notices_a_new_one():
    """A terminal added without an attribution is the failure mode this guards — and it
    has already caught TWO: `refused_by_operator` was added on 2026-09-18 when destructive
    experiments started escalating to the operator instead of being silently skipped, and
    `both_sides_absent` on 2026-09-19 when a 404/404 comparison stopped being filed as a
    measurement. Each failed this count until the attribution table was updated — which
    is the whole point: a terminal must not enter the vocabulary without someone deciding,
    in writing, whose limit it represents."""
    assert len(ALL_TERMINALS) == 12, ALL_TERMINALS


@pytest.mark.parametrize("outcome", ALL_TERMINALS)
def test_every_terminal_maps_to_exactly_one_attribution(outcome):
    got = attribution(outcome)
    assert got in hyp.ATTRIBUTIONS, (outcome, got)


@pytest.mark.parametrize("outcome,want", [
    # The target answered, and what it answered is why there is no measurement.
    ("setup_failed", "TARGET-REFUSED"),
    ("both_sides_failed", "TARGET-REFUSED"),
    # Ours: the request never went out, or went out and we could not use it.
    ("errored", "HARNESS-LIMIT"),
    ("no_answer", "HARNESS-LIMIT"),
    ("not_authenticated", "HARNESS-LIMIT"),
    ("second_unavailable", "HARNESS-LIMIT"),
    # A human declined a destructive experiment: ours, and the target never saw it.
    ("refused_by_operator", "HARNESS-LIMIT"),
    # The proposal itself was the limit.
    ("skipped", "MODEL-LIMIT"),
    ("unresolved_reference", "MODEL-LIMIT"),
    # A measurement happened. Neither a miss nor a limit.
    ("not_confirmed", "MEASURED"),
    ("confirmed", "MEASURED"),
])
def test_the_table_is_the_one_in_the_docstring(outcome, want):
    assert attribution(outcome) == want


def test_an_unknown_terminal_is_OURS_never_the_targets():
    """Fail-closed in the direction Fix 1 established: a terminal we cannot explain is a
    harness limit. Blaming the target for something we cannot account for is the exact
    defect the CR1 pre-flight found."""
    assert attribution("something_new") == "HARNESS-LIMIT"
    assert attribution("") == "HARNESS-LIMIT"
    assert attribution(None) == "HARNESS-LIMIT"


# --------------------------------------------------------------------------- #
# From the ledger alone
# --------------------------------------------------------------------------- #

def _rows(*outcomes, proposed=None, comparator="cross_account_resource"):
    n = len(outcomes) if proposed is None else proposed
    rows = [{"kind": "experiment_proposed",
             "data": {"title": f"h{i}", "comparator": comparator}} for i in range(n)]
    rows += [{"kind": "experiment_outcome",
              "data": {"title": f"h{i}", "comparator": comparator, "outcome": o,
                       "stage": hyp.outcome_stage(o), "attribution": attribution(o)}}
             for i, o in enumerate(outcomes)]
    return rows


def test_the_funnel_reports_attribution_counts_from_the_ledger_alone():
    f = funnel(_rows("confirmed", "not_confirmed", "setup_failed", "errored", "skipped"))
    assert f["attribution"] == {"MEASURED": 2, "TARGET-REFUSED": 1,
                                "HARNESS-LIMIT": 1, "MODEL-LIMIT": 1}


def test_the_attribution_counts_ALWAYS_SUM_TO_PROPOSED():
    """`unaccounted` becomes impossible by construction: a proposal with no outcome at
    all is attributed too, to HARNESS-LIMIT, because a run that died mid-experiment is
    our gap and not the target's refusal."""
    f = funnel(_rows("confirmed", "errored", proposed=5))
    assert f["proposed"] == 5
    assert sum(f["attribution"].values()) == 5
    assert f["attribution"]["HARNESS-LIMIT"] == 4      # 1 errored + 3 with no outcome
    assert f["unaccounted"] == 3, "the funnel's own gap count must still show the 3"


def test_attribution_is_reported_for_the_cross_account_line_too():
    f = funnel(_rows("confirmed", "setup_failed"))
    assert f["cross_account"]["attribution"] == {"MEASURED": 1, "TARGET-REFUSED": 1}


def test_a_ledger_with_no_experiments_reports_an_empty_attribution():
    f = funnel([])
    assert f["attribution"] == {}
    assert sum(f["attribution"].values()) == f["proposed"] == 0


# --------------------------------------------------------------------------- #
# The record itself
# --------------------------------------------------------------------------- #

def test_the_outcome_record_CARRIES_the_attribution(tmp_path):
    """Derived once, at the point of record, so every reader sees the same value and
    nobody recomputes it from prose."""
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import ExecResult

    scope = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope_fast.json")
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession("10.10.10.5", ex, StrategistAgent(llm))
    h = type("H", (), {"title": "t", "comparator": "cross_account_resource"})()
    s._record_experiment_outcome(h, "errored")
    row = [json.loads(l) for l in open(audit.path)
           if json.loads(l)["kind"] == "experiment_outcome"][0]
    assert row["data"]["attribution"] == "HARNESS-LIMIT"
    assert row["data"]["stage"] == "refused"
