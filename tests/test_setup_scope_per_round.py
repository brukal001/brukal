"""
test_setup_scope_per_round.py — a refine round has no setups of its own until it writes them.

THE PROPERTY
    `{{setup.<i>.<path>}}` addresses the setup steps of **the proposal it appears in**.
    `setup_results` is rebuilt per proposal inside `_run_one_round`, so index 0 exists
    only if that same proposal carries a setup step. Nothing persists across rounds, and
    nothing should: an experiment whose evidence depends on state established by a
    DIFFERENT experiment is the external-seeding problem the capability milestone forbids.

THE DEFECT THIS PINS (measured in run CM1, 2026-09-10)
    ALL THREE of the second round's proposals referenced a setup they did not supply:

        {{setup.0.data.id}}:        no setup response at index 0   (x2)
        {{setup.0.data.BasketId}}:  no setup response at index 0

    The fail-safe behaved correctly — not dispatched, not judged, fed back as
    not-a-result — so the round cost a model call and produced nothing.

    The likely cause is a prompt contract gap rather than a model error, and it was
    introduced by the fix for the PREVIOUS defect. `SETUP_SHAPE_HEADER` shows the last
    round's setup responses so the model stops guessing at field names; phrased as "what
    your setup requests actually RETURNED … exactly the paths a {{setup.i.path}} reference
    may name", it reads as though those responses are still addressable.

THE CHOICE MADE HERE
    Two fixes were available: carry the prior setups forward so the references resolve, or
    scope the disclosure to the round it came from and say so. **The second.** Carrying
    them forward would let one experiment's control depend on another's setup, which is
    precisely what "no external seeding" excludes — the milestone asks that the ledger
    alone support a claim, and a value produced by an experiment that is not the one being
    judged is not in that experiment's record.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp


def test_the_refine_prompt_says_a_previous_round_s_setups_are_gone():
    """THE DEFECT. The disclosure invites a reference the resolver cannot honour, and the
    prompt never says the invitation expires with the round."""
    text = hyp.REFINE_PROMPT.lower()

    assert "setup" in text
    assert ("own setup" in text or "its own setup" in text or "your own setup" in text), (
        "the refine prompt never tells the model that a reference needs a setup step in "
        "THE SAME proposal — CM1 lost all three second-round experiments to this")


def test_the_shape_disclosure_is_marked_as_the_previous_round_s():
    """The header is shown in the refine round, so it has to name which round it is about.
    'What your setup requests actually RETURNED' reads as the present tense."""
    header = hyp.SETUP_SHAPE_HEADER.lower()

    assert "previous" in header or "last round" in header or "earlier round" in header, (
        f"the shape disclosure does not say which round it describes: {header!r}")
    assert "not" in header, (
        "the disclosure does not state that these responses are no longer addressable")


def test_both_rounds_carry_the_reference_syntax():
    """BOUNDARY. The contract that stopped the model guessing field names must survive
    this change in both directions — round one had it and must keep it."""
    assert hyp.SETUP_REF_SYNTAX in hyp.PROMPT
    assert hyp.SETUP_REF_SYNTAX in hyp.REFINE_PROMPT


def test_a_reference_without_its_own_setup_is_still_refused_not_guessed():
    """BOUNDARY, and the half that must never move: whatever the prompt says, a reference
    with no setup behind it aborts the experiment rather than being sent as text."""
    spec = {"method": "GET", "url": "http://t/api/Cards/{{setup.0.data.id}}"}

    try:
        hyp.resolve_setup_refs(spec, [])
    except hyp.UnresolvedReference as exc:
        assert "no setup response at index 0" in str(exc), str(exc)
    else:
        raise AssertionError("an unbacked reference resolved instead of aborting")


def test_a_proposal_that_supplies_its_own_setup_resolves(tmp_path):
    """BOUNDARY. The rule is 'your own setup', not 'no setup' — the working case from
    CM1's /api/Cards experiment must keep working."""
    class _R:
        status = 201
        body = '{"status":"success","data":{"id":7,"UserId":25}}'
        headers: dict = {}

    spec = {"method": "GET", "url": "http://t/api/Cards/{{setup.0.data.id}}"}
    got = hyp.resolve_setup_refs(spec, [_R()])

    assert got["url"] == "http://t/api/Cards/7", got
