"""A proposal the model MADE and validation DISCARDED must leave a trace.

GAP #17: `parse()` skipped malformed entries with a bare `continue`, and the raw reply
is persisted nowhere, so `grep -c state_changed <ledger>` measured "survived validation"
while being read as "the model never proposed it". Run 18's whole MODEL-LIMIT
attribution rested on that reading, and the run's artifacts could not tell the two apart.

The drop record is what makes the two distinguishable. Each test below is a shape the
model can plausibly emit -- the `setup` one is the prompt's OWN language for reaching an
interesting state -- so a silent drop there destroys exactly the signal run 19 exists to
measure."""
import json

from brukal import hypothesis as H


def _one(**over):
    base = dict(title="t", severity="high", comparator="state_changed",
                control={"url": "http://h/a", "method": "GET"},
                variant={"url": "http://h/a", "method": "GET"},
                act={"url": "http://h/a", "method": "POST"}, rationale="r")
    base.update(over)
    return json.dumps([base])


def test_a_valid_state_changed_proposal_still_parses():
    """Positive control. Without it, "nothing was dropped" is also satisfied by
    "nothing was accepted" -- the error that made GAP #11's boundary test pass for the
    wrong reason."""
    drops = []
    got = H.parse(_one(), drops=drops)
    assert len(got) == 1 and got[0].comparator == "state_changed"
    assert got[0].act is not None
    assert drops == []


def test_the_change_placed_in_setup_instead_of_act_is_recorded_not_silent():
    """The dangerous shape: control == variant with no `act`, because the model put the
    state change in `setup` -- which the prompt advertises for exactly that purpose."""
    drops = []
    got = H.parse(_one(act=None, setup=[{"url": "http://h/a", "method": "POST"}]),
                  drops=drops)
    assert got == []
    assert len(drops) == 1
    assert drops[0]["comparator"] == "state_changed"
    assert drops[0]["reason"] == "control_equals_variant_without_act"


def test_an_act_supplied_as_a_list_is_recorded():
    drops = []
    got = H.parse(_one(act=[{"url": "http://h/a", "method": "POST"}]), drops=drops)
    # `act` is unusable, so the sides are identical and nothing is judged -- but the
    # proposal was MADE, and the comparator it was made under is what run 19 counts.
    assert got == []
    assert len(drops) == 1 and drops[0]["comparator"] == "state_changed"


def test_an_unknown_comparator_is_recorded_with_the_name_the_model_used():
    drops = []
    got = H.parse(_one(comparator="totally_made_up"), drops=drops)
    assert got == []
    assert drops[0]["reason"] == "unknown_comparator"
    assert drops[0]["comparator"] == "totally_made_up"


def test_drops_are_opt_in_so_every_existing_caller_is_unaffected():
    """No caller that ignores drops may change behaviour -- the fix must not alter what
    parse() RETURNS, only what it can additionally report."""
    assert H.parse(_one(comparator="totally_made_up")) == []
    assert len(H.parse(_one())) == 1
