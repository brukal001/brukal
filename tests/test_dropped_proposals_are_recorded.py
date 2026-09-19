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


def test_a_proposal_cut_by_the_MAX_HYPOTHESES_cap_is_recorded(tmp_path=None):
    """GAP #18, second half. `parse()` `break`s at `_MAX_HYPOTHESES` and the entries
    after the cut were not even reached by the drop path -- they vanished more quietly
    than a malformed one.

    This is not hypothetical: an offline A/B showed the model placing `state_changed`
    LAST (index 5 of 6) in three of four replies, so the comparator run 18 was measuring
    is exactly the one the cap eats first."""
    doc = []
    for i in range(H._MAX_HYPOTHESES + 3):
        doc.append(dict(title=f"t{i}", severity="low",
                        comparator=("state_changed" if i >= H._MAX_HYPOTHESES
                                    else "unauthenticated_exposure"),
                        control={"url": f"http://h/{i}", "method": "GET"},
                        variant={"url": f"http://h/{i}?x=1", "method": "GET"},
                        rationale="r"))
    drops = []
    got = H.parse(json.dumps(doc), drops=drops)
    assert len(got) == H._MAX_HYPOTHESES
    cut = [d for d in drops if d["reason"] == "cap_truncated"]
    assert len(cut) == 3, f"{len(cut)} recorded, 3 were cut"
    assert {d["comparator"] for d in cut} == {"state_changed"}, (
        "the comparator that was cut must survive its own truncation -- that is the "
        "whole question a later run asks")


def test_the_drop_REACHES_THE_LEDGER_not_just_a_note(tmp_path):
    """The first version of the recorder called `audit.record(...)` -- a method AuditLog
    does not have -- inside a bare `except Exception: pass`. It raised AttributeError on
    every call and swallowed it, so the ledger row never existed and nothing could tell.

    A recorder wrapped in a silent except is unfalsifiable. This asserts the ROW, which
    is the only thing a later run can actually count."""
    import json as _json
    from pathlib import Path as _Path

    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import ExecResult

    scope = load_scope(_Path(__file__).resolve().parent / "fixtures" / "scope_fast.json")
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession("10.10.10.5", ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()))

    s._record_proposal_drops(
        [{"reason": "control_equals_variant_without_act",
          "comparator": "state_changed", "title": "coupon redeems twice"}])

    rows = [_json.loads(l) for l in open(audit.path)]
    dropped = [r for r in rows if r.get("kind") == "experiment_proposal_dropped"]
    assert dropped, "the drop never reached the ledger — the row a later run counts"
    assert dropped[0]["data"]["by_comparator"] == {"state_changed": 1}
