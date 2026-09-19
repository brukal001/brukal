"""
test_destructive_is_asked_for_not_forbidden.py — the door the approver was built for.

THE MEASURED FAULT (runs 14 and 17, crAPI, 2026-09-19)
    Recall sat at 1 of 14 across four runs. Six of the eleven misses are attributed
    HARNESS-LIMIT, and they are these:

        3   reset the password of a different user
        7   delete a video of another user
        10  update internal video properties
        13  redeem an already-claimed coupon

    `_approve_destructive_experiment` exists, is correctly fail-closed, escalates through
    the same approver the command path uses, and records `refused_by_operator` instead of
    a silent skip. It fired **ZERO times in both runs**.

    Because the experiment prompt ends with:

        "Do not propose anything destructive (no DELETE of data you did not create, no
         password changes to accounts you do not own, no endpoints named
         reset/drop/wipe)."

    Unconditional — it ignores `scope.destructive_allowed` entirely. The approval
    machinery was built and the door was nailed shut, so nothing ever reached it. Run 17
    proposed exactly three comparators, all of them READ comparators; `state_changed` and
    `oob_callback` were proposed zero times.

    The maintainer's instruction was explicit: Brukal must be able to act destructively
    when authorised beforehand, and must ASK. "We are not compromising on its ability."

THE SECOND HALF, and it is a SAFETY hole, not a capability one
    `_is_destructive_path` matches WORDS IN THE URL (reset, drop, wipe). Challenge 7 is
    `DELETE /identity/api/v2/user/videos/9` — no destructive word anywhere in it. Opening
    the prompt without also judging the METHOD would let a DELETE execute having never
    reached the approver. The two changes are only safe together.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from brukal import AuditLog, Executor, Gate, load_scope
from brukal import hypothesis as hyp
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"


class _Cage:
    def __init__(self):
        self.seen = []

    def run(self, action):
        self.seen.append((action.method, action.url))
        return WebResult(status=200, url=action.url, body='{"ok":true}')


def _session(tmp_path, destructive, approver=None):
    scope = load_scope(SCOPE)
    object.__setattr__(scope, "destructive_allowed", destructive)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=approver or (lambda d: True))
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    cage = _Cage()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    return s, cage, audit


def _h(method, url, comparator="state_changed"):
    return hyp.Hypothesis(
        title="t", severity="high", comparator=comparator, setup=[],
        control={"method": "GET", "url": BASE + "/identity/api/v2/user/videos/9",
                 "as": "self"},
        variant={"method": method, "url": BASE + url, "as": "self"})


# --------------------------------------------------------------------------- #
# HALF ONE — the safety hole that must close FIRST
# --------------------------------------------------------------------------- #

def test_a_DELETE_on_an_innocuous_url_is_still_destructive(tmp_path):
    """CHALLENGE 7's actual request. No destructive word anywhere in the path, so the
    URL-word classifier called it harmless. Once the prompt permits such proposals, this
    executes without the approver ever being consulted."""
    s, _c, _a = _session(tmp_path, destructive=True)
    for method in ("DELETE", "PUT", "PATCH"):
        assert s._is_destructive_request(method, BASE + "/identity/api/v2/user/videos/9"), \
            f"{method} on another user's object was not judged destructive"


def test_a_read_is_still_not_destructive(tmp_path):
    """BOUNDARY, load-bearing. If GET/HEAD became destructive, every ordinary experiment
    would escalate and the approver would be meaningless."""
    s, _c, _a = _session(tmp_path, destructive=True)
    for method in ("GET", "HEAD", "OPTIONS"):
        assert not s._is_destructive_request(method, BASE + "/identity/api/v2/user/videos/9")


def test_a_destructive_WORD_is_still_caught_under_any_method(tmp_path):
    """BOUNDARY. The URL rule is not replaced by the method rule — /createdb behind a
    plain GET is how Brukal once wiped its own test target."""
    s, _c, _a = _session(tmp_path, destructive=True)
    assert s._is_destructive_request("GET", BASE + "/createdb")
    assert s._is_destructive_request("POST", BASE + "/identity/api/auth/reset-password")


def test_a_POST_is_not_destructive_by_itself(tmp_path):
    """BOUNDARY. POST creates; it is how setup steps reach an interesting state. Treating
    every POST as destructive would escalate the whole workflow surface."""
    s, _c, _a = _session(tmp_path, destructive=True)
    assert not s._is_destructive_request("POST", BASE + "/identity/api/v2/vehicle/vehicles")


# --------------------------------------------------------------------------- #
# HALF TWO — the door
# --------------------------------------------------------------------------- #

def test_the_prompt_FORBIDS_when_the_scope_did_not_opt_in():
    """UNCHANGED DEFAULT. An engagement that never authorised this must not be invited
    to propose it."""
    p = hyp.experiment_prompt(destructive_allowed=False)
    assert "Do not propose anything destructive" in p
    assert "escalated" not in p.lower()


def test_the_prompt_PERMITS_AND_EXPLAINS_when_the_scope_opted_in():
    """THE DEFECT. `destructive_allowed: true` was in crAPI's scope for both runs and the
    prompt forbade it anyway."""
    p = hyp.experiment_prompt(destructive_allowed=True)
    assert "Do not propose anything destructive" not in p
    # it must say what happens, or the model has no reason to believe it is allowed
    assert "approval" in p.lower() or "escalat" in p.lower()
    # and it must point at the comparator that proves a side effect
    assert "state_changed" in p


def test_the_scope_wall_is_never_relaxed_by_it():
    """BOUNDARY. Destructive authorisation is about WHAT may be done to the target, never
    about WHICH target."""
    for flag in (True, False):
        assert "authorised target" in hyp.experiment_prompt(destructive_allowed=flag)


# --------------------------------------------------------------------------- #
# END TO END — the proposal now reaches the approver
# --------------------------------------------------------------------------- #

def test_a_destructive_proposal_reaches_the_approver_and_is_recorded(tmp_path):
    """The whole point: it is ASKED, not dropped, and the ledger shows who answered."""
    asked = []
    s, cage, audit = _session(tmp_path, destructive=True,
                              approver=lambda d: (asked.append(d), True)[1])
    s._run_one_round([_h("DELETE", "/identity/api/v2/user/videos/9")], [])
    assert asked, "the approver was never consulted for a DELETE"
    blob = (tmp_path / "a.jsonl").read_text()
    assert "soft:destructive-experiment" in blob


def test_without_the_opt_in_it_is_refused_and_recorded_not_silently_dropped(tmp_path):
    """FAIL-CLOSED, and visibly so."""
    asked = []
    s, cage, audit = _session(tmp_path, destructive=False,
                              approver=lambda d: (asked.append(d), True)[1])
    s._run_one_round([_h("DELETE", "/identity/api/v2/user/videos/9")], [])
    assert not asked, "an engagement that never opted in consulted the approver"
    assert not [m for m, _u in cage.seen if m == "DELETE"], "a DELETE was executed anyway"
    blob = (tmp_path / "a.jsonl").read_text()
    assert "refused_by_operator" in blob


def test_the_REFINE_prompt_carries_the_same_permission():
    """The follow-up is a FRESH call, not a continuation. Without this the model is
    permitted on round one and forbidden on round two, which is the worse of both: it
    proposes a state-changing experiment, the round is refined, and the refinement
    quietly retreats to read-only."""
    assert "Do not propose anything destructive" in hyp.refine_prompt(False)
    p = hyp.refine_prompt(True)
    assert "Do not propose anything destructive" not in p
    assert "state_changed" in p
