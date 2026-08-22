"""
test_plan_covers_methodology.py — the methodology is the floor, not a suggestion.

WEB_METHODOLOGY has ten phases and business-logic is the ninth. The checklist is handed
to the planner as text and the model writes its own plan, so on the 2026-08-16 Juice Shop
run the plan came back with seven steps and four phases silently absent — configuration,
cryptography, business-logic, client-side. The loop then executed that plan to completion
and stopped, and the run was recorded as a business-logic measurement that never planned
a business-logic step.

The existing floor checked `len(new) < 2`. That validates a PROXY (the model said
something) rather than the CLAIM (the plan covers the methodology), and a seven-step plan
missing the phase under measurement passes a length check comfortably.

Coverage, not ordering: the model keeps its own sequence and its own wording, and a phase
it left out is appended rather than the whole plan being replaced.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal.methodology import WEB_METHODOLOGY, Methodology


class _PlanLLM:
    """Returns a fixed plan text, whatever it is asked."""
    reply = ""

    def propose(self, system, user, max_tokens=1024):
        return _PlanLLM.reply


def _session(kind="web"):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import FakeKali
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_PlanLLM()))
    sess.set_methodology(kind)
    return sess


# The seven-step plan the live run actually produced, phases and all.
THE_LIVE_PLAN = """
1. [recon] Crawl authenticated site map with curl against /rest/products/search
2. [input-validation] Run sqlmap against /rest/products/search?q=
3. [authorization] IDOR-test /rest/basket/<id> by incrementing ids
4. [authorization] Attempt forced browsing to /#/administration
5. [session] Inspect the JWT bearer token for weak signing
6. [input-validation] Test the profile image endpoint for path traversal
7. [error-handling] Trigger verbose errors on REST endpoints
"""


def _phases(plan):
    return [s.phase for s in plan]


# -- the coverage floor --------------------------------------------------------

def test_a_plan_that_omits_business_logic_gets_it_planned_anyway():
    """The named case. This plan ran to completion on a live engagement and the phase
    being measured was never in it."""
    _PlanLLM.reply = THE_LIVE_PLAN
    plan = _session().make_plan()
    assert "business-logic" in _phases(plan)


def test_every_methodology_phase_survives_a_plan_that_dropped_four_of_them():
    _PlanLLM.reply = THE_LIVE_PLAN
    plan = _session().make_plan()
    for step in WEB_METHODOLOGY:
        assert step.phase in _phases(plan), f"{step.phase} was silently dropped"


def test_the_model_keeps_its_own_steps_and_their_order():
    """Coverage is the requirement, not ordering. Replacing the model's plan would throw
    away target-specific reasoning — the live plan named the real endpoints."""
    _PlanLLM.reply = THE_LIVE_PLAN
    plan = _session().make_plan()
    assert _phases(plan)[:7] == ["recon", "input-validation", "authorization",
                                 "authorization", "session", "input-validation",
                                 "error-handling"]
    assert "sqlmap" in plan[1].text


def test_an_appended_step_carries_its_phase_and_wstg_reference():
    """An appended step has to be as actionable as one the model wrote, or the loop has
    a phase it cannot work."""
    _PlanLLM.reply = THE_LIVE_PLAN
    plan = _session().make_plan()
    busl = next(s for s in plan if s.phase == "business-logic")
    assert "WSTG-BUSL" in busl.text
    assert "price" in busl.text or "workflow" in busl.text


def test_a_plan_that_already_covers_everything_is_left_alone():
    """The floor must be a floor, not a rewrite: a good plan is returned unchanged."""
    _PlanLLM.reply = "\n".join(
        f"{i}. [{s.phase}] {s.title}" for i, s in enumerate(WEB_METHODOLOGY, 1))
    plan = _session().make_plan()
    assert len(plan) == len(WEB_METHODOLOGY)
    assert _phases(plan) == [s.phase for s in WEB_METHODOLOGY]


def test_a_repeated_phase_is_covered_once_not_appended_again():
    """The box methodology names `enumeration` three times. Coverage asks whether the
    phase is planned at all — appending two more enumeration steps because the model
    wrote one would pad the plan without adding coverage."""
    _PlanLLM.reply = ("1. [enumeration] sweep the ports and enumerate every service\n"
                      "2. [enumeration] enumerate SMB shares and LDAP anonymous bind\n")
    plan = _session("box").make_plan()
    assert _phases(plan).count("enumeration") == 2, "an enumeration step was padded in"
    assert "exploitation" in _phases(plan)
    assert "privilege-escalation" in _phases(plan)


def test_an_empty_plan_still_falls_back_to_the_whole_checklist():
    """The pre-existing behaviour for a model that says nothing useful, unchanged."""
    _PlanLLM.reply = "I could not think of anything."
    plan = _session().make_plan()
    assert _phases(plan) == [s.phase for s in WEB_METHODOLOGY]


def test_missing_phases_returns_what_a_plan_does_not_cover():
    """The check itself, addressable without a session: deterministic set arithmetic
    over the methodology, with the model nowhere in it."""
    from brukal.agents.strategist import PlanStep
    m = Methodology("web")
    assert m.missing_phases([]) == [s.phase for s in WEB_METHODOLOGY]
    covered = [PlanStep(text="x", phase=s.phase) for s in WEB_METHODOLOGY]
    assert m.missing_phases(covered) == []
    partial = [PlanStep(text="x", phase="recon")]
    assert "recon" not in m.missing_phases(partial)
    assert "business-logic" in m.missing_phases(partial)


def test_progress_through_a_plan_is_preserved_across_a_replan():
    """Appending must not disturb the cursor bookkeeping a re-plan depends on."""
    _PlanLLM.reply = THE_LIVE_PLAN
    sess = _session()
    sess.make_plan()
    sess.plan_cursor = 3
    plan = sess.make_plan()
    assert sess.plan_cursor == 3
    assert all(s.done for s in plan[:3])
