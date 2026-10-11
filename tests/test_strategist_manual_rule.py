"""The strategist prompt states ONE rule for MANUAL.

It said both 'give MANUAL for intrusive/interactive work' and, later, 'use MANUAL ONLY
for steps the cage truly cannot do' — a model following the first sentence hands
in-scope exploitation back. Risky steps reach the operator through the gate's
ESCALATE path anyway."""
from brukal.agents.strategist import STRATEGIST_SYSTEM


def test_old_contradictory_sentence_is_gone():
    assert "give MANUAL for intrusive/interactive" not in STRATEGIST_SYSTEM


def test_new_rule_says_risky_steps_are_paused_by_the_gate():
    assert "Give RUN or WEB for in-scope actions, including exploitation" in STRATEGIST_SYSTEM
    assert "Give MANUAL only for steps the cage cannot perform" in STRATEGIST_SYSTEM


def test_the_detailed_manual_guidance_is_still_present():
    assert "Use MANUAL ONLY for steps the cage truly cannot do" in STRATEGIST_SYSTEM
