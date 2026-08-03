"""
test_health.py — notice when the target is dying, and stop.

Brukal took an authorised target down during an engagement: sustained path discovery
against an app that threw for every unknown path exhausted its heap. It then carried on
for twenty more steps, found nothing, and reported that as a clean result.

The second failure is the worse one. "No findings against a corpse" and "no findings
against a healthy application" are the same sentence in a report unless something says
otherwise. A rate limit does not help — it bounds how fast requests leave, not whether
anything is still receiving them.
"""
from __future__ import annotations

from brukal.health import TargetHealth


def test_an_error_status_is_the_target_ANSWERING():
    """Several of the flaws Brukal looks for are found by making an application error.
    Counting a 500 as ill health would halt the run at the moment it started working."""
    h = TargetHealth()
    for _ in range(10):
        h.record(True)              # answered, whatever the code
    assert h.state == "healthy" and h.should_stop() == ""


def test_a_target_that_stops_answering_halts_the_run():
    h = TargetHealth(fail_run=5)
    for _ in range(6):
        h.record(True)
    for _ in range(5):
        h.record(False)
    assert h.state in ("degraded", "dead")
    why = h.should_stop()
    assert "stopped responding" in why and "worthless" in why


def test_a_single_blip_is_not_degradation():
    """Consecutive, not cumulative: an app that misses one probe and recovers is fine,
    and halting on that would make the tool useless on a flaky network."""
    h = TargetHealth(fail_run=5)
    for _ in range(5):
        h.record(True)
    h.record(False)
    h.record(True)
    h.record(False)
    assert h.state == "healthy" and h.should_stop() == ""


def test_a_target_that_never_answered_is_the_operators_problem_not_ours():
    """An address that never responded is a configuration mistake. There is nothing we
    could be harming, so this must not masquerade as 'we broke it'."""
    h = TargetHealth(fail_run=3)
    for _ in range(8):
        h.record(False)
    assert h.state == "unreachable"
    assert h.should_stop() == ""             # nothing to protect; let the run report it
    assert "nothing was actually assessed" in h.summary()


def test_the_summary_stops_an_empty_report_reading_as_clean():
    h = TargetHealth(fail_run=4)
    for _ in range(5):
        h.record(True)
    for _ in range(4):
        h.record(False)
    s = h.summary()
    assert s.startswith("⚠") and "NOT a clean result" in s


def test_a_healthy_run_says_so_without_alarming():
    h = TargetHealth()
    for _ in range(6):
        h.record(True)
    assert h.summary().startswith("target health:") and "⚠" not in h.summary()


def test_the_loop_halts_when_the_browser_reports_a_dying_target():
    """The check is only worth anything if the loop acts on it."""
    from brukal.loop import GroundedLoop
    loop = GroundedLoop.__new__(GroundedLoop)
    h = TargetHealth(fail_run=3)
    for _ in range(4):
        h.record(True)
    for _ in range(3):
        h.record(False)
    loop.session = type("S", (), {"browser": type("B", (), {"health": h})()})()
    assert "stopped responding" in loop._target_unwell()


def test_health_monitoring_cannot_itself_end_a_run():
    """Instrumentation must never be able to kill the thing it measures."""
    from brukal.loop import GroundedLoop
    loop = GroundedLoop.__new__(GroundedLoop)
    loop.session = type("S", (), {})()          # no browser at all
    assert loop._target_unwell() == ""
