"""
health.py — notice when the target is dying, and stop.

Brukal took a target down during an engagement. Sustained path discovery against an
application that threw an exception for every unknown path exhausted its heap; it exited
mid-run, and Brukal carried on for twenty more steps, produced no findings, and reported
that as a clean result. Two separate failures, and the second is the worse one:

  * it kept issuing requests to something it was plausibly harming, and
  * "no findings against a corpse" is indistinguishable, in a report, from
    "no findings against a healthy application".

A rate limit does not catch this. A rate limit bounds how FAST requests go out; it says
nothing about whether the thing receiving them is still alive. What is missing is the
question a human operator asks continuously and no code was asking: *is the target still
answering the way it did five minutes ago?*

So this tracks outcomes over a rolling window and distinguishes three states:

    healthy    — answering, whatever the status code. A 404 is an answer.
    degraded   — was answering, now mostly failing to. Consecutive, not cumulative:
                 an app that 500s on one probe and recovers is not degraded.
    dead       — not answering at all.

A degraded verdict is a reason to STOP, not to slow down. If the target is failing
because of what we are doing, throttling only prolongs it; and if it is failing for its
own reasons, everything measured after that point is worthless anyway.

Deterministic arithmetic over observed outcomes. No model, nothing a target's content
could influence — only whether bytes came back.
"""
from __future__ import annotations

import time

# How many recent outcomes to weigh, and how many consecutive failures constitute a
# verdict. Small on purpose: by the time twenty requests have failed the damage, if any,
# is done.
_WINDOW = 12
_CONSECUTIVE_FAIL = 5


class TargetHealth:
    """Rolling health of one target, fed by every governed request."""

    def __init__(self, window: int = _WINDOW, fail_run: int = _CONSECUTIVE_FAIL):
        self.window = max(4, window)
        self.fail_run = max(2, fail_run)
        self._recent: list = []          # True = answered, False = did not
        self.total = 0
        self.failures = 0
        self.ever_healthy = False
        self.first_failure_at: float | None = None
        self.consecutive = 0

    def record(self, answered: bool) -> None:
        """One observation. `answered` means bytes came back — a 404 or a 500 is an
        answer; a timeout, a refused connection or a torn-down socket is not.

        A 5xx is deliberately NOT counted as a failure here. Plenty of the flaws Brukal
        looks for are found precisely by making an application error, and treating those
        as ill health would halt the run at the moment it started working."""
        self.total += 1
        self._recent.append(bool(answered))
        if len(self._recent) > self.window:
            self._recent.pop(0)
        if answered:
            self.ever_healthy = True
            self.consecutive = 0
        else:
            self.failures += 1
            self.consecutive += 1
            if self.first_failure_at is None:
                self.first_failure_at = time.time()

    @property
    def state(self) -> str:
        if not self.ever_healthy:
            # Never answered: that is an unreachable target or a wrong address, which is
            # the operator's problem to fix, not a target we broke.
            return "unreachable" if self.total >= self.fail_run else "unknown"
        if self.consecutive >= self.fail_run:
            return "dead" if self.consecutive >= self.fail_run * 2 else "degraded"
        return "healthy"

    def should_stop(self) -> str:
        """A human reason to hand back, or "".

        Only fires for a target that was answering and then stopped — the case where
        continuing is both useless and possibly harmful. An address that never answered
        is left alone: it is a configuration mistake, and there is nothing to protect."""
        state = self.state
        if state not in ("degraded", "dead"):
            return ""
        return (f"target stopped responding: {self.consecutive} consecutive requests got "
                f"no answer after {self.total - self.failures} successful one(s). "
                f"Halting rather than continuing — if the target is failing because of "
                f"this engagement, more requests prolong it, and anything measured from "
                f"here on is worthless either way.")

    def summary(self) -> str:
        """One line for the report, so an empty finding list cannot be misread."""
        if self.total == 0:
            return ""
        answered = self.total - self.failures
        if self.state in ("degraded", "dead"):
            return (f"⚠ TARGET HEALTH: {answered}/{self.total} requests answered; the "
                    f"target stopped responding during the run. Findings below cover "
                    f"only the period it was up, and the absence of others is NOT a "
                    f"clean result.")
        if self.state == "unreachable":
            return (f"⚠ TARGET HEALTH: none of {self.total} requests were answered — "
                    f"nothing was actually assessed.")
        return f"target health: {answered}/{self.total} requests answered"
