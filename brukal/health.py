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

# --------------------------------------------------------------------------- #
# WHOSE silence is it
# --------------------------------------------------------------------------- #
# The CR1 pre-flight (crAPI, 2026-09-17) halted with `target-unhealthy` against a target
# that was answering 200s throughout, and the report blamed the target. nmap found 443
# open, the crawler followed it to https, crAPI serves a self-signed certificate, and ten
# `CERTIFICATE_VERIFY_FAILED` fetches were folded into `answered=False`.
#
# The docstring above already had the answer and did not apply it: "a timeout, a refused
# connection or a torn-down socket is not [an answer]". A TLS verification failure is none
# of those three. The socket connected and the server answered; the CLIENT refused the
# answer. So the property is ORIGIN:
#
#   TARGET-ORIGIN  the target did not answer         -> counts toward health
#   CLIENT-ORIGIN  we refused, failed, or never asked -> a HARNESS LIMIT, recorded with
#                                                        its cause, never target health
#
# This matters beyond a halted run. CR1's definition of done requires every outcome
# attributed to target / harness / model; a harness limit written into the ledger as a
# target refusal mis-attributes by construction.
TARGET_ORIGIN = "target"
CLIENT_ORIGIN = "client"

# Cause label -> the substrings that identify it. Ordered, and matched in order, because
# one note can carry several words ("cage web error: ... timed out" is our plumbing
# timing out, not the target). Every entry is a shape observed in this codebase's own
# failure paths — see `failure_origin` for the inventory.
_CLIENT_CAUSES: tuple = (
    # We refused the answer the server gave us.
    ("tls-verification", ("certificate verify failed", "certificate_verify_failed",
                          "ssl: ", "[ssl", "sslerror", "sslcertverificationerror",
                          "alert handshake failure", "wrong version number",
                          "unable to get local issuer")),
    # Our own cage plumbing: docker exec failed, timed out, or returned unparseable JSON.
    ("cage-plumbing", ("cage web error",)),
    # A capability this build does not have. The request was never made.
    ("not-wired", ("needs the live cdp browser", "[fake ", "interception armed")),
    # We could not resolve the name, so nothing was ever sent.
    ("dns", ("name or service not known", "temporary failure in name resolution",
             "nodename nor servname", "getaddrinfo", "name resolution")),
    # Routing. OUR OWN EGRESS LOCK produces exactly this shape for a host we refused to
    # reach: counting it as the target's silence would let containment halt the run and
    # then blame the target for being contained.
    ("routing", ("network is unreachable", "no route to host", "host is unreachable",
                 "network unreachable")),
    ("proxy", ("proxy",)),
    # A request we malformed, or an answer we could not parse. Ours either way.
    ("malformed", ("unknown url type", "invalid url", "can't contain control characters",
                   "valueerror", "codec can't decode", "expecting value")),
)


def failure_origin(note: str) -> str:
    """Whose silence a failed request was — deterministic, from the note alone.

    THE INVENTORY. Every path in this codebase that reaches `TargetHealth.record` with a
    falsy status, and how each is classified:

      web.py HttpWebCage        `except URLError`      -> "unreachable: <reason>"
                                  reason is a socket error (timeout / refused / reset)
                                  -> TARGET, or an SSL / DNS / routing error -> CLIENT
      web.py DockerHttpWebCage  in-cage `except Exception` -> str(e), the CR1 shape
                                  ("<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] …>")
                                  -> classified on the same table
      web.py DockerHttpWebCage  outer `except Exception` -> "cage web error: <e>"
                                  -> CLIENT (docker exec / subprocess timeout / bad JSON)
      web.py SplitWebCage       unknown kind           -> "needs the live CDP browser"
                                  -> CLIENT (the request was never made)
      web.py FakeWebCage        "[fake …]" / "interception armed for …"
                                  -> CLIENT (no observation of the target at all)

    An unrecognised silence is TARGET-ORIGIN. That is fail-closed in the direction that
    matters here (invariant 2): the safe default is to stop, because continuing to hammer
    something that may be dying is the failure this module exists to prevent. It is
    recorded as unclassified, so it can never masquerade as a diagnosis.
    """
    return TARGET_ORIGIN if failure_cause(note) is None else CLIENT_ORIGIN


def failure_cause(note: str) -> str | None:
    """The client-origin cause label, or None when the silence is the target's."""
    low = (note or "").lower()
    if not low:
        return None
    for label, needles in _CLIENT_CAUSES:
        if any(n in low for n in needles):
            return label
    return None


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
        # Failures WE caused, kept apart from the target's silence and never allowed to
        # reach `state`. Counted and labelled so they surface as harness limits.
        self.client_failures = 0
        self.client_causes: dict = {}

    def record(self, answered: bool, note: str = "") -> str:
        """One observation. `answered` means bytes came back — a 404 or a 500 is an
        answer; a timeout, a refused connection or a torn-down socket is not.

        A 5xx is deliberately NOT counted as a failure here. Plenty of the flaws Brukal
        looks for are found precisely by making an application error, and treating those
        as ill health would halt the run at the moment it started working.

        `note` is the failure's own text, and it decides WHOSE silence this was. A
        client-origin failure (we refused the answer, never asked, or could not route) is
        counted separately, labelled with its cause, and left out of `state` entirely —
        it neither advances the consecutive run nor resets it, because it is not an
        observation of the target at all.

        Returns the client-origin cause label, or "" when this was a real observation —
        the caller uses it to record a harness limit at its own plane's door."""
        if not answered:
            cause = failure_cause(note)
            if cause is not None:
                self.client_failures += 1
                self.client_causes[cause] = self.client_causes.get(cause, 0) + 1
                return cause
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
        return ""

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
                f"here on is worthless either way." + self._client_clause())

    def _client_clause(self) -> str:
        """Our own failures, named beside the target's — never folded into its tally.
        The operator reads this sentence and the ledger side by side; the numbers in it
        are exactly the ones `web_result` rows support."""
        if not self.client_failures:
            return ""
        causes = ", ".join(f"{k}×{v}" for k, v in sorted(self.client_causes.items()))
        return (f" Separately, {self.client_failures} request(s) failed client-origin "
                f"({causes}) and are NOT counted against the target.")

    def summary(self) -> str:
        """One line for the report, so an empty finding list cannot be misread."""
        if self.total == 0:
            if self.client_failures:
                causes = ", ".join(f"{k}×{v}" for k, v in sorted(self.client_causes.items()))
                return (f"harness limit: {self.client_failures} request(s) never reached "
                        f"the target ({causes}); nothing was observed of it.")
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
        line = f"target health: {answered}/{self.total} requests answered"
        if self.client_failures:
            causes = ", ".join(f"{k}×{v}" for k, v in sorted(self.client_causes.items()))
            line += (f"; {self.client_failures} further request(s) failed client-origin "
                     f"({causes}) — a harness limit, not the target's health")
        return line
