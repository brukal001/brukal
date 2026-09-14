r"""
executor.py — the ONLY path from a proposed action to execution.

This is the single most important file for your safety claim. Nothing in
Brukal may run a command except by calling Executor.run(). And Executor.run()
ALWAYS consults the gate first and ALWAYS logs the decision. There is no other
door to the cage.

    propose ->  gate.check()  ->  [ALLOW] -> kali.run()  -> log result
                              \->  [DENY/ESCALATE]        -> log, do not run

When you add agents (milestone 2), they call this exact method. They are never
handed the Kali backend directly. That is what makes "the agent cannot bypass
the gate" a structural fact rather than a promise.
"""
from __future__ import annotations

from typing import Callable, Optional

from . import redact
from .audit import AuditLog
from .gate import Decision, Gate
from .kali import ExecResult

# Type of a human-approval callback for ESCALATE decisions.
Approver = Callable[[Decision], bool]


def _deny_all_approver(decision: Decision) -> bool:
    """Default approver: refuse. Fail-closed (invariant 2) — if no human
    approval channel is wired, an ESCALATE never runs. A real interface (CLI
    prompt, review queue) is injected explicitly when one exists."""
    return False


class Executor:
    def __init__(self, gate: Gate, kali, audit: AuditLog,
                 approver: Optional[Approver] = None):
        self._gate = gate
        self._kali = kali        # FakeKali or DockerKali
        self._audit = audit
        # Consulted ONLY for ESCALATE decisions. Defaults to fail-closed.
        self._approver: Approver = approver or _deny_all_approver

    def run(self, command: str, target: str, agent: str = "unknown"):
        """Judge, log, and (only if permitted) execute one action.

        Returns (Decision, ExecResult | None). The three verdicts:
          * ALLOW    -> run.
          * ESCALATE -> ask the human approver; run only if approved.
          * DENY (or anything unexpected) -> fail-closed, never runs.
        """
        decision: Decision = self._gate.check(command, target, agent)
        self._audit.append("decision", decision)

        if decision.verdict == "ESCALATE":
            approved = bool(self._approver(decision))
            self._audit.append("approval", {
                "action": decision.action,
                "target": decision.target,
                "agent": decision.agent,
                "risk_band": decision.risk_band,
                "approved": approved,
            })
            if not approved:
                return decision, None          # human declined -> do not run
            # approved -> fall through to execution
        elif decision.verdict != "ALLOW":
            # DENY, or any verdict we do not explicitly permit -> never runs.
            return decision, None

        result: ExecResult = self._kali.run(command)
        # TARGET OUTPUT ENTERS THE RECORD HERE, and this is where three unpublishable
        # bundles actually leaked. The agent recovered an admin password hash from a SQLi
        # dump and then typed it into `md5sum` and `hashcat`; runs CM4 and CM5 both
        # measured ZERO credential-like values in captured response bodies and the
        # credential present in these execution records. Registering what the RESPONSE
        # ITSELF named a secret, before the record is written, masks it here and in every
        # later command that carries it — through the funnel that already exists.
        for _stream in (getattr(result, "stdout", ""), getattr(result, "stderr", "")):
            redact.observe_response(_stream)
        self._audit.append("execution", result)
        return decision, result
