"""
identity.py — who is asking, and what that principal is allowed to do.

Two problems this closes, both foundational.

**Identity was self-reported.** `Executor.run` took `agent: str = "unknown"`, and the
recon and exploit agents passed `agent=request.proposing_agent` — a field the LLM
writes in its own Action Request. The audit record, adaptive trust, and now the
capability check all key on that string, so a model that wrote
`"proposing_agent": "operator"` promoted itself. Identity is now MINTED by the
dispatcher (`mint`) and the capability set is always re-derived from ROLE_CAPABILITIES,
so a forged identity object cannot widen itself either. That is invariant 3 enforced in
code rather than asked for in a prompt.

**Role separation was prompt-deep.** The recon agent's persona said "enumerate", but
nothing stopped it emitting `msfconsole`. `required_capability` maps a command to the
one capability it needs, DETERMINISTICALLY, reusing the same tool vocabulary the soft
risk layer already uses (`risk.py`) — no second parser to drift, and no LLM anywhere
near the decision (invariant 1). Anything it cannot classify requires the most
restrictive capability (invariant 2), so an unrecognised binary is never a free pass.

The capability check is enforced in `Gate.check` as one more AND-condition. Like every
hard check it can only DENY; it can never widen an action the earlier checks refused.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, replace


# --- the capability vocabulary ---------------------------------------------- #
# Deliberately small. Five capabilities that map onto boundaries the codebase
# already draws; splitting further (e.g. POST_EXPLOITATION) is not possible today
# without inventing distinctions the tool vocabulary does not make — impacket-psexec
# is both exploitation and post-exploitation. Kept for a later phase.
RECON = "RECON"                      # read-only observation and enumeration
WEB_REQUEST = "WEB_REQUEST"          # HTTP that changes remote state
INJECTION_TEST = "INJECTION_TEST"    # active injection tooling
CREDENTIAL_TEST = "CREDENTIAL_TEST"  # brute force / cracking
EXPLOITATION = "EXPLOITATION"        # code execution, shells, pivots, MITM, DoS

ALL_CAPABILITIES = frozenset({RECON, WEB_REQUEST, INJECTION_TEST,
                              CREDENTIAL_TEST, EXPLOITATION})

# The machine-readable code for THIS check only. The full reason-code refactor
# across every gate layer is a later phase; this one exists because a capability
# denial is the one an operator most needs to distinguish from a scope denial.
CAPABILITY_DENIED_REASON = "CAPABILITY_NOT_GRANTED"

AGENT_VERSION = "1"

# --- which attack tools belong to which capability --------------------------- #
# Subsets of risk._ATTACK_TOOLS. Anything in _ATTACK_TOOLS not named here is
# EXPLOITATION — the most restrictive of the three, so the fallback is the safe way.

# --- role -> capabilities ---------------------------------------------------- #
# These CODIFY the boundaries the roles already had in prose; they do not shrink
# them. `recon` and `verify` are the two that gain a real constraint: both are
# defined by their own prompts as read-only, and now cannot exceed that whatever
# the model proposes.
#
# `strategist`, `exploit` and the experiment identities keep the full set on
# purpose. Narrowing them here would change behaviour rather than codify it — and
# for `harness`/`badbot`/`goodbot` it would silently move the published experiment
# metrics, which must stay reproducible.
ROLE_CAPABILITIES: dict[str, frozenset] = {
    # human principal, acting on their own authority
    "operator": ALL_CAPABILITIES,
    # agent principals
    "recon": frozenset({RECON}),
    "verify": frozenset({RECON}),
    "web": frozenset({RECON, WEB_REQUEST}),
    "exploit": ALL_CAPABILITIES,
    "strategist": ALL_CAPABILITIES,
    # experiment-harness principals (reproducibility of published metrics)
    "harness": ALL_CAPABILITIES,
    "badbot": ALL_CAPABILITIES,
    "goodbot": ALL_CAPABILITIES,
}


@dataclass(frozen=True)
class AgentIdentity:
    """Bound identity for one running principal. Frozen: a holder cannot edit it,
    and `resolve_identity` re-derives capabilities from the role regardless."""
    agent_id: str
    role: str
    capabilities: frozenset
    engagement_id: str = ""
    agent_version: str = AGENT_VERSION

    def can(self, capability: str) -> bool:
        return capability in self.capabilities

    def __str__(self) -> str:            # audit + trust key on the role
        return self.role


def capabilities_for(role: str) -> frozenset:
    """The authority a role carries. Unknown role -> nothing (fail closed)."""
    return ROLE_CAPABILITIES.get((role or "").strip().lower(), frozenset())


def mint(role: str, engagement_id: str = "", agent_version: str = AGENT_VERSION
         ) -> AgentIdentity:
    """Create a bound identity. Called by the ORCHESTRATOR / dispatcher at the point
    a role runs — never from anything the model produced."""
    role = (role or "").strip().lower()
    return AgentIdentity(agent_id=f"{role}-{uuid.uuid4().hex[:12]}", role=role,
                         capabilities=capabilities_for(role),
                         engagement_id=engagement_id, agent_version=agent_version)


def operator_identity(engagement_id: str = "") -> AgentIdentity:
    """The human at the CLI. A person running `brukal exec` acts on their own
    authority, so they hold every capability; the constraint exists for AGENT
    principals. This keeps `brukal exec` / `brukal shell` behaviour unchanged."""
    return mint("operator", engagement_id=engagement_id)


def resolve_identity(agent) -> AgentIdentity:
    """Coerce whatever a caller passed into a bound identity.

    Capabilities are ALWAYS re-derived from the role. A caller handing in an
    AgentIdentity with a self-declared capability set gains nothing — authority comes
    from ROLE_CAPABILITIES, never from the object claiming it.
    """
    if isinstance(agent, AgentIdentity):
        return replace(agent, capabilities=capabilities_for(agent.role))
    role = (str(agent or "")).strip().lower()
    return AgentIdentity(agent_id=f"{role or 'unnamed'}-unbound", role=role,
                         capabilities=capabilities_for(role))
