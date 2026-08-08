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

import os
import uuid
from dataclasses import dataclass, replace

from .risk import (_ATTACK_TOOLS, _CURL_BODY_FLAGS, _HTTP_WRITE_METHODS,
                   _IRREVERSIBLE_SCRIPT_CATS, _READ_ONLY_TOOLS,
                   _script_categories, _tokens)

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
_INJECTION_TOOLS = frozenset({"sqlmap", "commix", "nosqlmap", "tplmap"})
_CREDENTIAL_TOOLS = frozenset({
    "hydra", "medusa", "ncrack", "patator", "crowbar", "brutespray",
    "kerbrute", "john", "hashcat", "sshpass"})

_WEB_CLIENTS = frozenset({"curl", "wget"})

# netexec/crackmapexec are attack-CAPABLE but are used read-only for AD enumeration.
# `AssistSession.ad_enum_commands()` already draws this line in prose — the proactive
# set is "UNAUTHENTICATED and read-only ONLY ... no dump/relay/roast/exploit — those
# stay with the planner". These flags are what cross it: credentials, execution, and
# secret dumping. Codifying an existing documented boundary, not inventing one.
_NETEXEC_TOOLS = frozenset({"netexec", "crackmapexec", "nxc"})
_NETEXEC_PRIVILEGED_FLAGS = frozenset({
    "-u", "--username", "-p", "--password", "-H", "--hash", "--hashes",
    "-x", "-X", "--exec", "--exec-method", "-M", "--module",
    "--sam", "--lsa", "--ntds", "--dpapi", "--laps", "--local-auth"})

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


# Roles permitted to take a single-action verification grant. Kept to the role whose
# entire purpose is independent confirmation — without this gate the grant would be a
# universal escape hatch any role could take.
ROLES_THAT_MAY_VERIFY = frozenset({"verify"})


@dataclass(frozen=True)
class AgentIdentity:
    """Bound identity for one running principal. Frozen: a holder cannot edit it,
    and `resolve_identity` re-derives capabilities from the role regardless."""
    agent_id: str
    role: str
    capabilities: frozenset
    engagement_id: str = ""
    agent_version: str = AGENT_VERSION
    # Set ONLY by `verification_grant`. Names the single command this identity is
    # authorised to run beyond its role. It is a command, never a capability and
    # never a finding-class: the gate recomputes the capability from these bytes,
    # so the identity cannot declare what it is owed.
    verifying_command: str = ""

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


def verification_grant(identity: AgentIdentity, command: str) -> AgentIdentity:
    """Authorise ONE command for a verifying principal.

    The verifier's job is to reproduce a finding independently, and some findings
    cannot be confirmed without performing the thing they describe — you cannot
    confirm an injection without injecting. Phase 1 gave `verify` only RECON, which
    made SUPPORTED structurally unreachable for the injection, auth and foothold
    classes (`agents/verify.py:106-111` returns UNVERIFIED whenever nothing ran).

    This grants no capability directly. It records the single command the action is
    for; the gate recomputes `required_capability(command)` from those bytes. So:

      * nothing persists — the base identity is untouched, and the elevation applies
        to one command in one action;
      * nothing is claimed — there is no parameter for a finding-class or a
        capability name, so a model cannot widen itself by asserting what it is
        confirming (invariant 1: no LLM in the capability decision);
      * only a verifying role may take it, or it would be a universal escape hatch.
    """
    if identity.role not in ROLES_THAT_MAY_VERIFY:
        return identity
    return replace(identity, verifying_command=command or "")


def resolve_identity(agent, command: str = "") -> AgentIdentity:
    """Coerce whatever a caller passed into a bound identity.

    Capabilities are ALWAYS re-derived from the role. A caller handing in an
    AgentIdentity with a self-declared capability set gains nothing — authority comes
    from ROLE_CAPABILITIES, never from the object claiming it.

    The one addition on top of the role's set is a verification grant, and it is
    self-validating: it applies only when the command being judged is byte-identical
    to the command the grant names, and the capability added is recomputed here from
    that command rather than read from the identity.
    """
    if isinstance(agent, AgentIdentity):
        caps = capabilities_for(agent.role)
        if (agent.verifying_command
                and agent.role in ROLES_THAT_MAY_VERIFY
                and command
                and agent.verifying_command == command):
            caps = caps | {required_capability(command)}
        return replace(agent, capabilities=caps)
    role = (str(agent or "")).strip().lower()
    return AgentIdentity(agent_id=f"{role or 'unnamed'}-unbound", role=role,
                         capabilities=capabilities_for(role))


def required_capability(command: str) -> str:
    """The single capability `command` needs. Deterministic; no LLM; fail-closed.

    Reuses risk.py's tool vocabulary rather than introducing a second classifier —
    one list to keep correct, and the capability boundary can never drift away from
    the risk boundary it is derived from.
    """
    tokens = _tokens(command)
    if not tokens:
        # Unparseable or empty -> most restrictive (invariant 2).
        return EXPLOITATION

    tool = os.path.basename(tokens[0]).lower()

    if tool in _INJECTION_TOOLS:
        return INJECTION_TEST
    if tool in _CREDENTIAL_TOOLS:
        return CREDENTIAL_TEST
    if tool in _NETEXEC_TOOLS:
        # Unauthenticated enumeration is recon; credentials, execution or dumping
        # are not. This is the boundary ad_enum_commands() already documents.
        # Case is LOAD-BEARING for short flags: -H (hash) is not -h (help), and
        # -X (powershell exec) is not -x (command exec) — both are privileged, but
        # lowercasing them once let `-H <hash>` through as plain recon. Long options
        # are normalised; short ones are compared exactly.
        flags = set()
        for tok in tokens[1:]:
            if not tok.startswith("-"):
                continue
            head = tok.split("=", 1)[0]
            flags.add(head if len(head) == 2 and not head.startswith("--")
                      else head.lower())
        return EXPLOITATION if flags & _NETEXEC_PRIVILEGED_FLAGS else RECON
    if tool in _ATTACK_TOOLS:
        return EXPLOITATION

    if tool in _READ_ONLY_TOOLS:
        # An nmap script category that exploits is exploitation, whatever the binary.
        if _script_categories(tokens) & _IRREVERSIBLE_SCRIPT_CATS:
            return EXPLOITATION
        if tool in _WEB_CLIENTS and _writes_over_http(tokens):
            return WEB_REQUEST
        return RECON

    # Unrecognised binary -> most restrictive. An unknown tool is never recon.
    return EXPLOITATION


# Web action kinds that only ever READ. Everything else either drives a
# state-changing interaction or is unrecognised, and both are handled below.
_READ_ONLY_WEB_KINDS = frozenset({"get", "navigate", "screenshot"})
# Kinds that drive or modify an interaction with the page/request.
_INTERACTIVE_WEB_KINDS = frozenset({"click", "fill", "eval", "intercept"})


def required_capability_for_web(action) -> str:
    """The capability one governed WEB action needs.

    The web plane took a different gate (`web.check_web`) and consulted no capability
    at all, so role separation held on the shell path and not here. This is the same
    decision procedure as `required_capability`, expressed over a WebAction instead of
    a command line: it shares the constants, shares `_HTTP_WRITE_METHODS`, and shares
    the fail-closed rule. It is deliberately NOT a second classifier with its own
    opinions.

    Note the symmetry with the shell path: a payload carried in a QUERY STRING is
    RECON in both places, because neither path inspects payload CONTENT. Detecting
    "this looks like SQLi" would be a content classifier over target-influenced text,
    which is exactly the kind of judgement the gate refuses to make (invariant 1).
    What is classified is the SHAPE of the action, which the attacker does not get to
    misrepresent.
    """
    kind = (getattr(action, "kind", "") or "").strip().lower()
    if kind in _READ_ONLY_WEB_KINDS:
        return RECON
    if kind == "request":
        method = (getattr(action, "method", "") or "GET").strip().lower()
        if getattr(action, "body", "") or method in _HTTP_WRITE_METHODS:
            return WEB_REQUEST
        return RECON
    if kind in _INTERACTIVE_WEB_KINDS:
        return WEB_REQUEST
    # Unrecognised kind -> most restrictive (invariant 2).
    return EXPLOITATION


def _writes_over_http(tokens: list[str]) -> bool:
    """A curl/wget invocation that sends a body or a write method changes remote
    state. Mirrors the signals risk.derive_reversibility already uses."""
    lowered = [t.lower() for t in tokens]
    for i, tok in enumerate(lowered):
        if tok in ("-x", "--request") and i + 1 < len(lowered):
            if lowered[i + 1] in _HTTP_WRITE_METHODS:
                return True
        if tok.startswith("--request="):
            if tok.split("=", 1)[1] in _HTTP_WRITE_METHODS:
                return True
        if tok in _CURL_BODY_FLAGS or any(
                tok.startswith(f + "=") for f in _CURL_BODY_FLAGS):
            return True
        if tok in ("--method", "--post-data", "--post-file"):
            return True
    return False
