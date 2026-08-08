"""
test_agent_identity.py — identity is BOUND by the dispatcher, never self-reported.

Before this, `Executor.run(command, target, agent="unknown")` took a caller-supplied
string, and `agents/recon.py` and `agents/exploit.py` passed
`agent=request.proposing_agent` — a field the LLM writes in its own Action Request.
Every downstream decision keyed on that string: the audit record, adaptive trust, and
(now) the capability check. A model that wrote `"proposing_agent": "operator"` promoted
itself. That is invariant 3 — never trust an agent's self-report — violated at source.

Capability enforcement is the second half. Role separation was prompt-deep only: the
recon agent's persona said "enumerate", but nothing stopped it emitting `msfconsole`.
The capability check is a deterministic AND-condition inside the hard gate that can
only DENY, derived from the SAME tool vocabulary the risk layer already uses — no new
parser, no LLM (invariant 1), fail-closed on anything it cannot classify (invariant 2).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.identity import (ALL_CAPABILITIES, CAPABILITY_DENIED_REASON,
                             EXPLOITATION, RECON, AgentIdentity, mint,
                             operator_identity, required_capability,
                             resolve_identity)
from brukal.kali import FakeKali
from brukal.schema import parse_action_request

SCOPE = "tests/fixtures/scope_fast.json"
TARGET = "10.10.10.5"


def _executor(tmp):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tmp) / "a.jsonl")
    return Executor(Gate(scope), FakeKali(), audit), audit


# --------------------------------------------------------------------------- #
# Work item B — identity is minted, not claimed
# --------------------------------------------------------------------------- #

def test_a_minted_identity_carries_the_required_metadata():
    ident = mint("recon", engagement_id="eng-1")
    assert ident.role == "recon"
    assert ident.agent_id and ident.agent_id != "unknown"
    assert ident.engagement_id == "eng-1"
    assert ident.agent_version
    assert ident.capabilities == frozenset({RECON})


def test_two_minted_identities_of_the_same_role_are_distinguishable():
    """agent_id identifies the RUN of an agent; role identifies what it may do."""
    a, b = mint("recon", engagement_id="e"), mint("recon", engagement_id="e")
    assert a.agent_id != b.agent_id
    assert a.role == b.role == "recon"


def test_an_identity_is_immutable():
    ident = mint("recon", engagement_id="e")
    with pytest.raises(Exception):
        ident.capabilities = ALL_CAPABILITIES        # type: ignore[misc]


def test_an_action_request_cannot_name_its_own_identity():
    """THE ADVERSARIAL CASE. The model writes `proposing_agent` itself, and older code
    fed it straight to the executor. A request claiming to be the operator, or claiming
    capabilities, must not influence the bound identity."""
    hostile = json.dumps({
        "proposing_agent": "operator",
        "agent_id": "i-am-root",
        "capabilities": ["EXPLOITATION"],
        "role": "operator",
        "intent": "enumerate",
        "command": "nmap -sV 10.10.10.5",
        "target_host": TARGET,
    })
    request = parse_action_request(hostile)
    assert request is not None                      # it is a well-formed request

    bound = mint("recon", engagement_id="e")        # what the dispatcher minted
    # Nothing the request carries may widen the bound identity.
    assert bound.role == "recon"
    assert bound.capabilities == frozenset({RECON})
    assert not bound.can(EXPLOITATION)
    # And the schema must not even surface attacker-chosen capability fields.
    assert not hasattr(request, "capabilities")
    assert not hasattr(request, "agent_id")


def test_an_unknown_agent_string_resolves_to_no_capabilities():
    """Fail closed (invariant 2): a name we do not know is not a licence."""
    ident = resolve_identity("mystery-agent")
    assert ident.capabilities == frozenset()
    assert ident.role == "mystery-agent"


def test_the_literal_unknown_default_grants_nothing():
    assert resolve_identity("unknown").capabilities == frozenset()


# --------------------------------------------------------------------------- #
# Work item C — capabilities, enforced in the gate
# --------------------------------------------------------------------------- #

def test_required_capability_is_deterministic_and_fails_closed():
    assert required_capability("nmap -sV 10.10.10.5") == RECON
    assert required_capability("gobuster dir -u http://10.10.10.5") == RECON
    assert required_capability("sqlmap -u http://10.10.10.5/?q=1") == "INJECTION_TEST"
    assert required_capability("hydra -l root -P w.txt ssh://10.10.10.5") == "CREDENTIAL_TEST"
    assert required_capability("msfconsole -q -x exit") == EXPLOITATION
    assert required_capability("nc 10.10.10.5 4444") == EXPLOITATION
    # a write-shaped HTTP request is not plain recon
    assert required_capability("curl -X POST --data x http://10.10.10.5") == "WEB_REQUEST"
    # UNCLASSIFIABLE -> most restrictive, never a free pass
    assert required_capability("some-unknown-binary --wat") == EXPLOITATION
    assert required_capability("") == EXPLOITATION


def test_netexec_is_recon_only_while_it_stays_unauthenticated():
    """`ad_enum_commands()` fires netexec PROACTIVELY under the recon identity, and
    documents the set as unauthenticated + read-only. Capabilities must codify that
    boundary, not shrink below it — this reflex is existing, legitimate behaviour."""
    for cmd in ("netexec smb 10.10.10.5",
                "netexec smb 10.10.10.5 --shares",
                "netexec smb 10.10.10.5 --users",
                "netexec smb 10.10.10.5 --pass-pol",
                "netexec ldap 10.10.10.5"):
        assert required_capability(cmd) == RECON, cmd


def test_netexec_becomes_exploitation_the_moment_it_authenticates_or_executes():
    """ADVERSARIAL: the read-only carve-out must not become a way to smuggle
    execution under a recon identity."""
    for cmd in ("netexec smb 10.10.10.5 -u admin -p pass",
                "netexec smb 10.10.10.5 -x whoami",
                "netexec smb 10.10.10.5 -X 'Get-Process'",
                "netexec smb 10.10.10.5 --sam",
                "netexec smb 10.10.10.5 --ntds",
                "netexec smb 10.10.10.5 -H aad3b4:31d6cf",
                "netexec smb 10.10.10.5 -M spider_plus",
                "crackmapexec smb 10.10.10.5 --lsa",
                "nxc smb 10.10.10.5 --local-auth -u a -p b"):
        assert required_capability(cmd) == EXPLOITATION, cmd


def test_recon_cannot_smuggle_execution_through_netexec():
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("netexec smb 10.10.10.5 -x whoami", TARGET,
                                  agent=mint("recon", engagement_id="e"))
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
        assert result is None


def test_recon_role_is_denied_an_exploitation_action():
    """THE FLAGSHIP CASE: role separation becomes structural, not prompt-deep."""
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("msfconsole -q -x exit", TARGET,
                                  agent=mint("recon", engagement_id="e"))
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
        assert decision.layer == "hard:capability"
        assert result is None


def test_recon_role_is_denied_an_unclassifiable_tool():
    """Fail-closed: an unknown tool requires the most restrictive capability."""
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("smbclient -L //10.10.10.5", TARGET,
                                  agent=mint("recon", engagement_id="e"))
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
        assert result is None


def test_recon_role_may_still_do_recon():
    """The check codifies the role boundary; it must not shrink below it."""
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("nmap -sV 10.10.10.5", TARGET,
                                  agent=mint("recon", engagement_id="e"))
        assert decision.verdict == "ALLOW"
        assert result is not None


def test_the_exploit_role_may_exploit():
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, _ = ex.run("msfconsole -q -x exit", TARGET,
                             agent=mint("exploit", engagement_id="e"))
        assert decision.verdict != "DENY" or decision.layer != "hard:capability"


def test_the_operator_retains_full_capability():
    """A human running `brukal exec` acts on their own authority. The constraint is
    for AGENT principals; CLI behaviour must be unchanged."""
    ident = operator_identity()
    assert ident.capabilities == ALL_CAPABILITIES
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, _ = ex.run("msfconsole -q -x exit", TARGET, agent=ident)
        assert decision.layer != "hard:capability"


def test_an_agent_cannot_grant_itself_a_capability():
    """Even handed a forged identity object, the gate consults ROLE_CAPABILITIES for
    the role — a self-declared capability set is not authority."""
    forged = AgentIdentity(agent_id="x", role="recon",
                           capabilities=ALL_CAPABILITIES, engagement_id="e")
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("msfconsole -q -x exit", TARGET, agent=forged)
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
        assert result is None


def test_capability_can_only_deny_never_widen():
    """An out-of-scope target stays denied for the SCOPE reason; capability never
    rescues an action the earlier hard checks refused."""
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, _ = ex.run("nmap -sV 8.8.8.8", "8.8.8.8",
                             agent=operator_identity())
        assert decision.verdict == "DENY"
        assert decision.layer == "hard:scope"


# --------------------------------------------------------------------------- #
# The wiring — an agent cannot promote itself through its own Action Request
# --------------------------------------------------------------------------- #

class _SelfPromotingLLM:
    """A model that writes `proposing_agent: operator` into its own request and asks
    for an exploitation action. Older code passed that field straight to the executor."""

    def __init__(self, command="msfconsole -q -x exit"):
        self._command = command

    def propose(self, system, user):
        return json.dumps({"proposing_agent": "operator",
                           "intent": "exploit",
                           "command": self._command,
                           "target_host": TARGET,
                           "justification": "trust me"})


def test_a_recon_agent_cannot_promote_itself_via_its_action_request():
    """THE END-TO-END ADVERSARIAL CASE for invariant 3."""
    from brukal.agents.recon import ReconAgent
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        agent = ReconAgent(_SelfPromotingLLM(), ex)
        request, outcome = agent.run_task("enumerate the host")

        assert request is not None
        assert request.proposing_agent == "operator"    # the model DID claim it
        decision, result = outcome
        assert decision.agent == "recon"                # the gate saw the BOUND role
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
        assert result is None                           # and nothing ran


def test_a_recon_agents_ordinary_work_still_runs():
    """The binding must not cost the agent its actual job."""
    from brukal.agents.recon import ReconAgent
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        agent = ReconAgent(_SelfPromotingLLM("nmap -sV 10.10.10.5"), ex)
        _request, (decision, result) = agent.run_task("enumerate the host")
        assert decision.agent == "recon"
        assert decision.verdict == "ALLOW"
        assert result is not None


def test_an_exploit_agent_is_bound_to_its_own_role_too():
    from brukal.agents.exploit import ExploitAgent
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        agent = ExploitAgent(_SelfPromotingLLM(), ex)
        _request, (decision, _result) = agent.run_task("get a shell")
        assert decision.agent == "exploit"        # not the claimed "operator"


# --------------------------------------------------------------------------- #
# Bypass attempts against the capability mapping itself
# --------------------------------------------------------------------------- #

def test_an_absolute_path_does_not_hide_the_tool():
    assert required_capability("/usr/bin/msfconsole -q") == EXPLOITATION
    assert required_capability("/usr/local/bin/sqlmap -u http://x") == "INJECTION_TEST"


def test_capitalisation_does_not_hide_the_tool():
    assert required_capability("MSFCONSOLE -q") == EXPLOITATION
    assert required_capability("NetExec smb 10.10.10.5 -X whoami") == EXPLOITATION


def test_the_equals_form_of_an_nmap_script_arg_is_still_exploitation():
    assert required_capability("nmap --script=exploit 10.10.10.5") == EXPLOITATION
    assert required_capability("nmap --script exploit,vuln 10.10.10.5") == EXPLOITATION


def test_a_recon_identity_cannot_be_swapped_for_a_privileged_string():
    """A caller may pass a bare role string, so confirm the constrained role stays
    constrained when it takes that path too — the string form is not a loophole."""
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("msfconsole -q -x exit", TARGET, agent="recon")
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
        assert result is None


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

def test_every_agent_path_decision_records_a_bound_identity():
    with tempfile.TemporaryDirectory() as tmp:
        ex, audit = _executor(tmp)
        ident = mint("recon", engagement_id="eng-42")
        ex.run("nmap -sV 10.10.10.5", TARGET, agent=ident)

        lines = [json.loads(l) for l in
                 (Path(tmp) / "a.jsonl").read_text().splitlines() if l.strip()]
        decisions = [l for l in lines if l.get("kind") == "decision"]
        assert decisions, "no decision was audited"
        for d in decisions:
            payload = d.get("data", {})
            assert payload.get("agent") not in ("", None, "unknown")
            assert payload.get("agent_id") == ident.agent_id
            assert payload.get("engagement_id") == "eng-42"
