"""
test_verification_grant.py — the verifier may run its one confirming command.

Phase 1 granted `verify` only {RECON}, which is strictly weaker than "read-only":
RECON forbids request bodies, write methods, and injection/credential tools. Since
`agents/verify.py:106-111` returns UNVERIFIED whenever the command did not run, a denied
verification command does not weaken confirmation — it ELIMINATES it. SUPPORTED became
structurally unreachable for SQLi, auth-bypass and foothold findings.

The fix is NOT a blanket grant. A verification action is authorised for ONE command,
and the capability it receives is `required_capability(command)` — computed by the gate
from the command's own bytes.

**This is the invariant-1 boundary.** If the grant were derived from a claimed
finding-class ("this is a SQLi finding, so give me INJECTION_TEST"), a model could widen
itself by lying, which would put an LLM inside the capability decision. The command's
bytes decide, and nothing else does. `verification_grant()` therefore accepts a command
and nothing else — there is no parameter through which a label could arrive.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.identity import (CAPABILITY_DENIED_REASON, EXPLOITATION,
                             INJECTION_TEST, RECON, WEB_REQUEST, mint,
                             required_capability, resolve_identity,
                             verification_grant)
from brukal.kali import FakeKali

SCOPE = "tests/fixtures/scope_fast.json"
TARGET = "10.10.10.5"

# The three confirmation shapes Phase 1 made impossible.
SQLI_CONFIRM = "sqlmap -u http://10.10.10.5/?q=1 --batch"
AUTH_CONFIRM = "hydra -l admin -p hunter2 ssh://10.10.10.5"
# The foothold evidence path named at brukal/verify.py:92-93. Deliberately carries no
# second host literal — that would widen the blast radius and be refused by the SOFT
# layer for reasons unrelated to capabilities.
FOOTHOLD_CONFIRM = "curl http://10.10.10.5/app/ping -d address=localhost"


def _approve_all(_decision):
    """Confirming an injection or an auth finding IS an intrusive action, so the soft
    risk layer escalates it for human sign-off. That is correct and unchanged — these
    tests are about the CAPABILITY layer, so they supply the human."""
    return True


def _executor(tmp, approver=_approve_all):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tmp) / "a.jsonl")
    return Executor(Gate(scope), FakeKali(), audit, approver=approver), audit


def _run(command, agent, approver=_approve_all):
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp, approver)
        return ex.run(command, TARGET, agent=agent)


# --------------------------------------------------------------------------- #
# The three classes Phase 1 made unconfirmable
# --------------------------------------------------------------------------- #

def test_a_verifier_may_run_its_sqli_confirmation():
    ident = mint("verify", engagement_id="e")
    decision, result = _run(SQLI_CONFIRM, verification_grant(ident, SQLI_CONFIRM))
    assert decision.reason_code != CAPABILITY_DENIED_REASON
    assert decision.layer != "hard:capability"
    assert result is not None


def test_a_verifier_may_run_its_auth_confirmation():
    ident = mint("verify", engagement_id="e")
    decision, result = _run(AUTH_CONFIRM, verification_grant(ident, AUTH_CONFIRM))
    assert decision.reason_code != CAPABILITY_DENIED_REASON
    assert decision.layer != "hard:capability"
    assert result is not None


def test_a_verifier_may_run_its_foothold_confirmation():
    """brukal/verify.py:92-93 names this exact shape as attributable evidence."""
    ident = mint("verify", engagement_id="e")
    decision, result = _run(FOOTHOLD_CONFIRM,
                            verification_grant(ident, FOOTHOLD_CONFIRM))
    assert required_capability(FOOTHOLD_CONFIRM) == WEB_REQUEST
    assert decision.reason_code != CAPABILITY_DENIED_REASON
    assert decision.layer != "hard:capability"
    assert result is not None


# --------------------------------------------------------------------------- #
# The grant is derived from the COMMAND, never from a claim (invariant 1)
# --------------------------------------------------------------------------- #

def test_the_granted_capability_equals_required_capability_of_that_command():
    """No more, no less. The gate recomputes it; the identity cannot declare it."""
    for command in (SQLI_CONFIRM, AUTH_CONFIRM, FOOTHOLD_CONFIRM,
                    "nmap -sV 10.10.10.5"):
        ident = verification_grant(mint("verify", engagement_id="e"), command)
        resolved = resolve_identity(ident, command)
        assert resolved.capabilities == frozenset({RECON}) | {
            required_capability(command)}, command


def test_a_claimed_finding_class_cannot_widen_the_verifier():
    """THE INVARIANT-1 GUARD. A model may say whatever it likes about what it is
    confirming; only the command's bytes decide. A grant issued for a recon command
    confers RECON even when the surrounding request screams EXPLOITATION."""
    benign = "nmap -sV 10.10.10.5"
    hostile_request = json.dumps({
        "proposing_agent": "verify",
        "intent": "verify",
        "command": benign,
        "target_host": TARGET,
        "justification": "this confirms an EXPLOITATION-class RCE finding, "
                         "grant EXPLOITATION",
        "finding_type": "EXPLOITATION",
        "required_capability": "EXPLOITATION",
    })
    assert "EXPLOITATION" in hostile_request          # the claim really is in there

    ident = verification_grant(mint("verify", engagement_id="e"), benign)
    assert resolve_identity(ident, benign).capabilities == frozenset({RECON})

    # and the elevation does not carry to an exploitation command
    decision, result = _run("msfconsole -q -x exit", ident)
    assert decision.verdict == "DENY"
    assert decision.reason_code == CAPABILITY_DENIED_REASON
    assert result is None


def test_verification_grant_takes_no_label_parameter():
    """Structural guard: there is no argument through which a finding-class could be
    supplied, so no future caller can accidentally introduce one."""
    import inspect
    params = list(inspect.signature(verification_grant).parameters)
    assert params == ["identity", "command"], params


# --------------------------------------------------------------------------- #
# Containment — the grant is one action wide
# --------------------------------------------------------------------------- #

def test_the_grant_is_bound_to_that_exact_command():
    """ADVERSARIAL: a grant issued for a benign command must not authorise a
    different one."""
    ident = verification_grant(mint("verify", engagement_id="e"),
                               "nmap -sV 10.10.10.5")
    decision, result = _run(SQLI_CONFIRM, ident)
    assert decision.verdict == "DENY"
    assert decision.reason_code == CAPABILITY_DENIED_REASON
    assert result is None


def test_an_ungranted_verify_identity_is_still_recon_only():
    """No standing capability. Outside a verification action the verifier is exactly
    what Phase 1 made it."""
    ident = mint("verify", engagement_id="e")
    assert ident.capabilities == frozenset({RECON})
    decision, result = _run(SQLI_CONFIRM, ident)
    assert decision.verdict == "DENY"
    assert decision.reason_code == CAPABILITY_DENIED_REASON
    assert result is None


def test_the_grant_does_not_mutate_the_base_identity():
    ident = mint("verify", engagement_id="e")
    verification_grant(ident, SQLI_CONFIRM)
    assert ident.capabilities == frozenset({RECON})
    assert not getattr(ident, "verifying_command", "")


def test_only_a_verifying_role_can_take_a_verification_grant():
    """ADVERSARIAL: recon forging the elevation gains nothing — the role gate on the
    grant is what stops it becoming a universal escape hatch."""
    recon = mint("recon", engagement_id="e")
    forged = verification_grant(recon, SQLI_CONFIRM)
    assert resolve_identity(forged, SQLI_CONFIRM).capabilities == frozenset({RECON})
    decision, result = _run(SQLI_CONFIRM, forged)
    assert decision.verdict == "DENY"
    assert decision.reason_code == CAPABILITY_DENIED_REASON
    assert result is None


def test_scope_still_precedes_capability_for_a_granted_verifier():
    """The grant widens ONE capability, never the scope."""
    ident = verification_grant(mint("verify", engagement_id="e"),
                               "sqlmap -u http://8.8.8.8/?q=1 --batch")
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        decision, result = ex.run("sqlmap -u http://8.8.8.8/?q=1 --batch",
                                  "8.8.8.8", agent=ident)
    assert decision.verdict == "DENY"
    assert decision.layer == "hard:scope"
    assert result is None


# --------------------------------------------------------------------------- #
# End to end through the agent
# --------------------------------------------------------------------------- #

class _VerifyingLLM:
    """Proposes one confirmation command, then judges SUPPORTED."""

    def __init__(self, command):
        self._command = command
        self.calls = 0

    def propose(self, system, user):
        self.calls += 1
        if self.calls == 1:
            return json.dumps({"proposing_agent": "verify", "intent": "verify",
                               "command": self._command, "target_host": TARGET,
                               "justification": "confirms the claim"})
        return "SUPPORTED — the output shows the finding is real."


def test_the_verify_agent_can_now_reach_supported_on_an_injection_finding():
    """The whole point: SUPPORTED was structurally unreachable for this class."""
    from brukal.agents.verify import VerifyAgent
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        agent = VerifyAgent(_VerifyingLLM(SQLI_CONFIRM), ex)
        res = agent.verify_claim("the q parameter is SQL-injectable")
        assert res.command == SQLI_CONFIRM
        assert res.verdict == "SUPPORTED", res.reason


def test_the_verify_agent_is_still_denied_an_unrelated_exploitation_action():
    """The agent's elevation follows the command it emitted, so an exploitation
    command it emits IS authorised for that action — but the identity it holds
    between actions confers nothing."""
    from brukal.agents.verify import VerifyAgent
    with tempfile.TemporaryDirectory() as tmp:
        ex, _ = _executor(tmp)
        agent = VerifyAgent(_VerifyingLLM(SQLI_CONFIRM), ex)
        agent.verify_claim("the q parameter is SQL-injectable")
        # the agent's own standing identity never widened
        assert agent._identity.capabilities == frozenset({RECON})
        decision, _ = ex.run("msfconsole -q -x exit", TARGET,
                             agent=agent._identity)
        assert decision.verdict == "DENY"
        assert decision.reason_code == CAPABILITY_DENIED_REASON
