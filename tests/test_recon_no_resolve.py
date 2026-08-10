"""
test_recon_no_resolve.py — under a scoped egress lock, name resolution can only
ever time out, so a proposed nmap command must carry `-n` whether or not the model
remembered it.

THE PROPERTY
    The egress lock permits tun0, the pinned VPN server and the scope IP, and nothing
    else. A resolver is therefore unreachable BY CONSTRUCTION. nmap without `-n` tries
    reverse-DNS on its target, the lookup hangs, and `Executor.run` kills the command at
    its 180s cap. The command returns `exit 124` with `Starting Nmap ...` and nothing
    else — indistinguishable from an unreachable host.

WHY THIS IS A RULE AND NOT A PROMPT
    The model has been told. It forgot three times: on 10.129.100.21, on 10.129.100.61,
    and on 10.129.101.3 — where 14 of 14 shell commands failed (7x rc=124), the loop
    never reached the web plane, and the strategist then self-diagnosed the cause
    WRONGLY as an output-file permission wall. A correctness property that a model must
    remember is not a property; it is a hope. So the flag is applied by deterministic
    command normalisation, with no model in the path.

Measured: the same scan WITH `-n` completes in 0.34s and finds 21/22/80 open.
"""
from __future__ import annotations

from brukal.agents.strategist import parse_options
from brukal.schema import apply_no_resolve, parse_action_request


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #

def test_an_nmap_command_without_n_is_given_n():
    """THE DEFECT. This is the command shape that burned three engagements."""
    out = apply_no_resolve("nmap -Pn -sS --top-ports 1000 10.129.101.3")
    assert " -n " in f" {out} ", f"nmap was left able to resolve: {out!r}"
    assert out.startswith("nmap "), out
    assert "--top-ports 1000" in out and "10.129.101.3" in out, \
        f"normalisation damaged the command: {out!r}"


def test_an_nmap_command_that_already_has_n_is_unchanged():
    """Idempotent — the rule must not stack duplicate flags on repeated passes."""
    original = "nmap -Pn -n -sT --top-ports 20 10.129.101.3"
    assert apply_no_resolve(original) == original
    assert apply_no_resolve(apply_no_resolve(original)) == original


def test_a_non_nmap_command_is_untouched():
    """The rule is an explicit per-tool allowlist, not a general flag heuristic."""
    for cmd in ("whatweb http://10.129.101.3/",
                "nikto -host http://10.129.101.3/ -maxtime 120",
                "curl -s http://10.129.101.3/data/1",
                ""):
        assert apply_no_resolve(cmd) == cmd, f"unrelated command was rewritten: {cmd!r}"


def test_a_tool_whose_name_merely_contains_nmap_is_untouched():
    """`nmap` must be matched as the program, not as a substring."""
    assert apply_no_resolve("zenmap-report --in x") == "zenmap-report --in x"
    assert apply_no_resolve("echo nmap is a scanner") == "echo nmap is a scanner"


def test_the_rule_is_off_when_the_egress_lock_is_off(monkeypatch):
    """Without the lock a resolver is reachable, so resolution is a legitimate choice
    and Brukal does not silently override the operator."""
    monkeypatch.setenv("BRUKAL_EGRESS_LOCK", "0")
    cmd = "nmap -Pn -sS --top-ports 100 10.129.101.3"
    assert apply_no_resolve(cmd) == cmd


def test_the_rule_is_on_by_default(monkeypatch):
    """Fail-closed: the lock is on unless explicitly disabled, and so is the rule."""
    monkeypatch.delenv("BRUKAL_EGRESS_LOCK", raising=False)
    assert " -n " in f" {apply_no_resolve('nmap -Pn 10.129.101.3')} "


# --------------------------------------------------------------------------- #
# Wired into the real proposal paths — a helper nothing calls fixes nothing
# --------------------------------------------------------------------------- #

def test_a_parsed_action_request_carries_the_normalised_command():
    """The recon / exploit / verify agents propose through parse_action_request."""
    req = parse_action_request(
        '{"proposing_agent": "recon", "intent": "enumerate", '
        '"command": "nmap -Pn -sS --top-ports 1000 10.129.101.3", '
        '"target_host": "10.129.101.3"}')
    assert req is not None
    assert " -n " in f" {req.command} ", \
        f"the agent path still proposes a resolving nmap: {req.command!r}"


def test_a_strategist_suggestion_carries_the_normalised_command():
    """The auto loop proposes through the strategist's RUN: line — the path that
    actually issued all 14 failing commands on 10.129.101.3."""
    opts = parse_options("PHASE: recon\nGOAL: sweep\n"
                         "RUN: nmap -Pn -sS -p- 10.129.101.3\n", "10.129.101.3")
    assert opts and opts[0].command
    assert " -n " in f" {opts[0].command} ", \
        f"the auto-loop path still proposes a resolving nmap: {opts[0].command!r}"
