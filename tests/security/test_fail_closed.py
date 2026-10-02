# tests/security/test_fail_closed.py   (test fns take the `record` conftest fixture)
"""Invariant I2 — malformed / ambiguous / unsupported input must NOT execute.

"The action request" tested here is the schema-validated agent Action Request
(brukal/schema.py: ActionRequest via parse_action_request) followed by the shell
gate (Gate.check) — the exact path Recon/Exploit agents use before Executor.run.
The WebAction/check_web path is a separate dataclass door (no schema validation)
and is covered by the web-gate tests, not here.

_resolve() reimplements nothing: it calls the real parser and the real gate.
  parse exception            -> "ERROR"   (handled; nothing executed)
  parse returns None         -> "ERROR"   (the documented "no valid proposal" no-op)
  otherwise Gate.check(...)  -> its verdict (ALLOW / DENY / ESCALATE)
"""
import ipaddress
import json

import pytest
from brukal.gate import Gate
from brukal.schema import parse_action_request
from brukal.scope import Scope

IN_HOST = "10.10.10.10"


def _scope():
    return Scope(engagement="security-audit",
                 authorized_networks=(ipaddress.ip_network("10.10.10.0/24"),),
                 allowlisted_tools=frozenset({"nmap"}),
                 rate_limit_per_min=30,
                 authorized_hosts=frozenset())


def _valid_in_scope_action() -> dict:
    return {"proposing_agent": "recon", "intent": "enumerate",
            "command": f"nmap -n {IN_HOST}", "target_host": IN_HOST,
            "justification": "benign in-scope scan"}


def _resolve(payload) -> str:
    """Run the REAL parse + gate path; map the outcome to a verdict string."""
    text = json.dumps(payload) if isinstance(payload, dict) else payload
    try:
        req = parse_action_request(text)
        if req is None:
            return "ERROR"
        # Gate.check is what Executor.run calls; a fresh Gate per case => no rate-limit bleed.
        return Gate(_scope()).check(req.command, req.target_host, req.proposing_agent).verdict
    except Exception:
        return "ERROR"


def _v(**over) -> dict:
    d = _valid_in_scope_action()
    d.update(over)
    return d


MALFORMED = [
    ("bad json", "{not json"),
    ("truncated json", '{"proposing_agent": "recon", "intent": "enum'),
    ("missing required field", {"proposing_agent": "recon", "intent": "enumerate"}),
    ("missing command", {k: v for k, v in _valid_in_scope_action().items() if k != "command"}),
    ("missing target_host", {k: v for k, v in _valid_in_scope_action().items() if k != "target_host"}),
    ("null command", _v(command=None)),
    ("null target_host", _v(target_host=None)),
    ("null agent", _v(proposing_agent=None)),
    ("type confusion: target int", _v(target_host=12345)),
    ("type confusion: command list", _v(command=["nmap", IN_HOST])),
    ("type confusion: port string", _v(target_port="80; id")),
    ("type confusion: port object", _v(target_port={"a": 1})),
    ("invalid enum intent", _v(intent="no_such_kind")),
    ("intent case variant", _v(intent="ENUMERATE")),
    ("empty intent", _v(intent="")),
    ("oversized target", _v(target_host="A" * 100000)),
    ("unicode: shell chain in target", _v(target_host=f"{IN_HOST} ; rm -rf /")),
    ("unicode: NUL byte in command", _v(command=f"nmap -n {IN_HOST}\x00 8.8.8.8")),
    ("unicode: fullwidth host", _v(command="nmap -n １０.１０.１０.１０", target_host="１０.１０.１０.１０")),
    ("empty object", {}),
    ("empty string", ""),
    ("whitespace only", "   \n\t "),
    ("json null", "null"),
    ("json array", "[1, 2, 3]"),
    ("json scalar", "12345"),
    ("empty command", _v(command="")),
    ("empty target_host", _v(target_host="")),
    ("NaN port", '{"proposing_agent":"recon","intent":"enumerate","command":"nmap -n 10.10.10.10","target_host":"10.10.10.10","target_port":NaN}'),
    ("deeply nested", '{"a":' * 5000 + "1" + "}" * 5000),
    ("non-string input (None)", None),
    ("non-string input (int)", 12345),
    ("unknown agent role", _v(proposing_agent="root")),
    ("empty agent role", _v(proposing_agent="")),
    ("out-of-scope target, valid shape", _v(command="nmap -n 8.8.8.8", target_host="8.8.8.8")),
    ("smuggled second host", _v(command=f"nmap -n {IN_HOST} 8.8.8.8")),
]


# Valid in-scope commands whose ONLY oddity is benign: they must ALLOW (asserted below).
# Execution is argv-based (DockerKali.run -> shlex.split, NO shell), so neither can start a
# second command or reach another target.
#  * oversized arg: an unbounded-length argument is at most a bounded-resource/robustness
#    observation (cage kills at 180s), NOT an authorization bypass.
#  * U+2028: not a shlex separator (only " \t\r\n"), so it stays inside one token -> nmap gets one
#    unresolvable hostname; extract_hosts splits on \s+ (which DOES match U+2028) so any
#    pieces are scope-checked anyway.
_LS = chr(0x2028)
EXPECT_ALLOW = [
    ("oversized command arg", _v(command="nmap -n " + IN_HOST + " " + "A" * 100000)),
    ("unicode: line-separator in command", _v(command=f"nmap -n {IN_HOST}{_LS}rm -rf /")),
]
_PARAMS = [pytest.param(d, p, id=d) for d, p in MALFORMED]


@pytest.mark.parametrize("desc,payload", EXPECT_ALLOW, ids=[m[0] for m in EXPECT_ALLOW])
def test_benign_oddity_in_scope_command_correctly_allows(record, desc, payload):
    outcome = _resolve(payload)
    record(f"fail-closed::{desc}", "fail-closed", "I2", repr(payload)[:120],
           "ALLOW", outcome, "n/a")
    assert outcome == "ALLOW"


@pytest.mark.parametrize("desc,payload", _PARAMS)
def test_malformed_action_never_allows(record, desc, payload):
    outcome = _resolve(payload)
    record(f"fail-closed::{desc}", "fail-closed", "I2", repr(payload)[:120],
           "not ALLOW", outcome, "critical")
    assert outcome in ("DENY", "ESCALATE", "ERROR"), f"{desc} resolved to {outcome}"


def test_extra_field_is_inert_and_cannot_widen_authority(record):
    """Unexpected extra fields are ignored by the schema (pydantic default). That is only
    safe if they cannot change the verdict: the extra-field request must resolve exactly
    as the same request without it, and must not rescue an otherwise-denied one."""
    extras = {"evil": "x", "capabilities": ["EXPLOIT"], "scope": "0.0.0.0/0",
              "destructive_allowed": True}
    same = _resolve({**_valid_in_scope_action(), **extras})
    base = _resolve(_valid_in_scope_action())
    denied = _resolve({**_v(command="nmap -n 8.8.8.8", target_host="8.8.8.8"), **extras})
    record("fail-closed::unexpected extra field", "fail-closed", "I2",
           "valid action + extra fields", "no widening", f"{same}/{denied}", "critical")
    assert same == base, "extra fields changed the verdict"
    assert denied == "DENY", f"extra fields rescued an out-of-scope action: {denied}"


def test_positive_control_wellformed_in_scope_action_allows(record):
    outcome = _resolve(_valid_in_scope_action())
    record("fail-closed::positive", "fail-closed", "I2", "<valid in-scope action>", "ALLOW", outcome, "n/a")
    assert outcome == "ALLOW"


def test_positive_control_fenced_json_with_prose_allows(record):
    """Second control: the parser's documented tolerance (prose + code fence) still works,
    proving ERROR/DENY above are not just 'everything rejected'."""
    text = "Here is my plan:\n```json\n" + json.dumps(_valid_in_scope_action()) + "\n```"
    outcome = _resolve(text)
    record("fail-closed::positive-fenced", "fail-closed", "I2", "fenced valid action", "ALLOW", outcome, "n/a")
    assert outcome == "ALLOW"
