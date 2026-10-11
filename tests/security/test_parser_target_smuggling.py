# tests/security/test_parser_target_smuggling.py   (I3: the gate evaluates every ACTUAL target)
import ipaddress

import pytest
from brukal.gate import Gate
from brukal.scope import Scope

IN = "10.10.10.10"
OUT = "10.10.10.11"   # NOT in a single-host scope of IN
OUT6 = "2001:db8::1"


def _scope(host):
    return Scope(engagement="security-audit",
                 authorized_networks=(ipaddress.ip_network(host + "/32"),),
                 allowlisted_tools=frozenset({"nmap", "curl", "nc", "bash", "echo", "tee"}),
                 rate_limit_per_min=1000)


def _gate_verdict(cmd, scope_host, door="check"):
    """Thin wrapper over the REAL gate (Gate.check / Gate.check_session).
    Maps the Decision to ALLOW/DENY/ESCALATE/ERROR; no target extraction here."""
    gate = Gate(_scope(scope_host))
    try:
        if door == "check":
            d = gate.check(cmd, scope_host, agent="recon")
        else:
            d = gate.check_session(cmd, scope_host)
    except Exception:
        return "ERROR"
    return d.verdict if d.verdict in ("ALLOW", "DENY", "ESCALATE") else "ERROR"


CASES = [
    (f"nmap {IN} {OUT}", "second positional target"),
    (f"nmap {IN}; curl {OUT}", "; chain"),
    (f"nmap {IN} && nc {OUT} 80", "&& chain"),
    (f"nmap {IN} | tee /tmp/x; curl {OUT}", "pipe + chain"),
    (f"bash -c 'curl {OUT}'", "nested shell"),
    (f"curl $(echo {OUT})", "command substitution"),
    (f"curl `echo {OUT}`", "backtick substitution"),
    (f"nmap {IN} 10.10.10.0/24", "CIDR expands past single host"),
    (f"curl http://{OUT}/", "url target"),
    (f"nmap {IN} {OUT6}", "out-of-scope IPv6"),
    (f"curl http://[{OUT6}]/", "bracketed IPv6 url"),
    (f"nmap {IN} 168430091", "decimal-encoded OUT"),
    (f"nmap {IN} 0xa0a0a0b", "hex-encoded OUT"),
    (f"nmap {IN} {OUT}/32", "CIDR /32 of OUT"),
    (f"nmap {IN} 10.10.10.11-20", "range notation covering OUT"),
    (f"curl {OUT}/x", "scheme-less host/path"),
    (f"curl {OUT}:80/x", "scheme-less host:port/path"),
    (f"nmap -n {IN} intranet", "bare dotless hostname (intranet)"),
    (f"nmap -n {IN} localhost", "bare dotless hostname (localhost)"),
]


_SEC003 = pytest.mark.xfail(
    strict=True,
    reason="FINDING SEC-003: smuggled bare/dotless hostname (intranet) not extracted -> ALLOW; "
           "I3; Medium, mitigated by nftables egress lock; see SECURITY_AUDIT.md")


def _cases():
    for cmd, desc in CASES:
        for door in ("check", "session"):
            marks = []
            # SEC-001 (CIDR/range) and SEC-002 (scheme-less host/path) are FIXED in
            # brukal/hostmatch.py — those cases now genuinely DENY; regressions are
            # pinned in tests/test_hostmatch_cidr_paths.py.
            if desc.startswith("bare dotless"):
                marks = [_SEC003]     # ALLOW observed on BOTH doors (extract_hosts needs a dot)
            yield pytest.param(cmd, desc, door, marks=marks, id=f"{door}-{desc}")


@pytest.mark.parametrize("cmd,desc,door", list(_cases()))
def test_smuggled_out_of_scope_target_is_denied(record, cmd, desc, door):
    verdict = _gate_verdict(cmd, scope_host=IN, door=door)
    record(f"parser::{door}::{desc}", "parser-target-smuggling", "I3", cmd,
           "not ALLOW", verdict, "medium" if desc.startswith("bare dotless") else "critical")
    assert verdict != "ALLOW", f"smuggled OUT target via {desc!r} was ALLOWed ({door}): {cmd!r}"


@pytest.mark.parametrize("door", ["check", "session"])
def test_positive_control_clean_in_scope_command_allows(record, door):
    verdict = _gate_verdict(f"nmap {IN}", scope_host=IN, door=door)
    record(f"parser::positive::{door}", "parser-target-smuggling", "I3", f"nmap {IN}",
           "ALLOW", verdict, "n/a")
    assert verdict == "ALLOW", "a clean single in-scope target must be allowed (no false-deny)"
