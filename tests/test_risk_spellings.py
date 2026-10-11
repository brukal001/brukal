"""
test_risk_spellings.py — SEC-009 / SEC-010 regressions for brukal/risk.py.

SEC-009: the soft layer matched exact tokens, so a write spelled differently (-XPOST,
--request=DELETE, -F, --json, -sSd, wget --post-data/--method) scored REVERSIBLE and was
auto-ALLOWed; nmap script expressions (not safe, +exploit, wildcards, intrusive script
names, custom .nse) dodged the category check; and a wrapper (timeout/sudo/env/nice)
hid the tool, turning a DENY into an approvable ESCALATE.
SEC-010: assess(trust=nan) raised instead of treating unreadable trust as zero.

Both directions: every write/intrusive spelling is at least ESCALATE and a wrapper never
lowers a verdict; read-only spellings of the same tools (and nmap's own categories,
which keep their designed meaning) are unchanged. benchmarks/replay_gate_corpus.py
confirms 0 historical decisions changed.
"""
from __future__ import annotations

import pytest

from brukal.risk import assess, derive_reversibility

U = "http://10.10.10.10/x"
H = "10.10.10.10"
_RANK = {"ALLOW": 0, "ESCALATE": 1, "DENY": 2}


@pytest.mark.parametrize("cmd", [
    f"curl -XPOST {U}", f"curl -XDELETE {U}", f"curl --request=PUT {U}",
    f"curl -F a=@f {U}", f"curl --form a=b {U}", f"curl --json '{{}}' {U}",
    f"curl --data=a {U}", f"curl -da=1 {U}", f"curl -sSd a=1 {U}", f"curl -sX PATCH {U}",
    f"curl --data-ascii a {U}", f"curl -T file {U}",
    f"wget --post-data=a=1 {U}", f"wget --post-file f {U}", f"wget --method=DELETE {U}",
    f"wget --method PUT {U}", f"wget --body-data=x {U}",
])
def test_write_spellings_are_irreversible(cmd):
    assert derive_reversibility(cmd) == "irreversible", cmd


@pytest.mark.parametrize("cmd", [
    f"curl -sSL {U}", f"curl -o data.txt {U}", f"curl -sk {U}",
    f"curl -H 'X-Data: d' {U}", f"curl -I {U}", f"curl -X GET {U}", f"curl -XHEAD {U}",
    f"curl -sSo dump.bin {U}", f"wget -O out {U}", f"wget --method=GET {U}",
    f"wget --method=HEAD {U}",
])
def test_read_only_spellings_unchanged(cmd):
    assert derive_reversibility(cmd) == "reversible", cmd
    assert assess(cmd).decision == "ALLOW", cmd


@pytest.mark.parametrize("expr", [
    "'not safe'", "+exploit", "'(exploit or dos)'", "'http-*'", "http-slowloris",
    "smb-vuln-ms17-010", "/tmp/custom.nse", "default,http-shellshock",
])
def test_script_expressions_reaching_intrusive_scripts_are_irreversible(expr):
    cmd = f"nmap --script {expr} {H}"
    assert derive_reversibility(cmd) == "irreversible", cmd
    assert assess(cmd).decision == "DENY", cmd


@pytest.mark.parametrize("expr,decision", [
    ("http-title", "ALLOW"), ("default,safe", "ALLOW"), ("http-headers,http-title", "ALLOW"),
    ("vuln", "ESCALATE"),           # category: aggressive by design, not irreversible
])
def test_safe_scripts_and_categories_keep_their_meaning(expr, decision):
    assert assess(f"nmap --script {expr} {H}").decision == decision


@pytest.mark.parametrize("bare", [
    f"nmap --script exploit {H}", f"curl -X POST -d a {U}", f"nmap -sV {H}",
    f"hydra -l a -P p ssh://{H}",
])
@pytest.mark.parametrize("wrapper", ["timeout 9", "sudo", "sudo -u root", "env X=1",
                                     "nice -n 5", "nohup", "X=1"])
def test_a_wrapper_never_lowers_the_verdict(bare, wrapper):
    assert _RANK[assess(f"{wrapper} {bare}").decision] >= _RANK[assess(bare).decision]


def test_wrapped_read_only_command_still_escalates_as_before():
    assert assess(f"sudo nmap -sV {H}").decision == "ESCALATE"


def test_nan_trust_is_most_cautious():
    assert assess(f"nmap -sV {H}", trust=float("nan")).score == \
        assess(f"nmap -sV {H}", trust=0.0).score
