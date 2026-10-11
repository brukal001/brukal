"""
test_hostmatch_cidr_paths.py — SEC-001 / SEC-002 regressions (I3: the gate judges
every ACTUAL target, not just the declared one).

SEC-001: a CIDR (`10.10.10.0/24`, `10.10.10.11/32`) or nmap octet range
(`10.10.10.11-20`, `10.10.10.*`) was skipped by `extract_hosts` because it holds a
'/' or isn't an IP literal, so `check_session` ALLOWed a scan of a whole network.

SEC-002: a scheme-less `ip/path`, `ip:port/path`, or bare `ip:port` was skipped the
same way, ALLOWed on both doors.

Both directions are pinned: every smuggle DENIES, and the everyday in-scope forms and
ordinary path / MIME / wordlist arguments still ALLOW (no false-deny regression).
"""
from __future__ import annotations

import ipaddress

import pytest

from brukal.gate import Gate
from brukal.hostmatch import extract_hosts
from brukal.scope import Scope

IN = "10.10.10.10"
OUT = "10.10.10.11"


def _gate(*cidrs):
    return Gate(Scope(engagement="sec-001-002",
                      authorized_networks=tuple(ipaddress.ip_network(c) for c in cidrs),
                      allowlisted_tools=frozenset({"nmap", "curl", "scp", "ffuf", "gobuster"}),
                      rate_limit_per_min=100000))


SMUGGLES = [
    f"nmap {IN} 10.10.10.0/24",
    f"nmap {IN} {OUT}/32",
    f"nmap {IN} 10.10.10.11-20",
    f"nmap {IN} 10.10.10.1-254",
    f"nmap {IN} 10.10.10.*",
    f"nmap {IN} 10.10.10.10,11",
    f"nmap {IN} 2001:db8::/32",
    f"curl {OUT}/x",
    f"curl {OUT}:80/x",
    f"curl {OUT}:80",
    f"curl {IN}/x {OUT}:8080",
    f"scp f u@{OUT}:/p",
    "curl evil.example.com/x",
]


# Session lines are typed into a real bash: an operator glued to the host, quoting,
# and brace expansion all still reach the host and must not hide it from the scan.
SESSION_SMUGGLES = [
    f"curl {OUT};id",
    f"curl {OUT}|cat",
    f"curl {OUT}&&id",
    f"curl {OUT}>/tmp/x",
    'curl 10.10.10."11"',
    "curl 1\\0.10.10.11",
    "curl${IFS}10.10.10.11",
    "nmap 10.10.10.{10,11}",
    "nmap 10.10.10.{10..20}",
    "curl {10.10.10.11,x}",
]


@pytest.mark.parametrize("line", SESSION_SMUGGLES)
def test_shell_shaped_session_smuggle_is_denied(line):
    d = _gate(f"{IN}/32").check_session(line, IN)
    assert d.verdict == "DENY", f"{line!r} -> {d.verdict} ({d.reason})"


@pytest.mark.parametrize("cmd", SMUGGLES)
@pytest.mark.parametrize("door", ["check", "session"])
def test_smuggled_network_or_hostpath_is_denied(cmd, door):
    g = _gate(f"{IN}/32")
    d = g.check(cmd, IN, agent="recon") if door == "check" else g.check_session(cmd, IN)
    assert d.verdict == "DENY", f"{door}: {cmd!r} -> {d.verdict} ({d.reason})"
    assert d.layer in ("hard:scope", "session:scope"), d.layer


ALLOWED_SESSION = [
    f"curl {IN}/x",
    f"curl {IN}:80/x",
    f"curl {IN}:80",
    f"nmap {IN}/32",
    f"scp f u@{IN}:/p",
    f"gobuster dir -u http://{IN} -w /usr/share/wordlists/dirb/common.txt",
    f"ffuf -u http://{IN}/FUZZ -w SecLists/Discovery/Web-Content/raft.txt",
    f"curl -H 'Content-Type: application/json' -A Mozilla/5.0 http://{IN}/api",
    f"nmap -oN scans/out.nmap {IN}",
    "cat ./notes/creds",
    f"curl {IN};id",
    f"echo {{a,b}} && curl http://{IN}/",
]


@pytest.mark.parametrize("cmd", ALLOWED_SESSION)
def test_in_scope_hostpath_and_ordinary_paths_still_allowed(cmd):
    d = _gate(f"{IN}/32").check_session(cmd, IN)
    assert d.verdict == "ALLOW", f"{cmd!r} -> {d.verdict} ({d.reason})"


@pytest.mark.parametrize("cmd", [
    "nmap 10.10.10.0/28",
    "nmap 10.10.10.0/24",
    "nmap 10.10.10.1-254",
    "nmap 10.10.10.*",
])
def test_network_inside_authorised_cidr_passes_the_hard_scope_check(cmd):
    # A network wholly inside an authorised CIDR is in scope. (The soft layer may
    # still ESCALATE it for breadth — that is a separate, tightening-only check.)
    d = _gate("10.10.10.0/24").check_session(cmd, IN)
    assert d.verdict == "ALLOW", f"{cmd!r} -> {d.verdict} ({d.reason})"


def test_network_straddling_two_authorised_blocks_is_denied_fail_closed():
    # Only the /25 halves are authorised separately; a /24 straddles both and is not a
    # subnet of either. Fail-closed: deny rather than reason about unions.
    d = _gate("10.10.10.0/25", "10.10.10.128/26").check_session("nmap 10.10.10.0/24", IN)
    assert d.verdict == "DENY"


def test_malformed_network_token_is_denied_not_dropped():
    for tok in ("10.10.10.0/33", "10.10.10.300-310", "10.10.10.20-5"):
        d = _gate("10.10.10.0/24").check_session(f"nmap {IN} {tok}", IN)
        assert d.verdict == "DENY", f"{tok!r} -> {d.verdict} ({d.reason})"


def test_extract_hosts_reports_networks_and_path_hosts():
    hosts = extract_hosts(f"nmap 10.10.10.0/24 10.10.10.11-20; curl {OUT}:80/x")
    assert "10.10.10.0/24" in hosts
    assert "10.10.10.11" in hosts                    # from the host:port/path token
    assert any(h.startswith("10.10.10.") and "/" in h and h != "10.10.10.0/24"
               for h in hosts), hosts                # the range, summarised to networks


def test_ordinary_paths_and_mime_types_yield_no_hosts():
    assert extract_hosts("cat /etc/passwd ./x/y wordlists/common.txt "
                         "application/json Mozilla/5.0 HTTP/1.1 1/2 */*") == []
