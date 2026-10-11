"""
test_unseen_targets.py — SEC-008 regressions (I3: the gate judges every ACTUAL target).

Some forms choose targets that are never written in the command, so the host scan has
nothing to check: target-list files, request/config files carrying the host, random or
search-engine target sources, stdin-fed scanners, fan-out, a shell variable in a host
position. `nmap -iR 100` was ALLOWed — 100 random internet hosts. Each is now DENIED on
both doors, with a reason telling the agent how to restate it with written targets.

Both directions: every unseen form DENIES; the same tools with written targets, and
ordinary uses of the same letters (curl -i, nuclei -t, loop variables in a PATH, a
non-network tool reading stdin), still ALLOW.
"""
from __future__ import annotations

import ipaddress

import pytest

from brukal.gate import Gate
from brukal.hostmatch import unseen_targets
from brukal.scope import Scope

IN = "10.10.10.10"


def _gate():
    return Gate(Scope(engagement="sec-008",
                      authorized_networks=(ipaddress.ip_network(IN + "/32"),),
                      allowlisted_tools=frozenset({"nmap", "masscan", "nuclei", "httpx",
                                                   "curl", "wget", "sqlmap", "nikto",
                                                   "whatweb", "hydra", "naabu", "katana"}),
                      rate_limit_per_min=100000))


UNSEEN = [
    "nmap -iR 100", "nmap -iL /etc/hosts", f"nmap -iLtargets.txt {IN}",
    "masscan -iL t.txt -p80", "masscan -c scan.conf",
    "nuclei -l urls.txt", "nuclei -list urls.txt", "nuclei -uncover -uq apache",
    "httpx -l hosts.txt", "naabu -list h.txt", "katana -list u.txt",
    "wget -i urls.txt", "wget --input-file=urls.txt", f"curl -K cfg http://{IN}/",
    "whatweb -i list.txt", "sqlmap -r req.txt", "sqlmap -g inurl:id=",
    "sqlmap -m bulk.txt", "hydra -M hosts.txt ssh", "nikto -h hosts.txt",
    "curl $TARGET", "curl $T/admin",
]

SESSION_ONLY = [
    "cat hosts.txt | httpx -silent", "cat h | nuclei -t cves", "cat u | xargs curl",
    "cat u | xargs -n1 nmap -sV", "bash -c 'nmap -iL targets.txt'",
    "sudo nmap -iR 10", "nmap -sV ${HOST}",
]


@pytest.mark.parametrize("cmd", UNSEEN)
@pytest.mark.parametrize("door", ["check", "session"])
def test_unseen_targets_denied(cmd, door):
    g = _gate()
    d = g.check(cmd, IN, agent="recon") if door == "check" else g.check_session(cmd, IN)
    assert d.verdict == "DENY", f"{door}: {cmd!r} -> {d.verdict} ({d.reason})"
    assert d.layer in ("hard:scope", "session:scope")
    assert "write every target in the command" in d.reason


@pytest.mark.parametrize("line", SESSION_ONLY)
def test_session_stdin_and_fanout_denied(line):
    d = _gate().check_session(line, IN)
    assert d.verdict == "DENY", f"{line!r} -> {d.verdict} ({d.reason})"


LEGIT = [
    f"nmap -sV -oN scan.txt {IN}", f"nuclei -u http://{IN} -t cves -silent",
    f"nuclei -u http://{IN},http://{IN}:8080", f"httpx -u http://{IN} -title",
    f"curl -i http://{IN}/", f"wget -O out.html http://{IN}/",
    f"sqlmap -u http://{IN}/item?id=1 --batch", f"nikto -h http://{IN}/",
    f"for i in 1 2; do curl http://{IN}/orders/$i; done",
    f"curl -s http://{IN}/ | grep -i title", "cat notes.txt | sort | uniq",
    f"echo {IN} | xargs -I{{}} echo {{}}",
]


@pytest.mark.parametrize("cmd", LEGIT)
def test_written_targets_still_allowed(cmd):
    d = _gate().check_session(cmd, IN)
    assert d.verdict == "ALLOW", f"{cmd!r} -> {d.verdict} ({d.reason})"


def test_unseen_targets_reports_each_form():
    assert unseen_targets("nmap -iR 5") == ["nmap -iR"]
    assert unseen_targets(f"nmap -sV {IN}") == []
