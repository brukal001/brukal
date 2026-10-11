"""
test_hostmatch_dotless.py — SEC-003 regressions (I3: every ACTUAL target is judged).

SEC-003: a dotless name (`intranet`, a Docker service like `crapi-identity`) or a
loopback name (`localhost`) was never extracted, so `nmap 10.10.10.10 intranet` was
ALLOWed on both doors. Such a word is indistinguishable from ordinary words, so it is
read only in HOST POSITIONS of known network tools; header/data values are never hosts.

Both directions are pinned: smuggles in host positions DENY (including through
wrappers, nested shells, ssh remote commands, tunnels and proxies), and the everyday
forms — vhost `Host:` headers, `--script vuln`, loop variables, DB names, plain shell
words — still ALLOW. A loopback name is judged as the loopback IP, so `localhost` is
allowed exactly when 127.0.0.1 is authorised (it used to be denied even then).
"""
from __future__ import annotations

import ipaddress

import pytest

from brukal.gate import Gate
from brukal.hostmatch import extract_hosts, loopback_ip
from brukal.scope import Scope

IN = "10.10.10.10"


def _gate(*cidrs, hosts=()):
    return Gate(Scope(engagement="sec-003",
                      authorized_networks=tuple(ipaddress.ip_network(c) for c in cidrs),
                      authorized_hosts=frozenset(hosts),
                      allowlisted_tools=frozenset({"nmap", "curl", "nc", "ssh", "masscan",
                                                   "whatweb", "nikto", "ffuf", "smbclient",
                                                   "mongosh"}),
                      rate_limit_per_min=100000))


SMUGGLES = [
    f"nmap -n {IN} intranet",
    f"nmap -n {IN} localhost",
    "curl intranet:8080/admin",
    "curl http://localhost:9222/json",
    "curl crapi-identity:8080",
    f"curl -x squid:3128 http://{IN}/",
    "nc intranet 80",
    "ssh u@intranet",
    f"ssh -J jumpbox u@{IN}",
    f"ssh -L 8080:intranet:80 u@{IN}",
    f"masscan -p80 --rate 100 {IN} intranet",
    "nikto -h intranet",
    "ffuf -u http://localhost/FUZZ -w words.txt",
    "smbclient //fileserv/share -U guest",
    "mongosh --host db1",
    "curl app.localhost",
]

SESSION_ONLY_SMUGGLES = [
    "sudo -u root timeout 5 nc intranet 80",
    "bash -c 'curl crapi-identity:8080'",
    "eval curl intranet",
    f"ssh u@{IN} curl intranet:8080",
    "for i in 1 2; do curl intranet/$i; done",
    "curl${IFS}intranet",
    "echo $(curl intranet)",
]


@pytest.mark.parametrize("cmd", SMUGGLES)
@pytest.mark.parametrize("door", ["check", "session"])
def test_dotless_or_loopback_host_in_host_position_is_denied(cmd, door):
    g = _gate(f"{IN}/32")
    d = g.check(cmd, IN, agent="recon") if door == "check" else g.check_session(cmd, IN)
    assert d.verdict == "DENY", f"{door}: {cmd!r} -> {d.verdict} ({d.reason})"
    assert d.layer in ("hard:scope", "session:scope"), (d.layer, d.reason)


@pytest.mark.parametrize("line", SESSION_ONLY_SMUGGLES)
def test_session_shell_forms_are_denied(line):
    d = _gate(f"{IN}/32").check_session(line, IN)
    assert d.verdict == "DENY", f"{line!r} -> {d.verdict} ({d.reason})"


LEGIT = [
    f'curl -sk -H "Host: crapi-identity:8080" http://{IN}/identity/',
    f'curl -H "Host: localhost" http://{IN}/admin',
    f"nmap --script vuln -p 80 -oN scan {IN}",
    f"nmap -sV --top-ports 100 --max-retries 2 {IN}",
    f"masscan -p1-65535 --rate=10000 -e tun0 --output-format list "
    f"--output-filename out.txt {IN}",
    f"whatweb -a 3 -v -e HTTP_RESPONSEHEADER http://{IN}/",
    f"for i in 1 2 3; do curl -s http://{IN}/orders/$i; done",
    f"curl -X POST -A Mozilla -u admin:admin http://{IN}/login -o out",
    "cat flag; id; sudo -l; ls -la /home",
    f"mongosh --host {IN} --port 27017 admin --eval 'db.adminCommand({{ping:1}})'",
    f"ssh -i key -p 2222 u@{IN} id",
    "nc -lvnp 4444",
    "curl $URL",
]


@pytest.mark.parametrize("cmd", LEGIT)
def test_everyday_forms_still_allowed(cmd):
    d = _gate(f"{IN}/32").check_session(cmd, IN)
    assert d.verdict == "ALLOW", f"{cmd!r} -> {d.verdict} ({d.reason})"


def test_localhost_allowed_when_loopback_authorised():
    g = _gate(f"{IN}/32", "127.0.0.1/32")
    for cmd in ("curl http://localhost:5000/createdb", "nmap localhost", "curl app.localhost"):
        assert g.check_session(cmd, IN).verdict == "ALLOW", cmd


def test_authorised_dotless_name_allowed():
    g = _gate(f"{IN}/32", hosts={"crapi-identity"})
    assert g.check_session("curl crapi-identity:8080", IN).verdict == "ALLOW"


def test_deny_reason_tells_the_agent_how_to_rephrase():
    d = _gate(f"{IN}/32").check_session(f"nmap {IN} intranet", IN)
    assert "--option=intranet" in d.reason


def test_loopback_ip_names():
    assert loopback_ip("localhost") == "127.0.0.1"
    assert loopback_ip("LOCALHOST.") == "127.0.0.1"
    assert loopback_ip("api.localhost") == "127.0.0.1"
    assert loopback_ip("ip6-localhost") == "::1"
    assert loopback_ip("localhost.evil.com") is None
    assert loopback_ip("notlocalhost") is None


def test_header_and_data_values_are_never_dotless_hosts():
    assert extract_hosts('curl -H "Host: intranet" -d name=intranet -A intranet '
                         f'http://{IN}/') == [IN]
