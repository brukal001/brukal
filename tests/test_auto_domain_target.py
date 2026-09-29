"""
test_auto_domain_target.py — `auto`/`solve` must accept a single-exact-host DOMAIN
scope as the run target.

Regression for the gap found on Brukal's first domain-target live run (a PortSwigger
Web Security Academy lab, 2026-09-29): `_prepare_session` decided target authorisation
with `scope.contains_ip(target)` ALONE. For an IP/CIDR scope (crAPI, DVWA, HTB) that is
correct, but a pure domain scope (authorized_hosts, no CIDRs) has no CIDR for the host
to fall inside, so the run was refused and offered to authorise the URL as a `/32` —
and the only "yes" path (`--host`) wildcard-expands to `*.parent`, authorising OTHER
users' lab instances. The fix is host-aware, membership-only target authorisation:
`_target_authorised` — no DNS, no widen, no wildcard. The per-request web gate still
governs every request; this only decides whether the loaded scope is used as-is.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Import the package in its working order first (assist_cli <-> assist is circular if
# assist_cli is imported as the entry point; assist is the entry the CLI itself uses).
import brukal.assist  # noqa: F401,E402
from brukal.assist_cli import _target_authorised, _target_host  # noqa: E402
from brukal.scope import Scope  # noqa: E402

LAB = "0ad600d60433060d809571a700cb00b4.web-security-academy.net"


def _domain_scope(host: str = LAB) -> Scope:
    """A single-exact-host DOMAIN scope: one authorised host, NO CIDRs."""
    return Scope(engagement="lab", authorized_networks=(),
                 allowlisted_tools=frozenset({"*"}), rate_limit_per_min=30,
                 authorized_hosts=frozenset({host}), authorization="approved by op")


def _ip_scope() -> Scope:
    import ipaddress
    return Scope(engagement="crapi",
                 authorized_networks=(ipaddress.ip_network("172.20.0.12/32"),),
                 allowlisted_tools=frozenset({"*"}), rate_limit_per_min=30,
                 authorization="approved by op")


# --- _target_host: pull a bare host out of URL / host:port / bare host -------------

def test_target_host_from_full_url():
    assert _target_host(f"https://{LAB}/") == LAB
    assert _target_host(f"https://{LAB}/filter?category=Gifts") == LAB
    assert _target_host(f"http://{LAB}:8080/x") == LAB  # contains_host strips :port too


def test_target_host_from_bare_host_and_hostport():
    assert _target_host(LAB) == LAB
    assert _target_host(f"{LAB}/path") == LAB
    assert _target_host("") == ""


# --- _target_authorised: DOMAIN scope accepts its exact host, denies everything else

def test_domain_scope_accepts_exact_host_as_url_or_bare():
    s = _domain_scope()
    assert _target_authorised(s, f"https://{LAB}/") is True
    assert _target_authorised(s, f"https://{LAB}/filter?category=Gifts%27+OR+1=1--") is True
    assert _target_authorised(s, LAB) is True


def test_domain_scope_denies_other_instances_and_hosts():
    s = _domain_scope()
    # a sibling lab instance (another user's) must NOT be authorised
    assert _target_authorised(s, "https://0adEVILother.web-security-academy.net/") is False
    # the parent domain / unrelated hosts / suffix-confusion
    assert _target_authorised(s, "https://web-security-academy.net/") is False
    assert _target_authorised(s, "https://portswigger.net/") is False
    assert _target_authorised(s, f"https://{LAB}.evil.com/") is False


def test_ip_scope_behaviour_unchanged():
    """The pre-existing IP/CIDR path must still authorise an in-scope IP and reject
    an out-of-scope one — the fix only ADDS a host path, it removes nothing."""
    s = _ip_scope()
    assert _target_authorised(s, "172.20.0.12") is True
    assert _target_authorised(s, "10.10.10.5") is False
    # a domain scope does not authorise by IP, and an IP scope does not authorise a host
    assert _target_authorised(_domain_scope(), "34.246.129.62") is False
