"""
test_authorise_host_one_host.py — `_authorise_host` authorises EXACTLY one host.

SEC-011 (found 2026-10-11): it built `ip_network(f"{target}/32", strict=False)`.
  * a URL target (`https://lab.example/`) crashed with ValueError;
  * an IPv6 target `2001:db8::5` became `2001:db8::/32` — about 7.9e28 addresses —
    behind a prompt that said "authorise this single host".
Now: IPv4 -> /32, IPv6 -> /128, hostname / host:port / URL -> that exact name (no
wildcard); anything else raises (fail-closed) and the caller refuses.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from brukal.assist import _authorise_host
from brukal.scope import load_scope

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


@pytest.fixture
def scope():
    return load_scope(SCOPE)


def test_ipv4_is_one_slash_32(scope):
    s = _authorise_host(scope, "10.129.51.168")
    assert [str(n) for n in s.authorized_networks] == ["10.129.51.168/32"]
    assert s.contains_ip("10.129.51.168") and not s.contains_ip("10.129.51.169")


def test_ipv6_is_one_slash_128_not_a_slash_32_block(scope):
    s = _authorise_host(scope, "2001:db8::5")
    assert [str(n) for n in s.authorized_networks] == ["2001:db8::5/128"]
    assert s.contains_ip("2001:db8::5")
    assert not s.contains_ip("2001:db8::6")
    assert not s.contains_ip("2001:db8:ffff::1")


@pytest.mark.parametrize("target,host", [
    ("https://0a1c00dd.web-security-academy.net/", "0a1c00dd.web-security-academy.net"),
    ("lab.example.com", "lab.example.com"),
    ("lab.example.com:8443", "lab.example.com"),
    ("http://nexus.htb/login", "nexus.htb"),
    ("http://[2001:db8::7]:8080/", None),
    ("http://10.10.10.5:3000/", None),
])
def test_url_and_host_targets_authorise_exactly_that_host(scope, target, host):
    s = _authorise_host(scope, target)
    if host is None:
        assert len(s.authorized_networks) == 1
        assert s.authorized_networks[0].num_addresses == 1
        assert not s.authorized_hosts
    else:
        assert set(s.authorized_hosts) == {host}
        assert not s.authorized_networks
        assert s.contains_host(host)
        assert not s.contains_host("other." + host)        # no wildcard


@pytest.mark.parametrize("bad", ["", "   ", "https://", "*.example.com", "a b", "10.0.0.0/8"])
def test_anything_not_one_host_is_refused(scope, bad):
    with pytest.raises(ValueError):
        _authorise_host(scope, bad)


def test_keeps_allowlist_and_rate(scope):
    s = _authorise_host(scope, "10.129.51.168")
    assert s.allowlisted_tools == scope.allowlisted_tools
    assert s.rate_limit_per_min == scope.rate_limit_per_min
