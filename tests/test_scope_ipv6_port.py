"""
test_scope_ipv6_port.py — _norm_host strips brackets/port off an IPv6 host:port.

A web request host can arrive as a bracketed IPv6 literal with a port, `[::1]:8443`.
Before the fix _norm_host left it verbatim, so `contains_ip` could not parse it and the
target was denied as *unauthorized* — never judged on its real scope membership — and an
IPv6 exclusion written in bare form (`::1`) never matched it. `_norm_host` now unwraps
`[addr]` / `[addr]:port` to the bare address so authorization and exclusion both match an
IPv6 written in bare form. This is a correctness fix, not a security one: the prior
behavior failed *closed* (denied), never open.
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.scope import Scope


def _scope(**kw) -> Scope:
    return Scope(engagement="t",
                 authorized_networks=(ipaddress.ip_network("::1/128"),),
                 allowlisted_tools=frozenset({"*"}), rate_limit_per_min=60, **kw)


def test_norm_host_unwraps_bracketed_ipv6_with_and_without_port():
    assert Scope._norm_host("[::1]:8443") == "::1"
    assert Scope._norm_host("[::1]") == "::1"
    assert Scope._norm_host("[2001:db8::1]:443") == "2001:db8::1"
    # Case/trailing-dot normalization still applies before unwrapping.
    assert Scope._norm_host("[2001:DB8::1]:443") == "2001:db8::1"


def test_norm_host_regressions_preserved():
    # IPv4 / hostname host:port still strips the port.
    assert Scope._norm_host("example.com:8080") == "example.com"
    assert Scope._norm_host("10.10.10.5:80") == "10.10.10.5"
    # A bare word (no port) is untouched.
    assert Scope._norm_host("localhost") == "localhost"
    # A bare IPv6 literal (2+ colons, no brackets) is left alone.
    assert Scope._norm_host("::1") == "::1"
    assert Scope._norm_host("2001:db8::1") == "2001:db8::1"
    # Malformed (no closing bracket): left as-is -> unparseable downstream -> denied.
    assert Scope._norm_host("[::1") == "[::1"


def test_norm_host_rejects_junk_after_the_bracket():
    # A bracketed authority may be followed only by an empty remainder or a numeric
    # :port. Any other trailing text is malformed and fails closed to "" rather than
    # being truncated to the inside (which would judge the junk host on the IP's scope).
    assert Scope._norm_host("[::1]evil.com") == ""      # trailing label -> reject
    assert Scope._norm_host("[::1]:") == ""             # empty port -> reject
    assert Scope._norm_host("[::1]:80x") == ""          # non-numeric port -> reject
    assert Scope._norm_host("[::1].evil") == ""         # trailing junk -> reject
    # The valid forms are unaffected.
    assert Scope._norm_host("[::1]") == "::1"
    assert Scope._norm_host("[::1]:8443") == "::1"


def test_norm_host_junk_after_bracket_is_out_of_scope_even_if_the_inner_ip_is_authorized():
    # ::1 is authorized, but "[::1]evil.com" must NOT ride on ::1's membership.
    s = _scope()
    assert s.in_scope("[::1]evil.com", "/") is False
    assert s.contains_host("[::1]evil.com") is False


def test_ipv6_exclusion_in_bare_form_matches_a_bracketed_port_request():
    # Exclusion written bare; request arrives bracketed with a port.
    s = _scope(exclusions=frozenset({"::1"}))
    assert s._excluded("[::1]:8443", "/") is True
    # And the bare-form request it was always meant to match still matches.
    assert s._excluded("::1", "/") is True


def test_authorized_ipv6_with_bracketed_port_is_now_in_scope():
    # ::1/128 is authorized and NOT excluded: the bracketed+port form is now recognized
    # as in scope (it was denied pre-fix because contains_ip could not parse it).
    s = _scope()
    assert s.in_scope("[::1]:8443", "/") is True
    assert s.in_scope("::1", "/") is True


def test_authorized_but_excluded_ipv6_bracketed_port_is_out_of_scope():
    # Authorization + exclusion together: the exclusion wins (fail-closed), and it only
    # gets the chance to win because the bracketed+port host now normalizes to `::1`.
    s = _scope(exclusions=frozenset({"::1"}))
    assert s.in_scope("[::1]:8443", "/") is False


def test_contains_host_normalizes_a_bracketed_ipv6_port_like_norm_host():
    # contains_host previously had only its own host:port strip (no bracket unwrap), so a
    # direct call with a bracketed IPv6+port denied an authorized host. It now shares
    # _norm_host, so authorization is consistent whether reached via contains_host or
    # in_scope.
    s = _scope()
    assert s.contains_host("[::1]:8443") is True
    assert s.contains_host("[::1]") is True
    assert s.contains_host("::1") is True                # bare form still works


def test_contains_host_regressions_preserved():
    # A hostname scope: the pre-existing contains_host behavior (host:port strip, case,
    # wildcard subdomain, fail-closed) must be unchanged by routing through _norm_host.
    s = Scope(engagement="t", authorized_networks=(),
              allowlisted_tools=frozenset({"*"}), rate_limit_per_min=60,
              authorized_hosts=frozenset({"nexus.htb", "*.nexus.htb"}))
    assert s.contains_host("nexus.htb") is True
    assert s.contains_host("NEXUS.HTB:8080") is True     # case + port
    assert s.contains_host("git.nexus.htb") is True      # wildcard subdomain
    assert s.contains_host("nexus.htb.evil.com") is False
    assert s.contains_host("") is False                  # fail-closed
    # _norm_host adds trailing-FQDN-dot canonicalization, aligning contains_host with
    # in_scope (previously contains_host would NOT have matched a trailing-dot host).
    assert s.contains_host("nexus.htb.") is True
