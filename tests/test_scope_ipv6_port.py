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
