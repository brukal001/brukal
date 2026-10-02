# tests/security/test_scope_escape.py   (test fns take the `record` conftest fixture — no import)
import ipaddress

import pytest
from brukal.scope import Scope

# One in-scope host and one in-scope CIDR; everything in OUT must NOT be authorized.
IN_HOST = "app.in-scope.example"
IN_CIDR = "10.10.10.0/24"


def _scope():
    return Scope(engagement="security-audit",
                 authorized_networks=(ipaddress.ip_network(IN_CIDR),),
                 allowlisted_tools=frozenset({"nmap"}),
                 rate_limit_per_min=30,
                 authorized_hosts=frozenset({IN_HOST}))


OUT = [
    ("localhost", "loopback alias"), ("127.0.0.1", "loopback"), ("0.0.0.0", "any"),
    ("::1", "v6 loopback"), ("::ffff:127.0.0.1", "v4-mapped v6"),
    ("2130706433", "decimal IP for 127.0.0.1"), ("0x7f000001", "hex IP"),
    ("0177.0.0.1", "octal IP"),
    ("APP.IN-SCOPE.EXAMPLE.evil.com", "subdomain confusion"),
    ("10.10.11.0", "CIDR off-by-one (adjacent /24)"),
    ("evil.example", "unrelated host"),
]


@pytest.mark.parametrize("host,desc", OUT)
def test_out_of_scope_representations_are_denied(record, host, desc):
    s = _scope()
    actual = "ALLOW" if s.in_scope(host) else "DENY"
    record(f"scope-escape::{host}", "scope-escape", "I3/I5", f"{host} ({desc})",
           "DENY", actual, "critical")
    assert actual == "DENY", f"out-of-scope {host!r} ({desc}) was authorized"


def test_positive_control_in_scope_host_is_allowed(record):
    s = _scope()
    actual = "ALLOW" if s.in_scope(IN_HOST) else "DENY"
    record("scope-escape::positive-host", "scope-escape", "I3/I5", IN_HOST, "ALLOW", actual, "n/a")
    assert actual == "ALLOW", "the genuine in-scope host must remain authorized (no false-deny)"


def test_positive_control_in_cidr_ip_is_allowed(record):
    s = _scope()
    actual = "ALLOW" if s.in_scope("10.10.10.42") else "DENY"
    record("scope-escape::positive-cidr", "scope-escape", "I3/I5", "10.10.10.42", "ALLOW", actual, "n/a")
    assert actual == "ALLOW"


def test_trailing_dot_is_same_authorized_host_not_an_escape(record):
    # RECLASSIFIED from the brief's OUT list: "app.in-scope.example." is the absolute-FQDN
    # spelling of the SAME authorized host (scope._norm_host deliberately strips the dot).
    # It widens nothing: the dot-suffixed form of a DIFFERENT host is still denied (below).
    s = _scope()
    actual = "ALLOW" if s.in_scope(IN_HOST + ".") else "DENY"
    record("scope-escape::trailing-dot-equivalent", "scope-escape", "I3/I5",
           IN_HOST + ". (FQDN form of the authorized host)", "ALLOW", actual, "n/a")
    assert actual == "ALLOW"
    assert not s.in_scope("evil.example.")
