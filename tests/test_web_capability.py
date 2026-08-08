"""
test_web_capability.py — the web plane is governed by the same capability logic.

Phase 1 enforced capabilities in `Gate.check`, which rules on SHELL commands. Web
actions take the other gate — `web.check_web()` — and it consulted no capability at
all. So a recon-role identity could emit a WEB request carrying a SQLi or command
injection payload and the capability layer never saw it: role separation held on one
plane and not the other.

That matters now rather than later because the next phase builds authenticated web and
business-logic testing on this plane. Governing it afterwards would mean governing it
retroactively.

The classification is NOT a second classifier. `identity.required_capability_for_web`
sits beside `required_capability` and shares its constants and its fail-closed rule:
anything unrecognised requires the most restrictive capability.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, load_scope
from brukal.identity import (CAPABILITY_DENIED_REASON, EXPLOITATION, RECON,
                             WEB_REQUEST, mint, operator_identity,
                             required_capability_for_web)
from brukal.web import FakeWebCage, GovernedBrowser, WebAction, check_web

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
IN_SCOPE = "http://10.10.10.5/"


def _scope():
    return load_scope(SCOPE)


# --------------------------------------------------------------------------- #
# The mapping — deterministic, fail-closed
# --------------------------------------------------------------------------- #

def test_a_plain_read_is_recon():
    assert required_capability_for_web(WebAction("get", url=IN_SCOPE)) == RECON
    assert required_capability_for_web(WebAction("navigate", url=IN_SCOPE)) == RECON
    assert required_capability_for_web(
        WebAction("request", url=IN_SCOPE, method="GET")) == RECON


def test_a_body_or_write_method_is_a_web_request():
    assert required_capability_for_web(
        WebAction("request", url=IN_SCOPE, method="POST",
                  body="q=1' OR '1'='1")) == WEB_REQUEST
    assert required_capability_for_web(
        WebAction("request", url=IN_SCOPE, method="PUT")) == WEB_REQUEST
    assert required_capability_for_web(
        WebAction("request", url=IN_SCOPE, method="GET",
                  body='{"admin":true}')) == WEB_REQUEST


def test_an_unknown_action_kind_fails_closed():
    """Invariant 2. An action we cannot classify requires the most restrictive
    capability, exactly as an unrecognised binary does on the shell path."""
    assert required_capability_for_web(WebAction("teleport", url=IN_SCOPE)) == EXPLOITATION
    assert required_capability_for_web(WebAction("", url=IN_SCOPE)) == EXPLOITATION


# --------------------------------------------------------------------------- #
# Enforcement in the web gate
# --------------------------------------------------------------------------- #

def test_a_recon_role_web_action_carrying_an_injection_payload_is_denied():
    """THE FLAGSHIP CASE for this work item."""
    d = check_web(WebAction("request", url=IN_SCOPE, method="POST",
                            body="q=1' OR '1'='1--"),
                  _scope(), agent=mint("recon", engagement_id="e"))
    assert d.verdict == "DENY"
    assert d.reason_code == CAPABILITY_DENIED_REASON
    assert d.layer == "hard:web-capability"


def test_a_web_role_plain_get_is_allowed():
    d = check_web(WebAction("get", url=IN_SCOPE), _scope(),
                  agent=mint("web", engagement_id="e"))
    assert d.verdict == "ALLOW"


def test_a_web_role_may_send_a_body():
    """The governed browser's whole job includes state-changing HTTP — the web role
    holds WEB_REQUEST, so this must not be narrowed."""
    d = check_web(WebAction("request", url=IN_SCOPE, method="POST", body="a=b"),
                  _scope(), agent=mint("web", engagement_id="e"))
    assert d.verdict == "ALLOW"


def test_a_recon_role_may_still_read():
    """Codify, do not shrink: recon reads the web surface today."""
    d = check_web(WebAction("get", url=IN_SCOPE), _scope(),
                  agent=mint("recon", engagement_id="e"))
    assert d.verdict == "ALLOW"


def test_an_unclassifiable_web_action_under_a_constrained_role_fails_closed():
    d = check_web(WebAction("teleport", url=IN_SCOPE), _scope(),
                  agent=mint("recon", engagement_id="e"))
    assert d.verdict == "DENY"


def test_scope_precedes_capability_on_the_web_path():
    """An out-of-scope host is denied for the SCOPE reason even for a principal that
    holds every capability — capability can only ever add denials."""
    d = check_web(WebAction("get", url="http://evil.com/"), _scope(),
                  agent=operator_identity())
    assert d.verdict == "DENY"
    assert d.layer == "hard:web-scope"


def test_the_operator_is_unconstrained_on_the_web_path_too():
    d = check_web(WebAction("request", url=IN_SCOPE, method="DELETE"),
                  _scope(), agent=operator_identity())
    assert d.verdict == "ALLOW"


def test_an_unknown_role_gets_nothing_on_the_web_path():
    d = check_web(WebAction("get", url=IN_SCOPE), _scope(), agent="mystery-agent")
    assert d.verdict == "DENY"
    assert d.reason_code == CAPABILITY_DENIED_REASON


# --------------------------------------------------------------------------- #
# Bypass attempts against the mapping
# --------------------------------------------------------------------------- #

def test_method_casing_and_padding_do_not_hide_a_write():
    for method in ("post", "PoSt", " POST ", "put", "DELETE", "patch"):
        assert required_capability_for_web(
            WebAction("request", url=IN_SCOPE, method=method)) == WEB_REQUEST, method


def test_action_kind_casing_does_not_hide_an_interaction():
    for kind in ("FILL", "Click", "EVAL", "InterCept"):
        assert required_capability_for_web(
            WebAction(kind, url=IN_SCOPE, selector="#x")) == WEB_REQUEST, kind


def test_an_interaction_under_a_recon_role_is_denied():
    """`fill` plants a payload and `click` submits it — a recon identity driving a
    form is doing more than reading."""
    for action in (WebAction("fill", selector="#u", value="' OR 1=1--"),
                   WebAction("click", selector="#go"),
                   WebAction("eval", expression="fetch('/admin')"),
                   WebAction("intercept", url=IN_SCOPE, body="tampered")):
        d = check_web(action, _scope(), current_url=IN_SCOPE,
                      agent=mint("recon", engagement_id="e"))
        assert d.verdict == "DENY", action.kind
        assert d.reason_code == CAPABILITY_DENIED_REASON, action.kind


def test_a_verification_grant_does_not_leak_onto_the_web_path():
    """ADVERSARIAL: the single-action grant names a SHELL command. It must not widen
    a principal on the web plane, where no command was matched against it."""
    from brukal.identity import verification_grant
    granted = verification_grant(mint("verify", engagement_id="e"),
                                 "sqlmap -u http://10.10.10.5/?q=1 --batch")
    d = check_web(WebAction("request", url=IN_SCOPE, method="POST", body="q=1"),
                  _scope(), agent=granted)
    assert d.verdict == "DENY"
    assert d.reason_code == CAPABILITY_DENIED_REASON


# --------------------------------------------------------------------------- #
# End to end — the denied action never reaches the cage
# --------------------------------------------------------------------------- #

def test_a_denied_web_action_never_reaches_the_cage():
    tmp = tempfile.mkdtemp()
    cage = FakeWebCage(responses={})
    br = GovernedBrowser(_scope(), cage, AuditLog(Path(tmp) / "w.jsonl"))
    d, r = br.run(WebAction("request", url=IN_SCOPE, method="POST",
                            body="q=1' OR '1'='1--"),
                  agent=mint("recon", engagement_id="e"))
    assert d.verdict == "DENY"
    assert d.reason_code == CAPABILITY_DENIED_REASON
    assert r is None
    assert cage.actions == []


def test_the_default_web_principal_still_works_end_to_end():
    """GovernedBrowser defaults to agent='web'; every existing detector relies on it."""
    tmp = tempfile.mkdtemp()
    cage = FakeWebCage(responses={"10.10.10.5/x": "ok"})
    br = GovernedBrowser(_scope(), cage, AuditLog(Path(tmp) / "w.jsonl"))
    d, r = br.run(WebAction("request", url="http://10.10.10.5/x",
                            method="POST", body="a=b"))
    assert d.verdict == "ALLOW"
    assert r is not None
