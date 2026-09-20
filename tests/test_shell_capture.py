"""
test_shell_capture.py — the third of every run that self-capture could not see.

Self-capture hooks `GovernedBrowser.run`, the web plane's single door. But agents also
reach the target with `curl` through the SHELL plane, and those requests were invisible to
it: in CR2 run 1, four of eleven shell commands were HTTP requests against the target, each
one a control that answered and none of them a replay candidate.

A curl command is structured enough to read: the URL, `-X`, `-H`, `-d`. It is not a full
shell parser and must not pretend to be — anything it cannot read confidently it declines,
because a MISREAD request would put a URL nobody issued into the surface.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import load_scope
from brukal.capture import parse_curl

SCOPE = Path(__file__).resolve().parent.parent / "scope.crapi.json"


def _scope():
    return load_scope(SCOPE)


def test_a_plain_curl_becomes_a_capture():
    c = parse_curl("curl -sS http://172.20.0.12/workshop/api/shop/orders/all", _scope(), 200)
    assert c and c.method == "GET"
    assert c.path() == "/workshop/api/shop/orders/all"
    assert c.source == "shell"


def test_an_explicit_method_and_body_are_read():
    c = parse_curl(
        "curl -s -X POST http://172.20.0.12/workshop/api/shop/orders/return_order "
        "-H 'Content-Type: application/json' -d '{\"order_id\":2}'", _scope(), 200)
    assert c.method == "POST"
    assert c.is_write()
    assert "order_id" in c.param_names()


def test_data_without_an_explicit_method_is_a_POST():
    """curl's own rule: -d implies POST. Reading it as GET would file a write as a read."""
    c = parse_curl("curl -s http://172.20.0.12/x -d 'a=1'", _scope(), 200)
    assert c.method == "POST"


def test_credentials_in_the_command_do_not_survive():
    c = parse_curl(
        "curl -s http://172.20.0.12/identity/api/v2/user/dashboard "
        "-H 'Authorization: Bearer eyJREALTOKEN.sig'", _scope(), 200)
    assert "REALTOKEN" not in str(c.headers) + str(c.body)
    assert c.auth_kind == "bearer"


def test_an_out_of_scope_url_is_refused():
    assert parse_curl("curl -s http://evil.example.com/x", _scope(), 200) is None


def test_a_non_curl_or_unreadable_command_is_declined():
    """It must not guess. A misread command would put a URL nobody issued into the
    surface, which is worse than missing it."""
    assert parse_curl("sqlmap -u http://172.20.0.12/x --batch", _scope(), 0) is None
    assert parse_curl("curl --some-flag-we-do-not-know", _scope(), 0) is None
    assert parse_curl("", _scope(), 0) is None


def test_an_absence_is_not_captured():
    """Same floor as the web plane: a 404 control is not a control."""
    assert parse_curl("curl -s http://172.20.0.12/nope", _scope(), 404) is None


def test_the_session_captures_a_curl_it_ran(tmp_path):
    """WIRING. A parser nothing calls changes nothing — the lesson of capture.py (twice),
    the ffuf tooling, and discover_content, all in one day."""
    from brukal import AuditLog, Executor, Gate
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.gate import Decision
    from brukal.kali import ExecResult

    scope = _scope()
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession("172.20.0.12", ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()))

    cmd = ("curl -s -X POST http://172.20.0.12/workshop/api/shop/orders/return_order "
           "-d '{\"order_id\":2}'")
    s._absorb_shell(cmd,
                    Decision(verdict="ALLOW", action=cmd, target="172.20.0.12",
                             agent="exploit", reason="t", layer="t"),
                    ExecResult(cmd, 0, '{"message":"returned"}', ""))

    caps = s.shell_captures()
    assert caps, "a curl the session ran produced no capture"
    assert caps[0].method == "POST" and caps[0].is_write()

    from brukal.capture import hypotheses_from
    hyps = hypotheses_from(caps)
    assert any(h.comparator == "state_changed" for h in hyps), (
        "a POST run via the shell did not become a state-changing experiment")
