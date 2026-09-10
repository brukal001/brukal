"""
test_setup_failure_is_not_a_bad_reference.py — a setup that FAILED is not a bad reference.

THE PROPERTY
    When an experiment cannot be run, the sentence fed back to the next round has to name
    the thing that has to change. "The reference is unresolvable" and "the setup request
    failed" point at two different repairs, and only one of them is available to a model
    that is only shown the first.

THE DEFECT THIS PINS (measured in run CM1, 2026-09-10)
    The `/api/Addresses/{id}` experiment ran `POST /api/Addresses` as its setup. The
    target answered **HTTP 500**. What went back to the model was:

        UNRESOLVED REFERENCE (experiment NOT run, this is not a result)
        IDOR on /api/Addresses/{id} leaks another user's saved address
        ({{setup.0.data.id}}: setup response body is not JSON)

    Every word of that is true and it points the wrong way. A model reading it has reason
    to change the dotted path and none to fix the request body that 500'd. The shape line
    beside it did carry `HTTP 500`, but the outcome text is what the refine round reasons
    from, and CM1's next round changed neither.

    Same family as the entries above it: a component correct on its own axis — the
    resolver truthfully reporting what it could not resolve — is wrong about what the
    next component will do with its output.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp


class _Res:
    """A setup response, as the dispatcher records one."""

    def __init__(self, status, body="", headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_a_500_setup_says_the_setup_failed_not_that_the_reference_is_bad():
    """THE DEFECT, at the point the sentence is written."""
    spec = {"method": "GET", "url": "http://t/api/Addresses/{{setup.0.data.id}}"}
    failed = _Res(500, "<html>Internal Server Error</html>")

    with pytest.raises(hyp.UnresolvedReference) as caught:
        hyp.resolve_setup_refs(spec, [failed])

    message = str(caught.value)
    assert "500" in message, f"the status the setup actually returned is missing: {message}"
    assert "setup" in message.lower() and "fail" in message.lower(), message
    assert "not JSON" not in message, (
        "the failure is still described as a parsing problem, which points the repair at "
        "the reference instead of at the request that 500'd")


def test_the_failed_setup_is_its_own_exception_type():
    """A subclass, so every existing `except UnresolvedReference` still aborts the
    experiment exactly as before — the distinction is in what is SAID, not in what is
    allowed to run."""
    assert issubclass(hyp.SetupRequestFailed, hyp.UnresolvedReference)

    spec = {"method": "GET", "url": "http://t/x/{{setup.0.id}}"}
    with pytest.raises(hyp.SetupRequestFailed):
        hyp.resolve_setup_refs(spec, [_Res(500, "boom")])


def test_a_setup_that_never_answered_is_also_a_failed_setup():
    """`status=None` is the gate refusing it or the target not replying. Neither is a
    reference problem either."""
    spec = {"method": "GET", "url": "http://t/x/{{setup.0.id}}"}

    with pytest.raises(hyp.SetupRequestFailed) as caught:
        hyp.resolve_setup_refs(spec, [_Res(None, "")])

    assert "no answer" in str(caught.value).lower() or "none" in str(caught.value).lower()


# --------------------------------------------------------------------------- #
# The boundary: a genuinely bad reference must still say so
# --------------------------------------------------------------------------- #

def test_a_successful_setup_with_a_wrong_path_still_reports_the_reference():
    """THE BOUNDARY. This is 2C4's failure — a rich body and a wrong path — and it must
    keep pointing at the path, or the fix trades one misdirection for another."""
    spec = {"method": "GET", "url": "http://t/x/{{setup.0.id}}"}
    ok = _Res(200, '{"user":{"id":25}}')

    with pytest.raises(hyp.UnresolvedReference) as caught:
        hyp.resolve_setup_refs(spec, [ok])

    assert not isinstance(caught.value, hyp.SetupRequestFailed)
    assert "no field 'id'" in str(caught.value), str(caught.value)


def test_a_successful_setup_with_a_non_json_body_still_reports_the_reference():
    """A 200 that is not JSON is the application answering in a shape the reference cannot
    walk. That IS a reference problem."""
    spec = {"method": "GET", "url": "http://t/x/{{setup.0.id}}"}

    with pytest.raises(hyp.UnresolvedReference) as caught:
        hyp.resolve_setup_refs(spec, [_Res(200, "<html>hello</html>")])

    assert not isinstance(caught.value, hyp.SetupRequestFailed)
    assert "not JSON" in str(caught.value)


def test_a_working_setup_still_resolves():
    spec = {"method": "GET", "url": "http://t/api/Cards/{{setup.0.data.id}}"}
    got = hyp.resolve_setup_refs(spec, [_Res(201, '{"data":{"id":7}}')])

    assert got["url"] == "http://t/api/Cards/7"


# --------------------------------------------------------------------------- #
# The distinction has to survive into the next round
# --------------------------------------------------------------------------- #

def test_the_next_round_is_told_the_setup_failed(tmp_path):
    """The outcomes list IS the refine round's input. A distinction that dies before it
    gets there has fixed nothing — CM1's whole loss was in this hand-off."""
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import ExecResult
    from brukal.web import GovernedBrowser, WebResult

    scope = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope_fast.json")
    target_ip = "10.10.10.5"

    class _Kali:
        def run(self, command):
            return ExecResult(command, 0, "", "")

    class _Site:
        def run(self, action):
            if action.method == "POST":
                return WebResult(status=500, url=action.url, headers={},
                                 body="<html>Internal Server Error</html>")
            return WebResult(status=200, url=action.url, headers={}, body='{"ok":1}')

    class _LLM:
        last_stop_reason = "end_turn"

        def propose(self, system, user, max_tokens=1024):
            return ""

    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    s = AssistSession(target_ip, ex, StrategistAgent(_LLM()),
                      browser=GovernedBrowser(scope, _Site(), audit))
    s.allow_intrusive = True

    h = hyp.Hypothesis(
        title="IDOR on /api/Addresses/{id}", severity="high",
        comparator="a_denied_b_allowed",
        setup=[{"method": "POST", "url": f"http://{target_ip}:3000/api/Addresses",
                "body": "{}", "as": "self"}],
        control={"method": "GET",
                 "url": f"http://{target_ip}:3000/api/Addresses/{{{{setup.0.data.id}}}}",
                 "as": "anonymous"},
        variant={"method": "GET",
                 "url": f"http://{target_ip}:3000/api/Addresses/{{{{setup.0.data.id}}}}",
                 "as": "anonymous"})

    outcomes: list = []
    assert s._run_one_round([h], outcomes) == 0
    assert outcomes, "the round recorded nothing at all"
    text = outcomes[0]

    assert "SETUP FAILED" in text, f"the next round is still told this was a reference: {text}"
    assert "500" in text, text
    assert "this is not a result" in text.lower(), text
    assert "UNRESOLVED REFERENCE" not in text, text
