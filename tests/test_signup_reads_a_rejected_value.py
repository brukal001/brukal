"""
test_signup_reads_a_rejected_value.py — GAP #27: MISSING and INVALID are different refusals.

THE MEASURED PROBLEM (crAPI, 2026-09-20)
    Ten `state_changed` experiments — the comparator no model in either series had ever
    proposed — died `second_unavailable`, because no second account could be created. The
    target was not being obstructive. It said exactly what was wrong:

        POST /identity/api/auth/signup -> 400
        {"message":"Validation failed","details":"... Field error in object 'signUpForm'
         on field 'name': rejected value [T]; codes [Size.signUpForm.name, Size.name, ...]"}

    `missing_fields()` deliberately skips any field the request already carried —
    "re-adding it would spin the caller's retry loop" — which is right for a MISSING
    field and wrong for a REJECTED one. crAPI is not asking for `name`; it HAS `name` and
    will not accept THAT VALUE. So the harness read the error, found nothing it could
    add, and gave up with "its error named no field we could supply".

    A hand-made signup with `name=BrukalB` returns 200 against the same endpoint and the
    account logs in. The whole cross-account class was blocked behind a value being four
    characters too short, on an endpoint that named the field AND the constraint.

THE PROPERTY
    A field the target REJECTED gets a better value; a field it is MISSING gets added.
    The two are told apart, and neither is guessed at when the target names nothing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import signup

CRAPI_400 = json.dumps({
    "message": "Validation failed",
    "details": ("org.springframework.validation.BeanPropertyBindingResult: 1 errors\n"
                "Field error in object 'signUpForm' on field 'name': rejected value [T]; "
                "codes [Size.signUpForm.name,Size.name,Size.java.lang.String,Size]; "
                "default message [size must be between 3 and 30]")})


def test_a_rejected_field_we_ALREADY_SENT_is_found():
    """`missing_fields` cannot see this by design, and must not — the two are different
    refusals with different repairs."""
    assert signup.missing_fields(CRAPI_400, already={"name", "email"}) == []
    rejected = signup.rejected_fields(CRAPI_400, already={"name", "email"})
    assert [f for f, _c in rejected] == ["name"], rejected


def test_the_constraint_is_read_not_guessed():
    (_field, constraint), = signup.rejected_fields(CRAPI_400, already={"name"})
    assert "size" in constraint.lower()


def test_a_size_rejection_produces_a_LONGER_value():
    """crAPI wanted between 3 and 30; the harness was sending something shorter."""
    better = signup.repair_value("name", "size must be between 3 and 30", current="T")
    assert len(better) >= 3 and len(better) <= 30
    assert better != "T"


def test_a_field_we_never_sent_is_NOT_treated_as_rejected():
    """BOUNDARY: that is the MISSING case, and `missing_fields` owns it. Confusing them
    would make the retry loop add a field and change its value in the same round, so a
    subsequent refusal could not be attributed to either."""
    assert signup.rejected_fields(CRAPI_400, already={"email"}) == []


def test_an_error_that_names_nothing_yields_nothing():
    """FAIL CLOSED, unchanged: no field named, no guess. The refusal is recorded instead."""
    assert signup.rejected_fields('{"message":"Bad Request"}', already={"name"}) == []
    assert signup.rejected_fields("", already={"name"}) == []


def test_repair_is_idempotent_enough_to_not_loop():
    """A repaired value that is still rejected must not produce the same value again, or
    the retry loop spins — the very thing `missing_fields`' `already` rule prevents."""
    first = signup.repair_value("name", "size must be between 3 and 30", current="T")
    second = signup.repair_value("name", "size must be between 3 and 30", current=first)
    assert second != first


def test_the_SESSION_retries_with_the_repaired_value(tmp_path):
    """WIRING. crAPI's exact sequence: the first POST is refused on a value, the second
    carries a repaired one and is accepted. A parser nothing calls changes nothing — the
    lesson of five silent no-ops in one session."""
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import ExecResult
    from brukal.web import GovernedBrowser, WebResult
    from brukal.webmap import AttackSurface

    scope = load_scope(Path(__file__).resolve().parent.parent / "scope.crapi.json")
    audit = AuditLog(tmp_path / "a.jsonl")
    bodies = []

    class _Cage:
        def run(self, a):
            if a.method != "POST":
                return WebResult(status=200, url=a.url, body="{}")
            bodies.append(a.body or "")
            payload = json.loads(a.body or "{}")
            if len(str(payload.get("name", ""))) < 3:
                return WebResult(status=400, url=a.url, body=CRAPI_400)
            return WebResult(status=200, url=a.url, body='{"token":"t"}')

    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession("172.20.0.12", ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, _Cage(), audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed="http://172.20.0.12/")
    s.surface.confirmed_routes = ["/identity/api/auth/signup"]
    s.surface.api_routes = ["/identity/api/auth/signup"]

    s._register_account_json()
    assert len(bodies) >= 2, "the refusal was not retried at all"
    assert len(json.loads(bodies[-1]).get("name", "")) >= 3, (
        f"the retry did not repair the value it was told about: {bodies[-1]}")
