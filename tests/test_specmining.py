"""
test_specmining.py — reading the target's own contract instead of guessing at it.

The competing tool reached findings Brukal missed partly by fetching the application's
SOURCE from GitHub. That works on an open-source target and nowhere else. The
generalising version of the same move is the OpenAPI document: the app ships a
machine-readable statement of which operations mutate what, and which body fields a
client may set. Brukal already fetched that document, mined two things from it, and
threw the rest away.

These are selection mechanisms only — what they choose still has to survive the same
differential proof, so a hostile spec can waste a request but never manufacture a
finding.
"""
from __future__ import annotations

import json

from brukal.webmap import (AttackSurface, state_changing_operations,
                           writable_privileged_fields)

SPEC = json.dumps({
    "basePath": "/api",
    "paths": {
        "/users/{username}/password": {
            "put": {"requestBody": {"content": {"application/json": {
                "schema": {"properties": {"password": {"type": "string"}}}}}}},
            "get": {},
        },
        "/users/{id}": {"delete": {}, "get": {}},
        "/register": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"properties": {"username": {}, "password": {},
                                      "account_tier": {}, "is_verified": {}}}}}}}},
        "/health": {"get": {}},
    },
})


def test_state_changing_operations_are_templated_writes_only():
    ops = state_changing_operations(SPEC)
    assert ("PUT", "/api/users/{username}/password") in ops
    assert ("DELETE", "/api/users/{id}") in ops
    # a GET mutates nothing, and an untemplated path has no owner to confuse
    assert all(m != "GET" for m, _ in ops)
    assert all("{" in p for _, p in ops)


def test_privileged_fields_come_from_the_apps_own_vocabulary():
    """The point of mining rather than guessing: `account_tier` is in no fixed list."""
    fields = writable_privileged_fields(SPEC)
    assert "account_tier" in fields and "is_verified" in fields
    assert "password" not in fields and "username" not in fields


def test_malformed_or_hostile_specs_yield_nothing_rather_than_raising():
    for junk in ("", "not json", "[]", '{"paths": "nope"}', '{"paths": {"/a": 3}}'):
        assert state_changing_operations(junk) == []
        assert writable_privileged_fields(junk) == []


def test_bfla_discovery_prefers_the_spec_over_the_name_heuristic():
    """The heuristic only matched routes ending in 'password'. An app that calls the
    same operation /accounts/{id}/credentials was invisible to it."""
    from brukal.assist import AssistSession
    sess = AssistSession.__new__(AssistSession)          # discovery needs no I/O
    s = AttackSurface(seed="http://t/")
    s.add_routes(["/accounts/{id}/credentials", "/auth/login", "/accounts"])
    s.write_operations = [("PUT", "/accounts/{id}/credentials")]
    sess.surface, sess.last_jwt, sess.target = s, "tok", "t"
    sess.identity, sess.browser = "me", None
    change = sess.bfla_targets()
    # browser is None so victim lookup returns "" and the tuple is None overall — but
    # the point under test is that the SPEC route was selected, not the name pattern.
    assert change is None                                 # no victim discoverable
    s2 = AttackSurface(seed="http://t/")
    s2.add_routes(["/accounts/{id}/credentials", "/auth/login"])
    s2.write_operations = [("PUT", "/accounts/{id}/credentials")]
    sess.surface = sess.surface = s2
    sess._other_principal = lambda *a, **k: "victim"
    assert sess.bfla_targets() == ("http://t/accounts/{id}/credentials",
                                   "http://t/auth/login", "victim")


def test_credential_operations_outrank_other_writes_in_the_spec():
    """The live regression: VAmPI's own document lists PUT /users/{u}/email BEFORE
    PUT /users/{u}/password. Taking the head of the list aimed the password-takeover
    proof at the email endpoint and silently lost a confirmed critical finding.
    Generalising the discovery must not cost the case it already handled."""
    from brukal.assist import AssistSession
    sess = AssistSession.__new__(AssistSession)
    s = AttackSurface(seed="http://t/")
    s.add_routes(["/users/v1", "/users/v1/login"])
    s.write_operations = [("DELETE", "/users/v1/{username}"),
                          ("PUT", "/users/v1/{username}/email"),
                          ("PUT", "/users/v1/{username}/password")]
    sess.surface, sess.last_jwt, sess.target = s, "tok", "t"
    sess.identity, sess.browser = "me", None
    sess._other_principal = lambda *a, **k: "victim"
    change, _login, _victim = sess.bfla_targets()
    assert change == "http://t/users/v1/{username}/password"


def test_a_non_credential_write_is_still_used_when_that_is_all_there_is():
    """The generalisation must survive: an app whose only templated write is
    /accounts/{id}/credentials or /profile/{id} is still worth probing."""
    from brukal.assist import AssistSession
    sess = AssistSession.__new__(AssistSession)
    s = AttackSurface(seed="http://t/")
    s.add_routes(["/auth/login"])
    s.write_operations = [("PUT", "/profile/{id}")]
    sess.surface, sess.last_jwt, sess.target = s, "tok", "t"
    sess.identity, sess.browser = "me", None
    sess._other_principal = lambda *a, **k: "victim"
    assert sess.bfla_targets()[0] == "http://t/profile/{id}"
