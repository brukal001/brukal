"""
test_principal_handle_boundary.py — another principal's handle must match as a WHOLE
handle, never as a substring of a longer one.

THE DEFECT (found 2026-10-11 chasing a 7/40 flake in test_principal_switch_is_atomic)
    `_answered_as_another_principal` used `handle in text`. The second principal's
    generated email `brk8b0bf16f2a@brukal.test` CONTAINS the first principal's
    `a@brukal.test`, so whenever the random handle ended in "a" the second principal's
    own identity probe was recorded as an `authentication_mismatch` naming the first —
    a legitimate login REFUTED, and the cross-account lane it unlocks lost. Live, the
    same shape is `admin` vs `superadmin`, `bob@x.io` vs `jbob@x.io`.

Both directions: a longer handle that merely contains another is NOT a match; the
other principal's handle standing on its own (JSON value, quoted, plain text) IS.
"""
from __future__ import annotations

import pytest

from brukal.assist_auth import _AuthMixin


class _S(_AuthMixin):
    def __init__(self, handles):
        self._principal_handles = dict(handles)


H = {"self": "a@brukal.test", "second": "brk8b0bf16f2a@brukal.test"}


@pytest.mark.parametrize("body", [
    '{"user":{"id":41,"email":"brk8b0bf16f2a@brukal.test"}}',
    "logged in as brk8b0bf16f2a@brukal.test",
    '{"email":"xa@brukal.test"}',
    '{"email":"a@brukal.testing.io"}',
])
def test_handle_embedded_in_a_longer_one_is_not_another_principal(body):
    assert _S(H)._answered_as_another_principal(body, "second") == ""


@pytest.mark.parametrize("body", [
    '{"user":{"id":25,"email":"a@brukal.test"}}',
    "hello a@brukal.test, welcome",
    "<td>a@brukal.test</td>",
    "a@brukal.test",
])
def test_other_principals_own_handle_is_detected(body):
    assert _S(H)._answered_as_another_principal(body, "second") == "a@brukal.test"


def test_username_handles_respect_boundaries():
    s = _S({"self": "admin", "second": "superadmin"})
    assert s._answered_as_another_principal('{"username":"superadmin"}', "second") == ""
    assert s._answered_as_another_principal('{"username":"admin"}', "second") == "admin"
    assert s._answered_as_another_principal('{"username":"admin"}', "self") == ""
