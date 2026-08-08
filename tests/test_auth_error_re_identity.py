"""
test_auth_error_re_identity.py — the auth-failure pattern cannot drift.

`_AUTH_ERROR_RE` used to be one object; the A1 port left two byte-identical copies
(auth.py's SessionOracle and assist.py's AssistSession). Byte-identical is not the
same as one object: a phrase added to one copy but not the other makes the oracle
LESS able to see an explicit failure — the exact failure mode auth.py exists to
prevent. Asserting identity, not equality, makes drift impossible rather than
merely unlikely: this test fails the moment either side stops importing the other's
pattern and starts compiling its own again.
"""
from __future__ import annotations

from brukal.assist import AssistSession
from brukal.auth import SessionOracle


def test_assist_session_and_session_oracle_share_the_identical_pattern_object():
    assert AssistSession._AUTH_ERROR_RE is SessionOracle._AUTH_ERROR_RE
