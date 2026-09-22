"""
test_a_confirmation_credits_only_its_own_challenge.py — GAP #23, caught in CR2 run 1.

THE MEASURED PROBLEM (2026-09-20)
    CR2 run 1 confirmed exactly TWO experiments and the benchmark reported **3 of 14**.
    The extra credit was challenge 15, "Forge a valid JWT token", awarded to:

        [cross_account_resource] Cross-account user dashboard IDOR
            http://172.20.0.12/identity/api/v2/user/dashboard?user_id=35

    because `/identity/api/v2/user/dashboard` sat in challenge 15's signature list. **No
    token was ever forged** — the string "alg" appears ZERO times in that run's ledger.

    A shared URL therefore credited a challenge whose evidence class is completely
    different. That is the same family as this file's oldest law, COVERAGE IS NOT A
    FINDING, one step along: **a confirmation on a URL is not a confirmation of every
    challenge whose signature contains that URL.** Left alone it would have gone into a
    write-up as a 50% recall improvement over the true number, in the very run where
    recall moved for the first time in seven attempts — the worst possible moment to
    over-report.

THE PROPERTY
    Forging a JWT is proved by a FORGED TOKEN being accepted, never by reading a dashboard
    that an ordinary session can already read.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.crapi_recall import measure

DASH = "http://t/identity/api/v2/user/dashboard?user_id=35"


def _ledger(tmp_path, rows):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


def _confirmed(urls, comparator, title="t"):
    out = [{"kind": "experiment_result", "data": {"url": u}} for u in urls]
    out.append({"kind": "experiment_outcome",
                "data": {"title": title, "outcome": "confirmed", "stage": "judged",
                         "comparator": comparator, "attribution": "MEASURED"}})
    return out


def _rounds(n=4):
    return [{"kind": "experiment_round", "data": {"source": "model", "proposals": 6}}
            for _ in range(n)]


def _of(m, cid):
    return [r for r in m["results"] if r["id"] == cid][0]


def test_a_dashboard_IDOR_does_not_credit_JWT_FORGERY(tmp_path):
    """CR2 run 1's exact shape."""
    m = measure(_ledger(tmp_path, _rounds() + _confirmed([DASH], "cross_account_resource",
                                                         "Cross-account user dashboard IDOR")))
    assert _of(m, 15)["state"] != "FOUND", (
        "reading a dashboard was credited as forging a token")


def test_a_cross_account_IDOR_does_not_credit_NO_AUTHENTICATION_CHECK_either(tmp_path):
    """CORRECTED 2026-09-22, and this test previously asserted the OPPOSITE.

    It used to read: "Challenge 14 — an endpoint performing no authentication check — is
    proved by exactly this", and it credited a `cross_account_resource` dashboard
    confirmation. That claim is wrong, and the comparator's own definition is what settles
    it: `_cross_account_resource` requires BOTH SIDES ALLOWED between members of
    `_REGISTERED_PRINCIPALS = ("self", "second")`, and the module states that `anonymous`
    "can never be the recorded owner of anything". It is an authenticated-vs-authenticated
    comparison BY CONSTRUCTION. It shows a broken AUTHORISATION check; challenge 14 is a
    missing AUTHENTICATION one, and the two are different failures.

    The narrowing that introduced this test fixed challenge 15 and left 14 holding the
    same wrong credit — which is why CR3 run 1 reported it again. A positive control is
    only as good as the claim it encodes."""
    m = measure(_ledger(tmp_path, _rounds() + _confirmed([DASH], "cross_account_resource")))
    assert _of(m, 14)["state"] != "FOUND", (
        "an authenticated cross-account read was credited as an endpoint with no "
        "authentication check")


def test_challenge_14_is_STILL_creditable_by_the_evidence_it_describes(tmp_path):
    """THE OTHER HALF, which is what the overturned test was for: narrowing must not make
    a challenge unreachable. An UNAUTHENTICATED read of the same endpoint credits it."""
    m = measure(_ledger(tmp_path, _rounds() + _confirmed(
        [DASH], "unauthenticated_exposure", "Dashboard readable with NO credentials")))
    assert _of(m, 14)["state"] == "FOUND"


def test_a_real_forged_token_DOES_credit_challenge_15(tmp_path):
    """The other half: narrowing must not make the challenge unreachable. A confirmation
    carrying the token-forgery surface still counts."""
    rows = _rounds() + _confirmed(["http://t/identity/api/auth/v4.0/user/login-with-token"],
                                  "a_denied_b_allowed", "Forged token accepted")
    m = measure(_ledger(tmp_path, rows))
    assert _of(m, 15)["state"] == "FOUND"
