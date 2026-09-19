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


def test_the_dashboard_STILL_credits_the_challenges_it_really_proves(tmp_path):
    """POSITIVE CONTROL, and the boundary that matters: narrowing challenge 15 must not
    silently cost the credits that confirmation legitimately earns. Challenge 14 — an
    endpoint performing no authentication check — is proved by exactly this."""
    m = measure(_ledger(tmp_path, _rounds() + _confirmed([DASH], "cross_account_resource")))
    assert _of(m, 14)["state"] == "FOUND"


def test_a_real_forged_token_DOES_credit_challenge_15(tmp_path):
    """The other half: narrowing must not make the challenge unreachable. A confirmation
    carrying the token-forgery surface still counts."""
    rows = _rounds() + _confirmed(["http://t/identity/api/auth/v4.0/user/login-with-token"],
                                  "a_denied_b_allowed", "Forged token accepted")
    m = measure(_ledger(tmp_path, rows))
    assert _of(m, 15)["state"] == "FOUND"
