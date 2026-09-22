"""
test_a_credit_needs_the_challenges_own_evidence.py — GAP #23, third and fourth instances.

THE MEASURING INSTRUMENT HAS NOW MIS-CREDITED FOUR TIMES. It matches a challenge by URL
SUBSTRING alone, so any confirmed experiment touching a challenge's endpoint credits that
challenge no matter what the experiment actually showed:

  CR2 c1  ch15 "Forge a valid JWT"          <- a dashboard IDOR that merely READ the
                                               dashboard. "alg" appears 0 times in that
                                               ledger. (narrowed 2026-09-20)
  CR2 c2  ch13 "Redeem a claimed coupon BY MODIFYING THE DATABASE" (SQLi)
                                            <- the foreign-value coupon experiment. Not
                                               narrowed, so it recurred:
  CR3 r1  ch13  same false credit again
  CR3 r1  ch3  "Reset the password of a DIFFERENT USER"
                                            <- "Account enumeration via forget-password".
                                               Enumerating which accounts exist is not
                                               resetting one.
  CR3 r1  ch14 "An endpoint that performs NO AUTHENTICATION CHECK"
                                            <- a `cross_account_resource` confirmation,
                                               i.e. an AUTHENTICATED user reading another
                                               user's data. That is a broken authorisation
                                               check, not a missing authentication one.

Run 1 printed 4 of 14 — double a ceiling no configuration had ever passed. Three of those
four credits were false. Quoting it would have been this project's first reported
breakthrough, and it would have been an artifact of its own scorer.

THE FIX. A challenge may carry a GATE: a predicate on the confirming experiment, not just
on its URL. The URL says WHERE the experiment looked; the gate says whether what it found
is the thing this challenge describes.

DELIBERATELY ONE-DIRECTIONAL. This edit only ever REMOVES credit. No signature is widened
and none is added, even where a finding would arguably qualify under a broader reading —
CR3 r1's unauthenticated read of another tenant's order is genuinely an endpoint with no
authentication check, but crediting challenge 14 for it would mean loosening the scorer in
the same edit that tightens it, and a scorer that gains recall from its own correction is
not evidence. It stays a MISS.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from crapi_recall import CHALLENGES, _credits


def _chal(cid):
    return [c for c in CHALLENGES if c[0] == cid][0]


def _exp(title, comparator, urls, outcome="confirmed"):
    return {"outcome": outcome, "title": title, "comparator": comparator,
            "urls": urls, "attribution": ""}


def test_account_enumeration_does_NOT_credit_resetting_another_users_password():
    """CR3 r1's false credit on challenge 3."""
    e = _exp("Account enumeration via forget-password (correct request)", "status_differs",
             ["http://t/identity/api/auth/forget-password"])
    assert not _credits(_chal(3), e), "enumeration credited as a password reset"


def test_a_foreign_value_coupon_does_NOT_credit_the_SQL_INJECTION_challenge():
    """CR2 c2's false credit, unnarrowed, recurring in CR3 r1."""
    e = _exp("/workshop/api/shop/apply_coupon: does a coupon_code issued to another "
             "account behave differently from one issued to nobody?", "status_differs",
             ["http://t/workshop/api/shop/apply_coupon"])
    assert not _credits(_chal(13), e), "a coupon reuse credited as modifying the database"


def test_a_cross_account_IDOR_does_NOT_credit_NO_AUTHENTICATION_CHECK():
    """CR3 r1's false credit on challenge 14. An authenticated user reading someone
    else's record is a broken authorisation check, not a missing authentication one."""
    e = _exp("Dashboard IDOR exposes another user profile", "cross_account_resource",
             ["http://t/identity/api/v2/user/dashboard"])
    assert not _credits(_chal(14), e), "an authenticated IDOR credited as unauthenticated"


def test_the_REAL_evidence_still_credits_each_one():
    """THE OTHER HALF: a gate that rejects everything would score 0 and look rigorous.
    Each challenge must still be creditable by the evidence it actually describes."""
    assert _credits(_chal(14), _exp(
        "Community posts readable with NO credentials", "unauthenticated_exposure",
        ["http://t/community/api/v2/community/posts"]))
    assert _credits(_chal(13), _exp(
        "SQL injection in coupon_code redeems a claimed coupon", "bodies_differ",
        ["http://t/community/api/v2/coupon/validate-coupon"]))
    assert _credits(_chal(3), _exp(
        "OTP brute force resets another user's password", "state_changed",
        ["http://t/identity/api/auth/v3/check-otp"]))


def test_an_ungated_challenge_is_unchanged():
    """Only the four audited challenges gain a gate; the rest keep URL matching."""
    assert _credits(_chal(4), _exp(
        "Addressed record at orders is readable with NO credentials",
        "unauthenticated_exposure", ["http://t/workshop/api/shop/orders/9"]))
