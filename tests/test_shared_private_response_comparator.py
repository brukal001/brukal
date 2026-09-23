"""
test_shared_private_response_comparator.py — the both-allowed-AND-EQUAL isolation shape.

THE GAP (metamorphic access-control relation)
    Every access-control comparator in the closed set confirms on a DIFFERENCE — a refusal
    (`a_denied_b_allowed`), a size jump (`b_reveals_more`), a differing body
    (`bodies_differ`) — or needs the ownership ledger to name an owner
    (`cross_account_resource`). None can see the failure where two DISTINCT authenticated
    principals are handed the SAME private record: authentication is enforced, per-principal
    isolation is absent.

THE PROPERTY (an invariant, not a signature)
    A per-principal endpoint must not return identical private answers to different
    principals. The comparator confirms a VIOLATION when, and only when:
      - the two sides were genuinely different recorded identities (`distinct_principals`);
      - an unauthenticated caller issuing the SAME request was refused (`anon_refused`) —
        the guard against the public-endpoint false positive;
      - both sides succeeded (2xx) and are substantive;
      - the bodies are equal;
      - (in judge) the request is a read of the SAME url, and what remains after stripping
        the values WE submitted is non-empty — so an echo of our own input is not mistaken
        for a shared stored record.

    Bound MEDIUM / authz False: it proves the endpoint does not isolate per principal, not
    whose data was exposed — that judgement stays with a human, below the ledger-grounded
    cross-account HIGH.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp

COMPARATOR = "shared_private_response"

# A private-looking record with content beyond anything we submitted, so the echo guard
# has something to keep. Identical on both sides is the whole point.
PRIVATE = '{"balance":"4210.55","owner":"alice@example.com","statements":[1,2,3,4]}'
URL = "http://t:3000/api/me/dashboard"


class _R:
    """One observed response."""

    def __init__(self, status, body=""):
        self.status = status
        self.body = body


def _h(control_as="self", variant_as="second", *, url=URL, method="GET",
       variant_url=None):
    return hyp.Hypothesis(
        title="two principals, one private record", severity="high",
        comparator=COMPARATOR, setup=[],
        control={"method": method, "url": url, "as": control_as},
        variant={"method": method, "url": variant_url or url, "as": variant_as})


def _ctx(distinct=True, anon_refused=True, profile=None):
    return {"distinct_principals": distinct, "anon_refused": anon_refused,
            "profile": profile}


# --------------------------------------------------------------------------- #
# POSITIVE CONTROL — the finding this comparator exists to publish
# --------------------------------------------------------------------------- #

def test_two_distinct_principals_get_the_same_private_record_confirms():
    holds, meaning = hyp.judge(_h(), _R(200, PRIVATE), _R(200, PRIVATE),
                               None, _ctx())
    assert holds is True
    assert meaning  # the comparator's recorded meaning travels with the verdict


def test_confirmation_is_bounded_medium_and_not_an_authorization_claim():
    claim = hyp.derive_claim(COMPARATOR, "self", "second",
                             {"url": URL, "status": 200, "size": len(PRIVATE)},
                             {"url": URL, "status": 200, "size": len(PRIVATE)})
    assert claim["severity_cap"] == "medium"
    assert claim["authz"] is False
    assert claim["evidence_class"] == COMPARATOR
    # The model cannot inflate past the class cap, and may ask for less.
    assert hyp.cap_severity("critical", claim["severity_cap"]) == "medium"
    assert hyp.cap_severity("high", claim["severity_cap"]) == "medium"
    assert hyp.cap_severity("low", claim["severity_cap"]) == "low"


# --------------------------------------------------------------------------- #
# NEGATIVE CONTROLS — each refuses one specific false positive
# --------------------------------------------------------------------------- #

def test_same_session_is_not_an_isolation_claim():
    # Two reads from one principal say nothing about isolation.
    holds, _ = hyp.judge(_h(control_as="self", variant_as="self"),
                         _R(200, PRIVATE), _R(200, PRIVATE),
                         None, _ctx(distinct=False))
    assert holds is False


def test_public_endpoint_is_not_a_leak():
    # Anonymous was NOT refused — the same body to everyone is public, not private.
    holds, _ = hyp.judge(_h(), _R(200, PRIVATE), _R(200, PRIVATE),
                         None, _ctx(anon_refused=False))
    assert holds is False


def test_a_refusal_on_one_side_is_not_this_shape():
    # That is `a_denied_b_allowed`, not shared isolation. Both must be allowed.
    holds, _ = hyp.judge(_h(), _R(403, ""), _R(200, PRIVATE), None, _ctx())
    assert holds is False


def test_a_server_error_is_not_a_shared_record():
    holds, _ = hyp.judge(_h(), _R(200, PRIVATE), _R(500, PRIVATE), None, _ctx())
    assert holds is False


def test_differing_bodies_are_not_a_shared_record():
    other = '{"balance":"9.99","owner":"bob@example.com","statements":[7]}'
    holds, _ = hyp.judge(_h(), _R(200, PRIVATE), _R(200, other), None, _ctx())
    assert holds is False


def test_two_empty_bodies_are_not_substantive():
    holds, _ = hyp.judge(_h(), _R(200, ""), _R(200, ""), None, _ctx())
    assert holds is False


def test_a_write_is_out_of_scope_even_when_equal():
    # A POST that returns the same body is not a read of a shared stored record.
    holds, _ = hyp.judge(_h(method="POST"), _R(200, PRIVATE), _R(200, PRIVATE),
                         None, _ctx())
    assert holds is False


def test_different_requests_answering_alike_prove_nothing():
    holds, _ = hyp.judge(
        _h(variant_url="http://t:3000/api/me/settings"),
        _R(200, PRIVATE), _R(200, PRIVATE), None, _ctx())
    assert holds is False


def test_an_echo_of_our_own_input_is_not_a_shared_record():
    # The whole body is a value we submitted in the url; nothing survives the strip.
    token_url = "http://t:3000/api/items/hello-world-token"
    body = "hello-world-token"
    holds, _ = hyp.judge(_h(url=token_url), _R(200, body), _R(200, body),
                         None, _ctx())
    assert holds is False


def test_a_missing_response_never_confirms():
    holds, _ = hyp.judge(_h(), None, _R(200, PRIVATE), None, _ctx())
    assert holds is False


# --------------------------------------------------------------------------- #
# DRIFT GUARD — a comparator and its bound must never diverge (the 2026-08-22 bug)
# --------------------------------------------------------------------------- #

def test_every_comparator_has_a_severity_bound_and_vice_versa():
    assert set(hyp._COMPARATORS) == set(hyp._EVIDENCE_CLASS), (
        "a comparator without a bound publishes at the generic low cap, and a bound "
        "without a comparator is dead — they must stay in lockstep")


def test_new_comparator_is_registered_everywhere_it_must_be():
    assert COMPARATOR in hyp._COMPARATORS
    assert COMPARATOR in hyp._EVIDENCE_CLASS
    # It reads engine-established context (distinct_principals, anon_refused), so it must be
    # dispatched with the four-argument signature, not silently called with two.
    assert COMPARATOR in hyp._CONTEXT_COMPARATORS


def test_every_context_comparator_is_a_real_comparator():
    for name in hyp._CONTEXT_COMPARATORS:
        assert name in hyp._COMPARATORS
