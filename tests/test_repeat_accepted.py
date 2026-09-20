"""
test_repeat_accepted.py — a comparator whose CONFIRMATION means the reuse worked.

WHY A NEW ONE, rather than reusing an existing comparator
    The reuse question is "was a value the application already consumed accepted AGAIN".
    Every existing comparator answers it BACKWARDS:

      status_differs  confirms when the two answers DIFFER — which is the app enforcing
                      single-use, the SAFE outcome, reported as a finding.
      bodies_differ   same inversion.
      b_errors_a_does_not  confirms when the second errors — again the safe outcome.

    Wiring any of them would have manufactured a "finding" out of correct behaviour, which
    is worse than having none. `repeat_accepted` confirms when BOTH attempts were accepted.

WHAT IT MAY AND MAY NOT CLAIM
    It sees two requests. It can say "this was accepted twice". It CANNOT say the value was
    single-use — plenty of operations are legitimately repeatable — so its severity cap is
    LOW and its claim says exactly what was shown. The interesting part is the CONJUNCTION
    with a link: the value came from `capture.link_fields`, meaning the application itself
    handed it back, and it was then accepted again. A human judges whether that operation
    should have been single-use.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.hypothesis import _COMPARATORS, _EVIDENCE_CLASS, derive_claim


class _R:
    def __init__(self, status, body=""):
        self.status, self.body = status, body


def _judge(a, b):
    fn = _COMPARATORS["repeat_accepted"][0]
    try:
        return bool(fn(a, b))
    except TypeError:
        return bool(fn(a, b, None))


def test_two_acceptances_CONFIRM():
    """The reuse worked: the application took the same state-changing request twice."""
    assert _judge(_R(200, '{"credit":90}'), _R(200, '{"credit":105}')) is True


def test_the_app_refusing_the_second_use_does_NOT_confirm():
    """THE INVERSION THIS EXISTS TO AVOID. Single-use enforced is correct behaviour and
    must never be reported as a finding."""
    assert _judge(_R(200), _R(400, '{"message":"coupon already used"}')) is False
    assert _judge(_R(200), _R(403)) is False
    assert _judge(_R(200), _R(500)) is False


def test_a_failed_FIRST_attempt_does_not_confirm():
    """If the first replay was already refused there is no reuse to speak of, whatever
    the second did."""
    assert _judge(_R(400), _R(400)) is False
    assert _judge(_R(400), _R(200)) is False


def test_no_answer_does_not_confirm():
    assert _judge(_R(None), _R(200)) is False
    assert _judge(_R(200), _R(None)) is False


def test_it_has_a_severity_BOUND_in_the_same_edit():
    """The file's own rule: a comparator that gains a meaning gains a bound with it, or
    the two drift and a verdict goes out under a sentence nobody verified."""
    assert "repeat_accepted" in _EVIDENCE_CLASS
    claim, cap, authz = _EVIDENCE_CLASS["repeat_accepted"]
    assert cap == "low", "repetition alone is not proof that an operation is single-use"
    assert authz is False, "this comparator says nothing about WHO may do something"
    assert "accept" in claim.lower()


def test_the_derived_claim_does_not_overstate():
    d = derive_claim("repeat_accepted", "self", "self", None, None)
    text = (d.get("claim") or "").lower()
    assert "twice" in text or "again" in text or "more than once" in text
    assert "vulnerab" not in text, "the comparator may not call it a vulnerability"
    assert d.get("severity_cap") == "low"
    assert d.get("authz") is False
