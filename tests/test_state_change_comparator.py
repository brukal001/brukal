"""
test_state_change_comparator.py — a new EVIDENCE CLASS: the proof is a side-effect.

WHY (measured across six CR1 runs)
    Every comparator Brukal has reads a RESPONSE DIFFERENTIAL — A versus B, status, body,
    size. Four of crAPI's fourteen measurable challenges cannot be proved that way, no
    matter how well the model plays:

        8, 9  mass assignment      the proof is that a BALANCE CHANGED
        10    internal properties  the proof is that a stored field CHANGED
        13    coupon re-redemption the proof is that the DATABASE CHANGED

    So these were never "hard for the model". They were unpublishable by construction,
    and that is the direct cost of the rule that a finding must be comparator-derived.

THE SHAPE, and why the existing one could not carry it
    `setup` always runs BEFORE both sides, so "read, act, read again" is inexpressible:
    by the time the control runs, the action has already happened and both reads see the
    same world. So a hypothesis may carry an `act` — a request dispatched BETWEEN the two
    reads — and `state_changed` judges whether the world moved.

THE SOUNDNESS PROBLEM, and the project's own answer to it
    Plenty of endpoints change on their own: timestamps, nonces, counters. A naive
    before/after diff would call every one of them a finding. So the baseline is read
    TWICE and must be identical before the action is allowed to count for anything —
    the same discipline `confirm_authentication` already uses when it probes an identity
    oracle anonymously twice before trusting it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.hypothesis import Hypothesis, comparator_names, judge, parse
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
BALANCE = f"{BASE}/workshop/api/shop/orders"
ACT = f"{BASE}/workshop/api/shop/orders/1/return_order"


class _Shop:
    """A shop whose balance moves only when the action is invoked."""

    def __init__(self, noisy=False, acts=True):
        self.balance = 100
        self.noisy = noisy
        self.acts = acts
        self.reads = 0
        self.seen: list = []

    def run(self, action):
        self.seen.append((action.method, action.url))
        if "return_order" in action.url:
            if self.acts:
                self.balance += 1000
            return WebResult(status=200, url=action.url, body='{"message":"returned"}')
        self.reads += 1
        extra = f',"nonce":{self.reads}' if self.noisy else ""
        return WebResult(status=200, url=action.url,
                         body=f'{{"balance":{self.balance}{extra}}}')


def _h(act=True):
    return Hypothesis(
        title="Return-order flow credits the account without a matching debit",
        severity="high", comparator="state_changed",
        control={"method": "GET", "url": BALANCE, "as": "self"},
        variant={"method": "GET", "url": BALANCE, "as": "self"},
        act=({"method": "POST", "url": ACT, "as": "self"} if act else None),
        rationale="challenge 9", setup=[])


def _session(tmp_path, cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    s.surface = AttackSurface(seed=f"{BASE}/")
    return s, audit


def _outcome(audit):
    rows = [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == "experiment_outcome"]
    return rows[-1] if rows else None


# --------------------------------------------------------------------------- #

def test_the_comparator_exists_and_is_offered_to_the_model():
    assert "state_changed" in comparator_names()


def test_a_hypothesis_can_carry_an_ACT():
    """Parsed from the model's own reply, like every other field."""
    got = parse(json.dumps([{
        "title": "t", "severity": "high", "comparator": "state_changed",
        "control": {"method": "GET", "url": BALANCE},
        "act": {"method": "POST", "url": ACT},
        "variant": {"method": "GET", "url": BALANCE}}]))
    assert got and got[0].act and got[0].act["url"] == ACT


def test_a_MOVED_world_is_a_finding(tmp_path):
    """THE POINT: read, act, read again — and the balance moved."""
    cage = _Shop()
    s, audit = _session(tmp_path, cage)
    s._run_one_round([_h()], [], [])
    out = _outcome(audit)
    assert out and out["outcome"] == "confirmed", out
    assert cage.balance == 1100


def test_a_world_that_did_NOT_move_is_not_a_finding(tmp_path):
    """BOUNDARY: the action ran and changed nothing. That is the application behaving."""
    s, audit = _session(tmp_path, _Shop(acts=False))
    s._run_one_round([_h()], [], [])
    assert _outcome(audit)["outcome"] == "not_confirmed"


def test_a_NOISY_endpoint_proves_nothing(tmp_path):
    """THE SOUNDNESS TEST. This endpoint changes on its own — a naive before/after diff
    would call every timestamped response a finding. The baseline is read twice and must
    be identical before the action counts for anything."""
    cage = _Shop(noisy=True)
    s, audit = _session(tmp_path, cage)
    s._run_one_round([_h()], [], [])
    out = _outcome(audit)
    assert out["outcome"] == "not_confirmed", out


def test_the_act_runs_BETWEEN_the_two_reads(tmp_path):
    """Ordering is the whole evidence. Read, read, act, read."""
    cage = _Shop()
    s, _audit = _session(tmp_path, cage)
    s._run_one_round([_h()], [], [])
    kinds = ["act" if "return_order" in u else "read" for _m, u in cage.seen]
    assert kinds == ["read", "read", "act", "read"], kinds


def test_without_an_act_it_cannot_hold(tmp_path):
    """BOUNDARY: `state_changed` with nothing performed between the reads is two reads of
    a stable endpoint, and must never be reported as a change."""
    s, audit = _session(tmp_path, _Shop())
    s._run_one_round([_h(act=False)], [], [])
    assert _outcome(audit)["outcome"] != "confirmed"


def test_the_claim_names_the_change_and_claims_nothing_more(tmp_path):
    """The derived claim must say a state we can observe moved after an action we
    performed — not that money was stolen."""
    holds, meaning = judge(_h(),
                           WebResult(status=200, url=BALANCE, body='{"balance":100}'),
                           WebResult(status=200, url=BALANCE, body='{"balance":1100}'),
                           None, {"baseline_stable": True, "acted": True})
    assert holds
    # And both facts are required: a change nothing was performed against has nothing to
    # attribute it to, so `acted` is as load-bearing as the stable baseline.
    assert not judge(_h(),
                     WebResult(status=200, url=BALANCE, body='{"balance":100}'),
                     WebResult(status=200, url=BALANCE, body='{"balance":1100}'),
                     None, {"baseline_stable": True, "acted": False})[0]
    low = meaning.lower()
    assert "state" in low or "changed" in low, meaning
    for overclaim in ("stole", "critical", "takeover", "money"):
        assert overclaim not in low, meaning
