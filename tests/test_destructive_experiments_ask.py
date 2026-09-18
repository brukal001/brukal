"""
test_destructive_experiments_ask.py — a destructive experiment ASKS; it is never dropped.

THE MEASURED PROBLEM (CR1 run 4, 2026-09-18)
    crAPI challenge 3 is "reset the password of a different user". The model proposed
    exactly that experiment, and `_run_one_round` refused it before dispatch:

        outcome: skipped   stage: refused   "SKIPPED (destructive path)"

    Nothing asked the operator. Meanwhile the COMMAND path escalates destructive actions
    to the human approver and ran 11 of them in that same engagement. So a destructive
    curl is a question for the operator, and a destructive experiment is a silent refusal
    — the same action, two different answers, decided by which code path reached it.

THE POSITION THIS ENCODES (the maintainer's, stated 2026-09-18)
    Brukal must be able to perform destructive work WHEN THE OPERATOR HAS AUTHORISED IT,
    and where it needs that authorisation it must ASK. Capability is not traded away for
    tidiness; the decision belongs to a human and the record must show who made it.

WHAT DOES NOT CHANGE
    Fail-closed stays fail-closed. The default approver refuses, an engagement that has
    not opted in still does not act, and the refusal is now RECORDED as an operator
    decision instead of vanishing as a skip. Scope is still the authorisation artifact:
    `destructive_allowed` is a disclosed per-engagement parameter, in the fingerprint and
    in the authorisation record, exactly like `tls_verify` and `rate_limit_per_min`.
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
from brukal.hypothesis import Hypothesis, attribution
from brukal.kali import ExecResult
from brukal.scope import authorization_record
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
RESET = f"{BASE}/identity/api/auth/reset-password"


def _scope(tmp_path, **over):
    data = json.loads(SCOPE.read_text())
    data.update(over)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(data))
    return load_scope(p)


def _destructive():
    return Hypothesis(
        title="Password reset allows resetting another account's password",
        severity="critical", comparator="cross_account_resource",
        control={"method": "POST", "url": RESET, "as": "self"},
        variant={"method": "POST", "url": RESET, "as": "second"},
        rationale="challenge 3", setup=[])


def _benign():
    return Hypothesis(
        title="Dashboard exposure", severity="high", comparator="cross_account_resource",
        control={"method": "GET", "url": f"{BASE}/identity/api/v2/user/dashboard", "as": "self"},
        variant={"method": "GET", "url": f"{BASE}/identity/api/v2/user/dashboard", "as": "second"},
        rationale="baseline", setup=[])


def _session(tmp_path, approver, **scope_over):
    scope = _scope(tmp_path, **scope_over)
    audit = AuditLog(tmp_path / "a.jsonl")
    asked = []
    def _approve(decision):
        asked.append(decision)
        return approver(decision)
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=_approve)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, type("C", (), {
                          "run": lambda self, a: WebResult(status=200, url=a.url,
                                                           body='{"ok":true}')})(), audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    return s, audit, asked


def _outcomes(audit):
    return [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == "experiment_outcome"]


# --------------------------------------------------------------------------- #
# It asks
# --------------------------------------------------------------------------- #

def test_a_destructive_experiment_ASKS_THE_OPERATOR(tmp_path):
    """THE DEFECT: run 4 dropped challenge 3 without asking anyone."""
    s, _audit, asked = _session(tmp_path, lambda d: False, destructive_allowed=True)
    s._run_one_round([_destructive()], [], [])
    assert asked, "the operator was never asked — the proposal was dropped"
    assert asked[0].verdict == "ESCALATE", asked[0].verdict


def test_when_the_operator_APPROVES_it_is_dispatched(tmp_path):
    """Capability, not tidiness: an authorised destructive experiment RUNS — it reaches
    dispatch and is judged on its evidence like any other.

    Both sides are `as: self` here because this test is about the authorisation gate, not
    the comparator: with no second principal the round would legitimately stop at
    `second_unavailable`, which is a different mechanism entirely."""
    h = _destructive()
    h.variant["as"] = "self"
    s, audit, _asked = _session(tmp_path, lambda d: True, destructive_allowed=True)
    s._run_one_round([h], [], [])
    out = _outcomes(audit)
    assert out, "the experiment vanished"
    assert out[-1]["outcome"] not in ("skipped", "refused_by_operator"), out[-1]
    assert out[-1]["stage"] == "judged", out[-1]


def test_when_the_operator_REFUSES_it_is_recorded_as_their_decision(tmp_path):
    """Not a skip, not a target refusal — a decision a human made, on the record."""
    s, audit, _asked = _session(tmp_path, lambda d: False, destructive_allowed=True)
    s._run_one_round([_destructive()], [], [])
    out = _outcomes(audit)
    assert out[-1]["outcome"] == "refused_by_operator", out[-1]
    assert out[-1]["attribution"] == "HARNESS-LIMIT", out[-1]


def test_the_decision_is_AUDITED(tmp_path):
    s, audit, _ = _session(tmp_path, lambda d: True, destructive_allowed=True)
    s._run_one_round([_destructive()], [], [])
    rows = [json.loads(l) for l in open(audit.path)]
    esc = [r for r in rows if r["kind"] == "web_decision" or r["kind"] == "approval"
           or (r.get("data") or {}).get("verdict") == "ESCALATE"]
    assert esc, "a destructive experiment was authorised with no record of the decision"


# --------------------------------------------------------------------------- #
# Fail-closed, and unchanged where it should be
# --------------------------------------------------------------------------- #

def test_without_scope_authorisation_it_does_not_act(tmp_path):
    """BOUNDARY: an engagement that never opted in still does nothing destructive — and
    now says so as an operator refusal instead of a silent skip."""
    s, audit, _asked = _session(tmp_path, lambda d: True)      # approver would say yes
    s._run_one_round([_destructive()], [], [])
    assert _outcomes(audit)[-1]["outcome"] == "refused_by_operator"


def test_scope_authorisation_is_DISCLOSED(tmp_path):
    """Same idiom as tls_verify: in the fingerprint, and in the authorisation record, so
    a run that was permitted to break things says so where a reader looks."""
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    off = _scope(tmp_path / "a")
    on = _scope(tmp_path / "b", destructive_allowed=True)
    assert off.destructive_allowed is False and on.destructive_allowed is True
    assert off.fingerprint() != on.fingerprint()
    assert authorization_record(on, TARGET)["destructive_allowed"] is True


def test_a_BENIGN_experiment_never_asks(tmp_path):
    """BOUNDARY: the ordinary path is untouched — no prompt, no escalation, no change."""
    s, _audit, asked = _session(tmp_path, lambda d: True, destructive_allowed=True)
    s._run_one_round([_benign()], [], [])
    assert asked == [], "a read-only experiment interrupted the operator"


def test_the_new_terminal_has_an_attribution():
    """The guard in test_outcome_attribution exists for exactly this."""
    assert attribution("refused_by_operator") == "HARNESS-LIMIT"
