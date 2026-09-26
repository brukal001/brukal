"""
test_auto_confirm.py — capability lever #1: corroborate what the model reaches
(docs/AUTO_CONFIRM_REACHED.md).

crAPI #12 leak: the model POSTed a NoSQL operator to the coupon endpoint 150x and got the
free coupon, but scored 0 because only a proof-carrying differential counts. auto-confirm
runs the matching confirm_* on the endpoint the model's own command reached, turning
"the model did it" into a scored CONFIRMED finding. Opt-in, deduped, bounded, and it only
records what a differential PROVES.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, FakeKali, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "127.0.0.1"
BASE = f"http://{TARGET}:5000"
COUPON = f"{BASE}/community/api/v2/coupon/validate-coupon"


class _CouponCage:
    """Vulnerable coupon lookup: a benign string matches nothing (404); a NoSQL operator
    object matches any coupon (200)."""
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable

    def run(self, action):
        try:
            body = json.loads(action.body or "{}")
        except Exception:
            body = {}
        if isinstance(body.get("coupon_code"), dict) and self.vulnerable:
            return WebResult(status=200, url=action.url,
                             body=json.dumps({"coupon": "TRAC075", "amount": 75}))
        return WebResult(status=404, url=action.url, body='{"message":"not found"}')


def _session(vulnerable=True, on=True):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit, approver=lambda d: True),
                      StrategistAgent(type("L", (), {"propose": lambda s, *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _CouponCage(vulnerable), audit))
    s.allow_intrusive = True
    s.auto_confirm_reached = on
    s.surface = AttackSurface(seed=f"{BASE}/")
    return s


CMD = f"curl -s -X POST {COUPON} -H 'Content-Type: application/json' --data '{{\"coupon_code\":\"NOPE\"}}'"


def test_a_reached_endpoint_is_auto_confirmed_into_a_finding():
    s = _session()
    n = s._auto_confirm_reached(CMD)
    assert n == 1
    f = next(f for f in s.findings.all() if f.title == "NoSQL injection (operator)")
    assert f.confirmed and "validate-coupon" in f.target


def test_off_by_default_does_nothing():
    s = _session(on=False)
    assert s._auto_confirm_reached(CMD) == 0
    assert not s.findings.all()


def test_a_non_vulnerable_endpoint_is_not_falsely_confirmed():
    s = _session(vulnerable=False)                 # operator -> 404, benign -> 404
    assert s._auto_confirm_reached(CMD) == 0
    assert not any(f.title == "NoSQL injection (operator)" for f in s.findings.all())


def test_the_same_command_is_confirmed_once():
    s = _session()
    assert s._auto_confirm_reached(CMD) == 1
    assert s._auto_confirm_reached(CMD) == 0       # deduped
    assert sum(1 for f in s.findings.all() if f.title == "NoSQL injection (operator)") == 1


def test_it_fires_through_the_absorb_shell_hook():
    """Guards a dead hook: the confirmation must fire from the real observation point, not
    only when called directly."""
    s = _session()
    decision, result = s.executor.run(CMD, TARGET, agent="exploit")
    s._absorb_shell(CMD, decision, result)
    assert any(f.title == "NoSQL injection (operator)" and f.confirmed
               for f in s.findings.all())
