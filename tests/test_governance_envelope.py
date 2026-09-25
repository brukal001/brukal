"""
test_governance_envelope.py — the safety envelope is legible in the ledger (roadmap §3.4).

The audit already records THAT a run stopped and why (engagement_stop). It did not record
the limits the run ran WITHIN — so a ledger reading `reason: budget` never said what the
budget was, and a third party could not verify the envelope from the audit alone. The loop
now writes a `governance_envelope` record at start: the budget ceilings, whether a kill
switch was armed, and the scope's rate/destructive/expiry facts. Pure instrumentation, and
it must not break the hash chain.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.budget import EngagementBudget
from brukal.kali import ExecResult
from brukal.killswitch import KillSwitch
from brukal.loop import GroundedLoop
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"


class _Done:
    last_stop_reason = "end_turn"

    def propose(self, *a, **k):
        return "PHASE: recon\nGOAL: finished\nREASONING: nothing further."


def _loop(tmp_path, **kw):
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(load_scope(SCOPE)), type("K", (), {
        "run": lambda s, c: ExecResult(c, 0, "ok", "")})(), audit, approver=lambda d: True)
    s = AssistSession("10.10.10.5", ex, StrategistAgent(_Done()))
    s.surface = AttackSurface(seed="http://10.10.10.5/")
    return GroundedLoop(s, max_steps=4, **kw), s, audit


def _envelopes(audit):
    return [json.loads(l)["data"] for l in audit.path.read_text().splitlines()
            if json.loads(l)["kind"] == "governance_envelope"]


def test_the_envelope_records_the_caps_kill_and_scope(tmp_path):
    budget = EngagementBudget(max_cost=0.5, max_steps=70,
                              max_research_fetches=5, max_wall_seconds=600)
    loop, _s, audit = _loop(tmp_path, budget=budget, kill=KillSwitch())
    loop.run()
    env = _envelopes(audit)
    assert len(env) == 1, "exactly one envelope, written at start"
    e = env[0]
    assert e["kill_switch_armed"] is True
    assert e["budget"]["max_cost"] == 0.5 and e["budget"]["max_steps"] == 70
    assert e["budget"]["max_research_fetches"] == 5
    assert e["scope"]["rate_limit_per_min"] is not None       # a disclosed measurement param
    assert "destructive_allowed" in e["scope"]
    assert audit.verify() is True                              # the new record keeps the chain


def test_no_budget_no_kill_is_recorded_honestly(tmp_path):
    loop, _s, audit = _loop(tmp_path)                          # no budget, no kill
    loop.run()
    e = _envelopes(audit)[0]
    assert e["budget"] is None and e["kill_switch_armed"] is False
    assert e["loop_max_steps"] == 4
    assert audit.verify() is True
