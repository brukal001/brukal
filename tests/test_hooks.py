"""
test_hooks.py — the deterministic event bus (roadmap §1.1) and its safety contract.

The bus must be USEFUL (observe lifecycle events; veto an action by a site-specific rule)
and INCAPABLE of weakening the invariants: a hook can only SKIP an action, never widen
scope or run anything, and a broken hook can neither crash a run nor open a path.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, HookBus, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.loop import GroundedLoop

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "127.0.0.1"


def _session():
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit, approver=lambda d: True)
    return AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()))


# ---- the bus itself --------------------------------------------------------

def test_emit_fires_observers_and_swallows_errors():
    seen = []
    bus = HookBus().on("start", lambda **c: seen.append(c)).on("start", lambda **c: 1 / 0)
    bus.emit("start", target="t")                          # the raising hook must not crash
    assert seen == [{"target": "t"}]
    bus.emit("never_registered")                           # no-op


def test_veto_returns_first_reason_and_a_raising_hook_is_silent():
    calls = []
    bus = (HookBus()
           .on("pre_action", lambda **c: calls.append("boom") or (_ for _ in ()).throw(ValueError()))
           .on("pre_action", lambda command, **c: "blocked /createdb" if "/createdb" in command else None))
    assert bus.veto("pre_action", command="curl http://h/createdb") == "blocked /createdb"
    assert bus.veto("pre_action", command="curl http://h/safe") is None
    assert calls == ["boom", "boom"]                       # the raising hook ran both times


# ---- the veto at the one door (session.run) --------------------------------

def test_a_pre_action_hook_can_skip_an_action_before_the_gate():
    s = _session()
    s.hooks = HookBus().on("pre_action",
                           lambda command, **c: "createdb is destructive" if "createdb" in command else None)
    decision, result, hl = s.run("curl http://127.0.0.1:5000/createdb")
    assert decision is None and result is None             # never reached the gate/cage
    assert any("vetoed" in h for h in hl)
    # a non-matching command is untouched and runs through the gate as normal
    decision2, _r2, _h2 = s.run("curl http://127.0.0.1:5000/")
    assert decision2 is not None


def test_a_hook_cannot_make_an_out_of_scope_command_run():
    """The load-bearing invariant: a pre_action hook that stays SILENT (returns None,
    i.e. 'allow') cannot widen scope — the gate still denies an out-of-scope command. A
    hook can only ever SUBTRACT."""
    s = _session()
    s.hooks = HookBus().on("pre_action", lambda **c: None)   # a hook that never vetoes
    decision, result, _hl = s.run("curl http://evil.example/")
    assert decision is not None and decision.verdict == "DENY"   # the gate, not the hook, rules
    assert result is None                                        # it did not execute


def test_no_bus_is_byte_identical():
    s = _session()
    assert s.hooks is None
    decision, _r, _hl = s.run("curl http://127.0.0.1:5000/")
    assert decision is not None                            # unchanged path


# ---- loop wiring -----------------------------------------------------------

def test_loop_attaches_the_bus_and_fires_lifecycle_events():
    s = _session()
    from brukal.webmap import AttackSurface
    s.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    started = []
    bus = HookBus().on("start", lambda **c: started.append(c))
    loop = GroundedLoop(s, max_steps=2, hooks=bus)
    assert s.hooks is bus                                   # the one door can see it
    loop.run()
    assert started, "the start lifecycle event never reached the hook bus"
