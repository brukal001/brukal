"""
test_auto_context_brief.py — `auto --context` seeds the planner's focus.

Direction from the operator's first live run (2026-09-29): on a fresh target the
planner wandered (proposed nmap/whatweb the gate denied, never converged on the
category-filter SQLi) because it had NO per-target brief — what the app is, what to
focus on. `--context` feeds that brief into the strategist's objective channel as
RECOVERED INTENT ONLY: it steers what the model proposes; every proposal still passes
the deterministic gate unchanged, so a brief can never widen scope or authorise a host.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import brukal.assist  # noqa: F401,E402  (package import order; assist is the entry)
from brukal import AuditLog, Executor, FakeKali, Gate, load_scope  # noqa: E402
from brukal.agents import StrategistAgent  # noqa: E402
from brukal.assist import AssistSession  # noqa: E402
from brukal.assist_cli import _apply_context, _context_objectives  # noqa: E402

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


class StubLLM:
    def __init__(self, response):
        self.response = response
        self.last_user = None

    def propose(self, system, user, max_tokens=1024):
        self.last_user = user
        return self.response


# --- _context_objectives: normalise None / str / list into clean lines ---------

def test_context_objectives_normalises():
    assert _context_objectives(None) == []
    assert _context_objectives("") == []
    assert _context_objectives("  SQLi in category filter  ") == ["SQLi in category filter"]
    # newlines split into separate objective lines; blanks dropped
    assert _context_objectives("a\n\n  b  ") == ["a", "b"]
    # a list is accepted; order preserved; exact dupes dropped
    assert _context_objectives(["x", "x", " y "]) == ["x", "y"]


# --- _apply_context: sets objectives AND they reach the planner prompt ---------

def test_apply_context_sets_objectives_and_reaches_planner():
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        stub = StubLLM("PHASE: recon\nGOAL: focus\nRUN: nmap 10.10.10.5")
        ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(stub))

        added = _apply_context(sess, [
            "SQL injection in the product category filter",
            "goal: display one or more unreleased products",
        ])
        assert added == [
            "SQL injection in the product category filter",
            "goal: display one or more unreleased products",
        ]
        assert sess.objectives == added

        # the brief must actually reach the strategist's prompt
        sess.make_plan()
        assert "category filter" in (stub.last_user or "")
        assert "unreleased products" in (stub.last_user or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_apply_context_empty_is_noop():
    scope = load_scope(SCOPE)
    tmp = tempfile.mkdtemp()
    try:
        ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tmp) / "a.jsonl"))
        sess = AssistSession("10.10.10.5", ex, StrategistAgent(StubLLM("")))
        assert _apply_context(sess, None) == []
        assert sess.objectives == []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
