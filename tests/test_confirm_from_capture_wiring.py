"""
test_confirm_from_capture_wiring.py — Task 9: `_confirm_from_capture` always-on wiring.

capture_confirm.findings_from_capture (Task 8) can prove a finding from traffic the
gated door already captured, but nothing called it. This test proves:
  1. `_confirm_from_capture()` turns a captured is-solved banner into exactly one
     CONFIRMED finding via `_record_confirmed`.
  2. A second call does NOT double-record (FindingStore dedup by signature).
  3. `confirm_surface()` — the method the hunt loop already calls once per round —
     invokes it too, unconditionally (always-on, no env flag).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, FakeKali, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebAction, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "127.0.0.1"
BASE = f"http://{TARGET}:5000"
SOLVED_URL = f"{BASE}/lab/solved"


class _SolvedCage:
    """Always answers with a PortSwigger-style is-solved banner — this test only
    needs ONE captured response for `_confirm_from_capture` to prove a finding from."""

    def run(self, action):
        return WebResult(status=200, url=action.url,
                         body="<div id='is-solved'>Congratulations, you solved the lab</div>")


def _session():
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit, approver=lambda d: True),
                      StrategistAgent(type("L", (), {"propose": lambda s, *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _SolvedCage(), audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed=f"{BASE}/")
    return s


def test_confirm_from_capture_records_exactly_one_finding_and_dedups():
    s = _session()
    # Populate browser.captured() the same way any confirm_* reflex does: one governed
    # request through the one door.
    s.browser.run(WebAction("request", url=SOLVED_URL, method="GET"))
    assert s.browser.captured(), "fixture must have produced a captured request"

    n = s._confirm_from_capture()
    assert n == 1
    confirmed = s.findings.confirmed()
    assert len(confirmed) == 1
    assert confirmed[0].title == "Lab solved (exploit succeeded)"

    # Second call: FindingStore dedups by signature — no new finding, no double-count.
    before = len(s.findings)
    n2 = s._confirm_from_capture()
    assert n2 == 0
    assert len(s.findings) == before


def test_confirm_from_capture_is_llm_free_and_safe_with_no_browser():
    s = _session()
    s.browser = None
    assert s._confirm_from_capture() == 0


def test_confirm_surface_invokes_confirm_from_capture_every_round():
    s = _session()
    s.browser.run(WebAction("request", url=SOLVED_URL, method="GET"))
    # confirm_surface short-circuits to 0 immediately when surface is None, which is
    # exactly the early-return path the always-on capture read must survive.
    s.surface = None
    s.confirm_surface()
    confirmed = s.findings.confirmed()
    assert len(confirmed) == 1
    assert confirmed[0].title == "Lab solved (exploit succeeded)"
