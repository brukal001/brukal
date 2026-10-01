"""
test_confirm_from_capture_wiring.py — Task 9: `_confirm_from_capture` always-on wiring.

capture_confirm.findings_from_capture (Task 8) can prove a finding from traffic the
gated door already captured, but nothing called it. This test proves:
  1. `_confirm_from_capture()` turns a captured is-solved banner into exactly one
     CONFIRMED finding via `_record_confirmed`.
  2. A second call does NOT double-record (FindingStore dedup by signature).
  3. `confirm_surface()` — the method the hunt loop already calls once per round —
     invokes it too, unconditionally (always-on, no env flag).
  4. (fix round 1) `browser.captured()` is cumulative and never cleared, and
     `_confirm_from_capture` runs every round — so the SAME capture must not be
     re-recorded on every later round. FindingStore already dedups the store, but
     `_record_confirmed` unconditionally appends to `highlights`/`notes` and emits a
     fresh `experiment_result`/`experiment_outcome` audit pair regardless of whether
     the Finding was new. `_confirm_from_capture` must therefore emit each unique
     capture-finding signature AT MOST ONCE across the whole run, not just dedupe the
     FindingStore.
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
    audit_path = Path(tempfile.mkdtemp()) / "a.jsonl"
    scope = load_scope(SCOPE)
    audit = AuditLog(audit_path)
    s = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit, approver=lambda d: True),
                      StrategistAgent(type("L", (), {"propose": lambda s, *a, **k: ""})()),
                      browser=GovernedBrowser(scope, _SolvedCage(), audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed=f"{BASE}/")
    return s, audit_path


def _rows(audit_path):
    if not Path(audit_path).exists():
        return []
    return [json.loads(l) for l in open(audit_path) if l.strip()]


def test_confirm_from_capture_records_exactly_one_finding_and_dedups():
    s, _ = _session()
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
    s, _ = _session()
    s.browser = None
    assert s._confirm_from_capture() == 0


def test_confirm_surface_invokes_confirm_from_capture_every_round():
    s, _ = _session()
    s.browser.run(WebAction("request", url=SOLVED_URL, method="GET"))
    # confirm_surface short-circuits to 0 immediately when surface is None, which is
    # exactly the early-return path the always-on capture read must survive.
    s.surface = None
    s.confirm_surface()
    confirmed = s.findings.confirmed()
    assert len(confirmed) == 1
    assert confirmed[0].title == "Lab solved (exploit succeeded)"


def test_a_persistent_capture_is_not_reemitted_every_round():
    """The regression this fix round closes: `captured()` never clears, so a single
    captured is-solved banner is still sitting there on round 2 and round 3. Driving
    `confirm_surface()` (the real per-round call site) three times over that ONE
    persistent capture must leave the FindingStore AND every side-effect channel
    (`highlights`, `notes`, audit `experiment_outcome`) at exactly ONE — not three."""
    s, audit_path = _session()
    s.browser.run(WebAction("request", url=SOLVED_URL, method="GET"))
    s.surface = None   # keep confirm_surface's active sweep out of the way

    for _ in range(3):
        s.confirm_surface()

    assert len(s.findings.confirmed()) == 1

    capture_highlights = [h for h in s.highlights
                          if h[0] == "confirmed" and "Lab solved" in h[1]]
    assert len(capture_highlights) == 1, (
        f"expected exactly 1 highlight for the one capture-finding, got "
        f"{len(capture_highlights)} over 3 rounds")

    capture_notes = [note for note in s.notes
                     if "Lab solved" in note and "[confirm]" in note]
    assert len(capture_notes) == 1, (
        f"expected exactly 1 [confirm] note, got {len(capture_notes)} over 3 rounds")

    outcomes = [r for r in _rows(audit_path)
               if r.get("kind") == "experiment_outcome"
               and r["data"].get("comparator") == "lab_solved_banner"]
    assert len(outcomes) == 1, (
        f"expected exactly 1 experiment_outcome for the one capture-finding, got "
        f"{len(outcomes)} over 3 rounds — the audit ledger must not be repolluted "
        f"by re-offering the same persistent capture")
