"""
test_funnel_from_the_ledger.py — the funnel is a property of the LEDGER, not of the notes.

THE MEASURED PROBLEM (run CM5, 2026-09-14)
    `_write_notebook` renders `self.notes[-40:]`. CM5 ran 70 steps, produced well over
    forty notes, and **every `[experiment]` line was evicted from `engagement.md`** — the
    file contains the string "experiment" zero times where CM4's contains it eight.

    No evidence was lost: `experiment_principal`, `experiment_result` and `ownership_match`
    are on the audit log. But the funnel — proposed / dispatched / resolved / judged /
    confirmed — had been computed by reading those notes for every previous run, and
    `proposed` and `judged` were NOT derivable from the ledger at all:

      * a proposal left no audit record until it dispatched or ran a setup, so a
        zero-setup proposal refused at reference resolution was invisible;
      * nothing distinguished "reached a comparator and did not hold" from "never judged",
        except `cross_account_resource`, which writes `ownership_match` either way.

    Third instance of self-report disagreeing with the ledger.

THE PROPERTY
    Every proposal writes `experiment_proposed`, and every terminal state writes
    `experiment_outcome`, so the funnel is derivable from the audit log BY CONSTRUCTION.
    `hypothesis.funnel()` is the single place it is computed, and every printed or
    reported count comes from it. Nothing counts by reading notes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope, redact
from brukal import hypothesis as hyp
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"


class _Target:
    """Answers the three shapes the funnel has to tell apart: a judged pair, a pair that
    both 500, and an endpoint a reference cannot resolve against."""

    def run(self, action):
        url = action.url
        if "/rest/basket/" in url:
            want = url.rsplit("/", 1)[-1]
            return WebResult(status=200, url=url, headers={}, body=json.dumps(
                {"status": "success", "data": {"id": int(want), "UserId": 25}}))
        if "/api/BasketItems" in url:
            return WebResult(status=500, url=url, headers={}, body='{"error":"boom"}')
        return WebResult(status=404, url=url, headers={}, body="nope")


class _Kali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _LLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return "[]"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(_LLM()),
                      browser=GovernedBrowser(scope, _Target(), audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    return s, audit


def _entries(audit_path):
    out = []
    for line in Path(audit_path).read_text(errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def _three_proposals():
    """One that is judged, one whose sides both fail, one whose reference cannot resolve."""
    return [
        # 200 against 404, so `status_differs` actually HOLDS. A pair that merely
        # dispatches would leave `judged` and `confirmed` indistinguishable here.
        hyp.Hypothesis(title="judged pair", severity="high", comparator="status_differs",
                       setup=[],
                       control={"method": "GET", "url": f"{BASE}/rest/basket/6"},
                       variant={"method": "GET", "url": f"{BASE}/nothing-here"}),
        hyp.Hypothesis(title="both sides fail", severity="high",
                       comparator="bodies_differ", setup=[],
                       control={"method": "POST", "url": f"{BASE}/api/BasketItems"},
                       variant={"method": "POST", "url": f"{BASE}/api/BasketItems"}),
        hyp.Hypothesis(title="unresolvable reference", severity="high",
                       comparator="bodies_differ", setup=[],
                       control={"method": "GET", "url": f"{BASE}/rest/basket/6"},
                       variant={"method": "GET",
                                "url": f"{BASE}/rest/basket/{{{{setup.0.id}}}}"}),
    ]


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_the_funnel_is_correct_when_every_note_has_been_evicted(tmp_path):
    """THE DEFECT. CM5's condition exactly: a run long enough that the notes window has
    thrown away every experiment line."""
    s, audit = _session(tmp_path)
    s._run_one_round(_three_proposals(), [])

    # Push the experiment notes out of the window, as a 70-step run does.
    for i in range(80):
        s.note(f"[recon] filler note {i}")
    s._write_notebook()
    page = (tmp_path / "vault" / "engagement.md")
    assert page.exists()
    assert "[experiment]" not in page.read_text(), (
        "the fixture did not reproduce eviction; the test would prove nothing")

    f = hyp.funnel(_entries(audit.path))
    assert f["proposed"] == 3, f
    assert f["dispatched"] == 2, f          # the unresolvable reference never dispatched
    assert f["resolved"] == 1, f            # the 500/500 pair was not resolvable
    assert f["judged"] == 1, f
    assert f["confirmed"] == 1, f


def test_the_notes_window_cannot_change_a_published_count(tmp_path):
    """The count must be identical with the notes intact and with them evicted."""
    s, audit = _session(tmp_path)
    s._run_one_round(_three_proposals(), [])
    before = hyp.funnel(_entries(audit.path))

    for i in range(200):
        s.note(f"[recon] filler {i}")
    s._write_notebook()
    after = hyp.funnel(_entries(audit.path))
    assert before == after, (before, after)


def test_a_proposal_refused_before_dispatch_is_still_counted(tmp_path):
    """`proposed` was not derivable at all: a zero-setup proposal refused at reference
    resolution left no audit record whatsoever."""
    s, audit = _session(tmp_path)
    only = [_three_proposals()[2]]
    s._run_one_round(only, [])

    f = hyp.funnel(_entries(audit.path))
    assert f["proposed"] == 1, f
    assert f["dispatched"] == 0, f
    assert f["judged"] == 0, f


def test_the_cross_account_line_comes_from_the_ledger_too(tmp_path):
    """The milestone metric, and the one that must never be read off a note."""
    s, audit = _session(tmp_path)
    s._record_principal_ids("second", "login", json.dumps({"authentication": {"bid": 9}}))
    s._record_principal_ids("self", "login", json.dumps({"authentication": {"bid": 6}}))
    h = hyp.Hypothesis(title="cross", severity="high",
                       comparator="cross_account_resource", setup=[],
                       control={"method": "GET", "url": f"{BASE}/rest/basket/6",
                                "as": "self"},
                       variant={"method": "GET", "url": f"{BASE}/rest/basket/9",
                                "as": "self"})
    s._run_one_round([h], [])

    f = hyp.funnel(_entries(audit.path))
    xa = f["cross_account"]
    assert xa["proposed"] == 1, f
    assert xa["dispatched"] == 1, f
    assert xa["judged"] == 1, f
    assert xa["confirmed"] == 1, f


# --------------------------------------------------------------------------- #
# BOUNDARY — the notes are untouched
# --------------------------------------------------------------------------- #

def test_the_notes_are_unchanged_and_still_rendered(tmp_path):
    """BOUNDARY. The fix adds a ledger-derived count; it does not remove the human
    timeline, which is the thing a reader opens first."""
    s, audit = _session(tmp_path)
    s._run_one_round(_three_proposals(), [])
    notes = [n for n in s.notes if "[experiment]" in n]
    assert notes, "the experiment notes stopped being written"
    s._write_notebook()
    page = (tmp_path / "vault" / "engagement.md").read_text()
    assert "## Timeline" in page
    assert "[experiment]" in page, "a short run must still show its experiment notes"


def test_the_report_prints_the_LEDGER_funnel_not_the_notes(tmp_path):
    """The wiring, not just the function. A correct `funnel()` nobody calls would leave
    the published count exactly as wrong as it was."""
    from brukal.findings import FindingStore
    from brukal.report import write_reports

    s, audit = _session(tmp_path)
    s._run_one_round(_three_proposals(), [])
    for i in range(200):                      # evict every experiment note
        s.note(f"[recon] filler {i}")
    s._write_notebook()
    assert "[experiment]" not in (tmp_path / "vault" / "engagement.md").read_text()

    led = hyp.funnel_from_log(audit.path)
    out = tmp_path / "out"
    write_reports(FindingStore(tmp_path / "f.jsonl"),
                  {"engagement": "t", "target": TARGET, "funnel": led}, out)
    md = (out / "report.md").read_text()

    assert "Model-proposed experiments — the funnel" in md, md[:400]
    assert f"| all | {led['proposed']} | {led['dispatched']} |" in md, md
    assert "not from the engagement notes" in md
