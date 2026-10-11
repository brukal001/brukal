"""The model-facing note and the vault summary show the changed region / start+end.

2026-10-01: after rendering the decisive request the model was shown body[:600] — the
page header — and handed the step back as MANUAL. Baselines are the last few FULL 2xx
bodies per endpoint, held in memory only (bounded)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebAction, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
BASE = "http://10.10.10.5/filter"
HEADER = "\n".join(f"<div class='nav-{i}'>navigation item {i}</div>" for i in range(90))
NORMAL = HEADER + "\n<table>\n<tr><td>Product A</td></tr>\n</table>"
RESULT = HEADER + "\n<table>\n<tr><td>RESULT-ROW-1</td><td>value-7f3a</td></tr>\n</table>"


class _Cage:
    def __init__(self, pages):
        self.pages = pages

    def run(self, action):
        status, body = self.pages.get(action.url, (404, "nope"))
        return WebResult(status=status, url=action.url, headers={}, body=body)


class _LLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


def _session(pages):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_LLM()),
                         browser=GovernedBrowser(scope, _Cage(pages), audit))


def test_note_shows_the_result_region_after_a_normal_request():
    q_normal, q_probe = f"{BASE}?category=Gifts", f"{BASE}?category=Gifts%27+UNION"
    s = _session({q_normal: (200, NORMAL), q_probe: (200, RESULT)})
    s.run_web(f"get {q_normal}")
    s.run_web(f"get {q_probe}")
    note = s.notes[-1]
    assert "RESULT-ROW-1" in note
    assert "navigation item 0" not in note.split("\n", 2)[-1]


def test_without_a_baseline_the_end_of_the_page_is_visible():
    q = f"{BASE}?category=x"
    s = _session({q: (200, RESULT)})
    s.run_web(f"get {q}")
    assert "RESULT-ROW-1" in s.notes[-1]


def test_same_request_is_not_its_own_baseline():
    q_normal, q_probe = f"{BASE}?category=Gifts", f"{BASE}?category=Gifts%27+UNION"
    s = _session({q_normal: (200, NORMAL), q_probe: (200, RESULT)})
    s.run_web(f"get {q_normal}")
    s.run_web(f"get {q_probe}")
    s.run_web(f"get {q_probe}")                     # repeated: baseline is still NORMAL
    assert "RESULT-ROW-1" in s.notes[-1] and "changed region" in s.notes[-1]


def test_error_responses_are_not_baselines():
    s = _session({})
    a1 = WebAction(kind="get", url=f"{BASE}?category=bad")
    a2 = WebAction(kind="get", url=f"{BASE}?category=Gifts")
    assert s._web_baseline(a1, 500, "<h1>Internal Server Error</h1>") is None
    assert s._web_baseline(a2, 200, NORMAL) is None   # the 500 was not remembered


def test_short_bodies_are_unchanged_in_the_note():
    q = f"{BASE}?category=short"
    s = _session({q: (200, "<p>tiny</p>")})
    s.run_web(f"get {q}")
    assert s.notes[-1].endswith("<p>tiny</p>")


def test_baseline_memory_is_bounded():
    s = _session({})
    for i in range(100):
        for j in range(5):
            a = WebAction(kind="get", url=f"http://10.10.10.5/p{i}?v={j}")
            s._web_baseline(a, 200, "x" * 300_000)
    store = s._endpoint_bodies
    assert len(store) <= 64
    assert all(len(v) <= 3 for v in store.values())
    assert all(len(b) <= 200_000 for v in store.values() for _k, b in v)
