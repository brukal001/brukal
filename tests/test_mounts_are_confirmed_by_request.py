"""
test_mounts_are_confirmed_by_request.py — a candidate mount is proved, never assumed.

`extract_mount_candidates` reads service names out of the application's own bundle. That
is a LEAD, not a fact, and this project's law is that nothing derived is acted on until
one gated request has confirmed it against the target.

THE EVIDENCE, measured on the live crAPI container 2026-09-19 ($0.00, no model):

    |404|159|  /zzz-nonexistent            <- the FRONT DOOR's own 404
    |404|179|  /workshop/zzz-nonexistent   <- the workshop SERVICE answered
    |404|179|  /workshop/api/shop/zzz      <- same service, same fingerprint
    |404| 19|  /community/zzz-nonexistent  <- the community service answered
    |401| 49|  /identity/zzz-nonexistent   <- identity's auth filter answered

A gateway that routes `/workshop/...` to a backend produces an answer that DIFFERS from
its own 404 for an unrouted path. That difference is the proof, and it needs one request
per candidate plus one baseline.

It also fails closed in the case that matters: on a host where every unknown path returns
the same thing (a soft-404 SPA, or a gateway with a catch-all), nothing differs from the
baseline and NO mount is confirmed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"


def _session(tmp_path, answer):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    calls = []

    class _Cage:
        def run(self, a):
            calls.append(a.url)
            st, body = answer(a.url)
            return WebResult(status=st, url=a.url, body=body)

    s = AssistSession(TARGET, ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, _Cage(), audit))
    s.allow_intrusive = True
    from brukal.webmap import AttackSurface
    s.surface = AttackSurface(seed=f"http://{TARGET}/")
    return s, calls


def _crapi_like(url):
    """The live fingerprints above."""
    path = url.split(TARGET, 1)[-1]
    if path.startswith("/workshop"):
        return 404, "w" * 179
    if path.startswith("/community"):
        return 404, "c" * 19
    if path.startswith("/identity"):
        return 401, "i" * 49
    return 404, "f" * 159                      # the front door


def test_a_routed_mount_is_confirmed_and_an_unrouted_one_is_not(tmp_path):
    s, _calls = _session(tmp_path, _crapi_like)
    got = s.discover_mounts(["workshop", "community", "identity", "nosuchservice"])
    assert set(got) == {"workshop", "community", "identity"}, got
    assert "nosuchservice" not in got, (
        "a segment the gateway does not route answered exactly like the front door")


def test_a_catch_all_host_confirms_NOTHING(tmp_path):
    """FAIL-CLOSED, and the case that matters: if every unknown path answers identically
    there is no evidence of routing, and inventing mounts from a bundle would put a whole
    fabricated surface in front of the model."""
    s, _calls = _session(tmp_path, lambda url: (200, "same for everything"))
    assert s.discover_mounts(["workshop", "community", "anything"]) == []


def test_it_costs_one_request_per_candidate_plus_one_baseline(tmp_path):
    s, calls = _session(tmp_path, _crapi_like)
    s.discover_mounts(["workshop", "community", "identity"])
    assert len(calls) == 4, calls


def test_it_is_bounded(tmp_path):
    """A bundle can name many segments; discovery must not become a sweep."""
    s, calls = _session(tmp_path, _crapi_like)
    s.discover_mounts([f"svc{i}" for i in range(100)], cap=8)
    assert len(calls) <= 9, len(calls)
