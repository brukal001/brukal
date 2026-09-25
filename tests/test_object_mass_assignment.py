"""
test_object_mass_assignment.py — mass assignment on an EXISTING object (crAPI #8/#10).

The registration prover only covers signup; crAPI's free-item (#8), balance (#9) and
internal-video-property (#10) challenges write an internal field to an object that already
exists. The proof is a write-then-read-back: the object reports the field we set where it
did not before.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

FIX = Path(__file__).resolve().parent / "fixtures"
SCOPE = FIX / "scope_destructive.json"       # writing to an object is destructive → authorised
SCOPE_READONLY = FIX / "scope_fast.json"     # PUT gated out; only POST authorised
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
VIDEO = "/identity/api/v2/user/videos/7"


class _VideoObject:
    """crAPI's video in miniature: GET returns it; a PUT that blindly applies the body lets
    the client set the internal `conversion_params` (challenge 10)."""
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.obj = {"id": 7, "video_name": "clip", "views": 3}

    def run(self, action):
        method = (getattr(action, "method", "") or "GET").upper()
        if method == "GET":
            return WebResult(status=200, url=action.url, body=json.dumps(self.obj))
        if method in ("PUT", "POST"):
            try:
                body = json.loads(action.body or "{}")
            except Exception:
                body = {}
            if self.vulnerable:
                self.obj.update(body)          # binds every field the client sends
            return WebResult(status=200, url=action.url, body=json.dumps(self.obj))
        return WebResult(status=405, url=action.url, body="")


def _session(cage, scope_path=SCOPE):
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    scope = load_scope(scope_path)
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    llm = type("L", (), {"last_stop_reason": "end", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(llm), browser=GovernedBrowser(scope, cage, audit))
    s.blackboard = Blackboard(root / "vault", scope)
    s.allow_intrusive = True
    s.surface = AttackSurface(seed=f"{BASE}/")
    s._confirm_budget = 200
    return s


def test_writing_an_internal_property_and_reading_it_back_confirms():
    s = _session(_VideoObject(vulnerable=True))
    assert s.confirm_object_mass_assignment(f"{BASE}{VIDEO}", method="PUT") is True
    f = next(f for f in s.findings.all()
             if f.title == "Mass assignment of an internal object property")
    assert f.confirmed and f.severity == "high"
    assert "conversion_params" in f.param or "conversion_params" in f.evidence


def test_an_object_that_ignores_the_field_is_left_alone():
    s = _session(_VideoObject(vulnerable=False))       # PUT does not apply the body
    assert s.confirm_object_mass_assignment(f"{BASE}{VIDEO}", method="PUT") is False
    assert not any(f.title == "Mass assignment of an internal object property"
                   for f in s.findings.all())


def test_the_object_sweep_targets_object_shaped_routes():
    s = _session(_VideoObject(vulnerable=True))
    s.surface.confirmed_routes = [VIDEO]               # a "video" object route
    assert s.confirm_object_mass_assignment_sinks() == 1
    assert any(f.title == "Mass assignment of an internal object property" and f.confirmed
               for f in s.findings.all())


def test_the_object_sweep_needs_allow_intrusive():
    s = _session(_VideoObject(vulnerable=True))
    s.allow_intrusive = False
    s.surface.confirmed_routes = [VIDEO]
    assert s.confirm_object_mass_assignment_sinks() == 0


def test_the_sweep_falls_back_to_post_when_put_is_not_authorised():
    """Under a scope that did NOT authorise destructive methods the gate refuses PUT, so the
    sweep must still reach the object via the authorised POST — the object bug is found
    without ever needing the operator to unlock DELETE/PUT-shaped destruction."""
    s = _session(_VideoObject(vulnerable=True), scope_path=SCOPE_READONLY)
    s.surface.confirmed_routes = [VIDEO]
    assert s.confirm_object_mass_assignment_sinks() == 1


def test_a_direct_put_is_refused_by_the_gate_without_destructive_authorisation():
    """The safety gate, not the prover, is the thing that stops an unauthorised state change:
    a bare PUT under the read-only scope returns False because the write never leaves."""
    s = _session(_VideoObject(vulnerable=True), scope_path=SCOPE_READONLY)
    assert s.confirm_object_mass_assignment(f"{BASE}{VIDEO}", method="PUT") is False
