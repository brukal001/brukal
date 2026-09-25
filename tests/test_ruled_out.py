"""
test_ruled_out.py — corroborate-or-shelve (roadmap §2.1).

When a deterministic differential RUNS on an endpoint and returns False, that class is a
genuine NEGATIVE there. Recording it (and surfacing it through the opt-in working set)
stops the model re-proposing a refuted lead — the sqlmap-on-login budget burn, generalised
past sqlmap to every confirm_* check.

The load-bearing discipline (the vault's oldest law): a negative is recorded ONLY when the
check ran and returned False, never when it raised — a positive control before a negative.
Placement inside the probe loop's try, after the truthy return, guarantees that.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = "tests/fixtures/scope_fast.json"
TARGET = "127.0.0.1"
B = "http://127.0.0.1:5000"


def _session(cage=None):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    kw = {"browser": GovernedBrowser(scope, cage, audit)} if cage is not None else {}
    sess = AssistSession(TARGET, ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()), **kw)
    sess.allow_intrusive = True
    return sess


def test_record_ruled_out_maps_dedups_and_ignores_unknown():
    s = _session()
    s._record_ruled_out("confirm_sqli", "http://h/s", "q")
    assert ("SQL injection", "http://h/s", "q", "GET") in s.ruled_out
    n = len(s.ruled_out)
    s._record_ruled_out("confirm_sqli", "http://h/s", "q")     # dup -> ignored
    assert len(s.ruled_out) == n
    s._record_ruled_out("confirm_xss", "http://h/s", "q", method="POST")
    assert ("Cross-site scripting", "http://h/s", "q", "POST") in s.ruled_out
    before = len(s.ruled_out)
    s._record_ruled_out("not_a_real_check", "http://h/s", "q")  # unknown -> no record
    assert len(s.ruled_out) == before


def test_ruled_out_surfaces_only_when_opted_in():
    s = _session()
    s.ruled_out = [("SQL injection", "http://h/login", "email", "POST")]
    assert "RULED OUT" not in s.plan_context()          # default OFF -> baseline safe
    s.context_working_set = True
    ws = s.working_set_text()
    assert "RULED OUT" in ws and "SQL injection @ http://h/login" in ws
    assert "RULED OUT" in s.plan_context()


class _Benign:
    """A cage that answers every governed web request with an empty JSON body — so every
    injection differential runs to completion and returns False (a clean negative)."""
    def run(self, action):
        return WebResult(status=200, url=action.url, body="{}")


def test_confirm_surface_shelves_a_refuted_class():
    s = _session(_Benign())
    surface = AttackSurface(seed=B + "/")
    # one GET endpoint with a query parameter, so the per-parameter probe loop runs the
    # tier-1/tier-2 differentials against it.
    surface.add_page(B + "/search?q=1", links={B + "/search?q=1"}, forms=[],
                     params={B + "/search": {"q"}})
    s.surface = surface
    s.confirm_surface()
    assert s.ruled_out, "a refuted differential recorded no negative — the hook is dead"
    classes = {t[0] for t in s.ruled_out}
    # the tier-1 battery (SQLi, command injection) ran on the param and found nothing
    assert "SQL injection" in classes, s.ruled_out
    assert all(t[1] and t[2] for t in s.ruled_out)        # every negative names where


def test_a_check_that_raises_is_not_recorded_as_a_negative():
    """The positive-control law: a class is 'ruled out' only when its differential RAN and
    disproved it. A check that raised proved nothing, so it must not be shelved — otherwise
    a thrown probe would silently suppress a class that was never actually tested."""
    s = _session(_Benign())
    def _boom(*a, **k):
        raise RuntimeError("probe blew up")
    s.confirm_cmdi = _boom                                 # the sole 'Command injection' check
    surface = AttackSurface(seed=B + "/")
    surface.add_page(B + "/search?q=1", links={B + "/search?q=1"}, forms=[],
                     params={B + "/search": {"q"}})
    s.surface = surface
    s.confirm_surface()
    classes = {t[0] for t in s.ruled_out}
    assert "Command injection" not in classes             # it raised -> not a negative
    assert "SQL injection" in classes                      # its siblings ran and refuted
