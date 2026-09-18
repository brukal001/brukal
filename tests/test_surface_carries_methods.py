"""
test_surface_carries_methods.py — the surface knows the method and was throwing it away.

THE MEASURED FAULT (all nine CR1 runs)
    Route confirmation probes each candidate with a GET and treats any non-404 as "this
    route exists" — which is right. But a 405 says something more: the route exists AND
    GET is not how you reach it. That second half was discarded, so the surface advertised

        /identity/api/v2/user/pictures
        /identity/api/v2/user/videos
        /identity/api/v2/user/videos/convert_video

    as plain paths, the model proposed GET experiments against them, and every one came
    back 405. In run cr1c that was SIX OF EIGHT experiment requests; across runs it is
    20-75% of a budget that only ever holds seven to fifteen proposals.

    The experiment budget is the scarce resource that determines recall, and it was being
    spent on requests that could not work — with the information needed to avoid it
    already in hand and thrown away.
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
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
FRAGMENTS = ["/auth/login", "/v2/user/pictures", "/v2/user/dashboard"]
# crAPI as measured: the dashboard answers GET, the pictures endpoint is upload-only.
GETTABLE = {"/identity/api/v2/user/dashboard"}
EXISTS_NOT_GET = {"/identity/api/auth/login", "/identity/api/v2/user/pictures"}


class _App:
    def run(self, action):
        from urllib.parse import urlsplit
        path = urlsplit(action.url).path
        if path in GETTABLE:
            return WebResult(status=200, url=action.url, body='{"id":9}')
        if path in EXISTS_NOT_GET:
            return WebResult(status=405, url=action.url,
                             body='{"detail":"Method \\"GET\\" not allowed."}')
        return WebResult(status=404, url=action.url, body="{}")


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, _App(), audit))
    s.allow_intrusive = True
    s._principals_established = True
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(FRAGMENTS))
    s.surface = surface
    s._login_url = f"{BASE}/identity/api/auth/login"
    return s


def test_a_405_is_recorded_as_exists_but_NOT_gettable(tmp_path):
    """THE DISCARDED HALF. The probe already learned it; it just was not kept."""
    s = _session(tmp_path)
    s.resolve_mined_routes()
    assert "/identity/api/v2/user/pictures" in s.surface.confirmed_routes
    assert s.surface.route_methods.get("/identity/api/v2/user/pictures") == "not-GET"


def test_a_200_is_recorded_as_gettable(tmp_path):
    s = _session(tmp_path)
    s.resolve_mined_routes()
    assert s.surface.route_methods.get("/identity/api/v2/user/dashboard") == "GET"


def test_the_MODEL_is_told_which_is_which(tmp_path):
    """The surface summary is the model's whole picture of the application. A path it
    cannot GET must not be presented identically to one it can."""
    s = _session(tmp_path)
    s.resolve_mined_routes()
    summary = s.surface.summary()
    assert "not-GET" in summary or "405" in summary, summary
    line = [l for l in summary.splitlines() if "pictures" in l]
    assert line and ("not-GET" in line[0] or "405" in line[0]), summary


def test_a_route_with_no_method_evidence_says_nothing_about_methods(tmp_path):
    """BOUNDARY: silence where nothing was learned. Guessing 'GET' for an unprobed route
    would be the same defect in the other direction."""
    s = _session(tmp_path)
    s.surface.confirmed_routes.append("/never/probed")
    assert "/never/probed" not in (s.surface.route_methods or {})
