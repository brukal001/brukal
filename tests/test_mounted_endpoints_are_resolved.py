"""
test_mounted_endpoints_are_resolved.py — GAP #21: the endpoint suffixes were unrooted.

THE MEASURED PROBLEM (2026-09-19, found at $0.00 immediately after GAP #20)
    GAP #20 recovered the service MOUNTS from crAPI's bundle (`"workshop/"`, `"identity/"`)
    and confirmed them by request. A mount is an anchor, not an endpoint.

    The endpoints were in the same bundle the whole time, as UNROOTED strings:

        "api/shop/orders"                "api/shop/orders/return_order"
        "api/v2/user/dashboard"          "api/v2/user/videos"
        "api/v2/coupon/validate-coupon"  "api/auth/login"

    `_API_ROUTE_RE` requires a LEADING SLASH, so it could not see one of them. The SPA
    concatenates mount + suffix at runtime — `"workshop/" + "api/shop/orders"` — which is
    exactly the join the miner was blind to at BOTH ends.

    Every CR1 miss on an order, coupon or video was a miss on a path spelled out in full
    in a file the harness had already downloaded.

THE PROPERTY
    Compose only CONFIRMED mounts with MINED suffixes, confirm every composition by
    request, and never invent an infix.
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
from brukal.webmap import AttackSurface, extract_api_suffixes

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"

BUNDLE = ('og="identity/",ig="workshop/",lg="community/",'
          'a="api/shop/orders",b="api/v2/user/dashboard",'
          'c="api/v2/coupon/validate-coupon",d="/orders",e="https://x/"')


def test_unrooted_api_suffixes_are_mined():
    got = extract_api_suffixes(BUNDLE)
    assert "api/shop/orders" in got
    assert "api/v2/user/dashboard" in got
    assert "api/v2/coupon/validate-coupon" in got


def test_a_rooted_path_is_left_to_the_existing_miner():
    """`/orders` is already handled (and is a router path). This extractor is for the
    unrooted halves that `_API_ROUTE_RE` cannot see."""
    assert not any(s.startswith("/") for s in extract_api_suffixes(BUNDLE))


def test_noise_is_not_mined():
    got = extract_api_suffixes('a="https://",b="text/html",c="application/json",d="api/x"')
    assert "text/html" not in got and "application/json" not in got


def _session(tmp_path, exists):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    calls = []

    class _Cage:
        def run(self, a):
            calls.append(a.url)
            path = a.url.split(TARGET, 1)[-1]
            if path in exists:
                return WebResult(status=200, url=a.url, body='{"ok":1}')
            return WebResult(status=404, url=a.url, body="x" * 179)

    s = AssistSession(TARGET, ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, _Cage(), audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed=f"http://{TARGET}/")
    return s, calls


def test_the_real_endpoint_is_composed_and_CONFIRMED(tmp_path):
    """crAPI's exact shape: the orders API is under /workshop, the dashboard under
    /identity, and nothing says which suffix belongs to which mount."""
    real = {"/workshop/api/shop/orders", "/identity/api/v2/user/dashboard"}
    s, _calls = _session(tmp_path, real)
    s.surface.confirmed_mounts = ["identity", "workshop", "community"]
    got = s.resolve_mounted_endpoints(["api/shop/orders", "api/v2/user/dashboard"])
    assert set(got) == real, got
    assert set(s.surface.confirmed_routes) >= real


def test_an_unconfirmable_suffix_adds_NOTHING(tmp_path):
    """FAIL-CLOSED. A suffix that answers 404 under every mount is not an endpoint, and
    must not be written down as one — that is how a fabricated surface reaches the model."""
    s, _calls = _session(tmp_path, set())
    s.surface.confirmed_mounts = ["identity", "workshop"]
    assert s.resolve_mounted_endpoints(["api/nope"]) == []
    assert s.surface.confirmed_routes == []


def test_it_stops_at_the_first_mount_that_answers(tmp_path):
    """Cost control: a suffix belongs to ONE service, so the search must not continue
    after it is found.

    The contract is one BASELINE per mount (what does this mount say about a path that
    cannot exist -- see the blanket-401 test below) plus the search itself. Here: 3
    baselines + 1 hit on the first mount tried."""
    s, calls = _session(tmp_path, {"/identity/api/v2/user/dashboard"})
    s.surface.confirmed_mounts = ["identity", "workshop", "community"]
    s.resolve_mounted_endpoints(["api/v2/user/dashboard"])
    assert len(calls) == 4, calls
    assert sum(1 for c in calls if "brukal-absent-" in c) == 3, calls
    assert sum(1 for c in calls if "dashboard" in c) == 1, (
        "the search continued after the endpoint was found", calls)


def test_it_is_bounded(tmp_path):
    """Worst case, and it must stay computable: one baseline per mount, then at most
    `cap` suffixes x mounts. 3 + 10*3 = 33."""
    s, calls = _session(tmp_path, set())
    s.surface.confirmed_mounts = ["a", "b", "c"]
    s.resolve_mounted_endpoints([f"api/x{i}" for i in range(50)], cap=10)
    assert len(calls) <= 33, len(calls)


def test_a_mount_whose_AUTH_FILTER_answers_everything_confirms_nothing_falsely(tmp_path):
    """THE DEFECT THE FIRST FIXTURE COULD NOT EXPRESS, caught on the live target.

    crAPI's identity service answers 401 for EVERY path under /identity, existing or not
    (`/identity/zzz-nonexistent` -> 401/49B, measured). A rule of "any answer that is not
    404 proves the route" therefore confirmed all 32 suffixes under /identity — including
    `/identity/api/shop/orders` and `/identity/api/v2/coupon/validate-coupon`, which live
    under /workshop and /community. A fabricated surface, handed to the model as fact.

    The first fixture returned 404 for unknown paths, so a blanket-401 mount could not
    occur in it. **A fixture that cannot express the defect is not a test of it** — the
    lesson GAP #12 already recorded, met again here.

    The fix is the same evidence discover_mounts uses: compare against what THAT MOUNT
    says about a path that cannot exist."""
    class _Cage:
        def __init__(self):
            self.calls = []

        def run(self, a):
            self.calls.append(a.url)
            path = a.url.split(TARGET, 1)[-1]
            if path.startswith("/identity"):
                return WebResult(status=401, url=a.url, body="x" * 49)   # blanket auth
            if path == "/workshop/api/shop/orders":
                return WebResult(status=200, url=a.url, body='{"orders":[]}')
            return WebResult(status=404, url=a.url, body="w" * 179)

    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope),
                  type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(type("M", (), {
        "propose": lambda *a, **k: "[]", "last_stop_reason": "end_turn"})()),
        browser=GovernedBrowser(scope, _Cage(), audit))
    s.surface = AttackSurface(seed=f"http://{TARGET}/")
    s.surface.confirmed_mounts = ["identity", "workshop"]

    got = s.resolve_mounted_endpoints(["api/shop/orders"])
    assert got == ["/workshop/api/shop/orders"], got
    assert "/identity/api/shop/orders" not in got, (
        "a blanket 401 was read as proof that a path exists")
