"""
test_route_prefix_resolution.py — a mined route is a hypothesis until the target answers it.

THE MEASURED PROBLEM (CR1 pre-flight 2, crAPI, 2026-09-17 — GAP #4)
    crAPI's front door proxies by SERVICE PREFIX: /identity/..., /workshop/...,
    /community/.... Its React bundle carries the client-side paths, so every route mined
    from it lost the prefix. Measured, from the run's own record:

        signup candidates tried:  /REGISTER        -> 404
                                  /auth/signup     -> 404
        the endpoint that works:  /identity/api/auth/signup
        experiment targets:       /v2/user/dashboard, /orders/all -> 404

    B3 and B8 both failed on this, and nothing else. Juice Shop hid it for six
    measurement runs: one service, and its bundle's /rest/... strings WERE the API paths.

THE WARNING WAS ALREADY THERE, AND IT WAS NOT A CONTROL
    `Surface.summary()` already labelled these "UNVERIFIED — the mount prefix may be
    missing". The model read that sentence and proposed against them anyway, and
    `_json_signup_candidates` consumed them as if they were real URLs. A caveat in prose
    that no code enforces is a comment, not a safeguard.

THE FIX, and why it is not a guess
    The prefix is DERIVED BY ALIGNMENT against a path that already answered. The login URL
    `/identity/api/auth/login` answered 200; the mined fragment `/auth/login` is a suffix
    of it; therefore this application mounts that fragment under `/identity/api`. No
    hardcoded prefix, no "try /api and see" — an alignment against evidence the run
    already holds.

    Then every composed path is CONFIRMED with one gated request before anything uses it.
    That is the rule this whole class of defect keeps asking for: never act on a derived
    fact that has not been confirmed against the target once.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal import webmap
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface as Surface, align_mount_prefixes

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"

# crAPI's real mined set, from runs/vault-preflight-cr1b.
CRAPI_FRAGMENTS = ["/REGISTER", "/login", "/orders", "/auth/login", "/auth/signup",
                   "/v2/user/dashboard", "/orders/all", "/v2/user/pictures"]
CRAPI_LOGIN = "/identity/api/auth/login"
# What actually exists on crAPI, measured.
CRAPI_REAL = {"/identity/api/auth/login", "/identity/api/auth/signup",
              "/identity/api/v2/user/dashboard", "/identity/api/v2/user/pictures",
              "/workshop/api/shop/orders"}


# --------------------------------------------------------------------------- #
# The alignment
# --------------------------------------------------------------------------- #

def test_the_prefix_is_ALIGNED_against_a_path_that_answered():
    got = align_mount_prefixes([CRAPI_LOGIN], CRAPI_FRAGMENTS)
    assert got and got[0] == "/identity/api", got


def test_the_LONGEST_fragment_wins_the_alignment():
    """`/login` also aligns, and yields `/identity/api/auth` — which would compose
    `/identity/api/auth/auth/signup`. The longest matching fragment is the most specific
    alignment and the only one that composes correctly."""
    got = align_mount_prefixes([CRAPI_LOGIN], ["/login", "/auth/login"])
    assert got[0] == "/identity/api"


def test_an_app_with_no_prefix_LEARNS_NOTHING():
    """BOUNDARY — Juice Shop. The observed path IS the fragment, so there is no prefix to
    learn and the mechanism must stay switched off rather than invent one."""
    assert align_mount_prefixes(["/rest/user/login"], ["/rest/user/login", "/api/Users"]) == []


def test_a_fragment_that_is_not_a_suffix_aligns_nothing():
    assert align_mount_prefixes(["/identity/api/auth/login"], ["/shop/orders"]) == []
    assert align_mount_prefixes([], CRAPI_FRAGMENTS) == []
    assert align_mount_prefixes([CRAPI_LOGIN], []) == []


# --------------------------------------------------------------------------- #
# The confirmation
# --------------------------------------------------------------------------- #

class _CrAPI:
    """Answers only under the real service prefixes; 404 everywhere else — crAPI."""

    def __init__(self, real=CRAPI_REAL):
        self.real = set(real)
        self.asked: list = []

    def run(self, action):
        from urllib.parse import urlsplit
        path = urlsplit(action.url).path
        self.asked.append(path)
        if path in self.real:
            return WebResult(status=200, url=action.url, body='{"ok":true}')
        return WebResult(status=404, url=action.url,
                         body="<html><head><title>404 Not Found</title></head></html>")


def _session(tmp_path, cage, fragments=CRAPI_FRAGMENTS, login=CRAPI_LOGIN, soft404=False):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    # These tests are about resolution mechanics, not about the rate budget, so they run
    # in the phase where the full sweep is allowed: after the principals are in hand.
    # The narrowed pre-establishment pass has its own file.
    s._principals_established = True
    surface = Surface(seed=f"{BASE}/")
    surface.add_routes(list(fragments))
    surface.soft_404 = soft404
    s.surface = surface
    s._login_url = f"{BASE}{login}" if login else ""
    return s, audit


def test_crAPIs_fragments_are_resolved_to_paths_that_answer(tmp_path):
    """THE DEFECT, with crAPI's real fragment set and its real endpoints."""
    s, _ = _session(tmp_path, _CrAPI())
    resolved = s.resolve_mined_routes()
    assert "/identity/api/auth/signup" in s.surface.api_routes, resolved
    assert "/identity/api/v2/user/dashboard" in s.surface.api_routes
    assert "/auth/signup" not in s.surface.api_routes, (
        "the dead fragment is still being offered to the model")


def test_an_unconfirmed_composition_is_NOT_adopted(tmp_path):
    """A composed path the target does not answer is a guess, and stays out of the map."""
    s, _ = _session(tmp_path, _CrAPI(real={CRAPI_LOGIN}))
    s.resolve_mined_routes()
    assert not [r for r in s.surface.api_routes if r.startswith("/identity/api/v2")]
    assert "/v2/user/dashboard" in s.surface.api_routes, (
        "an unconfirmed fragment must be left exactly as it was")


def test_every_confirmation_goes_through_the_GATE(tmp_path):
    """Invariant 4: these are real requests at a real target, so they are gated, rate
    limited and audited like everything else — not a side channel."""
    s, audit = _session(tmp_path, _CrAPI())
    s.resolve_mined_routes()
    rows = [json.loads(l) for l in open(audit.path)]
    probes = [r for r in rows if r["kind"] == "web_decision"
              and "/identity/api/auth/signup" in r["data"]["action"]]
    assert probes and probes[0]["data"]["verdict"] == "ALLOW"


def test_the_confirmation_budget_is_BOUNDED(tmp_path):
    """A hundred fragments must not become a hundred requests at somebody's application."""
    many = [f"/auth/thing{i}" for i in range(100)]
    s, _ = _session(tmp_path, _CrAPI(), fragments=["/auth/login"] + many)
    s.resolve_mined_routes()
    assert len(s.browser._cage.asked) <= 40, len(s.browser._cage.asked)


def test_a_SOFT_404_target_resolves_NOTHING(tmp_path):
    """Fail-closed. If the app answers 200 for paths that do not exist, a confirmation
    proves nothing and every composition would be 'confirmed'."""
    class _Catchall:
        def __init__(self): self.asked = []
        def run(self, action):
            self.asked.append(action.url)
            return WebResult(status=200, url=action.url, body="<html>spa</html>")
    s, _ = _session(tmp_path, _Catchall(), soft404=True)
    assert s.resolve_mined_routes() == []
    assert "/identity/api/auth/signup" not in s.surface.api_routes
    assert s.browser._cage.asked == [], "it spent requests on a target that cannot answer"


def test_JUICE_SHOP_is_untouched(tmp_path):
    """BOUNDARY: nothing is learned, nothing is composed, NO request is made. The six
    measurement runs' surface behaviour is unchanged."""
    class _JuiceShop:
        def __init__(self): self.asked = []
        def run(self, action):
            self.asked.append(action.url)
            return WebResult(status=200, url=action.url, body="{}")
    s, _ = _session(tmp_path, _JuiceShop(),
                    fragments=["/rest/user/login", "/api/Users", "/rest/basket"],
                    login="/rest/user/login")
    assert s.resolve_mined_routes() == []
    assert s.surface.api_routes == ["/rest/user/login", "/api/Users", "/rest/basket"]
    assert s.browser._cage.asked == []


# --------------------------------------------------------------------------- #
# What it buys: B3's signup, and an honest summary
# --------------------------------------------------------------------------- #

def test_the_signup_candidate_becomes_the_REAL_endpoint(tmp_path):
    """The whole of B3, end to end: resolution finds the endpoint, and the field-discovery
    fix from this morning then gets the chance it never had."""
    class _Signup(_CrAPI):
        def run(self, action):
            from urllib.parse import urlsplit
            path = urlsplit(action.url).path
            if path == "/identity/api/auth/signup" and (action.method or "GET") == "POST":
                body = json.loads(action.body or "{}")
                missing = {"name", "number"} - set(body)
                if missing:
                    det = "\n".join(f"Field error in object 'signUpForm' on field '{m}': "
                                    f"default message [must not be blank]" for m in sorted(missing))
                    return WebResult(status=400, url=action.url,
                                     body=json.dumps({"message": "Validation failed",
                                                      "details": det}))
                return WebResult(status=200, url=action.url, body=json.dumps(body))
            return super().run(action)
    s, _ = _session(tmp_path, _Signup())
    s.resolve_mined_routes()
    cands = s._json_signup_candidates()
    assert any(c.endswith("/identity/api/auth/signup") for c in cands), cands
    made = s._register_account_json()
    assert made is not None, "B3 still cannot create the second principal"


def test_a_confirmed_route_stops_being_called_UNVERIFIED(tmp_path):
    """The prose that failed to be a control now reports what was actually established."""
    s, _ = _session(tmp_path, _CrAPI())
    s.resolve_mined_routes()
    summary = s.surface.summary()
    assert "/identity/api/auth/signup" in summary
    assert "CONFIRMED" in summary or "VERIFIED" in summary, summary
