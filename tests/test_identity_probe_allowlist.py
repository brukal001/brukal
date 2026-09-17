"""
test_identity_probe_allowlist.py — the oracle crAPI was chosen for.

THE MEASURED PROBLEM (CR1 portability tally, item 6)
    `_IDENTITY_PROBE_PATHS` listed ten conventional "who am I" paths. crAPI's is
    `GET /identity/api/v2/user/dashboard`, which is not among them — and crAPI was chosen
    *because* that endpoint reads the AUTHORIZATION HEADER and returns a numeric id,
    which is exactly what Juice Shop could not do. `/rest/user/whoami` is cookie-only, so
    CM5 and CM6 had to disclose on every `variant_as: second` claim that the second
    principal's identity was never verified against the target.

    Measured on crAPI at 172.20.0.12, 2026-09-17:
        Authorization: Bearer <A's token>  -> {"id":9,"name":"brukalA",...}
        the same token as Cookie: token=…  -> 404
        anonymous                          -> 404

WHY AN ALLOWLIST AND NOT A PATTERN
    The list is deliberate: a regex loose enough to match "anything that looks like a
    profile endpoint" is how a probe starts GETting arbitrary routes on a live target.
    The cost of that choice is exactly this defect — a new target needs a new entry — and
    that cost is paid in the portability tally, where it can be counted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import _IDENTITY_PROBE_PATHS, AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}/"
CRAPI_PATH = "/identity/api/v2/user/dashboard"
CRAPI_ME = json.dumps({"id": 9, "name": "brukalA", "email": "a@brukal.test",
                       "number": "9226048190", "role": "ROLE_USER"})


def test_crAPIs_header_reading_oracle_is_in_the_allowlist():
    assert CRAPI_PATH in _IDENTITY_PROBE_PATHS


def test_the_conventional_paths_are_still_tried_FIRST():
    """BOUNDARY: crAPI's path is long and target-specific; it must not displace the
    conventional ones, which answer on most targets in one request."""
    assert _IDENTITY_PROBE_PATHS[0] == "/rest/user/whoami"
    assert _IDENTITY_PROBE_PATHS.index(CRAPI_PATH) > _IDENTITY_PROBE_PATHS.index("/me")


class _Oracle:
    """crAPI: only the dashboard path distinguishes a bearer from an anonymous caller,
    and only via the header."""

    def __init__(self):
        self.asked: list = []

    def run(self, action):
        url, hdrs = action.url, (action.headers or {})
        self.asked.append(url)
        if CRAPI_PATH in url:
            if "Bearer" in (hdrs.get("Authorization") or ""):
                return WebResult(status=200, url=url, body=CRAPI_ME)
            return WebResult(status=404, url=url, body='{"message":"Given Email is not registered! "}')
        return WebResult(status=404, url=url, body="not found")


class _Silent:
    """A target with no identity endpoint at all — the common case."""
    def __init__(self):
        self.asked: list = []

    def run(self, action):
        self.asked.append(action.url)
        return WebResult(status=404, url=action.url, body="nope")


def _session(tmp_path, cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn",
                         "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    s.authenticated = True
    s._login_url = BASE
    s.browser.auth_header = "Bearer eyJhbGciOiJSUzI1NiJ9.test.sig"
    return s, audit


def test_the_probe_reaches_crAPIs_oracle_and_records_the_principals_id(tmp_path):
    s, audit = _session(tmp_path, _Oracle())
    carriage = s.confirm_authentication()
    assert carriage == "header", carriage
    rows = [json.loads(l) for l in open(audit.path)
            if json.loads(l)["kind"] == "principal_ownership"]
    assert rows, "the oracle answered and no principal id was recorded"
    assert "9" in json.dumps(rows[0]["data"]), rows[0]["data"]


def test_the_allowlist_is_consulted_IN_ORDER(tmp_path):
    """The conventional paths are asked before the target-specific one."""
    cage = _Oracle()
    s, _ = _session(tmp_path, cage)
    s.confirm_authentication()
    paths = [u for u in cage.asked]
    first_conventional = next(i for i, u in enumerate(paths) if "whoami" in u)
    first_crapi = next(i for i, u in enumerate(paths) if CRAPI_PATH in u)
    assert first_conventional < first_crapi


def test_an_unknown_target_still_DEGRADES_QUIETLY(tmp_path):
    """BOUNDARY: most targets expose no identity endpoint. The carriage we HOLD is still
    reported — refusing those targets would trade this defect for a worse one — but it is
    reported as UNPROVEN, and no claim about identity is recorded."""
    s, audit = _session(tmp_path, _Silent())
    assert s.confirm_authentication() == "header"
    rows = [json.loads(l) for l in open(audit.path)]
    assert not [r for r in rows
                if r["kind"] in ("principal_ownership", "authentication_mismatch")], \
        "a target that said nothing produced a claim about identity"
    carriage = [r for r in rows if r["kind"] == "authentication_carriage"]
    assert carriage and carriage[-1]["data"]["confirmed"] is None, carriage


def test_a_404_to_an_ANONYMOUS_caller_IS_AN_ANSWER(tmp_path):
    """THE SECOND DEFECT, found by this file rather than by a run.

    `_probe_identity` returned None for a 404, reading it as "this path does not exist
    here". crAPI's oracle USES 404 as its answer to a caller it does not recognise
    (measured: anonymous -> 404, bearer -> 200 {"id":9,...}). So the path was skipped
    before the session was ever tried, and adding it to the allowlist alone would have
    left B7 exactly as unanswerable as it was on Juice Shop.

    A 404 that DISCRIMINATES is an oracle. A 404 that everyone gets is an absent path."""
    s, audit = _session(tmp_path, _Oracle())
    assert s.confirm_authentication() == "header"
    rows = [json.loads(l) for l in open(audit.path)
            if json.loads(l)["kind"] == "authentication_carriage"]
    assert rows and rows[-1]["data"]["confirmed"] is True, rows


def test_a_path_that_404s_for_EVERYONE_is_still_absent(tmp_path):
    """BOUNDARY, and the one that keeps the change honest: an absent path must not become
    an oracle, or every 404 route on the target would start a cookie-carriage hunt."""
    cage = _Silent()
    s, _ = _session(tmp_path, cage)
    s.confirm_authentication()
    # Two probes per path (anon twice) plus one with the session, and NOT one per
    # session-cookie name — a cookie hunt at an absent path is the regression.
    assert len(cage.asked) <= 3 * len(_IDENTITY_PROBE_PATHS), len(cage.asked)
