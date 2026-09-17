"""
test_second_principal_confirmed.py — the question crAPI was CHOSEN to answer.

THE STANDING GAP (CM5, CM6, and CR1 pre-flights 2-4)
    Every `variant_as: second` claim this project has published carried a disclosure: the
    SECOND principal's identity was never verified against the target. On Juice Shop that
    was unavoidable — `/rest/user/whoami` is cookie-only, and the second principal holds a
    bearer. crAPI was chosen because `/identity/api/v2/user/dashboard` READS THE HEADER and
    returns a numeric id, so both principals can be verified there.

    Pre-flight 4 established the second principal (two distinct sessions, three dispatches
    `as: second`) and STILL did not confirm it. The cause, located in that run:

        `confirm_authentication` is called from the experiment dispatch path
        (`_as_identity`) for the principal CURRENTLY in effect, and nothing calls it while
        the second principal is being established.

    Everything it needs was already there and already correct: it keys its record as
    `second` when `_establishing_second` is set, `_separate_identity` saves and restores
    the carriage memo so a confirmation inside it cannot memoise against ours, and the
    oracle is proven every run by the first principal.

CR1's DEFINITION OF DONE requires both principals verified against that oracle. This file
is that requirement, as a test.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_portability_profiles import (GatewayPrefixShape, JuiceShopShape,  # noqa: E402
                                       _json)

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"


def _make(tmp_path, cage_cls, routes, login_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    cage = cage_cls()
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    surface = AttackSurface(seed=f"{BASE}/")
    surface.add_routes(list(routes))
    s.surface = surface
    s._login_url = f"{BASE}{login_path}"
    ok = s.login(s._login_url, "first@brukal.test", "First-1!",
                 user_field="email", login_type="json")
    s.authenticated = bool(ok)
    s.identity = "first@brukal.test"
    return s, cage, audit


def _rows(audit, kind):
    return [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == kind]


def _gateway(tmp_path):
    return _make(tmp_path, GatewayPrefixShape,
                 ["/auth/login", "/auth/signup", "/v2/user/dashboard"],
                 GatewayPrefixShape.LOGIN)


# --------------------------------------------------------------------------- #
# The requirement
# --------------------------------------------------------------------------- #

def test_the_SECOND_principal_is_confirmed_against_the_targets_own_oracle(tmp_path):
    """THE GAP. After establishment, the ledger must carry a carriage record for the
    second principal, confirmed by asking the target — not inferred from the fact that a
    login returned 200."""
    s, _cage, audit = _gateway(tmp_path)
    s.resolve_mined_routes()
    second = s.establish_second_identity()
    assert second, "the second principal was not established at all"
    rows = _rows(audit, "authentication_carriage")
    by_principal = {r["principal"]: r for r in rows}
    assert second in by_principal, (
        f"no carriage record for the second principal; got {list(by_principal)}")
    assert by_principal[second]["confirmed"] is True, by_principal[second]
    assert "dashboard" in by_principal[second]["probe"], by_principal[second]


def test_the_second_principals_OWN_ID_reaches_the_ledger(tmp_path):
    """What the confirmation is FOR: a cross-account claim needs the second principal's
    identifiers, attributed to it and to nothing else."""
    s, _cage, audit = _gateway(tmp_path)
    s.resolve_mined_routes()
    s.establish_second_identity()
    owners = _rows(audit, "principal_ownership")
    seconds = [o for o in owners if o["principal"] == "second"]
    assert seconds, f"only {[o['principal'] for o in owners]} reached the ledger"
    assert any(o["name"] == "id" for o in seconds), seconds


def test_the_two_principals_are_recorded_as_DIFFERENT_identities(tmp_path):
    """The whole point of confirming both: if the oracle answers with the same id for
    both sessions, every cross-account verdict built on them is worthless."""
    s, _cage, audit = _gateway(tmp_path)
    s.resolve_mined_routes()
    s.confirm_authentication()                 # first principal
    s.establish_second_identity()              # second principal, confirmed inside
    owners = _rows(audit, "principal_ownership")
    ids = {o["principal"]: o["value"] for o in owners if o["name"] == "id"}
    assert "self" in ids and "second" in ids, ids
    assert ids["self"] != ids["second"], f"both principals answered as the same id: {ids}"


def test_our_own_session_is_intact_afterwards(tmp_path):
    """BOUNDARY, and the one CM4 was burned by: a confirmation performed as the second
    principal must not leave its token in our jar, nor memoise against our key, nor
    record its id under `self`."""
    s, _cage, audit = _gateway(tmp_path)
    s.resolve_mined_routes()
    s.confirm_authentication()
    mine_before = (s.browser.auth_header, dict(s.browser._cookies), s.identity)
    s.establish_second_identity()
    assert (s.browser.auth_header, dict(s.browser._cookies), s.identity) == mine_before
    selves = [o for o in _rows(audit, "principal_ownership") if o["principal"] == "self"]
    assert all(o["value"] == selves[0]["value"] for o in selves if o["name"] == "id"), selves


def test_a_target_with_NO_oracle_confirms_nothing_and_says_so(tmp_path):
    """BOUNDARY: the second principal is still established on a target that offers no way
    to verify it — the claim is simply not made. Refusing those targets would trade this
    gap for a worse one."""
    class _NoOracle(JuiceShopShape):
        def run(self, action):
            from urllib.parse import urlsplit
            if urlsplit(action.url).path == self.WHOAMI:
                return _json(404, {"error": "no such thing"}, action.url)
            return super().run(action)
    s, _cage, audit = _make(tmp_path, _NoOracle,
                            ["/rest/user/login", "/api/Users"], JuiceShopShape.LOGIN)
    second = s.establish_second_identity()
    assert second, "a target with no oracle must still yield a second principal"
    rows = _rows(audit, "authentication_carriage")
    assert all(r.get("confirmed") is not True for r in rows if r["principal"] == second), rows


def test_the_confirmation_costs_ONE_probe_not_one_per_experiment(tmp_path):
    """It is memoised per principal, so a round of experiments pays for one probe."""
    s, _cage, audit = _gateway(tmp_path)
    s.resolve_mined_routes()
    s.establish_second_identity()
    before = len(_rows(audit, "authentication_carriage"))
    for _ in range(3):
        s.establish_second_identity()
    assert len(_rows(audit, "authentication_carriage")) == before
