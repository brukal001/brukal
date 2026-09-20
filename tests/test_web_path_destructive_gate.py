"""
test_web_path_destructive_gate.py — GAP #15: the approver guarded one of two doors.

THE MEASURED PROBLEM (CR1 run 18, 2026-09-19)
    GAP #14 added `_is_destructive_request(method, url)` so a DELETE carrying no
    destructive word could not bypass the approver. It has exactly ONE caller — the
    EXPERIMENT path. `check_web`, the door every web action passes through, decides on
    kind -> url -> scheme -> host-in-scope -> capability -> ALLOW, and never reads
    `scope.destructive_allowed` at all.

    Run 18's ledger, the `strategist` agent:

        ALLOW  web:allow  request: PUT    /workshop/api/shop/orders/1
        ALLOW  web:allow  request: DELETE /workshop/api/shop/orders/1

    Total ESCALATE entries in that run: 0. And the inversion that makes it concrete: a
    READ on the shell path escalated for human sign-off while a DELETE on the web path
    did not, because the shell path risk-scores and the web path never has.

    Proven by EXECUTING both branches against the real scope file rather than reading the
    code: `DELETE /workshop/api/shop/orders/1` returned ALLOW / web:allow under
    `destructive_allowed` FALSE and TRUE alike. That is a fail-OPEN against SAFETY
    INVARIANT 2, not merely an asymmetry — an engagement that never authorised
    destructive actions would have had that DELETE executed having consulted no one.

THE DELIBERATE LIMIT
    This judges the METHOD only, not the URL-word rule (`reset`, `drop`, `wipe`) the shell
    path uses. That rule exists because a shell command hides its method — `curl
    .../createdb` is a GET by shape and a catastrophe by effect. On the web plane the
    method is EXPLICIT and is the better signal, and applying the word rule here would
    deny ordinary reconnaissance: endpoint discovery legitimately GETs
    `/identity/api/v2/user/reset-password`. The boundary is pinned below.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import load_scope
from brukal.web import WebAction, check_web

BASE = Path(__file__).resolve().parent.parent / "scope.crapi.json"
URL = "http://172.20.0.12/workshop/api/shop/orders/1"


def _scope(destructive: bool):
    d = json.load(open(BASE))
    d["destructive_allowed"] = destructive
    p = tempfile.mktemp(suffix=".json")
    json.dump(d, open(p, "w"))
    return load_scope(p)


def _verdict(method, url=URL, destructive=False):
    return check_web(WebAction(kind="request", url=url, method=method),
                     _scope(destructive), "", "strategist")


def test_a_DELETE_is_refused_when_the_engagement_never_authorised_one():
    """THE FAIL-OPEN. This exact request returned ALLOW in run 18."""
    d = _verdict("DELETE")
    assert d.verdict == "DENY", d.verdict
    assert "destructive" in (d.layer or "") + (d.reason or "").lower()


def test_PUT_and_PATCH_are_refused_too():
    for m in ("PUT", "PATCH"):
        assert _verdict(m).verdict == "DENY", m


def test_they_are_ALLOWED_once_the_operator_authorises_them():
    """The scope is the authorisation. An engagement that opted in keeps working — this
    closes a hole, it does not remove a capability."""
    for m in ("DELETE", "PUT", "PATCH"):
        assert _verdict(m, destructive=True).verdict == "ALLOW", m


def test_reads_are_untouched():
    assert _verdict("GET").verdict == "ALLOW"
    assert _verdict("HEAD").verdict == "ALLOW"


def test_POST_is_deliberately_NOT_refused():
    """Same call as `_is_destructive_request`: POST CREATES, which is how setup steps
    reach an interesting state, and escalating every POST would make the rule
    meaningless. Recorded as a decision, not an oversight."""
    assert _verdict("POST").verdict == "ALLOW"


def test_a_GET_at_a_reset_password_URL_is_STILL_ALLOWED():
    """THE BOUNDARY. The shell path's URL-word rule would deny this, and applying it here
    would break endpoint discovery, which legitimately GETs this exact path on crAPI. On
    the web plane the method is explicit, so the method is what is judged."""
    d = _verdict("GET", url="http://172.20.0.12/identity/api/v2/user/reset-password")
    assert d.verdict == "ALLOW", d.reason


def test_an_out_of_scope_DELETE_still_fails_on_SCOPE_first():
    """Ordering: the destructive rule must not mask the scope refusal, or a reader cannot
    tell which wall stopped the request."""
    d = _verdict("DELETE", url="http://evil.example.com/x")
    assert d.verdict == "DENY"
    assert "scope" in (d.layer or "")
