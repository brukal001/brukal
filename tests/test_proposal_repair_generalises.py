"""
test_proposal_repair_generalises.py — repair must carry the prefix to the FAMILY.

THE MEASURED FAULT (run 14, ledger `runs/audit_cr1n.jsonl`)
    `proposal_repaired` fired ZERO times in a run whose model proposed four paths with no
    service prefix — the 404 class repair exists for:

        /orders/9            /orders/31
        /v2/user/videos/9    /v2/user/pictures/31

    Repair keys on the EXACT fragment resolution recorded. Resolution had proved
    `/v2/user/dashboard` lives at `/identity/api/v2/user/dashboard`, so the prefix for
    that whole family was known by measurement — but `/v2/user/videos/9` is not the
    string `/v2/user/dashboard`, so nothing matched and the request went out unprefixed
    and 404'd.

    The knowledge was in hand and the lookup was too narrow to use it.

THE RULE
    A prefix proven for one member of a family applies to its siblings. Still
    deterministic and still evidence-backed: the prefix came from a request that
    answered, no model is consulted, and every rewrite is recorded. A family we never
    resolved anything under is left exactly as proposed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal import hypothesis as hyp

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm))
    # exactly what run 14's resolution proved, and all it proved
    s._resolved_map = {"/v2/user/dashboard": "/identity/api/v2/user/dashboard",
                       "/orders/all": "/workshop/api/shop/orders/all"}
    return s


def _h(url):
    return hyp.Hypothesis(title="t", severity="low", comparator="status_differs",
                          setup=[], control={"method": "GET", "url": BASE + "/x"},
                          variant={"method": "GET", "url": url})


def test_a_sibling_of_a_resolved_route_is_repaired(tmp_path):
    """RUN 14'S OWN FOUR, verbatim. Each 404'd; each has a proven prefix."""
    s = _session(tmp_path)
    props = [_h(BASE + p) for p in ("/v2/user/videos/9", "/v2/user/pictures/31",
                                    "/orders/9", "/orders/31")]
    got = [h.variant["url"] for h in s.repair_proposals(props)]
    assert got == [BASE + "/identity/api/v2/user/videos/9",
                   BASE + "/identity/api/v2/user/pictures/31",
                   BASE + "/workshop/api/shop/orders/9",
                   BASE + "/workshop/api/shop/orders/31"], got


def test_the_exact_match_still_wins(tmp_path):
    """BOUNDARY. The family rule is a FALLBACK; a fragment we resolved exactly keeps the
    path resolution proved for it, not one derived from a sibling."""
    s = _session(tmp_path)
    s._resolved_map["/v2/user/videos"] = "/media/api/v2/user/videos"
    h = s.repair_proposals([_h(BASE + "/v2/user/videos")])[0]
    assert h.variant["url"] == BASE + "/media/api/v2/user/videos"


def test_an_unknown_family_is_left_alone(tmp_path):
    """BOUNDARY, load-bearing. Repair rewrites what a request PROVED. A path in a family
    nothing resolved under is a path we know nothing about, and guessing a prefix for it
    would put a fabricated URL on the wire under the model's name."""
    s = _session(tmp_path)
    for p in ("/admin/panel", "/v3/user/dashboard", "/"):
        h = s.repair_proposals([_h(BASE + p)])[0]
        assert h.variant["url"] == BASE + p, p


def test_an_already_prefixed_proposal_is_untouched(tmp_path):
    """BOUNDARY. The double-prefix bug, at the repair layer this time."""
    s = _session(tmp_path)
    url = BASE + "/identity/api/v2/user/videos/9"
    assert s.repair_proposals([_h(url)])[0].variant["url"] == url


def test_every_family_rewrite_is_in_the_ledger(tmp_path):
    """A request that is not the one the model wrote must be visible as such."""
    s = _session(tmp_path)
    s.repair_proposals([_h(BASE + "/v2/user/videos/9")])
    blob = (tmp_path / "a.jsonl").read_text()
    assert "proposal_repaired" in blob and "/identity/api/v2/user/videos/9" in blob
