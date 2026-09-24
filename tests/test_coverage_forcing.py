"""
test_coverage_forcing.py — every confirmed route family gets asked at least one question.

THE MEASURED PROBLEM (CR1 runs 2-5, same target, same configuration, same model)

    run | experiments proposed | foreign records | recall
      2 |  7                   | 0               | 0 of 14
      3 |  4                   | 2               | 2 of 14
      4 | 15                   | 8               | 2 of 14
      5 |  4                   | 0               | 2 of 14

    Run 4 went to /workshop/api/shop/orders and found another tenant's order. Run 5 never
    went near it. Nothing is wrong with either run: the agent goes deep where it gets
    traction and never visits the rest, so WHICH endpoints get examined is a coin flip,
    and three challenges sit at MODEL-LIMIT because nobody ever asked about them.

THE FIX
    After the model has proposed, every CONFIRMED route family that no proposal touched
    gets one deterministic question: is this endpoint open to an anonymous caller? That is
    `a_denied_b_allowed` with an anonymous control — read-only, two requests, no model
    call — and it is the question that found crAPI's unauthenticated order exposure by
    accident in run 4.

    Coverage, not cleverness. It does not replace the model's proposals; it guarantees a
    floor under them so a run cannot silently skip half the application.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.hypothesis import Hypothesis, coverage_proposals, route_families

CONFIRMED = [
    "/identity/api/auth/login", "/identity/api/auth/signup",
    "/identity/api/v2/user/dashboard", "/identity/api/v2/user/videos",
    "/identity/api/v2/vehicle/vehicles", "/identity/api/v2/vehicle/resend_email",
    "/workshop/api/shop/orders", "/workshop/api/shop/products",
    "/community/api/v2/community/posts/recent",
]
BASE = "http://10.10.10.5"


def _proposal(url):
    return Hypothesis(title="t", severity="low", comparator="status_differs",
                      control={"method": "GET", "url": url},
                      variant={"method": "GET", "url": url}, setup=[])


def test_families_group_an_application_by_its_own_mount_points():
    fams = route_families(CONFIRMED)
    assert "/identity/api/v2/vehicle" in fams
    assert "/workshop/api/shop" in fams
    assert any(f.startswith("/community/api/v2/community") for f in fams), sorted(fams)
    # One family per area, not one per endpoint — two vehicle routes are one question.
    assert len(fams["/identity/api/v2/vehicle"]) == 2


def test_an_untouched_family_gets_a_question(tmp_path):
    """THE DEFECT: run 5 never asked anything about /workshop/api/shop."""
    props = coverage_proposals(CONFIRMED, [_proposal(f"{BASE}/identity/api/v2/user/dashboard")],
                               base=BASE)
    urls = [p.variant["url"] for p in props]
    assert any("/workshop/api/shop" in u for u in urls), urls
    assert any("/community/api/v2/community" in u for u in urls), urls


def test_a_family_the_model_ALREADY_covered_is_not_asked_twice(tmp_path):
    """It is a floor under the model, not a replacement for it."""
    props = coverage_proposals(CONFIRMED, [_proposal(f"{BASE}/workshop/api/shop/orders")],
                               base=BASE)
    assert not any("/workshop/api/shop" in p.variant["url"] for p in props)


def test_the_question_is_the_one_that_found_run_4s_exposure():
    """Anonymous control, us as the variant: does this endpoint authenticate at all."""
    props = coverage_proposals(CONFIRMED, [], base=BASE)
    assert props
    p = props[0]
    assert p.comparator == "a_denied_b_allowed"
    assert p.control["as"] == "anonymous" and p.variant["as"] == "self"
    assert p.control["method"] == "GET" and p.setup == []


def test_the_battery_also_asks_the_cross_account_question():
    """The harness fires the standard access-control BATTERY per family, not just the
    anonymous question — self-vs-second is the canonical BOLA read the model kept failing
    to propose (CR3 'reached-not-proposed'). This is the harness carrying the load."""
    props = coverage_proposals(["/workshop/api/shop/orders"], [], base=BASE)
    by_cmp = {p.comparator for p in props}
    assert "a_denied_b_allowed" in by_cmp and "cross_account_resource" in by_cmp, by_cmp
    bola = next(p for p in props if p.comparator == "cross_account_resource")
    assert bola.control["as"] == "self" and bola.variant["as"] == "second"
    assert bola.control["method"] == "GET" and bola.setup == []   # read-only


def test_the_battery_respects_per_program_comparator_selection():
    """A program that did not enable cross_account_resource never has it proposed — the
    deterministic proposer honours the same allowlist as the model path."""
    props = coverage_proposals(["/workshop/api/shop/orders"], [], base=BASE,
                               allowed=("a_denied_b_allowed",))
    assert {p.comparator for p in props} == {"a_denied_b_allowed"}, props


def test_it_is_BOUNDED():
    """A wide application must not turn into a hundred experiments. The floor covers at most
    `cap` families, each with its read-only battery (2 comparators)."""
    wide = [f"/svc{i}/api/thing" for i in range(50)]
    props = coverage_proposals(wide, [], base=BASE)
    assert len({p.variant["url"] for p in props}) <= 4      # at most cap families
    assert len(props) <= 8                                  # battery of 2 per family


def test_state_changing_routes_are_NOT_swept():
    """BOUNDARY: coverage is read-only. A sweep that POSTs to everything it finds is a
    different kind of tool, and not this one."""
    routes = ["/api/v2/user/delete_account", "/api/v2/admin/reset", "/api/v2/shop/orders"]
    props = coverage_proposals(routes, [], base=BASE)
    urls = " ".join(p.variant["url"] for p in props)
    assert "delete" not in urls and "reset" not in urls, urls


def test_nothing_confirmed_means_nothing_swept():
    """BOUNDARY: mined-but-unconfirmed routes are not a surface to sweep — that is the
    GAP #4 lesson, and a sweep would spend two requests per phantom."""
    assert coverage_proposals([], [], base=BASE) == []


def test_the_ROUND_includes_the_coverage_floor(tmp_path):
    """END TO END: a session whose model proposes nothing still asks one question of every
    confirmed family — which is precisely run 5's failure mode."""
    import json
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import ExecResult
    from brukal.web import GovernedBrowser, WebResult
    from brukal.webmap import AttackSurface

    scope = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope_fast.json")
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession("10.10.10.5", ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, type("C", (), {
                          "run": lambda self, a: WebResult(status=200, url=a.url, body="{}")})(),
                          audit))
    s.allow_intrusive = True
    surface = AttackSurface(seed="http://10.10.10.5/")
    surface.confirmed_routes = list(CONFIRMED)
    surface.add_routes(list(CONFIRMED))
    s.surface = surface
    asked = []
    s._run_one_round = lambda proposals, outcomes, shapes=None: (asked.extend(proposals) or 0)
    s.run_hypotheses()
    assert asked, "the model proposed nothing and the run asked nothing"
    # The deterministic battery: anon-vs-self (a_denied_b_allowed) + self-vs-second
    # (cross_account_resource). Both are read-only questions the harness fires itself.
    assert all(h.comparator in ("a_denied_b_allowed", "cross_account_resource")
               for h in asked), asked
    assert any(h.comparator == "a_denied_b_allowed" for h in asked), asked
    fams = {h.variant["url"] for h in asked}
    assert len(fams) >= 3, fams
