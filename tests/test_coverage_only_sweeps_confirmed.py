"""
test_coverage_only_sweeps_confirmed.py — GAP #13, pinned rather than patched.

THE MEASURED PROBLEM (CR1 runs 17 and 18)
    Eight experiment URLs per run carried NO service prefix — `/v2/user/dashboard`,
    `/v2/user/videos`, `/v2/user/pictures`, `/orders/all` — on an application that mounts
    everything under `/identity/api`, `/workshop/api/shop` or `/community/api/v2`. Each
    spent two gated requests proving that a path which does not exist answers the same way
    for everybody.

THE MEASUREMENT THAT DECIDED THE FIX (2026-09-21)

    run                experiment urls   UNPREFIXED
    CR1 run 17                     36            8
    CR1 run 18                     36            8
    CR2 run 1                      26            0
    A/B arm A                      22            0 (2 were "/", the base)

    **The waste was already gone.** It disappeared when mount/endpoint discovery began
    filling `confirmed_routes` with paths PROVED BY REQUEST, because coverage only ever
    swept that list — the list had simply been full of unproven fragments before.

    So there was nothing left to patch, and patching anyway would have been the mistake
    this survey exists to record: fixing a symptom at the layer it is visible rather than
    where it is caused. What was missing is that the absence was INCIDENTAL. These tests
    make it a property, so a future change that refills `confirmed_routes` with guesses
    fails here instead of quietly spending eight requests a run again.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.hypothesis import coverage_proposals

BASE = "http://172.20.0.12"
CONFIRMED = ["/identity/api/v2/user/dashboard", "/identity/api/v2/user/videos",
             "/workshop/api/shop/orders/all", "/community/api/v2/coupon/validate-coupon"]


def _paths(props):
    out = []
    for h in props:
        for spec in (h.control, h.variant):
            url = (spec or {}).get("url", "")
            if BASE in url:
                out.append(url.split(BASE, 1)[-1].split("?")[0])
    return out


def test_every_proposed_path_comes_from_the_CONFIRMED_list():
    props = coverage_proposals(CONFIRMED, [], base=BASE)
    assert props, "coverage proposed nothing at all from four confirmed families"
    for p in _paths(props):
        assert any(p.startswith(c) or c.startswith(p) for c in CONFIRMED), p


def test_an_unconfirmed_fragment_can_never_be_swept():
    """THE DEFECT, stated as a property. `/v2/user/dashboard` is what CR1 runs 17 and 18
    actually put on the wire; it must be unreachable unless the target CONFIRMED it."""
    props = coverage_proposals([], [], base=BASE)
    assert props == [], "coverage swept something with nothing confirmed"

    props = coverage_proposals(CONFIRMED, [], base=BASE)
    for p in _paths(props):
        assert not p.startswith("/v2/"), f"an unprefixed fragment was swept: {p}"
        assert not p.startswith("/orders"), f"an unprefixed fragment was swept: {p}"


def test_it_is_bounded():
    many = [f"/identity/api/v2/thing{i}/x" for i in range(50)]
    assert len(coverage_proposals(many, [], base=BASE)) <= 8


def test_a_family_already_asked_about_is_not_re_swept():
    """Coverage is a FLOOR, not a duplicate: a family an experiment already addressed
    must not be swept again."""
    first = coverage_proposals(CONFIRMED, [], base=BASE)
    again = coverage_proposals(CONFIRMED, first, base=BASE)
    assert len(again) < len(first)


def test_the_call_site_passes_CONFIRMED_routes_not_mined_fragments():
    """The function can only be as good as what it is handed. This pins the wiring: the
    session must pass `surface.confirmed_routes`, never `api_routes`, which is the
    unverified tier that held the fragments in the first place."""
    import re
    # AssistSession is split across assist.py + assist_*.py mixins; scan them all.
    src = "".join(p.read_text() for p in
                  sorted((Path(__file__).resolve().parents[1] / "brukal").glob("assist*.py")))
    call = re.search(r"coverage_proposals\((.{0,160})", src, re.S)
    assert call, "the coverage call site vanished"
    assert "confirmed_routes" in call.group(1), call.group(1)[:160]
    assert "api_routes" not in call.group(1), call.group(1)[:160]
