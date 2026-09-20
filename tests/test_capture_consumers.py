"""
test_capture_consumers.py — what the capture is FOR.

`capture.py` parses traffic into records. A parser nothing calls changes nothing, and the
two consumers are where a capture becomes capability:

  1. SURFACE ENRICHMENT — the application's shape, from traffic instead of guesses. The
     cold run on DVWA mapped ONE page while /setup.php answered 200 unasked.
  2. REPLAY AS ANOTHER PRINCIPAL — every captured request is an experiment whose CONTROL
     IS ALREADY KNOWN TO WORK. This is aimed at the failure that survived every fix of
     2026-09-19/20: `state_changed` was proposed 0 of 14 times in a run where the same
     model, on the same prompt, produced one in 4 of 4 offline calls. A captured write is
     a state-changing experiment assembled from evidence rather than imagination.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import load_scope
from brukal.capture import apply_to_surface, hypotheses_from, parse_har
from brukal.webmap import AttackSurface

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dvwa_capture.har"
SCOPE = Path(__file__).resolve().parent.parent / "scope.dvwa.json"


def _caps():
    return parse_har(FIXTURE.read_text(), load_scope(SCOPE))[0]


# --- consumer 1: the surface ---------------------------------------------------------

def test_the_surface_learns_the_routes_the_crawl_never_reached():
    s = AttackSurface(seed="http://172.20.0.2/")
    apply_to_surface(_caps(), s)
    routes = " ".join(s.api_routes)
    assert "/setup.php" in routes
    assert "/vulnerabilities/exec/" in routes


def test_captured_routes_are_CANDIDATES_not_confirmed():
    """The law: never act on a derived fact that has not been confirmed against the
    target once. A capture is an observation from the OPERATOR's session at an EARLIER
    time — the route may be gone, or may answer differently to us."""
    s = AttackSurface(seed="http://172.20.0.2/")
    apply_to_surface(_caps(), s)
    assert s.api_routes, "nothing was learned at all"
    assert s.confirmed_routes == [], (
        "captured routes were written down as CONFIRMED without asking the target")


def test_real_methods_and_parameters_reach_the_surface():
    """The harness has never had real parameter names: `surface.params` came only from
    HTML forms the crawl happened to reach."""
    s = AttackSurface(seed="http://172.20.0.2/")
    apply_to_surface(_caps(), s)
    assert s.route_methods.get("/vulnerabilities/exec/") == "POST"
    names = set()
    for v in s.params.values():
        names |= set(v)
    assert {"id", "Submit", "username", "password", "ip"} <= names, names


def test_the_state_changing_surface_is_NAMED():
    s = AttackSurface(seed="http://172.20.0.2/")
    apply_to_surface(_caps(), s)
    writes = {p for _m, p in s.write_operations}
    assert "/vulnerabilities/exec/" in writes
    assert "/login.php" in writes


def test_routes_that_expect_auth_are_recorded_with_their_mechanism():
    s = AttackSurface(seed="http://172.20.0.2/")
    apply_to_surface(_caps(), s)
    protected = {p for _m, p in s.protected_routes}
    assert "/vulnerabilities/exec/" in protected


# --- consumer 2: replay --------------------------------------------------------------

def test_every_capture_becomes_an_experiment_with_a_known_good_control():
    """Both shapes address the SAME resource — what varies differs by comparator:

    a READ varies the PRINCIPAL (same url, different `as`), while `state_changed` varies
    NEITHER side (same url, same principal) and carries the change in `act`. Asserting
    "control.as != variant.as" for everything was this test's own first mistake: it is
    true for reads and wrong by construction for the comparator that matters most."""
    hyps = hypotheses_from(_caps())
    assert hyps, "no experiments were derived from real traffic"
    for h in hyps:
        assert h.control["url"] == h.variant["url"], h.title
        if h.comparator == "state_changed":
            assert h.control["as"] == h.variant["as"], h.title
            assert h.act and h.act.get("as") != h.control["as"], (
                "the captured write must be performed as a DIFFERENT principal, or the "
                "experiment only proves we can change our own data")
        else:
            assert h.control["as"] != h.variant["as"], h.title


def test_a_captured_WRITE_becomes_a_state_changed_experiment():
    """THE POINT. `state_changed` has been proposed zero times by any model in any run."""
    hyps = hypotheses_from(_caps())
    sc = [h for h in hyps if h.comparator == "state_changed"]
    assert sc, "a captured POST did not become a state-changing experiment"
    h = sc[0]
    assert h.act is not None, "a state_changed experiment needs the change in `act`"
    assert h.act["method"] == "POST"
    assert h.control["url"] == h.variant["url"], (
        "for state_changed the two sides are the SAME read and `act` is the change")


def test_a_captured_READ_becomes_a_cross_principal_experiment():
    hyps = hypotheses_from(_caps())
    reads = [h for h in hyps if h.comparator != "state_changed"]
    assert reads
    assert {h.comparator for h in reads} <= {
        "cross_account_resource", "unauthenticated_exposure", "a_denied_b_allowed"}


def test_derivation_is_bounded():
    """A 2000-entry capture must not become 2000 experiments."""
    hyps = hypotheses_from(_caps() * 50, max_hypotheses=6)
    assert len(hyps) <= 6


def test_no_credential_reaches_a_derived_experiment():
    """The captured session must not ride along into the replay — that would replay as
    the SAME principal and prove nothing, and it would hand a live secret to the model."""
    import json as _json
    blob = _json.dumps([[h.control, h.variant, h.act] for h in hypotheses_from(_caps())])
    assert "PHPSESSID" not in blob and "Bearer" not in blob


def test_captures_are_applied_even_when_the_surface_does_not_exist_yet(tmp_path):
    """REGRESSION. The first wiring applied the capture in `run_auto` before the crawl had
    created `session.surface`, so every real run died with

        AttributeError: 'NoneType' object has no attribute 'api_routes'

    and the whole feature was swallowed into a one-line warning — the surface was built
    from guesses exactly as before. Parsing early is right (a bad path should be visible
    at start-up); APPLYING early is not.

    The fix splits the two: parse and hold at start-up, apply when the surface exists."""
    from brukal.capture import hold_for_surface, drain_onto_surface

    caps = _caps()

    class _Session:
        surface = None                      # exactly the state run_auto is in

    s = _Session()
    hold_for_surface(s, caps)               # must not raise with no surface
    assert getattr(s, "_captured", None), "the captures were dropped, not held"

    s.surface = AttackSurface(seed="http://172.20.0.2/")
    learned = drain_onto_surface(s)
    assert learned > 0
    assert any("/setup.php" in r for r in s.surface.api_routes)
    assert drain_onto_surface(s) == 0, "draining twice must not double-apply"
