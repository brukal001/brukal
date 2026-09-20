"""
test_capture_ingest.py — hunting from traffic that actually happened.

THE MEASURED PROBLEM (cold target 1, DVWA, 2026-09-20)
    Of 30 URLs the harness fetched on an unfamiliar app, TWO were real DVWA paths and
    NINETEEN were API-shaped guesses inherited from crAPI and Juice Shop —
    `/api/v1/coupon/apply`, `/coupons`, `/swagger.json`, `/graphql/console`. `/setup.php`
    answers 200 and was never requested. There is no content discovery at all.

    A captured request is evidence no wordlist can produce: it happened, and the target
    answered it.

THE TWO GUARANTEES, and they live in ONE constructor path so a later live-capture
producer cannot bypass them:
    1. SCOPE AT INGEST — an out-of-scope host never becomes a record, so it can never
       become an experiment. The fixture deliberately contains a DIFFERENT TARGET
       (crAPI, 172.20.0.12) alongside a CDN and an analytics host, because "another
       engagement's traffic in the same capture" is the case that actually matters.
    2. CREDENTIALS STRIPPED — the capture carries a live PHPSESSID and a Bearer token.
       Neither may survive. The auth SHAPE is kept, because "this route expects a bearer"
       is exactly what the grounding never knew and the value is exactly what it must
       never hold.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import load_scope
from brukal.capture import parse_har

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dvwa_capture.har"
SCOPE = Path(__file__).resolve().parent.parent / "scope.dvwa.json"


def _ingest():
    return parse_har(FIXTURE.read_text(), load_scope(SCOPE))


def test_it_finds_the_real_routes_the_cold_run_never_requested():
    """`/setup.php` answers 200 on the live container and twenty runs of guessing never
    asked for it."""
    caps, _report = _ingest()
    paths = {c.url.split("172.20.0.2", 1)[-1].split("?")[0] for c in caps}
    assert "/setup.php" in paths
    assert "/instructions.php" in paths
    assert "/vulnerabilities/exec/" in paths


def test_an_out_of_scope_host_never_becomes_a_record():
    """GUARANTEE 1. The fixture carries a CDN, an analytics host, and — the one that
    matters — ANOTHER ENGAGEMENT'S TARGET."""
    caps, report = _ingest()
    hosts = {c.url.split("/")[2] for c in caps}
    assert hosts == {"172.20.0.2"}, hosts
    assert not any("172.20.0.12" in c.url for c in caps), "another target's traffic survived"
    assert report.dropped_out_of_scope == 3, report


def test_no_credential_survives_ingest():
    """GUARANTEE 2. A live PHPSESSID and a Bearer token are in the fixture."""
    caps, _ = _ingest()
    blob = json.dumps([{"h": c.headers, "b": c.body} for c in caps])
    assert "PHPSESSID" not in blob
    assert "b9a1f0c2d3e4f5061728394a5b6c7d8e" not in blob
    assert "REALLOOKINGTOKEN" not in blob
    assert "Bearer" not in blob


def test_the_auth_SHAPE_is_kept_even_though_the_value_is_not():
    """What the grounding never knew: WHICH routes expect auth, and by what mechanism."""
    caps, _ = _ingest()
    by_path = {c.url.split("172.20.0.2", 1)[-1].split("?")[0]: c for c in caps}
    assert by_path["/vulnerabilities/exec/"].auth_kind == "bearer"
    assert by_path["/setup.php"].auth_kind == "cookie"


def test_write_operations_are_identified():
    """The state-changing surface, named from real traffic rather than inferred from a
    405. This is what a `state_changed` experiment needs and the model never proposed."""
    caps, _ = _ingest()
    writes = {(c.method, c.url.split("172.20.0.2", 1)[-1].split("?")[0])
              for c in caps if c.method in ("POST", "PUT", "PATCH", "DELETE")}
    assert ("POST", "/login.php") in writes
    assert ("POST", "/vulnerabilities/exec/") in writes


def test_real_parameters_are_recovered_from_query_and_body():
    caps, _ = _ingest()
    names = set()
    for c in caps:
        names |= set(c.param_names())
    assert {"id", "Submit", "name"} <= names, names          # query
    assert {"username", "password", "ip"} <= names, names    # body


def test_static_assets_are_skipped():
    """The bulk of any real capture, and they carry no surface."""
    caps, report = _ingest()
    assert not any(c.url.endswith((".css", ".png")) for c in caps)
    assert report.dropped_static >= 2


def test_a_malformed_har_reports_rather_than_crashes():
    """"ingested 12 of 900" must never read as "the app has 12 endpoints"."""
    caps, report = parse_har("{not json at all", load_scope(SCOPE))
    assert caps == []
    assert report.dropped_malformed >= 1

    caps2, report2 = parse_har(json.dumps({"log": {"entries": [{"nonsense": 1}]}}),
                               load_scope(SCOPE))
    assert caps2 == []
    assert report2.dropped_malformed >= 1


def test_ingest_is_bounded():
    """A real HAR can be 50MB. An unbounded parser turns one into a sweep."""
    big = {"log": {"entries": [
        {"request": {"method": "GET", "url": f"http://172.20.0.2/p{i}", "headers": []},
         "response": {"status": 200, "content": {"size": 10, "mimeType": "text/html"}}}
        for i in range(5000)]}}
    caps, _ = parse_har(json.dumps(big), load_scope(SCOPE), max_entries=100)
    assert len(caps) <= 100
