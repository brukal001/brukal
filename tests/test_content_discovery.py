"""
test_content_discovery.py — GAP #26's other half: the tools were installed all along.

THE MEASURED PROBLEM (cold target 1, DVWA, 2026-09-20)
    The harness fetched 30 URLs on an unfamiliar app. Two were real. Nineteen were
    API-shaped guesses inherited from crAPI and Juice Shop. `/setup.php` answers 200 and
    was never requested — because NOTHING in the harness has ever asked a target what it
    has. `ffuf`, `gobuster`, `dirb` and `wfuzz` are all installed in the cage and not one
    has ever been invoked in a measured engagement.

WHAT THIS IS, AND WHAT IT IS NOT
    It is one bounded ffuf run whose findings are proved by the harness's own request
    before anything uses them. It is NOT a licence to sweep: the command is built here,
    with an explicit rate and an explicit wordlist size, so the cost of recon is a number
    someone chose rather than a default someone inherited.

THE SOFT-404 TRAP, which this project has already paid for once
    `surface.soft_404` exists because a host that answers 200 for everything makes every
    discovery tool report the whole wordlist as found. Discovery MUST refuse to run there
    rather than return 4749 fabricated paths — the same fail-closed reflex as the mount
    discovery that declines to invent a surface it cannot prove.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.discovery import build_ffuf_command, parse_ffuf_json, should_discover


def test_the_command_is_bounded_and_rate_limited():
    cmd = build_ffuf_command("http://172.20.0.2", rate_per_min=120, max_words=500)
    assert cmd.startswith("ffuf ")
    assert "-rate 2" in cmd, "a discovery sweep must honour the engagement's rate limit"
    assert "FUZZ" in cmd and "-of json" in cmd
    assert "-ac" in cmd or "-fc" in cmd, "no soft-404 calibration would report everything"


def test_it_refuses_to_run_against_a_soft_404_host():
    """A host that answers 200 for everything would report the entire wordlist as found."""
    class _S:
        soft_404 = True
    assert should_discover(_S()) is False


def test_it_runs_against_an_ordinary_host():
    class _S:
        soft_404 = False
    assert should_discover(_S()) is True


def test_real_ffuf_output_becomes_routes():
    """ffuf's own JSON shape, with the statuses DVWA actually returns."""
    out = {"results": [
        {"input": {"FUZZ": "setup.php"}, "url": "http://172.20.0.2/setup.php",
         "status": 200, "length": 4076, "words": 100, "lines": 10},
        {"input": {"FUZZ": "instructions.php"}, "url": "http://172.20.0.2/instructions.php",
         "status": 200, "length": 14014, "words": 200, "lines": 20},
        {"input": {"FUZZ": "security.php"}, "url": "http://172.20.0.2/security.php",
         "status": 302, "length": 0, "words": 0, "lines": 0},
    ]}
    found = parse_ffuf_json(json.dumps(out))
    paths = {p for p, _st, _ln in found}
    assert {"/setup.php", "/instructions.php", "/security.php"} == paths


def test_a_uniform_wall_of_identical_answers_is_discarded():
    """BOUNDARY. Even with calibration, a host can answer 200/1234 bytes to everything.
    Identical length across every hit is a wall, not a surface, and reporting it would put
    a fabricated map in front of the model — the failure GAP #26 is made of."""
    out = {"results": [
        {"input": {"FUZZ": f"w{i}"}, "url": f"http://t/w{i}", "status": 200,
         "length": 1234, "words": 5, "lines": 2} for i in range(25)]}
    assert parse_ffuf_json(json.dumps(out)) == []


def test_malformed_output_yields_nothing_rather_than_an_exception():
    assert parse_ffuf_json("not json") == []
    assert parse_ffuf_json(json.dumps({"results": "nonsense"})) == []


def test_the_wordlist_bound_is_REAL_not_an_ignored_argument():
    """`max_words` was accepted and never used — the command came out identical whatever
    was passed. That is the fourth silent no-op found in one session (audit.record,
    agent="probe", the capture wiring twice), and the shape is always the same: an
    argument that looks like a control and controls nothing.

    Here the bound has to be real, because at an engagement's own rate limit (120/min =
    2/sec) a 4749-word list cannot finish: a measured run against DVWA got through roughly
    360 requests in its 180-second budget and found one path."""
    small = build_ffuf_command("http://t", rate_per_min=120, max_words=200)
    big = build_ffuf_command("http://t", rate_per_min=120, max_words=4000)
    assert small != big, "max_words changed nothing about the command"
    assert "-maxtime" in small, "a rate-limited sweep must also be time-bounded"


def test_the_sweep_cannot_outlive_its_own_budget():
    """At 2 requests/second, 200 words is ~100s. The time bound must leave room for the
    words asked for, or the sweep reports a fraction of the list as if it were the whole
    answer — 'searched 4749 paths' when it searched 360."""
    from brukal.discovery import sweep_seconds_for
    assert sweep_seconds_for(200, 120) >= 100
    assert sweep_seconds_for(4000, 120) >= 1900


def test_extensions_come_from_what_the_target_IS():
    """MEASURED: a 900-request sweep of common.txt against DVWA found exactly one path,
    `/.gitignore`. The wordlist carries no file extensions and DVWA serves `.php`, so
    `/setup.php` — 200, unauthenticated, the thing the cold run never asked for — was
    unreachable by construction.

    Generic recon is not recon. The fingerprinting step already knows the target runs PHP
    on Apache; discovery has to USE that, or it is a memorised wordlist with extra steps —
    the same failure as the crAPI path wishlist, one layer down."""
    php = build_ffuf_command("http://t", techs={"PHP", "Apache"})
    assert "-e " in php and ".php" in php

    node = build_ffuf_command("http://t", techs={"Express", "Node.js"})
    assert ".php" not in node, "a Node app was swept for PHP files"

    bare = build_ffuf_command("http://t")
    assert "-e " not in bare, "unknown stack must not guess an extension set"


def test_the_high_yield_list_is_small_and_stack_aware():
    """MEASURED on DVWA: 900 requests of common.txt found ONE path (`/.gitignore`).
    22 stack-targeted words found ELEVEN — /setup.php, /instructions.php, /phpinfo.php,
    /security.php, /config, /docs, /about.php, /robots.txt.

    Under an engagement's own rate limit a generic sweep cannot finish, so what matters is
    yield per request, not list size."""
    from brukal.discovery import high_yield_candidates

    php = high_yield_candidates({"PHP", "Apache"})
    assert len(php) <= 80, "a 'high yield' list that is big is just a slow sweep"
    assert "/setup.php" in php and "/phpinfo.php" in php
    assert "/robots.txt" in php

    node = high_yield_candidates({"Express"})
    assert not any(p.endswith(".php") for p in node), "a Node app got PHP candidates"

    bare = high_yield_candidates(set())
    assert bare, "an unknown stack still deserves the extension-free basics"
    assert not any(p.endswith(".php") for p in bare)


def test_candidates_are_paths_ready_to_request():
    from brukal.discovery import high_yield_candidates
    for p in high_yield_candidates({"PHP"}):
        assert p.startswith("/") and " " not in p
