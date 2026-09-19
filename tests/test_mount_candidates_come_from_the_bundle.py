"""
test_mount_candidates_come_from_the_bundle.py — where the missing prefix actually lives.

THE MEASURED PROBLEM (CR1 run 19, diagnosed 2026-09-19 at $0.00)
    The harness mined `/orders` from crAPI's bundle, labelled it an API route, and the
    model aimed an experiment at it. crAPI's order API is `/workshop/api/shop/orders`.
    The two-session assumption was that mining STRIPPED the prefix. It did not: the
    bundle's path strings genuinely have no prefix, because the SPA keeps the mounts in
    SEPARATE constants and concatenates them at runtime:

        og="identity/", ig="workshop/", ag="chatbot/", lg="community/"

    A regex looking for path-SHAPED strings cannot see those — they are bare segments —
    so every mount but the operator-supplied login prefix was invisible, and
    `align_mount_prefixes` could only ever learn `/identity/api`.

    The evidence was in the target's own bundle the whole time. This is not guessing a
    wordlist: it is reading what the application says about itself, and then CONFIRMING
    each candidate by request before anything uses it -- the same law
    `resolve_mined_routes` already follows.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.webmap import extract_mount_candidates

# Verbatim from crAPI's main.8c78208c.js, fetched from the live container.
CRAPI = ('ateStreamMessage:!0,rcbStartStreamMessage:!0}}),c},og="identity/",'
         'ig="workshop/",ag="chatbot/",lg="community/",sg={LOG')


def test_the_four_crapi_mounts_are_recovered():
    got = extract_mount_candidates(CRAPI)
    assert {"identity", "workshop", "community", "chatbot"} <= set(got), got


def test_a_path_shaped_string_is_not_a_mount_candidate():
    """`/workshop/api/shop/orders` is a PATH; the miner already handles those. A mount
    candidate is the bare segment the app concatenates onto one."""
    got = extract_mount_candidates('x="/workshop/api/shop/orders",y="/orders"')
    assert "workshop/api/shop/orders" not in got
    assert not any(c.startswith("/") for c in got), got


def test_obvious_non_mounts_are_not_returned():
    """BOUNDARY. Every candidate costs a confirmation request, so the extractor must not
    turn a bundle into a wordlist."""
    got = extract_mount_candidates('a="https://",b="//",c="a/",d="' + "x" * 60 + '/"')
    assert "https:" not in got and "" not in got
    assert not any(len(c) > 40 for c in got), got
    assert "a" not in got, "a single character is noise, not a service name"


def test_it_is_bounded():
    """A minified bundle is megabytes of strings. An unbounded extractor is a scan."""
    text = ",".join(f'v{i}="svc{i}/"' for i in range(500))
    assert len(extract_mount_candidates(text)) <= 24


def test_confirmed_mounts_reach_the_GROUNDING():
    """A fact the model never sees changes nothing. The whole failure was the model
    aiming at `/orders` with no idea the app mounts services at all."""
    from brukal.webmap import AttackSurface
    s = AttackSurface(seed="http://t/")
    s.api_routes = ["/orders"]
    s.confirmed_mounts = ["identity", "workshop", "community"]
    text = s.summary()
    assert "/workshop" in text
    assert "mount" in text.lower()


def test_no_mounts_no_claim():
    """BOUNDARY: a target with no confirmed mounts must not grow an empty section that
    reads as 'this app has none'."""
    from brukal.webmap import AttackSurface
    s = AttackSurface(seed="http://t/")
    s.api_routes = ["/orders"]
    text = s.summary()
    assert "service mount" not in text.lower()
