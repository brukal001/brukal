"""
test_mined_fragments_are_not_called_api_routes.py — GAP #13, properly diagnosed.

THE MEASURED PROBLEM (CR1 run 19, 2026-09-19)
    The model aimed its first correct `state_changed` experiment at
    `http://172.20.0.12/orders/40` and both sides 404'd. The assumption for two sessions
    was that mining had STRIPPED a mount prefix which resolution should restore.

    It had not. crAPI's bundle was fetched directly ($0.00, no model):

        "/change-email" "/change-phone-number" "/dashboard" "/forgot-password"
        "/orders" "/past-orders" "/reset-password" "/signup" ...

    and it contains NO `/workshop/api/shop` anywhere. Those are the SPA's CLIENT-SIDE
    ROUTER paths. `/orders` is a React route; crAPI's order API is
    `/workshop/api/shop/orders`. Nothing was stripped -- the prefix was never present.

    `_API_ROUTE_RE` matches `/orders` because `orders?` sits in its keyword allowlist, so
    a UI route is mined and then rendered to the model under the heading "API route
    fragments". **The label is asserted by a regex, not earned by evidence**, and the
    model reasonably used it as an endpoint.

THE PROPERTY
    The grounding may not call an unconfirmed path-shaped string an API route. It must
    say what it actually is: a string that LOOKS like a path, which on a single-page app
    is very often a router path, not an endpoint.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.webmap import AttackSurface


def _surface():
    s = AttackSurface(seed="http://t/")
    s.api_routes = ["/orders", "/change-phone-number", "/identity/api/v2/user/dashboard"]
    s.confirmed_routes = ["/identity/api/v2/user/dashboard"]
    s.route_methods = {"/identity/api/v2/user/dashboard": "GET"}
    return s


def test_unconfirmed_fragments_are_NOT_labelled_API_routes():
    """The heading is the claim. `/orders` is a router path and was presented as an API
    route fragment, which is what the model then aimed an experiment at."""
    text = _surface().summary()
    before = text.split("CONFIRMED to exist")[-1]
    assert "API route fragments mined" not in before, (
        "unconfirmed path-shaped strings are still being called API routes")


def test_the_grounding_WARNS_that_they_may_be_client_side_routes():
    """Saying 'unverified' was not enough: it read as 'this endpoint might 404', not as
    'this might not be an endpoint at all'."""
    text = _surface().summary().lower()
    assert "router" in text or "client-side" in text, (
        "the grounding never tells the model these may be UI routes rather than endpoints")


def test_CONFIRMED_routes_keep_their_earned_label():
    """POSITIVE CONTROL. A route proved by a request has earned the word, and the fix must
    not water that down — otherwise the model cannot tell the two apart at all, which is
    the same defect pointing the other way."""
    text = _surface().summary()
    assert "CONFIRMED to exist" in text
    assert "/identity/api/v2/user/dashboard" in text
