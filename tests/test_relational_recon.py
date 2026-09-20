"""
test_relational_recon.py — the grammar, not just the nouns and verbs.

WHERE THIS CAME FROM (2026-09-21)
    Asked whether Brukal understands the target's architecture, the honest answer was
    "structurally, yes; relationally, no". From a captured session it derives the services,
    the state-changing surface, the auth model and the real parameter names — but it does
    not know that `product_id` in /orders REFERS TO the `id` in /products, that `order_id`
    in return_order must be an order you OWN, or that the workflow is browse -> buy ->
    return. It knows the nouns and the verbs, not the grammar.

    That limit explains the results. Every experiment it derives is "same request,
    different principal", which is all a structural map can support. The classes never
    reached — coupon reuse, price tampering, workflow bypass — need the grammar: redeeming
    a SPENT coupon means replaying a code after a successful redemption, not sending it as
    somebody else. And the A/B/C showed the model will not supply that grammar either:
    zero `state_changed` proposals across three model families in 23 runs.

    The link is derivable deterministically. A value the target HANDED BACK and the client
    later SENT is a reference, and the traffic shows it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.capture import CapturedRequest, link_fields


def _cap(method, path, body=None, response=None, status=200):
    return CapturedRequest(method=method, url=f"http://t{path}", body=body,
                           status=status, resp_bytes=len(response or ""),
                           content_type="application/json", response=response)


def test_a_value_the_response_GAVE_and_a_later_request_SENT_is_a_link():
    """crAPI's exact shape: buying returns an order id, returning it sends that id back."""
    caps = [
        _cap("POST", "/workshop/api/shop/orders", '{"product_id":1,"quantity":1}',
             response='{"id":6,"message":"Order sent successfully.","credit":155.0}'),
        _cap("POST", "/workshop/api/shop/orders/return_order", '{"order_id":6}',
             response='{"message":"Return in progress"}'),
    ]
    links = link_fields(caps)
    assert links, "no reference was found between two requests that clearly share one"
    l = links[0]
    assert l["source_path"] == "/workshop/api/shop/orders"
    assert l["source_field"] == "id"
    assert l["consumer_path"] == "/workshop/api/shop/orders/return_order"
    assert l["consumer_field"] == "order_id"
    assert str(l["value"]) == "6"


def test_a_value_that_was_never_handed_back_is_not_a_link():
    """BOUNDARY. A client-chosen constant is not a reference — treating it as one would
    invent a dependency the application does not have."""
    caps = [
        _cap("GET", "/a", response='{"unrelated":99}'),
        _cap("POST", "/b", '{"quantity":1}', response='{"ok":true}'),
    ]
    assert link_fields(caps) == []


def test_order_matters_a_request_cannot_consume_a_LATER_response():
    """The reference must be causal: the value has to exist before it is sent."""
    caps = [
        _cap("POST", "/b", '{"order_id":6}', response='{"ok":true}'),
        _cap("POST", "/a", response='{"id":6}'),
    ]
    assert link_fields(caps) == []


def test_trivial_values_are_ignored():
    """0/1/true and short strings collide by chance constantly; a link built on one is
    noise, and noise here becomes a fabricated experiment."""
    caps = [
        _cap("POST", "/a", response='{"id":1,"ok":true,"n":0}'),
        _cap("POST", "/b", '{"quantity":1,"flag":true,"page":0}', response='{}'),
    ]
    assert link_fields(caps) == []


def test_nested_response_fields_are_found():
    caps = [
        _cap("GET", "/workshop/api/shop/orders/all",
             response='{"orders":[{"id":77,"product":{"id":3}}]}'),
        _cap("POST", "/workshop/api/shop/orders/return_order", '{"order_id":77}',
             response='{}'),
    ]
    links = link_fields(caps)
    assert any(l["consumer_field"] == "order_id" and str(l["value"]) == "77"
               for l in links), links


def test_it_is_bounded():
    caps = [_cap("GET", f"/r{i}", response=json.dumps({"id": 1000 + i})) for i in range(60)]
    caps += [_cap("POST", f"/w{i}", json.dumps({"ref": 1000 + i}), response="{}")
             for i in range(60)]
    assert len(link_fields(caps, max_links=10)) <= 10


def test_the_links_reach_the_GROUNDING():
    """A relationship nothing is told about changes nothing — the lesson of six
    capability-nothing-calls bugs in one session. The model has never been shown that
    `return_order.order_id` is whatever `orders` handed back."""
    from brukal.webmap import AttackSurface
    s = AttackSurface(seed="http://t/")
    s.field_links = [{"source_path": "/workshop/api/shop/orders", "source_field": "id",
                      "consumer_path": "/workshop/api/shop/orders/return_order",
                      "consumer_field": "order_id", "value": "9",
                      "consumer_method": "POST"}]
    text = s.summary()
    assert "return_order" in text and "order_id" in text
    assert "orders" in text
    low = text.lower()
    assert "refer" in low or "handed back" in low or "came from" in low


def test_no_links_no_section():
    """BOUNDARY: a target whose traffic showed no references must not grow an empty
    heading that reads as 'this application has none'."""
    from brukal.webmap import AttackSurface
    s = AttackSurface(seed="http://t/")
    assert "refer" not in s.summary().lower()


def test_a_link_to_a_WRITE_becomes_a_reuse_experiment():
    """The payoff. crAPI's coupon lifecycle crosses two services: validate-coupon hands
    back a code, apply_coupon consumes it. The reuse question — was a consumed value
    accepted AGAIN — is derivable from that link and from nothing else the harness had."""
    from brukal.capture import reuse_experiments
    links = [{"source_path": "/community/api/v2/coupon/validate-coupon",
              "source_field": "coupon_code",
              "consumer_path": "/workshop/api/shop/apply_coupon",
              "consumer_field": "coupon_code", "value": "TRAC075",
              "consumer_method": "POST"}]
    caps = [CapturedRequest(method="POST",
                            url="http://t/workshop/api/shop/apply_coupon",
                            body='{"coupon_code":"TRAC075","amount":75}', status=200)]
    hyps = reuse_experiments(links, caps, base="http://t")
    assert len(hyps) == 1
    h = hyps[0]
    assert h.comparator == "repeat_accepted"
    assert h.control["url"] == h.variant["url"] == "http://t/workshop/api/shop/apply_coupon"
    assert h.control["method"] == "POST" and h.variant["method"] == "POST"
    assert "TRAC075" in (h.control["body"] or "")
    assert h.control["as"] == h.variant["as"] == "self", (
        "reuse is about the SAME principal using a value twice; changing principal asks "
        "a different question entirely")


def test_a_link_to_a_READ_is_not_a_reuse_experiment():
    """BOUNDARY: reading something twice is not reuse. Only a state-changing consumer
    can 'consume' anything."""
    from brukal.capture import reuse_experiments
    links = [{"source_path": "/a", "source_field": "id", "consumer_path": "/b",
              "consumer_field": "order_id", "value": "9", "consumer_method": "GET"}]
    assert reuse_experiments(links, [], base="http://t") == []


def test_without_the_original_request_body_nothing_is_invented():
    """FAIL CLOSED: the replay must send what the operator actually sent. With no captured
    body for the consumer there is nothing faithful to replay, and guessing one would put
    a request nobody made on the wire."""
    from brukal.capture import reuse_experiments
    links = [{"source_path": "/a", "source_field": "coupon_code",
              "consumer_path": "/spend", "consumer_field": "coupon_code",
              "value": "X9Y8Z7", "consumer_method": "POST"}]
    assert reuse_experiments(links, [], base="http://t") == []
