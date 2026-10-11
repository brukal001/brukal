"""The capture store keeps the START and END of a long response.

2026-10-01: the decisive response was 4,447 bytes with the result near the end; the
capture store kept [:4000], so the deterministic provers never saw the result.
Bodies <= 4,000 chars are stored byte-identical to before."""
from __future__ import annotations

from pathlib import Path

from brukal import capture, redact
from brukal import capture_confirm as cc
from brukal.scope import load_scope

SCOPE = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope.json")
URL = "http://10.10.10.5/filter"


def _rec(response, q="", body=None, method="GET"):
    return capture._record(method, URL + (("?" + q) if q else ""), {}, body, 200,
                           len(response), "text/html", SCOPE, capture.IngestReport(),
                           "self", response=response)


def test_short_body_is_byte_identical():
    body = "x" * 4000
    assert _rec(body).response == body


def test_long_body_keeps_its_end_within_budget():
    body = "H" * 4000 + "<td>RESULT-ROW-END</td>"
    stored = _rec(body).response
    assert len(stored) <= 4000
    assert stored.startswith("H" * 2400)
    assert stored.endswith("<td>RESULT-ROW-END</td>")
    assert "chars omitted" in stored


def test_the_2026_10_01_shape_keeps_the_result():
    page = "<div>nav</div>\n" * 293 + "<table><tr><td>RESULT-ROW-1</td></tr></table>"
    assert 4000 < len(page) < 4500
    assert "RESULT-ROW-1" in _rec(page).response


def test_redaction_still_applies_to_text_landing_in_the_tail():
    secret = "S3cretValue-For-Test-0001"
    redact.register(secret)
    try:
        stored = _rec("H" * 5000 + secret).response
        assert secret not in stored and "[REDACTED:" in stored
    finally:
        redact.clear()


def test_boolean_differential_now_sees_a_tail_only_difference():
    head = "<p>same header</p>\n" * 300            # > 4,000 chars of identical start
    rows = "<tr><td>row one</td></tr>"
    caps = [_rec(head + rows, q="category=Gifts"),
            _rec(head + rows, q="category=Gifts' AND '1'='1"),
            _rec(head + "<tr><td>no rows</td></tr>", q="category=Gifts' AND '1'='2")]
    assert [f["param"] for f in cc.boolean_sqli_differential(caps)] == ["category"]


def test_dynamic_tail_content_is_now_compared_too():
    """Stated trade-off: a value that changes on every load, placed at the END of a long
    page, is now part of the comparison, so truthy != baseline and nothing is confirmed.
    Pinned so the effect is explicit."""
    head = "<p>same header</p>\n" * 300
    caps = [_rec(head + "<i>t=1</i>", q="category=Gifts"),
            _rec(head + "<i>t=2</i>", q="category=Gifts' AND '1'='1"),
            _rec(head + "<i>t=3</i>", q="category=Gifts' AND '1'='2")]
    assert cc.boolean_sqli_differential(caps) == []


def test_length_difference_in_the_omitted_middle_does_not_break_the_differential():
    """Final review #1: the stored marker used to carry the omitted length, so a search
    page that echoes the (longer) payload in its MIDDLE stored truthy != baseline even
    though head and tail were identical — a new false negative vs the old [:4000]. The
    marker is now fixed text, so only what is kept is compared."""
    def page(cat, rows):
        return ("<p>hdr</p>\n" * 80 + rows + "<p>mid</p>\n" * 350
                + f"<!-- you searched: {cat} -->\n" + "<p>foot</p>\n" * 200)
    ok, no = "<tr><td>row one</td></tr>", "<tr><td>none</td></tr>"
    caps = [_rec(page("Gifts", ok), q="category=Gifts"),
            _rec(page("Gifts' AND '1'='1", ok), q="category=Gifts' AND '1'='1"),
            _rec(page("Gifts' AND '1'='2", no), q="category=Gifts' AND '1'='2")]
    assert [f["param"] for f in cc.boolean_sqli_differential(caps)] == ["category"]
