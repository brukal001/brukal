"""salient_view — what the model is SHOWN of a response (not a gate component).

The 2026-10-01 live run: a 4,447-byte response with the result near the END; the model
saw body[:600] (the page header) and handed the step back as MANUAL. The view must show
the changed region (vs an earlier response to the same page) or the start AND end."""
from __future__ import annotations

from brukal.response_view import head_tail, salient_view

HEADER = "\n".join(f"<div class='nav-{i}'>navigation item {i}</div>" for i in range(90))
NORMAL = HEADER + "\n<table>\n<tr><td>Product A</td></tr>\n<tr><td>Product B</td></tr>\n</table>"
RESULT = HEADER + ("\n<table>\n<tr><td>RESULT-ROW-1</td><td>value-7f3a</td></tr>\n"
                   "<tr><td>RESULT-ROW-2</td><td>value-91bc</td></tr>\n</table>")


def test_within_budget_is_identity():
    assert salient_view("short body", None, 600) == "short body"
    assert salient_view("short body", "other", 600) == "short body"


def test_head_tail_keeps_start_and_end_within_budget():
    body = "S" * 3000 + "MIDDLE" + "E" * 3000
    v = head_tail(body, 600)
    assert len(v) <= 600
    assert v.startswith("S") and v.endswith("E")
    assert "chars omitted" in v and "MIDDLE" not in v


def test_no_baseline_long_body_uses_head_tail_and_sees_the_end():
    v = salient_view(RESULT, None, 600)
    assert len(v) <= 600
    assert "RESULT-ROW-2" in v                     # the end of the page is visible


def test_baseline_diff_surfaces_the_changed_region_at_the_end():
    assert len(RESULT) > 600
    v = salient_view(RESULT, NORMAL, 600)
    assert len(v) <= 600
    assert "RESULT-ROW-1" in v and "RESULT-ROW-2" in v
    assert "changed region" in v
    assert "navigation item 0" not in v            # the unchanged header is not repeated


def test_old_head_slice_would_have_missed_it():
    assert "RESULT-ROW-1" not in RESULT[:600]      # documents the defect being fixed


def test_empty_diff_falls_back_to_head_tail():
    v = salient_view(RESULT, RESULT, 600)
    assert len(v) <= 600 and "chars omitted" in v


def test_single_line_page_falls_back_to_head_tail():
    a = "<html>" + "x" * 5000 + "A-END</html>"
    b = "<html>" + "y" * 5000 + "B-END</html>"
    v = salient_view(a, b, 600)
    assert "chars omitted" in v and v.endswith("A-END</html>")


def test_mostly_changed_diff_falls_back():
    other = "\n".join(f"<p>error line {i}</p>" for i in range(120))
    v = salient_view(RESULT, other, 600)
    assert "chars omitted" in v and "changed region" not in v


def test_budget_is_never_exceeded():
    for budget in (1, 10, 50, 600, 800):
        for base in (None, NORMAL, RESULT):
            assert len(salient_view(RESULT, base, budget)) <= budget


def test_deterministic_and_never_raises():
    assert salient_view(RESULT, NORMAL, 600) == salient_view(RESULT, NORMAL, 600)
    assert salient_view(None, None, 600) == ""
    assert salient_view(12345, None, 3) == "123"
    assert salient_view("abc", None, 0) == ""
    assert salient_view("abc", None, -5) == ""
