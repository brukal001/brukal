"""
test_scope_parse.py — SP-B deterministic scaffold (brukal/scope_parse.py) driven end
to end against a CoinDCX-like free-text program description (spec §8), using a
StubJudge (no live TypeSafe call, no network, fully scripted).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.scope_judge import StubJudge
from brukal.scope_parse import (assemble, build_questions, render_rules_md, segment,
                                validate)

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "coindcx_like_program.md"


def _qid(questions: dict, needle: str) -> str:
    """Find the one question whose instructions mention `needle` — robust against
    the exact slugging scheme scope_parse.py happens to use internally."""
    hits = [qid for qid, q in questions.items() if needle in q.get("instructions", "")]
    assert len(hits) == 1, f"expected exactly one question mentioning {needle!r}, got {hits}"
    return hits[0]


def _script_answers(questions: dict) -> dict:
    """A plausible, fully-scripted 'model' response for the CoinDCX-like fixture —
    confident on everything explicit in the text, low-confidence on the one
    deliberately ambiguous row (staging.coindcx.com / severity 'Unclear')."""
    script = {}

    def choice(needle, value, conf=0.95):
        script[_qid(questions, needle)] = {"value": value, "confidence": conf}

    def noul(needle, value, conf=0.95):
        script[_qid(questions, needle)] = {"value": value, "confidence": conf}

    # assets: type + severity, confident for every explicit row
    choice("'coindcx.com'. Table type hint (if any): 'Domain'", "domain")
    choice("'coindcx.com'. Table severity hint (if any): 'High'", "high")
    choice("'*.coindcx.com'. Table type hint (if any): 'Wildcard'", "wildcard")
    choice("'*.coindcx.com'. Table severity hint (if any): 'High'", "high")
    choice("'api.coindcx.com'. Table type hint (if any): 'API'", "api")
    choice("'api.coindcx.com'. Table severity hint (if any): 'Critical'", "critical")
    choice("Android App (com.coindcx.app)'. Table type hint", "android")
    choice("Android App (com.coindcx.app)'. Table severity hint", "high")
    choice("iOS App (id1349116540)'. Table type hint", "ios")
    choice("iOS App (id1349116540)'. Table severity hint", "high")
    # the deliberately ambiguous row: type is still clear, severity is NOT
    choice("'staging.coindcx.com'. Table type hint (if any): 'Domain'", "domain")
    choice("'staging.coindcx.com'. Table severity hint (if any): 'Unclear'", None, conf=0.1)

    # exclusions
    noul("'info.coindcx.com'", True)
    noul("'otcdesk.coindcx.com'", True)
    noul("'careers.coindcx.com'", True)
    noul("'coindcx.com/blog'", True)

    # testing-policy bullets
    noul("no_automated_scanners", True)
    noul("read_only", True)
    noul("pii_redaction", True)
    noul("no_high_traffic", True)

    return script


def test_segment_pulls_expected_spans_from_the_fixture():
    text = _FIXTURE.read_text(encoding="utf-8")
    segs = segment(text)
    labels = [row["cells"][0] if row["cells"] else row["text"] for row in segs.assets]
    assert "*.coindcx.com" in labels
    assert "api.coindcx.com" in labels
    assert any("Android App" in l for l in labels)
    assert any("iOS App" in l for l in labels)
    assert segs.exclusions == [
        "info.coindcx.com", "otcdesk.coindcx.com", "careers.coindcx.com", "coindcx.com/blog"]
    assert "SQL Injection" in segs.allowed_vuln_lines
    assert any("Denial of Service" in l for l in segs.forbidden_vuln_lines)
    assert any("automated scanners" in l for l in segs.policy_lines)


@pytest.fixture()
def coindcx_draft():
    text = _FIXTURE.read_text(encoding="utf-8")
    segs = segment(text)
    questions = build_questions(segs)
    judge = StubJudge(_script_answers(questions))
    answers = judge.ask({"description": text}, questions)
    scope_dict, provenance = assemble(segs, answers)
    clean, review_items = validate(scope_dict)
    return clean, review_items, provenance


def test_coindcx_like_draft_assets_and_exclusions(coindcx_draft):
    clean, review_items, provenance = coindcx_draft
    hosts = set(clean["authorized_hosts"])
    assert {"*.coindcx.com", "api.coindcx.com"} <= hosts

    excl_hosts = {e for e in clean["exclusions"] if isinstance(e, str)}
    excl_pairs = {(e["host"], e["path_prefix"]) for e in clean["exclusions"] if isinstance(e, dict)}
    assert {"info.coindcx.com", "otcdesk.coindcx.com", "careers.coindcx.com"} <= excl_hosts
    assert ("coindcx.com", "/blog") in excl_pairs


def test_coindcx_like_draft_classes_and_envelope(coindcx_draft):
    clean, review_items, provenance = coindcx_draft
    allowed = set(clean["allowed_classes"])
    assert {"sqli", "xss", "rce", "idor", "ssrf", "csrf",
            "open_redirect", "business_logic"} <= allowed
    assert "dos" in set(clean["forbidden_classes"])
    assert {"no_automated_scanners", "read_only"} <= {
        k for k, v in clean["envelope"].items() if v}


def test_coindcx_like_draft_is_unauthorized_with_pending_review(coindcx_draft):
    clean, review_items, provenance = coindcx_draft
    assert clean["authorized"] is False
    assert clean["authorization"] == ""
    unresolved = [r for r in review_items if not r.get("resolved")]
    assert len(unresolved) > 0    # the ambiguous staging.coindcx.com severity, at least
    assert any("staging.coindcx.com" in (r.get("span") or "") for r in unresolved)


def test_render_rules_md_has_review_required_section(coindcx_draft):
    clean, review_items, provenance = coindcx_draft
    md = render_rules_md(clean, provenance, review_items)
    assert "REVIEW REQUIRED" in md
    assert "staging.coindcx.com" in md
    assert "*.coindcx.com" in md
    assert "authorized:` `False`" in md or "`False`" in md


def test_ambiguous_item_never_silently_included(coindcx_draft):
    """The deliberately-ambiguous severity never became a false-confident value in
    the enforced dict — it only shows up as a review item, never invented."""
    clean, review_items, provenance = coindcx_draft
    staging_asset = next(a for a in clean["assets"] if a["pattern"] == "staging.coindcx.com")
    assert staging_asset["value"] is None
    # but the (unambiguous) type still let the host through
    assert "staging.coindcx.com" in clean["authorized_hosts"]


# --------------------------------------------------------------------------- #
# validate() as an independent structural fail-closed pass
# --------------------------------------------------------------------------- #

def test_validate_drops_unparseable_host_pattern():
    scope_dict = {
        "authorized_hosts": ["not a host!!", "good.example.com"],
        "exclusions": [], "allowed_classes": [], "forbidden_classes": [], "envelope": {},
        "_provenance": {
            "h1": {"field": "authorized_hosts", "value": "not a host!!", "span": "x",
                  "engine": "stub", "confidence": 0.99},
            "h2": {"field": "authorized_hosts", "value": "good.example.com", "span": "y",
                  "engine": "stub", "confidence": 0.99},
        },
        "_review_items": [],
    }
    clean, review = validate(scope_dict)
    assert clean["authorized_hosts"] == ["good.example.com"]
    assert any("not a host!!" in (r.get("reason") or "") for r in review)


def test_validate_drops_low_confidence_class():
    scope_dict = {
        "authorized_hosts": [], "exclusions": [],
        "allowed_classes": ["sqli", "xss"], "forbidden_classes": [], "envelope": {},
        "_provenance": {
            "c1": {"field": "allowed_classes", "value": "sqli", "span": "a",
                  "engine": "stub", "confidence": 0.9},
            "c2": {"field": "allowed_classes", "value": "xss", "span": "b",
                  "engine": "stub", "confidence": 0.1},
        },
        "_review_items": [],
    }
    clean, review = validate(scope_dict)
    assert clean["allowed_classes"] == ["sqli"]
    assert any(r["field"] == "allowed_classes" and r.get("span") == "b" for r in review)
    assert any("0.10" in (r.get("reason") or "") for r in review)
