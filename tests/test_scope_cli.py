"""
test_scope_cli.py — the `brukal scope draft` / `brukal scope approve` commands (SP-B).

No Docker, no LLM/model key, no network: `draft` uses the DeterministicJudge
fallback (TYPESAFE_API_KEY absent by construction in this test run), and `approve`
is pure file I/O. Also proves the wider invariant: an unapproved (authorized:false)
drafted scope is refused by the existing run/authorization path — no new gate is
invented here (spec §2, §7).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.cli import main
from brukal.scope import authorization_record, load_scope

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "coindcx_like_program.md"


def test_scope_draft_writes_json_and_rules_md(tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)   # force the offline fallback
    out = tmp_path / "scope.coindcx.json"
    rules = tmp_path / "scope_rules.md"
    rc = main(["scope", "draft", str(_FIXTURE), "--out", str(out), "--rules", str(rules)])
    assert rc == 0
    assert out.exists() and rules.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["authorized"] is False
    assert data["authorization"] == ""
    assert "_provenance" in data
    assert "_review_items" in data
    assert "REVIEW REQUIRED" in rules.read_text(encoding="utf-8")


def test_scope_draft_json_loads_cleanly_via_sp_a_load_scope(tmp_path, monkeypatch):
    """The drafted JSON must use SP-A's own keys so load_scope can read it without error."""
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = tmp_path / "scope.coindcx.json"
    main(["scope", "draft", str(_FIXTURE), "--out", str(out),
         "--rules", str(tmp_path / "rules.md")])
    scope = load_scope(str(out))
    assert scope.is_authorized() is False
    # exclusions parsed by SP-A cover the ones the description named
    assert "info.coindcx.com" in scope.exclusions or any(
        isinstance(e, tuple) and e[0] == "info.coindcx.com" for e in scope.exclusions)


def test_scope_approve_refuses_while_a_review_item_is_unresolved(tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = tmp_path / "scope.coindcx.json"
    main(["scope", "draft", str(_FIXTURE), "--out", str(out),
         "--rules", str(tmp_path / "rules.md")])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert any(not r.get("resolved") for r in data["_review_items"])   # sanity: fixture has one

    rc = main(["scope", "approve", str(out)])
    assert rc == 2
    data_after = json.loads(out.read_text(encoding="utf-8"))
    assert data_after["authorized"] is False   # refused -> file untouched


def test_scope_approve_succeeds_once_review_items_are_resolved(tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = tmp_path / "scope.coindcx.json"
    main(["scope", "draft", str(_FIXTURE), "--out", str(out),
         "--rules", str(tmp_path / "rules.md")])

    data = json.loads(out.read_text(encoding="utf-8"))
    for r in data["_review_items"]:
        r["resolved"] = True     # simulate the human having read scope_rules.md and signed off
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")

    rc = main(["scope", "approve", str(out), "--as", "the-maintainer"])
    assert rc == 0

    approved = json.loads(out.read_text(encoding="utf-8"))
    assert approved["authorized"] is True
    assert approved["approved_by"] == "the-maintainer"
    assert approved["approved_at"]
    assert "the-maintainer" in approved["authorization"]

    scope = load_scope(str(out))
    assert scope.is_authorized() is True


def test_approved_scope_authorization_record_says_authorized_true(tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = tmp_path / "scope.coindcx.json"
    main(["scope", "draft", str(_FIXTURE), "--out", str(out),
         "--rules", str(tmp_path / "rules.md")])
    data = json.loads(out.read_text(encoding="utf-8"))
    for r in data["_review_items"]:
        r["resolved"] = True
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    main(["scope", "approve", str(out)])

    scope = load_scope(str(out))
    rec = authorization_record(scope, "api.coindcx.com")
    assert rec["authorized"] is True


# --------------------------------------------------------------------------- #
# The invariant: an unapproved (authorized:false) drafted scope is refused by the
# EXISTING run/authorization path — nothing new is invented here.
#
# scope.is_authorized() (brukal/scope.py) is exactly the field
# engagement.enforce_authorization() writes into the audit ledger via
# authorization_record() at the start of every `brukal run` / `brukal solve` /
# `brukal auto` invocation, BEFORE anything else happens. A freshly drafted scope
# — authorization=="" because it has not been through `brukal scope approve` — is
# faithfully marked unauthorized in that very first record.
# --------------------------------------------------------------------------- #

def test_unapproved_draft_is_marked_unauthorized_in_the_run_authorization_record(
        tmp_path, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = tmp_path / "scope.coindcx.json"
    main(["scope", "draft", str(_FIXTURE), "--out", str(out),
         "--rules", str(tmp_path / "rules.md")])

    scope = load_scope(str(out))
    assert scope.is_authorized() is False
    rec = authorization_record(scope, "api.coindcx.com")
    assert rec["authorized"] is False    # the run/authorization path's own receipt


def test_unapproved_draft_scope_refuses_a_live_run(tmp_path, monkeypatch):
    """A drafted (unapproved) scope also fails the ACTUAL `brukal run` entry point:
    it ships with allowlisted_tools=[] and authorized_cidrs=[] (fail-closed
    defaults — SP-B never authorises a tool or an IP by itself), so the deterministic
    gate/entry point refuses before any agent, cage, or network action."""
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    out = tmp_path / "scope.coindcx.json"
    main(["scope", "draft", str(_FIXTURE), "--out", str(out),
         "--rules", str(tmp_path / "rules.md")])

    from brukal import engagement
    rc = engagement.run("api.coindcx.com", fake=True, yes_authorised=True,
                        scope_path=str(out), audit_path=str(tmp_path / "audit.jsonl"),
                        vault_path=str(tmp_path / "vault"))
    assert rc == 2   # refused: not an IP in scope.contains_ip (host-based draft; no CIDRs)
