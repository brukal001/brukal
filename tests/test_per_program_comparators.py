"""
test_per_program_comparators.py — per-program comparator SELECTION (a fail-closed allowlist).

A program may restrict which comparators are active through its scope, to tune Brukal to
its own rules. The restriction is an ALLOWLIST intersected with the closed set — it can
DROP comparators or leave them all on, but it can never WIDEN beyond the trusted set, and
an unknown name never activates. No restriction means all comparators, exactly as before.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import hypothesis as hyp
from brukal.scope import load_scope


def _scope(comparators):
    return types.SimpleNamespace(comparators=frozenset(comparators))


# --------------------------------------------------------------------------- #
# active_comparators — the selection, fail-closed
# --------------------------------------------------------------------------- #

def test_no_scope_means_all_comparators():
    assert hyp.active_comparators() == tuple(sorted(hyp._COMPARATORS))


def test_empty_selection_means_all_comparators():
    assert hyp.active_comparators(_scope([])) == tuple(sorted(hyp._COMPARATORS))


def test_a_restriction_keeps_only_the_named_ones():
    got = hyp.active_comparators(_scope(["status_differs", "cross_account_resource"]))
    assert got == ("cross_account_resource", "status_differs")


def test_an_unknown_name_never_activates():
    got = hyp.active_comparators(_scope(["status_differs", "totally_made_up"]))
    assert got == ("status_differs",)               # the bogus one is dropped, not invented


def test_a_program_can_never_widen_beyond_the_closed_set():
    # Even asking for everything plus extras yields only real comparators.
    got = set(hyp.active_comparators(_scope(list(hyp._COMPARATORS) + ["evil", "rce"])))
    assert got == set(hyp._COMPARATORS)


# --------------------------------------------------------------------------- #
# the prompt menu and parse both respect the selection
# --------------------------------------------------------------------------- #

def test_the_prompt_menu_is_filtered_to_the_active_set():
    active = hyp.active_comparators(_scope(["status_differs", "bodies_differ"]))
    prompt = hyp.experiment_prompt(comparators=", ".join(active))
    assert "status_differs" in prompt and "bodies_differ" in prompt
    assert "cross_account_resource" not in prompt   # disabled for this program


def test_parse_drops_a_comparator_the_program_did_not_enable():
    reply = json.dumps([
        {"title": "enabled one", "severity": "low", "comparator": "status_differs",
         "control": {"url": "http://t/a", "method": "GET"},
         "variant": {"url": "http://t/b", "method": "GET"}},
        {"title": "disabled one", "severity": "high", "comparator": "cross_account_resource",
         "control": {"url": "http://t/a", "method": "GET"},
         "variant": {"url": "http://t/b", "method": "GET"}}])
    drops: list = []
    out = hyp.parse(reply, drops=drops, allowed=("status_differs",))
    assert [h.comparator for h in out] == ["status_differs"]
    assert any(d["reason"] == "comparator_not_enabled_for_program" for d in drops), drops


def test_parse_with_no_allowed_accepts_every_valid_comparator():
    # Backward compatible: allowed=None means the closed set governs, as before.
    reply = json.dumps([
        {"title": "x", "severity": "high", "comparator": "cross_account_resource",
         "control": {"url": "http://t/a", "method": "GET"},
         "variant": {"url": "http://t/b", "method": "GET"}}])
    assert len(hyp.parse(reply)) == 1


# --------------------------------------------------------------------------- #
# scope loads and carries the selection
# --------------------------------------------------------------------------- #

def _write_scope(tmp_path, extra):
    doc = {"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
           "allowlisted_tools": "all"}
    doc.update(extra)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(doc))
    return load_scope(str(p))


def test_load_scope_reads_the_comparators_allowlist(tmp_path):
    s = _write_scope(tmp_path, {"comparators": ["status_differs", "composed", 42, ""]})
    assert s.comparators == frozenset({"status_differs", "composed"})  # non-strings ignored
    assert hyp.active_comparators(s) == ("composed", "status_differs")


def test_load_scope_without_comparators_activates_all(tmp_path):
    s = _write_scope(tmp_path, {})
    assert s.comparators == frozenset()
    assert hyp.active_comparators(s) == tuple(sorted(hyp._COMPARATORS))


def test_with_host_preserves_the_comparators_selection(tmp_path):
    s = _write_scope(tmp_path, {"comparators": ["status_differs"]})
    s2 = s.with_host("nexus.htb")
    assert s2.comparators == frozenset({"status_differs"})
    assert "nexus.htb" in s2.authorized_hosts
