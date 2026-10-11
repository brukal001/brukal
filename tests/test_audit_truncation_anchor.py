"""
test_audit_truncation_anchor.py — SEC-006 regressions (I5: append-only audit).

SEC-006: deleting the LAST record(s) of a ledger left a self-consistent prefix that
verify() accepted, in keyed mode too — a chain proves each record's predecessor, never
how many records there were. Truncation is only detectable against an anchor held
OUTSIDE the truncated bytes. Three are checked:

  1. the live AuditLog's own memory of what it wrote (catches truncation mid-run);
  2. the `<ledger>.head` sidecar (count + head hash, HMAC'd in keyed mode), written on
     every append — a fresh verifier later still sees it;
  3. an operator-held external anchor (`head()` -> `verify(anchor=...)`), which also
     defeats replaying an OLD keyed sidecar.

Both directions are pinned: every truncation the anchors can see FAILS, and legitimate
use — growth, later sessions appending, crash between line and sidecar, legacy
pre-anchor ledgers — still VERIFIES. The residuals each anchor cannot cover are pinned
too, so they stay documented rather than assumed away.
"""
from __future__ import annotations

import json

import pytest

from brukal.audit import AuditLog, _head_mac

N = 5


@pytest.fixture(autouse=True)
def _no_ambient_key(monkeypatch):
    monkeypatch.delenv("BRUKAL_AUDIT_KEY", raising=False)


def _build(tmp_path, n=N, key=None):
    log = AuditLog(tmp_path / "audit.jsonl", key=key)
    for i in range(n):
        log.append("note", {"step": i})
    return log


def _truncate(log, k):
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text("\n".join(lines[:-k]) + ("\n" if lines[:-k] else ""), encoding="utf-8")


def _head_path(log):
    return log.path.with_name(log.path.name + ".head")


# -------------------------------------------------------------- truncation FAILS ----

@pytest.mark.parametrize("keyed", [False, True], ids=["unkeyed", "keyed"])
@pytest.mark.parametrize("k", [1, 2, N])
def test_truncation_detected_by_live_instance(tmp_path, k, keyed):
    log = _build(tmp_path, key="k" if keyed else None)
    _truncate(log, k)
    assert log.verify() is False


@pytest.mark.parametrize("keyed", [False, True], ids=["unkeyed", "keyed"])
@pytest.mark.parametrize("k", [1, 2])
def test_truncation_detected_by_fresh_verifier_via_sidecar(tmp_path, k, keyed):
    key = "k" if keyed else None
    log = _build(tmp_path, key=key)
    _truncate(log, k)
    assert AuditLog(log.path, key=key).verify() is False


@pytest.mark.parametrize("keyed", [False, True], ids=["unkeyed", "keyed"])
def test_truncation_plus_deleted_sidecar_detected(tmp_path, keyed):
    # The attacker also removes the anchor. Records written by anchoring code are marked,
    # so a marked ledger with no sidecar is itself evidence of tampering.
    key = "k" if keyed else None
    log = _build(tmp_path, key=key)
    _truncate(log, 2)
    _head_path(log).unlink()
    assert AuditLog(log.path, key=key).verify() is False


def test_keyed_sidecar_cannot_be_forged_without_the_key(tmp_path):
    log = _build(tmp_path, key="k")
    _truncate(log, 2)
    recs = [json.loads(x) for x in log.path.read_text().splitlines()]
    forged = {"count": len(recs), "head": recs[-1]["entry_hash"],
              "mac": _head_mac(len(recs), recs[-1]["entry_hash"], None)}   # no key
    _head_path(log).write_text(json.dumps(forged))
    assert AuditLog(log.path, key="k").verify() is False


@pytest.mark.parametrize("bad", ["{not json", "{}", '{"count": "x", "head": "y", "mac": "z"}'])
def test_corrupt_sidecar_fails_closed(tmp_path, bad):
    log = _build(tmp_path)
    _head_path(log).write_text(bad)
    assert AuditLog(log.path).verify() is False


def test_external_anchor_defeats_replay_of_an_old_keyed_sidecar(tmp_path):
    # Residual of the sidecar alone: an attacker who SAVED an earlier, genuinely-MAC'd
    # sidecar can truncate back to it. The operator's external anchor catches that.
    log = _build(tmp_path, n=3, key="k")
    old_sidecar = _head_path(log).read_text()
    log.append("note", {"step": 3})
    log.append("note", {"step": 4})
    anchor = log.head()
    _truncate(log, 2)
    _head_path(log).write_text(old_sidecar)
    fresh = AuditLog(log.path, key="k")
    assert fresh.verify() is True                       # pinned residual: sidecar replay
    assert fresh.verify(anchor=anchor) is False         # external anchor closes it


# ----------------------------------------------------- legitimate use VERIFIES -----

@pytest.mark.parametrize("keyed", [False, True], ids=["unkeyed", "keyed"])
def test_intact_ledger_verifies_live_and_fresh(tmp_path, keyed):
    key = "k" if keyed else None
    log = _build(tmp_path, key=key)
    assert log.verify() is True
    assert AuditLog(log.path, key=key).verify() is True
    assert log.verify(anchor=log.head()) is True


def test_growth_after_anchor_still_verifies(tmp_path):
    log = _build(tmp_path)
    anchor = log.head()
    verifier = AuditLog(log.path)                # opened before more appends
    log.append("note", {"later": 1})
    AuditLog(log.path).append("note", {"later_session": 2})
    assert verifier.verify() is True
    assert log.verify(anchor=anchor) is True
    assert AuditLog(log.path).verify(anchor=anchor) is True


def test_crash_between_line_and_sidecar_still_verifies(tmp_path):
    # The line landed but the sidecar still names the previous head: the ledger is
    # LONGER than the anchor, never shorter — that is not truncation.
    log = _build(tmp_path)
    stale = _head_path(log).read_text()
    log.append("note", {"step": "in-flight"})
    _head_path(log).write_text(stale)
    assert AuditLog(log.path).verify() is True


def test_legacy_ledger_without_anchor_still_verifies(tmp_path):
    # Written before SEC-006: no `v` marker, no sidecar. Must keep verifying.
    from brukal.audit import _GENESIS, _chain
    path = tmp_path / "legacy.jsonl"
    prev, lines = _GENESIS, []
    for i in range(3):
        rec = {"ts": 1.0 + i, "kind": "note", "data": {"i": i}, "prev_hash": prev}
        payload = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        rec["entry_hash"] = prev = _chain(prev, payload, None)
        lines.append(json.dumps(rec, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n")
    assert AuditLog(path).verify() is True


def test_head_reports_count_and_last_hash(tmp_path):
    log = _build(tmp_path, n=3)
    count, head = log.head()
    last = json.loads(log.path.read_text().splitlines()[-1])["entry_hash"]
    assert (count, head) == (3, last)
    assert AuditLog(log.path).head() == (3, last)


def test_malformed_external_anchor_fails_closed(tmp_path):
    log = _build(tmp_path)
    for bad in [(99, "0" * 64), (2, "f" * 64), (-1, "x"), ("3", None)]:
        assert log.verify(anchor=bad) is False, bad


# ---------------------------------------------------------------- the CLI ----------

def test_cli_verify_prints_anchor_and_checks_expect(tmp_path, capsys):
    from brukal.cli import main
    log = _build(tmp_path)
    count, head = log.head()
    assert main(["verify", "--audit", str(log.path)]) == 0
    out = capsys.readouterr().out
    assert f"{count}:{head}" in out
    assert main(["verify", "--audit", str(log.path), "--expect", f"{count}:{head}"]) == 0
    _truncate(log, 1)
    assert main(["verify", "--audit", str(log.path), "--expect", f"{count}:{head}"]) == 1
