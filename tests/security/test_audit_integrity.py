"""I5 - the hash-chained append-only audit ledger must be tamper-evident.

Chains are built through the REAL AuditLog.append(); tampering is done by editing the
JSONL file on disk (what an attacker with file-write access would do). Each tamper test
asserts the SAFE outcome: verify() is False. The intact-chain positive control proves
verify() is not simply always-False.
"""
import json

import pytest

from brukal.audit import _GENESIS, AuditLog, _hash

N = 5


@pytest.fixture(autouse=True)
def _no_ambient_key(monkeypatch):
    """'Unkeyed' must be genuinely unkeyed even if the developer has the env var set."""
    monkeypatch.delenv("BRUKAL_AUDIT_KEY", raising=False)


def _build(tmp_path, n=N, key=None):
    log = AuditLog(tmp_path / "audit.jsonl", key=key)
    for i in range(n):
        log.append("note", {"step": i, "msg": f"record-{i}"})
    return log


def _lines(log):
    return log.path.read_text(encoding="utf-8").splitlines()


def _write(log, lines):
    log.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _verdict(log):
    return "VERIFY_OK" if log.verify() else "VERIFY_FAIL"


def test_positive_control_intact_chain_verifies(tmp_path, record):
    log = _build(tmp_path)
    assert len(_lines(log)) == N
    actual = _verdict(log)
    record("i5::intact", "audit-integrity", "I5", f"{N} valid records, untouched",
           "VERIFY_OK", actual, "n/a")
    assert actual == "VERIFY_OK"


def test_edited_field_breaks_verify(tmp_path, record):
    log = _build(tmp_path)
    lines = _lines(log)
    rec = json.loads(lines[2])
    rec["data"]["msg"] = "forged"
    lines[2] = json.dumps(rec, separators=(",", ":"))
    _write(log, lines)
    actual = _verdict(log)
    record("i5::edit-middle", "audit-integrity", "I5", "edit data.msg of middle record",
           "VERIFY_FAIL", actual, "high")
    assert not log.verify()


def test_reorder_breaks_verify(tmp_path, record):
    log = _build(tmp_path)
    lines = _lines(log)
    lines[1], lines[2] = lines[2], lines[1]
    _write(log, lines)
    actual = _verdict(log)
    record("i5::reorder", "audit-integrity", "I5", "swap records 1 and 2",
           "VERIFY_FAIL", actual, "high")
    assert not log.verify()


def test_delete_middle_breaks_verify(tmp_path, record):
    log = _build(tmp_path)
    lines = _lines(log)
    del lines[2]
    _write(log, lines)
    actual = _verdict(log)
    record("i5::delete-middle", "audit-integrity", "I5", "delete middle record",
           "VERIFY_FAIL", actual, "high")
    assert not log.verify()


_SEC006 = ("FINDING SEC-006: tail truncation not detected by verify() (GOVERNANCE/integrity, "
           "Medium, needs file-write access). The surviving prefix is a self-consistent chain and "
           "the head hash/count is not anchored externally. Affects KEYED mode too: "
           "BRUKAL_AUDIT_KEY does not help because the attacker deletes, not forges. Contradicts "
           "the audit.py:5-6 docstring claim that removing any past record is detectable by "
           "verify(); see SECURITY_AUDIT.md")


@pytest.mark.xfail(strict=True, reason=_SEC006)
@pytest.mark.parametrize("keyed", [False, True], ids=["unkeyed", "keyed"])
@pytest.mark.parametrize("k", [1, 2])
def test_truncate_tail_breaks_verify(tmp_path, record, k, keyed):
    log = _build(tmp_path, key="k" if keyed else None)
    _write(log, _lines(log)[:-k])
    actual = _verdict(log)
    record(f"i5::truncate-tail-k{k}-{'keyed' if keyed else 'unkeyed'}", "audit-integrity", "I5",
           f"drop last {k} record(s), {'keyed' if keyed else 'unkeyed'} chain",
           "VERIFY_FAIL", actual, "medium")
    assert not log.verify()


def _rechain(log, key_hash, index, mutate):
    """Edit record `index` then recompute every link from there on with `key_hash`."""
    recs = [json.loads(line) for line in _lines(log)]
    mutate(recs[index])
    prev = recs[index]["prev_hash"] if index else _GENESIS
    for r in recs[index:]:
        r["prev_hash"] = prev
        r.pop("entry_hash", None)
        payload = json.dumps(r, sort_keys=True, separators=(",", ":"))
        r["entry_hash"] = key_hash(prev, payload)
        prev = r["entry_hash"]
    _write(log, [json.dumps(r, separators=(",", ":")) for r in recs])


def _forge(r):
    r["data"]["msg"] = "forged"


def test_keyed_positive_control_intact_verifies(tmp_path, record):
    log = _build(tmp_path, key="k")
    actual = _verdict(log)
    record("i5::keyed-intact", "audit-integrity", "I5", "5 valid keyed records, untouched",
           "VERIFY_OK", actual, "n/a")
    assert actual == "VERIFY_OK"


def test_keyed_edit_with_unkeyed_rechain_detected(tmp_path, record):
    """Attacker without the key edits + re-chains with plain SHA-256: keyed verify rejects."""
    log = _build(tmp_path, key="k")
    _rechain(log, _hash, 2, _forge)
    actual = _verdict(log)
    record("i5::keyed-edit-rechain", "audit-integrity", "I5",
           "edit middle record, re-chain with unkeyed _hash, keyed ledger",
           "VERIFY_FAIL", actual, "high")
    assert not log.verify()


def test_keyed_chain_wrong_key_detected(tmp_path, record):
    log = _build(tmp_path, key="k")
    other = AuditLog(log.path, key="not-k")
    actual = _verdict(other)
    record("i5::keyed-wrong-key", "audit-integrity", "I5", "verify keyed chain with different key",
           "VERIFY_FAIL", actual, "high")
    assert not other.verify()


@pytest.mark.xfail(strict=True, reason=(
    "DESIGN-LIMIT (not a SEC finding), documented at audit.py:12-15: an UNKEYED chain can be "
    "edited and fully re-chained by anyone with file-write access and still verifies. Mitigated "
    "by keyed mode (see test_keyed_edit_with_unkeyed_rechain_detected)."))
def test_unkeyed_edit_with_rechain_is_design_limit(tmp_path, record):
    log = _build(tmp_path)
    _rechain(log, _hash, 2, _forge)
    actual = _verdict(log)
    record("i5::unkeyed-edit-rechain-DESIGN-LIMIT", "audit-integrity", "I5",
           "edit middle record + recompute chain with real _hash, unkeyed ledger "
           "(documented limit per audit.py:12-15)", "VERIFY_FAIL", actual, "low")
    assert not log.verify()


@pytest.mark.parametrize("which", [0, 2, N - 1])
@pytest.mark.parametrize("field", ["entry_hash", "prev_hash"])
def test_corrupted_hash_breaks_verify(tmp_path, record, which, field):
    log = _build(tmp_path)
    lines = _lines(log)
    rec = json.loads(lines[which])
    rec[field] = ("f" if rec[field][0] != "f" else "e") + rec[field][1:]
    lines[which] = json.dumps(rec, separators=(",", ":"))
    _write(log, lines)
    actual = _verdict(log)
    record(f"i5::corrupt-{field}-{which}", "audit-integrity", "I5",
           f"flip first hex char of {field} on record {which}", "VERIFY_FAIL", actual, "high")
    assert not log.verify()


def test_edited_kind_and_timestamp_break_verify(tmp_path, record):
    """Every chained field (kind, ts, data) is covered, not only data."""
    for field, val in (("kind", "decision"), ("ts", 1.0)):
        log = _build(tmp_path / field)
        lines = _lines(log)
        rec = json.loads(lines[1])
        rec[field] = val
        lines[1] = json.dumps(rec, separators=(",", ":"))
        _write(log, lines)
        actual = _verdict(log)
        record(f"i5::edit-{field}", "audit-integrity", "I5", f"edit {field}",
               "VERIFY_FAIL", actual, "high")
        assert not log.verify()
