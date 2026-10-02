"""I5 - the hash-chained append-only audit ledger must be tamper-evident.

Chains are built through the REAL AuditLog.append(); tampering is done by editing the
JSONL file on disk (what an attacker with file-write access would do). Each tamper test
asserts the SAFE outcome: verify() is False. The intact-chain positive control proves
verify() is not simply always-False.
"""
import json

import pytest

from brukal.audit import AuditLog

N = 5


def _build(tmp_path, n=N):
    log = AuditLog(tmp_path / "audit.jsonl", key=None)
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


@pytest.mark.xfail(strict=True, reason=(
    "FINDING SEC-006: tail truncation not detected by verify(); the surviving prefix is a "
    "self-consistent chain and the head hash is not anchored anywhere external, so deleting "
    "the last k records (e.g. the most recent denial/execution) verifies True; "
    "see SECURITY_AUDIT.md"))
def test_truncate_tail_breaks_verify(tmp_path, record):
    log = _build(tmp_path)
    _write(log, _lines(log)[:-2])
    actual = _verdict(log)
    record("i5::truncate-tail", "audit-integrity", "I5", "drop last 2 records",
           "VERIFY_FAIL", actual, "high")
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
