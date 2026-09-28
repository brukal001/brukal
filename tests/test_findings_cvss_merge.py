"""
test_findings_cvss_merge.py — evidence CVSS survives dedup when a comparator confirms late.

A finding's evidence CVSS (score + vector + basis) is set only when a comparator graded the
confirmation. A class/config-shaped sighting has none. FindingStore dedupes by
(title, target, param); on a duplicate it used to keep the FIRST record's CVSS, so an
un-comparatored sighting seen first would permanently mask a later comparator-graded score.
_absorb now merges the CVSS triple all-or-nothing: it adopts a later comparator's score
only when the stored finding has none yet, never overwrites an existing one, and never
clears one with a later un-comparatored sighting. Severity/dedup semantics are unchanged.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.findings import Finding, FindingStore

_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
_BASIS = "cross-account order read confirmed via IDOR comparator"

# Same (title, target, param) => same signature => the two records dedupe into one.
def _sighting(severity="medium", **kw):
    return Finding(title="IDOR", severity=severity, target="http://10.10.10.5/o",
                   param="id", **kw)


def test_later_comparator_fills_a_missing_evidence_cvss():
    store = FindingStore()
    store.add(_sighting())                                   # un-comparatored: cvss None
    store.add(_sighting(severity="high", confirmed=True,
                        cvss=9.6, cvss_vector=_VECTOR, cvss_basis=_BASIS))
    assert len(store) == 1                                   # deduped
    f = store.all()[0]
    assert f.cvss == 9.6 and f.cvss_vector == _VECTOR and f.cvss_basis == _BASIS
    assert f.severity == "high"                              # strongest severity kept
    assert f.confirmed is True                               # confirmation grows


def test_existing_evidence_cvss_is_not_overwritten_by_a_second_comparator():
    store = FindingStore()
    store.add(_sighting(confirmed=True, cvss=9.6, cvss_vector=_VECTOR, cvss_basis=_BASIS))
    store.add(_sighting(confirmed=True, cvss=4.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cvss_basis="a weaker second comparator"))
    f = store.all()[0]
    assert f.cvss == 9.6 and f.cvss_vector == _VECTOR and f.cvss_basis == _BASIS


def test_a_later_uncomparatored_sighting_does_not_clear_the_cvss():
    store = FindingStore()
    store.add(_sighting(confirmed=True, cvss=9.6, cvss_vector=_VECTOR, cvss_basis=_BASIS))
    store.add(_sighting())                                   # cvss None arriving second
    f = store.all()[0]
    assert f.cvss == 9.6 and f.cvss_vector == _VECTOR and f.cvss_basis == _BASIS


def test_merge_does_not_disturb_dedup_or_severity():
    store = FindingStore()
    store.add(_sighting(severity="low"))
    store.add(_sighting(severity="critical", confirmed=True,
                        cvss=9.9, cvss_vector=_VECTOR, cvss_basis=_BASIS))
    store.add(_sighting(severity="high"))                    # weaker, still same signature
    assert len(store) == 1
    f = store.all()[0]
    assert f.severity == "critical"                          # strongest wins, unchanged
    assert f.cvss == 9.9


def test_merged_cvss_survives_a_reload():
    tmp = tempfile.mkdtemp()
    try:
        path = Path(tmp) / "findings.jsonl"
        s1 = FindingStore(path)
        s1.add(_sighting())                                  # un-comparatored first
        s1.add(_sighting(confirmed=True, cvss=9.6, cvss_vector=_VECTOR, cvss_basis=_BASIS))
        # Fresh store replays the append-only ledger in write order.
        s2 = FindingStore(path)
        assert len(s2) == 1
        f = s2.all()[0]
        assert f.cvss == 9.6 and f.cvss_vector == _VECTOR and f.cvss_basis == _BASIS
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
