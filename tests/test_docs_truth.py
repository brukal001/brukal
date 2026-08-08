"""
test_docs_truth.py — the docs are part of the safety claim, so drift is a test failure.

A security tool whose README oversells its guarantees is a tool whose operator makes
decisions on false information. Three specific drifts were found by inventory on
2026-08-08 and are pinned closed here:

  1. `gate.py`'s own header said the soft risk score and ESCALATE path "are stubbed
     with a clear extension point for milestone 3". They have been fully implemented
     for a long time (`risk.py`), and the gate consumes them.
  2. README sold "Kernel-enforced scope" as an unconditional headline. It is real, but
     it needs host nftables + NET_ADMIN, and without them it degrades to the software
     gate alone.
  3. The documented test count was 40 in CLAUDE.md and 290 in README, against an actual
     suite of several hundred. Two docs disagreeing with each other is drift that no
     reader can resolve.

These are deliberately cheap, textual assertions. They cannot prove the docs are
*true*; they can prove the three known lies stay dead.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "brukal" / "gate.py"
README = ROOT / "README.md"
CLAUDE = ROOT / "CLAUDE.md"


def _head(path: Path, lines: int = 40) -> str:
    return "\n".join(path.read_text(encoding="utf-8").splitlines()[:lines])


def test_gate_header_does_not_claim_the_soft_layer_is_stubbed():
    """The soft risk layer is implemented in risk.py and consumed by Gate.check."""
    header = _head(GATE)
    assert "stubbed" not in header.lower(), (
        "gate.py's header still describes the soft risk layer as stubbed; "
        "it is implemented in risk.py and consumed in Gate.check")


def test_gate_header_points_at_the_real_risk_implementation():
    header = _head(GATE)
    assert "risk.py" in header, (
        "gate.py's header should name risk.py, where the soft layer actually lives")


def test_kernel_enforced_scope_claim_names_its_prerequisites():
    """The claim is true only with host nftables + NET_ADMIN. Without them the cage
    falls back to the software gate, and the operator must be told so where the claim
    is MADE, not 130 lines later."""
    text = README.read_text(encoding="utf-8")
    m = re.search(r"\*\*Kernel-enforced scope[^*]*\*\*(.{0,900})", text, re.S)
    assert m, "the 'Kernel-enforced scope' bullet is gone — update this test"
    claim = m.group(1).lower()
    assert "nftables" in claim
    assert "net_admin" in claim, (
        "the kernel-scope claim must name the NET_ADMIN requirement at the point of "
        "the claim")
    assert any(w in claim for w in ("without", "degrad", "fall back", "falls back")), (
        "the kernel-scope claim must state what happens when the prerequisites are "
        "absent — it degrades to the software gate alone")


def _documented_counts(path: Path) -> set[int]:
    """Every 'N tests' claim in a document."""
    text = path.read_text(encoding="utf-8")
    return {int(n) for n in re.findall(r"(\d{2,5})\s+tests\b", text)}


def test_docs_agree_with_each_other_on_the_test_count():
    """CLAUDE.md said 40 while README said 290. Whatever the number is, the docs must
    not contradict each other — that is drift a reader cannot resolve.

    The absolute number is refreshed by hand when the suite grows; this test only
    enforces internal consistency, which is what actually rotted."""
    counts = _documented_counts(CLAUDE) | _documented_counts(README)
    assert len(counts) <= 1, (
        f"docs disagree on the test count: {sorted(counts)} — "
        f"CLAUDE.md and README must state the same number")
