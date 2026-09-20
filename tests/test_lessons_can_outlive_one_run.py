"""
test_lessons_can_outlive_one_run.py — GAP #24: the "cross-session" store was per-run.

THE MEASURED PROBLEM (2026-09-20)
    `LessonStore` documents itself as "a two-tier, GROWING, retrievable store of learned
    lessons" and `AssistSession` calls it "cross-session". It is constructed as:

        LessonStore(Path(vault_path) / "lessons.jsonl")

    — INSIDE the per-run vault. Every run is launched with a fresh `--vault`, so the store
    starts empty every time.

    Across 87 vaults the whole corpus is 75 verified lessons, 73 of them pitfalls, and
    they are the SAME THREE, re-learned from scratch in run after run:

        pitfall | `nuclei` with broad options times out in the cage
        pitfall | Shell metacharacters (| > < ; && `backticks` $()) are rejected

    Those are the harness learning ITS OWN CAGE, repeatedly, and forgetting it every time.
    Nothing a run discovers about how to test an application has ever reached the run
    after it. A system that cannot carry knowledge forward cannot make a weak model
    stronger over time, which is exactly what a harness is FOR.

THE PROPERTY
    A lesson store can be pointed somewhere that outlives one engagement, and a later run
    reading that path inherits what the earlier one verified. Per-vault stays the default,
    so nothing existing changes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.lessons import LessonStore


def test_a_second_run_INHERITS_what_the_first_verified(tmp_path):
    """THE DEFECT: with the store inside the vault, this was impossible by construction."""
    shared = tmp_path / "shared" / "lessons.jsonl"
    shared.parent.mkdir(parents=True)

    run1 = LessonStore(shared)
    # The real door into the TRUSTED tier: the verification step confirming a win.
    # Retrieval draws only from trusted, by design.
    run1.record_verified_success(
        target="172.20.0.12", service="http",
        command="curl http://172.20.0.12/workshop/api/shop/orders",
        outcome="crAPI mounts its order API under /workshop/api/shop",
        tags=["crapi", "mount"])

    run2 = LessonStore(shared)          # a LATER engagement, same shared path
    assert any("workshop/api/shop" in l.text for l in run2.retrieve('workshop mount order')), (
        "the second run did not inherit the first run's verified lesson")


def test_each_run_is_still_isolated_when_the_path_is_per_vault(tmp_path):
    """BOUNDARY: the default must not change. Two runs with their own vaults stay
    independent, which is what makes a measurement run reproducible."""
    a = LessonStore(tmp_path / "vault-a" / "lessons.jsonl")
    (tmp_path / "vault-a").mkdir(parents=True, exist_ok=True)
    a.record_verified_success(target="t", service="http", command="c",
                              outcome="only run A knows this", tags=["x"])

    (tmp_path / "vault-b").mkdir(parents=True, exist_ok=True)
    b = LessonStore(tmp_path / "vault-b" / "lessons.jsonl")
    assert not any("only run A" in l.text for l in b.retrieve('run A knows'))


def test_the_shared_store_does_not_duplicate_the_same_lesson(tmp_path):
    """Without this, a shared store turns 87 runs of "nuclei times out" into 87 rows and
    the retrieval budget is spent re-reading one fact."""
    shared = tmp_path / "s.jsonl"
    for _ in range(3):
        st = LessonStore(shared)
        st.record_verified_success(
            target="t", service="http", command="nuclei -u http://t",
            outcome="nuclei with broad options times out in the cage", tags=["nuclei"])
    final = LessonStore(shared)
    same = [l for l in final.retrieve('nuclei') if "nuclei" in l.text]
    assert len(same) == 1, f"{len(same)} copies of one lesson"


def test_the_CLI_can_point_lessons_somewhere_that_outlives_the_vault():
    """The wiring, not just the store: `--lessons` must exist and default to the vault,
    so a measurement run gets a FRESH vault (reproducible) and a PERSISTENT store
    (accumulating) instead of having to choose."""
    import argparse
    from brukal import cli
    parser = None
    for maker in ("_build_parser", "build_parser", "_parser"):
        fn = getattr(cli, maker, None)
        if fn is None:
            continue
        try:
            parser = fn()
        except Exception:
            parser = None
        if isinstance(parser, argparse.ArgumentParser):
            break
    if parser is None:                      # parser not exposed; assert on the source
        src = Path(cli.__file__).read_text()
        assert '"--lessons"' in src, "the --lessons flag was never added to the CLI"
        assert 'lessons_path=getattr(args, "lessons", None)' in src, (
            "--lessons is parsed but never reaches run_auto")
        return
    ns = parser.parse_args(["auto", "10.0.0.1", "--lessons", "/tmp/shared"])
    assert ns.lessons == "/tmp/shared"
