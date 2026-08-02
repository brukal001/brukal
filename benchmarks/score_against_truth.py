"""
score_against_truth.py — score a run's findings.json against the known ground truth.

Reads the SAME `GROUND_TRUTH` table the comparative harness uses, so a run scored here
and a run scored there cannot disagree. Eyeballing finding titles is how you end up
reporting "6 findings" as if it were "6 of 7 flaws" — the two are different claims, and
only one of them is about coverage.

    python benchmarks/score_against_truth.py runs/vault/172.20.0.5/findings.json --target vampi

Findings that match nothing in the table are reported separately as `extra`. They are
not padding and not noise: a missing security header is a real finding, it simply is not
one of the seeded flaws the target is scored on. Counting them toward coverage would
inflate the score.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from comparative import GROUND_TRUTH          # noqa: E402  (path set above)


def score(findings, target: str, confirmed_only: bool = True) -> dict:
    truth = GROUND_TRUTH.get(target)
    if truth is None:
        raise SystemExit(f"no ground truth for '{target}'. "
                         f"Known: {', '.join(GROUND_TRUTH)}")
    considered = [f for f in findings
                  if (not confirmed_only) or f.get("confirmed")]
    matched, unmatched_truth = {}, []
    for item in truth:
        rx = re.compile(item["match"], re.I)
        hit = next((f for f in considered
                    if rx.search(f.get("title", "") or "")), None)
        if hit is not None:
            matched[item["id"]] = hit.get("title", "")
        else:
            unmatched_truth.append(item)
    claimed = set(matched.values())
    extra = [f.get("title", "") for f in considered
             if f.get("title", "") not in claimed]
    return {"target": target, "truth_total": len(truth), "found": len(matched),
            "matched": matched, "missed": unmatched_truth, "extra": extra,
            "considered": len(considered)}


def render(r: dict) -> str:
    out = [f"{r['target']}: {r['found']}/{r['truth_total']} ground-truth flaws "
           f"({r['considered']} confirmed finding(s) considered)", ""]
    for item in GROUND_TRUTH[r["target"]]:
        gid = item["id"]
        if gid in r["matched"]:
            out.append(f"  [FOUND]  {gid:28} <- {r['matched'][gid][:48]}")
        else:
            state = " (needs auth state)" if item.get("needs_state") else ""
            out.append(f"  [MISS ]  {gid:28}{state}")
            out.append(f"           how it is verified: {item['how_verified'][:90]}")
    if r["extra"]:
        out += ["", "  real findings, but not among the seeded flaws "
                    "(NOT counted toward coverage):"]
        out += [f"    · {t[:70]}" for t in r["extra"]]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("findings", help="path to a run's findings.json")
    ap.add_argument("--target", default="vampi")
    ap.add_argument("--include-unconfirmed", action="store_true",
                    help="also credit leads that carry no deterministic proof")
    a = ap.parse_args(argv)
    doc = json.loads(Path(a.findings).read_text(encoding="utf-8"))
    r = score(doc.get("findings", []), a.target,
              confirmed_only=not a.include_unconfirmed)
    print(render(r))
    spend = doc.get("spend") or {}
    if spend.get("cost_usd") is not None:
        print(f"\n  spend: {spend.get('calls')} call(s) · "
              f"{spend.get('prompt_tokens', 0):,} prompt / "
              f"{spend.get('output_tokens', 0):,} out · "
              f"${spend['cost_usd']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
