"""
replay_gate_corpus.py — capability/governance regression check for host extraction.

Replays every shell command and session line that historical runs ALLOWed (or a human
approved) — read from the gitignored `runs/**/*.jsonl` ledgers — through the CURRENT
`brukal.hostmatch.extract_hosts` and through the version at a git ref, and reports:

  NEW   hosts the current version extracts that the ref did not and that are not the
        command's own target — each one would now be DENIED: a capability regression
        unless it is a genuine smuggle;
  LOST  hosts the ref extracted that the current version does not — a governance
        regression.

    .venv/bin/python benchmarks/replay_gate_corpus.py [git-ref]   # default: main

Exit 1 if anything is NEW or LOST. Offline; reads ledgers only.
"""
from __future__ import annotations

import glob
import importlib.util
import ipaddress
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _corpus():
    rows = set()
    for f in glob.glob(str(ROOT / "runs" / "**" / "*.jsonl"), recursive=True):
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(r, dict) or r.get("kind") not in ("decision",
                                                                    "session_decision"):
                    continue
                d = r.get("data")
                if not isinstance(d, dict) or d.get("verdict") not in ("ALLOW", "ESCALATE"):
                    continue
                a = d.get("action")
                if isinstance(a, str):
                    rows.add((a, str(d.get("target") or "")))
    return sorted(rows)


def _load_ref(ref: str):
    src = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:brukal/hostmatch.py"],
                         capture_output=True, text=True, check=True).stdout
    path = Path(tempfile.mkdtemp()) / "hostmatch_ref.py"
    path.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("hostmatch_ref", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _is_target(host: str, target: str) -> bool:
    if host == target:
        return True
    try:
        net = ipaddress.ip_network(host, strict=False) if "/" in host else None
    except ValueError:
        return False
    return bool(net) and net.num_addresses == 1 and str(net.network_address) == target


def main(argv: list[str]) -> int:
    from brukal import hostmatch as cur
    ref = argv[1] if len(argv) > 1 else "main"
    old = _load_ref(ref)
    rows = _corpus()
    new_n = lost_n = 0
    for cmd, target in rows:
        o, n = set(old.extract_hosts(cmd)), set(cur.extract_hosts(cmd))
        new = sorted(h for h in n - o if not _is_target(h, target))
        lost = sorted(o - n)
        if new:
            new_n += 1
            print(f"NEW  {new}  target={target}  {cmd[:160]!r}")
        if lost:
            lost_n += 1
            print(f"LOST {lost}  target={target}  {cmd[:160]!r}")
    print(f"{len(rows)} historical commands vs {ref}: {new_n} NEW, {lost_n} LOST")
    return 1 if (new_n or lost_n) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
