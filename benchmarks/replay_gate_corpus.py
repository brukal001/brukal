"""
replay_gate_corpus.py — capability/governance regression check for host extraction.

Replays every shell command and session line that historical runs ALLOWed (or a human
approved) — read from the gitignored `runs/**/*.jsonl` ledgers — through the CURRENT
`brukal.hostmatch.extract_hosts` and through the version at a git ref, and reports:

  NEW   hosts the current version extracts that the ref did not and that are not the
        command's own target — each one would now be DENIED: a capability regression
        unless it is a genuine smuggle;
  LOST  hosts the ref extracted that the current version does not — a governance
        regression;
  UNSEEN commands `unseen_targets` (SEC-008) now denies that the ref did not — each a
        capability cost unless it truly picks targets the gate cannot see;
  RISK+ commands whose soft-risk decision got STRICTER (ALLOW->ESCALATE->DENY) — more
        human sign-offs, printed for review (not a failure on its own);
  RISK- commands whose soft-risk decision got LOOSER — a governance regression.

    .venv/bin/python benchmarks/replay_gate_corpus.py [git-ref]   # default: main

Exit 1 if anything is NEW or LOST, except NEW rows reviewed as TRUE positives and
listed in REVIEWED_TRUE_POSITIVES (by the command's sha256 prefix). Offline; reads
ledgers only.
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

# NEW rows a human reviewed and judged CORRECT denials. Both are model commands whose
# shell quoting is broken, so bash really hands the bare words to curl as extra URLs and
# curl resolves/contacts them (on a Docker network a service named `python` resolves):
#   - NoSQL `$where` payload whose inner single quotes close the -d string -> curl gets
#     URLs `nc python3 python wget curl` (crAPI, 2026-09)
#   - SQLi `test' OR '1'='1` inside a single-quoted -d -> curl gets URL `OR`
#     (Juice Shop, 2026-08)
REVIEWED_TRUE_POSITIVES = {"5ff5c05c825b", "4e39d31029cf",
    # SEC-008 unseen targets (2026-10-11 review): nuclei/httpx -l reading a target
    # file the gate cannot check -- incl. model misuse (-l as "templates"/"limit",
    # placeholder /path/to/ files). `-u a,b,c` restates each with checkable targets.
    "0d422fb853ee", "95c386afda6c", "501dac16b6ee", "2f66e5bccc4e", "25c328a7f566", "31aa2d388c02"}
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


def _load_ref(ref: str, module: str = "hostmatch"):
    src = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:brukal/{module}.py"],
                         capture_output=True, text=True, check=True).stdout
    path = Path(tempfile.mkdtemp()) / f"{module}_ref.py"
    path.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(f"{module}_ref", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod       # dataclasses resolve their module via sys.modules
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
    from brukal import risk as cur_risk
    ref = argv[1] if len(argv) > 1 else "main"
    old = _load_ref(ref)
    try:
        old_risk = _load_ref(ref, "risk")
    except Exception as exc:
        # Never silently skip: a comparison that did not run must not read as "0 changed".
        print(f"RISK comparison could NOT run against {ref}: {type(exc).__name__}: {exc}")
        return 2
    rank = {"ALLOW": 0, "ESCALATE": 1, "DENY": 2}
    up_n = down_n = 0
    rows = _corpus()
    new_n = lost_n = unseen_n = 0
    import hashlib
    reviewed = 0
    for cmd, target in rows:
        o, n = set(old.extract_hosts(cmd)), set(cur.extract_hosts(cmd))
        new = sorted(h for h in n - o if not _is_target(h, target))
        if new and hashlib.sha256(cmd.encode()).hexdigest()[:12] in REVIEWED_TRUE_POSITIVES:
            reviewed += 1
            new = []
        lost = sorted(o - n)
        uns_now = cur.unseen_targets(cmd) if hasattr(cur, "unseen_targets") else []
        uns_ref = old.unseen_targets(cmd) if hasattr(old, "unseen_targets") else []
        if uns_now and not uns_ref and \
                hashlib.sha256(cmd.encode()).hexdigest()[:12] in REVIEWED_TRUE_POSITIVES:
            reviewed += 1
        elif uns_now and not uns_ref:
            unseen_n += 1
            print(f"UNSEEN {uns_now}  target={target}  {cmd[:160]!r}")
        if new:
            new_n += 1
            print(f"NEW  {new}  target={target}  {cmd[:160]!r}")
        if old_risk is not None:
            a, b = old_risk.assess(cmd).decision, cur_risk.assess(cmd).decision
            if rank[b] > rank[a]:
                up_n += 1
                print(f"RISK+ {a}->{b}  {cmd[:160]!r}")
            elif rank[b] < rank[a]:
                down_n += 1
                print(f"RISK- {a}->{b}  {cmd[:160]!r}")
        if lost:
            lost_n += 1
            print(f"LOST {lost}  target={target}  {cmd[:160]!r}")
    print(f"{len(rows)} historical commands vs {ref}: {new_n} NEW, {lost_n} LOST, "
          f"{unseen_n} UNSEEN ({reviewed} reviewed true positives); risk: {up_n} stricter, "
          f"{down_n} looser")
    return 1 if (new_n or lost_n or unseen_n or down_n) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
