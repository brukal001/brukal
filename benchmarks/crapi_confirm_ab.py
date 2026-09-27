#!/usr/bin/env python3
"""
crapi_confirm_ab.py — isolate ONE deterministic prover's contribution to crAPI recall.

Item F provers carry "no LLM in the decision", so their contribution is measured cleanest
WITHOUT the model: authenticate as principal A, crawl + resolve the surface, run the
deterministic `confirm_surface` sweep, and write the audit ledger the crAPI recall scorer
reads. The A/B is two identical runs of THIS driver differing in one environment bit:

    BRUKAL_SQLI_STATUS=0  python benchmarks/crapi_confirm_ab.py ... --audit runs/..._ctrl.jsonl
    BRUKAL_SQLI_STATUS=1  python benchmarks/crapi_confirm_ab.py ... --audit runs/..._var.jsonl
    python benchmarks/crapi_recall.py runs/..._ctrl.jsonl
    python benchmarks/crapi_recall.py runs/..._var.jsonl

Same crawl, same surface, same budget, same principal — so any recall delta is the prover.
Only ever run against the authorised maintainer-owned crAPI lab; the gate denies all else.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession, _full_send_approver
from brukal.kali import DockerKali
from brukal.web import DockerHttpWebCage, GovernedBrowser, WebAction


class _NullLLM:
    last_stop_reason = "end"

    def propose(self, *a, **k):
        return ""


APPLY_COUPON = "/workshop/api/shop/apply_coupon"


def run(target: str, scope_path: str, cage: str, audit_out: str,
        email: str, password: str) -> dict:
    scope = load_scope(scope_path)
    ap = Path(audit_out)
    if ap.exists():
        ap.unlink()
    audit = AuditLog(ap)
    ex = Executor(Gate(scope), DockerKali(container=cage), audit,
                  approver=_full_send_approver)
    browser = GovernedBrowser(scope, DockerHttpWebCage(container=cage), audit)
    sess = AssistSession(target, ex, StrategistAgent(_NullLLM()), browser=browser)
    sess.allow_intrusive = True
    base = f"http://{target}"

    authed = sess.login(f"{base}/identity/api/auth/login", email, password,
                        user_field="email", login_type="json")

    # Establish the surface the sinks draw from. The SPA mines its API routes from the JS
    # bundle; resolve_mined_routes aligns prefixes (the 2026-09-26 fix that let the coupon
    # sinks reach a POST-only route). Both arms run this identically.
    sess.crawl(seeds=[base + "/"], max_pages=8, max_depth=2)
    try:
        sess.resolve_mined_routes()
    except Exception:
        pass

    routes = set(getattr(sess.surface, "confirmed_routes", []) or []) | \
        set(getattr(sess.surface, "api_routes", []) or [])
    coupon_seen = [r for r in routes if "coupon" in r.lower()]
    # Reach is a precondition, not the claim (prediction 0). If the crawl did not mine the
    # coupon-apply sink, seed it EQUALLY in both arms so the A/B measures the prover, not
    # the crawler — disclosed here and in the ledger.
    seeded = False
    if not any("apply_coupon" in r for r in routes):
        sess.surface.api_routes = list(getattr(sess.surface, "api_routes", []) or []) + [APPLY_COUPON]
        seeded = True
    audit.append("ab_reach_note", {
        "coupon_routes_mined": coupon_seen, "apply_coupon_seeded": seeded,
        "sqli_status_enabled": os.environ.get("BRUKAL_SQLI_STATUS", "1") != "0"})

    n = 0
    try:
        n = sess.confirm_surface()
    except Exception as e:
        print(f"  ! confirm_surface: {e}", file=sys.stderr)

    # Governance, read from the ledger — never a self-report.
    _d, oos = browser.run(WebAction("get", url="http://8.8.8.8/?x=1"))
    out_of_scope_blocked = oos is None
    entries = [json.loads(l) for l in ap.read_text().splitlines() if l.strip()]
    scope_denies = sum(1 for e in entries
                       if e.get("kind", "").endswith("decision")
                       and (e.get("data") or {}).get("verdict") == "DENY"
                       and "scope" in ((e.get("data") or {}).get("layer", "") or ""))
    return {
        "target": target,
        "sqli_status_enabled": os.environ.get("BRUKAL_SQLI_STATUS", "1") != "0",
        "authenticated": authed,
        "confirmed_count": n,
        "coupon_routes_mined": coupon_seen,
        "apply_coupon_seeded": seeded,
        "confirmed_findings_recorded": len(
            [f for f in sess.findings.all() if getattr(f, "confirmed", False)]),
        "out_of_scope_probe_blocked": out_of_scope_blocked,
        "scope_denies_logged": scope_denies,
        "audit_chain_intact": audit.verify(),
        "audit": str(ap),
        "ts": time.time(),
    }


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--cage", required=True)
    p.add_argument("--audit", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--yes-authorised", action="store_true", required=True)
    a = p.parse_args(argv[1:])
    r = run(a.target, a.scope, a.cage, a.audit, a.email, a.password)
    print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
