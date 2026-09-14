"""
report.py — render a FindingStore + engagement metadata into a deliverable.

Markdown (the human deliverable) and JSON (machine-readable). The report is
deliberately honest about provenance: every finding shows the exact command that
produced it and its real evidence line, confirmed findings are separated from
candidates (heuristic signals a human should verify), and the methodology section
states the governance guarantees (scope-locked, one gate, append-only audit) so a
reader knows the tool could not have strayed off the authorised target.
"""
from __future__ import annotations

import json
import time

from .findings import SEVERITIES, FindingStore

_BADGE = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
          "low": "🔵 LOW", "info": "⚪ INFO"}


def _ts(t=None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def _finding_md(f) -> str:
    from .knowledge import enrich
    kb = enrich(f.title, f.severity)
    cvss = f"CVSS {kb['cvss']:.1f}" + (f" ({kb['vector']})" if kb["cvss"] else "")
    lines = [f"### {_BADGE.get(f.severity, f.severity)} — {f.title}"
             f"{' *(candidate)*' if not f.confirmed else ''}"]
    lines.append(f"- **Severity:** {f.severity.upper()}  ·  **{cvss}**"
                 + (f"  ·  **Category:** {f.category}" if getattr(f, "category", "") else ""))
    lines.append(f"- **Target:** `{f.target or '-'}`"
                 + (f"  ·  **Parameter:** `{f.param}`" if f.param else ""))
    lines.append(f"- **Impact:** {kb['impact']}")
    if f.evidence:
        lines.append(f"- **Evidence:**\n\n  ```\n  {f.evidence.strip()[:500]}\n  ```")
    if f.source:
        lines.append(f"- **Reproduce:** `{f.source}`")
    lines.append(f"- **Remediation:** {kb['remediation']}")
    lines.append(f"- **References:** {', '.join(kb['refs'])}")
    lines.append(f"- **Status:** {'confirmed (evidence-backed)' if f.confirmed else 'candidate — verify manually'}")
    return "\n".join(lines)


def build_report(store: FindingStore, meta: dict) -> str:
    """A Markdown pentest report from the findings + engagement metadata."""
    m = meta or {}
    counts = store.counts()
    total = len(store)
    out = [f"# Brukal Pentest Report — {m.get('target', 'target')}", ""]

    # --- engagement metadata table -------------------------------------------
    rows = [
        ("Engagement", m.get("engagement", "-")),
        ("Target", m.get("target", "-")),
        ("Scope", m.get("scope", "-")),
        ("Cage", m.get("cage", "-")),
        ("Generated", _ts()),
        ("Autonomous steps", str(m.get("steps", "-"))),
        ("Commands executed", str(m.get("executed", "-"))),
        ("Stopped because", m.get("stop_reason", "-")),
        ("Audit chain intact", "✅ yes" if m.get("audit_intact") else "⚠ NOT VERIFIED"),
        ("Model spend", m.get("spend", "-")),
    ]
    out.append("| Field | Value |")
    out.append("|---|---|")
    out += [f"| {k} | {v} |" for k, v in rows]
    out.append("")

    # --- executive summary ----------------------------------------------------
    out.append("## Summary")
    out.append("")
    badges = "  ".join(f"**{counts[s]}** {s}" for s in SEVERITIES if counts[s])
    out.append(f"{total} finding(s): {badges or 'none'}."
               f"  ({len(store.confirmed())} confirmed, {len(store.candidates())} candidate.)")
    # What the findings ADD UP TO, before the list of what they are. A reader deciding
    # how urgent this is needs to know that one flaw alone hands over the application;
    # that sentence cannot be recovered from a severity histogram.
    try:
        from . import chains as _chains
        _composed = _chains.compose(store.confirmed())
        _headline = _chains.summarise(_composed)
        if _headline:
            out.append("")
            out.append(_headline)
    except Exception:
        _composed = []
    out.append("")

    # --- attack chains --------------------------------------------------------
    if _composed:
        try:
            out.append(_chains.render(_composed))
            out.append("")
        except Exception:
            pass

    # A run against a target that fell over produces an empty finding list, which in a
    # report is indistinguishable from a clean one. Say which it was, before the table.
    _health = m.get("target_health") or ""
    if _health.startswith("⚠"):
        out.append(f"> {_health}")
        out.append("")

    # Credentials were supplied and refused. Everything below was therefore measured
    # against the UNAUTHENTICATED surface, which on most applications is the small part
    # — and a reader given a finding list has no way to tell that apart from a clean
    # authenticated assessment. Said before the findings, because it changes how every
    # one of them should be read.
    _login = m.get("login_status") or ()
    if len(_login) >= 2 and _login[0] == "failed":
        out.append(f"> ⚠ AUTHENTICATION FAILED at `{_login[1]}`. The supplied credentials "
                   f"were rejected, so this run assessed only the surface reachable "
                   f"WITHOUT a session. Anything behind the login was not tested, and its "
                   f"absence from this report is not a clean result. Check the username, "
                   f"the field names (`--login-field-user`/`--login-field-pass`) and the "
                   f"login type before treating this as an authenticated assessment.")
        out.append("")

    # --- the experiment funnel, DERIVED FROM THE AUDIT LOG --------------------
    # Not from the notes. Run CM5 rendered `notes[-40:]`, evicted every `[experiment]`
    # line from engagement.md, and left a published funnel resting on lines that were no
    # longer in the bundle. These counts come from `hypothesis.funnel()` over the audit
    # records, so a reader holding the ledger can recompute every one of them.
    _f = m.get("funnel") or {}
    if _f.get("proposed"):
        _xa = _f.get("cross_account") or {}
        out.append("## Model-proposed experiments — the funnel")
        out.append("")
        out.append("| | proposed | dispatched | resolved | judged | confirmed |")
        out.append("|---|---|---|---|---|---|")
        out.append(f"| all | {_f.get('proposed',0)} | {_f.get('dispatched',0)} | "
                   f"{_f.get('resolved',0)} | {_f.get('judged',0)} | "
                   f"{_f.get('confirmed',0)} |")
        out.append(f"| cross-account | {_xa.get('proposed',0)} | "
                   f"{_xa.get('dispatched',0)} | {_xa.get('resolved',0)} | "
                   f"{_xa.get('judged',0)} | {_xa.get('confirmed',0)} |")
        out.append("")
        _refused = _f.get("refused_before_dispatch", 0)
        _unres = _f.get("dispatched_not_resolved", 0)
        _gap = _f.get("unaccounted", 0)
        out.append(f"_{_refused} proposal(s) were refused before dispatch and "
                   f"{_unres} dispatched without both sides answering; neither is a "
                   f"result about the application. "
                   + (f"**{_gap} proposal(s) have no recorded outcome** — the run ended "
                      f"mid-experiment. " if _gap else "")
                   + "Computed from the audit log, not from the engagement notes._")
        out.append("")

    # --- what was assessed ----------------------------------------------------
    # A reader cannot tell an absent finding from an absent CHECK unless the report
    # says which it is. Brukal already insists a rate-limited sweep declare its own
    # incompleteness; reporting the classes that ran clean is the same duty, and it is
    # what turns "no XSS listed" into "XSS was probed and none was found".
    _cov = (m.get("coverage") or [])
    if _cov:
        out.append("## Coverage — what was assessed")
        out.append("")
        out.append("| Class | Probes | Result | Method |")
        out.append("|---|---|---|---|")
        for klass, probes, note, found in _cov:
            verdict = "**finding**" if found else "none found"
            out.append(f"| {klass} | {probes} | {verdict} | {note or '-'} |")
        out.append("")
        out.append("_A class listed here was exercised **against the endpoints in the "
                   "map above** — which is a narrower statement than it looks. An "
                   "endpoint nothing links to, or one the crawl never reached, was not "
                   "probed by any class, so a row reading 'none found' is evidence "
                   "about the mapped surface and not about the application. A class "
                   "absent from this table was not reached at all, and its silence is "
                   "not a clean result either._")
        out.append("")

    # --- findings, ranked -----------------------------------------------------
    confirmed, candidates = store.confirmed(), store.candidates()
    if confirmed:
        out.append("## Confirmed findings")
        out.append("")
        out += [_finding_md(f) + "\n" for f in confirmed]
    if candidates:
        out.append("## Candidate findings (verify manually)")
        out.append("")
        out += [_finding_md(f) + "\n" for f in candidates]
    if total == 0:
        out.append("_No vulnerability signals were flagged in this run._")
        out.append("")

    # --- attack surface -------------------------------------------------------
    if m.get("surface"):
        out.append("## Web attack surface")
        out.append("")
        out.append("```")
        out.append(str(m["surface"]).strip())
        out.append("```")
        out.append("")

    # --- methodology / governance --------------------------------------------
    out.append("## Methodology & governance")
    out.append("")
    out.append(
        "Every command in this engagement was executed through a single deterministic "
        "gate (`Executor.run`): scope was enforced by CIDR/host arithmetic (no LLM in "
        "the gate), out-of-scope actions were denied, irreversible/attack actions were "
        "escalated for human sign-off, and the full action ledger is hash-chained and "
        "tamper-evident. Findings are evidence-backed — each is derived from real "
        "gate-executed output, with the reproducing command shown above.")
    out.append("")
    return "\n".join(out)


def report_json(store: FindingStore, meta: dict) -> dict:
    """Machine-readable report: metadata + counts + every finding."""
    return {
        "meta": {**(meta or {}), "generated": _ts()},
        "counts": store.counts(),
        "total": len(store),
        "findings": [f.to_dict() for f in store.all()],
    }


def write_reports(store: FindingStore, meta: dict, out_dir) -> dict:
    """Write report.md + report.json into out_dir. Returns {fmt: path} for those
    that wrote. Best-effort: an I/O error on one format never aborts the other."""
    from pathlib import Path
    out_dir = Path(out_dir)
    written = {}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        md = out_dir / "report.md"
        md.write_text(build_report(store, meta), encoding="utf-8")
        written["md"] = str(md)
    except OSError:
        pass
    try:
        js = out_dir / "report.json"
        js.write_text(json.dumps(report_json(store, meta), indent=2), encoding="utf-8")
        written["json"] = str(js)
    except OSError:
        pass
    # Interchange formats, so the run lands in whatever the organisation already runs
    # (SARIF is read by GitHub code scanning, GitLab, Azure DevOps, DefectDojo) without
    # anyone writing glue. Best-effort like the rest: a failure here never costs the
    # human report.
    try:
        from . import export
        written.update(export.write(store.all(), out_dir, meta))
    except Exception:
        pass
    return written
