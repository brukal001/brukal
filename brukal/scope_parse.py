"""
scope_parse.py — turns a free-text bug-bounty program description into a draft
`scope.json` (SP-A schema, `authorized:false`) + a human-readable `scope_rules.md`,
per docs/superpowers/specs/2026-09-28-scope-parser-design.md.

Pipeline: segment -> build_questions -> (judge.ask) -> assemble -> validate ->
render_rules_md. Every step is deterministic except the single `judge.ask()` call,
which happens once, model-side, at authoring time (spec §2 invariant) — this module
never talks to a target, never imports gate.py/executor.py/kali.py/audit.py/web.py,
and the scope it writes stays `authorized:false` until a human runs
`brukal scope approve`.

Fail-closed throughout: an item this module cannot classify with reasonable
confidence never widens the drafted scope — it becomes a `review_item`, excluded
from every enforced field, and is only included by an explicit, later human act.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import bugclass

CONFIDENCE_THRESHOLD = 0.6

_ASSET_TYPES = ("wildcard", "domain", "api", "android", "ios")
_ASSET_VALUES = ("low", "medium", "high", "critical")
_WEB_ASSET_TYPES = frozenset({"wildcard", "domain", "api"})
_ENVELOPE_FLAGS = ("no_automated_scanners", "no_high_traffic", "read_only", "pii_redaction")

_HOST_RE = re.compile(
    r"^(\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(\S.*)\s*$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(\S.*)\s*$")
_TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")
_TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:|-]+\|?\s*$")


# --------------------------------------------------------------------------- #
# 1. segment
# --------------------------------------------------------------------------- #

@dataclass
class Segments:
    engagement: str
    assets: list = field(default_factory=list)          # [{"raw","cells"|None,"text"?}]
    exclusions: list = field(default_factory=list)      # [str line]
    allowed_vuln_lines: list = field(default_factory=list)
    forbidden_vuln_lines: list = field(default_factory=list)
    policy_lines: list = field(default_factory=list)
    account_lines: list = field(default_factory=list)


def _classify_heading(text: str) -> str | None:
    t = text.strip().lower()
    if "out of scope" in t or "out-of-scope" in t or "excluded" in t:
        return "exclusions"
    if ("non-qualifying" in t or "non qualifying" in t or "not qualifying" in t
            or "forbidden" in t or "prohibited" in t):
        return "forbidden_vulns"
    if "qualifying" in t or "in-scope vulnerabilit" in t or "in scope vulnerabilit" in t:
        return "allowed_vulns"
    if "test" in t or "rule" in t or "polic" in t or "engagement" in t:
        return "policy"
    if "account" in t or "login" in t or "credential" in t:
        return "accounts"
    if "scope" in t or "asset" in t or "target" in t:
        return "assets"
    return None


def _lines_of(raw_lines: list) -> list:
    out = []
    for ln in raw_lines:
        s = ln.strip()
        if not s:
            continue
        m = _BULLET_RE.match(ln)
        out.append(m.group(1).strip() if m else s)
    return out


def _parse_asset_lines(raw_lines: list) -> list:
    rows: list = []
    i, n = 0, len(raw_lines)
    while i < n:
        ln = raw_lines[i]
        if _TABLE_ROW_RE.match(ln):
            block = []
            while i < n and _TABLE_ROW_RE.match(raw_lines[i]):
                block.append(raw_lines[i])
                i += 1
            start = 0
            if len(block) >= 2 and _TABLE_SEP_RE.match(block[1]):
                start = 2   # header row + its --- separator
            for row in block[start:]:
                if _TABLE_SEP_RE.match(row):
                    continue
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                if cells and cells[0]:
                    rows.append({"raw": row, "cells": cells})
            continue
        m = _BULLET_RE.match(ln)
        if m and ln.strip():
            rows.append({"raw": ln, "cells": None, "text": m.group(1).strip()})
        i += 1
    return rows


def segment(description: str) -> Segments:
    """Pull candidate spans out of free CODE text. Regex/heuristic only — never
    invents a value; a line this can't place under a recognised heading is simply
    not captured (it cannot silently become scope)."""
    lines = description.splitlines()
    engagement = "draft-scope"
    for ln in lines[:15]:
        m = _HEADING_RE.match(ln)
        if m:
            slug = re.sub(r"[^a-z0-9]+", "-", m.group(1).strip().lower()).strip("-")
            engagement = slug or "draft-scope"
            break

    buckets: dict = {"assets": [], "exclusions": [], "allowed_vulns": [],
                     "forbidden_vulns": [], "policy": [], "accounts": []}
    current = None
    for ln in lines:
        m = _HEADING_RE.match(ln)
        if m:
            current = _classify_heading(m.group(1))
            continue
        if current is None or not ln.strip():
            continue
        buckets[current].append(ln)

    return Segments(
        engagement=engagement,
        assets=_parse_asset_lines(buckets["assets"]),
        exclusions=_lines_of(buckets["exclusions"]),
        allowed_vuln_lines=_lines_of(buckets["allowed_vulns"]),
        forbidden_vuln_lines=_lines_of(buckets["forbidden_vulns"]),
        policy_lines=_lines_of(buckets["policy"]),
        account_lines=_lines_of(buckets["accounts"]),
    )


# --------------------------------------------------------------------------- #
# 2. build_questions
# --------------------------------------------------------------------------- #

def _slug(text: str, i: int) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return f"{s or 'item'}_{i}"


def _candidate_flags(line: str) -> list:
    t = line.lower()
    flags = []
    if "automated scan" in t or "automated tool" in t or "scanner" in t:
        flags.append("no_automated_scanners")
    if ("high traffic" in t or "high-traffic" in t or "load test" in t
            or "rate limit" in t or "throttle" in t):
        flags.append("no_high_traffic")
    if ("read-only" in t or "read only" in t or "do not modify" in t
            or "do not delete" in t or "no destructive" in t):
        flags.append("read_only")
    if ("pii" in t or "redact" in t or "personal data" in t
            or "personally identifiable" in t):
        flags.append("pii_redaction")
    if "denial of service" in t or "dos attack" in t or re.search(r"\bdos\b", t):
        flags.append("forbidden_dos")
    return flags


def _asset_label(row: dict) -> str:
    cells = row.get("cells")
    return cells[0] if cells else row.get("text", row["raw"]).strip()


def _asset_hints(row: dict) -> tuple:
    cells = row.get("cells")
    if not cells:
        return "", ""
    type_hint = cells[1] if len(cells) > 1 else ""
    value_hint = cells[2] if len(cells) > 2 else ""
    return type_hint, value_hint


def build_questions(segments: Segments) -> dict:
    """Per candidate: Choice(asset type), Choice(asset value); Noul per
    out-of-scope line; Noul per testing-policy bullet x candidate envelope flag.
    Vuln-class names go through bugclass.normalize_class first (see
    _resolve_vuln_line in assemble()) — a question is only produced for a line
    that fails that deterministic lookup outright."""
    questions: dict = {}

    for i, row in enumerate(segments.assets):
        label = _asset_label(row)
        type_hint, value_hint = _asset_hints(row)
        sid = _slug(label, i)
        questions[f"asset_type_{sid}"] = {
            "type": "choice",
            "instructions": (f"Asset entry: '{label}'. Table type hint (if any): "
                             f"'{type_hint}'. What kind of asset is this?"),
            "criteria": {
                "wildcard": "a wildcard domain such as *.example.com",
                "domain": "a single apex or specific subdomain hostname",
                "api": "an API host/subdomain",
                "android": "an Android application",
                "ios": "an iOS application",
            },
        }
        questions[f"asset_value_{sid}"] = {
            "type": "choice",
            "instructions": (f"Asset entry: '{label}'. Table severity hint (if any): "
                             f"'{value_hint}'. What severity/value tier applies?"),
            "criteria": {
                "low": "low severity / low reward tier",
                "medium": "medium severity / medium reward tier",
                "high": "high severity / high reward tier",
                "critical": "critical severity / top reward tier",
            },
        }

    for i, line in enumerate(segments.exclusions):
        sid = _slug(line, i)
        questions[f"exclusion_{sid}"] = {
            "type": "noul",
            "instructions": (f"Line from the Out-of-Scope section: '{line}'. Is this "
                             "a genuine host or host+path EXCLUSION (a pattern that "
                             "is explicitly out of scope), rather than incidental "
                             "text (a contact address, a general note, etc.)?"),
            "criteria": {
                "true": "the line names a host or host+path that is out of scope",
                "false": "the line is not an exclusion pattern",
            },
        }

    for i, line in enumerate(segments.policy_lines):
        for flag in _candidate_flags(line):
            sid = _slug(line, i)
            questions[f"policy_{flag}_{sid}"] = {
                "type": "noul",
                "instructions": (f"Testing-policy line: '{line}'. Does this line "
                                 f"clearly assert the rule '{flag}' for this "
                                 "engagement?"),
                "criteria": {
                    "true": f"the line clearly asserts '{flag}'",
                    "false": "the line does not clearly assert this, or is unrelated",
                },
            }

    return questions


# --------------------------------------------------------------------------- #
# 3. assemble
# --------------------------------------------------------------------------- #

def _clean_vuln_variants(line: str) -> list:
    variants = [line.strip()]
    no_parens = re.sub(r"\([^)]*\)", " ", line)
    no_parens = re.sub(r"\s+", " ", no_parens).strip()
    if no_parens and no_parens != line.strip():
        variants.append(no_parens)
    no_suffix = re.sub(
        r"\s+(flaws?|issues?|attacks?|errors?|vulnerabilit(?:y|ies))\s*\.?\s*$",
        "", no_parens, flags=re.IGNORECASE).strip()
    if no_suffix and no_suffix not in variants:
        variants.append(no_suffix)
    return variants


def _resolve_vuln_line(line: str, i: int, answers: dict, bucket: str,
                       classes_out: list, provenance: dict, review_items: list) -> None:
    for candidate in _clean_vuln_variants(line):
        canon = bugclass.normalize_class(candidate)
        if canon:
            pid = f"vuln_{bucket}_{_slug(line, i)}"
            provenance[pid] = {"field": f"{bucket}_classes", "value": canon, "span": line,
                               "engine": "deterministic", "confidence": 1.0}
            classes_out.append(canon)
            return
    # deterministic normalization failed outright -> genuinely unclassifiable text.
    # bugclass has no notion of "ask a judge to pick a class from a closed set" in
    # this build; an unresolved class name never invents a comparator (fail-closed).
    pid = f"vuln_{bucket}_{_slug(line, i)}"
    provenance[pid] = {"field": f"{bucket}_classes", "value": None, "span": line,
                       "engine": "deterministic", "confidence": 0.0}
    review_items.append({
        "id": pid, "field": f"{bucket}_classes", "span": line, "engine": "deterministic",
        "confidence": 0.0, "resolved": False,
        "reason": f"unrecognised vulnerability-class name (not in bugclass taxonomy): '{line}'",
    })


def assemble(segments: Segments, answers: dict) -> tuple:
    """Build the SP-A schema dict from segments + judge answers. Best-effort: every
    candidate the judge/deterministic layer positively classified is included here
    with its provenance recorded; validate() is the sole fail-closed filter that
    drops anything unparseable or below the confidence threshold. Nothing here talks
    to a network target."""
    provenance: dict = {}
    review_items: list = []
    hosts: list = []
    assets_meta: list = []
    exclusions: list = []
    allowed_classes: list = []
    forbidden_classes: list = []
    envelope: dict = {}

    # --- assets -------------------------------------------------------------
    for i, row in enumerate(segments.assets):
        label = _asset_label(row)
        sid = _slug(label, i)
        type_ans = answers.get(f"asset_type_{sid}") or {}
        value_ans = answers.get(f"asset_value_{sid}") or {}
        atype = type_ans.get("value")
        aconf = float(type_ans.get("confidence") or 0.0)
        aval = value_ans.get("value")
        vconf = float(value_ans.get("confidence") or 0.0)

        provenance[f"asset_type_{sid}"] = {
            "field": "authorized_hosts", "value": label, "span": label,
            "engine": type_ans.get("engine", "none"), "confidence": aconf if atype in _ASSET_TYPES else 0.0,
        }
        provenance[f"asset_value_{sid}"] = {
            "field": "_asset_value", "value": aval, "span": label,
            "engine": value_ans.get("engine", "none"), "confidence": vconf if aval in _ASSET_VALUES else 0.0,
        }
        assets_meta.append({"pattern": label, "type": atype, "value": aval})
        if atype in _WEB_ASSET_TYPES:
            hosts.append(label)
        elif atype not in ("android", "ios"):
            review_items.append({
                "id": f"asset_type_{sid}", "field": "authorized_hosts", "span": label,
                "engine": type_ans.get("engine", "none"), "confidence": aconf, "resolved": False,
                "reason": f"could not determine asset type for '{label}'",
            })
        if aval not in _ASSET_VALUES:
            review_items.append({
                "id": f"asset_value_{sid}", "field": "_asset_value", "span": label,
                "engine": value_ans.get("engine", "none"), "confidence": vconf, "resolved": False,
                "reason": f"could not determine severity/value tier for '{label}' (metadata only; "
                          "does not affect enforcement)",
            })

    # --- exclusions ----------------------------------------------------------
    for i, line in enumerate(segments.exclusions):
        sid = _slug(line, i)
        pid = f"exclusion_{sid}"
        ans = answers.get(pid) or {}
        accepted = ans.get("value") is True
        conf = float(ans.get("confidence") or 0.0)
        engine = ans.get("engine", "none")
        if "/" in line:
            host, _, rest = line.partition("/")
            value = {"host": host.strip().lower(), "path_prefix": "/" + rest.strip()}
        else:
            value = line.strip().lower()
        if accepted:
            provenance[pid] = {"field": "exclusions", "value": value, "span": line,
                              "engine": engine, "confidence": conf}
            exclusions.append(value)
        else:
            provenance[pid] = {"field": "exclusions", "value": value, "span": line,
                              "engine": engine, "confidence": 0.0}
            review_items.append({
                "id": pid, "field": "exclusions", "span": line, "engine": engine,
                "confidence": conf, "resolved": False,
                "reason": f"not confidently classified as a real exclusion pattern: '{line}'",
            })

    # --- vulnerability classes ------------------------------------------------
    for i, line in enumerate(segments.allowed_vuln_lines):
        _resolve_vuln_line(line, i, answers, "allowed", allowed_classes, provenance, review_items)
    for i, line in enumerate(segments.forbidden_vuln_lines):
        _resolve_vuln_line(line, i, answers, "forbidden", forbidden_classes, provenance, review_items)

    # --- testing-policy bullets -> envelope / forbidden:dos -------------------
    for i, line in enumerate(segments.policy_lines):
        cand = _candidate_flags(line)
        sid = _slug(line, i)
        if not cand:
            review_items.append({
                "id": f"policy_{sid}", "field": None, "span": line, "engine": "none",
                "confidence": 0.0, "resolved": False,
                "reason": f"unclassified testing-policy line: '{line}'",
            })
            continue
        for flag in cand:
            pid = f"policy_{flag}_{sid}"
            ans = answers.get(pid) or {}
            accepted = ans.get("value") is True
            conf = float(ans.get("confidence") or 0.0)
            engine = ans.get("engine", "none")
            target_field = "forbidden_classes" if flag == "forbidden_dos" else "envelope"
            if accepted:
                if flag == "forbidden_dos":
                    forbidden_classes.append("dos")
                    provenance[pid] = {"field": target_field, "value": "dos", "span": line,
                                      "engine": engine, "confidence": conf}
                else:
                    envelope[flag] = True
                    provenance[pid] = {"field": target_field, "value": flag, "span": line,
                                       "engine": engine, "confidence": conf}
            else:
                provenance[pid] = {"field": target_field,
                                   "value": "dos" if flag == "forbidden_dos" else flag,
                                   "span": line, "engine": engine, "confidence": 0.0}
                review_items.append({
                    "id": pid, "field": target_field, "span": line, "engine": engine,
                    "confidence": conf, "resolved": False,
                    "reason": f"not confidently classified as asserting '{flag}': '{line}'",
                })

    scope_dict = {
        "engagement": segments.engagement,
        "authorized_cidrs": [],
        "authorized_hosts": hosts,
        "allowlisted_tools": [],
        "rate_limit_per_min": 10 if envelope.get("no_high_traffic") else 30,
        "exclusions": exclusions,
        "allowed_classes": sorted(set(allowed_classes)),
        "forbidden_classes": sorted(set(forbidden_classes)),
        "envelope": envelope,
        "authorization": "",
        "authorized": False,
        "expires": "",
        "assets": assets_meta,
        "accounts": list(segments.account_lines),
        "_provenance": provenance,
        "_review_items": review_items,
    }
    return scope_dict, provenance


# --------------------------------------------------------------------------- #
# 4. validate
# --------------------------------------------------------------------------- #

def _valid_exclusion_value(value) -> bool:
    if isinstance(value, str):
        return bool(_HOST_RE.match(value))
    if isinstance(value, dict):
        host = str(value.get("host", ""))
        path = str(value.get("path_prefix", ""))
        return bool(_HOST_RE.match(host)) and path.startswith("/")
    return False


def validate(scope_dict: dict) -> tuple:
    """Fail-closed pass over an assembled scope_dict: every asset pattern must
    parse; unknown class names DROP; any low-confidence (< CONFIDENCE_THRESHOLD)
    or unparseable item is a review_item and is EXCLUDED from the enforced field —
    an asset that fails to validate authorizes nothing. Runs entirely off the
    scope_dict's own embedded `_provenance` / `_review_items` — no judge, no
    network, safe to call on a hand-edited file too."""
    provenance = dict(scope_dict.get("_provenance") or {})
    review_items = [dict(r) for r in (scope_dict.get("_review_items") or [])]
    seen_ids = {r["id"] for r in review_items if "id" in r}

    def _flag(pid: str, item: dict, reason: str) -> None:
        if pid in seen_ids:
            return
        review_items.append({
            "id": pid, "field": item.get("field"), "span": item.get("span"),
            "engine": item.get("engine"), "confidence": item.get("confidence"),
            "resolved": False, "reason": reason,
        })
        seen_ids.add(pid)

    clean_hosts = []
    for host in scope_dict.get("authorized_hosts", []):
        pid = next((k for k, v in provenance.items()
                   if v.get("field") == "authorized_hosts" and v.get("value") == host), None)
        prov = provenance.get(pid, {}) if pid else {}
        conf = float(prov.get("confidence") or 0.0)
        if not _HOST_RE.match(host):
            _flag(pid or f"host_{host}", prov, f"asset pattern does not parse as a host: '{host}'")
            continue
        if conf < CONFIDENCE_THRESHOLD:
            _flag(pid or f"host_{host}", prov,
                 f"low-confidence asset type classification for '{host}' ({conf:.2f})")
            continue
        clean_hosts.append(host)

    clean_exclusions = []
    for excl in scope_dict.get("exclusions", []):
        pid = next((k for k, v in provenance.items()
                   if v.get("field") == "exclusions" and v.get("value") == excl), None)
        prov = provenance.get(pid, {}) if pid else {}
        conf = float(prov.get("confidence") or 0.0)
        if not _valid_exclusion_value(excl):
            _flag(pid or f"excl_{excl}", prov, f"exclusion does not parse: '{excl}'")
            continue
        if conf < CONFIDENCE_THRESHOLD:
            _flag(pid or f"excl_{excl}", prov, f"low-confidence exclusion classification ({conf:.2f})")
            continue
        clean_exclusions.append(excl)

    def _clean_classes(key: str) -> list:
        out = []
        for c in scope_dict.get(key, []):
            pid = next((k for k, v in provenance.items()
                       if v.get("field") == key and v.get("value") == c), None)
            prov = provenance.get(pid, {}) if pid else {}
            conf = float(prov.get("confidence") or 0.0)
            canon = bugclass.normalize_class(c) or (c if c in bugclass.CANONICAL else None)
            if canon is None:
                _flag(pid or f"class_{key}_{c}", prov, f"unknown vulnerability class dropped: '{c}'")
                continue
            if conf < CONFIDENCE_THRESHOLD:
                _flag(pid or f"class_{key}_{c}", prov,
                     f"low-confidence class classification for '{c}' ({conf:.2f})")
                continue
            out.append(canon)
        return sorted(set(out))

    clean_envelope = {}
    for flag, val in (scope_dict.get("envelope") or {}).items():
        if flag not in _ENVELOPE_FLAGS or val is not True:
            continue
        pid = next((k for k, v in provenance.items()
                   if v.get("field") == "envelope" and v.get("value") == flag), None)
        prov = provenance.get(pid, {}) if pid else {}
        conf = float(prov.get("confidence") or 0.0)
        if conf < CONFIDENCE_THRESHOLD:
            _flag(pid or f"env_{flag}", prov, f"low-confidence envelope classification for '{flag}' ({conf:.2f})")
            continue
        clean_envelope[flag] = True

    clean_dict = dict(scope_dict)
    clean_dict["authorized_hosts"] = clean_hosts
    clean_dict["exclusions"] = clean_exclusions
    clean_dict["allowed_classes"] = _clean_classes("allowed_classes")
    clean_dict["forbidden_classes"] = _clean_classes("forbidden_classes")
    clean_dict["envelope"] = clean_envelope
    clean_dict["_review_items"] = review_items
    return clean_dict, review_items


# --------------------------------------------------------------------------- #
# 5. render_rules_md
# --------------------------------------------------------------------------- #

def render_rules_md(scope_dict: dict, provenance: dict, review_items: list) -> str:
    lines = [f"# Scope rules — {scope_dict.get('engagement', 'draft-scope')}", ""]
    lines.append(f"**authorized:** `{scope_dict.get('authorized', False)}`  "
                 f"(run `brukal scope approve` after review)")
    lines.append("")

    lines.append("## In-scope assets")
    assets = scope_dict.get("assets") or []
    if assets:
        for a in assets:
            lines.append(f"- `{a.get('pattern')}` — type: {a.get('type') or '?'}, "
                         f"value: {a.get('value') or '?'}")
    else:
        lines.append("- (none identified)")
    lines.append("")

    lines.append("## Authorized hosts (enforced)")
    hosts = scope_dict.get("authorized_hosts") or []
    if hosts:
        for h in hosts:
            lines.append(f"- `{h}`")
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("## Exclusions (enforced, override wildcards)")
    excl = scope_dict.get("exclusions") or []
    if excl:
        for e in excl:
            if isinstance(e, dict):
                lines.append(f"- `{e.get('host')}{e.get('path_prefix')}`")
            else:
                lines.append(f"- `{e}`")
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("## Allowed vulnerability classes")
    lines.append(", ".join(scope_dict.get("allowed_classes") or []) or "(none — all classes active)")
    lines.append("")
    lines.append("## Forbidden vulnerability classes")
    lines.append(", ".join(scope_dict.get("forbidden_classes") or []) or "(none)")
    lines.append("")
    lines.append("## Testing-policy envelope")
    env = scope_dict.get("envelope") or {}
    lines.append(", ".join(k for k, v in env.items() if v) or "(none)")
    lines.append("")

    accounts = scope_dict.get("accounts") or []
    if accounts:
        lines.append("## Account / login notes (informational only)")
        for a in accounts:
            lines.append(f"- {a}")
        lines.append("")

    lines.append("## REVIEW REQUIRED")
    if review_items:
        for r in review_items:
            if r.get("resolved"):
                continue
            conf = r.get("confidence")
            conf_s = f"{conf:.2f}" if isinstance(conf, (int, float)) else "n/a"
            lines.append(f"- **{r.get('field') or '(unclassified)'}** — {r.get('reason')}\n"
                        f"  - span: `{r.get('span')}`\n"
                        f"  - engine: {r.get('engine')}, confidence: {conf_s}\n"
                        f"  - id: `{r.get('id')}`")
    else:
        lines.append("- (none — nothing pending review)")
    lines.append("")

    return "\n".join(lines) + "\n"
