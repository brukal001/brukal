# SP-A — Rich scope schema + deterministic enforcement (design spec)

**Date:** 2026-09-27
**Status:** design, awaiting review
**Author:** operator + Claude (brainstorming)

---

## 1. Context and intent

Brukal's scope is authored per program (`scope.<program>.json`) and enforced by the
deterministic gate. Today it authorizes by **IP/CIDR + host (incl. `*.wildcard`) + tool
allowlist + rate limit + a per-program comparator allowlist**. That is enough for a
single-host lab (crAPI, DVWA) but not for a real authorized web bug-bounty program, whose
scope is expressed as: in-scope assets (wildcard domains, APIs, mobile apps), **out-of-scope
exclusions** (sibling subdomains and specific paths that override the wildcard), **qualifying
vs non-qualifying vulnerability classes**, and **testing-policy rules** (no automated
scanners, no DoS, no data modification, redact PII).

This spec is **SP-A** of a three-part pipeline agreed with the maintainer:

- **SP-A (this doc)** — the rich scope *schema* and its *deterministic enforcement*.
- **SP-B** — an LLM *scope-parser* that turns a free-text program description into a draft
  `scope.json` + human-readable `scope_rules.md` for **human approval** before freeze.
- **SP-C** — real-internet *containment* (cage egress for real domains / rotating CDN IPs).

Build order A → B → C. A is the target SP-B writes to and the object SP-C protects; A and B
are fully buildable and testable offline before any real target.

### The load-bearing safety reframe (applies to the whole pipeline, enforced by SP-A)

- **The LLM/ML may only DRAFT a scope** (SP-B), at authoring time, on the model side of the
  gate; a **human approves** it before it is `authorized`; the result is **frozen and
  immutable**.
- **No LLM/ML is ever in the runtime deny decision.** Invariant 1 stands: the gate reads a
  frozen deterministic JSON. A malicious or ambiguous program description can only change the
  *draft*; human review + deterministic schema validation + the immutable freeze contain it.
- Enforcement is **default-DENY (allow-list)**, never deny-list: an action is allowed **iff**
  it targets an in-scope asset **AND** its path is not excluded **AND** (prover-side) its bug
  class is allowed and not forbidden. Everything else is denied.

SP-A delivers only the schema + deterministic enforcement. It introduces **no LLM anywhere**
and changes nothing about the audit/executor spine.

## 2. The five invariants (unchanged, checked against this design)

1. **No LLM inside the gate.** SP-A adds only deterministic checks (string/CIDR/path/set
   membership) reading the frozen scope. ✔
2. **Fail-closed.** Empty new fields → today's behavior. Ambiguous/unparseable asset or
   exclusion → treated as *not authorized*. An exclusion always beats an in-scope wildcard. ✔
3. **Never trust an agent's self-report.** The gate keeps re-reading the command/URL itself;
   class selection is *data from the frozen scope*, not inference. ✔
4. **One execution path.** No change to `Executor.run()` / the cage handoff. ✔
5. **Immutable scope, append-only audit.** Scope cannot widen at runtime; new fields are part
   of the frozen `Scope` and its `fingerprint()`. ✔

## 3. Schema changes (`brukal/scope.py`)

Extend the frozen `Scope` dataclass. All new fields default empty/false so existing lab
scopes are byte-identical in behavior.

| Field | Type | Meaning | Enforcement? |
|---|---|---|---|
| `assets` | `tuple[dict]` `{pattern,type,value}` | typed in-scope assets (wildcard/domain/api/android/ios). `pattern` folds into the authorized-host set. | `pattern` yes; `type`/`value` metadata only (CVSS/reward) |
| `exclusions` | `frozenset[str \| {host,path_prefix}]` | out-of-scope hosts/paths; **overrides** an in-scope wildcard | yes |
| `allowed_classes` | `frozenset[str]` | qualifying vuln classes → maps to the existing `comparators` allowlist | yes (prover-side) |
| `forbidden_classes` | `frozenset[str]` | classes never tested even if otherwise active (e.g. DoS) | yes (prover-side, hard-off) |
| `envelope` | `dict` `{no_automated_scanners,no_high_traffic,read_only,pii_redaction}` | testing-policy behavior | yes (wired to existing knobs) |

`assets[].value` (Critical/High/…) and `type` are recorded for the CVSS/reward layer and are
**not** consulted by the gate. `allowed_classes` is a human-friendly synonym that normalizes
into the existing `comparators` allowlist at load time (one canonical allowlist internally).

`fingerprint()` gains the new fields so an audit entry pins exactly which rules authorized a
run and a later scope swap is visible.

## 4. Enforcement

### 4.1 Host + path scope (`brukal/scope.py`, `brukal/gate.py`)
- New `Scope.in_scope(host, path="") -> bool`: `True` iff `(contains_host(host) or
  contains_ip(host))` **AND NOT** `_excluded(host, path)`. Deterministic set/CIDR/prefix
  membership only; no DNS. Fail-closed on empty/unparseable.
- `_excluded(host, path)`: matches `exclusions` — an exact host, a `*.wildcard` host, or a
  `{host, path_prefix}` rule (path compared on a normalized, `/`-boundary prefix so `/blog`
  excludes `/blog` and `/blog/x` but not `/blogger`).
- The gate today calls `self.scope.contains_host(target)` and `contains_host` on every host
  extracted from the command (host-level only). SP-A: where a **web request** is gated, parse
  the URL into `(host, path)` and call `Scope.in_scope(host, path)` so a path exclusion
  denies (`coindcx.com/blog` DENY, `coindcx.com/api` ALLOW) and a sibling subdomain denies
  under a wildcard (`info.coindcx.com` DENY under `*.coindcx.com`). Command-level host
  extraction still runs (no-smuggled-host). The exact hook point (browser request path vs
  `Gate.check`) is pinned in the plan; the rule is: **no web request leaves the cage without
  passing `in_scope(host, path)`.**
- IP/CIDR, no-smuggled-host, tool allowlist, rate limit: unchanged.

### 4.2 Bug-class gating (prover-side; absorbs the approved decorator work)
- A static registry `PROVER_COMPARATORS: dict[str, frozenset[str]]` maps each `confirm_*`
  method → the comparator(s) it can emit.
- A decorator `@gated_by_class` on every `confirm_*`: at entry it computes the active set from
  the frozen scope (`allowed_classes`/`comparators` ∩ closed set, minus `forbidden_classes`)
  and, if none of the prover's comparators are active, **returns `False` before any
  `_probe`/network call**. Because every dispatch path (`confirm_surface`, the sink sweeps,
  `_auto_confirm_reached`, model-driven) calls the `confirm_*` methods, gating at method entry
  covers them all.
- `forbidden_classes` are removed from the active set unconditionally (hard-off), so a
  forbidden class is never tested even if it also appears in the allowlist.
- Reuses `hypothesis.active_comparators(scope)` for the model side (already implemented);
  SP-A extends the *same* active-set computation with `forbidden_classes` and applies it to
  the prover side.

### 4.3 Behavioral envelope (wired to existing knobs)
- `no_automated_scanners` → the aggressive `confirm_surface` breadth sweep is disabled/
  narrowed to targeted, evidence-driven checks, and scanner-class tools drop from the
  effective tool allowlist.
- `no_high_traffic` → `rate_limit_per_min` tightened to a conservative ceiling.
- `read_only` → `destructive_allowed=false` and write-shaped provers stay gated.
- `pii_redaction` → the existing redaction is enforced on recorded evidence.

## 5. Fail-closed semantics (explicit)
- All new fields empty → identical to today (lab scopes unchanged; existing tests green).
- Non-empty `exclusions` → an exclusion match denies even inside an in-scope wildcard.
- Non-empty allowlist → only allowed-class provers run; a prover whose classes are all
  disallowed sends nothing; an **unmapped** prover while an allowlist is active is skipped.
- `forbidden_classes` always wins over `allowed_classes`.
- Ambiguous/unparseable asset or exclusion at load → that entry authorizes nothing (it cannot
  widen scope; at worst it narrows).

## 6. Testing (TDD, offline / fake cage)
1. Exclusion beats wildcard: `*.coindcx.com` authorized, `info.coindcx.com` DENY.
2. Path exclusion: `coindcx.com/blog` DENY, `coindcx.com/api` ALLOW.
3. Allowed-class gating: restricted allowlist → only allowed classes confirm.
4. Forbidden-class never tested: `forbidden_classes={"dos"}` (and a forbidden differential) →
   the prover issues **zero** probes (spy the fake browser), records nothing.
5. Registry completeness: every `confirm_*` in `_ConfirmMixin` is decorated / in the registry
   (introspection) — a future prover cannot silently bypass the allowlist.
6. Envelope: `no_automated_scanners=true` → `confirm_surface` issues no sweep probes;
   `read_only=true` → write-shaped provers gated; `no_high_traffic` tightens the rate.
7. Default-deny: unknown host/path DENY.
8. Backward compat: empty new fields → all provers run, host-level scope as today.
9. Full suite (`python -m pytest`) green.

## 7. Files
- `brukal/scope.py` — new fields, `in_scope`, `_excluded`, `fingerprint` update, load-time
  normalization of `allowed_classes`→`comparators` (fail-closed).
- `brukal/gate.py` — web-request scope check consults `(host, path)` via `in_scope`.
- `brukal/assist_confirm.py` — `PROVER_COMPARATORS` registry, `@gated_by_class`, apply to the
  `confirm_*` methods, envelope wiring.
- `brukal/hypothesis.py` — extend `active_comparators` with `forbidden_classes` (shared).
- `tests/test_scope_rules_enforcement.py` — new.
- No change to `executor.py` / `audit.py` / `kali.py` / the cage.

## 8. Explicitly out of scope for SP-A
- The LLM scope-parser and `scope_rules.md` generation (**SP-B**).
- Real-internet egress / rotating-CDN-IP containment (**SP-C**) — SP-A is validated offline
  and against the existing lab cages; it does not authorize a live non-lab run by itself.
- CVSS/reward mapping from `assets[].value` (the separate, paused evidence-based CVSS work).
- The recall scorer (untouched; realness stays with the differential).

## 9. Open questions for review
1. `allowed_classes` vocabulary: use the human vuln names (sqli, xss, idor, …) normalized to
   comparator names at load, or require raw comparator names in the scope? (Proposed: accept
   human names, normalize deterministically, fail-closed on unknowns.)
2. Path model: exclusions only (deny paths), or also positive `allowed_paths` (scope to
   specific endpoints)? (Proposed: exclusions for SP-A; `allowed_paths` deferred unless a
   program needs it.)
3. Envelope `no_automated_scanners`: narrow the sweep vs disable it entirely? (Proposed:
   narrow to targeted checks; a program that forbids scanners still permits manual-grade
   proofs.)
