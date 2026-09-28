# NEXT — Brukal improvement queue (read by brukal-improve-loop.sh)

> One fresh session per change. Take the **TOP** item only, ship it as a tested milestone under
> the five invariants, commit, then rewrite this file with the new top item. BUILD + SELF-TEST
> ONLY — never a live pentest, never a real/external target, never a Docker/crAPI/DVWA run,
> never a push. Anything under "HUMAN-GATED" is NOT for the autonomous loop.

## TOP (do this next)
- **`check_web` micro-cleanup** — reuse the `urlsplit(url)` result already computed by `_host_of`
  instead of parsing twice (pure refactor; behavior identical; keep tests green).

## QUEUE (safe, tested, autonomous — promote to TOP when the current one lands)
1. **`gated_by_class` docstring** — clarify that a `None` scope means "unrestricted" (safety comes
   from the web door, not the decorator); wording only, no behavior change.
2. **`FindingStore` dedup + CVSS** — when a finding is re-confirmed with a comparator after an
   earlier un-comparatored sighting, merge in the evidence `cvss`/`cvss_vector`/`cvss_basis` (today
   first-write-wins drops them). Add a test. (Confirm this does not disturb severity/dedup semantics.)

## DONE (most recent first — for the next session's context, not an action item)
- **2026-09-28** `scope._norm_host` now unwraps a bracketed IPv6 `host:port` (`[::1]:8443` → `::1`,
  `[2001:db8::1]:443` → `2001:db8::1`) so authorization and exclusion match a bare-form IPv6; a
  missing closing bracket stays verbatim (denied downstream). Correctness fix — prior behavior failed
  closed. 5 tests, regressions preserved. `e8afb63`.
- **2026-09-28** Report `_finding_md` evidence-CVSS rendering pinned: 3 tests that the finding's own
  `cvss`/`cvss_vector` + "Demonstrated impact:" line render and override the class number, the line
  requires both a score and a basis, and absent an evidence CVSS it falls back to `knowledge.enrich`.
  Test-only. `9bd0997`.
- **2026-09-28** `score_from_vector` now raises `ValueError` on an incomplete CVSS vector instead of
  defaulting missing metrics; docstring corrected. `b6ffd03`.

## HUMAN-GATED — do NOT touch in the autonomous loop
- **SP-C real-internet containment** (scope-aware egress proxy / DNS handling) — changes the
  containment boundary for real external targets; needs explicit maintainer sign-off. Draft:
  the operator's scratch design (sp-c-design-draft).
- **SP-B scope-parser** — being built/merged on branch `sp-b-scope-parser`; leave it to the human.
- **Any live run** against crAPI / DVWA / a real program — requires explicit per-session
  authorization (CLAUDE.md). The loop is build+self-test only.
- **Positive `allowed_paths` scoping** (deferred SP-A decision 2) — a schema/enforcement change;
  fine to *propose* here, but implement only after a human confirms the design.
