# NEXT — Brukal improvement queue (read by brukal-improve-loop.sh)

> One fresh session per change. Take the **TOP** item only, ship it as a tested milestone under
> the five invariants, commit, then rewrite this file with the new top item. BUILD + SELF-TEST
> ONLY — never a live pentest, never a real/external target, never a Docker/crAPI/DVWA run,
> never a push. Anything under "HUMAN-GATED" is NOT for the autonomous loop.

## TOP (do this next)
- **CVSS `score_from_vector` hardening (Minor, from the SP-A/CVSS reviews).** In `brukal/cvss.py`,
  make `score_from_vector` **reject an incomplete CVSS vector** (missing any of AV/AC/PR/UI/S/C/I/A)
  by raising `ValueError` — instead of defaulting missing metrics (the current asymmetric default is
  safe for C/I/A→0 but the exploitability metrics fail toward most-severe, and the docstring wrongly
  says "worst-case"). Fix the docstring to describe the real behavior. Add tests: a vector missing a
  metric raises; all 24 `COMPARATOR_CVSS` vectors still score unchanged (they are complete). Keep the
  full suite green.

## QUEUE (safe, tested, autonomous — promote to TOP when the current one lands)
1. **Report evidence-CVSS rendering test** — add a test that `report.py`'s `_finding_md` prints the
   finding's own `cvss`/`cvss_vector` + a "Demonstrated impact:" line when present, and falls back to
   the class CVSS otherwise (coverage gap noted in the CVSS review).
2. **`_norm_host` IPv6 port-strip** — in `brukal/scope.py`, handle a bracketed IPv6 `host:port`
   (`[::1]:8443` → `::1`) in `_norm_host` so an IPv6 exclusion with a port matches; add a test. (It
   currently fails *closed* for authorization, so this is a correctness nicety, not a security fix.)
3. **`check_web` micro-cleanup** — reuse the `urlsplit(url)` result already computed by `_host_of`
   instead of parsing twice (pure refactor; behavior identical; keep tests green).
4. **`gated_by_class` docstring** — clarify that a `None` scope means "unrestricted" (safety comes
   from the web door, not the decorator); wording only, no behavior change.
5. **`FindingStore` dedup + CVSS** — when a finding is re-confirmed with a comparator after an
   earlier un-comparatored sighting, merge in the evidence `cvss`/`cvss_vector`/`cvss_basis` (today
   first-write-wins drops them). Add a test. (Confirm this does not disturb severity/dedup semantics.)

## HUMAN-GATED — do NOT touch in the autonomous loop
- **SP-C real-internet containment** (scope-aware egress proxy / DNS handling) — changes the
  containment boundary for real external targets; needs explicit maintainer sign-off. Draft:
  the operator's scratch design (sp-c-design-draft).
- **SP-B scope-parser** — being built/merged on branch `sp-b-scope-parser`; leave it to the human.
- **Any live run** against crAPI / DVWA / a real program — requires explicit per-session
  authorization (CLAUDE.md). The loop is build+self-test only.
- **Positive `allowed_paths` scoping** (deferred SP-A decision 2) — a schema/enforcement change;
  fine to *propose* here, but implement only after a human confirms the design.
