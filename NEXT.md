# NEXT — Brukal improvement queue (read by brukal-improve-loop.sh)

> One fresh session per change. Take the **TOP** item only, ship it as a tested milestone under
> the five invariants, commit, then rewrite this file with the new top item. BUILD + SELF-TEST
> ONLY — never a live pentest, never a real/external target, never a Docker/crAPI/DVWA run,
> never a push. Anything under "HUMAN-GATED" is NOT for the autonomous loop.

## TOP (do this next)
- **_Queue drained 2026-09-28._** No autonomous item is queued. **Refill before the loop can run
  again**: take the top of a fresh `/code-review` pass or a coverage sweep, confirm it is
  build+self-test only (nothing under HUMAN-GATED), and write it here as the new TOP. The loop MUST
  NOT invent scope-relevant work on its own — a human or a review supplies the next item.

## QUEUE (safe, tested, autonomous — promote to TOP when the current one lands)
_(empty — refill from a review or a fresh coverage pass)_

## DONE (most recent first — for the next session's context, not an action item)
- **2026-09-28** `findings.FindingStore._absorb` now merges the evidence CVSS triple
  (`cvss`/`cvss_vector`/`cvss_basis`) all-or-nothing on dedup: a late comparator-graded confirmation
  fills a score an earlier un-comparatored sighting lacked (first-write-wins used to drop it), while
  an existing evidence CVSS is never overwritten or cleared. Severity/dedup untouched. 5 tests incl.
  reload. `c144ea3`.
- **2026-09-28** `bugclass.gated_by_class` docstring clarified: a `None` scope means UNRESTRICTED
  (prover runs), which is not a scope bypass — authorization + host/path scope are enforced at the
  web door (`web.check_web`/the gate) on every request, so this decorator is only a class-selection
  tuner, not a security boundary. Docstring only. `cf8d738`.
- **2026-09-28** `web.check_web` now `urlsplit`s the URL once (scheme/host/path read off one parse)
  instead of three times; `ValueError` fails closed to the identical host-parse denial, so verdict/
  reason/layer are unchanged. Helpers `_scheme_of`/`_host_of` kept (still used at web.py:638). Pure
  refactor, no new test. `13acf81`.
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
