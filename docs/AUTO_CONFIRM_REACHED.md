# Spec — Auto-confirm what the model reaches (capability lever #1)

*Written 2026-09-27, from the crAPI #12 investigation. Highest-EV capability uplift on the
board, and it needs no scope change and no model upgrade. Checked against the five safety
invariants; it adds only deterministic confirmation, so none is touched.*

---

## The problem, measured
In a live crAPI run this session the exploit agent hit
`POST /community/api/v2/coupon/validate-coupon` with a NoSQL operator **150 times** and
got the real coupon back (`TRAC075`). Brukal **exploited crAPI #12** — and scored it
**zero**, because recall credits only a *proof-carrying confirmed finding* from a
deterministic differential, and the model's raw curls are not that.

So there is a standing leak: **the model reaches a vulnerable endpoint, but nothing turns
that into a scored, evidence-backed finding.** The deterministic provers exist and work
(`confirm_nosqli`, `confirm_sqli`, `confirm_bola`, `confirm_object_mass_assignment`, …) —
they just are not *pointed at what the model already touched*.

## The idea
When a model command **reaches** an endpoint, **automatically run the matching
deterministic differential on that endpoint** and record the confirmed finding. Turn
"the model did it" into "Brukal proved it." The model becomes a *discovery* engine for the
provers, not the sole path to a finding.

## Where it hooks (exact, verified 2026-09-27)
`AssistSession._absorb_shell` (`brukal/assist_web.py:151`) is the one place every
gate-executed command's output is observed — it already calls `_observe_record(url, body)`
and `_observe_answer(url, status)` (lines ~194–198). Add one call right after those:

```python
# after _observe_record / _observe_answer in _absorb_shell:
try:
    self._auto_confirm_reached(command, raw)   # new: corroborate what the model touched
except Exception:
    pass                                       # instrumentation, never derails a run
```

## What `_auto_confirm_reached(command, raw)` does
1. **Parse the command deterministically** (it is the agent's own text; never eval it):
   pull the URL, HTTP method, and the field/param names from a `curl`/`http`/WEB request —
   query params from the URL, body field names from `-d`/`--data` JSON or form. Reuse the
   existing `_url_in`, the JSON-body parsing in `discover_params`, and `webmap` helpers.
2. **Only act on a real target** — the URL host must be in scope (the gate already proved
   the command was in scope, so this is a cheap re-check), and only when there is a
   field/param to test.
3. **Dispatch to the matching prover(s)**, deduplicated per (url, field, method) so a
   model that spams one endpoint triggers at most one confirmation:
   - a JSON/form body with fields → `confirm_nosqli(url, field)` and
     `confirm_sqli(url, field, method="JSON")` (lookup/validate shape);
   - a query parameter → `confirm_sqli` / `confirm_xss` / the tier battery;
   - an id-addressed URL (`…/{id}`) or object body → `confirm_bola` /
     `confirm_object_mass_assignment`;
   - a URL-valued field → `confirm_ssrf_sinks`' probe.
   Each already records a CONFIRMED finding on success — so a credited challenge falls out
   for free.
4. **Bounded and deduped** — a per-run `_auto_confirmed: set` of (url, field) keys, capped
   (e.g. 24 confirmations/run) so it cannot become unbounded work; honours
   `_confirm_budget` and the rate wall like the surface sweep.

## Why it is safe (the invariant check)
- **No LLM in the gate.** This is pure deterministic dispatch on the model's own command
  text; the gate still rules every confirmation request it issues.
- **One execution path.** Every confirmation goes through `confirm_*` → the governed
  browser → `Executor.run` → the gate, exactly as the surface sweep does. It is handed no
  cage.
- **Fail-closed / no false credit.** It only records what a *differential* confirms
  (benign refused vs operator accepted, etc.) — never "the model got a 200," which is the
  exact over-claim the impact-gate and confirmed-vs-candidate rules exist to prevent.
- **Write-shaped confirmations stay `allow_intrusive`-gated**, as they are today.

## TDD plan
1. **Red→green unit:** feed `_absorb_shell` a crafted model command
   (`curl -X POST …/validate-coupon --data '{"coupon_code":"x"}'`) against a vulnerable
   fake Mongo cage; assert a CONFIRMED "NoSQL injection (operator)" finding is recorded —
   and that it is NOT recorded against a non-vulnerable cage (positive control).
2. **Dedup:** the same command twice → one confirmation, not two.
3. **Safety:** a write-shaped confirmation is skipped when `allow_intrusive` is False; an
   out-of-scope URL in the command is never confirmed (the gate would deny anyway).
4. **Wiring (guards a dead hook):** an integration test driving `_absorb_shell` proves the
   confirmation actually fires — the vault's "wired but never invoked" law.

## How to know it worked (measurement, not feeling)
- **Recreate crAPI fresh** (disposable lab; state from ~10 un-reset runs confounds any
  number), then run **≥3 engagements each** with the reflex off and on.
- Score with `benchmarks/crapi_recall.py` (audited challenge-by-challenge, GAP #23-guarded).
- **Success = the sink family the model reaches (#8/#9/#10/#11/#12) converts from
  MEASURED-NOT-CONFIRMED / REACHED-NOT-PROPOSED to FOUND**, at equal-or-better cost, with
  containment intact (audit chain, 0 out-of-scope) and no new false positives on VAmPI/
  Juice Shop (the precision guard).

## Ship discipline
One milestone, default-off behind a flag first (so the experiment baseline is unchanged
until measured), tests green, committed — then flip to default only after the ≥3×3
measurement shows a real recall gain and no precision regression.
