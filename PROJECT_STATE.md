# PROJECT_STATE.md — Brukal standing context

> Purpose: single source of truth for any new chat or Claude Code session. Read this + `docs/HARDENING_ROADMAP.md`
> first, then trust `git log` for the live commit state. This file holds the things that DON'T change often
> (invariants, working rules, phase map, paper criteria). The roadmap holds the live open/closed findings.
> Do NOT trust any `SESSION_HANDOFF.md` — a stale one describes an unrelated DVGA/767-test workstream.

---

## GOAL — what we are building, and what "beating them" means
Brukal is a **governed execution platform for autonomous security testing**: LLM agents reason, plan, and
collaborate to find real vulnerabilities on real targets, while deterministic policy, capability isolation,
sandboxing, evidence verification, and a tamper-evident audit trail constrain what they are actually allowed
to do. Not "an LLM that runs pentest tools" — a system where autonomous agents can hunt, but cannot leave
scope, cannot fake a finding, and cannot act without it being provable.

### We ARE trying to beat XBOW / PentestGPT — on the axes where a solo, governed project can win
This is a real competitive goal, not a consolation lane. Brukal targets a decisive win on:
- **Precision (false-positive rate).** Verified-findings discipline: Brukal structurally refuses unverified
  findings; ungoverned tools hallucinate them. Target: measurably lower FP rate than PentestGPT on the same
  targets. This is a capability metric and it is winnable TODAY.
- **Containment / safety.** Provably stays in scope on a shared network (off-scope host one IP away, dropped
  at the kernel). Neither competitor can be safely pointed at production. Brukal can prove it can.
- **Auditability & reproducibility.** Keyed tamper-evident audit chain; every action provable; runs replayable.
  Competitors do not offer this at all — an uncontested win.
- **Reasoning-heavy bug classes (esp. business logic).** Where the win is methodology + reasoning, not model
  brute force (IDOR/BOLA workflow abuse, auth/authorization chains), Brukal can match or beat general-purpose
  tools on specific targets. This is the capability frontier to push.

### The honest headline
"Governed autonomy beats ungoverned tools on precision, containment, and auditability — at a measured cost in
raw coverage." A paper that shows *fewer bugs, zero false positives, full audit trail, provably contained* is
a STRONGER and more defensible result than a gamed aggregate win, and it quantifies a trade-off nobody else has.

### The one axis we do NOT chase — and why (be explicit so the goal stays honest)
**Aggregate raw bug-count across a broad benchmark.** This is dominated by the underlying model's capability
and inference budget + a mature, team-built exploit arsenal + thousands of tuning iterations — all resource-
bound, and a solo project running affordable models is structurally behind a funded team on frontier models
here. No amount of good harness engineering closes a model-and-money gap. We do not stake the thesis on it,
we do not claim it, and we cite it as a scope limit. (Note: the SAME Brukal harness on a frontier model with
a full budget would find far more — proof the ceiling is model/resources, not Brukal's design. If those
resources ever arrive, this axis reopens.)

### Definition of done for THIS effort
The three PAPER-READY criteria below — NOT the full 56-section product spec (that is a north star; the
enterprise/platform pile is deferred and cited as scope limits, not built). "Beating them" is proven by the
four win-axes above being MEASURED against the competitors on shared targets, not asserted.

---

## What Brukal is
A trust-governed multi-agent LLM penetration-testing system. Paper title: "Trust-Governed Multi-Agent Large
Language Model Penetration Testing with Risk-Constrained Action Gating" (with Dr. Ammar Alazab).
Repo: github.com/sanjaygaire/brukal.

**The contribution is the governance model, not a capability benchmark.** Brukal's differentiator is
*provably-governed, auditable, reproducible* autonomous testing — a lane funded tools (XBOW, PentestGPT,
Strix, PentAGI) do not occupy. The goal is NOT to beat them on raw bug-count (not achievable solo, and not
the point). It is: every finding is real (verified), every action is provable (keyed audit), the agent stays
contained (deterministic scope). Capability results support the governance thesis; they are not the thesis.

---

## The five invariants (never weaken; flag anything that touches them)
1. **No LLM inside the gate** — scope/capability decided by deterministic code.
2. **Fail-closed** — anything ambiguous/unparseable/unloadable is DENIED / exits non-zero.
3. **Never trust an agent's self-report** — the gate re-reads the actual bytes that will execute.
4. **One execution path** — everything runs through `Executor.run()`; no second path, no `--no-gate`.
5. **Immutable scope, append-only tamper-evident audit** (HMAC-keyed when `BRUKAL_AUDIT_KEY` set).

If a proposed change would weaken/route-around any invariant: STOP, write the conflict to the roadmap, do not ship.

---

## Working rules (the discipline that has carried this project)
- **Test-first.** Write the FAILING test before the fix. Confirm it goes red *for the right reason* (not
  vacuously — a guard that passes without the fix protects nothing).
- **Fix the property, not the instance.** No hardcoding the one observed case. The fix must generalise.
  Corollary: find EVERY construction/record/decision site (grep/graphify) — sites hide (the `-n` fix had a
  third; the truncation fix needed a backend-layer fix, not just the loop).
- **Record, don't fix, mid-engagement.** During a live run or setup, findings get written to the roadmap,
  not patched on the spot. Fixes are their own test-first sessions.
- **The check must prove the claim, not a narrower proxy.** (Root of multiple P1s: a banner/probe asserting
  more than it verified.) Every place that prints a guarantee ("locked", "verified", "intact", "SUPPORTED")
  must have a check behind it that validates the FULL claim.
- **Severity tracks blast radius when it fires, not fix size.** A one-line fix that kills engagements is not a P3.
- **Smallest secure change; diff-based; preserve CLI compat; no unrelated refactors.**
- **Secrets never reach the cage.** Provider keys live in the orchestrator env only, never in the container
  env or a mounted path. Audit key persisted outside the repo, mode 600, value out of transcripts.
- **Written rules don't self-enforce.** A SessionStart hook (ponytail) overrode this file's own rule until the
  hook was disabled. Policy must be enforced, not just stated.
- **A control that transforms data must be tested on BOTH sides** — what it writes, and what happens when its
  output is read back. (Redaction was verified for leakage but not for consumption; a `[REDACTED]` placeholder
  was accepted as a real credential until fixed.)
- **A fix for a silent failure must not be able to fail silently itself.** Four instances now, the sharpest
  being `LLMClient.propose`'s thinking-retry: built so "the model had nothing to say" would stop being
  indistinguishable from "it never got to say it", it escalates into an SDK `ValueError` that a bare
  `except Exception: return 0` then erases. Every recovery path needs its own failure recorded on a surface,
  and a bare `except: return <empty>` around an LLM call is a defect on sight.
- **A capability that degrades on rich input is worse than one that never worked** — it passes every small
  test and disappears on exactly the targets worth measuring. Prefer fixtures at production scale; a
  three-route surface proves nothing about a forty-route one.

---

## Phase status
- **Phase 1 — CLOSED.** Truth-in-docs; agent identity binding (orchestrator-attached, not model-supplied);
  enforced per-agent capabilities as a hard-gate AND-condition.
- **Phase 2 Part 1 — CLOSED.** Verify-plane per-action grant (`verification_grant` re-derives the required
  capability from the emitted command's own bytes — no finding-class label; structurally pinned by test).
  Web-plane capability enforcement (`required_capability_for_web`, applied last inside `check_web`).
- **Phase 2 Part 2 (capability, live) — IN PROGRESS.** Cap (HTB) fully exercised; Juice Shop 2B run done.
  **Redaction boundary CLOSED (`66185da`)** — one redactor, eight write sites, per-surface tests green.
  **Business-logic capability now PARTIALLY measured (2026-08-20/21, run 2C2):** the loop plans and works
  the phase, and records the evidence — but the experiment engine that alone may confirm a finding never
  ran, so the capability itself is still unmeasured. Governance measured clean for the second consecutive
  run. See criterion #2 below.

## Deferred (documented, not abandoned — future phases, not paper blockers)
Artifact analysis (pcap/binary fetch+parse — Cap's confirmed missing capability class); enterprise API /
RBAC / multi-tenancy / MCP / tool registry / observability / deployment modes. These are cited as scope
limits in the paper, not fixed before writing.

---

## Live findings — see docs/HARDENING_ROADMAP.md for the authoritative list
**Open at last update (2026-08-21):**
- **P1 — the experiment engine cannot ask on a rich surface (NEW, found in run 2C2; not yet in the roadmap,
  written up only in `docs/CASE_STUDY_JUICESHOP_2C.md`).** `run_hypotheses` calls `propose(max_tokens=8000)`;
  on a rich surface the model spends the whole allowance thinking and returns `""` with
  `stop_reason=max_tokens`. `LLMClient.propose` (`brukal/llm.py:257`) correctly detects that and retries at
  `bigger = min(8000×4, 32_000)` = 32,000 — still **non-streaming** (`_propose_once` → `messages.create`).
  The Anthropic SDK refuses before sending: *"Streaming is required for operations that may take longer than
  10 minutes."* Verified locally against `anthropic 0.116.0` with no API call — 8,000 and 16,000 pass, the
  ceiling is **21,333**, 32,000 always raises (`claude-sonnet-5` is not in `MODEL_NONSTREAMING_TOKENS`, so
  the generic 10-minute estimator applies). `assist.py:3608`'s `except Exception: return 0` then swallows it,
  and REFLEX 0b is `_confirmed_done`-gated to fire once — so one erased error removes model-proposed
  experiments from the **entire** engagement. **Deterministic and worst where it matters most:** it needs a
  rich surface to trigger, so a 3-route fixture succeeds and the real 43-route crawl failed 3/3.
  Fix: stream the retry or cap `bigger` below the ceiling, **and** make the swallow record what it caught.
- **P1 — no second principal on an SPA (pre-existing, independent, newly visible).** `establish_second_identity()`
  returns `""` on Juice Shop: it needs an HTML `<form>` via `_signup_form()`, and an Angular SPA has none, so
  `_register_account()` returns `None`. Without a second principal the **`a_denied_b_allowed` comparator is
  unconstructible**, and every cross-account experiment degrades to self-vs-anonymous. This bites the whole
  SPA class. **Fixing the streaming P1 alone will NOT produce a cross-account result.**
- egress P1 #2 (lock blanket-allows the tunnel interface → doesn't constrain in-tunnel traffic;
  dodged-by-construction on local single-host nets but unfixed for VPN).
- P2s: report self-count vs audit ledger mismatch; pytest writes into live `runs/vault/`; **the suite
  READS a live engagement artifact, so it does not pass on a fresh clone** (`tests/test_coverage.py:78`
  opens `runs/vault-wb/172.20.0.5/findings.json`, which `.gitignore:63` excludes — 964 passed / 1 failed
  in any clone and in CI, at every commit including the pre-existing baseline). The last two are one root
  cause in opposite directions and should be fixed together. **Until then the published suite count is
  reproducible on one machine only, which the reproducibility win-axis does not survive.**

**Closed recently:** egress P1 #1 (fail-open on ruleset-apply failure); loop-truncation P1 (a truncated reply
no longer terminates the loop — keyed on `finish_reason`/stop reason at the backend layer so it holds across
providers); redaction P1 (`66185da`); `-n` third construction site (**CLOSED 2026-08-17** at `loop.py:413` via
`apply_no_resolve()`, deliberately NOT at the executor — rewriting on the execution path would make the gate
audit a different string from the one that runs, trading away invariant 3; coverage bought by a dispatch-point
test instead, and confirmed there is no fourth site); the three 2026-08-16 business-logic plumbing defects
(setup substitution, evidence body, planner coverage floor).

**Truncation caveat for the paper:** runs recorded BEFORE the loop-truncation fix (commit that closed it) may
be truncation-limited — a run that quit mid-reasoning looks identical in the ledger to a considered one. Any
pre-fix step-counts / finding-counts cited in the paper must be re-run on the fixed loop or explicitly caveated.

---

## PAPER-READY criteria (the definition of "confident enough" — do not move these)
Start the paper skeleton NOW in parallel (architecture + threat-model sections are done and won't change).
Trigger the evaluation write-up when ALL three hold:
1. ~~Redaction boundary CLOSED~~ — **MET (`66185da`)**. No session material on any record surface; eight
   write sites, per-surface tests green, 11 of 16 verified red first.
2. ONE clean authenticated capability run where the loop REACHES business logic, nothing leaks, chain keyed
   + intact, containment proven — result publishable whether it finds flaws or not (an honest "governed
   autonomy vs ungoverned tools, trade-off measured" framing, NOT "we beat tool X").
   **NOT MET — and it is no longer "just needs the run".** The three original blockers are long closed:
   truncation (`be94446`), redaction (`66185da`), and the auth-path regression redaction itself introduced
   (`2f3cc51`) — auth attaches for real on both planes and the token stays redacted on every record surface.
   Two runs have since been made against that clean baseline; each one closed the blockers it found and
   uncovered the next layer down. **Met now needs the two P1s above fixed first, then a run.**

   **Two runs made. Neither met it. NOT MET as of 2026-08-21.**

   *Run 2C (2026-08-16)* — four of five conditions held (no leak, chain keyed + intact, containment proven
   against a same-bridge off-scope control, publishable), but it **never reached business logic**. Not a
   reasoning failure: the model proposed the right four IDOR experiments and hit a real negative-quantity
   flaw. Three deterministic harness defects between reasoning and record ate all five results, all closed
   2026-08-17 — `{{setup.*}}` never resolved, a finding-worthy response recorded without its body, and the
   planner silently dropping four methodology phases including business-logic. See
   `docs/HARDENING_ROADMAP.md` → *"the business-logic capability was blocked by plumbing"*.

   *Run 2C2 (2026-08-20/21, `runs/audit_juiceshop2c2.jsonl` + `runs/vault2c2/172.20.0.3/`)* — 50/70 steps,
   `plan_cursor 12/12`, 73 calls, **$3.89**, `stop_reason: target-unhealthy`. Full analysis:
   **`docs/CASE_STUDY_JUICESHOP_2C.md`**.

   | Condition | 2C | 2C2 |
   |---|---|---|
   | Reaches business logic | ✗ never planned | **partial** — planned + worked, nothing confirmable |
   | Nothing leaks | ✓ | ✓ **including the newly-captured bodies** |
   | Chain keyed + intact | ✓ | ✓ |
   | Containment proven | ✓ | ✓ |
   | Publishable either way | ✓ | ✓ |

   **Three of the four fixes are confirmed live in production:** the planner coverage floor (the model
   dropped business-logic a *second* time on a fresh target; the floor appended it as phase 11 and the plan
   was worked to completion), the evidence body (the `PUT /api/BasketItems/1` → 200 record now carries its
   JSON body, on the exact endpoint it was built for), and the `-n` third site (the sweep completed instead
   of dying at the 180 s cap). **The fourth — setup substitution — remains unexercised against a live
   target:** zero experiments dispatched, so the zero literal `{{` and zero `UnresolvedReference` are
   vacuous. Cause is the new P1 above, one layer below the fix.

   **Why it is still NOT MET, precisely:** the acceptance case is met *as plumbing* and not *as a finding* —
   the model sent `quantity: 2`, not `-100`, so the negative-quantity flaw was never re-triggered, and the
   four findings (1 medium, 3 low) contain nothing business-logic. **This is NOT the stop-and-write signal.**
   That signal requires the model to have been asked and to have failed; here it was never asked. A re-run
   that does not first fix both P1s above will reproduce this exact null result, because the failure is
   deterministic on a rich surface.

   **Do not cite from 2C2 without a controlled re-test:** the case study reads three `PUT /api/BasketItems/1`
   → 200 as an unrecognised real cross-user write. The mechanism is plausible (object-level authz missing on
   `BasketItems`) but the tenant mapping was seeded **externally** and appears nowhere in the artifacts, and
   `GET /rest/user/whoami` returned `{"user":{}}` on that path — so the ledger alone cannot say whether the
   write was A-as-A or anonymous. Either reading is interesting; neither is evidenced.

   **STOPPING RULE — written 2026-08-22, before the fix, so it cannot be renegotiated after the result.**
   The next capability run is ONE run.
   - Fails because of a NEW harness defect → **STOP and write.** The capability boundary is then measured
     five layers deep and that is the paper.
   - Fails because of the TARGET (no second principal on an SPA, no confirmable class, target unhealthy)
     → that is a **RESULT, not a blocker.** Write it up as a measured limit. This outcome permits at most
     ONE further fix-and-run cycle, not an open-ended series.
   - Succeeds (loop reaches business logic, the experiment engine is actually **ASKED**, nothing leaks,
     chain keyed + intact, containment proven) → **criterion #2 is MET.**
3. Pre-fix numbers re-read for the truncation bug (re-run or caveat anything cited). **REMAINS.**

Everything else on the roadmap is a cited limitation, not a prerequisite for writing.

---

## Environment quick-reference
- Python is `.venv/bin/python` (Ubuntu has no bare `python`). Tests: `.venv/bin/python -m pytest -q`.
- Cage: Docker, nftables egress lock built at startup from the mounted scope; recon nmap needs `-n` (the lock
  blocks resolvers → 180s timeouts that look like a dead host).
- Local targets: run as a second container on the cage's docker network, scope to its container IP /32.
- **Docker Desktop WSL integration turns itself OFF across restarts** — `docker` then reports *"could not be
  found in this WSL 2 distro"* and there are no containers at all, not even Exited. Check before planning a
  live run. A recreate also means the container IP may change: **re-read it, re-seed both tenants externally,
  re-stamp the scope, and bring the cage up AFTER the scope is set** (the ruleset pins the IP at start).
- Each run gets its own vault root (`runs/vault2c2/<ip>/`, not `runs/vault/`) — find a run's artifacts by
  mtime under `runs/`, not by assuming the default path.
- HTB VPN configs expire; prefer the TCP config on restricted networks (UDP 1337 gets filtered). The cage's
  `docker/vpn/config.ovpn` is renamed `.disabled-for-2b` during local runs — restore it for HTB.
- Token/context economy: use graphify (`graphify extract . --code-only`, then `query`/`path`/`explain`) to
  navigate code instead of reading whole files. Keep `graphify-out/` in `.claudeignore`. Do NOT use the
  docs/PDF semantic pass (it calls an LLM). Do NOT use ponytail (code-minimalism skill — wrong for security
  test-first work).
- Engagement artifacts stay UNCOMMITTED in the working tree (scope file, compose scope-mount edit, disabled
  ovpn, graphify-out) — they are per-engagement state, not project code.
