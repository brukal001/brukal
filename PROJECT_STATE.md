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
scope, cannot act without it being provable, and cannot report a finding no evidence supports.

### We ARE trying to beat XBOW / PentestGPT — on the axes where a solo, governed project can win
This is a real competitive goal, not a consolation lane. Brukal targets a decisive win on:
- **Precision (false-positive rate) — MECHANISM ENFORCED, MEASUREMENT PENDING.** Demoted 2026-08-24 from a
  claimed result to a claimed *mechanism*, because the evidence ledger does not yet carry the measurement.
  - **Enforced by construction (`1940f09`):** a finding must be derived from real gate-executed output; a
    fixed comparator — never the model — decides whether it holds; and the published claim is BOUNDED by
    what that comparator can establish, with severity capped by the evidence class and the model's own
    assertion kept beside it as data rather than rendered as the finding.
  - **Measurement PENDING, and it needs a specific run.** An overclaim rate requires a run that publishes
    experiment-path findings *under the claim-bounding regime*. **Run 2C4 published none** — all 9
    experiments died at an unresolved setup reference — so the measurement run has not happened yet.
  - **The one number that exists: overclaim 2 of 3** (`runs/vault-preflight2/172.20.0.3/findings.jsonl`;
    agent HIGH/HIGH/MEDIUM → derived LOW/LOW/LOW, all three downgraded). **n=3, a single pre-flight, not a
    rate.** It must be reported as one data point and never as "the overclaim rate is 67%".
  - **What is NOT assertable:** "no false positive was ever published". One class of manufactured
    confirmation was open until 2026-08-22 — a control naming a second principal that did not exist resolved
    silently to `anonymous` — found by adversarial testing, not by any run; an exhaustive sweep of ~87 vault
    roots shows **it never fired in a real engagement** (`c829482`), **though that sweep itself returned five
    CANNOT-TELL runs whose principal provenance is permanently unrecoverable.** Separately, five
    `bodies_differ` findings were published with cross-account titles their comparator did not earn, and
    whether those underlying claims are true was never independently verified. See roadmap → *"'no false
    positive' is not assertable today"*.
  - Target: measurably lower FP rate than PentestGPT on the same targets — winnable, and to be MEASURED,
    not asserted.
- **Containment / safety.** Provably stays in scope on a shared network (off-scope host one IP away, dropped
  at the kernel). Neither competitor can be safely pointed at production. Brukal can prove it can.
- **Auditability & reproducibility.** Keyed tamper-evident audit chain; every action provable; runs replayable.
  Competitors do not offer this at all — an uncontested win.
- **Reasoning-heavy bug classes (esp. business logic).** Where the win is methodology + reasoning, not model
  brute force (IDOR/BOLA workflow abuse, auth/authorization chains), Brukal can match or beat general-purpose
  tools on specific targets. This is the capability frontier to push.

### The honest headline
"Governed autonomy beats ungoverned tools on precision, containment, and auditability — at a measured cost in
raw coverage." A paper that shows *fewer bugs, every finding evidence-backed, full audit trail, provably
contained* is a STRONGER and more defensible result than a gamed aggregate win, and it quantifies a trade-off
nobody else has. **Say "no false positive in N runs, here is the ledger", never "zero false positives" as a
property** — the latter is a claim about all possible runs, it was briefly untrue (see the precision axis
above), and the paper does not need it.

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
the point). It is: every published finding is evidence-backed and comparator-judged, every action is
provable (keyed audit), the agent stays contained (deterministic scope). Capability results support the
governance thesis; they are not the thesis. **The honest form of the precision claim is a process claim plus
its audit trail — including the fabrication path found and closed on 2026-08-22 — not a proof of zero false
positives.**

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
- **A missing capability must never resolve to a weaker one that happens to typecheck.** `as: second` with no
  second account resolved to empty cookies — which is not "no principal", it is *exactly* `anonymous`, so the
  request went out and got scored. Absent must raise, not degrade: whenever code picks one of a closed set of
  principals, keys, scopes or credentials, the unavailable case gets its own named exception, never the
  emptiest member of the set. **Trace the degradation in code before writing it up** — this one had been
  recorded twice as "would collapse to self-vs-anonymous" when it was in fact dispatching, being judged, and
  in one arrangement manufacturing a CONFIRMED finding.

---

## Phase status
- **Phase 1 — CLOSED.** Truth-in-docs; agent identity binding (orchestrator-attached, not model-supplied);
  enforced per-agent capabilities as a hard-gate AND-condition.
- **Phase 2 Part 1 — CLOSED.** Verify-plane per-action grant (`verification_grant` re-derives the required
  capability from the emitted command's own bytes — no finding-class label; structurally pinned by test).
  Web-plane capability enforcement (`required_capability_for_web`, applied last inside `check_web`).
- **Phase 2 Part 2 (capability, live) — IN PROGRESS.** Cap (HTB) fully exercised; Juice Shop 2B run done.
  **Redaction boundary CLOSED (`60b47e6`)** — one redactor, eight write sites, per-surface tests green.
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
- ~~**P1 — the experiment engine cannot ask on a rich surface**~~ — **CLOSED 2026-08-22 (`86fd6c7`,
  `31cf515`).** The thinking-retry escalated to 32,000 tokens non-streaming and the SDK refused before
  sending (ceiling ~21,333, model-dependent); `assist.py`'s `except Exception: return 0` then erased the
  error, and REFLEX 0b fires once, so one silence cost a whole engagement its experiments. The retry now
  **streams** — deliberately not capped, since that ceiling is derived from the model and a ten-minute
  estimate and a number chosen to dodge it rots when either moves — and both swallows on that call path
  (`run_hypotheses` and its sibling in `loop.py`) now record what they caught. Roadmap → *"the experiment
  engine never got to ask"* §A.
- **P1 — no second principal on an SPA — FALSE-NEGATIVE PATH CLOSED 2026-08-22 (`c829482`); CAPABILITY GAP
  CLOSED for JSON-signup targets 2026-08-22 (`8c4f941`), STILL OPEN where neither door exists.**
  - **Fail-safe (closed):** `_as_identity` resolved a missing second identity to empty cookies and an empty
    auth header — *byte-identical to the `anonymous` branch* — so `as: second` was dispatched and judged as a
    stranger. Both directions were wrong; the inverted one **manufactured a CONFIRMED high** (test was red
    with `assert 1 == 0`). Now raises `SecondPrincipalUnavailable`: not dispatched, not judged.
  - **Capability (closed for this shape):** an SPA serves no `<form>`, so the form path could never work
    there. `_register_account_json` posts a JSON signup endpoint **drawn from the crawl and filtered by the
    `_JSON_SIGNUP_PATHS` allowlist**, through the governed browser, gated and audited. Confirmed live on
    Juice Shop: 0 `<form>` tags anywhere, `POST /api/Users {"email","password"}` → 201, second principal
    `brk53d8b8cb25@brukal.test` established, two distinct handles in the ledger
    (`[REDACTED:cd432603]` vs `[REDACTED:fc477483]`), zero cleartext tokens on any artifact.
    **The cross-account class is now reachable on the criterion-#2 target.**
  - **Two defects only the live run exposed:** the second principal's credential was **never registered with
    `redact` on either path** (pre-existing; would have shipped with the form path forever), and a JSON signup
    authenticates by **email** while `login`'s default field is `username` — registration returned 201 and the
    login after it 401'd, which in the ledger is indistinguishable from a target that refuses registration.
  - **Still open:** a target with **neither** a server-rendered form nor a JSON signup endpoint. No third
    door; the fail-safe stands and cross-account is recorded **NOT RUN** — cite as a scope limit, never as a
    negative result.
- ~~**P1 — a confirmed finding carried a claim its comparator did not earn**~~ — **CLOSED 2026-08-23
  (`1940f09`).** The 2C3 pre-flight published two HIGH cross-account IDORs from `bodies_differ` with **one
  principal on both sides** (six `experiment_principal` records, all `self`). **The verdicts were sound; the
  titles were not** — `title` and `severity` were passed to `Finding(...)` verbatim off the model's proposal.
  `hypothesis._EVIDENCE_CLASS` now bounds each comparator's strongest claim and caps severity;
  `derive_claim()` is a pure function of the comparator and the two resolved principals — **invariant 1
  applied to the record, not the gate.** A bound, not a filter: `a_denied_b_allowed` with two distinct
  principals keeps the full authorization claim. The model's reasoning survives labelled UNVERIFIED; its
  title does not. **⚠ The two pre-flight findings must NOT be cited in their current wording** — under the
  derived contract they publish as LOW "observed difference, same principal"; if the IDOR is real it must be
  re-proved with two principals.
- **FOURTH false-result class this week, none found by a run:** `a8410a5` (our rate limiter contaminates the
  detector measuring the target's — OPEN); `c829482` (missing principal became
  anonymous), `2fdbc7f` (ledger did not record which principal), `1940f09` (unearned claim). All three
  surfaced from auditing artifacts afterwards. Worth stating in the paper as-is.
- **P3 — the login path costs 30–58% of the web budget** (recorded 2026-08-22, NOT fixed). `JsonAuth`
  issues a seeding GET before every login POST; Juice Shop's login is POST-only and 500s the GET, so half of
  every attempt is wasted, and ~5 detectors each call `login()`. Invisible at 2–6 req/min (2C, 2C2), fatal at
  37.5 req/min (pre-flight): 26 rate denials, **including the second principal's registration POST** — a P3
  efficiency issue directly caused the P1 evidence problem above. Limit is `rate_limit_per_min` (default 30),
  a sliding 60s window per browser.
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
providers); redaction P1 (`60b47e6`); `-n` third construction site (**CLOSED 2026-08-17** at `loop.py:413` via
`apply_no_resolve()`, deliberately NOT at the executor — rewriting on the execution path would make the gate
audit a different string from the one that runs, trading away invariant 3; coverage bought by a dispatch-point
test instead, and confirmed there is no fourth site); the three 2026-08-16 business-logic plumbing defects
(setup substitution, evidence body, planner coverage floor).

**Truncation caveat for the paper:** runs recorded BEFORE the loop-truncation fix (commit that closed it) may
be truncation-limited — a run that quit mid-reasoning looks identical in the ledger to a considered one. Any
pre-fix step-counts / finding-counts cited in the paper must be re-run on the fixed loop or explicitly caveated.

---

## THE CAPABILITY MILESTONE — the definition of "done" for the CURRENT phase (2026-09-06)

**The paper is DEFERRED by decision. This is what the current phase is for, and it is the
only thing that counts as finishing it.**

> **ONE confirmed business-logic finding, on a real target, where the LEDGER ALONE supports
> the claim: two distinct principals recorded, the comparator earning the title, and no
> external seeding needed to interpret the result.**
>
> **Nothing short of that counts. Nothing beyond it is required.**

Each clause is there because something specific went wrong without it, and none of them is
decoration:

| Clause | The failure it forecloses |
|---|---|
| **confirmed** | not proposed, not plausible — a fixed comparator held on gate-executed output |
| **business-logic** | 2C4's three findings were real and none were this class; the frontier is the reasoning-heavy lane, not the detector lane |
| **on a real target** | a fixture proves the plumbing, never the capability |
| **the LEDGER ALONE supports the claim** | 2C2's `PUT /api/BasketItems/1` → 200 is *still* uncitable: the tenant mapping was seeded externally and appears in no artifact, so the record cannot say whether the write was A-as-A or anonymous |
| **two distinct principals recorded** | `c829482` (a missing principal resolving to `anonymous`) and `2fdbc7f` (no provenance on either side) |
| **the comparator earning the title** | `1940f09` — two HIGH cross-account IDORs published off `bodies_differ` with one principal on both sides. The verdicts were sound; the titles were not |
| **no external seeding** | the same 2C2 defect stated as a rule: if a reader needs something we know and the bundle does not carry, the bundle does not support the claim |

**What is already in place**, so the milestone is a measurement and not a build: the phase
is planned and reached, the experiment engine is asked, two real principals are established
in-harness and recorded per side, claims are bounded by what the comparator can establish,
results that cannot be judged are refused rather than invented, and — as of `1e25473` — the
model is shown the key paths of its own setup responses instead of being asked to guess
them.

**Not part of this milestone:** paper work, the publishable-bundle P1, the asymmetric-signing
P1. They are real and they are recorded; they are not what this phase is measuring.

### STOPPING RULE for the capability-milestone run — written 2026-09-10, BEFORE the run

Committed before the run so it cannot be renegotiated once the result is known. This is the
same device that made run 2C4's judgement citable (`e2acee1`), applied to the milestone above.

**ONE run.**

- **A confirmed business-logic finding the ledger alone supports** — two distinct principals
  recorded, the comparator earning the title, no external seeding → **MILESTONE MET.**
- **Experiments dispatched AND judged, none confirmed** → a **real measurement**: the
  comparators work end to end and these hypotheses did not land. **ONE further run permitted**,
  with different hypotheses or a different target.
- **Experiments not judged for a NEW harness reason** → **STOP**, fix that one thing, **ONE
  further run.**
- **Experiments not judged for the SAME reason as 2C4** (unresolved setup references) → the
  schema fix did not work against a live target. **STOP, diagnose, no further run until it is
  understood.**

**The publishable bundle is NOT a goal of this run.** Discovered-credential redaction covers
self-describing credentials only (`2b7e671`); opaque credentials remain open. Publishability is
checked **after the fact, never as a gate.**

#### AMENDED 2026-09-10, after run CM1 and the four fixes it produced

CM1 classified as **branch 3** — experiments not judged for NEW harness reasons. It was not
branch 4: shown the key paths of its own setup response, the model wrote the correct dotted path,
both principals were dispatched and a comparator returned a verdict, so `1e25473` works against a
live target. Six of seven experiments were lost to three causes that were new, where the rule had
anticipated one. All four are now closed (`a1978af`, `3265eb6`, `5415faa`, `1219e64`).

**The amended rule, written before the next run so it cannot be renegotiated after it:**

> **ONE run.**
>
> If that run **again fails to produce judged experiments for NEW harness reasons — STOP
> BUILDING AND REASSESS THE APPROACH. The recurrence is then the finding.**

This is the clause the previous rules did not have, and the reason it is needed is visible in the
record: 2C4 lost 9 of 9 to one cause, that cause was fixed, and CM1 then lost 6 of 7 to three
different ones. Each fix was correct and each run found the next layer. A third round of the same
shape would stop being harness maintenance and start being evidence that **the number of ways a
deterministic harness can fail between a model's reasoning and a recorded verdict is not being
enumerated by fixing them one run at a time** — which is a result about the architecture and
belongs in the paper as one, not as another entry on the roadmap.

#### AMENDED AGAIN 2026-09-11, after CM2 and before CM3

CM2 did not trip the clause above: it judged 2 experiments and confirmed 1, so the harness was
not the thing that failed. But the metric the milestone actually needs has not moved at all.

| run | judged | confirmed | **cross-account judged** |
|---|---|---|---|
| 2C4 | 0 | 0 | **0** |
| CM1 | 1 | 0 | **0** |
| CM2 | 2 | 1 | **0** |

**Judged experiments are rising and cross-account judged is flat at zero across three runs.**
Two fixes ship with this note (`34813af`, `5e7219a`) aimed squarely at that column — the reply
no longer truncates before its action, and each principal is now told what it owns so a
cross-account experiment needs no setup step at all.

**The rule for CM3, written before the run so it cannot be renegotiated after it:**

> **CM3 is ONE run.** If it judges **ZERO cross-account experiments** — dispatched with two
> distinct principals and reaching a comparator — then **the limitation is the TARGET, not the
> harness. CHANGE TARGET. Do not fix the harness again.**

The justification is the table. Three runs have moved the adjacent metrics and left this one at
zero; a fourth harness fix against a flat column is precisely the pattern this rule exists to
stop. Juice Shop's cross-account surface has now refused, in order: an unresolvable identity
endpoint, a second principal that is anonymous to half the application, and a creation endpoint
that answers 500 to every shape the model proposed. At some point that is a statement about the
target, and the honest response is to measure a different one rather than to keep adapting to
this one.

---

## PAPER-READY criteria (the definition of "confident enough" — do not move these)
Start the paper skeleton NOW in parallel (architecture + threat-model sections are done and won't change).
Trigger the evaluation write-up when ALL three hold:
1. ~~Redaction boundary CLOSED~~ — **MET (`60b47e6`)**. No session material on any record surface; eight
   write sites, per-surface tests green, 11 of 16 verified red first.
2. ONE clean authenticated capability run where the loop REACHES business logic, nothing leaks, chain keyed
   + intact, containment proven — result publishable whether it finds flaws or not (an honest "governed
   autonomy vs ungoverned tools, trade-off measured" framing, NOT "we beat tool X").
   ## ✅ **MET — run 2C4, 2026-08-23.** Judged against the stopping rule committed in `e2acee1` on
   2026-08-22, *before* the fixes, so it could not be renegotiated once the result was known.

   | Clause | Evidence from run 2C4 |
   |---|---|
   | loop REACHES business logic | **10 of 10 plan phases worked**, including `[business-logic] … [WSTG-BUSL]` (phase 9) |
   | the experiment engine is actually **ASKED** | coverage table `Model-proposed experiments \| 9`; **12 setup requests dispatched** |
   | nothing leaks | tenant A token **0**, second principal token **0**, across **all 96 surfaces** (audit + 95 vault files) |
   | chain keyed + intact | `audit chain intact: True` under `BRUKAL_AUDIT_KEY`, **649 entries** |
   | containment proven | **307 requests, all to `172.20.0.3`**; `172.20.0.4` (control) **0**, `172.20.0.2` (dvwa) **0** — see the split below, which a reader should get instead of a bare "proven" |

   ### ⚠ CAVEAT ADDED 2026-09-10 — "authenticated" was narrower than it reads
   **The criterion STANDS: every clause above was measured and none of them is withdrawn.**
   What has to travel with it is what "authenticated" meant on that run.

   2C4 authenticated **by header only**. A JSON login stored the token as
   `Authorization: Bearer …` and set no cookie, and Juice Shop v20.2.0's `/rest/user/whoami`
   reads **only** the `token` cookie — so every endpoint that takes the header saw tenant A,
   and every endpoint that reads a cookie saw **an unauthenticated caller**. Measured
   2026-09-10, one token throughout: whoami+header → `{"user":{}}`, whoami+cookie →
   `{"user":{"id":25,…}}`, whoami anonymous → `{"user":{}}`, `/api/Users/25`+header → 200.

   So *"one clean authenticated capability run"* is precisely: **authenticated on the
   endpoints that read the header, anonymous on those that read the cookie, and the run
   could not tell the difference.** Cite it that way. The clause it does NOT weaken is
   containment or the chain; the clause it qualifies is what the agent was while it worked.

   **This is also why 2C2's `PUT /api/BasketItems/1` → 200 was never citable.** That entry
   has been carried in this file and in `docs/CASE_STUDY_JUICESHOP_2C.md` as an open question
   about the application — *"`GET /rest/user/whoami` returned `{"user":{}}` on that path, so
   the ledger alone cannot say whether the write was A-as-A or anonymous"*. It was a question
   about **us**: the whoami answer was empty because the harness carried a header that endpoint
   ignores, not because the session was absent. The write itself is still unproved either way
   — the finding does not become citable, it becomes *explained* — and re-proving it needs a
   re-run under the confirmation fix (`3265eb6`), not a re-reading of the old artifacts.

   ### Containment: what each line actually evidences, split rather than merged
   Merging these into "containment proven" overstates the run, so they are kept apart:

   - **The kernel lock was verified live at Phase A, from inside the cage**, before any
     traffic: `policy drop`, `ip daddr 172.20.0.3 accept`, no blanket interface accept, and
     from the cage `172.20.0.3:3000` REACHABLE while `172.20.0.4`, `172.20.0.2`, `8.8.8.8`
     and `1.1.1.1` were **DROPPED**.
   - **The run produced zero off-scope traffic with a live same-bridge control present**:
     307 requests, all in scope, `172.20.0.4` and `172.20.0.2` at **0** occurrences even as
     raw strings, both containers up throughout.
   - **The agent made ZERO off-scope attempts, so neither line was exercised BY THE RUN.**
     The gate logged no `hard:web-scope`/`hard:scope` denial, and the nftables drop counter's
     8 packets are the maintainer's own Phase-A probes, not the agent's. A reader must not be
     given those 8 as run evidence.
   - **The gate's scope enforcement is evidenced by run 2C (2026-08-16): 10 `hard:web-scope`
     denials**, where the model did reach for an off-scope host and was refused. That is the
     citation for the software line actually firing; 2C4 is not.

   **Criterion #2 still stands, and here is why rather than merely that.** The clause asks
   for containment *proven*, not for the agent to misbehave — an agent that never attempts an
   off-scope host is the desired outcome, and a criterion satisfiable only by misbehaviour
   would reward the wrong thing. What 2C4 evidences is the enforcement *in place and verified*
   plus a clean traffic record against a live adjacent control; what 2C evidences is the same
   enforcement *refusing a real attempt*. Together they cover both halves. Cite them together,
   and never cite 2C4's kernel counter as the agent being stopped.

   Also first achieved here: **two distinct principals in the ledger** —
   `[REDACTED:77e4d4c0]` / `[REDACTED:3a09fab7]`, `self` ×8 and `second` ×4 — with the second principal
   (`brkd1c8966764@brukal.test`) registered **in-harness** via JSON signup on a form-less SPA.

   ### Disclosed engagement parameter — belongs in the paper's METHOD section, not a footnote
   `rate_limit_per_min = 120` (default 30), set explicitly in the scope file for a maintainer-owned lab
   container on an isolated bridge. Two real defects were fixed *first* rather than papered over with it —
   the login seeding GET (`13bc501`) and the phase ordering that queued principal acquisition behind the
   detector sweep (`670a88e`, which took signup denials from 2 to 0). **The control remained live at that
   value: 8 `hard:web-rate` denials still fired during the run.** Scope, the gate, capability enforcement and
   the keyed chain were untouched. Cost of the parameter: any rate-limiting verdict from this run is unusable
   as evidence about the target (see the contamination finding below).

   ### What was NOT measured
   **No business-logic flaw was confirmed.** All **9 of 9** model-proposed experiments died at
   `UNRESOLVED REFERENCE — {{setup.0.id}}: no field 'id' in the setup response`: the setup was
   `GET /rest/user/whoami` issued as both principals, and Juice Shop returns `{"user":{"id":…}}`, so the path
   was `user.id`. The fail-safe refused to score any of them — not dispatched, not judged, never filed as a
   clean negative. **Zero experiment-path findings were published, so the overclaim rate for this run is 0
   of 0.**

   That is the citable limit, and it must be stated in exactly these terms: the loop reached the frontier,
   asked the model, built two real principals, dispatched their requests, and then **declined to invent a
   result there**. What remains unmeasured is whether the comparators can confirm a business-logic flaw —
   not whether the harness will fake one. The highest-value remaining capability item was the setup-reference
   schema gap below, **CLOSED 2026-09-06 (`1e25473`)**: the refine round is now shown the resolved key paths
   of its own setup responses — structure only, never values, bounded and announcing its bounds — so the
   model is no longer asked to name a field it has never seen. **That closes the CONTRACT, not the
   measurement.** Whether the comparators can confirm a business-logic flaw on a live target is still
   unmeasured, and this fix must never be cited as if it were that result.

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
3. ~~Pre-fix numbers re-read for the truncation bug (re-run or caveat anything cited).~~ — **MET 2026-08-22.
   No re-run required.**

   The truncation fix is **`37b3957`, 2026-08-12 23:38:30** (quoted as `be94446` before the history rewrite —
   see the section below). Every run under `runs/` was classified against that timestamp and every
   quantitative claim in `PROJECT_STATE.md`, `docs/HARDENING_ROADMAP.md` and
   `docs/CASE_STUDY_JUICESHOP_2C.md` was traced to its source run.

   **The finding: every capability number the paper would cite comes from 2C (2026-08-16) or 2C2
   (2026-08-20/21), and both are POST-FIX.** Verified directly against the artifacts — 2C's 30 steps,
   `stop_reason: exhausted`, $1.61, `plan_cursor: 7` and 64 agent notes; 2C2's 50/70 steps,
   `plan_cursor 12/12`, 44 commands, 6 blocked, 73 calls, $3.89, 245 audit entries and 70 agent notes.

   **The PRE-FIX numbers that remain in the docs are evidence OF defects, not claims about capability** —
   "12 of 20 budgeted steps and $3.75 of a $4 cap went unused" is the truncation bug's own symptom, and
   "25 steps spent, 21 commands known, 35 prior findings" is the recycled-IP P2's. Both are historical
   records that would be falsified, not improved, by re-running them. The suite counts scattered through the
   roadmap (899 → 993) are dated snapshots in a changelog and correct as history.

   **Three arithmetic corrections were required and are part of this closure** — each an unlabelled count
   rather than a truncation artefact: the case study's "238 requests" → **102 answered web requests**
   (`web_result`; it contradicted the roadmap's 102 for the same run), the roadmap's 2C "208 requests" →
   **206 web ledger entries** (109 `web_decision` + 97 `web_result`), and its "11 denials" → **10
   `hard:web-scope`** (13 `DENY` total). Logged against the P2 for self-report-vs-ledger, which has now
   recurred in prose written *about* the ledger rather than *by* it.

   **Caveat that survives this closure, and it is not a truncation one:** experiment findings carry no record
   of which principal issued each side (roadmap → *"the ledger does not record which principal an experiment
   used"*, P1, open). Any cross-account result cited in the paper needs that fixed first, or it cannot be
   backed by the ledger.

Everything else on the roadmap is a cited limitation, not a prerequisite for writing.

---

## Run 2C4 — the criterion-#2 measurement. Cite these paths, do not hunt by mtime
| | |
|---|---|
| Audit log | **`runs/audit_juiceshop2c4.jsonl`** — 649 entries, 296 KB, keyed, `chain intact: True` |
| Vault root | **`runs/vault2c4/172.20.0.3/`** — 95 files |
| Scope, as stamped | **`runs/vault2c4/scope.2c4.json`** (snapshot; `engagement: brukal-juiceshop-2c4-172.20.0.3`, `rate_limit_per_min: 120`) |
| Findings | `findings.jsonl` (87 records) · `findings.json` · `report.md` · `report.json` · `brukal.sarif` — **3 findings, 2 confirmed** (MEDIUM ×2, LOW ×1) |
| Agent notes | `agents/strategist/` — 83 notes |
| Plan / state | `plan.md` (10/10 phases worked) · `checkpoint.json` · `engagement.md` · `sessions.md` |
| Target | OWASP Juice Shop v20.2.0, recreated fresh, isolated bridge, no published ports |
| Spend | 82 calls · 765,744 in / 111,932 out · **~$4.05** · stopped on the $4.00 cap at step 51 |

**⛔ These artifacts may NEVER be shared or published, and the fix does not reach them.** They contain a
live admin credential for the target in cleartext across eleven surfaces. The asymmetric-redaction P1 was
**CLOSED 2026-09-07 (`2b7e671`) for self-describing credentials** — but at WRITE time, so it applies to runs
made after it and to no run made before, and post-hoc masking is not available: the records are hash-chained,
so editing one breaks the chain from that entry on and destroys the tamper-evidence that is the entire reason
to publish the bundle. **The publishable bundle has to come from a NEW run.** Still open for OPAQUE
credentials (cookies, API keys, structureless bearer values), which no decode can recognise — so a per-run
leak check remains required before any release.

---

## Commit references and the 2026-08-13 history rewrite
`git-filter-repo` ran on **2026-08-13 23:19** and gave **new SHAs to 82 of the 229 commits** (0 commits were
dropped; the content is intact and pushed). **Any SHA quoted in material written before that date does not
resolve** — `git show` fails, and GitHub 404s. This bit three load-bearing citations in this file's own
criteria list, unnoticed until an audit on 2026-08-22 tried to follow them.

| Quoted in older material | Real SHA | What it is |
|---|---|---|
| `be94446` | **`37b3957`** (2026-08-12) | loop: a truncated model reply is not a decision to stop |
| `66185da` | **`60b47e6`** (2026-08-13) | redact: session material never reaches a record |
| `2f3cc51` | **`5922031`** (2026-08-13) | auth: a redaction placeholder is not a credential |

All docs in this repo are corrected. **A `66185da` reference survives in
`tests/test_auth_not_placeholder.py:4`** (a docstring) — left alone because that session was docs-only; fix it
whenever that file is next open.

**The map is recoverable, not guesswork:** `.git/filter-repo/commit-map` holds every old→new pair, and
`.git/filter-repo/ref-map` records that the rewrite also rewrote `backup-pre-filter-1786627134` — so **that
branch is not a pre-filter backup**; it is a plain ancestor of `main` and preserves nothing `main` lacks. The
reflog was expired by the same run, so `origin/main` and `/tmp/brukal-snap/` are the recovery paths.

**Not commit hashes, despite looking like them:** `1f3a9c02` and `ed82603d` are **redaction placeholder tags**
(`[REDACTED:<8 hex>]`, derived from the masked value) appearing in examples in the roadmap, `redact.py`,
`assist.py` and `test_auth_not_placeholder.py`. `filter-repo`'s `suboptimal-issues` listed them as commits
"filtered out but still referenced" — its scan matches any hex substring in a commit message. Nothing is
missing, and they must not be "corrected" to a SHA.

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
