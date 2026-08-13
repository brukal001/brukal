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

---

## Phase status
- **Phase 1 — CLOSED.** Truth-in-docs; agent identity binding (orchestrator-attached, not model-supplied);
  enforced per-agent capabilities as a hard-gate AND-condition.
- **Phase 2 Part 1 — CLOSED.** Verify-plane per-action grant (`verification_grant` re-derives the required
  capability from the emitted command's own bytes — no finding-class label; structurally pinned by test).
  Web-plane capability enforcement (`required_capability_for_web`, applied last inside `check_web`).
- **Phase 2 Part 2 (capability, live) — IN PROGRESS.** Cap (HTB) fully exercised; Juice Shop 2B run done.
  Currently building the redaction boundary (see roadmap). Business-logic capability NOT yet measured.

## Deferred (documented, not abandoned — future phases, not paper blockers)
Artifact analysis (pcap/binary fetch+parse — Cap's confirmed missing capability class); enterprise API /
RBAC / multi-tenancy / MCP / tool registry / observability / deployment modes. These are cited as scope
limits in the paper, not fixed before writing.

---

## Live findings — see docs/HARDENING_ROADMAP.md for the authoritative list
Open at last update: egress P1 #2 (lock blanket-allows the tunnel interface → doesn't constrain in-tunnel
traffic; dodged-by-construction on local single-host nets but unfixed for VPN); redaction P1 (session
material / JWT leaked cleartext across 5 of 6 record surfaces — building the fix now); `-n` third construction
site (`loop.py:408` bypasses both patched paths — reopened); P2s (report self-count vs audit ledger mismatch;
pytest writes into live `runs/vault/`). Closed recently: egress P1 #1 (fail-open on ruleset-apply failure);
loop-truncation P1 (a truncated reply no longer terminates the loop — keyed on `finish_reason`/stop reason at
the backend layer so it holds across providers).

**Truncation caveat for the paper:** runs recorded BEFORE the loop-truncation fix (commit that closed it) may
be truncation-limited — a run that quit mid-reasoning looks identical in the ledger to a considered one. Any
pre-fix step-counts / finding-counts cited in the paper must be re-run on the fixed loop or explicitly caveated.

---

## PAPER-READY criteria (the definition of "confident enough" — do not move these)
Start the paper skeleton NOW in parallel (architecture + threat-model sections are done and won't change).
Trigger the evaluation write-up when ALL three hold:
1. Redaction boundary CLOSED (no session material on any record surface; per-surface tests green).
2. ONE clean authenticated capability run where the loop REACHES business logic, nothing leaks, chain keyed
   + intact, containment proven — result publishable whether it finds flaws or not (an honest "governed
   autonomy vs ungoverned tools, trade-off measured" framing, NOT "we beat tool X").
3. Pre-fix numbers re-read for the truncation bug (re-run or caveat anything cited).

Everything else on the roadmap is a cited limitation, not a prerequisite for writing.

---

## Environment quick-reference
- Python is `.venv/bin/python` (Ubuntu has no bare `python`). Tests: `.venv/bin/python -m pytest -q`.
- Cage: Docker, nftables egress lock built at startup from the mounted scope; recon nmap needs `-n` (the lock
  blocks resolvers → 180s timeouts that look like a dead host).
- Local targets: run as a second container on the cage's docker network, scope to its container IP /32.
- HTB VPN configs expire; prefer the TCP config on restricted networks (UDP 1337 gets filtered). The cage's
  `docker/vpn/config.ovpn` is renamed `.disabled-for-2b` during local runs — restore it for HTB.
- Token/context economy: use graphify (`graphify extract . --code-only`, then `query`/`path`/`explain`) to
  navigate code instead of reading whole files. Keep `graphify-out/` in `.claudeignore`. Do NOT use the
  docs/PDF semantic pass (it calls an LLM). Do NOT use ponytail (code-minimalism skill — wrong for security
  test-first work).
- Engagement artifacts stay UNCOMMITTED in the working tree (scope file, compose scope-mount edit, disabled
  ovpn, graphify-out) — they are per-engagement state, not project code.
