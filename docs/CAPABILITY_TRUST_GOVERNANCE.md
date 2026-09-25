# Brukal — Capability, Trust & Governance Roadmap

*Written 2026-09-25. Research input: Claude Code's published architecture (the agent
loop, permission modes, hooks, subagents, MCP, skills, context compaction, the Agent
SDK) and the 2026 autonomous-pentest governance literature. Every proposal below is
checked against **the five safety invariants** in `CLAUDE.md`; anything that would touch
one is flagged and gated on maintainer sign-off. This is a menu, not a work order — per
`CLAUDE.md`, "do NOT over-build".*

---

## 0. How to read this

Each item carries:

- **What** — the change.
- **Why** — the capability/trust/governance gain.
- **Invariants** — ✅ neutral, ⚠️ touches an invariant (needs sign-off), ❌ would violate one (do not build).
- **Cost** — S / M / L.
- **Where** — the module(s) it lands in.

Brukal's spine today (`CLAUDE.md`): `scope.py → gate.py → executor.py → kali.py →
audit.py`; agents emit schema-validated Action Requests; `Executor.run()` is the one
door (gate → log → run); `risk.py` adds a soft score that can ESCALATE; `trust.py` is
adaptive per-agent trust; `hypothesis.py` holds the deterministic comparators (the
trusted side); `verify.py` grounds "solved" on real output.

---

## 1. Claude Code architecture → what maps onto Brukal

Claude Code is, at core, a while-loop that calls a model and runs tools; almost all of
its engineering is in the **systems around the loop** — a permission layer with a
deterministic rule engine, a multi-stage context-compaction pipeline, four extensibility
seams (MCP, skills, plugins, hooks), and subagent delegation. Brukal already has the
governance spine Claude Code's permission system provides (its gate is *stronger* — no
LLM inside it, which Claude Code's ML classifier cannot claim). The gaps are in the
loop's *ergonomics and context discipline*, not its safety.

### 1.1 Hooks — a deterministic event bus around the loop  ✅  Cost M  (`loop.py`, new `hooks.py`)
**What.** Claude Code exposes ~33 lifecycle events (session start/end, per-turn,
pre/post every tool call, compaction, subagent) where deterministic code runs and can
*modify or veto* what the loop does next. Give Brukal the same seam: named hook points
(`pre_action`, `post_action`, `pre_gate`, `on_escalate`, `on_finding`, `session_start`,
`session_end`) that dispatch to registered Python callables.
**Why.** Today the reflexes (crawl → confirm_surface, coverage forcing, capture
ingest) are hard-wired into `loop.py`. A hook bus turns them into registered,
individually testable, individually disable-able units, and lets an operator drop in a
site-specific rule (e.g. "never fetch `/createdb`") without editing the loop. It is also
the natural home for the FP guards (see §2.1).
**Invariants.** ✅ *only if* hooks can DENY/annotate but never WIDEN — a hook must not be
able to authorise what the gate refused. Enforce by giving hooks a read-only view of the
decision plus a veto, never the `kali` object. Document this as invariant-1-adjacent.

### 1.2 Real subagent isolation with per-agent tool scopes  ⚠️  Cost M  (`orchestrator.py`, `identity.py`, `trust.py`)
**What.** Claude Code subagents each get their own instructions **and a narrower tool
set**. Brukal has recon/exploit/verify agents but they share the executor surface.
Give each agent a declared **capability set** (allow-list of tools/action-kinds) that the
gate enforces per `agent=` — recon cannot invoke `sqlmap --dump`; verify can only issue
read methods.
**Why.** Least privilege per role; a compromised/hallucinating exploit agent cannot
reach credential attacks unless its role grants them. Strengthens invariant 3 (never
trust the agent) with invariant-style *capability* confinement, and feeds `trust.py`
(trust can gate capability, not just escalation).
**Invariants.** ⚠️ changes the gate's inputs (adds a per-agent allow-list AND). It only
ever *narrows*, so it cannot widen scope — but it is a gate change, so: sign-off + a test
that proves a role cannot exceed its set, before it ships.

### 1.3 Context compaction / a "working-set" summariser  ✅  Cost M  (`loop.py`, `knowledge.py`)
**What.** Claude Code runs a multi-layer compaction pipeline so long sessions don't blow
the context window. Brukal's `PROJECT_STATE`/vault log shows runs that "stop having
actions to propose at ~1/5 of budget" (GAP #28) — partly a *context* problem: the model
loses the thread of what's untested. Add a deterministic **working-set builder** that,
each turn, hands the model a compacted state: confirmed findings, the coverage ledger's
*unchecked* rows, open leads, and the last N outcomes — instead of raw scrollback.
**Why.** Directly attacks the "runs out of ideas early" ceiling the vault keeps hitting;
the coverage ledger already knows what's untested, so surface it *as the prompt*.
**Invariants.** ✅ pure context assembly, no gate/scope impact. This is the highest-EV
capability item on the board.

### 1.4 Skills as first-class, versioned methodology packs  ✅  Cost S–M  (`skills.py`, `methodology.py`, `packs.py`)
**What.** Brukal already has `skills.py`, `packs.py`, `methodology.py`. Claude Code's
lesson is *progressive disclosure*: a one-line description in context, full body loaded
only when the task matches. Convert Brukal's methodology into match-triggered packs
(signal → section, like the §16.2 activation matrix in the hunting vault) so the planner
is fed only the relevant classes for the detected stack.
**Why.** Less prompt noise (see §1.3), better coverage targeting, and the pack set
becomes the auditable definition of "what Brukal knows how to test".
**Invariants.** ✅ advisory content only.

### 1.5 Checkpoint / rewind for engagements  ✅  Cost S  (`checkpoint.py`, `session.py`)
**What.** `checkpoint.py` exists; make it a first-class "rewind to before step N" so a
run that wandered (e.g. the DVGA `/difficulty/hard` incident) can be replayed from a
known-good point without re-running from zero.
**Why.** Reproducibility (a paper requirement) and cheaper iteration.
**Invariants.** ✅ audit stays append-only; a rewind starts a *new* audit segment, never
edits history.

### 1.6 MCP as a governed tool-ingestion path  ⚠️  Cost L  (new `mcp.py`)
**What.** Let Brukal consume MCP tool servers (e.g. a Burp/ZAP bridge) as additional
tools — but every MCP call still funnels through `Executor.run()` and the gate.
**Why.** Capability breadth without hand-writing each integration.
**Invariants.** ⚠️ new egress + new tool surface. Only safe if MCP tools are treated
exactly like cage tools: no direct handle to the agent, scope re-checked on every call,
allow-listed per engagement. Sign-off required; defer until §1.1/§1.2 exist to confine it.

### 1.7 The Agent SDK pattern — don't rebuild, borrow the shape  ✅  Cost S (design only)
The SDK exposes the same loop/permission/subagent machinery as a library. Brukal
shouldn't depend on it (the whole thesis is *its own* deterministic gate), but the SDK's
separation — loop core vs. permission engine vs. tool registry vs. subagent manager — is
a good target shape for §3's refactor of `assist.py`.

---

## 2. Trust — lower false positives, prove impact, stay honest

The vault's own law: **false positives are the #1 credibility killer**, and 40% of filed
YWH reports were RTFS'd for proving *mechanism, not impact*. These are the trust levers.

### 2.1 A false-positive guard layer (generalise the fix just shipped)  ✅  Cost M  (`webprobe.py`, new guard in `loop.py`/`hooks.py`)
**What.** The 2026-09-25 sqlmap-login FP (GAP #23) was one instance of a recurring shape:
*a scanner's tentative signal recorded as a confirmed finding*. Today's fix hard-codes the
sqlmap case. Generalise it: (a) every scanner signal is a **candidate** until a
deterministic differential (`confirm_*`) or self-evident evidence corroborates it; (b) a
candidate that the differential *refutes* becomes a recorded **NEGATIVE** that suppresses
re-proposal (kills the budget-burn loop, not just the finding). This is the "positive
control before recording a result" law, enforced in code.
**Why.** Precision is the measurable axis Brukal can win on vs. nuclei/PentestGPT
(`PROJECT_STATE` §precision). Every FP that reaches the model also burns budget (§1.3).
**Invariants.** ✅ tightens findings; no gate impact.

### 2.2 Impact-completion gate on findings  ✅  Cost S–M  (`findings.py`, `report.py`)
**What.** Encode the vault's "file impact, not mechanism" gate as a field: a finding is
`impact_proven` only when it names the privilege boundary crossed, shows the completed
outcome, and states the attacker start position. Reports separate `impact_proven` from
`mechanism_only`.
**Why.** Directly attacks the 40% RTFS rate. Makes the report self-audit.
**Invariants.** ✅.

### 2.3 Contradiction / consistency self-check before report  ✅  Cost S  (`report.py`, extend `test_coverage_consistency`)
**What.** The vault records the "report contradicts its own coverage table" defect *three
times*. There is already a static test; add a **runtime** assertion at report time (every
finding maps to a coverage class; no class shows "none found" while holding a finding).
**Why.** The self-contradiction defect keeps recurring; make it impossible at emit time.
**Invariants.** ✅.

### 2.4 Provenance on every trusted write (already strong — extend)  ✅  Cost S  (`lessons.py`, `knowledge.py`)
Brukal already funnels trusted writes through `_commit_trusted` with a minted token.
Extend the same discipline to the coverage ledger and the working-set: every "tested /
negative" mark carries the evidence pointer that justifies it, so a stale mark is
detectable, not believed. (The hunting protocol's `[x]/[~]/[ ]` three-state model.)

---

## 3. Governance — keep it provably safe as it grows

### 3.1 Machine-readable rules-of-engagement (RoE) in the scope file  ⚠️  Cost M  (`scope.py`, `gate.py`)
**What.** The 2026 governance consensus: agents enforce **scope, production-safe
execution (rate/test-window), and a forensic audit trail**. Brukal has scope + rate +
audit. Add the missing RoE fields to the immutable scope: test windows, tier ceilings
(no-T3/no-DoS), per-endpoint deny-lists (`/createdb`), and max-intrusiveness — all
enforced by deterministic gate checks.
**Why.** Encodes the real-world engagement rules the hunting vault tracks by hand;
makes "we honoured the RoE" a property the audit log *proves*.
**Invariants.** ⚠️ extends the gate. Safe because every field can only DENY. Immutable +
fail-closed must hold: an unparseable RoE field ⇒ deny. Sign-off + tests.

### 3.2 EU AI Act / accountability posture  ✅  Cost S (doc)
The EU AI Act is fully applicable Aug 2026 and adds evaluation + incident-reporting
duties for autonomous systems. Brukal's audit chain + experiment harness already produce
most of the evidence; write a short `docs/COMPLIANCE.md` mapping invariants → obligations
(model eval = the experiment harness; incident reporting = the audit ledger; human
oversight = the ESCALATE path). Cheap, and it's a paper/marketing asset.

### 3.3 Prompt-injection resistance from the target  ✅ (already the core thesis)
The literature's top threat to pentest agents is the **target talking the agent into
acting** (indirect prompt injection via response bodies). Brukal's invariant 1 (no LLM in
the gate) and "untrusted output is a lead, never an instruction" already answer this —
it is Brukal's headline differentiator. Action: make it *demonstrable* — a test target
that serves an injection payload in a 200 body and a test that proves the gate/verifier
ignore it. Turn the strongest claim into a reproducible artifact.

### 3.4 Kill-switch + budget as first-class governance  ✅  Cost S  (`killswitch.py`, `budget.py`)
Both exist; surface them in the audit as governance events (budget ceiling hit, kill
engaged) so a run's safety envelope is legible in the ledger, not just in behaviour.

---

## 4. Priority (highest expected value first)

| # | Item | Axis | Cost | Invariants |
|---|------|------|------|-----------|
| 1 | §1.3 Working-set / context compaction | capability (the budget ceiling) | M | ✅ |
| 2 | §2.1 Generalised FP guard + negative-suppression | trust | M | ✅ |
| 3 | §1.1 Hook bus | capability/maintainability | M | ✅ (with veto-only rule) |
| 4 | §2.2 Impact-completion gate | trust (RTFS rate) | S–M | ✅ |
| 5 | §2.3 Runtime contradiction check | trust | S | ✅ |
| 6 | §1.4 Match-triggered methodology packs | capability | S–M | ✅ |
| 7 | §1.2 Per-agent capability sets | governance | M | ⚠️ sign-off |
| 8 | §3.1 Machine-readable RoE | governance | M | ⚠️ sign-off |
| 9 | §1.5 Checkpoint/rewind | reproducibility | S | ✅ |
| 10 | §1.6 MCP ingestion | capability | L | ⚠️ defer behind 3+7 |

**Do-not-build (would violate an invariant):** any LLM-in-the-gate "smart" scope check;
any hook/subagent path that can widen scope or hold the `kali` object; any auto-promotion
of a model claim to a trusted/confirmed state without gate-derived evidence.

---

## 5. Suggested first three milestones (each test-green, committed, `CLAUDE.md`-style)

1. **Working-set builder** (§1.3) — a pure function `build_working_set(session) -> str`
   fed to the planner; test that it surfaces unchecked coverage rows and confirmed
   findings and omits raw scrollback. No gate impact.
2. **Generalised FP guard** (§2.1) — lift today's sqlmap fix into a `corroborate_or_shelve`
   step: a scanner SQLi/again-any-class candidate must pass the matching `confirm_*`
   differential or be shelved as a NEGATIVE that suppresses re-proposal. Tests from live
   logs (`runs/bake_ds32_260925.log` is a ready fixture).
3. **Hook bus** (§1.1) — extract the existing reflexes into registered hooks with a
   veto-only contract; test that a hook cannot widen a gate decision.
