# Brukal capability uplift — research memo (2026-09-27)

**Question.** Brukal is solid on *governance* but weak on *capability* (crAPI recall 3/14). How do we
make it genuinely more powerful **without** weakening the governance that is its whole thesis?

**The organising principle (why "powerful AND governed" is not a trade-off).**
Capability and governance live on **opposite sides of the gate**. Every technique below adds power on
the *model side* — proposal, planning, memory, verification — and **nothing** is added inside the
deterministic gate. The 2026 literature validates exactly this split: *Before the Tool Call:
Deterministic Pre-Action Authorization* (arXiv 2603.20953) argues that controlling high-privilege
autonomous agents "cannot be solved by heuristically patching semantic filters; it requires formally
decidable constraints and deterministic control," and that semantic (LLM) guardrails "struggle to
provide the guarantees required for high-privilege autonomous operations." That is Brukal's Invariant 1,
independently arrived at. So: **make the proposer smarter and the verifier deeper; keep the gate dumb
and deterministic.** Growing capability this way *cannot* erode governance, because the gate never sees
the new machinery.

---

## 1. Diagnosis — where Brukal's capability actually fails

Read straight off the crAPI attribution taxonomy (this is why we built it):

| Miss class | crAPI challenges | Root cause | The capability lever it points to |
|---|---|---|---|
| **REACHED-NOT-PROPOSED** | #1, #5, #7, #10 | model reached the endpoint but never *proposed* an experiment | planning / hypothesis generation / memory |
| **MEASURED-NOT-CONFIRMED** | #2, #3, #8, #9, #13 | experiment aimed but the differential didn't hold or couldn't be judged | multi-step / stateful exploit construction + more provers |
| **CONFIRMED** | #4, #11, #12 | deterministic provers landed it | (our strength — extend it) |

The field's own human-vs-agent data says the same thing: the best autonomous agent beat 9/10 OSCP humans
but lost to the top one, and **the gap was "creative exploit chaining and business logic, not speed."**
crAPI #2/#3/#8/#9/#13 are exactly that: multi-step, stateful, business-logic chains (OTP-driven password
reset, mass-assignment on order return, coupon-DB modification). **That is where our recall dies, and it
is the field's hard problem too** — models remain "not yet reliably capable of autonomous, goal-directed
exploitation in dynamic environments" (RAG-augmented pentest benchmark).

---

## 2. The techniques, prioritised, each tagged for governance-compatibility

Legend: **Gov** = effect on governance (＋ strengthens · ○ neutral, model-side only · − would risk it —
none below are −). **Targets** = which miss class. **Effort** = rough build size.

### A. Persistent memory + a skill library  · Gov ○ · targets REACHED-NOT-PROPOSED · effort M
Wiki-style knowledge base the agent reads once and answers from (compounds knowledge, fights forgetting);
plus a Voyager-style *skill library* of exploit routines that worked, keyed by target shape. The field
finds "coverage-memory layers" and persistent wikis materially reduce repeated work and forgetting.
**Governance:** memory only *informs proposals*; the gate and provers are unchanged. Brukal already has a
blackboard/PTT and a coverage ledger — extend them into a durable cross-run episodic store.

### B. Reflexion / knowledge-informed self-reflection  · Gov ○ · targets MEASURED-NOT-CONFIRMED · effort M
When an experiment fails to confirm, the agent verbally reflects on *why* and retries a better-formed one
(Reflexion; RefPentester ties self-reflection to pentest *stage recognition* and improves recovery from
failed operations on HTB). This directly attacks MEASURED-NOT-CONFIRMED — the aim was there, the
construction was wrong. **Governance:** reflection produces new *proposals*, still gated.

### C. RAG over an exploit / vulnerability knowledge base  · Gov ＋ (with care) · targets REACHED-NOT-PROPOSED · effort M–L
Retrieval of exploit techniques/PoCs to raise hypothesis quality (PentestAgent; a Knowledge-Repository
module took a fine-tuned model to *perfect completion* on some targets). **Governance angle is a feature,
not a footnote:** RAG introduces *knowledge-base poisoning* attacks — but in Brukal a poisoned KB can only
change what the agent **proposes**; the deterministic gate still disposes and the provers still demand a
differential. So Brukal is a natural home for *governed RAG*: we get RAG's uplift while the gate contains
its worst failure mode. That is a publishable "powerful AND governed" result in itself.

### D. Deeper multi-step planning (extend the PTT)  · Gov ○ · targets MEASURED-NOT-CONFIRMED · effort M
A pentest state machine / task tree prevents infinite loops and structures multi-path attacks; nonlinear
task+clue orchestration (MazeRunner) handles black-box chaining. Brukal already has a Pentesting Task Tree
— deepen it toward *sub-goal decomposition for stateful chains* (e.g. "obtain OTP → reset → verify").

### E. Stronger / domain-adapted driver model  · Gov ○ · targets all · effort S (swap) – L (finetune)
The single biggest lever the field reports: newer models gave existing tools **16–25× success-rate
uplift**, and a fine-tuned Qwen3-32B (xOffense) hit **79% sub-task completion, beating GPT-4**. Brukal is
model-agnostic (provider abstraction already exists), so this is a config change to evaluate, with an
optional domain-adapted model later. **Governance:** the model sits *behind* the gate; strength there
cannot widen scope.

### F. More & multi-step deterministic provers  · Gov ＋ · targets MEASURED-NOT-CONFIRMED · effort M (ongoing)
Our confirmed challenges (#4/#11/#12) all came from deterministic provers, **not** the model. The highest-
certainty way to raise recall is therefore to **extend the prover library to the stateful classes**:
mass-assignment-then-read chains (#8/#9/#10), OTP/reset flows (#3), coupon-DB modification (#13). Each new
prover is pure governance-positive: it *adds proof-carrying verification*. This is Brukal's comparative
advantage — lean into it.

### G. Digital-twin / sandbox rehearsal before the live target  · Gov ＋ · targets MEASURED-NOT-CONFIRMED · effort L
Rehearse destructive or multi-step exploits in a *risk-mitigated twin* before touching the live target
(Automation-Exploit, under review at Computers & Security; co-evolutionary arms race in a fortified twin
sandbox). This is the cleanest synthesis: it makes Brukal **more capable** (it can attempt risky chains it
currently must refuse or escalate) **and more governed** (the rehearsal is air-gapped; only a validated,
minimal action reaches the live gate). Strong fit with our escalate-not-deny soft layer.

### H. Verification hardened against deceptive targets  · Gov ＋ · targets confirmation trust · effort S–M
ATOBench studies how agents verify vulnerabilities *when the target's evidence lies*. Brukal's proof-
carrying differential is already the right defence (a target can't fake a benign-vs-operator differential
cheaply). Benchmark and harden it explicitly — it becomes a distinct contribution: *governed verification
is also robust verification.*

---

## 3. Prioritised roadmap (highest expected value first, given our measured misses)

1. **F — extend the prover library to stateful classes.** Directly converts MEASURED-NOT-CONFIRMED →
   CONFIRMED, is our strength, and is governance-positive. Start with mass-assignment chains (#8/#9/#10),
   then #13, then #3. *Fastest path to a higher, honestly-earned recall number.*
2. **E — evaluate a stronger driver model** (config change; A/B it the way we just A/B'd the emission fix).
   Cheap to try, potentially the biggest single uplift.
3. **B — Reflexion loop** on failed experiments (recover MEASURED-NOT-CONFIRMED that are construction, not
   capability, failures).
4. **A — persistent memory + skill library** (attack REACHED-NOT-PROPOSED; compounding value across runs).
5. **C — governed RAG** (hypothesis quality + a publishable governance story).
6. **D / G — deeper PTT and digital-twin rehearsal** (the multi-step frontier; larger builds).
7. **H — deceptive-target verification benchmark** (turns our verifier into a measured contribution).

Every item is a **tested milestone that preserves all five invariants** (per CLAUDE.md's amended build
rule: build when it lifts the *measured* ceiling). Measure each with the crAPI A/B harness and the
attribution taxonomy, exactly as we did for the emission fix — a claimed uplift that the ledger can't see
is not an uplift.

---

## 4. Governance guardrails to *preserve* as capability grows (the "at the same time")

- **The gate stays deterministic and LLM-free** — non-negotiable (validated by arXiv 2603.20953,
  2605.29251 *Provably Secure Agent Guardrail*).
- **RAG and memory are proposal-side only** — a poisoned KB or a bad memory can only change what is
  *proposed*, never what is *allowed*. Never let retrieval feed the gate.
- **Provers stay deterministic** — no LLM in a confirmation decision.
- **Harden the cage.** The literature warns that offensive-agent tools have design flaws letting
  adversaries *exfiltrate keys and compromise the operator machine even inside sandboxes*; NVIDIA
  NemoClaw's answer is kernel-level network allowlisting, filesystem-write restrictions, config
  protection. Audit Brukal's DockerKali against that checklist as capability (and thus attack surface)
  grows.
- **Digital-twin rehearsal is air-gapped** — a twin must have *no* path to the live network.
- **Audit everything, measure honestly** — keep the attribution taxonomy as the arbiter; report deltas as
  measurement vs capability (the lesson from the emission-fix A/B).

---

## 5. Key sources

- *Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI Agents* — arXiv:2603.20953. **[validates the deterministic gate; formal-authorization direction]**
- *Provably Secure Agent Guardrail* — arXiv:2605.29251. **[formalise-the-gate future work]**
- *Toward Secure AI-Powered Penetration Testing Agents: … Guardrails … Architectural Perspectives* — arXiv:2609.16694. **[closest related work]**
- *Automation-Exploit: Multi-Agent LLM Framework … Digital Twin-Based Risk-Mitigated Exploitation* — arXiv:2604.22427 (under review, Computers & Security). **[digital-twin rehearsal]**
- *ATOBench: … How Autonomous Pentest Agents Verify Vulnerabilities When Target Evidence Lies* — arXiv:2608.12996. **[deceptive-target verification]**
- *RefPentester* (knowledge-informed self-reflection, stage recognition) — via LLM4Pentest survey. **[Reflexion]**
- *xOffense: Autonomous Multi-Agent … Domain-Adapted LLMs* — arXiv:2509.13021. **[fine-tuned model, 79% sub-task]**
- *RAG-Augmented LLMs for Penetration Testing* (ScienceDirect S2667305326000566) & *PentestAgent* (ACM AsiaCCS, 10.1145/3708821.3733882). **[RAG uplift + poisoning risk]**
- *A Survey of LLM-Driven Penetration Testing* — arXiv:2607.02605; *A Survey on Agentic Security* — arXiv:2510.06445. **[field maps]**
- *Big Enough to Break Out: Rising Capability of LLM Pentest Agents* — arXiv:2609.10780. **[capability trend, human gap]**

> Verify every arXiv ID and venue before citing in the paper; several are 2026 preprints found via search.
