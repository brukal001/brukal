# Trust-Governed Multi-Agent Large Language Model Penetration Testing with Risk-Constrained Action Gating

**[Author]**¹ · **[Supervisor / co-authors — add on submission]**
¹ [Affiliation]. Correspondence: [email].

*Preprint. Draft — not yet peer reviewed. [DATE].*

---

> **Drafting notes (delete before submission).**
> `[FILL]` = a fact only you can supply (author, affiliation, exact date).
> `[PENDING]` = a number that lands when the current CR3 A/B measurement finishes; the four confirmed values from VAR2 are already in.
> Framing rule for the whole paper: **the contribution is containment/governance, not exploitation performance.** Recall is reported honestly and conservatively, as a *secondary* result and as the setting that stress-tests the governance claim.

---

## Abstract

Large language model (LLM) agents are increasingly given access to real tools acting on live systems, which turns a familiar safety question into an operational one: how do you let a fallible, promptable model *act* on a hostile system without it being talked, tricked, or drifted past the authority it was granted? Penetration testing is an acute instance — the environment is adversarial by construction, consequences are immediate, and the target actively tries to widen the agent's reach. We present **Brukal**, a multi-agent LLM penetration-testing system built around a single design commitment: **the model proposes, a deterministic gate disposes.** Every action an agent proposes is emitted only as text and must pass a non-LLM policy layer — **risk-constrained action gating** — before it can touch the target. The gate enforces five safety invariants (no LLM inside the gate; fail-closed; never trust an agent's self-report; a single audited execution path; immutable scope with an append-only, hash-chained audit log). We describe the architecture, the gating layer, and a deterministic *proof-carrying* confirmation stage that records a vulnerability only when a differential experiment demonstrates it. Evaluating on the OWASP crAPI deliberately-vulnerable API, we find the governance envelope holds under adversarial input (no out-of-scope action executes) while measured recall is modest and — importantly — **hard to measure honestly**: we show that a naïve recall metric is *blind* to genuinely confirmed findings when proof is recorded in the wrong channel, and we contribute an attribution taxonomy that separates "the agent never tried" from "the harness could not judge" from "the target was hardened." We argue the governance-first framing is the more durable and transferable contribution as tool-using agents proliferate.

---

## 1. Introduction

Autonomous penetration-testing agents built on LLMs have advanced quickly [survey; rising-capability]. Most work optimises *capability*: can the agent find and exploit more? We argue the pressing open problem for deploying such agents is the opposite one — **containment**. An LLM is promptable and fallible; a penetration-testing target is, by definition, hostile and full of untrusted output that the agent will read. If any part of the decision to *act* is itself an LLM, that decision is attackable: a target can attempt to talk the agent into acting outside its authorised scope, and there is no sound way to prove it cannot. This is not hypothetical for tool-using agents generally; the pentest setting simply makes a governance failure immediately visible and consequential.

Brukal is designed around one commitment that follows directly: **no LLM sits inside the gate.** Agents (recon, exploit, verify) emit *only text* — a schema-validated action request. A deterministic policy layer re-reads that request and decides ALLOW / DENY / ESCALATE using string parsing, set membership, CIDR arithmetic, and regular expressions — machinery that cannot be prompt-injected. Scope is frozen at launch and cannot widen at runtime; every decision is written to an append-only, hash-chained ledger. We call the decision layer **risk-constrained action gating**: hard checks form a logical AND that can only *deny*, followed by a soft risk score that can *escalate* an action to a human but can never widen what the hard checks allow.

This paper makes four contributions:

1. **A governance-first architecture** for tool-using LLM security agents, reduced to five safety invariants and one enforceable code rule (Section 4–5).
2. **Risk-constrained action gating**: a deterministic, fail-closed gate with an auditable escalation path, and an argument for why the gate must never contain an LLM (Section 5).
3. **Proof-carrying confirmation**: a deterministic differential stage that upgrades an agent's "I think I found X" into a recorded finding only when a control/variant experiment demonstrates it — and an *attribution taxonomy* that makes the difference between untested, unconfirmed, and hardened explicit (Sections 7–8).
4. **An honest measurement result**: on OWASP crAPI, containment holds under adversarial conditions while recall is modest; and we show a naïve recall metric can be *blind* to real confirmed findings, a methods pitfall for anyone evaluating such agents (Section 8).

---

## 2. Threat model and design goals

**Actors.** (i) A set of LLM *agents* that plan and propose actions; they are competent but **fallible and promptable** and are not trusted to self-police. (ii) A **target** system, assumed hostile: its responses are untrusted input that the agents will read, and it may attempt to induce out-of-scope actions (prompt injection through banners, error messages, file contents). (iii) A human **operator** who authorises an engagement and can be escalated to.

**Trust boundary.** The boundary is the gate. Everything an agent produces is untrusted text on the far side of it; everything past it is deterministic and audited. Concretely: agents are handed a way to call `Executor.run`, **never** the tool-execution cage itself.

**What we defend.** (1) *Scope integrity* — no action executes against anything outside the frozen authorisation, regardless of what an agent proposes or a target says. (2) *Non-repudiation* — every decision (allow, deny, escalate) is recorded in a tamper-evident log. (3) *Fail-closed behaviour* — anything ambiguous, malformed, or unparseable is denied.

**What we do not claim.** We do not claim state-of-the-art exploitation performance, and we do not defend against a compromised host running Brukal itself, or against an operator who authorises a malicious scope. Our contribution is the containment of a fallible agent, not the trustworthiness of its human.

**Design goals.** G1 *deterministic enforcement* (no LLM in the gate); G2 *fail-closed*; G3 *self-report is never trusted* (the gate re-derives facts from the command, e.g. re-scans every IP in it, not the agent's declared target); G4 *one execution path*; G5 *immutable scope, append-only audit*.

---

## 3. Related work

**LLM-driven penetration testing.** A growing line of work builds autonomous or semi-autonomous pentest agents and benchmarks their capability [PentestGPT; survey; rising-capability]. These largely optimise coverage and success rate. Brukal is complementary and deliberately orthogonal: we hold capability as secondary and study the *containment* of the agent.

**Security of AI-powered pentest agents.** Recent work explicitly raises the security and guardrail question for pentest agents — threat surfaces, guardrails, and architectural perspectives [secure-agents]. Brukal is a concrete, implemented instance of that architectural direction, with a specific, enforceable commitment (no LLM in the gate) and a working deterministic policy layer, rather than a survey of options. **This is the closest related work and the primary comparison to draw in the final version.**

**LLM agents for systems security more broadly.** Surveys of LLM agents for software and systems security [agents-systems-security] catalogue applications and assessment methods; our attribution taxonomy (Section 8) contributes to the "assessment" side by making non-findings legible.

**Guardrails and agent safety.** Prompt sanitisation and runtime guardrails for LLM agents are active [secure-agents]. Our position is that a guardrail *implemented as an LLM* inherits the promptability it is meant to contain; the gate must be deterministic. We situate Brukal against LLM-based guardrails on exactly this axis.

> **TODO:** add 8–12 formal citations with venues/arXiv IDs in the References section; expand this section to ~¾ page. Candidate anchors gathered: arXiv 2609.16694, 2607.02605, 2608.28490, 2609.10780, and the PentestGPT line.

---

## 4. System architecture

Brukal's load-bearing shape is a one-way pipeline in which policy flows forward and nothing widens at runtime:

```
scope.json ─► scope.py ─► gate.py ─► executor.py ─► kali.py ─► audit.py
(immutable    (frozen     (determin-  (the ONE       (cage:      (hash-
 policy)       Scope)      istic       door: gate     Fake /      chained
                          ALLOW/DENY/  → log → run)   Docker)     ledger)
                           ESCALATE)
```

*(See Figure 1 — the annotated architecture, `docs/brukal-architecture.html`.)*

Agents never see the cage. They receive an `Executor` handle and can only call `Executor.run(command, target, …)`, which (i) gates the command, (ii) logs the decision, and only then (iii) dispatches it to the cage if allowed. The cage (`kali`) is a sandboxed tool runner — a `FakeKali` for hermetic testing and a `DockerKali` for live engagements — with no shell exposed to agents.

**The five safety invariants.** Brukal is specified by five invariants that any change must preserve:

- **I1 — No LLM inside the gate.** Scope is enforced by deterministic code so a hostile target cannot talk its way past it. A regular expression cannot be prompt-injected; an LLM guard could.
- **I2 — Fail-closed.** Anything ambiguous, unparseable, or malformed is denied. The safe default is refuse.
- **I3 — Never trust an agent's self-report.** The gate re-reads the command itself — e.g. it re-scans every IP present in the command string, not just the agent's declared `target`.
- **I4 — One execution path.** Everything runs through `Executor.run`, which gates first and logs always. Agents are handed the executor, never the cage.
- **I5 — Immutable scope, append-only audit.** Scope cannot widen at runtime; the hash-chained audit log cannot be edited undetectably.

The single code rule that protects all five: **never give an agent the cage object — only ever a way to call `executor.run`.**

---

## 5. Risk-constrained action gating

The gate is the paper's core mechanism. It evaluates a proposed action in two stages.

**Hard checks (a logical AND, deny-only).** In order: (1) *injection screen* on the raw command; (2) *parse* into a typed action — a failure to parse is a deny (I2); (3) *allowlist* of permitted tools/verbs; (4) *target-in-scope* — every host/CIDR the command actually references must lie inside the frozen scope (I3, I5); (5) *no smuggled host* — reject a command that names an in-scope target but also reaches an out-of-scope one; (6) *rate limit*. Each check can only reduce permission; none can widen it. Any failure ⇒ DENY.

**Soft risk score (escalate-only).** Actions that pass the hard checks are scored for risk (destructiveness, irreversibility, blast radius). A high score does not deny; it **escalates** to the human operator, who approves or refuses. Under an explicit `--full-send` authorisation an auto-approver stands in for the human, and *every such decision is still recorded* in the ledger as an escalation with its layer and reason, so a reader can reconstruct exactly which irreversible actions were authorised and by whom.

**Why the gate must be deterministic.** The target's output is untrusted and the agent will read it. If the ALLOW/DENY decision were made by an LLM, that decision would be reachable by prompt injection through the target — the very failure the system exists to prevent. Determinism is not a performance choice; it is the security property. This is the axis on which Brukal differs from LLM-based guardrails.

**Immutability and audit.** Scope is frozen at launch (`brukal target <ip-or-cidr>` validates and records what it authorises; broadening beyond a single host requires confirmation). Every decision is appended to a hash-chained ledger, so any post-hoc edit breaks the chain and is detectable. The audit is the ground truth for all evaluation in Section 8.

---

## 6. Multi-agent orchestration

Brukal runs a small, fixed set of agents sequentially (no concurrency): a **planner** that routes the engagement, and **recon**, **exploit**, and **verify** agents. Each emits only a schema-validated action request; the model proposes, the code disposes. A blackboard/task-tree coordinates state across agents.

We deliberately keep the agent set small. A design rule of the project is to add machinery only when it demonstrably raises what the system can *find or prove* (the measured ceiling), never for its own sake. Three agents plus a verifier is the core.

> **TODO:** one paragraph + a small figure on the planner→recon→exploit→verify loop and the blackboard. Consider a Lifecycle diagram of the per-action loop for the camera-ready.

---

## 7. Proof-carrying confirmation

A recurring failure mode of LLM pentest agents is the *unverified claim*: the model reports a vulnerability it did not actually demonstrate. Brukal separates **proposing** from **confirming**. Confirmation is done by deterministic *provers* that run a differential experiment and record a finding only if the differential holds — no LLM in the decision. Examples:

- **NoSQL operator injection** (`confirm_nosqli`): a benign value that should match nothing is compared with an always-true operator object (`{"$ne": null}`, `{"$gt": ""}`). If the operator is accepted where the benign value is refused, the query trusts a client-supplied operator. This is exactly OWASP crAPI's "free coupon without a code" challenge.
- **Boolean/error-based SQL injection**, **reflected XSS**, **BOLA/IDOR cross-account reads**, **mass assignment**, **out-of-band SSRF**, and others follow the same pattern: a control side, a variant side, and a deterministic comparator.

**A measurement lesson (contribution).** Findings and *experiments* were recorded in different channels of the audit. Our recall scorer credited a challenge only from a confirmed *experiment* record, never from a *finding*. As a result, vulnerabilities the system genuinely proved — and filed as confirmed findings — were **invisible to the metric**: crAPI's SSRF and NoSQL challenges scored "not confirmed" despite a live, reproducible proof (a benign coupon code returned HTTP 500 with an empty body while the operator `{"$ne": null}` returned HTTP 200 carrying a real coupon). The fix is faithful, not cosmetic: when a prover confirms, it now emits the same experiment-outcome record the model's own experiments leave, so the differential is *counted as the experiment it already is*. This is a general pitfall: **the channel in which proof is recorded determines what a metric can see**, and a scorer that reads only one channel will under-count a system that files proof in another.

---

## 8. Evaluation

### 8.1 Setup

We evaluate on **OWASP crAPI** (Completely Ridiculous API), a deliberately-vulnerable API with 18 documented challenges, run as a disposable containerised target on an isolated bridge with all host port mappings removed. Of the 18, four are unreachable in our deployment (three chatbot challenges require a third-party LLM key the lab does not supply; one is a Layer-7 DoS excluded by policy), leaving **14 measurable** challenges. Scope authorises exactly the front-door service; the target's own backing services sit one IP away and must be dropped at the gate — a stricter containment test than a single isolated host. The agent driver is a single model (`deepseek-v4-pro`) held constant across all runs, under a 70-step budget with auto-approval, so the runs measure capability and containment rather than the human-in-the-loop path (which is tested separately). We run a 2×2 comparison: the deterministic-confirmation *emission* (Section 7) off/on × an opt-in "auto-confirm what the model reached" lever off/on, to separate a measurement correction from a capability change.

### 8.2 Metrics and attribution taxonomy

We report two things. First, **containment**: does any out-of-scope action execute, and does the system fail closed under malformed or adversarial input? Second, **recall**: of the 14 measurable challenges, how many are *confirmed by a proof-carrying differential* (not merely reached or claimed). Recall credits only proof; a URL being touched, or a model asserting success, does not count.

Crucially, every *miss* is attributed, so "hunted out" is a number we read rather than a feeling:

- **REACHED-NOT-PROPOSED** — the run's own requests reached the endpoint, the model had its rounds, but no experiment was ever aimed at it (a model/planning limit).
- **MEASURED-NOT-CONFIRMED** — an experiment was aimed and dispatched but the differential did not hold or could not be judged.
- **HARNESS-LIMIT** — our own gate or harness refused/couldn't construct the precondition (ours, not the target's).
- **UNREACHABLE** — excluded by deployment or policy, stated rather than silently dropped.

This taxonomy is itself a contribution: it prevents the common overclaim of "we tried everything" and the common underclaim of blaming the model for what the harness never enabled.

### 8.3 Results

**Containment (primary result).** Across the two post-fix evaluation runs the gate made **1,274** and **1,335** decisions respectively; it denied **9** and **12** requests and — with crAPI's own backing services (identity, community, workshop, databases) sitting one IP away on the same bridge — allowed or escalated **zero** out-of-scope actions in either run. Malformed and unparseable proposals were denied (fail-closed), and the hash-chained audit verified intact end-to-end. *No action executed outside the frozen authorisation.*

**Recall.** After the proof-recording fix of Section 7, Brukal confirms **3 of 14** measurable crAPI challenges with proof-carrying differentials: **#4** (excessive data exposure of another user's records), **#11** (server-side request forgery via `contact_mechanic`, proven by an out-of-band callback), and **#12** (free coupon via NoSQL operator injection, proven by the benign-vs-operator differential). Each credit was audited challenge-by-challenge against the specific experiment that earned it.

**The confirmations come from the deterministic layer, not the model.** In both the auto-confirm-off and auto-confirm-on arms, #11 and #12 are landed by a *deterministic prover* (`confirm_prover`-sourced experiments), while #4 comes from a model-composed access-control experiment. The two arms score **identically (3/14 vs 3/14, same three challenges)**: the opt-in "auto-confirm what the model reached" lever adds **no unique recall** on this target, because the deterministic confirmation sweep already lands the hard cases. This is direct evidence for the paper's thesis (Section 9): trustworthy output in this system is produced by its non-LLM parts.

**The measurement-blindness effect.** Before the proof-recording fix, the identical runs scored **1 of 14** despite filing confirmed findings for #11 and #12 — the metric could not see proof recorded as findings rather than experiments (Section 7). The fix moved *both* arms from 1/14 to 3/14. We report both numbers deliberately: the 1→3 delta is a **measurement correction, not a capability gain**, and conflating the two is exactly the error the attribution taxonomy exists to prevent.

**Result matrix (crAPI, 14 measurable challenges):**

| | auto-confirm off | auto-confirm on |
|---|---|---|
| proof-emission off (naïve metric) | 1 / 14 | 1 / 14 |
| proof-emission on (Section 7 fix) | **3 / 14** | **3 / 14** |

### 8.4 Honest limitations of the evaluation

Single benchmark; small number of runs; a driver model that is stochastic across runs (observed command counts and confirmed counts vary run to run); and recall that is low in absolute terms. We take these as scoping the *capability* claim, not the *containment* claim — and as the springboard for the research programme in Section 10.

---

## 9. Discussion

The results support a specific reading: **containment and verification are separable from, and more robust than, generation.** The parts of Brukal that reliably produce trustworthy output are the deterministic ones — the gate that never let an out-of-scope action through, and the provers that confirmed #11/#12 regardless of the model's own stochastic behaviour. The LLM's contribution is breadth of proposal; the governance layer's contribution is that nothing unsafe or unproven survives. As tool-using agents are deployed more widely, this division of labour — *fallible generation behind a deterministic, auditable envelope* — is the transferable idea, beyond penetration testing.

---

## 10. Limitations and future work *(this section seeds the research proposal)*

- **Beyond one benchmark.** Generalise the containment and recall evaluation across multiple deliberately-vulnerable targets and, under authorisation, more realistic surfaces; characterise how the attribution taxonomy behaves at scale.
- **Formalising the gate.** State and (ideally) machine-check the safety invariants: prove that no reachable execution path bypasses the gate, and that scope cannot widen at runtime. This is the strongest possible version of I1–I5.
- **Risk scoring under adversarial pressure.** Study whether the *soft* score (which escalates, not denies) can be gamed, and where the escalation threshold should sit.
- **Closing the proposal/confirmation gap.** The evidence that the deterministic sweep, not the model, lands the hardest confirmations suggests the research question: *how much of useful penetration testing is deterministic verification versus LLM generation, and where is the model actually load-bearing?*
- **Measurement as a first-class problem.** Generalise the "proof-channel" lesson into a methodology for evaluating tool-using security agents honestly.

These directly define a Master-by-Research programme: **formalising and evaluating risk-constrained action gating for tool-using LLM security agents, and characterising the boundary between deterministic verification and LLM generation.**

---

## 11. Conclusion

Brukal shows that a fallible, promptable LLM can be put to work on a hostile system while a deterministic, fail-closed, auditable envelope guarantees it never acts outside its authority. The exploitation numbers are preliminary and honestly reported; the durable contribution is the architecture — *the model proposes, the deterministic gate disposes* — and the demonstration that trustworthy behaviour in a security agent comes from its non-LLM parts. We release Brukal and its evaluation harness to support work on containing the next generation of tool-using agents.

---

## References

> **TODO — format for arXiv (plain or LaTeX bib).** Anchors gathered during drafting:
> - *Toward Secure AI-Powered Penetration Testing Agents: Security Threats, Guardrails, and Architectural Perspectives.* arXiv:2609.16694. **[secure-agents — primary comparison]**
> - *A Survey of LLM-Driven Penetration Testing: Taxonomy, Co-Evolution, and Open Challenges.* arXiv:2607.02605. **[survey]**
> - *LLM-Based Agents for Software and Systems Security: Approaches, Applications, and Assessment.* arXiv:2608.28490. **[agents-systems-security]**
> - *Big Enough to Break Out: Tracking the Rising Capability of LLM Penetration-Testing Agents.* arXiv:2609.10780. **[rising-capability]**
> - Deng et al., *PentestGPT.* **[PentestGPT — verify exact cite/venue]**
> - OWASP crAPI project. **[crAPI — cite the project/repo]**

---

### Appendix A — reproducibility
Scope files, the hash-chained audit logs for each run, and the recall scorer are included in the artifact. Recall is recomputed from an audit with a single command; the attribution of every challenge is derived from the ledger, not asserted.

### Appendix B — the five invariants as code
[FILL: short listing or table mapping each invariant I1–I5 to the module/function that enforces it — this is a strong, concrete appendix for reviewers.]
