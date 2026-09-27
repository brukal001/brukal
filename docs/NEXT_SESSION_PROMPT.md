# Handoff prompt — Brukal capability-uplift session

*Paste the block below into a fresh Claude Code session started in the Brukal repo
(`/mnt/c/Users/ashis/Desktop/Brukal/brukal`). It carries the context, the goal, the first task,
and the guardrails.*

---

Read `CLAUDE.md` (the five safety invariants and the build discipline) and the vault note `Brukal.md`
first — this session must obey them.

**Where we are.** Brukal is *solid on governance, weak on capability.* On the OWASP crAPI lab it
confirms only 3/14 measurable challenges (#4 data-exposure, #11 SSRF, #12 NoSQL), and we proved those
come from the **deterministic provers, not the model**. Containment is strong (0 out-of-scope actions
across ~1300 gated decisions/run, hash-chained audit intact). Last session we fixed a measurement
blindness (confirmed findings now emit scorable `experiment_outcome` records) and re-ran a clean crAPI
2×2 A/B. Full read of the plan is in **`docs/CAPABILITY_UPLIFT_RESEARCH.md`** — start there.

**The goal of THIS session and the ones after it:** make Brukal *genuinely more powerful and useful on
real targets* **without weakening governance.** We do not contact research supervisors or push the paper
until Brukal is genuinely capable in the real world — capability is the whole job now.

**The one principle that makes "powerful AND governed" possible:** capability lives on the *model side*
of the gate — proposal, planning, memory, verification. **Nothing new goes inside the gate.** The gate
stays deterministic and LLM-free (validated externally by arXiv:2603.20953 "Before the Tool Call" and
2605.29251 "Provably Secure Agent Guardrail"). Provers stay deterministic. RAG/memory may only inform
*proposals*, never the gate. Growing capability this way cannot erode governance.

**Diagnosis to attack (from the crAPI attribution taxonomy):**
- `MEASURED-NOT-CONFIRMED` (#2, #3, #8, #9, #13) — multi-step / stateful / business-logic chains the
  experiment couldn't confirm. *This is where recall dies, and it's the field's hard problem too.*
- `REACHED-NOT-PROPOSED` (#1, #5, #7, #10) — model reached the endpoint but never proposed an experiment.

**First task (highest expected value, governance-positive):** implement roadmap item **F** from
`docs/CAPABILITY_UPLIFT_RESEARCH.md` — **extend the deterministic prover library to the stateful
classes**, starting with **mass-assignment-then-read chains (#8/#9/#10)**, then **#13 (coupon-DB
modification)**, then **#3 (OTP-driven password reset)**. Each new prover:
1. runs a control/variant differential (no LLM in the decision);
2. files a proof-carrying finding AND emits the `experiment_outcome{outcome:confirmed, comparator:...}`
   via the existing `_record_confirmed(..., comparator=...)` path (see `brukal/assist_confirm.py`);
3. ships as a tested milestone (red→green, `python -m pytest` fully green) that preserves all five
   invariants.

**Then** evaluate roadmap item **E** — A/B a stronger driver model (the field reports 16–25× uplift from
newer models; Brukal is provider-agnostic) using the same harness.

**Measurement discipline (non-negotiable, this is how we stay honest):**
- Use the crAPI A/B harness and the attribution taxonomy in `benchmarks/crapi_recall.py`.
- **Write predictions BEFORE any run** (a prediction fixed after the fact proves nothing).
- **Audit every recall credit challenge-by-challenge** against the experiment that earned it (GAP #23:
  URL-signature credits can be false — we already caught two).
- Always distinguish a **measurement correction** from a **capability gain**; never quote a recall number
  the ledger can't justify.
- Re-measure any server-stated limit/lifetime right before relying on it.

**Constraints / rules of engagement:**
- Live runs only against the authorized, maintainer-owned crAPI lab, with `scope.crapi.json` matching and
  the Docker cage up. Build-and-self-test otherwise.
- crAPI is disposable (public-image defaults). `crapi-preflight.yml` recreates it:
  `docker compose -p crapi -f crapi-preflight.yml up -d`. crapi-web is at 172.20.0.12 on port 80 inside
  the isolated bridge (verify the IP each time — it can drift). Principal A staged at `/tmp/a_email`,
  `/tmp/a_pass` (recreate via signup with name+number if lost).
- Provider keys live in `runs/*.env` (gitignored). Anthropic + deepseek-direct were out of balance last
  session; OpenRouter worked (`deepseek/deepseek-v4-pro`). Check balances first.
- Harden the cage as capability (and thus attack surface) grows — the literature warns offensive-agent
  tools can leak keys / compromise the operator even inside a sandbox (see the memo's §4 guardrails).
- Commit per milestone with clear messages; update `Brukal.md`; keep the attribution lines.

**Definition of done for the session:** at least one new stateful prover landing a previously
`MEASURED-NOT-CONFIRMED` challenge as a proof-carrying CONFIRMED finding on the live crAPI lab, measured
via the A/B harness, with the recall rise audited challenge-by-challenge and the full test suite green —
and containment still holding (0 out-of-scope actions).
