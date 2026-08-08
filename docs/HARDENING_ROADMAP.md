# Hardening roadmap

Findings closed, and the conflicts deferred rather than shipped. Each entry names the
regression test that keeps it closed, so a reader can verify the claim instead of
trusting it.

---

## Phase 1 — agent identity binding, enforced capabilities, truth-in-docs (2026-08-08)

### A. Truth-in-docs

**Finding: `gate.py`'s own header misdescribed the gate.** Lines 16–18 said the soft
risk score and ESCALATE path "are stubbed with a clear extension point for milestone
3". Both have been fully implemented for a long time (`risk.py:206-227`), and
`Gate.check` consumes them. A security file whose header misstates which of its layers
exist is a file no reader can safely reason about.
*Closed — header now describes both layers and names `risk.py`.*
Tests: `test_docs_truth.py::test_gate_header_does_not_claim_the_soft_layer_is_stubbed`,
`::test_gate_header_points_at_the_real_risk_implementation`

**Finding: "Kernel-enforced scope" was sold unconditionally.** The nftables egress lock
is real, but it needs host nftables support and `NET_ADMIN`, and without them the cage
starts anyway and falls back to the software gate. The caveat existed 130 lines below
the claim. An operator reading the headline would believe they had a kernel guarantee
they may not have.
*Closed — the claim now states the prerequisites and the degradation at the point it is
made. **The degradation BEHAVIOUR is unchanged** — that is a later item (see Deferred).*
Test: `test_docs_truth.py::test_kernel_enforced_scope_claim_names_its_prerequisites`

**Finding: the documented test count was wrong in two places and inconsistent between
them** — `CLAUDE.md` said 40, `README.md` said 290. Two docs disagreeing is drift no
reader can resolve.
*Closed — both now state the real count, derived from the suite.*
Test: `test_docs_truth.py::test_docs_agree_with_each_other_on_the_test_count` — this
asserts the docs agree with **each other**, so the two can never diverge again even
when the absolute number is refreshed by hand.

### B. Agent identity binding (invariant 3)

**Finding: agent identity was self-reported by the LLM.** `Executor.run` took
`agent: str = "unknown"`, and `agents/recon.py` and `agents/exploit.py` passed
`agent=request.proposing_agent` — a field the model writes in its own Action Request.
The audit record, the adaptive trust model, and (now) the capability check all key on
that string. A model emitting `"proposing_agent": "operator"` promoted itself.
Demonstrated end-to-end before the fix: the gate recorded `decision.agent == "operator"`
for a request from the recon agent.

*Closed.* Identity is minted by the constructing code (`identity.mint`), carries
`agent_id` / `role` / `agent_version` / `capabilities` / `engagement_id`, and is
`frozen`. `resolve_identity` **always re-derives capabilities from the role**, so even a
forged `AgentIdentity` object with a self-declared capability set gains nothing. Every
decision is stamped with `agent_id` and `engagement_id` in `Gate.check`, so the audit
chain records which run of a role asked.

Tests: `test_agent_identity.py::test_a_recon_agent_cannot_promote_itself_via_its_action_request`,
`::test_an_action_request_cannot_name_its_own_identity`,
`::test_an_agent_cannot_grant_itself_a_capability`,
`::test_every_agent_path_decision_records_a_bound_identity`,
`::test_an_unknown_agent_string_resolves_to_no_capabilities`

### C. Enforced per-agent capabilities (invariants 2 + 4)

**Finding: role separation was prompt-deep.** The recon agent's persona said
"enumerate", but nothing stopped it emitting `msfconsole`. Roles were a narrative, not a
boundary.

*Closed.* `identity.required_capability` maps a command to the one capability it needs,
deterministically, reusing the tool vocabulary the soft risk layer already owns
(`risk.py`) — no second classifier to drift, and no LLM near the decision. The check is
an AND-condition inside the hard gate, placed **after** the existing hard checks so
every current denial keeps its own reason and layer; it can only ever add denials.
Unclassifiable input maps to the most restrictive capability and is refused.

Tests: `test_agent_identity.py::test_recon_role_is_denied_an_exploitation_action`,
`::test_recon_role_is_denied_an_unclassifiable_tool`,
`::test_required_capability_is_deterministic_and_fails_closed`,
`::test_capability_can_only_deny_never_widen`,
`::test_the_operator_retains_full_capability`

**Bug found by adversarial testing of the fix itself.** The netexec flag comparison
lowercased every flag, which turned `-H` (pass-the-hash) into `-h` (help) and `-X`
(powershell exec) into `-x`. A recon identity could therefore have run
`netexec smb <host> -H <hash>` as plain enumeration. Case is load-bearing for short
flags; long options are still normalised.
Test: `::test_netexec_becomes_exploitation_the_moment_it_authenticates_or_executes`

### The capability → role matrix

| Role | Capabilities | Why |
|---|---|---|
| `operator` | all five | A human at the CLI acts on their own authority. `brukal exec` / `shell` unchanged (`--agent` already defaults to `operator`). |
| `recon` | `RECON` | Its own prompt defines it as enumeration. Now structural. |
| `verify` | `RECON` | Its prompt mandates "exactly one READ-ONLY command". Now structural. |
| `web` | `RECON`, `WEB_REQUEST` | The governed browser sends state-changing HTTP. |
| `exploit` | all five | Codifies current behaviour; this role is the one meant to attack. |
| `strategist` | all five | Codifies current behaviour — it drives the operator-facing hunt and its actions are already gated and approval-driven. Splitting it is a later item. |
| `harness`, `badbot`, `goodbot` | all five | Experiment identities. Narrowing them would silently move published metrics. |
| anything else | **none** | Fail closed. An unrecognised name is not a licence. |

Five capabilities: `RECON`, `WEB_REQUEST`, `INJECTION_TEST`, `CREDENTIAL_TEST`,
`EXPLOITATION`. Deliberately not more — see Deferred.

### Two existing tests were restated, not weakened

Both were testing a *different* layer and were incidentally intercepted by the new
check. Neither assertion was loosened.

- `test_soft_gate.py::test_soft_deny_never_runs_and_never_asks_human` ran
  `nmap --script exploit` as `recon`. Its subject is the SOFT layer, so it is now
  stated as `exploit` — a role that legitimately holds the capability — and still
  asserts `layer == "soft:deny"` and `risk_band == "HIGH"`.
- `test_web.py::test_broad_allowlist_mode_safe_runs_dangerous_asks_human` called
  `Gate.check` with no agent at all. Its subject is the allowlist, so it is now stated
  as the `operator` principal.

---

## Deferred — conflicts and scope boundaries NOT shipped in Phase 1

**The capability check covers the shell path only.** Web actions gate through
`web.check_web()`, a separate function, not `Gate.check`. Extending capabilities to the
web path is a real gap and is deliberately out of Phase 1 scope. Today `web` holds
`RECON` + `WEB_REQUEST` in the matrix, but nothing consults it on that path yet.

**`POST_EXPLOITATION` is not a separate capability.** The tool vocabulary does not
distinguish it — `impacket-psexec` is both exploitation and post-exploitation. Splitting
it would require inventing a distinction the codebase does not currently make, which is
over-fragmentation on day one.

**`strategist` holds every capability.** It is the operator-facing autonomous hunt, and
narrowing it would change behaviour rather than codify it. Splitting the strategist into
a planner (no execution) and an executing principal is the natural next step.

**The kernel egress lock still degrades silently.** Phase 1 made the *claim* honest; the
*behaviour* — starting anyway when nftables is unavailable — is unchanged, and should
become a loud, recorded downgrade rather than a quiet one.

**Reason codes exist for one check only.** `CAPABILITY_NOT_GRANTED` is machine-readable
because a capability denial is the one an operator most needs to tell apart from a scope
denial. Every other layer still carries prose in `reason`. The full reason-code refactor
is its own phase.

**The audit chain is unkeyed by default.** `BRUKAL_AUDIT_KEY` upgrades it to
HMAC-SHA-256; without it the chain is tamper-*evident*, not tamper-proof. Unchanged in
Phase 1, and not a documentation problem — `audit.py` already states it plainly.

---

## Known gaps carried into Phase 2

### VERIFY ROLE MIS-SCOPED — a regression introduced in Phase 1

`agents/verify.py:102-103` executes exactly one command to confirm a finding, and
`agents/verify.py:106-111` returns `UNVERIFIED` whenever `result is None`. **A denied
verification command therefore eliminates confirmation, not merely weakens it** —
`SUPPORTED` is structurally unreachable without an executed command.

The Phase 1 matrix granted `verify` only `{RECON}`, which is strictly weaker than
"read-only". `RECON` forbids request bodies, write methods, and injection/credential
tools, so independent confirmation is impossible for the SQLi, auth-bypass, and
RCE/foothold classes. The foothold evidence path at `verify.py:92-93` makes this
concrete: the codebase's own canonical example of attributable foothold evidence is
`curl http://<target>/app/ping -d 'address=127.0.0.1;id'`, and `-d` classifies as
`WEB_REQUEST`, which `verify` does not hold.

Deciding lines: `identity.py:92` (the grant), `identity.py:196-197` (curl with a body →
`WEB_REQUEST`), `identity.py:201` (unclassifiable → `EXPLOITATION`), `gate.py:258-263`
(the AND-check that denies).

**No test exercises the verifier proposing an injection or auth command**, which is why
the suite stayed green at 851. The `recon` narrowing was caught only because a
production reflex (`ad_enum_commands()`) happened to exercise it; `verify` has no
equivalent reflex. This is a regression: pre-Phase-1 `verify` had no capability
constraint at all.

The root confusion is conceptual. The verifier's prompt says "read-only", meaning *does
not change state*; `RECON` means *does not send a payload*. Confirmation lives in the
gap — you cannot independently confirm an injection without injecting.

### Intended Phase 2 fix (design note — NOT implemented)

A verification action **inherits the capability required by the finding it verifies**,
scoped to that one confirming command. The verifier can then reproduce the specific
command — send the SQLi payload, make the authenticated call — without becoming a
standing exploitation principal.

A blanket multi-capability grant to `verify` is **rejected**: it gives narrower coverage
(it still cannot follow a finding into a class nobody anticipated) *and* less containment
(the capability persists for every later action), so it loses on both axes.

### Carried forward

Capability enforcement covers the **shell path only**. Web actions route through
`web.check_web()` and consult no capability yet, so the `web` role's
`{RECON, WEB_REQUEST}` entry is currently declarative rather than enforced.
