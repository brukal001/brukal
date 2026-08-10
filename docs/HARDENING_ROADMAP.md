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

### ~~VERIFY ROLE MIS-SCOPED~~ — **CLOSED in Phase 2 Part 1**, see below

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

### ~~Carried forward: web path ungoverned~~ — **CLOSED in Phase 2 Part 1**

Capability enforcement covered the **shell path only**. Web actions route through
`web.check_web()` and consult no capability yet, so the `web` role's
`{RECON, WEB_REQUEST}` entry is currently declarative rather than enforced.

---

## Phase 2 Part 1 — closing the two capability holes (2026-08-08)

### A. The verifier can confirm without becoming an attacker — CLOSED

**The problem.** `agents/verify.py` runs exactly one command to confirm a claim, and
returns `UNVERIFIED` whenever that command did not run. A denied verification command
therefore *eliminates* confirmation rather than weakening it. With `verify` holding only
`{RECON}`, `SUPPORTED` was structurally unreachable for the SQLi, auth-bypass and
foothold classes.

**The fix, and the boundary it respects.** `identity.verification_grant(identity,
command)` authorises ONE command. It confers no capability itself — it records the
command, and `resolve_identity` recomputes `required_capability(command)` from those
bytes when the gate judges that exact command.

**This is the invariant-1 boundary and it is the load-bearing part of the design.** Had
the grant been derived from a claimed finding-class — "this confirms a SQLi, so give me
INJECTION_TEST" — a model could widen itself by lying, putting an LLM inside the
capability decision. `verification_grant` takes a command and nothing else; there is no
parameter through which a label could arrive, and a test asserts that signature so no
future caller can quietly add one.

Containment: the base identity is never mutated, the grant matches one exact command,
and only a role in `ROLES_THAT_MAY_VERIFY` can take one — otherwise it would be a
universal escape hatch.

Tests: `test_verification_grant.py::test_a_verifier_may_run_its_sqli_confirmation`,
`::test_a_verifier_may_run_its_auth_confirmation`,
`::test_a_verifier_may_run_its_foothold_confirmation`,
`::test_a_claimed_finding_class_cannot_widen_the_verifier`,
`::test_verification_grant_takes_no_label_parameter`,
`::test_the_grant_is_bound_to_that_exact_command`,
`::test_an_ungranted_verify_identity_is_still_recon_only`,
`::test_only_a_verifying_role_can_take_a_verification_grant`,
`::test_scope_still_precedes_capability_for_a_granted_verifier`,
`::test_the_verify_agent_can_now_reach_supported_on_an_injection_finding`

**Unchanged by design:** the SOFT risk layer still escalates attack-class confirmations
for human sign-off. Confirming a SQLi by running sqlmap *is* intrusive; the capability
grant lets it past the capability check, not past risk or approval.

### B. Capability enforcement on the web plane — CLOSED

**The problem.** Web actions take `web.check_web()`, which consulted no capability, so a
recon-role identity could emit a WEB request carrying an injection payload and the
capability layer never saw it. Role separation held on one plane and not the other.

**The fix.** `identity.required_capability_for_web` sits beside `required_capability`,
sharing its constants, its `_HTTP_WRITE_METHODS` predicate and its fail-closed rule —
one module owning capability classification, not a parallel copy. `check_web` resolves
the identity the same way `Gate.check` does and applies the capability as its LAST
check, so every earlier denial keeps its own reason and layer and this can only add
denials. Denials carry `CAPABILITY_NOT_GRANTED` at layer `hard:web-capability`.

Tests: `test_web_capability.py::test_a_recon_role_web_action_carrying_an_injection_payload_is_denied`,
`::test_a_web_role_plain_get_is_allowed`,
`::test_an_unclassifiable_web_action_under_a_constrained_role_fails_closed`,
`::test_scope_precedes_capability_on_the_web_path`,
`::test_a_denied_web_action_never_reaches_the_cage`,
`::test_an_interaction_under_a_recon_role_is_denied`,
`::test_method_casing_and_padding_do_not_hide_a_write`

### Residual risks — recorded, not fixed

**A verifying agent can authorise any single command it emits.** The grant is bounded to
one action, audited, and still subject to scope, risk and approval — but a
prompt-injected verifier could emit an exploitation command and have it authorised for
that action. This is inherent to "the verifier must reproduce the finding": narrowing it
further would re-create the hole this part closed. The mitigations that matter are the
soft layer's escalation and the audit record, both intact.

**Payload CONTENT is not classified on either plane.** A payload in a query string is
`RECON` on the shell path and on the web path alike, because neither inspects payload
text. Detecting "this looks like SQLi" would mean a content classifier over
target-influenced text — precisely the judgement the gate refuses to make (invariant 1).
What is classified is the SHAPE of the action, which an attacker cannot misrepresent.

**`eval` maps to `WEB_REQUEST`, not `EXPLOITATION`.** It executes JS in page context,
which is arguably closer to exploitation, but mapping it higher would narrow below
current behaviour — the Phase 1 lesson. Open question for a later phase.

**The verification grant does not extend to the web plane.** It names a shell command and
is matched against the command being judged; on the web path no command is matched, so it
confers nothing. Pinned by
`test_web_capability.py::test_a_verification_grant_does_not_leak_onto_the_web_path`. If a
verifier ever needs to confirm a finding over the web plane, that is a deliberate design
step, not an accident.

---

## P1 — open, not fixed

### EGRESS LOCK FAILS OPEN ON RULESET-APPLY FAILURE

**Severity: P1.** This is a fail-OPEN on the kernel-enforced-scope control — the exact
claim the Phase 1 docs work just made honest.

`docker/entrypoint.sh` guards one failure mode: a scope file that is missing or
unparseable installs a drop-all ruleset and exits non-zero. It has **no guard for the
ruleset failing to APPLY**.

**Observed during Cap engagement setup (2026-08-08), on the 881-test baseline:**

The `oif "tun0" accept` rule failed to parse because `tun0` did not exist at cage start
— OpenVPN had not yet brought the tunnel up:

```
/dev/stdin:5:9-14: Error: Interface does not exist
    oif "tun0" accept
        ^^^^^^
[cage] egress locked to scope. Ruleset:
```

nftables aborts the whole load on a parse error, so **no rules were installed at all**.
`nft list ruleset` returned empty (0 lines, exit 0) — not drop-all, not degraded, empty.
The container started anyway with `BRUKAL_EGRESS_LOCK=1` and **unrestricted egress**,
while the entrypoint printed `egress locked to scope.`

The scope itself parsed fine, so the existing missing-scope guard never triggered. The
success message is printed unconditionally after the load attempt, so nothing in the log
distinguishes "locked" from "silently wide open".

Harmless only incidentally on this occasion: with no tunnel there was nothing to reach.
That is luck, not containment — the same failure with a tunnel already up would leave the
cage able to egress anywhere while reporting itself locked.

**Intended fix (design note — NOT implemented, later phase):**

1. After building the ruleset, **verify it actually loaded** — `nft list ruleset` is
   non-empty and the expected default-drop policy is present — and **fail closed**
   (exit non-zero) if it did not, matching the existing missing-scope behaviour. The
   success message must be emitted only after that verification passes, never before.
2. **Decouple the `tun0`-dependent allow rule from the rest of the ruleset**, so a
   not-yet-existent VPN interface cannot abort the whole default-drop policy. The
   base deny-by-default must install even when the tunnel is still coming up; the
   tunnel allow rule can be added once the interface appears.

No code, tunnel, or configuration was changed when recording this.

### EGRESS LOCK DOES NOT CONSTRAIN IN-TUNNEL TRAFFIC

**Severity: P1.** The kernel lock blocks egress that leaves by the wrong interface. It
does **not** constrain where traffic goes once it is on the tunnel.

The ruleset accepts the tunnel interface wholesale:

```
oif "tun0" accept
```

Because the VPN pushes `route 10.129.0.0/16`, that single rule permits the **entire
VPN-side network** — every other subscriber's machine on a shared lab network — not
just the authorised scope /32. The `ip daddr <scope> accept` rule below it is
effectively dead code for tunnel traffic: `oif "tun0"` has already matched.

**Proven by the drop counter (2026-08-08, Cap engagement setup):**

```
drop counter BEFORE:                                4
probe 10.129.93.131  (out-of-scope, INSIDE tunnel): 4   <- NOT dropped
probe 8.8.8.8        (out-of-scope, via eth0):     10   <- dropped (+6)
```

An out-of-scope host inside the tunnel was reached without incrementing the counter.
Only the non-tunnel probe was dropped. Every in-tunnel probe run during setup behaved
the same way.

**Consequence.** For in-tunnel destinations — precisely the ones that matter on a
shared lab/VPN network — the kernel lock provides no containment, and the software
gate is the SOLE line of defence. This breaks the "two independent lines of defence"
property exactly where it is most needed.

Combined with the fail-open-on-apply P1 above, **the kernel backstop cannot be relied
on for in-tunnel scope on a shared network.** One defect means the lock may not install
at all; this one means that even when it does install, it does not enforce scope where
the targets live.

Note that `docker/verify_egress.sh` cannot detect this: it probes an out-of-scope
*internet* address (8.8.8.8), which is dropped correctly, and then prints
`scope enforced at the kernel`. The test passes while the property it names does not
hold for tunnel traffic.

**Intended fix (design note — NOT implemented, later phase):** scope the tunnel allow
rule to the authorised CIDR(s) over `tun0` — `oif "tun0" ip daddr <scope> accept`,
everything else dropped — rather than blanket-accepting the interface, so the kernel
lock enforces the SAME scope on-tunnel as off. The VPN server itself already has its
own pinned-IP accept rule, so it does not need the blanket interface rule to survive.

---

## P3 — operational notes

### ~~GATED NMAP NEEDS `-n`~~ — **CLOSED 2026-08-10** (and it was never a P3)

**This was misfiled.** It is not an operational note; it is a total recon blocker, and
it went on to kill a third engagement after being written down as a nice-to-have. On
`10.129.101.3`, **14 of 14 shell commands failed** (7 × `rc=124`), the loop never reached
the web plane, and the strategist then diagnosed the cause **wrongly** — blaming an
"output-file permission wall" that does not exist (the cage's cwd is writable and a
relative `-oN` scan completes in 3.02 s) — and spent further steps optimising against an
imaginary constraint. Severity should track *what a defect costs when it fires*, not how
small the fix looks.

**Fixed by deterministic command normalisation**, not by telling the model again. The
model had already been told; it forgot on `10.129.100.21`, on `10.129.100.61`, and on
`10.129.101.3`. A correctness property that depends on a model remembering is not a
property.

`schema.apply_no_resolve()` adds the no-resolve flag to a proposed command when the
egress lock is active (on unless `BRUKAL_EGRESS_LOCK=0`), from an **explicit tool → flag
allowlist** (`{"nmap": "-n"}`) — never a guess at what flag a tool might have. It is
idempotent, leaves non-listed commands byte-identical, and matches the program name
rather than a substring. It is applied at both places a command is constructed:
`parse_action_request()` (the recon / exploit / verify agents) and the strategist's
`RUN:` parse (the auto loop, which issued all 14 failing commands).

**No invariant moved.** This shapes how a command is *constructed*, not how it is
gated or executed: there is still one execution path, the gate still re-reads the
command it is handed, and nothing here can widen scope, authorise a tool, or turn a
DENY into an ALLOW.

masscan is deliberately **not** in the allowlist: it takes addresses and does not
resolve, and its failures in the same runs had a different cause. The allowlist stays
small and explicit rather than becoming a "guess the flag" heuristic.

Tests: `tests/test_recon_no_resolve.py` — the rule, its idempotence, non-nmap commands
left untouched, program-name-not-substring matching, the lock-off case, and both real
proposal paths end to end. Eighteen existing assertions that pinned the verbatim command
were **restated, not weakened**: each still asserts what it always did (the command
reached the cage, was gated, was deduplicated), against the now-correct text.

Suite: **899 tests** (898 passed, 1 skipped).

<details>
<summary>Original note, kept for the record</summary>

Without `-n`, nmap attempts reverse-DNS on its targets. Those lookups go to resolvers
the egress lock blocks (only `tun0`, the pinned VPN server, and the scope IP are
permitted), so the lookup hangs and `Executor.run` kills the command at its 180s cap.

The failure is **indistinguishable from an unreachable host**: the command returns
`exit 124` with `Starting Nmap ...` and nothing else. Observed twice during Cap setup
before the cause was identified; the same scan with `-n` completed in **9.8 seconds**.

A hunt would burn its command budget on timeouts and read them as "nothing there" —
a silent coverage failure of the kind this project treats as its worst mode.

**Design note (not this session):** default recon proposals to `-n`, or have the
executor add it for DNS-capable tools when the egress lock is active.

</details>

---

## P2 — recorded 2026-08-10, not fixed (found while auditing the Cap `.61` run)

### SELF-REPORT DISAGREES WITH THE LEDGER (invariant 3)

**Severity: P2.** The generated report for `10.129.100.61` states
`Autonomous steps | 13` and `Commands executed | 13`. The hash-chained audit log
(`runs/audit_cap61.jsonl`) holds **10** `execution` entries, and `checkpoint.json`
lists **10** commands in `executed_cmds`. The report's count is almost certainly
summing web-plane actions into a row labelled "commands executed".

Invariant 3 says never trust an agent's self-report — but here it is the **reporting
layer itself** that publishes a number the ledger does not support. The audit log is
the evidence; a report that disagrees with it undermines the one artifact a reader is
supposed to be able to check. Whatever the row means, it must be derived from the
ledger and labelled as what it actually counts.

**Fix (not this session):** compute every count in the report from the audit log, and
separate "shell commands executed" from "governed web actions" as two labelled rows.

### TESTS WRITE INTO THE LIVE `runs/vault/` (evidence isolation)

**Severity: P2.** Running `python -m pytest` writes `report.md`, `report.json`,
`findings.json` and `brukal.sarif` into `runs/vault/` **at top level** — observed
2026-08-09 22:23, immediately after a suite run, alongside the real per-target
engagement directories.

The audit logs are hash-chained and unaffected, so this is not a tamper issue. It is an
**evidence-isolation** issue: test fixtures deposit synthetic findings into the same
tree that holds real engagement output, where a later reader — or a future run's
lesson-learning pass — cannot tell them apart by location alone. Engagement evidence
should be inert to the test suite.

**Fix (not this session):** point the vault root at a `tmp_path` fixture for the whole
suite (an autouse fixture or a `BRUKAL_VAULT` env override), and assert in CI that a
test run leaves `runs/` byte-identical.
