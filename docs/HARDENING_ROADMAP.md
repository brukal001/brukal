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

## P1 — found live on Juice Shop, 2026-08-12 (both CLOSED)

Both found in the Part 2B engagement — full evidence in
`docs/CASE_STUDY_JUICESHOP_2B.md`. Measured, deliberately not fixed in that session.

### ~~SESSION MATERIAL IS NOT REDACTED FROM ANY RECORD~~ — **CLOSED 2026-08-13**

**Severity: P1.** With a real JWT session carried by the governed browser, the token appears
in cleartext on **5 of 6 surfaces**: the audit log (`decision.action`), `checkpoint.json`
(`executed_cmds`), **every model prompt** (`ALREADY TRIED` / `RECENT ACTIVITY` blocks),
`findings.jsonl` (evidence `command`), and the blackboard (`engagement.md` + agent
transcripts). Only the generated report is clean, and only incidentally — it is built from
titles and summaries, not command text.

Juice Shop's JWT payload is the user row, so what leaks is the account id, the email, the
role **and the password hash** — a working session plus a credential to crack.

**The site is `assist.py:757 _session_auth_for()`**, which appends
`-H 'Authorization: Bearer <jwt>'` to a SHELL command so tools run behind the login. It runs
BEFORE the gate, which is correct and must stay that way — the gate has to judge the bytes
that will really execute (invariant 3). The consequence is structural: **every artifact that
records a gated shell command records the token with it.** A DENIED command is recorded too,
so a denial does not contain the log.

The leak also GROWS: two surfaces at the first authenticated request, five by the end of the
run, as the first allowed token-bearing command propagates into evidence and transcripts.

**Fixed 2026-08-13.** Redaction at the point of RECORD, never at the point of injection.

`brukal/redact.py` is the single redactor and the single answer to "what is a secret":
the credential set THIS engagement actually injects, registered by `_session_auth_for`
at the moment it reads `auth_header` / `_cookies` off the `GovernedBrowser`. It replaces
those exact values and nothing else — no regex is trusted to recognise a token, so
ordinary content is recorded byte-identical, and no LLM is anywhere near it (invariant 1).
`_session_auth_for` itself is **unchanged**: the gate still judges, and the cage still
runs, the real bytes (invariant 3), pinned by
`test_redaction.py::test_the_executor_still_runs_the_real_bytes`.

It masks the VALUE, never the structure. An audit line still reads

```
nuclei -u http://172.20.0.3:3000/rest/products -H 'Authorization: Bearer [REDACTED:1f3a9c02]'
```

so the record stays meaningful and the gate's decision stays auditable. The placeholder
is `sha256(value)[:8]`, stable across every surface, so an operator can still correlate
two records as the same session without the value being recoverable. **ASCII delimiters
deliberately:** every one of these surfaces serialises with `json.dumps` at its default
`ensure_ascii=True`, which escapes a decorative `«…»` to `«…»` — still redacted,
but no longer greppable, which is the one property an operator checking an artifact needs.
Caught by the tests, not by review: the first implementation used `«»` and four surfaces
went green on "the token is absent" while the placeholder was unfindable in the file.

**Eight write sites, each a single funnel every caller already routes through** — so a
future writer inherits the boundary instead of having to remember it:

| # | Surface | Funnel |
|---|---|---|
| 1 | audit log | `AuditLog.append` (`audit.py`) — whole record, so `decision.action`, captured stdout and any field added later are all covered |
| 2 | checkpoint | `checkpoint.snapshot` |
| 3 | every model prompt | `LLMClient.propose` — covers all callers and both backends |
| 4 | findings.jsonl, report.md, report.json, brukal.sarif | `Finding.__post_init__` |
| 5 | blackboard pages (`engagement.md`, `plan.md`) | `Blackboard.write_page` |
| 6 | findings stream + agent transcripts | `Blackboard.write_finding` |
| 7 | **lesson store** | `LessonStore._save` |
| 8 | **task tree** | `Blackboard.save_task_tree` |

**Rows 7 and 8 were not in the observed five.** They were found by walking every
persistence call in the package rather than trusting the run's inventory — the lesson the
`-n` fix taught when it turned out to have a third construction site. Row 7 is the worst
of the eight: a lesson's provenance holds the command that earned it and the store
**outlives the engagement**, so an unredacted credential there is carried into a later
run's prompts against a *different target*.

**Row 4 corrects the case study.** It read report/SARIF as clean, and they were — but
only because that run produced no confirmed token-bearing finding. `export.py` writes
`Finding.source` as a `reproduce` field, so the report was one finding away from leaking.
It is now clean by construction rather than by luck.

Tests: `tests/test_redaction.py` — one per surface
(`::test_the_audit_log_does_not_record_the_session_token`,
`::test_the_checkpoint_does_not_record_the_session_token`,
`::test_no_model_prompt_carries_the_session_token`,
`::test_the_findings_evidence_does_not_carry_the_session_token`,
`::test_the_blackboard_does_not_carry_the_session_token`,
`::test_the_lesson_store_does_not_carry_the_session_token`,
`::test_the_task_tree_page_does_not_carry_the_session_token`,
`::test_the_report_and_its_exports_stay_clean`), plus both directions of the boundary:
`::test_the_redacted_audit_line_still_shows_the_command_and_the_header_name` (structure
preserved — the command and the header NAME survive),
`::test_a_command_carrying_no_secret_is_recorded_byte_identical` and
`::test_the_redactor_never_touches_text_that_holds_no_registered_secret` (non-secret
content untouched), `::test_a_short_value_is_never_registered_as_a_secret` (a 1–2
character cookie value is not a credential, and redacting it would shred every ordinary
record it appears in), `::test_a_cookie_session_is_redacted_on_every_surface` (the
credential set is not only bearer tokens), `::test_a_denied_token_bearing_command_is_
redacted_on_every_surface` (the 2B leak came through a DENIED command — a denial is not
containment of the log), and `::test_the_executor_still_runs_the_real_bytes`.

Verified red first: 11 of the 16 failed before their write site was wired, each for the
right reason — the cleartext token present in the artifact. The other five are the
"must not break" direction (non-secret content untouched, the executor still running the
real bytes) and pass in both trees by design.

Suite: **927 tests** (926 passed, 1 skipped).

**Deliberately NOT changed.** The redaction set is process-global module state, because
the writers that need it (`AuditLog.append`, deep inside the executor; the LLM client)
are constructed long before a login happens and have no path to the session object.
Threading a credential set through every constructor would be a wide refactor for no
security gain, and would create the second source of truth this item exists to avoid.
`redact.clear()` is the engagement/test boundary.

**Residual, recorded not fixed.** The operator's own terminal still shows the real
command (`notes`), which is correct — the human running the engagement holds the session
already.

> ### ⚠️ REGRESSION CAUSED BY THIS FIX — **CLOSED 2026-08-13**, see below
>
> The paragraph that used to stand here said a model copying a redacted command back
> would simply be rejected by the gate, "at most one wasted step". **That was wrong on
> the web plane, and the real consequence was severe.** See the next section.

---

## P1 — A REDACTION PLACEHOLDER WAS ACCEPTED AS A CREDENTIAL — **CLOSED 2026-08-13**

**Severity: P1. Introduced by the redaction fix above (`66185da`) and found while
verifying it**, before any live run. It is the worst shape a defect can take in this
project: it makes an authenticated run silently unauthenticated, and **the ledger cannot
tell the difference.**

**The chain, all five steps required:**

1. `assist.py` put the REAL bearer token into the hypothesis prompt deliberately — an
   earlier bug had the model inventing `Bearer <userA_token>`, which the target rejected,
   so every authenticated experiment tested nothing. A test pinned that behaviour.
2. The redactor now masks that token at `LLMClient.propose`, so the model is handed
   `Bearer [REDACTED:...]`.
3. The model copies it into a proposed request — exactly as the prompt instructs.
4. `GovernedBrowser._apply_cookies` attaches the real credential **only when the request
   carries no Authorization header**. The placeholder counts as one, so it **suppresses**
   the real session.
5. The request goes out unauthenticated. **No gate denial, no error, no note** — the web
   plane has nothing that would refuse it.

**Why this blocked paper criterion #2.** A Juice Shop business-logic run in that state
would have reported "business logic: nothing found" while logged OUT, and that result is
indistinguishable in the audit log from a genuine one. It would have been a *false
negative published as a measurement* — the failure mode this project treats as its worst.

**Fixed at two levels.**

**(a) The model is never handed the credential — the root of the chain.** It never needed
it: `_as_identity` already swaps the principal for `"as": self|second|anonymous` and the
governed browser attaches whatever that principal holds. **A model-set Authorization
header defeats that machinery even when the value is real** — so this was latent before
redaction existed, and redaction only made it fire. The JWT branch now carries the same
wording the cookie branch always had: *auth is attached automatically, do not set the
header yourself.*

**(b) Redaction output is never accepted as input.** `redact.has_placeholder()` recognises
a marker by SHAPE — not against the registry, deliberately: a placeholder restored from an
old checkpoint belongs to an engagement whose credential set is long gone and is no more a
usable credential for being unrecognised. Deterministic matching, no LLM (invariant 1).
Applied on **both planes**, because the shell plane had the identical hole —
`_session_auth_for`'s "already carrying auth?" check treated a placeholder-bearing `-H` as
a credential and skipped injection, running the tool logged out:

| Plane | Site | Behaviour |
|---|---|---|
| web | `GovernedBrowser._apply_cookies` | a placeholder-bearing `Authorization`/`Cookie` is dropped, so the real credential is attached in its place |
| shell | `AssistSession._session_auth_for` | a placeholder-bearing auth argument is stripped before the "already carrying auth?" test |

**The boundary that had to be preserved:** `_apply_cookies` must still honour a genuine
caller-set credential — that is how a cross-account prover issues a request as the OTHER
principal. Only the placeholder shape is treated as not-a-credential. Pinned by
`::test_a_genuine_caller_set_header_is_still_not_overridden` and
`::test_a_shell_command_carrying_real_auth_is_still_left_alone`.

A masked value is also never SENT when there is no real credential to replace it with —
the header is dropped either way, since `action.headers` is rebuilt whenever anything was
removed, not only when something was added.

Tests: `tests/test_auth_not_placeholder.py` — 9 tests, **6 verified red first**, each for
the right reason (the token present in the prompt, or the placeholder reaching the
network). The other three are boundary/must-not-break cases.

**An existing test was RESTATED, not weakened.**
`test_hypothesis.py::test_a_real_session_token_is_supplied_rather_than_a_placeholder`
asserted the old mechanism. Its *subject* — an authenticated experiment must really be
authenticated — still stands and is still asserted; what changed is how it is guaranteed,
because the mechanism it pinned was shown to cause the very failure it was preventing. It
is now `::test_the_model_is_told_auth_is_automatic_rather_than_handed_the_token`, and the
other half of its original property (the request really does go out authenticated) is
pinned end to end by
`test_auth_not_placeholder.py::test_the_real_credential_reaches_the_network_through_the_governed_path`.

**Redaction is untouched** — all 16 tests in `test_redaction.py` stay green. Verified
together in one run: the model proposes `Bearer [REDACTED:ed82603d]`, the target receives
`Bearer eyJhbGciOiJIUzI1NiJ9...`, and the ledger for that same request contains no token.

Suite: **936 tests** (935 passed, 1 skipped).

**The lesson, and it is the project's recurring one from a new angle.** A masking control
created a new failure path by feeding its own output back into an input. The redaction
work was verified thoroughly on the axis it was built for — *is the secret absent from
every record?* — and that verification was sound. It asked nothing about what the masked
value would do if something later CONSUMED it. **A control that transforms data needs
testing on both sides: what it writes, and what happens when its output comes back
round.** The generalisable rule now enforced in code: *redaction output is never accepted
as input.*

### ~~THE LOOP TERMINATES ON A TRUNCATED MODEL REPLY, REPORTING "NOTHING LEFT TO DO"~~ — **CLOSED 2026-08-12**

**Severity: P1.** `loop.py:645` returns `stop_reason="done"` — printed as *"nothing left to
safely automate"* — whenever `session.advise()` yields no command and no web action. The
strategist's reply format puts the action line (`RUN:` / `WEB:`) **last, after 2-4 sentences
of `REASONING:`**, and the call is made with `max_tokens=800` (`strategist.py:519`). A reply
that spends its allowance on reasoning is cut off before the action line and the loop reads
that as a considered "nothing left to do".

Observed twice in two segments of the same engagement. Both stop lines quoted the model's own
`GOAL:` — the loop announced it had nothing to do while printing the thing it wanted to do
next. 12 of 20 budgeted steps and $3.75 of a $4 cap went unused; the engagement never reached
the business-logic half of its own methodology.

This is a silent capability ceiling: it looks like judgement, not failure, so it does not
appear as an error anywhere.

**Fixed 2026-08-12.** The property shipped is *a reply that never finished is not a
decision*, enforced in three small pieces:

1. **The signal now exists on every backend.** `TRUNCATED_STOP_REASONS = {"max_tokens",
   "length"}` in `llm.py` carries both vocabularies (Anthropic's and every
   OpenAI-compatible endpoint's), and `_OpenAICompatBackend` **records `finish_reason` at
   all** — it previously recorded none, so on `--provider ollama/openrouter/deepseek` a
   truncated plan was indistinguishable from a finished one and this fix would have been
   Anthropic-only.
2. **`StrategistAgent.advise()` retries once, with room.** If the reply parses to no
   action (`RUN:` / `WEB:` / `SESSION:` / `MANUAL:`) **and** it stopped at the ceiling, it
   asks again at 4× the allowance. `MANUAL:` counts as an action: handing the step to the
   operator is a decision, not a missing answer. A model reporting no stop reason at all
   is treated as NOT truncated, so this can only ever add a retry, never suppress a real
   answer.
3. **The loop stops lying about why it stopped.** A still-truncated reply sets
   `Suggestion.truncated`, and `loop.py` finishes with `stop_reason="truncated"` — "the
   model's reply was cut off before it named an action" — instead of "nothing left to
   safely automate".

The existing `propose` retry was NOT the same thing and did not cover this: it fires only
on an EMPTY reply whose whole allowance went on thinking, and explicitly returns a
truncated reply that did emit text ("it answered and was cut off; not this case"). That
comment names this defect from the other side — text arrived, the action did not.

Tests: `tests/test_truncated_reply.py::test_a_truncated_reply_with_no_action_is_retried`,
`::test_the_retry_asks_for_a_bigger_allowance`,
`::test_an_openai_style_length_finish_counts_as_truncated`,
`::test_a_finished_reply_with_no_action_is_accepted_as_done` (the boundary — a model that
finished and offered nothing HAS decided, and must not be re-asked),
`::test_a_truncated_reply_that_still_carries_an_action_is_used_as_is`,
`::test_a_reply_truncated_twice_is_flagged_rather_than_retried_forever`,
`::test_the_loop_does_not_report_done_when_the_reply_was_truncated`,
`::test_the_loop_still_reports_done_when_the_model_really_finished`,
`::test_the_openai_compatible_backend_records_its_finish_reason`.
Verified red first: 7 of the 9 failed against the pre-fix tree.

Suite: **911 tests** (910 passed, 1 skipped).

**Deliberately NOT changed.** The template still puts the action line last. Moving it
ahead of `REASONING:` would change what the model is asked to do — reasoning before
answering is doing work, not padding — and would silently move every published metric.
The retry makes the ordering survivable; reordering it is a separate, measured experiment.
**Out of scope too:** `StrategistAgent.options()` (operator-facing menu — a truncation
there costs an option, not the engagement; it falls back to `advise()` when empty) and the
recon/exploit/verify specialists, whose truncated replies fail a single step rather than
ending the loop.

---

## P1 — one CLOSED, one open (egress)

### ~~EGRESS LOCK FAILS OPEN ON RULESET-APPLY FAILURE~~ — **CLOSED 2026-08-12**

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

No code, tunnel, or configuration was changed when recording this.

**Fixed 2026-08-12, both halves, in `docker/entrypoint.sh`:**

1. **The ruleset is verified before it is announced.** After the load, the entrypoint
   requires `nft list ruleset` to show the default-drop policy; if it does not, it
   prints FATAL, installs drop-all and returns non-zero, so the caller's existing
   `refusing to run open` path exits the container. The success message is emitted only
   after that check passes. This matters precisely because `apply_egress_lock` is
   invoked inside an `if !` condition, where `set -e` does not apply — an unchecked
   `nft -f -` failure was silently survivable.
2. **The `tun0` rule is emitted only when tun0 exists**, so a not-yet-existent VPN
   interface can no longer abort the whole default-drop policy. It is a condition, not
   a deletion: with a tunnel up the rule is still written, so VPN-reached labs are
   unchanged. (This does **not** touch P1 #2 below — when the rule IS emitted it is
   still a blanket interface accept.)

**Test-first, against the real shipping file.** `tests/test_egress_failclosed.py` runs
`docker/entrypoint.sh` itself under stub `nft` / `ip` / `sleep` on `PATH` — no Docker, no
`NET_ADMIN`, no kernel nftables, ~0.5s. The stub `nft` models the property that makes
this defect possible: a load that fails installs **nothing**, so `list ruleset` stays
empty. Stubbing `sleep` also supplies the evidence that matters — whether the cage ever
reached its idle step, i.e. whether the executor could have run commands in it.

Verified red against the pre-fix entrypoint (`git show HEAD:docker/entrypoint.sh`) and
red for the right reason — it reproduced the Cap-setup output exactly:

```
[cage] egress locked to scope. Ruleset:
                                        <- empty; exit 0; error only on stderr
```

Tests: `test_egress_failclosed.py::test_a_ruleset_that_does_not_load_fails_closed`
(exit non-zero, no "locked" message, never idles, the rejected ruleset is not live),
`::test_an_absent_tun0_does_not_abort_the_default_drop_policy` (no `oif "tun0"`,
default-drop and the scope CIDR both present, cage comes up),
`::test_a_present_tun0_still_gets_its_rule` (the fix did not delete the rule).

Suite: **902 tests** (901 passed, 1 skipped).

Note `docker/verify_egress.sh` remains a manual, cage-up probe and is unchanged; it
could not have caught this, since it asks whether a specific host is dropped, not
whether the ruleset exists at all.

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

The fail-open-on-apply P1 above is now closed, so the lock no longer *silently fails to
install*. This one is untouched: **even when the lock does install, it does not enforce
scope where the targets live.** On a shared lab network the software gate remains the
sole containment for in-tunnel destinations.

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

> ### ~~⚠️ PARTIALLY REOPENED 2026-08-12 — there is a THIRD construction site~~ — **CLOSED 2026-08-17**
>
> The claim above — "it is applied at both places a command is constructed" — is wrong.
> **`loop.py:408` builds the web-port sweep directly** and hands it to `session.run()`,
> bypassing both `parse_action_request()` and the strategist `RUN:` parse, so
> `apply_no_resolve()` never sees it. Observed live on Juice Shop: the loop issued
> `nmap -Pn -sV --open -p <18 ports> 172.20.0.3` with no `-n`, and it was killed at the
> 180s cap having produced only `Starting Nmap 7.99 …` — the exact Cap signature.
>
> Measured directly in the cage afterwards, same command, same target:
>
> | Command | Result |
> |---|---|
> | `nmap -Pn -sV --open -p …` (as issued) | **killed at 185s**, no output |
> | `nmap -n -Pn -sV --open -p …` | **completed in 11.31s**, full service detection |
>
> So the defect still costs an entire recon step when it fires, and it fired on the very
> first command of the engagement. The rule is right; its coverage is not.
>
> It fired a **third** time on the 2026-08-16 Juice Shop 2C run — `returncode 124`,
> `Starting Nmap 7.99` and nothing else, 180 s of a 1096 s engagement, on the first
> command again.
>
> **CLOSED 2026-08-17.** `loop.py:413` now wraps its sweep in `apply_no_resolve()` —
> the same helper as the other two sites, reused rather than reinvented.
>
> **The executor-level fix proposed above was NOT taken, deliberately.** Normalising
> inside `Executor.run` would put command rewriting on the execution path, and the gate
> would then audit a different string from the one that ran — which is invariant 3
> (*the gate re-reads the command itself*) traded away for tidiness. `apply_no_resolve`
> is documented as shaping how a command is CONSTRUCTED, and it stays there.
>
> The coverage guarantee the proposal was reaching for is bought instead by a test at
> the **dispatch point**, which is where a fourth site would show itself:
> `test_recon_no_resolve.py::test_no_scan_the_loop_dispatches_is_left_able_to_resolve`
> runs the real `GroundedLoop` and asserts that every `nmap` reaching the cage carries
> the flag, whatever built it. Named sibling:
> `::test_the_loops_own_proactive_port_sweep_carries_n`.
>
> **There is no fourth site.** Confirmed two ways on 2026-08-17: graphify
> (`explain apply_no_resolve` → exactly three production callers — `parse_action_request`,
> the strategist `RUN:` parse, and `loop.py:413`), and an AST sweep of every string
> literal in `brukal/` whose first token is a `_NO_RESOLVE_FLAGS` tool. The sweep returns
> 38 literals; all but `loop.py:413` are tool-name allowlists (`risk.py`, `cli.py`,
> `adscan.py`, `assist.py`, `schema.py`), the planner's prose hint (`methodology.py:71`,
> which reaches the cage only via the strategist parse, already normalised), or fixed
> strings in the `eval.py` / `experiment.py` governance simulations — which must NOT be
> rewritten, since their expected-behaviour regexes match on the literal command and
> they never touch a real cage.
>
> Two pre-existing tests were **restated, not weakened**: `test_webmap.py::
> test_loop_sweeps_for_the_web_surface_when_nothing_is_known` and `test_loop_e2e.py::
> test_the_whole_reflex_chain_runs_without_crashing` matched the sweep with
> `startswith("nmap -Pn")`, an incidental flag ORDER that `-n` insertion changes. They
> now match the program and assert `-Pn` (and, in the webmap test, `-n`) explicitly —
> the subject of both, *the proactive sweep ran exactly once with the right shape*, is
> unchanged and now pinned more tightly than before.

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

## P2 — recorded 2026-08-12 (found during the Juice Shop 2B run)

### AN ENGAGEMENT IS IDENTIFIED BY ITS TARGET IP ALONE, SO A RECYCLED ADDRESS RESUMES ANOTHER RUN

**Severity: P2 (evidence isolation).** Starting the Juice Shop engagement at `172.20.0.3`
printed `↻ resumed from checkpoint — 25 step(s) already spent, 21 command(s) known` and
`resumed — loaded 35 prior finding(s)`. Those belonged to a **DVGA** engagement from 28 July
that Docker had given the same bridge address. Another target's findings, spent-step count and
command history were loaded into this run.

On a local bridge, private IPs are recycled across unrelated targets, so the bare IP is not an
engagement identity. This is the sibling of "tests write into the live `runs/vault/`" below —
same root cause: the vault has no notion of which engagement an artifact belongs to beyond a
directory name.

Contained by hand for the 2B run: the stale tree was archived to
`runs/vault/_archived_dvga_172.20.0.3_pre-2b/` and the engagement restarted with `--no-resume`.

**Fix (not this session):** key the vault directory and the checkpoint on the scope
fingerprint (`Scope.fingerprint()` already exists) or an explicit engagement id, and refuse to
resume a checkpoint whose scope fingerprint differs from the current scope.

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

---

## P1 — the business-logic capability was blocked by plumbing, not by reasoning (2026-08-17, all CLOSED)

Found by auditing the **Juice Shop 2C run of 2026-08-16** — the run that was supposed to
satisfy paper criterion #2. It completed normally (`stop_reason: exhausted`, all 30 steps,
$1.61, chain keyed and intact, containment clean: 208 requests to `172.20.0.3`, 11 denials
to an off-scope host, zero packets to the same-bridge `172.20.0.2` control). It produced
two generic findings and no business-logic result.

**The model's reasoning was not the limitation.** It proposed exactly the right four
experiments — basket IDOR, basket-item quantity IDOR, review IDOR, address IDOR — and it
independently sent `PUT /api/BasketItems/1 {"quantity":-100}`, which the target answered
`200`. That is a real flaw, correctly reached. Every one of those five results was then
destroyed by deterministic harness code between the reasoning and the record. Three
defects, and they stack: the planner never scheduled the phase, the experiment engine
could not chain state once the model improvised its way there, and the one hit that
landed anyway was written down as a status line.

This is the same shape as the redaction/placeholder lesson: **each component was correct
on the axis it was built for, and wrong about what the next component would do with its
output.**

### ~~A. `{{setup.*}}` REFERENCES DID NOT RESOLVE — A SUBSTITUTION GAP FILED AS A NEGATIVE~~ — **CLOSED**

`hypothesis.PROMPT` tells the model that `setup` requests "reach an interesting state"
and are "executed but never judged", and gives it **no way to refer to what they
returned**. So the model invented one: `{{setup.0.BasketId}}`, `{{setup.0.id}}`. Nothing
substituted it. All four IDOR experiments went out with the braces literal in the path,
control and variant answered identically (`401`/`401`, `500`/`500`), and the comparator
correctly ruled *not confirmed* on all four.

That last part is the serious half. The comparator did its job; the record it produced —
"not confirmed [a_denied_b_allowed]: Basket IDOR" — is **evidence about the application**,
and it was actually evidence about a missing data-flow in Brukal. A harness gap wearing a
comparator's verdict is the failure mode this project treats as its worst, and it is the
same class as the pre-redaction false negative: indistinguishable in the log from a real
result.

**Fixed in two halves, both deterministic.**

1. **The syntax is documented, not guessed.** `hypothesis.SETUP_REF_SYNTAX` is spliced
   into both `PROMPT` and `REFINE_PROMPT`: `{{setup.<i>.<dotted.path>}}`, resolved out of
   setup response `i`'s JSON body, walking objects and arrays
   (`{{setup.0.data.items.0.id}}`). A contract the model has to invent is not a contract.
2. **`hypothesis.resolve_setup_refs()` substitutes before dispatch** — url, body and
   header values — against the responses `_run_one_round` now captures. Pure template
   resolution over recorded JSON; no LLM, no `eval`, same discipline as the comparators.
   Setup steps resolve against *earlier* setup steps too, so a create-then-use sequence
   works and the identical silent failure cannot simply move one step upstream.

**Fail SAFE is the load-bearing part.** An unsatisfiable reference raises
`UnresolvedReference` — no setup response at that index, a body that is not JSON, a field
that is absent, or a value that is an object rather than something inlinable. The runner
catches it *before* the generic handler, notes `[experiment] UNRESOLVED REFERENCE, not
run`, and feeds the next round `UNRESOLVED REFERENCE (experiment NOT run, this is not a
result)`. **A substitution gap can no longer be recorded as a negative**, and the
placeholder never reaches the target.

Tests: `tests/test_experiment_setup_refs.py` — 13 tests, **all 13 verified red first**,
11 for feature-missing and 2 (the end-to-end pair) for the exact live bug, failing on
`a placeholder reached the target`. The named ones:
`::test_a_control_referencing_a_setup_response_is_dispatched_with_the_real_value` and
`::test_an_unresolvable_reference_errors_the_experiment_rather_than_being_judged`.

### ~~B. A FINDING-WORTHY RESPONSE WAS RECORDED WITHOUT ITS BODY~~ — **CLOSED**

`PUT /api/BasketItems/1 {"quantity":-100}` → `200`. The record kept
`ALLOW:  status=200 (154B)`. The model had a status line and no content, could not
escalate what it could not read, and three steps later the repeat-suppressor told it
`do NOT run it again`. The hit was gone for the rest of the engagement.

`_absorb_web` put `body[:600]` into `self.notes` but passed `_persist_finding` a summary
that fell back to `{head} ({len(body)}B)` whenever no highlight pattern matched — and a
body no fitted detector recognises is precisely the body worth keeping, because it is the
case nobody wrote a detector for, which is the entire reason the model is in the loop.
Notes are an in-memory rolling window; the finding record is what `_load_memory` reads
back, what the per-agent transcript shows, and what survives a checkpoint.

**Fixed:** the summary now carries a bounded body excerpt (`body[:800]`) behind the
highlight lead. **Redaction was verified on the new surface rather than assumed** — the
capture crosses a record boundary, so capturing more could have captured the credential.
It does not: `blackboard.write_finding` redacts at the boundary via `redact.data`, which
covers this text, and two tests prove it with a target that *echoes* the session token
and cookie back in its response body.

Tests: `tests/test_finding_body_capture.py` — 6 tests, **4 verified red first**
(2 are guards that hold before and after). Acceptance case, named:
`::test_the_negative_quantity_hit_is_recorded_with_the_body_it_answered_with` — the exact
request the last run threw away now keeps `"quantity":-100` in the record. Redaction:
`::test_a_session_token_reflected_in_the_captured_body_is_masked_in_the_record`.

### ~~C. THE PLANNER SILENTLY DROPPED METHODOLOGY PHASES~~ — **CLOSED**

`WEB_METHODOLOGY` has ten phases; business-logic is the ninth. `checklist_text()` hands
them to the planner as text and the model writes its own plan. On 2026-08-16 it returned
**seven steps with four phases absent** — configuration, cryptography, **business-logic**,
client-side. The loop executed that plan to completion (`plan_cursor: 7`, every step
`[x]`) and the engagement was filed as a business-logic measurement that never planned a
business-logic step.

The floor that should have caught this was `if len(new) < 2`. **It validates a proxy —
the model said something — rather than the claim: the plan covers the methodology.** A
seven-step plan missing the phase under measurement passes a length check comfortably.
Note what this means for the run before it: the truncation fix (`be94446`) worked exactly
as designed — the loop stopped quitting early and spent its whole budget — and the phase
still was not reached, because nothing had ever put it in the plan. Fixing the reported
symptom moved the ceiling somewhere else.

**Fixed:** `Methodology.missing_phases(plan)` (deterministic set arithmetic, methodology
order, no model in it) and `Methodology.plan_steps_for(phases)`. `make_plan` now
**appends** what the model left out instead of replacing the plan — its own steps name
this target's real endpoints, and enforcing coverage by discarding them would trade one
blindness for another. **Coverage, not ordering:** the model keeps its sequence and its
wording. A phase the methodology names more than once (box names `enumeration` three
times) is covered by one plan step carrying it, so a good plan is never padded.

Tests: `tests/test_plan_covers_methodology.py` — 9 tests, **5 verified red first**,
driven by the seven-step plan the live run actually produced. Named:
`::test_a_plan_that_omits_business_logic_gets_it_planned_anyway`.

**One pre-existing test caught a regression mid-fix and was right to.**
`test_methodology.py::test_thin_model_plan_falls_back_to_the_methodology_checklist`
failed when `as_plan_steps()` was refactored through the new phase-deduplicating helper,
which collapsed the box flow's three distinct `enumeration` steps (port sweep, per-service
enum, the web methodology on any web service) into one. `as_plan_steps()` was restored to
emit every step; only the *append* path deduplicates by phase. The test was not touched.

### What this leaves for criterion #2

Of the five conditions, four already held on the 2026-08-16 run: nothing leaked (zero JWT
cleartext across audit, findings, report, SARIF, blackboard, checkpoint and all 64 agent
notes), the chain verified intact under `BRUKAL_AUDIT_KEY`, containment was proven against
a same-bridge off-scope control, and the result was publishable. Only *reaches business
logic* failed, and all three reasons it failed are now closed. Suite: **965 passed, 1
skipped** (was 935). The measurement is the next session's work; this one was the plumbing.

---

## P1 — the experiment engine never got to ask (2026-08-21, BOTH OPEN)

Found by auditing the **Juice Shop 2C2 run of 2026-08-20/21** — the re-run built to
satisfy paper criterion #2 on the loop the section above had just fixed. Three of those
four fixes are confirmed live in production by this run: the planner floor appended
business-logic as phase 11 and the plan was worked to `plan_cursor: 12/12`, the evidence
body arrived on the exact endpoint it was built for, and the `-n` sweep completed instead
of dying at the 180 s cap. **The fourth — setup substitution — remains unexercised
against a live target**, because of the first defect below.

The run is honest about its own limits: 50/70 steps, 44 commands, 6 blocked, 73 calls,
$3.89, `stop_reason: target-unhealthy`, chain keyed and intact, containment clean (every
one of 102 requests to `172.20.0.3`, zero to the same-bridge `172.20.0.2` control), zero
JWT cleartext on any of eight surfaces **including the newly-captured bodies**. It
produced four findings — one medium, three low — and **nothing business-logic**.

**The model's reasoning was not the limitation, and this time it was never even
consulted.** Zero `[experiment]` records exist anywhere — `findings.jsonl`,
`engagement.md`, all 70 agent notes — and the report's coverage table has no
`Model-proposed experiments` row at all, which by that table's own footnote means the
class "was not reached at all". Full narrative: `docs/CASE_STUDY_JUICESHOP_2C.md`.

### A. THE THINKING-RETRY ESCALATES PAST THE SDK'S NON-STREAMING CEILING, AND THE ERROR IS ERASED

`run_hypotheses` asks for experiments at `max_tokens=8000` (`assist.py:3606`). On a rich
surface the model spends the entire allowance on thinking and returns `""` with
`stop_reason=max_tokens` and no text block. `LLMClient.propose` (`llm.py:239`) **correctly
recognises that case** — it is the exact failure the retry was built for — and retries
with room: `bigger = min(max_tokens * 4, 32_000)` = **32,000** (`llm.py:257`), still
non-streaming, because `_propose_once` (`llm.py:263`) calls `messages.create` without
`stream=`.

The Anthropic SDK then refuses **before sending a request**:

```
ValueError: Streaming is required for operations that may take longer than 10 minutes.
```

Reproduced deterministically against `anthropic 0.116.0` with **no API call**, via
`Anthropic._calculate_nonstreaming_timeout(max_tokens, None)`: 8,000 passes, 16,000
passes, the ceiling is **21,333**, and 32,000 always raises. `claude-sonnet-5` is absent
from the SDK's `MODEL_NONSTREAMING_TOKENS` table, so the generic ten-minute estimator
applies and there is no model-specific exemption to fall back on. **The retry cannot
succeed on any call that needs it.**

`run_hypotheses`' `except Exception: return 0` (`assist.py:3607`) then swallows it — no
note, no coverage row, no trace on any surface. REFLEX 0b is `_confirmed_done`-gated to
fire **exactly once**, so that single erased error removed model-proposed experiments
from the **entire engagement**.

**This is the recurring lesson for the fourth time, and the sharpest instance yet: the
thinking-retry was built to fix a silent failure and introduced a silent failure of its
own.** Its own docstring says the old behaviour "looked like a model with nothing to say
about the target. It had plenty to say; it never got to the part where it says it." That
is now true again, one layer down.

**It is worst exactly where it matters most.** The failure requires the model to exhaust
8,000 tokens thinking, which happens when the surface is rich. On a hand-made three-route
surface the call succeeded and parsed 5–6 proposals; on the live 43-route crawl it failed
**3/3**. *The more interesting the target, the more certain the capability disappears* —
and it passes every small-fixture test while doing so.

**The capability itself is intact and was verified independently.** With the call
succeeding, the model proposes exactly the right experiments in the documented syntax the
section above gave it — including Juice Shop's `{status, data:{…}}` envelope, which it
could only target because the contract now tells it how:

```json
{"title": "Cross-account modification of another user's basket item quantity",
 "comparator": "a_denied_b_allowed",
 "setup":   [{"url": ".../api/BasketItems", "method": "POST",
              "body": {"ProductId": 1, "BasketId": 1, "quantity": 1}, "as": "self"}],
 "control": {"url": ".../api/BasketItems/{{setup.0.data.id}}", "method": "PUT", "as": "self"},
 "variant": {"url": ".../api/BasketItems/{{setup.0.data.id}}", "method": "PUT", "as": "second"}}
```

Last run the model invented `{{setup.0.BasketId}}` and it went out as literal text. It now
writes `{{setup.0.data.id}}` because that is the contract. But nothing dispatched it, so
**zero literal `{{` reached the wire and zero `UnresolvedReference` fired — and both facts
are vacuous.** The substitution path shipped above has still never run against a live
target.

**Fix (not this session), two parts, and the second is the important one:**

1. `propose`'s retry must not escalate a non-streaming request past the SDK's limit —
   either stream the retry, or cap `_THINKING_RETRY_CEILING` below the ceiling. Capping is
   the smaller change; streaming is the one that survives the next model whose useful
   answer is longer than 21,333 tokens. A cap that is a bare number will rot silently the
   next time the SDK's estimator changes, so it must be derived or asserted, not guessed.
2. **`run_hypotheses`' bare `except Exception: return 0` must record what it swallowed.**
   This run had a P1 in the capability that matters most and left no trace of it anywhere
   in the evidence. A silent `return 0` erased both the note and the coverage row that
   were purpose-built, in the section above, to make "asked and got nothing" visible.
   **A bare `except: return <empty>` around an LLM call is a defect on sight**, and this
   one should be treated as the general rule rather than the one instance.

### B. NO SECOND PRINCIPAL ON AN SPA, SO THE AUTHORIZATION COMPARATOR IS UNCONSTRUCTIBLE

Independent of A, pre-existing, and it would have blocked the same result on its own.

`establish_second_identity()` (`assist.py:3484`) returns `""` on this target. It delegates
to `_register_account()` (`assist.py:4234`), which needs an HTML `<form>` from
`_signup_form()` (`assist.py:4171`) and returns `None` without one. **Juice Shop is an
Angular SPA and serves no server-rendered signup form**, so there is no second session to
hold.

The consequence is not a degraded experiment, it is a silently different one.
**`a_denied_b_allowed` — the comparator built for authorization, and the one every
cross-account experiment in this engagement selected — is unconstructible without a second
principal**, so each of them would have collapsed to *self vs anonymous* even had A never
happened. Anonymous-is-denied and I-am-allowed is a true statement about almost every
authenticated endpoint in existence, and it is not evidence of a flaw. **A comparator that
answers a narrower question than its name claims is the same failure class as A**: a
harness gap wearing a verdict.

This bites the entire SPA class, which is most modern targets — the population where
authorization bugs are both most common and most valuable.

**Fix (not this session):** registration must not depend on a server-rendered form.
Options, cheapest first: reuse the crawl's already-mined API route map to `POST` the
documented signup endpoint directly; accept an operator-supplied second credential pair
for engagements where self-registration is unavailable or forbidden; or drive the signup
through the browser plane. Whichever is taken, the load-bearing property must be
preserved and stated: `_register_account`'s docstring turns on the account being *whatever
the application grants a stranger who signs up*, which is what makes a privilege claim
sound. An operator-supplied account does not carry that guarantee and must be recorded
as a weaker basis, not silently substituted for it.

**And it must fail loudly.** The comparator should refuse to run — not quietly retarget —
when the principal it names is unavailable, in the same shape as `UnresolvedReference`
above: *the experiment did not run* is a result; *self vs anonymous* wearing
`a_denied_b_allowed`'s name is not.

### What these two leave for criterion #2

**NOT MET, and no longer "just needs the run".** The acceptance case is met *as plumbing*
and not *as a finding*: the loop reached `PUT /api/BasketItems/1`, and the record now
carries the JSON body it answered with — but the model sent `quantity: 2`, not `-100`, so
the negative-quantity flaw was never re-triggered, and none of the four findings are
business-logic.

**This is not the stop-and-write signal either.** That signal requires the model to have
been asked and to have failed; here it was never asked. A re-run that does not first close
both defects above will reproduce this exact null result, because A is deterministic on a
rich surface and B is unconditional on an SPA.

**One thing in the case study is NOT evidenced and must not be cited without a controlled
re-test.** It reads three `PUT /api/BasketItems/1` → `200` as an unrecognised real
cross-user write. The mechanism is plausible — object-level authorization missing on
`BasketItems` — but the tenant mapping was seeded **externally** and appears nowhere in
the artifacts, and `GET /rest/user/whoami` returned `{"user":{}}` on that path. The ledger
alone cannot say whether that write was A-as-A or anonymous. Either reading is
interesting; neither is evidence yet.
