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

(`1f3a9c02` here is the **redaction placeholder's** own 8-hex tag — `[REDACTED:<hash>]`,
derived from the masked value — **not a commit reference**. Same for `ed82603d` below.
`git-filter-repo`'s 2026-08-13 scan for commit hashes in messages flagged both as
"filtered out but still referenced"; they were never commits, and nothing is missing.)

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

**Severity: P1. Introduced by the redaction fix above (`60b47e6`) and found while
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
together in one run: the model proposes `Bearer [REDACTED:ed82603d]` (again an illustrative
redaction tag, not a commit), the target receives
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

> ⏱ **THIS CONSTRAINT EXPIRED 2026-09-11, and is recorded as expired rather than quietly
> overridden.** It rested on protecting published metrics. The paper is deferred by
> decision, and every metric it protected is superseded by runs CM1 and CM2. The reason
> not to reorder is gone; the cost of not reordering was measured twice — CM1 stopped at
> step 16 of 70 and CM2 at step 22 of 70, both on a reply truncated at 800 and again at
> its 4x retry, CM2 leaving $10.55 of a $12.00 cap unspent. Reordered in the commit that
> carries this note. The half of the original reasoning that was never wrong is honoured:
> `REASONING:` is still asked for, still 2-4 sentences, and still recorded — the answer
> moved, the thinking did not.
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

**Update 2026-08-22 — the same defect has now been found in the DOCUMENTATION, three
times.** An audit re-derived every run-level number in these files from the artifacts, and
three did not reproduce — each for the identical root cause: **a count published without
saying what it counts.**

| Written | Where | Actual | What the number is |
|---|---|---|---|
| "238 requests" | case study §5 | **102** | answered web requests (`web_result`); 106 were decided, 208 ledger entries across both |
| "208 requests" | roadmap, 2C | **206** | 109 `web_decision` + 97 `web_result` |
| "11 denials" | roadmap, 2C | **10** | `hard:web-scope` denials; 13 `DENY` in total |

The first is the worst of the three: **two documents gave different figures for the same
run** (238 in the case study, 102 in the roadmap), and neither said which quantity it meant,
so no reader could tell that they disagreed — or which to believe. All three are corrected
and labelled. This is the report-layer defect above reappearing one layer out, in prose
written *about* the ledger rather than *by* it, which is the harder place to catch it: a
report can be regenerated from the audit log, a paragraph cannot.

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

### THE SUITE READS A LIVE ENGAGEMENT ARTIFACT, SO IT DOES NOT PASS ON A FRESH CLONE

**Severity: P2.** The same root cause as the entry above, in the opposite direction:
that one *writes* into engagement evidence, this one *reads* from it.

`tests/test_coverage.py:78` —
`::test_every_class_that_produced_a_finding_appears_in_the_table` — opens
`runs/vault-wb/172.20.0.5/findings.json` with a bare relative `Path(...)`. That file is
real engagement output from 2026-08-03, and `.gitignore:63` excludes `runs/`, so **it is
in no clone of this repository**. The test passes here only because that August output
still happens to be sitting in the working tree.

Found 2026-08-22 while verifying a six-commit split in a scratch clone. It failed at all
six commits **including the untouched baseline `ccd38fe`**, which is precisely what
identified it as environmental rather than a bad split — a defect introduced by the split
would not have been red before the split. In a clone the suite is **964 passed, 1 failed**
with `FileNotFoundError`, at every commit.

**Why this one is worse than it looks.** The project claims **reproducibility** as one of
its four win-axes, and the docs-truth tests pin an exact suite count as a published fact.
That count is currently reproducible on exactly one machine. **A reviewer who clones the
repository to check the paper's claims gets a red suite on the first command they run**,
and it fails identically in CI — so the axis the paper argues on is the axis the suite
itself does not satisfy. It also silently weakens the test: on any machine where the
artifact is missing the coverage promise it exists to enforce is not being checked at all.

**Fix (not this session):** either commit a small fixture for this case, or skip the test
when the artifact is absent — **a skip is honest; a pass that depends on one machine's
untracked files is not.** Do it together with the sibling P2's `tmp_path`/`BRUKAL_VAULT`
fix, so `runs/` becomes inert to the suite in both directions at once, and assert the
whole thing in CI from a clean clone rather than from a developer's working tree.

---

## P1 — the business-logic capability was blocked by plumbing, not by reasoning (2026-08-17, all CLOSED)

Found by auditing the **Juice Shop 2C run of 2026-08-16** — the run that was supposed to
satisfy paper criterion #2. It completed normally (`stop_reason: exhausted`, all 30 steps,
$1.61, chain keyed and intact, containment clean: **206 ledger entries for web traffic — 109
gate decisions (`web_decision`) and 97 answers (`web_result`) — all to `172.20.0.3`**, **10
`hard:web-scope` denials** of an off-scope host (13 `DENY` verdicts in total, the other three
being `hard:capability`, `hard:injection` and `hard:web-rate`), zero packets to the
same-bridge `172.20.0.2` control). It produced
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
Note what this means for the run before it: the truncation fix (`37b3957`) worked exactly
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

## P1 — the experiment engine never got to ask (2026-08-21; A CLOSED 2026-08-22; B — fail-safe closed 2026-08-22, CAPABILITY GAP OPEN)

Found by auditing the **Juice Shop 2C2 run of 2026-08-20/21** — the re-run built to
satisfy paper criterion #2 on the loop the section above had just fixed. Three of those
four fixes are confirmed live in production by this run: the planner floor appended
business-logic as phase 11 and the plan was worked to `plan_cursor: 12/12`, the evidence
body arrived on the exact endpoint it was built for, and the `-n` sweep completed instead
of dying at the 180 s cap. **The fourth — setup substitution — remains unexercised
against a live target**, because of the first defect below.

The run is honest about its own limits: 50/70 steps, 44 commands, 6 blocked, 73 calls,
$3.89, `stop_reason: target-unhealthy`, chain keyed and intact, containment clean (every
one of **102 answered web requests** (`web_result`; 106 gate decisions) to `172.20.0.3`, zero
to the same-bridge `172.20.0.2` control), zero
JWT cleartext on any of eight surfaces **including the newly-captured bodies**. It
produced four findings — one medium, three low — and **nothing business-logic**.

**The model's reasoning was not the limitation, and this time it was never even
consulted.** Zero `[experiment]` records exist anywhere — `findings.jsonl`,
`engagement.md`, all 70 agent notes — and the report's coverage table has no
`Model-proposed experiments` row at all, which by that table's own footnote means the
class "was not reached at all". Full narrative: `docs/CASE_STUDY_JUICESHOP_2C.md`.

### ~~A. THE THINKING-RETRY ESCALATES PAST THE SDK'S NON-STREAMING CEILING, AND THE ERROR IS ERASED~~ — **CLOSED 2026-08-22**

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

**Fixed in two halves. The retry is STREAMED, and the swallow now speaks.**

1. **`_propose_once` grew a `stream` parameter, and the retry — only the retry — uses
   it.** The request dict is built once and dispatched either way, so usage, stop reason,
   block kinds and text are parsed by one code path and cannot drift between transports.

   **Streamed, not capped, and the distinction is the whole lesson.** Capping
   `_THINKING_RETRY_CEILING` under 21,333 would have been one character of work and would
   have fixed the instance. That number is not ours: it is derived by the SDK from the
   model and a ten-minute estimate, `claude-sonnet-5` is absent from
   `MODEL_NONSTREAMING_TOKENS` so the generic estimator applies, and either half can move
   in a patch release — at which point a cap chosen to dodge it fails silently again, in
   the same place, for the same reason. The ceiling's comment now says it is a **cost**
   bound, deliberately above the SDK limit, and must not be lowered to stay under it.

   The blast radius is one call. The retry is the only request that can cross the limit,
   so every ordinary call still goes out non-streaming and unchanged.

2. **`run_hypotheses`' `except Exception: return 0` records what it caught** — a note
   naming the exception type and message, and a coverage row with `probes=0`. What is
   caught is **not** widened: it still returns 0 and the engagement still continues. The
   change is only that the failure stops being invisible.

   **The sweep found a sibling, and it is fixed in the same commit.** `loop.py` wrapped
   the *same call* in `except Exception: pass`, guarding everything raised outside the
   inner handler — parsing the reply, writing the coverage row, a round escaping its own
   guard. Left alone it would have reproduced the identical blindness for a slightly
   different failure, on a reflex that fires once. An AST sweep of the package for bare
   `except`/`except Exception` handlers returning an empty or zero value found **111
   such handlers, of which exactly 2 sit on an LLM call** — these two. The rest are
   parse- and probe-level and out of scope here.

**Both boundaries bought by earlier P1s were verified on the new path, not assumed.**
The streamed reply still carries its stop reason and its usage to the client, so the
truncation fix holds on the transport that did not exist when it was written. And the
prompt is still redacted: `LLMClient.propose` redacts *before* the backend is handed
anything and the retry re-uses that same text rather than rebuilding it, so redaction
write site #3 covers the new path by construction. A test registers a session token,
drives a real retry, and asserts the token is absent from — and its placeholder present
in — what the streamed call receives. A retry that rebuilt its prompt would have posted
the credential to a provider on the retry only, where nobody looks.

Tests: `tests/test_streaming_retry.py` — 11 tests, **8 verified red first**: 6 failing
with the real `ValueError: Streaming is required...` raised by a stub that refuses above
the ceiling exactly as the SDK does, 1 on the redaction precondition (no streamed prompt
was ever captured, because the retry never happened), and 1 because the raise escaped
`propose` entirely. Named:
`::test_a_retry_above_the_nonstreaming_ceiling_is_dispatched_rather_than_raising` and
`::test_capping_below_the_ceiling_is_not_what_fixes_this`, which fails if a future change
shrinks the retry under the limit instead of streaming past it.
`tests/test_swallow_records.py` — 5 tests, **3 verified red first** (an empty note
surface, an empty coverage dict, and the loop helper absent). Named:
`::test_a_failed_proposal_call_reaches_a_surface_instead_of_returning_zero` and
`::test_the_loops_outer_swallow_also_records_what_it_caught`.

One pre-existing test was **restated and strengthened, not weakened**:
`test_thinking_budget.py`'s `_Recorder` overrode `_propose_once` with the old three-
argument signature and broke on the new keyword. It now records the transport per call,
and `::test_a_reply_lost_to_thinking_is_retried_with_a_bigger_budget` additionally
asserts `streamed == [False, True]` — the file's subject is unchanged and it now pins
more than it did.

Suite: **981 passed, 1 skipped** (was 965).

**What this does NOT close.** The substitution path from the section above is still
unexercised against a live target — this fix makes the model reachable again, it does not
prove what the model then does. And **B below is untouched**, so the comparator that every
cross-account experiment selects remains unconstructible on an SPA. Criterion #2 needs
both.

### ~~B. NO SECOND PRINCIPAL ON AN SPA, SO THE AUTHORIZATION COMPARATOR IS UNCONSTRUCTIBLE~~ — **CLOSED for JSON-signup targets 2026-08-22 (`8c4f941`); still open where neither door exists**

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

---

#### Update 2026-08-22 — the FALSE-NEGATIVE PATH IS CLOSED. The CAPABILITY GAP IS NOT.

Read the two halves separately, because only one of them moved.

**CLOSED — a missing principal can no longer wear a verdict.** Tracing the degradation
in code rather than inferring it showed it was worse than recorded above. `_as_identity`
resolved a missing second identity to `browser._cookies = {}` and
`browser.auth_header = ""` — **byte-identical to the `anonymous` branch two lines above**
— so the request was not merely mis-attributed, it was *dispatched to the target* and
then *judged*. And it ran in **both** directions:

| arrangement | comparator says | what it really means |
|---|---|---|
| control `self`, variant `second`→anon | **NOT CONFIRMED** | a false negative that reads as evidence about the application |
| control `second`→anon, variant `self` | **CONFIRMED, high** | "an authenticated request succeeds where an anonymous one does not" — true of every authenticated endpoint on the web |

The second row is a **false positive**, and it is not hypothetical: the test written for it
was red with `assert 1 == 0` — `run_hypotheses()` really did return a manufactured
confirmation.

**On the phrase "structurally cannot produce false positives": this defect is the standing
counter-example, and the phrase must not be quoted on its own.** Before `c829482` the harness
*could* manufacture a confirmation, and it took adversarial testing rather than any run to
find that out. What is defensible after the fix is narrower and must be written out in full
wherever it appears: *a finding is derived from real gate-executed output, a fixed comparator
— never the model — decides whether it holds, the claim is bounded by what that comparator
can establish, and one known fabrication path is closed.* That is a statement about
mechanism, not a guarantee about all possible runs.
The 2026-08-20 run selected the first arrangement and so lost findings; the same defect
one field apart would have invented one.

`hypothesis.SecondPrincipalUnavailable` now mirrors `UnresolvedReference` exactly: raised
at the point the principal cannot be resolved — *before* the browser is touched, so the
degraded request cannot be built — and caught in the runner ahead of the generic handler.
The experiment is **not dispatched, not judged**, and the next round is told
`SECOND PRINCIPAL UNAVAILABLE (experiment NOT run, this is not a result)`, asserted
against the refine prompt the model actually receives rather than against the note
surface. **There is no fallback to `self` anywhere**: a missing principal is a missing
capability, never a quieter principal. All three dispatch sites — setup, control, variant
— share one `try` and are covered; a setup step naming `second` is pinned separately,
because an unjudged setup request still changes state on the target as the wrong caller.

Tests: `tests/test_second_principal_fail_safe.py` — 12 tests, **8 verified red first**.
Named: `::test_an_unrunnable_cross_account_experiment_is_never_judged` and
`::test_second_as_the_control_cannot_manufacture_a_confirmed_finding`. Suite: **993
passed, 1 skipped** (was 981).

**STILL OPEN — the capability gap, which is the whole of B's original subject.**
`establish_second_identity()` still returns `""` on an Angular SPA, because
`_signup_form()` still needs a server-rendered `<form>`. Nothing above creates a second
account; it only stops the absence of one from being scored. **The cross-account class
therefore cannot be tested on this target at all**, and that is true of most modern
targets — the population where authorization bugs are most common and most valuable. The
fix options recorded above stand unchanged, along with the property they must preserve.

**What this means for the next run, and it must be stated this way in the paper.**
Cross-account experiments will be recorded as **NOT RUN**. That is an **honest structural
limit of the harness on SPA targets** and must be cited as a scope limit — *not* reported
as a negative result, and *not* counted as evidence that the target's authorization is
sound. The reader must be able to tell "we asked and the application held" from "we could
not ask". Before this change the artifact could not express the difference; now it can,
and the write-up has to use it.


#### Update 2026-08-22 — the capability gap is closed for SPAs that expose a JSON signup

**Juice Shop is one of those, so the cross-account class is now reachable on the target
criterion #2 is measured against.**

Premise checked live before a line was written, which is what made it worth attempting:
`/`, `/register` and `/rest/user/register` serve **zero `<form>` tags**, while
`POST /api/Users {"email","password"}` answers **201** with `role: customer` and that
account then logs in for a token. The form path was not failing on a technicality — the
door it looks for does not exist on this shape of application.

`_register_account_json` is the fallback, tried only after the form path declines. Same
soundness argument, same front door: it posts to an endpoint the application advertised to
an anonymous crawler, as an anonymous caller, and takes whatever role it is given — so the
account is still, by construction, what a stranger gets. Candidates come from **what the
crawl observed**, filtered through `_JSON_SIGNUP_PATHS`, an explicit documented allowlist
in the spirit of `schema._NO_RESOLVE_FLAGS`. Without that filter a speculative signup would
be fired at every route the crawl mined — dozens on a real surface, some destructive — and
a test pins that unrelated routes are never posted to. It runs through the governed browser,
so it is gated by `check_web` and audited like any other web action.

**Two defects the live run caught that the fixtures alone would not have.** Both are the
reason this was worth doing against a real target rather than a model of one:

1. **The second principal's credential was never registered with `redact` — on EITHER
   path.** `_session_auth_for` registers the first identity's the moment it reads it off
   the browser; the second identity's session was stored and replayed on every `as: second`
   request without ever being registered, so it could have reached a record surface
   unmasked. Pre-existing, and it would have shipped with the form path forever.
2. **A JSON signup authenticates by EMAIL, and `login`'s default user field is
   `username`.** Registration answered `201` and the login immediately after was refused
   `401` — which would have left a real, created account unusable, and in the ledger would
   have been **indistinguishable from a target that refuses self-registration**. Exactly
   the class of silent mis-attribution this section exists to eliminate.

**Proven end to end on the live target**, second principal
`brk53d8b8cb25@brukal.test`, with the provenance work of `1f531af` making it checkable —
two experiment sides, two distinct handles in the ledger:

```
control  requested=second  resolved=second  handle=[REDACTED:cd432603]
variant  requested=self    resolved=self    handle=[REDACTED:fc477483]
```

Neither principal's token appears in cleartext on any artifact of that run — audit,
`findings.jsonl`, `engagement.md`, all six agent notes, the scope mirror: `eyJ` count zero
on every one.

**STILL OPEN: a target with neither a server-rendered form nor a JSON signup endpoint.**
There is no third door, and the fail-safe is deliberately untouched — such a target still
raises `SecondPrincipalUnavailable`, and its cross-account experiments are recorded
**NOT RUN**, which remains an honest structural limit to be cited as a scope limit rather
than reported as a negative result.

Tests: `tests/test_second_identity_json_signup.py` — 10 tests, **9 verified red first**.
Suite: **1012 passed, 1 skipped** (was 1002).

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

**Updated 2026-08-22 — A closed, B's fail-safe closed, B's capability gap open. A run is
now worth making, and its cross-account result is already known to be NOT RUN.**

Both silent failures are gone. A's fix makes the model reachable again — the retry
streams, and a call that fails says so on the note surface and in the coverage table
instead of vanishing. B's fail-safe makes the *answer* trustworthy: an experiment naming
a principal this target cannot supply is no longer dispatched, no longer judged, and no
longer able to file either a false negative or the false positive the trace uncovered.

What remains is a capability limit rather than a correctness bug, and it is visible
instead of silent. On an SPA there is still no second account, so **every cross-account
experiment will be recorded as NOT RUN.** A run made now will therefore ask the model,
reach business logic, and return an honest partial: whatever the self-only and anonymous
comparators can establish, plus an explicit, countable list of the questions the harness
could not put. That is a publishable result under the pre-committed stopping rule in
`PROJECT_STATE.md` — it is the *target-caused* branch, a measured limit rather than a
blocker — and it is a materially better artifact than the 2C2 run, which could not tell
the difference between a question it failed and a question it never asked.

The remaining choice is whether to spend one timeboxed session on SPA registration first
(which would open the cross-account class on the target where it matters most) or to run
now and cite the gap. That is a scope decision, not a defect.

**One thing in the case study is NOT evidenced and must not be cited without a controlled
re-test.** It reads three `PUT /api/BasketItems/1` → `200` as an unrecognised real
cross-user write. The mechanism is plausible — object-level authorization missing on
`BasketItems` — but the tenant mapping was seeded **externally** and appears nowhere in
the artifacts, and `GET /rest/user/whoami` returned `{"user":{}}` on that path. The ledger
alone cannot say whether that write was A-as-A or anonymous. Either reading is
interesting; neither is evidence yet.

---

## AUDIT 2026-08-22 — did the manufactured-confirmation path ever fire? (NO, and one new P1)

Prompted by the false-positive route found while closing P1 B: a control naming `as: second`
on a target with no second account resolved silently to `anonymous`, which makes
`a_denied_b_allowed` — *"the control was refused and the variant was accepted"* — hold for
**every authenticated endpoint on the web**. That path was closed by `c829482` before any of
this was known. The question this audit answers is whether it had already produced a finding
that is now published somewhere.

**It had not.** But establishing that turned out to be only half-possible from the ledger,
and the half that is impossible is a P1 in its own right.

### Method

The mechanism has a hard lower date bound: `_as_identity` and the `second` principal arrived
in `62e5e33` (2026-08-04) and the comparators in `8f354c4` (2026-08-03), so **no run before
2026-08-04 could exhibit it** — there was no `as` field to name. Of roughly **87 vault roots**
under `runs/`, **7 runs used the experiment path at all**. An exhaustive grep for the
comparator's own meaning string — `the control was refused and the variant was accepted` —
across every artifact in `runs/` returns **exactly one file**.

### Result

| Run | Date | Experiment verdicts | Second principal? | Verdict |
|---|---|---|---|---|
| `vault-dvna16/172.20.0.10` | 08-04 | none judged | **yes** (`brk3beee2bbb0`) | SOUND |
| `vault-dvna18/172.20.0.10` | 08-06 | **1 CONFIRMED** `a_denied_b_allowed` | **yes** (`brk6ba71274c4`) | **SOUND** |
| `vault-dvga3/172.20.0.5` | 08-07 | 4 not confirmed | no | **CANNOT TELL** |
| `vault/10.129.100.21` | 08-09 | ~8 not confirmed | no | **CANNOT TELL** |
| `vault/10.129.100.61` | 08-09 | 8 not confirmed | no | **CANNOT TELL** |
| `_archived_dvga_…_pre-2b` (2B) | 08-12 | 6 not confirmed | no | **CANNOT TELL** |
| `vault/172.20.0.3` (2C) | 08-16 | 4 not confirmed | no | **CANNOT TELL** |
| `vault2c2/172.20.0.3` (2C2) | 08-21 | none — the engine was never asked | no | SOUND |

**The single confirmed experiment finding in the project's entire history is sound**, on three
independent grounds rather than one: a second principal **did** exist in that run; the
finding's preserved hypothesis prose names the control as *"A stranger with no session"* —
`anonymous` by intent, not the manufactured arrangement; and the same vertical privilege
escalation is **independently corroborated by a separate CRITICAL finding** in the same run,
reached by a different route (*register through the public signup form, authenticate, and
`GET /app/admin` again* → `200`). DVNA genuinely has that bug.

### The five CANNOT TELLs are not "probably fine"

```
$ grep -rl '"as"' runs/
(no output)
```

**The proposal JSON is persisted nowhere.** Not in `findings.jsonl`, not in the audit log, not
in the agent notes, not in the blackboard. The record keeps a title, a comparator and two
URLs, and stops. So for those five runs it can be said with certainty that **no CONFIRMED
experiment finding exists in any of them** — the manufactured-confirmation path provably did
not fire there — while **whether `as: second` was named and silently degraded cannot be
determined at all**. That is recorded as unresolved and is not being rounded toward the good
case.

**Do not restate this as "no false positive was published".** That is a broader claim than
the evidence carries, and the evidence ledger of 2026-08-24 does not support it — see
*"'no false positive' is not assertable today"* below.

One pair is suggestive and permanently unresolvable, from the 2B run: *IDOR on
`/rest/basket/{id}` — control HTTP 200 (900B) vs variant HTTP 200 (1310B)*, filed NOT
CONFIRMED. If that variant was `second`→anonymous, an anonymous reader took 1310 bytes of
another user's basket and it was recorded as a clean negative. The 2B run is also entangled
with the `{{setup.*}}` substitution defect, so the two causes cannot be separated after the
fact. It is written down here because it will never be recoverable, not because it is
actionable.

### ~~P1 — THE LEDGER DOES NOT RECORD WHICH PRINCIPAL AN EXPERIMENT USED~~ — **CLOSED 2026-08-22 (`2fdbc7f`)**

**Severity: P1 (auditability — invariant 5, and the auditability win-axis directly). CLOSED 2026-08-22.**

A cross-account finding's entire claim is *which principal saw what*. The ledger does not
record it. `_as_identity` swaps the browser's cookies and auth header around a request and
restores them afterwards, and **nothing writes down which of the three principals was in
force** — not the audit entry, not the finding, not the note.

The consequence is exactly the shape this project treats as its worst: **the artifacts of a
sound finding and of a manufactured one are byte-identical.** The 2026-08-06 confirmation
above is checkable only because the model happened to write its intent into the hypothesis
prose. That is a narrative accident, not a governance property, and it is not repeatable.

**`c829482` stops the degradation but does not close this.** An experiment naming an
unavailable principal now errors instead of running — so no *future* finding can be
manufactured this way — but a future cross-account finding that legitimately runs will be
recorded with **exactly as little principal provenance as `vault-dvna18`'s**. The next
capability run is intended to produce citable authorization evidence, and as things stand its
ledger could not support the citation.

It also undercuts the reproducibility axis: a reader replaying a run from the audit log cannot
reconstruct which session issued which request, so the run is not replayable in the sense the
paper claims.

**Fixed 2026-08-22 (`2fdbc7f`), as proposed and in one place.**

Every experiment request now emits an `experiment_principal` audit record carrying
`role` (setup / control / variant), `requested`, `resolved`, a session `handle`, the url
and the target. The confirmed finding repeats the pair in its own `evidence`, because
`report.md`, `report.json` and the SARIF export are generated from the finding and a
reviewer reading a cross-account claim should not have to correlate an audit file to learn
who issued which side.

**Recorded inside `_as_identity`, not at the three call sites.** That is the one point
every dispatch passes through, so a fourth site added later inherits the record rather than
going silently unattributed — which is exactly how this defect stayed invisible. The
guarantee is bought by a **dispatch-point guard** in the style of
`test_recon_no_resolve.py`'s: `::test_every_experiment_request_dispatched_carries_a_principal_record`
asserts that the count of requests reaching the cage equals the count of principal records,
whatever built them.

**Identify, never credential.** The handle is `redact.placeholder_for`'s sha256[:8] —
deliberately the *same* form redaction already emits, so a handle here and a masked
credential elsewhere read identically and an operator can correlate two records as the same
session while the value stays unrecoverable. It rides an audit `kind` rather than a new
writer, so it inherits `redact.data` like every other record; verified against a target that
echoes the session token and cookie straight back, per surface — audit, `findings.jsonl`,
report, SARIF, blackboard.

**`requested` and `resolved` are both kept although they are equal by construction today.**
That is the point: the defect this closes was a silent substitution, and a pair that *can*
disagree makes the next one visible in the ledger instead of inferable only from the code of
the day. `anonymous` is recorded explicitly with an empty handle and never as an absent
field — **absence is precisely what made the past runs unresolvable.**

Tests: `tests/test_experiment_principal_recorded.py` — 9 tests, **6 verified red first**
(no such record existed, so the five structural ones failed on an empty ledger and the
finding-surface one on evidence with no `issued as` clause). The 16 `test_redaction.py` and
9 `test_auth_not_placeholder.py` tests that guard these same surfaces are unchanged and
green. Suite: **1002 passed, 1 skipped** (was 993).

> ### This does NOT make the past auditable
>
> **The five CANNOT-TELL runs of 2026-08-07 → 2026-08-16 remain permanently unresolvable.**
> Their artifacts were written before any principal was recorded, and nothing in this change
> is retroactive — there is no field to backfill from, because the information was never
> captured anywhere. `vault-dvga3`, `vault/10.129.100.21`, `vault/10.129.100.61`, the
> archived 2B run and 2C stay exactly as the audit found them: **no CONFIRMED experiment
> finding exists in any of them, and whether `as: second` silently degraded cannot be
> determined.** (Phrased as confirmations, not as false positives — see the ledger note below.)
> That distinction must survive into the paper intact. What closed here is the guarantee for
> **runs from 2026-08-22 onward**; the earlier ones are a cited gap in the evidence, not a
> resolved question, and the suggestive 2B pair (`control 200 (900B)` vs `variant 200
> (1310B)`) will never be settled.

---

## P1 — A CONFIRMED FINDING CARRIED A CLAIM ITS COMPARATOR DID NOT EARN (2026-08-22, CLOSED 2026-08-23)

Found by auditing the 2C3 pre-flight — a 3-step, $0.17 throwaway run whose purpose was
to check plumbing before the measurement. It did that, and then produced the most
important finding of the week about the harness itself.

**Severity: P1 (precision — the headline win-axis). CLOSED `1940f09`.**

The pre-flight published two HIGH findings, verbatim:

> **Basket IDOR - any authenticated user can read another user's basket by ID**
> `identical requests but for one changed value produced different bodies: control GET
> http://172.20.0.3:3000/rest/basket/1 -> HTTP 200 (1310B); variant GET
> http://172.20.0.3:3000/rest/basket/2 -> HTTP 200 (557B). Principals: control issued as
> self, variant issued as self.`

> **User PII IDOR - any authenticated user can read another user's profile via /api/Users/{id}**
> `... control GET .../api/Users/1 -> HTTP 200 (301B); variant GET .../api/Users/2 ->
> HTTP 200 (297B). Principals: control issued as self, variant issued as self.`

**Both verdicts were sound. Both titles were not.** The comparator was `bodies_differ`,
whose entire assertion is *"identical requests but for one changed value produced
different bodies"*. Every request on both sides was issued by ONE principal — six
`experiment_principal` records, all `self`, one handle `[REDACTED:5759af35]` — so what
was actually established is that two ids return two different bodies. Nothing in the
record ties either object to an owner: `grep -rl 'brukal.a@juice.test'` over the whole
pre-flight vault returns nothing, and no `UserId`/`BasketId` ownership mapping appears
anywhere. **That mapping existed only in the operator's head.**

`a_denied_b_allowed`, the comparator built for authorization, was never used — it was
unconstructible, because the second principal failed to establish (rate-limit denial).
So the model correctly chose the only comparator available to it, and then wrote the
claim it wanted anyway. `title` and `severity` were passed to `Finding(...)` **verbatim
off the model's proposal**, with nothing in between.

The findings are probably TRUE of Juice Shop, which is exactly what makes this dangerous:
a reader holding the artifacts cannot distinguish them from an application that
legitimately returns different content for different ids.

**Fixed.** `hypothesis._EVIDENCE_CLASS` sits beside `_COMPARATORS` — one table, so a
comparator that gains a meaning gains a bound in the same edit — and `derive_claim()` is
a pure function of the comparator plus the two RESOLVED principals. No model text reaches
it: **invariant 1 applied to the record rather than to the gate**, which is the right
framing, because this control exists precisely because a model authored a claim it had
not earned. Severity is capped by evidence class; the model may ask for less, never more.

**A bound, not a filter.** `a_denied_b_allowed` between two genuinely distinct recorded
principals keeps the full authorization claim at full severity — that is the finding the
entire second-principal effort exists to produce, and flattening it would trade one
blindness for another. The same comparator between one principal is capped and loses the
authz reading, because a refusal and an acceptance from the same session says nothing
about who may reach what.

The model's REASONING survives, labelled `UNVERIFIED agent interpretation (NOT part of
this finding's claim)`. Its TITLE does not — that flat assertion is the artefact that went
out unearned, and it remains in the note stream where it reads as agent chatter.

Tests: `tests/test_claim_bounded_by_comparator.py` — 8 tests, **5 verified red first**,
driven by both live cases verbatim. Three pre-existing tests restated, not weakened.
Suite: **1020 passed, 1 skipped** (was 1012).

### ⚠ THE TWO PRE-FLIGHT FINDINGS MUST NOT BE CITED IN THEIR CURRENT WORDING

They are recorded in `runs/vault-preflight/` under titles this fix would no longer allow.
Under the derived contract they publish as **LOW**, *"Observed difference [bodies_differ]
— the same principal (self) on both sides at /rest/basket/2"*. If the underlying IDOR is
real — it very likely is — it must be **re-proved with two distinct principals** and
cited from that run, never from these artifacts.

### The pattern: FOUR false-result classes in one week, all found by audit

| Closed | Class | How it would have read |
|---|---|---|
| `c829482` | A missing principal silently became `anonymous` | a fabricated CONFIRMED, or a false negative |
| `2fdbc7f` | The ledger did not record which principal was used | sound and manufactured findings byte-identical |
| `1940f09` | A sound verdict published under an unearned claim | a true measurement under a sentence nobody verified |
| `a8410a5` (OPEN) | Our own rate limiter contaminates the detector measuring the target's | a verdict about Brukal's governor read as a verdict about the target |

**None of the four was found by a run.** Every one surfaced from auditing artifacts
after the fact, and each was invisible to the run that produced it. That is worth saying
plainly in the paper: the governance model's value here was not that it prevented these,
but that the ledger was complete enough to find them afterwards — and twice it was not
quite complete enough, which is why `2fdbc7f` had to exist at all.

---

## "NO FALSE POSITIVE" IS NOT ASSERTABLE TODAY (evidence ledger, 2026-08-24)

Three facts, and the claim needs all three stated together or it overreaches.

1. **The manufactured-confirmation path provably never fired.** An exhaustive sweep of
   ~87 vault roots for the comparator's own meaning string returns **six** CONFIRMED
   experiment findings all-time. The one produced by `a_denied_b_allowed` (`vault-dvna18`,
   2026-08-06) is sound on three independent grounds — a second principal existed, the
   hypothesis prose names the control as anonymous, and a separate CRITICAL corroborates it
   by a different route.
2. **Five `bodies_differ` findings were published with cross-account titles their comparator
   did not earn.** Two in the 2C3 pre-flight, three in 2C3b, every side issued by a single
   principal. `1940f09` closed the mechanism; the artifacts still carry the old wording.
3. **Whether those five underlying claims are TRUE was never independently verified.** They
   are probably real Juice Shop IDORs. "Probably real" is not a measurement, and re-proving
   them with two distinct principals has not been done.

**So the assertable claim is "the manufactured-confirmation path never fired, and here is
the sweep", not "no false positive was ever published".** The second is a claim about every
finding this project has ever emitted; the evidence supports a claim about one path. A
reviewer who reads (2) will not accept (1) as covering it, and they would be right.

---

## ~~P3 — THE LOGIN PATH COSTS A THIRD TO A HALF OF THE WEB BUDGET~~ — **CLOSED 2026-08-23 (`13bc501`)** (2026-08-22)

**Severity: P3 (efficiency; becomes P2 whenever a run is dense).** Recorded during the
2C3 pre-flight audit. **Not fixed here** — this session was scoped to claim derivation,
and the login path was explicitly out of bounds.

`JsonAuth.authenticate` (`auth.py:244`) issues a **seeding GET on the login URL before
every POST**, deliberately and with a comment explaining why: some APIs hand back an
anti-CSRF or session cookie there, and dropping it would silently change the cookie jar
and the rate accounting. On Juice Shop the login route is **POST-only and answers 500 to
the GET**, so half of every login attempt is a wrong-method request that returns nothing
and still costs a rate slot.

Nothing retries — the cost is that **many detectors each call `login()`**, and each call
is two requests: *Default credentials*, *Function-level authz (BFLA)*, *Session
management*, *Password policy*, and `establish_second_identity`.

| Run | Duration | Web decisions | Login decisions | `hard:web-rate` | Login rate-denied | Density |
|---|---|---|---|---|---|---|
| 2C (08-16) | 18.3 min | 109 | 34 (31%) | 1 | 0 | 6.0/min |
| 2C2 (08-21) | 49.8 min | 106 | 32 (30%) | 2 | 0 | 2.1/min |
| **2C3 pre-flight** | **2.3 min** | 88 | **51 (58%)** | **26** | **22 (85%)** | **37.5/min** |

**It is a density effect, not a volume effect.** The limit is
`Scope.rate_limit_per_min` (default **30**, `scope.py:181`), enforced in
`GovernedBrowser._rate_ok` (`web.py:497`) as a **sliding 60-second window per browser** —
so per-engagement, not per-host. The long runs drained the window between requests and
never noticed; the 3-step pre-flight ran everything at 37.5/min and hit the ceiling.

**Consequence, and why it is recorded rather than shrugged at:** the denied requests
included `POST /api/Users` and `POST /register` — **the second principal's registration**.
That is what failed pre-flight condition B3, which in turn is why the two findings above
had only one principal to work with. A P3 efficiency issue directly caused a P1 evidence
problem, purely by exhausting a budget at the wrong moment.

**Fixed 2026-08-23 (`13bc501`) — dropped on evidence, not on principle.** The GET is
still issued the first time at any login endpoint. Once it has answered 5xx there, or
answered 2xx and seeded nothing, it is not issued at that URL again for the rest of the
engagement. Five logins on this shape of target now cost **6 requests instead of 10**.

**The skip is recorded** as a `login_seed_skipped` audit entry. A request that used to be
issued and no longer is must be explainable from the ledger alone, or a saving is
indistinguishable from a bug.

Two constraints the tests forced, both worth keeping in mind for the next optimisation of
this kind:

- **A DENIED seeding GET teaches nothing and is not memoised.** That is the gate or the
  rate limiter intervening, not the endpoint speaking — memoising it would let a transient
  rate denial permanently disable a control on a target that needs it.
- **"Did it yield anything" is judged on the response carrying `Set-Cookie`, not on a
  cookie-jar delta.** By the second login the cookie is already in the jar, so a delta
  alone reads a *working* seeding GET as useless and memoises exactly the endpoint the
  original comment is right to defend. The boundary test caught this on the first
  implementation.

`FormAuth`'s GET is untouched: it reads the form's hidden and CSRF fields, so it is not
waste. Tests: `tests/test_login_seed_get_cost.py` — 8 tests, **5 verified red first**.
Suite: **1038 passed, 1 skipped**.

**The lesson worth carrying:** this was a P3 by severity and a P1 by consequence. It sat
invisible through two complete engagements because neither was dense enough to hit the
ceiling, and it only surfaced when a 3-step pre-flight compressed the same work into 2.3
minutes. **A cost that scales with density is not visible in a slow run**, and the runs
this project makes are usually slow.

---

## P2 — OUR OWN RATE LIMITER CONTAMINATES THE DETECTOR THAT MEASURES THE TARGET'S (2026-08-23, OPEN)

**Severity: P2 (a detector whose verdict is unaudited). RECORDED, NOT FIXED.**

`confirm_missing_rate_limit` (`assist.py:5154`) sends **8 rapid failed logins** to decide
whether the TARGET throttles credential brute force. Its proof is explicitly that *"every
attempt was answered normally — no 429, no lockout message, no widening delay"*.

In run **2C3b**, **9 of the 13 `hard:web-rate` denials were that detector's own probes**,
refused by **Brukal's** governor before they ever reached the target. The detector
therefore counted answers to requests that were never sent.

**Its verdict cannot distinguish "the target did not rate-limit me" from "my own governor
did."** Those are opposite findings — one is a real API4 weakness in the target, the other
is Brukal working correctly — and the detector reports them identically. It reads
`r is None` as *"a blocked request is not evidence"* and returns `False`, so a
rate-limited run yields **no finding either way**, which is the safe direction; but the
absence is then indistinguishable from a target that throttles properly, and a *partially*
denied sweep still reaches `len(set(statuses)) != 1` or an all-same verdict built from a
truncated sample.

**This is the same class as the week's other three findings**, arriving from a fourth
direction: `c829482` (a missing principal wearing a comparator's verdict), `2fdbc7f` (a
verdict with no provenance), `1940f09` (a sound verdict under an unearned claim), and now
**a detector whose measurement is contaminated by the instrument**. Every one is the same
shape — *the artifact reads as a statement about the target when it is partly a statement
about Brukal* — and every one was found by auditing artifacts, never by a run.

**Any past run's rate-limiting verdict is suspect.** "No rate limiting on authentication"
appears as a confirmed MEDIUM in earlier engagements (`vault-dvna18`, 2026-08-06, among
others). Those were recorded before this interaction was understood, and none of them
records how many of its 8 probes actually reached the target. **They should not be cited
without re-deriving the denial count for that run from its audit log.**

**Fix (not this session).** The detector must know what the gate did to its own requests:
count denied probes, refuse to conclude unless all 8 reached the target, and record the
reached/denied split on the finding so a reader can see the sample it rests on. That is
the same remedy as the rest of this week's work — make the instrument's own effect
visible on the record rather than assume it away — and it is deliberately not being done
mid-engagement.

---

## DISCLOSED ENGAGEMENT PARAMETER — `rate_limit_per_min` raised to 120 for run 2C4 (2026-08-23)

**This is a condition of the measurement and must be stated wherever run 2C4 is cited.**

`Scope.rate_limit_per_min` defaults to **30**, enforced by `GovernedBrowser._rate_ok` as a
sliding 60-second window per browser. For run 2C4 it is set explicitly to **120** (2 req/s)
in `scope.juiceshop.json`.

**Why.** The default is tuned for a shared or production target. On three consecutive
pre-flights against a maintainer-owned lab container on an isolated bridge it denied
requests *the engagement itself depended on*:

| pre-flight | web decisions | login decisions | `hard:web-rate` | signup denied | density |
|---|---|---|---|---|---|
| 2C3 baseline | 88 | 51 | 26 | **2** | 37.5/min |
| 2C3b after the login-cost fix | 67 | 25 | 13 | **2** | 20.4/min |
| 2C4 after the ordering fix | 65 | 32 | 15 | **0** | 24.4/min |

Two real defects were found and fixed on the way here rather than papered over with this
parameter — the login seeding GET (`13bc501`, halving login cost) and the phase ordering
that queued principal acquisition behind the detector sweep (`670a88e`, which took signup
denials to zero). The parameter is raised on top of those, not instead of them.

**What it is not.** Scope, the gate, capability enforcement, the escalation path and the
keyed audit chain are untouched; `full_send` appears nowhere in `gate.py` or `scope.py`,
and the limiter still enforces 120/min. Nothing about containment or provability changes.

**What it costs the result.** Any rate-limiting verdict from run 2C4 is **unusable as
evidence about the target** — see *"our own rate limiter contaminates the detector that
measures the target's"* above. That was already true at 30/min; it is simply now explicit.
A run intended to measure the target's throttling must set this back to a defensible value
and count its own denials.

---

## ~~P1 — THE REDACTION CONTRACT IS ASYMMETRIC: IT PROTECTS CREDENTIALS WE INJECT, NOT CREDENTIALS WE DISCOVER~~ — **CLOSED FOR SELF-DESCRIBING CREDENTIALS 2026-09-07 (`2b7e671`); OPAQUE CREDENTIALS STILL OPEN** (2026-08-23)

**Severity: P1 (a live credential in shareable artifacts).**

Run 2C4's leak check was clean on exactly the axis every previous run measured: **tenant
A's token 0, the second principal's token 0, across all 96 surfaces.** Both are credentials
Brukal *injects*, and `_session_auth_for` registers them the moment it reads them off the
browser.

The same check found **an admin JWT for `admin@juice-sh.op` carrying `"role":"admin"`, in
cleartext**, on:

`runs/audit_juiceshop2c4.jsonl` (5) · `findings.jsonl` (4) · `checkpoint.json` (2) ·
`engagement.md` (2) · `findings.json` · `report.json` · `report.md` · `brukal.sarif` ·
`agents/strategist/00037.md`, `00038.md`, `00046.md`

It is a credential Brukal **discovered on the target**, and `redact.register` was never
called on it. The contract has only ever covered one direction.

**The tension, stated honestly rather than resolved by assertion.** That token is not
incidental — it *is* the evidence for the finding "JWT exposed in response". Blanket
redaction would destroy the proof, and a finding whose evidence has been erased is worth
nothing. So "just redact everything JWT-shaped" is the wrong fix and would quietly gut a
whole detector class.

**The resolution is the one the injected-secret redactor already implements: mask the
VALUE, keep the STRUCTURE.** `placeholder_for` emits a stable `[REDACTED:<8 hex>]` derived
from the value, so two records can be correlated as the same credential while the value
stays unrecoverable — and a decoded JWT's *header and claims* (`alg`, `role: admin`, no
`exp`) are the evidence, not the signature. A finding can say "an RS256 token for
`admin@juice-sh.op` with `role=admin` and no `exp`, `[REDACTED:ab12cd34]`" and lose
nothing a reviewer needs.

**Consequence, and it binds now: no artifact from run 2C4 may be shared or published until
this is closed.** That includes the report, the SARIF export and the audit log — i.e.
every file the paper would want to cite. The measurement stands; its artifacts are not yet
distributable.

**Fix (not this session):** register discovered credentials at the point they are
recognised (the JWT/token detectors already parse them), and give the finding a structural
rendering — claims and header, value masked — so the evidence survives redaction.

### CLOSED FOR SELF-DESCRIBING CREDENTIALS 2026-09-07 (`2b7e671`)

**The intended fix above was wrong about WHERE, and finding out why was the work.** It
proposed registering "at the point they are recognised". Tracing the two capture paths
shows that point is always **after** the first record is written:

| Path | First write of the body | When the detector sees it |
|---|---|---|
| shell | `Executor.run` → `audit.append("execution", result)`, **stdout included** | `_absorb_shell`, after `executor.run` has returned |
| web (crawl) | `_absorb_web` → notes + `_persist_finding("web", …, body[:800])` → blackboard | `scan_web_body`, called by the crawl *after* `run_web` returned |
| web (agent's own action) | same `_absorb_web` write | **never** — `scan_web_body` has only two call sites, both in the crawl |

**So the ordering is the defect, not the omission**, and on the shell path no
session-level hook can be early enough: the executor has already sealed a hash-chained
entry. A record cannot be fixed afterwards — masking it changes its bytes, breaks the
chain from there on, and destroys the tamper-evidence that is the only reason to publish
the bundle. This is the same trap the publishable-bundle P1 names, arriving from inside.

**Discovery therefore lives in `redact.text` itself.** `redact.observe()` registers any
self-describing credential on its way past, so the first record to carry a credential is
also the first to mask it, and all eight funnels — plus every future writer — inherit it
without having to remember. `redact.data`'s empty-registry short-circuit was removed with
it: that is exactly the state an engagement is in when the target first hands it a
credential, so the record carrying it was being waved straight through.

**Recognition is a DECODE, not a regex, and the distinction is load-bearing.** redact.py's
standing rule is that no pattern is trusted to say what a secret looks like. A JWT does not
need one: it either splits into three base64url segments whose header and payload decode to
JSON objects, or it is not a JWT. Four parametrised lookalikes (payload not JSON, header not
an object, two segments, payload an array) and a clean-body test pin that an ordinary record
stays byte-identical — over-redaction that shreds records is a regression, not caution.

**The tension the entry raised is resolved the way it predicted, and it needed one thing the
entry did not anticipate.** `jwtscan.describe()` records what a token IS — `alg`, `typ`, the
claim KEYS, whether an `exp` exists, signature length — with no claim value, and `scan_jwt`
files it beside the weaknesses. This is not decoration: 2C4's token was **RS256 with a valid
signature**, so the only weakness `scan_token` declared was the missing `exp`, and `alg`
appeared nowhere in the record at all. Masking the value would have left a finding no reader
could evaluate. The digest is conditional on there being a weakness to explain — it keeps a
finding provable and is not itself one; unconditional, it manufactured a finding against an
app whose only defect was elsewhere and turned `test_defaultcreds`'s *"an app that accepts
anything confirms nothing"* red. **That guard was right and the first cut of the code was
wrong.**

**The operator's live view is untouched.** Nothing mutates `result.body` or
`ExecResult.stdout` — only what is written. The human running the engagement still sees the
real value; the persisted record does not carry it.

### ⛔ WHAT REMAINS OPEN: OPAQUE CREDENTIALS

**The contract is now symmetric for SELF-DESCRIBING credentials only, and the gap is
structural rather than a missing case.** A session cookie, an API key, a signed URL
parameter, an opaque bearer value — none of these can be recognised by decoding, because
there is nothing inside them to decode. `observe()` cannot see them, and closing that gap
by *shape* would mean exactly the regex-guessing this module refuses: a rule loose enough
to catch a 32-character opaque token also catches a hash, a UUID, a build id and a base64
image fragment, and shredding those destroys the records the artifacts exist to be.

Consequences to carry forward, not paper over:

- A discovered **cookie** or **API key** is still recorded in cleartext. The class that
  bit us happened to be self-describing; the next one may not be.
- The honest claim is **"credentials we inject, plus self-describing credentials the
  target discloses"** — never "credentials are redacted".
- A publishable bundle still needs a **per-run leak check** before release. This fix
  narrows what that check has to catch; it does not replace it.

### ⛔ RUN 2C4'S ARTIFACTS REMAIN UNPUBLISHABLE, AND CANNOT BE RETROFITTED

The fix is at **write time**, so it applies to runs made *after* it and to no run made
before. 2C4's bundle still carries the admin JWT in cleartext across the eleven surfaces
listed above, and post-hoc masking is not an option for the reason this file has stated
twice: the records are hash-chained, so editing any one of them breaks the chain from that
entry onward and destroys the tamper-evidence that was the entire point of publishing it.
You would be sanitising the evidence you are citing, and the verification you invited the
reader to perform would then fail.

**The publishable bundle must come from a NEW run.** That was already the plan — step 1 of
*"every headline evaluation number is unverifiable by a reader"* is this closure, and step 2
is the clean run — and it is now unblocked for the JWT class specifically.

---

## P2 — A DELETED AUDIT LOG SILENTLY RESTARTS THE CHAIN (2026-08-23, OPEN)

**Severity: P2 (invariant 5 claims tamper-evidence this does not provide). RECORDED, NOT FIXED.**

Found by hand, and by accident: during run 2C4's aborted first attempt the maintainer
deleted the audit log while the engagement was still writing to it. `AuditLog.append`
**reopens the file by path on every append**, so the next record recreated the file and
began a fresh chain whose first entry's `prev_hash` referenced an entry that no longer
existed anywhere.

Nothing detected this. `brukal verify` on the resulting file verifies the *surviving*
chain and reports intact, because every link it can see is consistent — the missing prefix
leaves no trace.

**Invariant 5 says "append-only tamper-evident audit".** Truncation and in-place edits are
caught by the hash chain. **Wholesale replacement of the backing file is not**, and that is
the cheapest possible attack on the ledger: delete it, let the process recreate it, and the
run's early history is gone with a chain that still verifies.

The abort was a maintainer error rather than an attack, and the compromised run was
discarded — but the finding is about the property, not the incident.

**Fix (not this session):** bind the open chain to the file it started on — stat the inode
and length before each append and refuse (fail-closed) if either moved, or hold the
descriptor open for the engagement's lifetime and write through it. Then teach `verify` to
say "this chain does not start at a genesis record" rather than "intact".

---

## ~~P2 — THE SETUP-REFERENCE CONTRACT DOCUMENTS SYNTAX BUT NOT SCHEMA~~ — **CLOSED 2026-09-06 (`1e25473`)** (2026-08-23)

**Severity: P2 by blast radius, and it was the HIGHEST-VALUE REMAINING CAPABILITY ITEM.**

**9 of 9** model-proposed experiments in run 2C4 died at:

```
UNRESOLVED REFERENCE, not run: … ({{setup.0.id}}: no field 'id' in the setup response)
```

The setup was well chosen — `GET /rest/user/whoami` issued as *both* principals, which is
exactly how you identify two accounts before comparing them. Juice Shop answers
`{"user":{"id":25,…}}`, so the path is `user.id`. The model wrote `id`.

Defect A (`{{setup.*}} references did not resolve`) closed the **syntax** half: the model
is now told the reference grammar and writes it correctly. This is the **schema** half, and
it is not a model failure in any useful sense — **the model cannot reference a field it has
never been shown.** It is guessing at the shape of a response it never sees, and the
harness holds that response.

The fail-safe worked perfectly and that is the point: nothing was dispatched with a literal
placeholder, nothing was judged, nothing was filed as a clean negative. The capability was
blocked *safely* rather than silently — which is the correct failure and still a total
failure of the capability.

**Fix (not this session):** after the setup requests run, feed the next round the setup
responses' actual structure — the resolved key paths, or a depth-bounded key skeleton, not
the values (which may carry target data and must go through redaction). One round of
"here is what your setup returned: `user.id`, `user.email`, `bid`" turns nine unresolved
references into nine dispatched experiments.

**This is the single highest-value item left for criterion-#2 capability.** Everything
around it now works: the phase is planned and reached, the engine is asked, two real
principals exist, provenance is recorded, claims are bounded, and results that cannot be
judged are refused rather than invented. The one remaining gap between that and a confirmed
business-logic finding is that the model is asked to name a field it was never told about.

### CLOSED 2026-09-06 (`1e25473`) — the next round is shown the key paths

`hypothesis.key_paths()` extracts the dotted paths of a setup response body and
`describe_setup_shape()` renders one line per response; `_run_one_round` accumulates them
where the response is captured, and `run_hypotheses` shows them to the refine round above
the results that depend on them. The 2C4 prompt would now have read:

```
What your setup requests actually RETURNED. These are FIELD PATHS ONLY — no values are
shown — and they are exactly the paths a {{setup.<i>.<path>}} reference may name. ...
  - setup.0 GET http://…/rest/user/whoami -> HTTP 200; field paths: user.id, user.email, …

Results of your last round:
  - UNRESOLVED REFERENCE (experiment NOT run, this is not a result) …: {{setup.0.id}}: no field 'id'
```

**Four properties, each pinned rather than asserted.**

1. **What the model is shown IS what it may use.** `key_paths` is the mirror image of
   `_lookup`: it lists a path if and only if `_lookup` would return a value for it, so an
   object, a `null` and an empty container — all `UnresolvedReference` in the resolver —
   never appear. A parametrised test resolves *every* listed path through the real
   resolver, so the disclosure cannot drift into naming a field that then aborts its own
   experiment. The two halves of the contract are welded, not coincidentally in agreement.
2. **Structure, never values.** The line is built from `step`, the model's own request
   text, and not from the resolved spec — a value substituted into a url by an *earlier*
   reference therefore cannot ride out on it. Driven by a response whose values include a
   session token and an email, on both the prompt and the note surface.
3. **The prompt is the only boundary, and it already existed.** The block goes through
   `LLMClient.propose` → `redact.text`, no second funnel. Paths-only is not leak-proof on
   its own — a response keyed BY a credential, `{"sessions": {"<jwt>": …}}`, puts the
   secret in the *path* — so that exact shape is the test, through the real client, and it
   asserts the placeholder survives rather than the line being dropped. **A control that
   transforms data is tested on both sides.**
4. **Both bounds announce themselves.** Depth (4) and count (40) are deterministic, and
   when either bites the line carries `[TRUNCATED: …]` on the record *and* in the prompt.
   A partial list read as a complete one is a model concluding a field is absent when it
   was merely cut — the same silent-failure class this closure exists to end, so the fix
   for it does not get to fail silently either.

**The fail-safe is not weakened, and that is its own test.** An unresolvable reference
still raises `UnresolvedReference`, is still not dispatched and still not judged. Showing
the paths removes the *reason* to guess; it does not make a guess survivable.

**Carried in its own accumulator**, not in `outcomes` — the refine prompt windows that
list to its last 8 entries, so on a nine-experiment round the shapes would have been
exactly the entries the window discarded. The gap would have been closed in code and
still absent from the prompt.

**What this does NOT close.** It is a fix to the *contract*, verified against fixtures and
the recorded 2C4 shape. Whether the comparators can now confirm a business-logic flaw on a
live target is unmeasured until the next capability run, and this closure must not be cited
as if it were that measurement.

---

## P1 — EVERY HEADLINE EVALUATION NUMBER IS UNVERIFIABLE BY A READER (2026-08-24, OPEN)

**Severity: P1 (it contradicts the axis the paper leads on). RECORDED, NOT FIXED.**

The evidence ledger of 2026-08-24 sorted every number this project would cite into two
piles, and the split is the finding.

**Verifiable from the repository alone:** the suite (1052 passed, 1 skipped), the
comparator count (5), the single `cap_severity` call site, the SDK non-streaming ceiling
(21,333, recomputable from `anthropic` 0.116.0), and every line of fix and test in git.

**Verifiable only from artifacts a reader does not have:** *every headline evaluation
number.* Chain intact at 649 entries; 307 requests with zero off-scope; 9 experiments and
12 dispatches across two principal handles; the 0-of-96 leak counts; overclaim 2 of 3; the
six all-time confirmations drawn from ~87 vault roots. All of it lives under `runs/`, which
is **gitignored**, so none of it ships with the repository.

**Worse, two of those numbers are not reproducible even by us.** The 0/96 leak counts were
computed against the two principals' *live* tokens; the Juice Shop container has since been
recreated, and those sessions no longer exist. The measurement was real and it can never be
re-derived — only re-run, which produces different tokens and a different run.

**This directly contradicts the win-axis the paper leads on.** "Auditability &
reproducibility — keyed tamper-evident audit chain; every action provable; runs replayable"
is uncontested against the competitors precisely because they offer nothing like it. A
reviewer cannot currently check a single one of those claims. The chain is verifiable **in
principle** and unavailable **in practice**, and a guarantee nobody can exercise is a claim,
not a property.

**Intended resolution, in order.**

1. **Close the discovered-credential P1 first** (*"the redaction contract is asymmetric"*).
   Run 2C4's bundle currently carries a live admin JWT for the target in cleartext across
   eleven surfaces, so it cannot be published as it stands.
2. **Then produce ONE clean run whose complete artifact bundle can be published** — audit
   log, vault, findings, report, SARIF, and the scope exactly as stamped — **together with
   its `BRUKAL_AUDIT_KEY`**, so a reader can run `brukal verify` themselves and get
   `chain intact: True` from their own machine rather than from our transcript. Publishing
   the key is the point: the chain proves the ledger was not edited after the fact, and it
   proves nothing to anyone who cannot check it.

**Post-hoc redaction is NOT an option, and this is the trap to state explicitly.** The
artifacts are hash-chained. Editing any record to mask a credential changes its bytes,
breaks the chain from that entry onward, and destroys the tamper-evidence that is the whole
reason to publish the bundle — you would be sanitising the evidence you are citing, and the
verification you invited the reader to perform would then fail. **The redaction must happen
at write time, on the run that is going to be published.** That is why step 1 strictly
precedes step 2, and why the fix cannot be applied to any run already made.

**Until this is closed, every evaluation number in the paper is "trust our transcript".**
That is a materially weaker claim than the one the governance thesis rests on, and it should
be stated as a limitation if the paper is written before the publishable run exists.

---

## P1 — A PUBLISHED-KEY HMAC CHAIN DOES NOT GIVE THIRD-PARTY INTEGRITY (2026-09-06, OPEN)

**Severity: P1 (it undercuts the win-axis the thesis leads on). RECORDED, NOT FIXED.**

The intended resolution of *"every headline evaluation number is unverifiable by a reader"*
is to publish one clean artifact bundle **together with its `BRUKAL_AUDIT_KEY`**, so a
reader can run `brukal verify` and get `chain intact: True` from their own machine. That
step is necessary and it is not sufficient, because **the property it demonstrates is not
the property the reader wants.**

The chain is HMAC — a SYMMETRIC construction. Verifying it requires the same key that
produces it. So publishing the key does not turn the reader into an auditor; it turns them
into someone who can confirm that a bundle we assembled is **internally consistent with
itself**. Anyone holding that key — including us, before publication, at leisure — can edit
any record and recompute every link after it. `chain intact: True` on a published bundle
therefore evidences exactly one thing: *these files have not been corrupted or truncated
since they were written or last rewritten.* It cannot evidence *we did not edit them*, which
is the only question a sceptical reviewer is actually asking.

**This is a strictly weaker claim than the one the paper leads on.** "Keyed tamper-evident
audit chain; every action provable" reads to a reviewer as third-party verifiable, and it is
not. The chain is a real and useful control against an agent or a process corrupting the
ledger mid-run, and against silent bit-rot; it is not, and cannot be, evidence about the
authors' own conduct. Publishing the key makes the check runnable without making its result
mean more than it did.

**Intended fix, either of:**

- **Asymmetric signing with a published public key.** The signing key stays private, the
  verification key ships with the bundle, and `chain intact` then means *signed by the
  holder of a key that existed before publication* rather than *consistent with a key
  everybody now has*. This is the real fix and it changes what the artifact proves.
- **An external timestamped commitment of the chain head, made BEFORE scrutiny.** Publish
  the final HMAC head to something we do not control and cannot backdate — a git tag pushed
  to a public remote, a transparency log, an OTS timestamp — at the moment the run ends.
  Any later edit changes the head and no longer matches the commitment. Weaker than
  asymmetric signing (it pins one value, not every record's authorship) but far cheaper,
  and it closes the specific hole: *we could have rewritten the ledger after seeing how the
  results looked.*

**Do not publish the bundle-plus-key as "third-party verifiable integrity" before one of
these lands.** Publishing it as *"internally consistent, key included so you can check the
files are the ones we describe"* is honest and still worth doing; the stronger wording is
the claim this entry exists to stop, and it is exactly the shape of *the check must prove
the claim, not a narrower proxy*.

---

## P2 — THE THREAT MODEL DOES NOT NAME WHO THE AUDIT CHAIN DEFENDS AGAINST (2026-09-06, OPEN)

**Severity: P2 (a documentation gap that makes two other findings unrankable). RECORDED,
NOT FIXED.**

Invariant 5 says *"immutable scope, append-only tamper-evident audit (HMAC-keyed when
`BRUKAL_AUDIT_KEY` is set)"*. It does not say **against whom**. There are three candidate
adversaries and the control means something different against each:

| Adversary | What the chain is defending | Is the current design sufficient? |
|---|---|---|
| **The AGENT** — an LLM-driven process that could edit the record of what it did | that the ledger describes the actions really taken | **Yes, largely.** The key lives in the orchestrator env, outside the cage; the agent cannot forge a link. This is the case the design was actually built for. |
| **The OPERATOR** — us, editing our own evidence before publishing it | that the authors did not curate the result | **No.** The operator holds the key by construction, so a symmetric chain is self-consistent under any edit they make. See the P1 above. |
| **A THIRD-PARTY READER's doubt** — a reviewer with the bundle and nothing else | that what they were handed is what was produced | **No.** Same reason, plus *a deleted audit log silently restarts the chain* — a reader cannot distinguish a fresh run from a truncated one by inspecting the artifact. |

**This is not pedantry: two open findings are unrankable until it is answered.** *"A deleted
audit log silently restarts the chain"* is a P2 nuisance against the agent and a P1 hole
against a reader. The operator-held key is a non-issue against the agent and disqualifying
against a reviewer. Both were filed at severities that quietly assume an answer nobody has
written down, and **severity tracks blast radius when it fires** — which requires knowing
whose hand is on the trigger.

**Intended fix:** state the adversary explicitly in `PROJECT_STATE.md`'s invariant 5 and in
the paper's threat-model section, then re-rank every audit-chain finding against it. If the
answer is *the agent* — which is the defensible one for the current design — say so, and
demote the third-party claims to what the design earns. If the answer is *a third-party
reader*, the P1 above is a blocker for the paper's central win-axis and not a nice-to-have.
Pick one; do not let the ambiguity keep flattering the stronger reading.

---

## RUN CM1 — the capability-milestone measurement (2026-09-10). Four findings, RECORDED, NOT FIXED

Run CM1 was made under the stopping rule committed in `62226d7` **before** the run. Artifacts:
`runs/audit_juiceshop_cm1.jsonl` (562 entries, keyed, `chain intact: True`) and
`runs/vault-cm1/172.20.0.3/` (54 files), scope `brukal-juiceshop-cm1-172.20.0.3`, OWASP Juice
Shop v20.2.0 recreated fresh on the cage's isolated bridge, `rate_limit_per_min: 120` disclosed
in the scope file. 16 of 70 steps, 32 calls, ~$1.07 of a $4.00 cap.

**The experiment funnel, which is what the run was for: proposed 7 · dispatched 7 · RESOLVED 1 ·
JUDGED 1 · confirmed 0.** One experiment — `IDOR on /api/Cards/{id}` — resolved
`{{setup.0.data.id}}` from a `POST /api/Cards` → 201 whose shape disclosure listed
`status, data.id, data.UserId, …`, dispatched control as `self` and variant as `second`, and was
judged NOT CONFIRMED on `a_denied_b_allowed` (control HTTP 200/124B vs variant HTTP 400/55B).

⚠ **This is NOT a recurrence of 2C4, and the distinction is load-bearing.** 2C4 lost 9 of 9
experiments because the model named a field the response did not carry — a rich body, a wrong
path — which is exactly what `1e25473` was built to prevent. In CM1 the fix demonstrably WORKED
where it could: shown the key paths of its own setup response, the model wrote the correct dotted
path and the experiment reached a comparator. The six that did not reach one failed for **three
new reasons, none of them the resolver**, recorded below.

### P1 — A JSON SESSION IS CARRIED AS A BEARER HEADER ONLY, SO AN IDENTITY ENDPOINT THAT READS A COOKIE ANSWERS EVERY "WHO AM I" AS ANONYMOUS

**Severity: P1 (it is the direct cause of the single most-cited uncitable result in this file).
RECORDED, NOT FIXED.**

`login(..., login_type="json")` puts the token in `browser.auth_header` and sets no cookie.
Juice Shop v20.2.0's `/rest/user/whoami` reads **only** the `token` cookie. Measured from inside
the cage on 2026-09-10, same token throughout:

| Request | Answer |
|---|---|
| `/rest/user/whoami` + `Authorization: Bearer …` | `{"user":{}}` |
| `/rest/user/whoami` + `-b token=…` | `{"user":{"id":25,"email":…}}` |
| `/rest/user/whoami` anonymous | `{"user":{}}` |
| `/api/Users/25` + `Authorization: Bearer …` | **200** |

So the session IS attached and IS honoured — by every endpoint except the one that reports who
you are. **The authenticated answer and the anonymous answer are byte-identical**, which is the
same shape as the `as: second` → `anonymous` collapse closed in `c829482`, arriving this time
from the target's side rather than ours.

**Consequences, and they are larger than two lost experiments.** Two of CM1's seven proposals
(`/api/Users/{id}`, `/rest/basket/{id}`) chose `whoami` as their setup — the obvious choice, and
the same one 2C4's model made — and died at `no field 'id' in the setup response`. The shape
disclosure faithfully reported `field paths: (none — the body is not JSON, or carries no
inlinable value)`, so **the model was correctly told the body was empty and had no way to learn
why**. This is also the unresolved half of *"do not cite from 2C2 without a controlled re-test"*:
that run's `GET /rest/user/whoami` → `{"user":{}}` was read as a possible anonymous write, and it
was this, not the application.

**Not a dropped cookie.** The login response carries **no `Set-Cookie` at all** (verified: only
`HTTP/1.1 200 OK` and `Content-Type`); the SPA's own client sets the cookie from the JSON body.
Any fix therefore has to *synthesise* a cookie from the login response rather than record one,
which is a new behaviour and needs its own test-first session — exactly why it is recorded here
rather than patched mid-engagement.

**Positive control (this is why the finding is attributed to the session carriage and not to the
resolver):** in the same pre-flight, `GET /api/Products/1` → `data.id` resolved and reached a
comparator (1 confirmed), and `POST /rest/user/login` → `authentication.bid` resolved and was
judged across two distinct principals. The resolver works.

#### CLOSED 2026-09-10 — the harness now CONFIRMS the session, and refuses when it cannot

The fix is deliberately not "synthesise a cookie and carry on" — that is the same unchecked
claim one layer down. **After authenticating, the carriage is PROVED or the claim is not made.**

- **The oracle has to earn the job first.** An identity endpoint from `_IDENTITY_PROBE_PATHS` is
  asked **anonymously twice**. Two identical answers make it usable; two different ones mean it
  carries a nonce or a timestamp, so it cannot tell principals apart and is skipped rather than
  believed. Only then is it asked with our session, and only a **difference from the stable
  anonymous answer** counts as being logged in. Nothing pattern-matches a body for words like
  `user` — the whole defect is that authenticated and anonymous *look identical*, so a shape
  heuristic would be guessing at the very thing under test.
- **Cookie carriage comes from an allowlist, never a guess.** `_SESSION_COOKIE_NAMES`, the same
  discipline as `_JSON_SIGNUP_PATHS`. `csrf`/`XSRF` are deliberately absent: those are
  anti-forgery values, not credentials.
- **Three outcomes, not two.** `confirmed=True` proved · `False` an oracle existed and no carriage
  passed it · `None` no usable oracle. **Only `False` refuses.** Treating `None` as a refusal
  would break every target that exposes no conventional identity endpoint — trading this defect
  for a worse one — so an untested session stays untested and says so on the ledger.
- **The refusal is `hypothesis.PrincipalNotAuthenticated`**, sibling of
  `SecondPrincipalUnavailable`, raised in `_as_identity` before the request is built and caught
  ahead of the generic handler, fed back as `NOT AUTHENTICATED (experiment NOT run, this is not a
  result)`. An `as: self` from a session the target reads as a stranger is not `self`; it is
  byte-for-byte `anonymous` — the collapse `c829482` closed from our side, closed here from the
  target's.
- **The carriage is on the ledger** (`authentication_carriage`, per principal), because
  "authenticated" with no record of HOW is the unprovable shape `2fdbc7f` closed for experiments.

**⚠ WHAT THIS FIX GOT WRONG FIRST, and the guard now pinning it.** The first cut probed inside
`login()`. Five suites went red: ~5 detectors call `login()` per engagement, so an identity sweep
landed on each — **the exact expense `13bc501` closed** — and it perturbed the detectors that
reason about login's own request/cookie sequence, flipping `test_an_app_that_rotates_yields_nothing`.
Confirmation is now **owed at login and PAID at first authenticated use**, memoised per principal:
`_as_identity` is the single point every dispatch passes through, so a round of three experiments
costs one sweep instead of six. `test_confirmation_is_not_paid_on_every_login` and
`test_confirmation_is_probed_once_across_a_round_of_experiments` exist because that regression was
real and the suite caught it, not because it was anticipated.

#### ⛔ RESIDUAL — WHAT THIS CONTROL DOES NOT COVER (recorded 2026-09-11, before run CM2)

**The guarantee is "no experiment runs on a session PROVEN unhonoured". It is NOT "no vacuous
comparison is judged".** Those are different claims and only the first is enforced.

The refusal fires on `confirmed=False` alone — an identity oracle existed, and no carriage passed
it. Where **no usable oracle is found** (`confirmed=None`) the session is **untested**, the
experiment runs, and a comparison between two callers the target may both be reading as strangers
can still reach a comparator and be judged. That is the same vacuous comparison the entry above
describes, arriving through the case the control declines to police.

**And `None` is the MAJORITY case, not an edge.** `_IDENTITY_PROBE_PATHS` is ten conventional
routes; most applications expose none of them, and an endpoint that answers with a nonce or a
timestamp is skipped as an unusable oracle rather than believed — correctly, and it lands in the
same `None`. Juice Shop happens to have `/rest/user/whoami`, so this target is covered; a target
chosen for the next measurement may not be, and **the coverage has to be read off the run's own
ledger, per principal, rather than assumed from the fix existing**.

Treating `None` as a refusal was considered and rejected: it would refuse the cross-account class
on every target without a conventional identity endpoint, trading this defect for a strictly worse
one. The honest position is that this control **narrows** the vacuous-comparison class and does not
close it, and any claim made about a run has to say which of the two guarantees it rests on.

Tests: `tests/test_authentication_confirmed.py`, 9 tests, **7 red first**, plus the 2 cost guards
written after the regression. The doubles decide from the REQUEST HEADERS the way a real app does
and come in three modes — cookie-reading, header-reading, honouring-neither — because a double
that answered the same way for all three would let this fix pass without doing anything. The
redaction test uses a target that **echoes the token back in its own body** and asserts the ledger
is clean; assuming it would have proved nothing.

### P2 — THE REFINE ROUND PROPOSES `{{setup.N.*}}` REFERENCES WITH NO SETUP STEPS AT ALL

**Severity: P2 (it silently costs a whole refine round). RECORDED, NOT FIXED.**

All **three** of CM1's second-round proposals referenced `{{setup.0.data.id}}` /
`{{setup.0.data.BasketId}}` while supplying an **empty `setup` list**, and all three were refused
with `no setup response at index 0`. The fail-safe behaved correctly — not dispatched, not judged,
fed back as not-a-result.

The likely mechanism is a prompt-contract gap rather than a model error: `REFINE_PROMPT` shows the
previous round's setup **shapes** under `SETUP_SHAPE_HEADER`, which reads as though those setup
responses are still addressable. They are not — `setup_results` is rebuilt per proposal inside
`_run_one_round`, so index 0 exists only if *that* proposal carries its own setup step. The
disclosure that was added to stop the model guessing field names now invites it to reference a
round that is gone.

**Do not "fix" this by making setup results persist across rounds** — that would make an
experiment's evidence depend on state established by a different experiment, which is the seeding
problem the milestone forbids. The contract, not the lifetime, is what is wrong.

#### CLOSED 2026-09-10 — the disclosure is scoped to its round, and the prompt says so

**The choice, and why.** Two fixes were available: carry the prior round's setups forward so the
references resolve, or scope the disclosure and state the rule. **Scoped.** Carrying them forward
would let one experiment's control depend on another experiment's setup — precisely what *"no
external seeding"* excludes. The milestone asks that **the ledger alone** support a claim, and a
value produced by an experiment that is not the one being judged is not in that experiment's
record. Fixing the lifetime would have bought three working references at the cost of the property
the whole phase exists to measure.

`SETUP_SHAPE_HEADER` now names the round it describes and says outright that those responses are
**not still addressable** and must be repeated in the proposal's own `setup` to be used;
`REFINE_PROMPT` states the same rule in the reply contract, with the measured consequence beside
it. Note the shape of the original defect: **the disclosure added to stop the model guessing at
field names invited it to reference a round that no longer existed** — a fix creating its own
successor, the pattern this file has now recorded four times.

Tests: `tests/test_setup_scope_per_round.py`, 5 tests, **2 red first** — the two that pin the
contract. The other three are the must-not-break direction (both rounds keep the reference syntax;
an unbacked reference still aborts; a proposal supplying its own setup still resolves) and
**protected nothing new** — they are there so a future edit cannot buy clarity by loosening the
fail-safe.

### P2 — A SETUP REQUEST THAT FAILED IS REPORTED TO THE NEXT ROUND AS A BAD REFERENCE

**Severity: P2 (it points the model at the wrong repair). RECORDED, NOT FIXED.**

CM1's `/api/Addresses/{id}` experiment ran `POST /api/Addresses` as setup; the target answered
**HTTP 500**. The outcome fed back was
`UNRESOLVED REFERENCE … {{setup.0.data.id}}: setup response body is not JSON`.

That sentence is true and it is misleading: it describes the reference, when the fact that matters
is that **the setup request failed**. A model reading it has every reason to change the dotted
path and none to fix the request body that 500'd — and in CM1 the next round did neither, because
of the P2 above. The shape line has the same gap: `HTTP 500; field paths: (none …)` names the
status but the outcome text the model actually reasons from does not.

**Same family as the two entries above it in this file:** a component correct on its own axis
(the resolver truthfully reports what it could not resolve) is wrong about what the next component
will do with its output.

#### CLOSED 2026-09-10 — the status is consulted before the path is blamed

`_resolve_text` already held the setup's `WebResult`; it read only `.body`. It now reads `.status`
first and raises `SetupRequestFailed` for a `>= 400` or a `None`, naming the status and saying
which request to fix. `_run_one_round` catches it ahead of its parent and records
`SETUP FAILED (experiment NOT run, this is not a result)`.

**`SetupRequestFailed` subclasses `UnresolvedReference` deliberately.** Every existing
`except UnresolvedReference` goes on aborting exactly as before — a failed setup leaves the state
unestablished either way — so this change alters **what is said and nothing about what runs**. A
sibling class would have been a behaviour change wearing a message fix.

**The boundary is half the fix.** 2C4's failure was a rich body and a wrong path, and that must
keep pointing at the path: a `200` whose JSON lacks the field still says `no field 'id'`, and a
`200` that is not JSON still says `not JSON`. Both are pinned, because a fix that swallowed them
into "setup failed" would trade one misdirection for another.

Tests: `tests/test_setup_failure_is_not_a_bad_reference.py`, 7 tests, **6 red first** — though two
of those six were red only on the missing class name, so their behavioural value arrives with the
fix rather than before it. The single test green from the start (a working setup still resolves)
**protected nothing new**. The last test drives the real `_run_one_round` against a target that
500s every POST, because the whole loss in CM1 was in the hand-off from resolver to outcome text,
and a test of the exception alone would not have covered it.

### P1 — ONE UNPARSEABLE STRATEGIST REPLY ENDS THE ENGAGEMENT, REPORTED AS "DONE"

**Severity: P1 (it abandoned 54 of 70 steps and $2.93 of a $4.00 budget on one reply).
RECORDED, NOT FIXED.**

CM1 stopped at step 16 with `stop_reason: "done"`, rendered to the operator as
**"nothing left to safely automate"** and printed into `report.md` as **"Stopped because: done"**.
The actual event, one line earlier in the transcript:

```
strategist: could not extract an action from model reply: "PHASE: exploitation\n\nGOAL: Fix the
UNION-based SQLi against `/rest/products/search` — our first attempt threw a syntax error because
the closing parens didn't match the app's actual WHERE clause nesti…"
```

The model had proposed a next action. `strategist.py:429` warns only when the reply *clearly tried*
to propose one (a marker or a fence is present), so the warning firing is itself evidence that this
was an attempted action and not a deliberate advice-only turn. `_salvage_command` did not recover
it, every field came back `None`, and the loop read "no action" as "finished".

**This is the truncated-reply defect (`37b3957`, 2026-08-12) from a second angle, and it is worse
in one respect.** That fix keyed on the backend's `finish_reason` so a cut-off reply could no
longer end the loop. This reply was not cut off by the backend — it was *unparseable by us* — so
it takes a different path to the same wrong conclusion, and arrives at a **more confident** wording:
truncation stopped the loop saying "nothing left to do", while this stops it saying **"done"**, on
every surface a reader has. A run that abandons 77% of its budget must not be able to describe
itself with the same word as a run that finished.

**Do not fix by loosening the parser alone.** The property is that *the loop must not treat "we
could not read the reply" and "there is nothing to do" as the same state* — the parse failure
needs its own stop reason and its own line in the report, whatever the parser then recovers.

#### CLOSED 2026-09-10 — the original property was too narrow, and this is the uncovered door

`37b3957` shipped *"a reply that never FINISHED is not a decision"*, keyed on the backend's
`finish_reason`. That is **one cause** of a missing action line. The general property is
*"a reply that did not give us an ANSWER is not a decision"*, and an unparseable-but-complete
reply satisfies it while failing every check the narrower version had: `end_turn` is not a
truncation stop reason, so the retry never armed and the loop fell straight through to `done`.

**Fixing the reported symptom left the class open.** This is the same lesson the `-n` third
construction site and the truncation-then-phase-still-unreached entry above teach, arriving here
as *a property stated at the level of its first cause*. The retry is therefore now keyed on
`StrategistAgent._unanswered()` — "no action, and either truncated or unreadable" — so a third
cause discovered later inherits the retry rather than needing a third fix in the same shape.

- `Suggestion.unreadable` carries the condition `strategist.py` was **already computing** at the
  warning site and spending on a log line nobody consumed.
- `loop.py` gains a `unreadable` stop reason beside `truncated`; `done` now means only what it says.
- The operator sentences moved to a module-level `_STOP_LABELS`, and a test scans `loop.py` for
  every `_finish()` reason and fails when one has no sentence. **That scan immediately found a
  pre-existing gap: `target-unhealthy` had no label**, so run 2C2 — which stopped for exactly that
  reason — showed the operator a bare identifier. Added in the same change.
- Tests: `tests/test_unreadable_reply.py`, 9 tests, **7 red first**. The two that were green from
  the start are the must-not-break direction (a usable reply is not retried; a genuinely
  action-free reply is still `done`) and they **protected nothing new** — they are there so the
  fix cannot buy its retry by re-asking questions the model already answered.

---

## RUN CM2 — capability milestone, attempt 2 (2026-09-11). What the four fixes did, and four new findings

Artifacts, preserved: `runs/audit_juiceshop_cm2.jsonl` (587 entries, keyed, `chain intact: True`) ·
`runs/vault-cm2/172.20.0.3/` (62 files) · pre-flight `runs/audit_preflight_cm2.jsonl` (67 entries)
and `runs/vault-preflight-cm2/`. Scope `brukal-juiceshop-cm2-172.20.0.3`, Juice Shop v20.2.0
recreated fresh, `rate_limit_per_min: 120`, `--max-steps 70 --max-cost 12.00` (dollar cap set above
the projected spend so STEPS bind — disclosed in the scope's `_budget_note`). 22 of 70 steps,
34 calls, **~$1.45**.

**Funnel: proposed 7 · dispatched 7 · RESOLVED 2 · JUDGED 2 · confirmed 1.** Compare CM1
(7/7/1/1/0) and 2C4 (9/9/0/0/0).

### The three fixes that demonstrably worked, measured on this run

- **Fix 3 (`5415faa`) — closed, and the number is unambiguous.** CM1's artifacts contain
  `no setup response at index` **9 times**; CM2's contain it **0 times**. Every reference in CM2
  addressed a setup request that actually ran. Scoping the disclosure rather than carrying setups
  forward was the correct half of that choice.
- **Fix 4 (`1219e64`) — closed and load-bearing.** Four of the seven experiments were refused with
  `SETUP FAILED … HTTP 500 … Fix that request, not the reference`, naming the status. Under CM1's
  wording all four would have read as bad references.
- **Fix 1 (`a1978af`) — the sibling branch fired and was reported correctly.** The run ended on a
  truncated reply. `stop_reason: truncated` in the checkpoint, `| Stopped because | truncated |` in
  `report.md`, and the operator line was *"the model's reply was cut off before it named an action
  — retried once and still incomplete, so this is NOT 'nothing left to do'"*. **Ledger, report and
  operator agree, and the word `done` was not used.**
- **Fix 2 (`3265eb6`) — worked for the first principal.** Carriage `cookie:token`, `confirmed: True`,
  recorded on the ledger against `brkAad87e07da2@brukal.test`. `/rest/user/whoami` returned
  `{"user":{"id":25,…}}` where CM1 got `{"user":{}}`. `auth_confirmed` was `None` immediately after
  login, confirming the cost fix: owed at login, paid at first authenticated use.

### P1 — THE SECOND PRINCIPAL IS NEVER CONFIRMED, AND ON THIS TARGET IT IS ANONYMOUS TO HALF THE APP

**Severity: P1 (it is the cross-account class, which is the milestone). Found in PRE-FLIGHT, before
any budget was spent, and recorded here after the run. RECORDED, NOT FIXED.**

`confirm_authentication` is a method on the session's own `Principal`. The second identity is a
**dict** (`_second_identity`), established inside `_separate_identity`, and
`establish_second_identity` never pays the confirmation. The carriage ledger for CM2 therefore holds
**one** `authentication_carriage` record, for the first principal only — so "recorded per principal"
is, precisely, *recorded for one of two principals*.

Measured on the live target before the run:

| request | answer |
|---|---|
| `whoami` as `self` | `{"user":{"id":25,"email":"brkAad87e07da2@…"}}` |
| `whoami` as `second` | `{"user":{}}` — **byte-identical to anonymous** |
| `whoami` as `anonymous` | `{"user":{}}` |
| `/api/Cards` as `self` | `200 {"data":[{"UserId":25,…}]}` |
| `/api/Cards` as `second` | `200 {"data":[]}` — distinct from anonymous |
| `/api/Cards` as `anonymous` | `401` |

So `as: second` is a **real, distinct principal on header-reading endpoints and collapses to
anonymous on cookie-reading ones**, because the second identity holds a bearer header and an empty
cookie jar. This is one layer below the residual recorded in `8b2c92a`: that entry covers *"no
oracle exists"*; this is *"an oracle exists, the first principal is confirmed, the second is never
asked"*. The fix has to make confirmation a property of a PRINCIPAL rather than of the session.

### P2 — NOT ONE JUDGED EXPERIMENT USED THE SECOND PRINCIPAL

**Severity: P2 (it makes the milestone unreachable by construction on this run). RECORDED, NOT FIXED.**

Five of seven proposals named the cross-account class (`a_denied_b_allowed` on baskets, basket
items and reviews). **All five died before dispatch** — four on setup 500s, one on an unresolved
reference. The two that reached a comparator were both `bodies_differ` on
`/rest/user/security-question`, issued `anonymous` vs `anonymous`.

The nine `experiment_principal` records are `setup/self ×5`, `control/anonymous ×2`,
`variant/anonymous ×2`. **`second` appears zero times.** The second principal was registered
in-harness, held a session, and was never once used in a judged comparison — so CM2 measured the
comparator plumbing and did not measure the cross-account capability at all.

### P2 — THE MODEL DID NOT REPAIR A FAILING SETUP ACROSS ROUNDS, EVEN WHEN TOLD WHICH REQUEST FAILED

**Severity: P2. RECORDED, NOT FIXED.**

`POST /api/BasketItems` answered **HTTP 500** three separate times across both rounds, and
`POST /rest/products/1/reviews` once. Fix 4's message named the status and said *"Fix that request
(method, path, body, or the principal it runs as), not the reference"* — and the next round
proposed the same endpoint with the same shape.

The honest reading is that this is **not** a harness defect: the harness reported the failure
correctly and the target genuinely refuses that body. It is a capability limit at the boundary
between the model and the target's API contract, and it is what actually cost CM2 its
cross-account measurement. **Worth noting before anyone proposes a fifth harness fix: the sentence
was right and it did not change the behaviour.**

### P3 — THE SHAPE DISCLOSURE ONLY COVERS ENDPOINTS A PREVIOUS ROUND ALREADY DISPATCHED

**Severity: P3. RECORDED, NOT FIXED.**

One experiment set up `GET /rest/user/whoami` and referenced `{{setup.0.id}}`, where the body is
`{"user":{"id":…}}` — 2C4's exact failure. But the shape line for that response
(`field paths: user.id, user.email, …`) was recorded **in the same proposal that failed**, and the
disclosure is only fed to the NEXT round. The model had never been shown whoami's shape when it
wrote the reference, and the run ended before a round that would have had it.

**So this is not a recurrence despite the disclosure — it is the disclosure's boundary.** It helps
on an endpoint a previous round already used and cannot help on first use. Note also that this
reference was only reachable at all because Fix 2 made whoami return a populated body.

### P3 — THE PROCESS DOES NOT EXIT AFTER THE ENGAGEMENT COMPLETES

**Severity: P3 (operational). RECORDED, NOT FIXED.**

CM2 printed its full summary — report path, `chain intact: True`, spend line — at 09:41 and the
process was still alive at 17:25, nearly eight hours later, with no further audit writes. An orphan
`python3 -m http.server 29465 --directory /tmp` the agent had started as an OOB listener was still
running inside the cage at 7h40m. In-cage with no published ports, so not an exposure; but a run
that has finished should not need to be noticed.

**Operator note, and it is the maintainer's error rather than Brukal's:** the hang was not detected
for hours because the watch used `pgrep -f "brukal.cli auto …"`, which **matches the very shell
running it**. That failure mode is already recorded in this project's memory from an earlier
session and was reproduced exactly. No budget was lost — the spend line is unchanged from 09:41 —
only wall-clock.


---

## FIX A (2026-09-11) — the strategist's reply was the binding constraint

**CLOSED. Two levers, pinned by separate tests so a run can say which paid.**

`37b3957` and `a1978af` made a truncated reply *survivable* — retried, and honestly named
if it still has no action. Neither made it *less likely*, and it remained the single
largest waste in the programme: two consecutive runs ended before half their step budget
because the model's reply ran out before its action line.

**Lever (i) — ORDER.** `RUN:`/`WEB:`/`MANUAL:`/`SESSION:` now precede `REASONING:` in the
template, with the reason stated to the model in the template itself: *a reply whose
reasoning is truncated still works; a reply whose action is truncated ends the
engagement.* No parser change was needed or made — `_parse` was always order-independent,
which is exactly why **no parser test can detect this lever**. The instruction is the fix,
so the test asserts the instruction.

**Lever (ii) — ALLOWANCE.** `800 -> 2,000`, retry `3,200 -> 8,000` (the factor of 4 is
unchanged). 800 is the number both runs were cut at; 3,200 is the number CM2 was cut at a
second time, so both are known-failing values. Cost of the raise: ~1,200 extra output
tokens per call, about **$0.63 across a 35-call engagement** at sonnet-5 rates, against
the **$10.55 CM2 left unspent**.

**Streaming became a property of SIZE, not of the retry.** `_AnthropicBackend._STREAM_AT =
8_000`: any request at or above it streams. The strategist's raised retry needs it, and
the alternative — a `stream=` flag threaded from each caller — would force a parameter
onto every test double in the suite to serve one call site. Ordinary traffic is untouched:
the strategist plans at 2,000 and the specialists ask for less, so the only callers at or
above the threshold are `run_hypotheses` (8,000) and a retry.

**Two pre-existing tests in `test_streaming_retry.py` were amended, and they had been RIGHT
when written.** They encoded *"only the retry streams"*, which was true while streaming was
a property of the retry. The property moved deliberately; the guarantee they existed for —
the 32,000 retry streams — is unchanged and still asserted. The boundary they defended was
restated at a size that is actually ordinary (2,000), and a new test checks that **usage is
metered on a streamed FIRST call** rather than assuming it from the retry's test.

⚠ **COMPARABILITY.** Reordering the template changes what the model is asked to produce.
**No step count, finding count or spend figure from a run made before this commit should be
compared with one made after it without saying so** — 2C4, CM1 and CM2 are all pre-change.
The funnel counts (proposed/dispatched/resolved/judged/confirmed) are more robust than the
step counts, but they are not immune either.

Tests: `tests/test_action_survives_truncation.py`, 9 tests, **5 red first**. The 4 born
green are the boundaries and **protected nothing new**: an action-first reply cut in its
reasoning is used as-is (`_parse` never cared about order), the reasoning is still produced
and recorded, a genuinely actionless reply is still `done`, and `stop_reason` still agrees
with the operator sentence. They exist so this fix cannot buy reliability by suppressing
the thinking or by re-asking questions the model already answered.
