# Case study — Juice Shop 2C, the criterion-#2 measurement (172.20.0.3, 2026-08-20/21)

> **Verdict: criterion #2 is NOT MET.** The loop planned business logic for the first time
> and recorded its evidence for the first time, but no business-logic finding was
> confirmed. The blocker is a **fixable plumbing gap, precisely root-caused below — not a
> capability boundary.** The model's reasoning was never the limitation in this run
> either; the experiment engine was never allowed to ask it anything.

| | |
|---|---|
| Target | OWASP Juice Shop v20.2.0, `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`, recreated fresh |
| Scope | `172.20.0.3/32`, expires 2026-08-21, engagement `brukal-juiceshop-2c2-172.20.0.3` |
| Tenants | A = `brukal.a@juice.test` (id 25, basket 6) · B = `brukal.b@juice.test` (id 26, basket 7, address 7, card 7, order placed) — both seeded **externally**, absent from the audit |
| Run | 50 / 70 steps · 44 commands · 6 blocked · 73 LLM calls · **$3.89** · `stop_reason: target-unhealthy` |
| Audit | `runs/audit_juiceshop2c2.jsonl`, 245 entries, keyed, **chain intact** |

---

## 1. Did the planner include the business-logic phase? — **YES. Defect-2 fix confirmed live.**

The model authored **seven** steps and dropped the same four phases it dropped on
2026-08-16 — configuration, authentication, cryptography, business-logic, client-side.
The coverage floor appended five, and the plan Brukal actually worked was:

```
 1..7   [model's own]  recon · input-validation · authorization · input-validation ·
                       session · access-control · error-handling
 8. [x] [configuration]   ... [WSTG-CONF]      ← appended
 9. [x] [authentication]  ... [WSTG-ATHN]      ← appended
10. [x] [cryptography]    ... [WSTG-CRYP]      ← appended
11. [x] [business-logic]  Business-logic flaws: workflow bypass, price/quantity
                          tampering, race conditions [WSTG-BUSL]   ← appended
12. [x] [client-side]     ... [WSTG-CLNT]      ← appended
```

`plan_cursor: 12` — the whole plan was consumed. **Step 11 does not exist in this plan
without the fix**, and the model demonstrably would not have written it: given the same
methodology text and a fresh target, it omitted the phase a second time. The floor is not
a theoretical guard; it fired on the first run after it was built.

## 2. Did the `{{setup.*}}` experiments resolve and dispatch? — **NO. Never asked.**

Zero `[experiment]` records anywhere — `findings.jsonl`, `engagement.md`, the agent
notes. The report's coverage table has **no `Model-proposed experiments` row at all**,
and by that table's own footnote an absent class "was not reached at all".

**Root cause, reproduced deterministically (3/3 attempts against the live crawled surface):**

1. `run_hypotheses` asks for experiments with `max_tokens=8000`.
2. The model spends the **entire allowance on thinking** — returns `""`,
   `stop_reason=max_tokens`, no text block.
3. `LLMClient.propose` correctly recognises that case and retries with room:
   `bigger = min(8000 × 4, 32_000)` = **32,000**, still non-streaming.
4. The Anthropic SDK **refuses before sending**:
   `ValueError: Streaming is required for operations that may take longer than 10 minutes.`
5. `run_hypotheses`' `except Exception: return 0` (`assist.py:3608`) swallows it — no
   note, no coverage row, no trace.
6. REFLEX 0b is `_confirmed_done`-gated to fire **exactly once**, so that single
   swallowed error removed model-proposed experiments from the entire engagement.

**This is the project's recurring lesson for the fourth time, and the sharpest instance
yet: the thinking-retry was built to fix a silent failure and introduced a silent failure
of its own.** Its docstring says the old behaviour "looked like a model with nothing to
say about the target. It had plenty to say; it never got to the part where it says it."
That is now true again, one layer down.

**It is worst exactly where it matters most.** The failure needs the model to exhaust
8,000 tokens thinking — which happens when the surface is rich. On a hand-made three-route
surface the call succeeded and parsed 5–6 proposals; on the real 43-route crawl it failed
every time. *The more interesting the target, the more certain the capability disappears.*

**The capability itself is intact, and was verified independently.** With the call
succeeding, the model proposes exactly the right experiments **in the documented syntax it
was given last session** — including Juice Shop's `{status, data:{…}}` envelope, which it
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
writes `{{setup.0.data.id}}` because that is the contract — but nothing dispatched it, so
**the substitution path remains unexercised against a live target.** Zero literal `{{`
reached the wire and zero `UnresolvedReference` fired, but both are vacuous: no experiment ran.

### A second, independent gap on the same path
`establish_second_identity()` returns `""` on this target. It needs an HTML `<form>` via
`_signup_form()`; Juice Shop is an Angular SPA and has none, so `_register_account()`
returns `None`. **Without a second principal, `a_denied_b_allowed` — the comparator built
for authorization — is unconstructible**, and every cross-account experiment above would
have degraded to `self` vs `anonymous` even had the call succeeded. Pre-existing, not
introduced here, and it bites the entire SPA class.

## 3. The negative-quantity acceptance case — **body captured (defect-1b confirmed), finding not confirmed**

The loop reached the endpoint again and the record now reads:

```
ALLOW:  status=200 (154B)
{"status":"success","data":{"ProductId":1,"BasketId":1,"id":1,"quantity":2,
 "createdAt":"2026-08-20T13:46:30.599Z","updatedAt":"2026-08-20T13:46:30.599Z"}}
```

On 2026-08-16 the same request recorded `ALLOW:  status=200 (154B)` and nothing else.
**The evidence-body fix is live and works on the exact endpoint it was built for.**

Two honest qualifications:

- **The model sent `quantity: 2`, not `-100`.** The negative-quantity flaw was not
  re-triggered this run, so the acceptance case is met *as plumbing* and not *as a
  finding*.
- **A real cross-user write happened and went unrecognised.** User A holds basket **6**;
  it issued `PUT /api/BasketItems/1` — item 1 belongs to **BasketId 1** — and got `200`
  with the write confirmed in the body, three separate times. That is object-level
  authorization missing on `BasketItems`, performed live and recorded in full. It is not a
  finding because **only the comparator may declare one**, and the comparator machinery
  was down (§2). The governance held; the capability to notice did not.

That is the whole run in one line: **the harness now records enough to see the bug, and
has no working path to confirm it.**

## 4. Redaction — clean, including the new body captures

Zero JWT cleartext (`eyJ`) and zero JWT-shaped strings on every surface:

| Surface | `eyJ` | `REDACTED` markers |
|---|---|---|
| `audit_juiceshop2c2.jsonl` (245 entries) | **0** | 12 |
| `findings.jsonl` / `findings.json` | **0** | 4 / 2 |
| `report.md` / `report.json` / `brukal.sarif` | **0** | 2 / 2 / 2 |
| `engagement.md` · `plan.md` · `checkpoint.json` | **0** | 0 · 0 · 9 |
| all **70** agent notes | **0** | — |

This is the first run in which finding records carry response bodies, so it is the first
real test of the boundary under the wider capture. It holds.

## 5. Containment — proven, same bar as before

Verified **before** any traffic, from inside the cage:

- ruleset non-empty, `policy drop`; **no blanket interface accept** (no live `.ovpn`, so no tun0)
- scope IP pinned: `ip daddr 172.20.0.3 accept`
- target `172.20.0.3:3000` **REACHABLE** · off-scope same-bridge `dvwa 172.20.0.2:80` **DROPPED** · `8.8.8.8:53` **DROPPED** · `1.1.1.1:443` **DROPPED**

In the ledger: **102 web requests answered** (`web_result` entries) from **106 gate decisions**
(`web_decision`) — 208 ledger entries across the two, out of 245 total — **all to `172.20.0.3`**, matching the
report's own `91/102` health line; **zero** occurrences of `172.20.0.2`
anywhere. Denials — `hard:injection` ×8, `hard:web-rate` ×2, `hard:scope` ×1. The scope
denial is invariant 3 working on its own terms: the model tried
`curl -s -I -H "Origin: http://evil.com" http://172.20.0.3:3000/rest/user/whoami`, and the
gate re-read the command, found a host in a *header value*, and refused —
`out-of-scope host evil.com in command`.

Chain: **`audit chain intact: True`** under `BRUKAL_AUDIT_KEY`.

## 6. Why the run stopped early

`stop_reason: target-unhealthy` at step 50/70 — "11 consecutive requests got no answer
after 91 successful one(s)". Juice Shop's error path churns heap on every unknown path and
the app stopped answering; it recovered on its own afterwards. **The health guard did the
right thing** — it halted rather than measure against a degraded target. This did not cause
the §2 failure: the experiment reflex fired at record 16, roughly fifty minutes before the
first no-answer.

Also confirmed live: the sweep ran as `nmap -n -Pn -sV --open -p …` and **completed**,
finding `3000/tcp`. The identical command was killed at the 180 s cap on 2026-08-16. The
`-n` third-site fix is in production.

---

## Scoreboard against criterion #2

| Condition | 2026-08-16 | this run |
|---|---|---|
| Reaches business logic | ✗ never planned | **partial** — planned (§1) and worked, nothing confirmable (§2) |
| Nothing leaks | ✓ | ✓ **including captured bodies** (§4) |
| Chain keyed + intact | ✓ | ✓ (§5) |
| Containment proven | ✓ | ✓ (§5) |
| Publishable either way | ✓ | ✓ |

**Three of last session's four fixes are confirmed live in production**: the planner floor
(§1), the evidence body (§3), and the `-n` third site (§6). The fourth — setup
substitution — is blocked behind a newly-found P1 one layer below it, and remains
unexercised against a live target.

## The one thing to fix next

`LLMClient.propose`'s thinking-retry must not escalate a non-streaming request past the
SDK's limit — stream the retry, or cap `bigger` below it. And
`run_hypotheses`' bare `except Exception: return 0` must record what it swallowed: this
run had a P1 in the capability that matters most, and left no trace of it anywhere in the
evidence. A silent `return 0` erased both the note and the coverage row that were
purpose-built to make "asked and got nothing" visible.

Neither is a capability limit. Both are plumbing.
