# Case study — OWASP Juice Shop at 172.20.0.3:3000 (Part 2B: business logic + live redaction)

> ### 📌 PROVENANCE
> **Target: `172.20.0.3:3000` ONLY — `bkimminich/juice-shop:v20.2.0`, digest
> `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`, container
> `brukal-juiceshop` on the cage's own bridge `docker_brukal_isolated`. Date: 2026-08-12.**
> **This is NOT a Cap record and NOT the DVGA/Juice-Shop-injection workstream described in
> `SESSION_HANDOFF.md`.** Cap is closed (`docs/CASE_STUDY_CAP.md`, `docs/CASE_STUDY_CAP_101_3.md`).
> Ledger for THIS engagement: `runs/audit_juiceshop2b.jsonl` (keyed, HMAC-SHA-256).
> Scope: `scope.juiceshop.json` (uncommitted engagement artifact) = `172.20.0.3/32`.
>
> **Baseline:** HEAD `81d6aa2` (P1 #1 closed: egress fails closed if the ruleset does not
> load). **902 tests** (901 passed, 1 skipped). Brain: `claude-sonnet-5`.
>
> **Purpose:** (1) first live test of whether session material stays out of Brukal's
> artifacts — there is no dedicated redactor, so this MEASURES a property rather than
> verifying a built boundary; (2) a business-logic engagement against an authenticated
> app; (3) the first containment test where an off-scope DROP is genuinely provable.

---

## Headline

| Question | Answer |
|---|---|
| Did Brukal authenticate and carry a real session? | ✅ **yes** — JWT bearer, `brukal-a@juice-sh.op` |
| Does the session token stay out of the artifacts? | ❌ **NO — leaks on 5 of 6 surfaces**, and spreads as the run goes on |
| Did it reach the business-logic objective? | ❌ **no — stalled at methodology step 5 of 10** |
| Why did it stop? | ❌ **a truncated model reply read as "nothing left to do"** — 12 of 20 steps unused |
| Business-logic flaws found | **none — none were attempted** |
| Findings produced | 2, both real, both generic (JWT no expiry · missing CSP) |
| Spend | **~$0.2449** — 8 calls, `claude-sonnet-5` |
| Containment: only the target in the ledger | ✅ **yes** — `172.20.0.3` is the only IP present |
| Off-scope DROP provable | ✅ **yes** — including a host on the SAME bridge |
| Audit chain | ✅ `chain intact: True` (keyed) |

---

## 1. Setup, and why this target

Every previous containment claim was made on HTB, where the VPN pushes a route for the
whole shared `10.129.0.0/16` and the ruleset accepts `oif "tun0"` wholesale (open P1 #2).
An off-scope host inside that tunnel is reachable and the drop counter never moves, so
"scope enforced at the kernel" could not be demonstrated for the destinations that matter.

Juice Shop was therefore stood up as a second container on the cage's own bridge, with **no
VPN at all** (`docker/vpn/config.ovpn` renamed aside for the session). With no `tun0`, the
ruleset carries no blanket interface accept — and after the P1 #1 fix, no rule that could
abort the whole load either:

```
table inet brukal {
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr 127.0.0.11 udp dport 53 accept
    ip daddr 127.0.0.11 tcp dport 53 accept
    ip daddr 172.20.0.3 accept
    log prefix "brukal-egress-drop " counter packets 0 bytes 0 drop
  }
}
```

### Containment, measured before any traffic

| Probe from the cage | Result | Drop counter |
|---|---|---|
| `8.8.8.8` (off-scope, internet) | `000` | +4 |
| **`172.20.0.2:3000` (off-scope, SAME bridge)** | **`000`** | **+4** |
| `172.20.0.3:3000` (target) | `200` | +0 |

The middle row is the one HTB could never produce: an off-scope host one hop away on the
same L2 segment, dropped by the kernel, counter incrementing. On this run the kernel lock
is a real second line of defence rather than a claim that happens to hold.

### Two tenants, so authorization is actually testable

Seeded externally (a throwaway curl container — nothing entered the cage's audit):

- **A** `brukal-a@juice-sh.op` — basket 6, two products, address 7, card 7. Brukal logs in as A.
- **B** `brukal-b@juice-sh.op` — basket 7, address 8, card 8, **order placed**
  (`orderConfirmation eb1c-b95053c13041b092`).

B exists so that "read another user's basket/order" has something real to read. No
challenge hints, no solutions, and no objective text were given to Brukal: it received
credentials and a target, nothing else.

---

## 2. HEADLINE FINDING — the session token is not redacted anywhere

**Severity: P1 (missing redaction boundary). 5 of 6 surfaces leak.** Measured live, twice —
once at the early checkpoint (immediately after the first authenticated request) and again at
the end of the run:

| Surface | At request 1 | End of run | Where |
|---|---|---|---|
| **audit log** | ❌ FAIL | ❌ **FAIL** (10 hits) | `decision.action` in `runs/audit_juiceshop2b.jsonl` |
| **checkpoint** | ❌ FAIL | ❌ **FAIL** (6 hits) | `checkpoint.json` → `executed_cmds` |
| **model prompts** | — | ❌ **FAIL** (34 hits) | **every** LLM call: `ALREADY TRIED` + `RECENT ACTIVITY` blocks |
| **findings** | ✅ PASS | ❌ **FAIL** (4 hits) | `findings.jsonl` → evidence `command` field |
| **blackboard** | ✅ PASS | ❌ **FAIL** (6 hits) | `engagement.md`, agent transcripts `00018.md`, `00037.md` |
| report | ✅ PASS | ✅ **PASS** | `report.md`, `report.json`, `brukal.sarif` clean |

**The leak spreads as the run proceeds.** Two surfaces at the first authenticated request,
five by the end — because the first token-bearing command was DENIED (nothing to record as
evidence) while the second, `nuclei … -H 'Authorization: Bearer …'`, was ALLOWED and ran, so
its command text propagated into the findings evidence, the blackboard and the agent
transcripts. Checking only at the end would have found the same defect; checking at request
one showed that it *grows*, which is the part that matters for an operator deciding whether
an in-flight run can be shared.

The one surface that holds is the report — the deliverable a human is most likely to send
onward. That is worth noting and worth not over-reading: nothing redacts it, it is simply
built from finding titles and summaries rather than from command text.

### What leaks

Not just a token. Juice Shop's JWT payload is the user row, so one line of the audit log
base64-decodes to the account id, the email, `"role":"customer"` **and the password hash**:

```
{"data":{"id":25,"username":"","email":"brukal-a@juice-sh.op",
         "password":"ec084cfaf5…","role":"customer", …},"bid":6,"iat":1786539966}
```

A reader of the ledger gets a working session plus a credential to crack offline.

### The injection site, and why it is structural

`assist.py:757 _session_auth_for()` appends `-H 'Authorization: Bearer <jwt>'` to a **shell**
command so tools like curl/nuclei/sqlmap run behind the login. It runs **before** the gate —
which is correct and must not change: the gate has to judge the bytes that will actually
execute (invariant 3). The audit then records the judged command verbatim.

So the leak is not a slip in one writer. **Every artifact that records a gated shell command
records the token with it**, and the same augmented text is fed back into the model's next
prompt as history. Corollary observed here: the `curl … -X OPTIONS` command carrying the
token was **DENIED** (`hard:injection`) and never ran — the token was persisted anyway. A
denial is not a containment of the log.

*(An earlier guess in this session that the site was `web.py:452-461 _apply_cookies` was
wrong, and the distinction matters: that function attaches auth AFTER the web decision is
logged, which is why the web plane's `web_decision` entries are clean.)*

### Not fixed this session — deliberately

> **FIXED 2026-08-13** — `brukal/redact.py` + `tests/test_redaction.py`; see
> `HARDENING_ROADMAP.md`. The measurement below stands as the record of this run. Two
> corrections it earned: the fix needed **eight** write sites, not the three named here
> (the lesson store and the task tree also record commands, and the lesson store outlives
> the engagement), and **report/SARIF were clean only by luck** — `export.py` writes
> `Finding.source` as `reproduce`, so they were one confirmed token-bearing finding away
> from leaking too.

Per the engagement instruction, this was measured and recorded, not repaired. The fix is its
own test-first piece of work. Design note for whoever takes it: redaction has to happen at
the point of **record**, not at the point of injection (the gate must still see the real
bytes), and it must cover at least `AuditLog.append`, the checkpoint writer, and the prompt
builder — three writers, one shared redactor, keyed on the session material the
`GovernedBrowser` already holds (`auth_header`, `_cookies`) so it never has to guess what a
secret looks like.

---

## 3. The engagement — where the reasoning stalled

**Business-logic flaws found: none.** Not "none confirmed" — none attempted. The loop never
reached the part of its own methodology where business logic lives. Stated plainly because
the misses are the result here.

### What actually happened

Two segments, 20-step budget each, `--full-send`, same stop in both:

| Segment | Steps used | Commands | Stop reason printed |
|---|---|---|---|
| 1 | 7 of 20 | 6 (1 blocked) | "nothing left to safely automate" |
| 2 | 5 of 20 | 4 (1 blocked) | "nothing left to safely automate" |

Every step was `crawl → whatweb → nuclei → nikto → one login probe`. Findings: **2**, both
generic and both real — `JWT has no expiry` (medium) and a missing CSP header (low). Neither
touches basket ownership, price, quantity, coupons or order workflow.

### The stall is a TRUNCATED REPLY, not an exhausted agent

`loop.py:645` returns `stop_reason="done"` — printed as *"nothing left to safely automate"* —
when `session.advise()` yields a suggestion with **no command and no web action**. The
strategist's required reply format (`agents/strategist.py:91-97`) is:

```
PHASE: …
GOAL: …
REASONING: <2-4 sentences>
RUN: <command>        (optional)
WEB: <action>         (optional)
```

**The action line comes last, after free-text reasoning, and the call is made with
`max_tokens=800`** (`strategist.py:519`). Captured from the prompt log, both stalls are the
same event — the reply is cut off mid-`REASONING:` and never reaches `RUN:`/`WEB:`:

```
call 3: 262 chars, action lines: NONE, ends: "…d.\n\nREASONING: We've fingerprinted this as OW"
call 5: 747 chars, action lines: NONE, ends: "…ndard, fast next move and directly tests WSTG"
```

The three calls that *did* fit an action line (836, 864, 957 chars) all produced a `WEB:` and
the loop continued. So the terminal condition is being triggered by an output-length
accident.

The tell is in the stop message itself. Brukal printed:

> ⏹ stopped: nothing left to safely automate
> *Attempt classic Juice Shop SQL-injection login bypass on /rest/user/login (WSTG-INPV)…*

That second line is `suggestion.goal` — **the model's own statement of what to do next.** The
loop announced it had nothing left to do while quoting the thing it wanted to do. A false
"done" is the worst of the stop reasons to get wrong, because it looks like a considered
judgement and it silently caps the engagement: 12 of 20 steps and $3.75 of the $4 budget went
unused across the two segments.

**Recorded as a new P1** — see `HARDENING_ROADMAP.md`. Not fixed this session.

### And beneath that, business logic is 9th in a linear queue

Even with the truncation fixed, the route to the objective is long. `methodology.py:40-65`
orders the WSTG web methodology as recon → configuration → authentication → session →
input-validation → authorization → error-handling → cryptography → **business-logic** →
client-side. Business logic is step **9 of 10**, and its tooling hint is the only one in the
list with no tool at all: *"reason about the app's intended flow"*. Authorization (IDOR,
privilege escalation between roles) is step 6. The loop stalled inside step 5.

So the honest reading of this engagement is: **the business-logic capability was never
exercised, and this run says nothing about whether it works.** What it does say is that a
linear checklist whose interesting half is at the bottom, combined with a loop that can
terminate on a truncated reply, cannot reach that half.

### Two smaller stalls worth recording

- **The crawler sees one page.** `crawled 1 page(s); 5 links, 0 forms, 0 parameterised
  endpoints, 43 API routes`. Juice Shop is an Angular SPA: there is no server-rendered form
  to find, so a crawl-and-fill methodology has almost nothing to grip. The 43 API routes came
  from `swagger.json`, not from crawling. Any workflow testing here has to be driven from the
  API surface, which the loop never turned into a plan.
- **It re-ran the same four probes in segment 2** (crawl, whatweb, nuclei, nikto) despite the
  prompt's `ALREADY TRIED` block listing them. Those four are deterministic pre-steps in
  `loop.py`, not model choices, so the dedup memory does not gate them.

### Cost

| Segment | Calls | Spend |
|---|---|---|
| 2-step checkpoint run | 3 | $0.0399 |
| Segment 1 | 3 | $0.1208 |
| Segment 2 | 2 | $0.0842 |
| **Clean engagement total** | **8** | **~$0.2449** |

(A prior contaminated launch — see §4 — cost a further $0.1873 and is excluded.)

---

## 4. Other defects found while running this

### Vault and checkpoint identity is the bare IP — a recycled address resumes another engagement

**Severity: P2 (evidence isolation).** The first launch printed:

```
↻ resumed from checkpoint — 25 step(s) already spent, 21 command(s) known.
resumed — loaded 35 prior finding(s).
```

`runs/vault/172.20.0.3/` held a **DVGA** engagement from 28 July that had been given the same
Docker-assigned address. Brukal loaded another target's findings, spent-step count and
command history into a Juice Shop run. On a local bridge, private IPs are recycled across
completely unrelated targets, so the bare IP is not an engagement identity.

Archived to `runs/vault/_archived_dvga_172.20.0.3_pre-2b/` and the run restarted with
`--no-resume`; the contaminated ledger is kept as
`runs/audit_juiceshop2b.jsonl.contaminated-resume`. Sibling of the recorded P2 "tests write
into the live `runs/vault/`" — both are the same root cause: the vault has no notion of which
engagement an artifact belongs to beyond a directory name.

**Fix (not this session):** key the vault directory and checkpoint on the scope fingerprint
(`Scope.fingerprint()` already exists) or an engagement id, not the target string alone, and
refuse to resume a checkpoint whose scope fingerprint differs from the current one.

### The `-n` fix has a third construction site it does not cover — and it cost the recon step

**The closed P3 says the rule is applied "at both places a command is constructed". There
are three.** `loop.py:408` builds the web-port sweep directly and hands it to
`session.run()`, bypassing both `parse_action_request()` and the strategist `RUN:` parse, so
`apply_no_resolve()` never sees it. The engagement's very first command went out as
`nmap -Pn -sV --open -p <18 ports> 172.20.0.3` — no `-n` — and was killed at the 180s cap
having emitted only `Starting Nmap 7.99 …`, the exact Cap signature.

Measured afterwards in the cage, same command, same target:

| Command | Result |
|---|---|
| `nmap -Pn -sV --open -p …` (as Brukal issued it) | **killed at 185s**, no output |
| `nmap -n -Pn -sV --open -p …` | **completed in 11.31s**, full service detection |

A 16× difference between "found nothing" and "found everything", on the step that decides
what the rest of the engagement knows about the target. Recorded in the roadmap as a partial
reopen of the P3. The lesson is the one that item already taught once: normalise where the
command reaches the single execution path, not at each site that happens to build one.

### `auto` will not accept `host:port` as a target

`brukal auto 172.20.0.3:3000` is refused — `scope.contains_ip()` is handed the whole string
and the confirmation prompt offers to authorise `172.20.0.3:3000/32`. The port has to be
carried by `--login-url` and rediscovered by recon instead. Cosmetic, but it cost a run.

---

## 5. Reproducing this

```sh
# target
docker run -d --name brukal-juiceshop --network docker_brukal_isolated \
  bkimminich/juice-shop:v20.2.0

# cage, locked to exactly that container (no VPN => no tun0 rule)
docker compose -f docker/docker-compose.yml up -d --force-recreate   # mounts scope.juiceshop.json

# containment, before anything else
docker exec brukal-kali sh -c 'nft list ruleset'
docker/verify_egress.sh brukal-kali 172.20.0.2 172.20.0.3:3000

# the run
brukal auto 172.20.0.3 --yes-authorised --scope scope.juiceshop.json --full-send --web \
  --login-url http://172.20.0.3:3000/rest/user/login --login-type json \
  --login-field-user email --login-field-pass password \
  --login-user brukal-a@juice-sh.op --login-pass '<A password>' \
  --audit runs/audit_juiceshop2b.jsonl
```

The redaction measurement used a scratchpad-only harness that wraps `LLMClient.propose` to
record every prompt; no repo code was modified to take the measurement.
