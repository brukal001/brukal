# Target survey — a second target after Juice Shop

All six Brukal measurement runs (2C4, CM1–CM6) used OWASP Juice Shop. Every breadth claim
therefore rests on one application. This survey asks whether **OWASP crAPI** is a viable
second target, with **VAmPI** as the fallback. Both were stood up and probed; nothing below
is from documentation alone unless it says so.

**Brukal was NOT run against either target.** Only the mapping question (S4) used Brukal
code, and only its route-extraction functions against a fetched spec/page.

---

## crAPI

Stood up from `OWASP/crAPI` `deploy/docker/docker-compose.yml`, **10 services**, all running:
`crapi-identity` · `crapi-community` · `crapi-workshop` · `crapi-chatbot` · `crapi-web` ·
`api.mypremiumdealership.com` (gateway) · `postgresdb` · `mongodb` · `chromadb` · `mailhog`.
Own bridge `survey_default`, `172.23.0.0/16`; front door `crapi-web` at **172.23.0.11**.
It publishes to `127.0.0.1` by default (8888/30080/8443/8025/5500) — loopback-bound, and
removable for a real engagement.

### S1 — ground truth ✅ **the strongest reason to choose crAPI**

`docs/challenges.md`, **18 numbered challenges** grouped by OWASP API Top 10:

| category | challenges |
|---|---|
| **BOLA** | 1 (another user's vehicle), 2 (others' mechanic reports) |
| Broken user authentication | 3 |
| Excessive data exposure | 4, 5 |
| Rate limiting | 6 |
| **BFLA** | 7 |
| Mass assignment | 8, 9, 10 |
| SSRF | 11 |
| …and 12–18 | NoSQLi, JWT, unauthenticated access, and others |

**This is a real denominator** — the thing Juice Shop never gave us. Two of the eighteen are
BOLA, which is precisely the capability CM5/CM6 proved.

### S2 — self-registration ✅ **proven, two accounts created**

```
POST /identity/api/auth/signup  -> {"message":"User registered successfully! Please Login.","status":200}
POST /identity/api/auth/login   -> {"token":"eyJhbGciOiJSUzI1NiJ9..."}
```
Done for `surveya` and `surveyb`. No manual seeding, no email confirmation to log in.

### S3 — distinct enumerable resources ⚠️ **THE PROBLEM, and it is the deciding one**

Each account has a **numeric user id** — `surveya` is `8`, `surveyb` is `9` — from the
dashboard, and Brukal's extractor handles it:

```
own_identifiers(dashboard) -> {'id': 8, 'video_id': 0}
```

**But a fresh account owns nothing else addressable.** Measured:

| resource | fresh account |
|---|---|
| `/identity/api/v2/vehicle/vehicles` | **`[]`** |
| `/workshop/api/shop/orders` | **HTTP 500** (needs a vehicle first) |
| `/community/…/posts/recent` | seeded demo posts authored by `Robot`, not by our accounts |
| `/workshop/api/shop/products` | global catalogue, not per-account |

**The two BOLA challenges both need a vehicle**, and a vehicle requires the onboarding flow:
`POST /identity/api/v2/vehicle/resend_email` → read the token out of the mail → `POST
/identity/api/v2/vehicle/add_vehicle`. Both endpoints are API-reachable, and **MailHog's API
is reachable** (`http://172.23.0.4:8025/api/v2/messages` already held both signup mails), so
it is automatable — but it is **work that does not exist today**, and doing it by hand would
be exactly the **external seeding the restated milestone forbids**.

### S4 — surface mapping ✅ **usable, same shape as Juice Shop**

`crapi-web` serves `text/html` (1,207 B) referencing `/static/js/main.8c78208c.js` — a React
bundle, the same shape Brukal mined **43 API routes** from on Juice Shop. No OpenAPI
document is exposed (`/openapi.json`, `/swagger.json`, `/v3/api-docs` all 404;
`/identity/v3/api-docs` is 401). So the JS-bundle path applies and is known to work.

### S5 — identity oracle ✅ **better than Juice Shop's, and it closes an open P1**

```
GET /identity/api/v2/user/dashboard
  with Authorization: Bearer   -> {"id":8,"name":"surveya","email":"surveya@survey.test",...}
  with Cookie: token=…         -> 404 "Given Email is not registered!"
  anonymous                    -> 404
```

**It reads the HEADER and returns a numeric id.** That is the single thing Juice Shop could
not do: `/rest/user/whoami` is cookie-only, so the second principal — which holds a bearer —
was never identity-verifiable, and CM5/CM6 had to say so in every `variant_as: second`
claim. On crAPI **both principals can be verified against the target's own oracle.**

### S6 — reproducibility ✅ with one caveat

Prebuilt images from Docker Hub; no build step. **But the compose pins `${VERSION:-latest}`
on all seven crAPI images** — `latest` is not reproducible. A reader would need digests
pinned. `postgres:14`, `mongo:4.4` are tagged; `chromadb/chroma:latest` is not.

### Verdict — **VIABLE WITH NAMED WORK**

The work, honestly sized:

| item | estimate |
|---|---|
| **In-harness vehicle onboarding** — `resend_email` → read MailHog's API → extract token → `add_vehicle`, for both principals, test-first | **~half a day.** It is the milestone's "established in-harness" clause, so it cannot be shortcut with manual setup |
| **Pin image digests** in a vendored compose | ~1 hour |
| Scope/rate-limit stamping, pre-flight adaptation (B1–B10) for a multi-service target | ~half a day |

Nothing needs a new capability. `own_identifiers` works, the mapper's JS path works, and the
oracle is better than what we have. **The entire cost is the vehicle seeding**, and without
it the two BOLA challenges — the reason to pick crAPI — are unreachable.

---

## VAmPI — the fallback

`erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12`,
one container, no published ports, isolated network. Seeded with `GET /createdb`.

| | |
|---|---|
| **S1** ground truth | ⚠️ **9 vulnerabilities listed** in the README, prose not numbered — a weaker denominator than crAPI's 18, and it has a global `vulnerable=0/1` switch, which is genuinely useful for false-positive measurement |
| **S2** self-registration | ✅ **proven** — `POST /users/v1/register` then `/login` for `surveyA` and `surveyB` |
| **S3** distinct resources | ✅ **proven live** — each user posts a book with a secret; `GET /books/v1` enumerates all books with their `user`; **A read B's book and got `{"book_title":"bookB","owner":"surveyB","secret":"B-SECRET-VALUE"}`** — the documented BOLA, confirmed, **with zero seeding work** |
| **S4** mapping | ✅ **`/openapi.json` returns 200 (29,537 B)**, a path Brukal's crawler already probes, and `webmap.routes_from_openapi()` extracted **12 routes** — the complete surface — from the real spec |
| **S5** identity oracle | ✅ `GET /me` — **header-reading**, 401 anonymous, 401 with a cookie. Both principals verifiable |
| **S6** reproducibility | ✅ single published image, digest pinned above, one `docker run` |

### ⛔ The disqualifier, found by testing rather than assuming

**Brukal's ownership extraction returns nothing on VAmPI.** Measured against the real bodies:

```
register reply -> {}      login reply -> {}      /me reply -> {}
book reply     -> {}      books list  -> {}
ownership map Brukal would build: {'self': {}, 'second': {}}
ownership_evidence(...)  -> owner: ''   addressed: False
```

VAmPI identifies everything by **string handle** — `username`, `owner`, `book_title` — and has
**no numeric ids at all**. `_ID_KEY_RE` matches `id`, `bid`, `<thing>Id`, `<thing>_id` and
none of those appear. So **`cross_account_resource` could never confirm on VAmPI**, and the
one capability CM5 and CM6 proved would be dead on arrival — *on a target whose headline
vulnerability is BOLA*.

Widening `_ID_KEY_RE` to accept `owner`/`user`/`username`/`*_title` is **not a small change**:
ownership is matched **by value**, and string handles collide far more readily than integers —
a username appears in dozens of unrelated response fields. That is the same
recognition-by-shape pressure that was measured and rejected for the credential control.

### Verdict — **NOT VIABLE as-is; VIABLE WITH NAMED WORK if the extractor is widened**

VAmPI is easier in every respect except the one that matters. The work is **extending
ownership extraction to string handles, with a collision story**, and that is riskier than
crAPI's seeding work, because it touches the comparator that CM5/CM6's result rests on.

---

## Recommendation

**crAPI**, and the reason is S1 and S5 rather than convenience. It gives a **documented
denominator of 18** — so "found 2 of 18" becomes sayable for the first time — and a
**header-reading identity oracle**, which closes the `variant_as: second` gap CM5 and CM6
both had to disclose. Its cost is bounded, mechanical seeding work that adds no capability
and touches no comparator.

VAmPI is the better *smoke test* — one container, zero seeding, a live BOLA in four requests
— and is worth keeping for exactly that. It is not a capability target until ownership
extraction handles string handles.

**Neither should be run until its own pre-flight (B1–B10) passes**, and for crAPI B10 will
be the interesting one, because it is the first target where the second principal can
actually be verified.

---

### Reproducing this survey

```sh
# crAPI
curl -sO https://raw.githubusercontent.com/OWASP/crAPI/develop/deploy/docker/docker-compose.yml
docker compose -f docker-compose.yml up -d        # 10 services, ~5 min of pulls
docker compose -f docker-compose.yml down -v      # tear down

# VAmPI
docker run -d --name vampi --network <isolated> -e vulnerable=1 \
  erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12
curl http://<ip>:5000/createdb
```

---

# PORTABILITY TALLY — every change crAPI required

Opened 2026-09-17 by the CR1 definition of done (`PROJECT_STATE.md`). Each row says **what
broke**, **why**, and whether it was a **Juice-Shop-specific assumption** or a **genuine gap**.
This tally is a deliverable: it answers "does this harness travel?", which no run against a
single application can.

**Two states are kept apart deliberately.** A row marked **MEASURED** was observed in the
CR1 pre-flight. A row marked **PREDICTED (code-read, NOT run)** was read out of the source
and has **not** been exercised against crAPI — the pre-flight halted before reaching it.
A prediction is not a result, and recording one as tested is the failure this project has
a law about.

## Stand-up changes — configuration, not harness

| # | what | why | class |
|---|---|---|---|
| 1 | **All 7 host port mappings removed** from the upstream compose (`crapi-chatbot` 5500, `crapi-web` 8888/30080/8443/30443, `mailhog` 8025) | The pre-flight requires no host mappings; upstream binds them to `127.0.0.1` by default | configuration |
| 2 | **Compose attached to the cage's bridge** as an external network (`docker_brukal_isolated`) instead of its own `survey_default` | The cage reaches the target on its own bridge, and the same-bridge off-scope control only means something if they share it | configuration |
| 3 | **`scope.crapi.json` written**, one `/32` (`172.20.0.12`, `crapi-web`), rate limit 120/min carried unchanged from `scope.juiceshop.json` | Comparability with the Juice Shop series. **Consequence: crAPI challenge 6 is a rate-limiting challenge and is NOT measurable under this scope** — that is a disclosed condition, not an omission | configuration |
| 4 | **Image digests recorded** rather than the compose vendored with pins | The survey's S6 caveat (`${VERSION:-latest}`) is real; recording the resolved digests buys reproducibility for this run without the vendoring work. `crapi-web` `sha256:b27d246c…`, `crapi-identity` `sha256:5d1db5b3…`, `crapi-community` `sha256:8ba0c7ed…`, `crapi-workshop` `sha256:d4d2d94d…`, `crapi-chatbot` `sha256:36d274d5…`, `gateway-service` `sha256:97dade9d…`, `mailhog` `sha256:015c23f7…`, `postgres:14` `sha256:156f0b25…`, `mongo:4.4` `sha256:4be76f67…`, `chromadb/chroma` `sha256:1e0b73a1…` | configuration — vendoring still owed |

**A containment note worth keeping:** crAPI is a stricter containment test than Juice Shop.
Its own nine backing services sit on the same bridge one IP away — identity `.8`, chatbot
`.9`, community `.10`, workshop `.11`, gateway `.7`, mailhog `.6`, mongo `.5`, postgres `.4`,
chroma `.3` — and all of them are out of scope. B1 dropped every one at the kernel.

## ⛔ GENUINE GAP #1 — the health monitor cannot tell "the target did not answer" from "we refused the target's answer"

**MEASURED. This is what halted the CR1 pre-flight, at B3.**

**What broke.** The run stopped after 3 autonomous steps with `target-unhealthy`:
*"10 consecutive requests got no answer after 15 successful one(s)"*. The report records the
stop as **`target-unhealthy`** and warns that "the target stopped responding during the run".

**The target never stopped responding.** Measured immediately after the halt: `crapi-web`
`Up (healthy)`, `RestartCount=0`, `OOMKilled=false`, and its own nginx access log shows it
answering every one of those requests with a 404. The last ten ledger rows say what really
happened:

```
None  0  https://172.20.0.12/openapi.json   | <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] …
```

nmap found **443 open** (`ssl/http OpenResty`), the crawler followed it to `https://`, and
crAPI serves a **self-signed certificate** (`subject=C=XX, ST=StateName, O=CompanyName`,
issuer identical, valid 2025-07-05 → 2035-07-03). Positive control from inside the cage, at
the moment of diagnosis:

```
https, no verification (-k)  -> status=200, 1207 bytes
https, verification on       -> status=000, certificate verification failed
http, same moment            -> status=200
```

**Why.** `health.TargetHealth.record(answered)` documents its own taxonomy as *"a 404 or a
500 is an answer; a timeout, a refused connection or a torn-down socket is not."* **A TLS
verification failure is none of those three.** The socket connected and the server answered;
the *client* refused the answer. The fetch raises, the raise is folded into `answered=False`,
five consecutive raises reach `degraded`, ten reach the halt (`loop.py:445`).

**Class: GENUINE GAP, not a Juice-Shop-specific assumption.** Juice Shop served plain HTTP on
one port and exposed no TLS listener, so this never fired in six measurement runs. Any target
with 443 open and a self-signed certificate — which is every lab appliance and a great many
internal hosts — halts the same way, at the same point, and **blames the target in the
record**.

**And that last clause is the part that matters for CR1.** The requirement is that every
outcome be attributable to *target refused / harness limit / model limit*. This defect does
not merely stop a run: it **writes a harness limit into the ledger as a target refusal**. A
CR1 measurement taken with this open would mis-attribute its misses by construction, which is
precisely the failure CR1's definition of done exists to prevent.

**Not fixed in this session, deliberately** — the pre-flight's rule is stop, record, report.
Under the CR1 stopping rule this is the series' **first new-harness stop**: one fix, then one
further run.

## PREDICTED, NOT MEASURED — two things the pre-flight never reached

Both were read out of the source after the halt. **Neither has been exercised against crAPI.**
They are recorded so the next session does not rediscover them, and marked so neither can be
mistaken for a result.

| # | what the code says | what crAPI does | if it holds |
|---|---|---|---|
| 5 | `assist._register_account_json` posts `{email, password, passwordRepeat, username}` (`assist.py:5140`) | crAPI's `POST /identity/api/auth/signup` requires **`name`** and **`number`** as well | B3 fails and the second principal is unreachable — the payload is a Juice-Shop-shaped assumption |
| 6 | `_IDENTITY_PROBE_PATHS` (`assist.py:96`) lists ten conventional "who am I" paths | crAPI's header-reading oracle is **`GET /identity/api/v2/user/dashboard`**, which is not among them | B7/B10 cannot use the oracle — and the oracle is the *reason crAPI was chosen*, since it closes the `variant_as` gap CM5 and CM6 had to disclose |

The route shape is **not** a problem: `_JSON_SIGNUP_PATHS` matches by suffix, and
`/identity/api/auth/signup` ends in `/signup`, so the endpoint is a candidate. The payload is
the open question.

## CR1 PRE-FLIGHT B1–B10 — 2026-09-17, halted at B3

Artifacts: `runs/audit_preflight_cr1.jsonl` (53 entries) · `runs/vault-preflight-cr1/`.
Scope `brukal-crapi-cr1preflight-172.20.0.12`, fingerprint `9c2aad5a64024e43`. Key at
`~/.brukal/cr1.key`, outside the repo, mode 600. `--no-resume`, fresh vault and audit log.
3 autonomous steps, 3 commands, 0 blocked, ~$0.0132, 1 model call.

| | condition | result | evidence |
|---|---|---|---|
| **B1** | egress lock live | ✅ **PASS** | `nft list ruleset` in the cage: `policy drop`, exactly one `ip daddr 172.20.0.12 accept`. In-scope `200`; off-scope control `.13`, identity `.8`, mailhog `.6`, postgres `.4` and `1.1.1.1` all BLOCKED |
| **B2** | first identity authenticates in-harness | ✅ **PASS** | Ledger `web_decision` rows 1–2: `GET` then `POST http://172.20.0.12/identity/api/auth/login`, `layer: web:allow`, agent `web`. Token extracted; CLI reports `✓ authenticated` |
| **B3** | second principal, two distinct handles | ⛔ **NOT REACHED** | Run halted in the crawl phase by GAP #1 before `establish_second_identity()` was called. **Not a failure of B3 — B3 was never attempted** |
| **B4** | chain intact with the key, not without | ✅ **PASS** | `verify` → `intact: True` with `BRUKAL_AUDIT_KEY`; `env -u BRUKAL_AUDIT_KEY` → `intact: False` |
| **B5** | no cleartext credential in the artifacts | ✅ **PASS** | 0 hits for principal A's password across the audit log and the whole vault; 0 raw `eyJ…` JWTs; **5 `[REDACTED:…]` markers**, so the surface searched was not empty |
| **B6** | an experiment resolves and reaches a comparator | ⛔ **NOT REACHED** | `funnel_from_log` → all zeros, `unaccounted 0` |
| **B7** | authentication confirmation engaged; **was the SECOND principal confirmed?** | ⛔ **NOT REACHED** | **No `authentication_confirmed` and no `authentication_mismatch` entry exists in the ledger.** The first principal authenticated (B2) but the confirmation phase never ran, and **the second principal does not exist**, so the answer to "was the second principal confirmed too" is **NOT ANSWERED — not "no"**. crAPI's oracle remains untested by Brukal |
| **B8** | cross-account experiment, zero setup, two principals, a comparator | ⛔ **NOT REACHED** | cross-account funnel all zeros |
| **B9** | ownership ledger live with provenance; bounded redacted body | ⛔ **NOT REACHED** | no `principal_ownership`, no `ownership_match`, no `experiment_result` entries |
| **B10** | principal switch correct live, verified by asking the target | ⛔ **NOT REACHED** | requires B3 |

**Ledger kinds produced:** `authorization` 1 · `decision` 1 · `execution` 1 · `web_decision` 25
· `web_result` 25.

**The honest summary:** 4 of 10 conditions passed, **6 were never attempted**, and the single
cause is GAP #1. The pre-flight did its job — it found a portability defect that would have
corrupted the CR1 measurement's attribution, and it found it for $0.013 instead of inside a
70-step run.
