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
