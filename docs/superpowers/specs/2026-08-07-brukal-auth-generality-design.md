# Authentication generality — design

**Date:** 2026-08-07
**Status:** approved, not yet implemented
**Subsystem:** A of five (see "Where this sits" below)

---

## Problem

Brukal must be told how to log in. Every run supplies `--login-url`, `--login-type`,
`--login-field-user`, `--login-field-pass`. That is per-target tuning, performed by
hand, on every target — the thing this work exists to remove.

Protocol breadth is the smaller half of the problem. `login()` supports exactly
`form`, `json`, and `basic`. A real program is commonly none of those: Decathlon
required OAuth2 with PKCE, Betclic issued an anonymous HS256 token in a `BC-TOKEN`
header, and a large share of modern applications use double-submit CSRF (cookie →
header) that `login()` cannot perform at all.

Both halves matter because **almost every detector family Brukal is good at is
downstream of holding a session**: IDOR, BOLA, BFLA, session fixation, horizontal
takeover, no-session-revocation, default credentials. On a mature program the
unauthenticated surface is usually clean — four rounds against Decathlon found
nothing unauthenticated, and everything of interest sat behind the token.

## Success criterion

On a target Brukal has never seen, given only `--login-user` and `--login-pass`, it
discovers the login endpoint, selects an authentication strategy, and establishes a
confirmed session — with **no code change between prediction and run**.

This is the zero-tuning cold-trial metric applied to authentication. Any change made
after a cold trial must be a generic capability, never a target-specific patch.

## Operating envelope

Unattended runs are **read-only in effect**. Authentication uses credentials the
operator supplies for accounts they own. Anything that writes — account creation,
password change, cross-account writes, uploads — escalates for approval. This
follows the existing gate/ESCALATE design and keeps runs inside typical bug bounty
program rules.

---

## Architecture

New module `brukal/auth.py`. The gate is untouched: strategies receive the
`GovernedBrowser`, which scope-checks every request, and never a cage or the `kali`
object. Invariants 1 (no LLM inside the gate) and 4 (one execution path) hold
unchanged.

```
LoginDiscovery ──► AuthNegotiator ──► AuthStrategy (n) ──► SessionOracle
   (find where)      (rank & try)        (attempt)          (did it work?)
                            │
                            ▼
                       SessionState
              (token · expiry · refresh · identity)
```

### `SessionOracle`

The single answer to "do we hold a session?", lifted verbatim from `assist.py`
`login()` lines 1654–1706.

This is the safety core of the change. That logic has been wrong three separate
ways — a 302 bounced back to `/login` read as success; a 4xx whose body has no
password field read as success; an "account locked" 200 read as success. All three
were the same mistake: inferring success from the *absence* of a login form rather
than from positive evidence of a session.

Today that reasoning is fused to the form branch. Any new auth type added in place
would have re-derived it and re-made those mistakes. Extracting it means every
strategy — present and future — is judged by one hardened test.

### `AuthStrategy`

```python
class AuthStrategy(Protocol):
    name: str
    def detect(self, probe: LoginProbe) -> float: ...        # 0.0–1.0, deterministic
    def authenticate(self, browser, creds) -> AuthAttempt: ...
```

`detect` is deterministic and evidence-based — no model call, no guessing from
names. Evidence includes: a `<form>` containing `input[type=password]`; a
`Set-Cookie` matching the double-submit convention (`XSRF-TOKEN`, `csrftoken`); a
`WWW-Authenticate` header; an OIDC discovery document at
`/.well-known/openid-configuration`; a redirect to an `/authorize`-shaped URL; a
JSON error body naming a credential field.

`authenticate` returns evidence, not a verdict. Only `SessionOracle` decides.

| Strategy | Recognises | Notes |
|---|---|---|
| `FormAuth` | password input in a form | behaviour-preserving port of today's `form` |
| `JsonAuth` | JSON login API | behaviour-preserving port of today's `json` |
| `BasicAuth` | `WWW-Authenticate: Basic` | behaviour-preserving port of today's `basic` |
| `CsrfHeaderAuth` | cookie→header double submit | Angular/Axios/Laravel/Django convention |
| `MultiStepAuth` | identifier page → password page | optional OTP step escalates |
| `OAuth2PkceAuth` | OIDC discovery / `/authorize` | authorization code + PKCE |
| `BrowserAuth` | fallback | tried last, only when Chrome is present |

### `AuthNegotiator`

One `GET` of the login surface builds a `LoginProbe`. Every strategy scores it.
Strategies are tried highest-confidence first, stopping at the first
oracle-confirmed session. Every rejected attempt is recorded with its reason.

**Lockout is a first-class hazard.** Negotiation must not become a credential
attack. Each strategy tries exactly one credential pair; the negotiator caps total
authentication attempts per run and halts immediately on any lockout or throttling
signal. On a real program, locking your own account is the least bad outcome —
locking another user's is a report filed against you.

### `LoginDiscovery`

When `--login-url` is absent, candidate login endpoints come from the crawl and from
the OpenAPI spec (`state_changing_operations` already reads specs). This is what
removes the hand-tuning; `--login-type` and `--login-field-*` become optional
overrides.

**Field-name resolution uses the hybrid rule.** Deterministic first and free:
`type="password"` gives the password field; `type="email"`,
`autocomplete="username"`, or the sole remaining text input gives the user field.
Only when genuinely ambiguous — no `type="password"`, or two or more candidate user
fields with no distinguishing attribute — does Brukal make **at most one** LLM call
per run to read the form, and it must degrade to today's positional heuristic if the
model is unavailable or returns nothing usable. The common case makes zero
additional model calls and stays at today's cost (~$0.07–0.55 per run). The model
proposes field roles; the gate still enforces scope.

### `SessionState`

One object replacing `_cookies` + `auth_header` + `last_jwt` + `authenticated` +
`_login_url` + `_login_type`, currently spread across `assist.py` and `web.py`.

Holds: auth header, token, expiry (from JWT `exp` where present), refresh hook,
identity, login URL, and the winning strategy.

This is what makes refresh possible at all. Today a token expiring mid-crawl
degrades into every subsequent check finding nothing — indistinguishable from a
clean target. A 401 mid-run now triggers one re-authentication through the winning
strategy and one retry.

### Adapter

`AssistSession.login()` keeps its exact public signature and becomes a thin
delegation to the negotiator. Its call sites — `confirm_default_credentials`,
`_separate_identity`, and every cross-account proof — are unaffected, as are their
tests.

---

## Failure handling

**Failure must be loud.** If negotiation fails, Brukal does not silently continue as
though unauthenticated scanning were the plan. Every session-dependent class is
marked **blocked — no session**, never "probed, clean":

> IDOR · BOLA · BFLA · session fixation · horizontal takeover ·
> no-session-revocation · default credentials

A coverage table reporting those as clean when no session was ever held is the same
coverage lie that hid three detectors on 2026-08-07 — the detector ran, spent
budget, emitted a coverage row, and was structurally unable to report.

**BrowserAuth escalates rather than firing silently.** Launching Chrome costs more
than the entire remainder of a typical run, so it is tried last, only when Chrome is
available, and it surfaces as a pause in an unattended run.

**Credentials never reach the audit log or notes.** The existing note prints only
the username and a cookie count. That property gets a test rather than remaining a
habit.

---

## Testing

**Unit.** Each strategy tested in isolation with a *faithful* double — carrying every
attribute the real object exposes. On 2026-08-07 a double missing `.ip`/`.port`
raised into a swallowing `except` and hid a live defect for the whole session.
Doubles that are "close enough" manufacture confidence.

**Oracle regressions.** The three historical false positives get explicit tests: a
302 back to `/login`; a 4xx with no password field; an "account locked" 200 with no
password field. Extracting the oracle is exactly when those lessons would be lost.

**Negotiation.** The right strategy wins on each surface shape — and a *wrong*
strategy scoring high still cannot produce a false session, because only the oracle
confirms one.

**Every new test must be verified to FAIL when its fix is reverted.** A test that
passes against broken code is worse than no test; this has happened here before.

**Live validation.** No strategy ships without firing against a running target.
Three currently have nowhere to fire, so the lab grows as part of this work:

| Strategy | Target | Action |
|---|---|---|
| `FormAuth` | DVNA, DVWA | exists |
| `JsonAuth` | Juice Shop (JWT) | exists |
| `BasicAuth` | trivial container | stand up |
| `CsrfHeaderAuth` | Django or Laravel app | **stand up** |
| `MultiStepAuth` | crAPI | **stand up** |
| `OAuth2PkceAuth` | Keycloak | **stand up** |
| `BrowserAuth` | Juice Shop via Chrome | exists |

The lab doubles as the permanent regression harness for the cold-trial metric.

**Acceptance.** On a cold target, `brukal` given only `--login-user` and
`--login-pass` discovers the endpoint, selects a strategy, and authenticates.

---

## Implementation phasing

Three phases, each independently shippable with the suite green. This ordering keeps
the riskiest change — moving hard-won correctness logic — separate from and before
any new capability, so a regression has only one possible cause.

**A1 — Extract, no behaviour change.** Create `brukal/auth.py`. Move `SessionOracle`
out verbatim, add the `AuthStrategy` protocol, port `FormAuth`/`JsonAuth`/`BasicAuth`
as behaviour-preserving strategies, introduce `SessionState`, and reduce
`AssistSession.login()` to an adapter. **Definition of done: the entire existing
suite passes unchanged, and a live login against DVNA, DVWA and Juice Shop behaves
exactly as it does today.** No new auth types, no discovery. Nothing user-visible
changes.

**A2 — Remove the tuning flags.** Add `LoginDiscovery` and `AuthNegotiator`, plus
deterministic field-name resolution and the bounded LLM fallback. **Definition of
done: the acceptance test passes on DVNA, DVWA and Juice Shop — authentication with
only `--login-user` and `--login-pass`.** This is the phase that delivers the actual
ask; A3 only widens what it can reach.

**A3 — New strategies, each against a live target.** Stand up the missing lab
targets, then add `CsrfHeaderAuth`, `MultiStepAuth`, `OAuth2PkceAuth` and
`BrowserAuth`. **Definition of done: every strategy has fired against a running
target.** A strategy whose target is not up does not ship — shipping it would
recreate the 2026-08-07 failure exactly.

## Out of scope

YAGNI, explicitly: SAML, NTLM, Kerberos, client certificates; solving MFA or CAPTCHA
(an MFA-gated account escalates to the operator).

## Where this sits

"Generalize to any target" decomposes into five independent subsystems. This spec is
**A** only; each of the others gets its own spec → plan → build cycle.

- **A. Authentication generality** — this document
- **B. Semantic surface inference** — replace `_ID_FIELDS`, `_OWNER_FIELDS`,
  `_CREDENTIAL_FIELDS`, `_PII_FIELDS`, `_PRINCIPAL_FIELDS`, `_PRIVILEGE_HINTS`,
  `_PARAM_CANDIDATES` with deterministic→LLM role inference
- **C. Transport reality** — WAF and bot walls (Akamai refused plain curl on Louis
  Vuitton), adaptive rate limiting, browser-backed requests
- **D. Protocol breadth** — WebSocket, gRPC
- **E. Cold-trial harness** — pre-registration, no-tuning enforcement, scoring across
  a target taxonomy; partly exists as `benchmarks/score_against_truth.py`

## A note on the competitive claim

"Beat every other pentesting tool" is not a target this design can be built against:
nuclei wins on known-CVE breadth, Burp wins on human-guided depth, and neither is
the axis Brukal competes on. What Brukal can defensibly own is **governed autonomy
on an unfamiliar target at roughly 40× less cost** — already measured against
Shannon on DVNA. The cold-trial metric above is the falsifiable version of the
ambition, and this subsystem is the largest current obstacle to it.
