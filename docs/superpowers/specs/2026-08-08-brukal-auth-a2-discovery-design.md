# Authentication generality — Phase A2: discovery, negotiation, provenance

**Date:** 2026-08-08
**Status:** approved, not yet implemented
**Parent:** `2026-08-07-brukal-auth-generality-design.md` (subsystem A of five)
**Predecessor:** A1 shipped 2026-08-08 — `brukal/auth.py`, 774 → 822 tests, merged at `1e8f138`

---

## Problem

A1 made authentication *extensible*. It did not make it *automatic*. Brukal must still
be told how to log in:

```
--login-url --login-type --login-field-user --login-field-pass
```

That is per-target tuning, performed by hand, on every target — the thing this
programme exists to remove. **A2 is the phase that delivers the actual ask.**

A2 also fixes a defect found while specifying it, which is more serious than the A1
backlog recorded. `has_session()` cannot distinguish two genuinely different states:

- **we authenticated** as a known principal — `identity` is set, we know whose objects
  are "ours";
- **we found a credential** lying on the target — `identity` is empty, and *nothing
  ever validated the token*.

Both return `True`, because `has_session()` returns `True` on `last_jwt`, and
`scan_web_body` (`assist.py:1878`) assigns `last_jwt` from **any JWT in any crawled
body** — a bundle, a docs page, an error response. Reproduced on a clean checkout:

```
fresh session                     -> has_session(): False   authenticated: False
after crawling a page with a JWT  -> has_session(): True    authenticated: False
```

The harm is not a phantom session; it is subtler and worse. A demo, example, or expired
token — which is what usually sits in a bundle — makes every session-dependent detector
run with a dead credential and report its class **clean**. That is the coverage lie in
its usual shape: the check ran, spent budget, and was structurally unable to find
anything.

**This is not simply a bug to guard.** Using a token found on the target is a
*deliberate capability*: `bfla_targets` gates on `last_jwt` (`assist.py:3924`) and
`session_token()` feeds it to the BOLA and BFLA provers (`assist.py:5311`, `5453`).
An early attempt to "fix" `has_session()` by requiring `authenticated` was reverted
during specification precisely because it disabled that capability. The answer is not
to distrust discovered credentials — it is to **validate them and record where they
came from**.

## Success criterion

On each of DVNA, DVWA and Juice Shop, `brukal` given **only** `--login-user` and
`--login-pass` discovers the login endpoint, selects a strategy, resolves the field
names, and holds a confirmed session — with **no code change between prediction and
run**.

Plus the negative: a demo JWT planted in a crawled page must **not** produce a session,
and must not mark any class clean.

## Scope

**In:** `LoginDiscovery`, `AuthNegotiator`, `FieldResolver`, credential provenance and
validation, loud-failure coverage, and the `_separate_identity` `last_jwt` fix (which
the provenance work touches anyway).

**Out:** token expiry and mid-run refresh; the new strategies (`CsrfHeaderAuth`,
`MultiStepAuth`, `OAuth2PkceAuth`, `BrowserAuth`) and their lab targets — those remain
A3. The bearer-scheme flag on `AuthAttempt` (A1 backlog item 3) is deferred with them,
since it only matters once a non-bearer strategy exists.

---

## Architecture

All of it lands in the existing `brukal/auth.py` (340 → ~600 lines). It remains one
responsibility — *how Brukal gets a session, and how it knows it has one* — and
splitting discovery from negotiation would put two halves of one conversation in
separate files. If the module passes ~700 lines, split `LoginDiscovery` out rather than
let it sprawl.

```
shallow recon crawl ──► LoginDiscovery ──► AuthNegotiator ──► AuthStrategy(n) ──► SessionOracle
   (depth 1, ~10pp)      (where is it?)     (which one?)        (attempt)          (did it work?)
                                │                                                       │
                                └── probe list, only if the surface yields nothing      ▼
                                                                                    Principal
                                                                            (identity · provenance)
```

The gate is untouched. Strategies receive the `GovernedBrowser` only — never a cage,
never the `kali` object. No LLM anywhere except `FieldResolver`'s bounded fallback,
which sits far outside the gate and only proposes field *names*.

### `LoginDiscovery`

Returns **ranked candidates**, not one URL, so the negotiator can fall through when the
best guess turns out not to be a login page.

Sources, in confidence order:

1. a crawled form containing `input[type=password]` — strongest evidence there is;
2. an OpenAPI operation whose path matches an auth shape (`state_changing_operations`
   already reads specs);
3. a route or page matching `login|signin|sign-in|authenticate`;
4. **only if 1–3 are empty**, a GET of a fixed list of conventional paths.

The probe list is deliberately short and fixed. It is exactly these seven, in this
order:

```
/login
/signin
/auth/login
/api/auth/login
/api/v1/auth/login
/rest/user/login
/users/sign_in
```

Read-only GETs, seven requests maximum, and the list is a module constant so adding to
it is a reviewable change rather than a judgement call at runtime. This is not content discovery: a few hundred
candidate paths would be indistinguishable from directory brute-forcing, which many
programmes forbid and which would burn the rate budget the detectors need.

The probe list exists because an SPA's login is often a client-side route that never
appears as a crawlable form. **Juice Shop is exactly that shape**, which is what makes
it the acceptance gate that matters most.

`LoginDiscovery` subsumes today's `_login_endpoint()` (`assist.py:4748`), which keeps
its signature and delegates — its four callers are cross-account proofs and must not
change.

### `AuthNegotiator`

One GET of a candidate builds a `LoginProbe`. Every strategy scores it via `detect()`.
Strategies are tried highest-confidence first, stopping at the first
`SessionOracle`-confirmed session. Every rejected attempt is recorded with its reason.

This finally gives `LoginProbe` a **producer** — closing A1 backlog item 4, and
validating its `inputs` shape against a real crawl instead of hand-built test data.

**The lockout budget is a safety requirement, not a tuning knob.** Each strategy gets
**exactly one credential pair**. The negotiator caps total authentication attempts per
run at **6** — enough for the strategy list plus a second candidate URL, far below any
lockout threshold — and halts immediately on a lockout or throttling signal rather than
spending the remaining budget. On a real programme, locking your own account is the
least bad outcome; locking another user's is a report filed against you.

A candidate whose `LoginProbe` shows no password field and no auth-shaped JSON error is
discarded **without an authentication attempt**. It costs a GET, not a credential.

### `FieldResolver`

Deterministic and free first:

- `input[type="password"]` names the password field;
- `input[type="email"]`, `autocomplete="username"`, or the sole remaining text input
  names the user field.

Only when genuinely ambiguous — no `type="password"`, or two or more candidate user
fields with no distinguishing attribute — does Brukal make **at most one** LLM call per
run to read the form, degrading to the positional heuristic if the model is unavailable
or returns nothing usable. The common case makes **zero** additional model calls and
stays at today's cost (~$0.07–0.55 per run).

### `Principal.provenance` and `CredentialValidator`

`provenance` is `none | discovered | authenticated`:

- **`authenticated`** — a login succeeded through the negotiator; `identity` is known.
- **`discovered`** — a credential was found on the target **and** the target was proven
  to accept it.
- **`none`** — no session. A credential we have merely seen leaves provenance here.

Validation reuses machinery rather than inventing a rule. `calibrate.py` already learns
what *this* application's answers mean, establishing `ok` / `missing` / `denied`
baselines from four read-only requests and comparing response **structure**, not prose.
So: send one request carrying the discovered credential, and classify the answer against
those learned baselines.

The endpoint is chosen deterministically, first match wins: a route the calibration pass
already classified as `denied` when requested anonymously (the strongest choice — we
know it discriminates); else a templated API route from the surface with its parameter
filled from an id we have already seen; else the seed URL. If none of those exists,
validation does not run and provenance stays `none`.

- classifies as `ok` → the target accepts it; provenance becomes `discovered`;
- classifies as `denied`, **or calibration never learned a baseline** → provenance stays
  `none`, and the credential is recorded as a lead, not a session.

Failing closed on an unlearned baseline follows invariant 2.

A validated leaked credential is **itself a confirmed finding** — "token disclosed in a
bundle grants authenticated access" is a real report, and today Brukal uses such a token
without ever proving it works.

### `has_session()` after A2

> provenance is not `none` **and** something rides the next request.

Detectors that need to know *whose* objects are ours require
`provenance == "authenticated"`. Reach-the-surface checks accept either. Neither half of
the conjunction is sufficient alone: provenance without a carried credential is a claim
with nothing behind it; a credential without provenance is one we may merely have seen.

### `_separate_identity`

Switches to `Principal.snapshot()` / `restore()`, which A1 built for exactly this and
left with no production caller.

This fixes A1 backlog item 2: `_separate_identity` restored five fields but **not**
`last_jwt`, so acting as a second principal permanently swapped our token while
`identity` claimed otherwise, and `session_token()` plus every JWT-forgery proof
downstream then reasoned about the wrong account.

**Carried caveat:** `Principal` has seven fields today; A2 adds `provenance`, making
eight. `snapshot()` covers all of them — including `login_url` / `login_type`, which
`_separate_identity` deliberately did *not* restore. That widening is a deliberate,
tested change, not a side effect, and it needs a test of its own: acting as a second
principal must not leave the run pointed at the victim's login URL.

### CLI

`--login-url`, `--login-type`, `--login-field-user`, `--login-field-pass` all become
**optional overrides**. Supplying one skips the corresponding discovery step, so an
operator can pin any part of the process. Supplying `--login-url` skips the shallow
recon pass entirely — there is nothing to discover.

---

## Run order

```
1. shallow recon crawl   crawl(max_pages=10, max_depth=1) from the seed
2. LoginDiscovery        ranked candidates from that surface, else the probe list
3. AuthNegotiator        probe → score → try in order → SessionOracle confirms
4. full crawl            runs WITH the session
```

Step 1 is the existing crawler with new parameters, not a new mechanism. It is skipped
when `--login-url` is supplied.

The ordering exists because discovery and crawling are mutually dependent: discovery
needs a surface, and the full crawl wants a session. `_login_endpoint()`'s own docstring
records why a single authenticated crawl cannot serve both — *a logged-in user is
redirected away from `/login` exactly as from `/register`*, so an authenticated crawl
has no login route on precisely the runs that hold a session.

---

## Failure handling

Failure must be loud, and it must distinguish two cases an operator responds to
completely differently:

- **No login endpoint discovered** — the target may not have one, or discovery is
  inadequate. Report it as a discovery failure and name what was searched.
- **Login found, credentials rejected** — the credentials are wrong, or the app needs an
  auth type A2 does not implement. Report which strategies were tried and why each was
  rejected.

Either way every session-dependent class is marked **blocked — no session**, never
"probed, clean":

> IDOR · BOLA · BFLA · session fixation · horizontal takeover ·
> no-session-revocation · default credentials

---

## Testing

**Named risk, measured during specification, not inferred.** Changing `has_session()`
breaks **exactly seven** existing tests, and they are not incidental — they use
`last_jwt` as a stand-in for "we have a session", which is the substitution being
removed:

```
tests/test_bfla.py::test_victim_is_read_from_the_app_not_guessed
tests/test_bfla.py::test_confirm_surface_invokes_the_bfla_check
tests/test_bola.py::test_reflex_runs_object_authz_on_a_mined_route
tests/test_loop_e2e.py::test_the_chain_finds_a_leaked_token_and_uses_it
tests/test_specmining.py::test_bfla_discovery_prefers_the_spec_over_the_name_heuristic
tests/test_specmining.py::test_credential_operations_outrank_other_writes_in_the_spec
tests/test_specmining.py::test_a_non_credential_write_is_still_used_when_that_is_all_there_is
```

The plan must name all seven up front and require each to be **judged individually** —
updated to set provenance where the test's intent survives, rewritten where its intent
was the bug. `test_the_chain_finds_a_leaked_token_and_uses_it` deserves the most care:
it documents a capability being **kept**, with validation added. A blanket edit to green
here would discard the very lesson this phase exists to encode.

**Unit** — each component with faithful doubles carrying every attribute the real object
exposes. A double that is "close enough" manufactures confidence; in A1 one missing
attribute hid a live defect behind a swallowing `except` for an entire session.

**Live validation** on all three lab targets, which exercise genuinely different
discovery paths:

| Target | Exercises |
|---|---|
| DVNA | crawled form, cookie session, `username` field |
| DVWA | crawled form **plus a CSRF token** that must be carried |
| Juice Shop | SPA — no crawlable login form, so the **probe list** must find `/rest/user/login` |

**Acceptance** — on each target, only `--login-user` and `--login-pass`, no code change
between prediction and run. Plus the negative case: a demo JWT planted in a crawled page
produces no session and marks no class clean.

**Verification discipline carried from A1**, both earned the hard way:

- Every new test verified to **fail when its fix is reverted**.
- For anything claimed behaviour-preserving, **differential execution against the
  pre-change code** — reconstruct the old implementation and drive both through a
  scenario matrix. In A1 a green suite *and* a passing live parity check together
  certified a refactor that had changed behaviour four times; only differential
  execution found the last two.

---

## Out of scope

Token expiry and mid-run refresh; `CsrfHeaderAuth`, `MultiStepAuth`, `OAuth2PkceAuth`,
`BrowserAuth` and their lab targets (Keycloak, crAPI, a CSRF-header app); the
bearer-scheme flag on `AuthAttempt`. All remain A3.
