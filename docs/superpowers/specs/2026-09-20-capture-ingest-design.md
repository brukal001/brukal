# Capture ingest — hunting from real traffic instead of guessed paths

**Status:** approved 2026-09-20. Approach A (a `capture.py` seam) chosen over extending
`webmap.py` in place.

## Why

Cold target 1 (DVWA, 2026-09-20) measured the problem. Of 30 URLs the harness fetched,
**two were real DVWA paths and nineteen were API-shaped guesses inherited from crAPI and
Juice Shop** — `/api/v1/coupon/apply`, `/coupons`, `/swagger.json`, `/graphql/console`.
`/setup.php` returns 200 and was never requested. There is no content discovery: `ffuf`,
`gobuster` and `feroxbuster` are named in the codebase and have never run.

Recon is the lever. The one recon improvement of that session — reading the surface out
of the target's own JS bundle — is the one thing that moved recall in seven runs. Captured
traffic is the same idea without the dependency on the target shipping a bundle: **a
request that actually happened is evidence no wordlist can produce.**

## Shape

```
        ┌─ parse_har(text, scope) ─┐
HAR ───►│  SCOPE FILTER            │──► list[CapturedRequest] ──┬──► surface enrichment
        │  CREDENTIAL STRIP        │    + IngestReport          └──► replay as principals
mitm ──►└─ parse_mitm_flow(...) ───┘        (later)
```

Both producers pass through the same constructor path, so the two guarantees are checked
in ONE place rather than repeated per caller.

### `CapturedRequest` (frozen)

`method · url · headers (creds removed) · body (redacted) · status · resp_bytes ·
content_type · auth_kind ("bearer"|"cookie"|"apikey"|"none") · source ("har"|"mitm")`

`auth_kind` keeps the auth SHAPE without keeping any secret: the grounding learns that a
route expects a bearer token, never what the token was.

### Guarantee 1 — scope at ingest

Filtered with `scope.contains_host()`, the same predicate the gate uses, never a
reimplementation. An out-of-scope host cannot enter the surface, therefore cannot become
an experiment. `IngestReport` carries `ingested / dropped_out_of_scope / dropped_malformed`.

### Guarantee 2 — credentials stripped

`Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token` removed; bodies through `redact`.
`--use-captured-session` is the only path that retains a value, and it hands it to the
PRINCIPAL machinery rather than leaving it in headers — a model-set `Authorization` header
suppresses the real credential, which this codebase has already paid for once.

## Consumer 1 — surface enrichment

| from the capture | into the surface |
|---|---|
| path + method | route candidate, `route_methods[path] = METHOD` |
| query + body keys | `surface.params` |
| write methods | `surface.write_operations` |
| `auth_kind` | `surface.protected_routes` |
| status + bytes | differential baseline |

**Captured routes are CANDIDATES, not `confirmed_routes`, until one gated request confirms
them.** The law is "never act on a derived fact that has not been confirmed against the
target once", and a capture is an observation from the operator's session at an earlier
time. Confirmation costs one request and reuses `resolve_mounted_endpoints`; the capture's
contribution is that the method and params are known, so that request lands.

## Consumer 2 — replay as other principals

Each capture becomes a `Hypothesis` whose control is already known-good:

- control = captured request `as: self`
- variant = same request `as: second` or `anonymous`
- comparator = `cross_account_resource` (path carries an id) · `unauthenticated_exposure`
  (anonymous variant) · `a_denied_b_allowed` otherwise

This targets the failure that survived every fix of 2026-09-19/20: **`state_changed`
proposed 0 of 14 times in a run where the model demonstrably can build one.** A captured
`POST .../return_order` IS a state-changing experiment — same read either side, the
captured write in the middle — assembled from evidence rather than imagination. The
harness stops needing the model to invent the experiment; it needs it only to prioritise.

Write-method captures pass through `_is_destructive_request` and the approver unchanged.

## Bounds and failure modes

Cap entries parsed (2,000 default) and derived hypotheses per run. Skip static assets by
content-type. A malformed HAR yields an empty list plus a counted report — never a crash,
and never a partial surface silently treated as complete: "ingested 12 of 900" must not
read as "the app has 12 endpoints".

## Testing

The parser is pure, so real HAR fixtures test it offline at $0.00. The two guarantees get
their own tests (out-of-scope host never survives; no credential survives). End-to-end:
ingest a HAR captured from DVWA and assert the surface gains the `/vulnerabilities/*`
routes the cold run never found.

## Out of scope for this change

Live mitmproxy transport (a later, separately classified change that adds a producer only)
and content discovery (ffuf/gobuster), which is a sibling fix for the same GAP #26.
