# SP-C — real-internet containment (scope-aware egress proxy) — design spec, SLICE 1

**Date:** 2026-09-29 · **Approach:** C-c (approved). **Part C of the A→B→C pipeline.**

## Problem
The cage's kernel egress lock is IP-based; a real program is a domain/wildcard behind rotating
CDN IPs, so a static IP lock can't be both tight and reachable. Enforce on the **host** per request
(survives rotation); keep the kernel lock as a coarse backstop.

## Slice split
- **Slice 1 (THIS spec):** the deterministic, fully-offline-testable safety core + a runnable proxy
  process. No live internet, no cage rewiring, no real-target run.
- **Slice 2 (later, separately authorized):** wire the live cage's nftables + egress through the proxy;
  an authorized real-program dry run. NOT built here.

## Invariants (unchanged): deterministic gate, fail-closed, immutable scope, no LLM in enforcement.

## Slice-1 deliverables

### 1. `brukal/egress.py` (new, pure/deterministic)
- `is_blocked_ip(ip: str) -> bool`: True for any non-public IP — RFC1918 (10/8, 172.16/12, 192.168/16),
  loopback (127/8, ::1), link-local (169.254/16, fe80::/10), the cloud-metadata IP (169.254.169.254),
  ULA (fc00::/7), unspecified (0.0.0.0, ::), multicast/reserved. Uses `ipaddress`; anything unparseable
  → True (blocked, fail-closed).
- `parse_http_target(request_line: str, headers: dict) -> tuple[str, str]`: from a proxied HTTP request,
  return `(host, path)` — supports an absolute-form request-URI (`GET http://h/p`) and origin-form
  (`GET /p` + `Host:` header). Lowercase host, strip port. Fail-closed to `("","")` on anything odd.
- `parse_connect_target(connect_line: str) -> tuple[str, str]`: from `CONNECT host:port HTTP/1.1`,
  return `(host, port)`. (HTTPS path is encrypted → path-exclusions are NOT enforceable on CONNECT;
  host + host-exclusions ARE. Documented limitation; slice-2 may add TLS-intercept.)
- `@dataclass EgressDecision(allow: bool, reason: str, host: str, path: str)`.
- `egress_decision(scope, host: str, path: str, resolved_ips: list[str]) -> EgressDecision`:
  ALLOW iff **all** hold, else DENY (fail-closed, first failing reason):
  (a) `host` non-empty; (b) `scope.in_scope(host, path)` (SP-A, reused); (c) `resolved_ips` non-empty;
  (d) **no** ip in `resolved_ips` is `is_blocked_ip` (any private/metadata resolution → DENY — defeats
  DNS-rebinding-to-internal). Deterministic; no network (the caller resolves and passes IPs in).

### 2. `brukal/egress_proxy.py` (new, runnable; composes egress.py)
A minimal forward proxy (HTTP + HTTPS `CONNECT`) for the cage:
- Per connection: parse target (http or CONNECT); **resolve** the host (a `resolver` callable, injectable
  for tests — default `socket.getaddrinfo`); call `egress_decision(scope, host, path, ips)`; on ALLOW
  tunnel to a resolved **public** ip; on DENY return `403`/close and append an `egress_decision` audit
  record (same shape as the gate). Bind localhost:PORT; single-threaded is fine for slice 1.
- `run_proxy(scope, port, audit, resolver=None)` entry. Never connects to a blocked ip even on ALLOW
  (the decision already excludes them; belt-and-suspenders: connect only to a non-blocked resolved ip).
- The proxy holds the **frozen** scope; a DNS answer changes which ip a known in-scope host resolves to,
  never which host is in scope.

### 3. `scope.py` — tls-mandatory for domain scopes (fail-closed)
In `load_scope`, after parsing: if the scope authorizes any **domain/wildcard host** (an
`authorized_hosts` entry that is NOT an IP literal — i.e. `*.x`, `api.x.com`) AND `tls_verify` is not
true → **raise ValueError** ("a domain-scoped engagement must verify TLS (tls_verify:true) so a
poisoned-IP MITM is caught"). Lab IP-only scopes (crapi/dvwa: cidrs, no domain hosts, tls off) are
UNAFFECTED. Add `Scope.has_domain_asset() -> bool` helper.

### 4. `engagement.run` — hard authorization gate (closes the SP-B gap)
At the very top of `engagement.run` (before any action / cage use), if `not scope.is_authorized()`
→ refuse: print/raise a clear "scope not authorized (authorized:false / no authorization statement) —
refusing to run" and return a non-zero/False, BEFORE anything runs. (Today only `is_expired` guards;
`is_authorized` is not a hard runtime gate — a drafted SP-B scope is refused only incidentally.) Keep
the existing `is_expired` refusal. Tests must confirm an `authorized:false` scope is refused here.

## Tests (offline, `tests/test_egress.py` + additions)
- `is_blocked_ip`: 10.0.0.1/127.0.0.1/169.254.169.254/::1/fe80::1/fc00::1/0.0.0.0 → True; 1.1.1.1 /
  93.184.216.34 / 2606:4700::1 → False; junk → True.
- parsing: origin-form + Host, absolute-form, CONNECT host:port, malformed → ("","").
- `egress_decision`: in-scope host + public ip → ALLOW; out-of-scope host → DENY; excluded path (`/blog`)
  → DENY; in-scope host but a resolved private ip present → DENY (rebinding); empty resolution → DENY.
- proxy (loopback integration): start `run_proxy` with an **injected resolver** that maps a test host to
  `127.0.0.1` AND an injected `is_blocked_ip` override (or a decision that permits loopback for the test
  ONLY) so a real local server can stand in — assert an in-scope host tunnels and returns the server's
  body, an out-of-scope host gets 403, and the audit has both records. (Keep the guard real in unit
  tests; relax ONLY in the proxy-plumbing test, clearly.)
- tls rule: a domain scope (`authorized_hosts:["*.x.com"]`, `tls_verify:false`) → `load_scope` raises; an
  IP-only scope with `tls_verify:false` loads fine; a domain scope with `tls_verify:true` loads fine.
- authorization gate: `engagement.run` on an `authorized:false` scope refuses before acting (assert no
  cage/tool use), and an authorized scope proceeds past the check.
- Full existing suite stays green. Do NOT modify `gate.py`/`executor.py`/`kali.py`/`audit.py` internals;
  `engagement.run` gets only the top-of-function authorization refusal.

## Out of scope for slice 1 (→ slice 2, separately authorized)
- Editing `docker/entrypoint.sh` nftables / wiring the live cage egress through the proxy.
- Any real-internet or real-target run (still needs explicit per-session authorization, CLAUDE.md).
- TLS interception for HTTPS path-exclusions.
