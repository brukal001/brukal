# Design — Guided environment-adaptive bring-up (`brukal hunt` wizard + `envprep`)

**Date:** 2026-10-02
**Status:** design approved in brainstorming (S1 + S2); awaiting written-spec review → `writing-plans`.
**Branch target:** a fresh feature branch off `main` (not the unmerged `feat/chrome-cdp-capture`).
**Mode:** build + self-test only. Live bring-up is HUMAN-GATED (same rule as every live run).

---

## 1. Intent (the design brief)

Make `brukal` adapt to its environment so the operator does **not** run separate shell commands to
hunt. One guided command gathers only what a human must supply, prepares everything else, shows it,
takes **one** approval, then brings up the cage and launches the run.

- **Web engagement:** ask for the target **URL** + a one-line **context** brief (+ the API key, if not
  already available). Everything else — scope, cage DNS, cage recreate — is prepared automatically.
- **VPN engagement:** ask which **`.ovpn`** to use and the **target IP/CIDR(s)**; brukal pins the VPN
  server, stages the tunnel, and prepares the scope automatically.

Success = from a single `brukal hunt`, a correctly-scoped, contained run starts, with exactly one
human approval and zero manual `docker`/`scope`/DNS steps.

### Decisions settled in brainstorming (do not re-open in the plan)

1. **Auto-draft + one approval gate.** brukal computes the proposed scope and the exact bring-up
   actions, shows them, and nothing touches the cage or starts until the operator approves once.
   This preserves invariant #5 (scope is drafted → approved → frozen; never widened at runtime).
2. **VPN = pin server, ask targets.** The `.ovpn` is parsed only to pin the VPN server in the egress
   lock. Pushed routes are reachable-but-not-authorized; the operator supplies the in-scope target(s).
3. **Entry point = the existing `brukal hunt`**, rewritten as a mode-aware wizard. `auto`/`solve`/
   `scope`/`run` are unchanged (scripting/power path), so the 2072-test flows are undisturbed.
4. **Structure = `envprep` module + thin wizard**, plan/execute split, cage access behind an injected
   runner so the orchestration is testable without Docker.

---

## 2. Current state this builds on (grounded in the repo)

- `brukal hunt` already exists (`cli.py:_cmd_hunt` @127; parser @617) but only: anthropic-only key
  check, prompt for an **IP/CIDR** target, `_write_scope` (@74), a text authorization confirm, then
  `run_engagement`. It has **no** web/URL mode, no VPN handling, no provider-awareness, and — a latent
  bug — it writes `scope.json` **without recreating the cage**, so the cage keeps enforcing the stale
  scope (the compose header documents that scope changes require `--force-recreate`). The rewrite
  fixes this by making the cage recreate part of the approved bring-up.
- `scope draft` / `scope approve` exist (`cli.py:_cmd_scope_draft` @486, `_cmd_scope_approve` @532,
  SP-B): a draft carries `authorized:false`; approval freezes it to `authorized:true` with
  `approved_by`/`approved_at`. The wizard reuses the **draft→approve file contract and the freeze
  step**, but builds the draft dict **directly from structured inputs** (parsed host / CIDRs / VPN
  server) instead of SP-B's free-text parser, which under-scores lab hosts (confidence 0.55, noisy
  `_review_items` — observed 2026-09-30/10-01).
- Host-side cage lifecycle **does not exist in Python today** — only `docker exec`/`docker cp`
  (`kali.py`, `oob.py`, `cli.py:295`). The compose + entrypoint already implement: scope mount
  `../scope.*.json:/scope.json:ro`, `BRUKAL_DNS` → `RESOLVER` → nftables DNS-egress rule, uid-segmented
  egress lock, VPN bring-up from `docker/vpn/config.ovpn`, CDP published on `127.0.0.1:9222`.
- **WSL/Docker-Desktop DNS reality (verified 2026-10-01):** the embedded `127.0.0.11` resolver is dead;
  `BRUKAL_DNS` passed inline/exported does **not** propagate through compose on this host — the reliable
  fix is the compose **default** `BRUKAL_DNS=${BRUKAL_DNS:-1.1.1.1}` **plus** rewriting the in-cage
  `/etc/resolv.conf` to `nameserver 1.1.1.1` after recreate. `envprep` encodes both as plan steps.
- **Known adjacent bug (out of scope here, note for a separate fix):** `assist_cli._authorise_host`
  does `ipaddress.ip_network(target + "/32")` on a full URL when the host is not pre-authorized →
  `ValueError`. The wizard sidesteps it by always putting the host in scope before the run; it does not
  fix it.

---

## 3. Architecture & components

Four units, each with one purpose and a defined interface:

### 3.1 `brukal/envprep.py` — plan / execute / verify (pure where it can be)

```
@dataclass(frozen=True)
class BringUpPlan:
    mode: str                 # "web" | "vpn"
    scope_path: str           # the draft/approved scope file
    scope_summary: str        # human-readable one-liner for the approval gate
    cage_action: str          # "recreate" | "none"
    resolver: str             # e.g. "1.1.1.1"
    vpn_file: str | None      # staged .ovpn source path, or None
    verify_steps: tuple[str]  # named checks to run post-bring-up
    dispatch: Dispatch        # which run to launch + its kwargs

def plan_web(url, context, provider, model, scope_path, ...) -> BringUpPlan   # PURE
def plan_vpn(ovpn, targets, provider, model, scope_path, ...) -> BringUpPlan  # PURE
def execute(plan, runner) -> BringUpResult   # side effects ONLY here, via runner, post-approval
def verify(plan, runner) -> list[Check]      # post-bring-up checks, fail-closed
```

`plan_*` compute what *would* happen and never touch Docker/disk beyond reading the chosen `.ovpn`.
`execute`/`verify` act only through `runner`. `BringUpResult` carries per-step outcome for the log.

### 3.2 `brukal/cage.py` — the injected runner (the only shell-out site)

A small protocol + a real implementation + a fake:
```
class CageRunner(Protocol):
    def compose_recreate(self, scope_path: str, resolver: str) -> StepResult
    def set_resolver(self, ip: str) -> StepResult          # in-cage /etc/resolv.conf rewrite
    def stage_vpn(self, ovpn_src: str) -> StepResult        # copy to docker/vpn/config.ovpn
    def exec(self, argv: list[str]) -> StepResult           # docker exec passthrough
    def cdp_probe(self) -> StepResult                       # 127.0.0.1:9222/json has a page
    def http_probe_via_proxy(self, url: str) -> StepResult  # reach target through egress proxy
    def tun_up(self) -> StepResult                          # tun0 present (VPN)
```
`DockerCageRunner` wraps `subprocess`/`docker compose`. `FakeCageRunner` records calls and returns
scripted results — this is what makes every `execute`/`verify`/wizard test run without Docker.

### 3.3 `brukal/keys.py` — provider-aware key resolution

```
def resolve_key(provider: str, *, prompt=input, save=True) -> KeyResolution
```
Order: `$<PROVIDER>_API_KEY` (e.g. `OPENROUTER_API_KEY`) → gitignored `runs/<provider>.env` → prompt
and offer to persist there (`runs/` is gitignored; `chmod 600` is a no-op on `/mnt/c`, so we do not
claim it protects the file). The raw key is never printed or logged. Returns the value + its source.

### 3.4 `_cmd_hunt` (rewrite) — the thin wizard

Orchestrates only; no shell-out of its own. Flow: select mode → gather inputs → `keys.resolve_key`
→ build structured scope **draft** → `envprep.plan_*` → **print scope + plan + dispatch command** →
one `[y/N]` → on yes: `scope approve` (freeze) → `envprep.execute` → `envprep.verify` → dispatch
(`run_auto(web=True,…)` or `run_engagement(…)`). On no/EOF/any failed required step: abort cleanly,
cage untouched.

### 3.5 Boundaries / invariant mapping

- `envprep` and `cage` are **host orchestration invoked by the CLI before any agent exists**. They
  never import or receive the `kali` object or the `Executor`; the run still flows solely through
  `Executor.run()` (**#4** intact).
- The plan is **shown and frozen before execution** — propose → dispose, and scope goes
  draft→approve→freeze, never widened at runtime (**#5** intact).
- No LLM participates in planning, scoping, or the gate (**#1** intact); the wizard is deterministic.
- Any ambiguous/failed required bring-up step **aborts** rather than proceeding (**#2 fail-closed**).
- The audit/approval trail: the scope approval is logged as today; `BringUpResult` is recorded to the
  engagement log so the operator can see exactly what was recreated (**#3/#5** supporting evidence).

---

## 4. The two mode flows

Shared spine: **gather → draft scope → plan → show → one approval → execute+verify → dispatch.**

### 4.1 Web mode (direct internet target)
1. Prompt: target **URL**, then a one-line **context** brief (optional, strongly nudged).
2. `keys.resolve_key(provider)` — fail fast if none and no local model.
3. Structured draft (`authorized:false`): host parsed from the URL → `authorized_hosts=[host]`,
   `tls_verify:true`, `rate_limit_per_min` (default, operator-overridable), `forbidden_classes:[dos]`.
4. `plan_web`: `cage_action=recreate`, `resolver=1.1.1.1` (+ `set_resolver` step), `vpn_file=None`;
   `verify_steps = (cdp_live, cage_scope_matches_host, host_resolves_in_cage, proxy_reaches_host)`;
   dispatch = `run_auto(url, web=True, context=…, provider, model, vault, audit)`.

### 4.2 VPN mode (tunneled box)
1. Prompt: pick `.ovpn` (list `docker/vpn/*.ovpn` + accept a path), then target **IP/CIDR(s)**.
2. `keys.resolve_key(provider)`.
3. Parse the `.ovpn` `remote <host> <port>` line → the VPN **server** to pin. Pushed routes are NOT
   authorized.
4. Structured draft (`authorized:false`): `authorized_cidrs=[targets]`, VPN server recorded for
   pinning, rate limit, `forbidden_classes:[dos]`.
5. `plan_vpn`: `cage_action=recreate` with the chosen `.ovpn` staged to `docker/vpn/config.ovpn`,
   `resolver=1.1.1.1`; `verify_steps = (tun_up, vpn_server_reachable, target_reachable_via_tun,
   cage_scope_matches_targets)`; dispatch = `run_engagement(target, box multi-agent)`.

### 4.3 The one approval gate (shared)
Before any side effect, print: the **resolved scope** (hosts/CIDRs, `tls_verify`, rate, VPN server if
any), the **bring-up plan** as an ordered step list, and the **exact dispatch command**. One `[y/N]`.
Yes → freeze (`scope approve`) → `execute` → `verify` → dispatch. No/EOF → abort, nothing recreated.

### 4.4 Explicitly out of scope (YAGNI)
- Web-app-behind-VPN (the orthogonal network×run combination). Pieces compose cleanly later.
- Auto-classifying "lab vs real" targets (the gate must not make that judgement).
- Fixing the `_authorise_host` URL crash (separate tested fix; wizard only sidesteps it).

---

## 5. Error handling (fail-closed)

- **Missing/declined key, no local model** → stop before any scope/cage change, with the exact env var
  / local-model hint. No partial setup.
- **Unparseable URL / invalid CIDR / unreadable `.ovpn` / no `remote` line** → abort at draft time with
  a specific message; cage untouched.
- **`compose_recreate` fails** (Docker Desktop flaky — observed exit 255) → abort with the recovery
  hint (`wsl.exe --shutdown`, relaunch); do **not** dispatch against an unprepared cage.
- **Any `verify` step fails** → do not dispatch; print which check failed and the observed value. A
  failed verify is a stop, never a warning the run proceeds past.
- **Operator answers no / EOF at the gate** → clean abort, scope left as draft (`authorized:false`),
  cage untouched.
- Execution is idempotent-safe to re-run: a second `brukal hunt` recreates from the approved scope.

---

## 6. Testing (build + self-test; live is human-gated)

- **`plan_web` / `plan_vpn` (pure):** given inputs, assert the exact `BringUpPlan` (scope draft
  contents, resolver, vpn staging, verify_steps, dispatch) — no Docker, no network.
- **`.ovpn` parsing:** `remote host port` extraction incl. multiple/commented lines; missing-remote
  aborts.
- **`envprep.execute` / `verify` with `FakeCageRunner`:** assert the ordered runner calls, that a
  failed required step aborts before dispatch, and that nothing is dispatched on verify failure.
- **`keys.resolve_key`:** env hit, `runs/<provider>.env` hit, prompt+save path (prompt injected);
  assert the key is never returned in any printed/logged string.
- **Wizard (`_cmd_hunt`) with injected `input`, `FakeCageRunner`, and a stub dispatch:** web path and
  VPN path end-to-end; the approval `n` aborts with zero runner side effects; `y` freezes scope then
  executes then dispatches, in that order.
- **Scope freeze:** the structured draft is `authorized:false`; after the gated approve it is
  `authorized:true` with `approved_by`/`approved_at`; the run never starts on an `authorized:false`
  scope.
- **Regression:** `auto`/`solve`/`scope`/`run` unchanged; full suite stays green; pyflakes clean on new
  files.
- **Live validation (HUMAN-GATED, not in the loop):** one real `brukal hunt` web run and one VPN run,
  per CLAUDE.md per-session authorization — proving the real `DockerCageRunner` path end-to-end.

---

## 7. Milestone shape

One tested milestone, built under the five invariants and the build discipline (every existing test
green, tests for all new code, one commit). Suggested internal order for the plan: `cage.py`
(runner + fake) → `keys.py` → `envprep.py` (plan/execute/verify) → `_cmd_hunt` rewrite + wiring →
regression + docs. Live validation is a separate, human-gated step after the branch review.
