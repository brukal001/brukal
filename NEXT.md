# NEXT — Brukal improvement queue (read by brukal-improve-loop.sh)

> **STATE 2026-09-30:** SP-A / evidence-CVSS / SP-B / SP-C slice-1 + **slice-2** all in `docker-kali:latest`
> (cage runs the slice-2 proxy). **★ FIRST AUTHORIZED LIVE EXTERNAL RUN DONE** — PortSwigger Web Security
> Academy, Apprentice SQLi "retrieval of hidden data" (a rotating-CDN DOMAIN target).
> **Goal #1 CONTAINMENT PROVEN end-to-end**: `brukal verify` chain intact; **0 out-of-scope egress** (every
> allowed request the exact lab host); per-request domain enforcement through the in-cage proxy (no IP pin,
> survived CDN rotation); proxy-bypass kernel-dropped; metadata / portswigger.net / raw scanners (nmap,
> `curl -k`, whatweb) all DENIED. **Goal #2 FINDING: lab SOLVED autonomously** — the *briefed* deepseek run
> rendered `GET /filter?category=Gifts' OR 1=1--` and the lab shows `<p>Solved</p>` (`is-solved` banner);
> host-side audit shows the `%20`-encoded injection = the autonomous browser, not the operator.
> **Two fixes SHIPPED this session (tested, suite 2028 green, NOT committed):** (1) `auto`/`solve` accept a
> single-exact-host DOMAIN scope (`_target_authorised` host-aware target auth — no `/32` prompt, no `--host`
> `*.parent` wildcard); (2) `auto --context/--focus` planner brief (recovered intent only, gate untouched)
> — the brief was DECISIVE: unbriefed deepseek wandered on nmap/whatweb and missed, briefed it went straight
> to the category filter and solved it. ⚠️ Docker Desktop is UNSTABLE (cage exited 255 twice mid-session);
> the domain run needed resolv.conf→1.1.1.1 in-cage (embedded 127.0.0.11 resolver was dead) + compose
> `BRUKAL_DNS` default 1.1.1.1 — **both reverted at close; crAPI scope restored, cage left as found.**
>
> **STATE 2026-10-01:** the Chrome-CDP + full-capture milestone (branch `feat/chrome-cdp-capture`, this
> file's §Follow-ups item "Chrome-CDP + capture milestone") is BUILT, self-tested and VERIFIED
> (Task 11 of its own SDD plan): full suite 2072 green; four-metric benchmark is **bit-identical**
> branch-vs-baseline (`run_experiments.py` never builds a `GovernedBrowser` — `_confirm_from_capture`
> is structurally inert on that harness); pyflakes clean on every new/changed file (2 pre-existing
> warnings elsewhere, dated before this milestone, not its concern). 14 commits, **committed to the
> branch, NOT merged to main, NOT pushed, cage NOT rebuilt.** See `DONE` below for the full summary and
> `HUMAN-GATED` for what live validation remains.
>
> **STATE 2026-10-01 (live validation DONE, HITL, operator-approved):** first live CDP run of the
> milestone against a fresh PortSwigger Practitioner lab (UNION "retrieving data from other tables").
> **Containment PROVEN** (nmap+curl DENY on domain scope; every ALLOW in-scope; proxy-enforced per-request;
> 2 hash-chained ledgers). **Exploit CONFIRMED + lab SOLVED** (UNION dumped the users table; the solve
> needed an admin `POST /login` → 302 /my-account, driven manually). **Capture pipeline fires but
> registered 0 findings** — 5 gaps found (see TOP + full write-up in vault `Brukal.md` 2026-10-01). No
> code changed; bring-up (compose `BRUKAL_DNS` default + scope-mount swap) reverted, cage left on crAPI.
>
> **STATE 2026-10-02 (base CONVERGED on local `main`; NOT pushed — main 36 ahead of origin):** two branches
> merged, then deleted. (1) `feat/hunt-wizard-envprep` — guided `brukal hunt` wizard (web: URL+context /
> VPN: .ovpn+targets) over new `cage.py`/`keys.py`/`envprep.py`/`hunt_wizard.py`: auto-draft scope → one
> `[y/N]` → freeze → cage bring-up → dispatch, no separate shell commands; five invariants intact (brainstorm
> → spec → plan → SDD 6 TDD tasks + opus whole-branch review). (2) `feat/chrome-cdp-capture` — the full
> milestone (domain-auth + `auto --context` = `b3af852`, CDP capture, capture_confirm provers,
> proxied-chromium docker) after an opus whole-branch review + a fix wave for 3 live-CDP robustness bugs
> (`CDPError` fail-closed in `ChromeCage.run`; split probe-2s / session-20s timeout; `_MAX_MESSAGE` bounded
> fragment reassembly). **Clean 3-way merge; merged full suite 2114 pass/1 skip.** The wizard's 3 live
> blockers are now ON main (domain-auth, `auto --context`, egress-proxy/CDP/VPN) ⇒ it is build-complete and
> live-ready MODULO a cage rebuild + a human-gated run. ◻ **Small enabled follow-up** (build+self-test): wire
> `hunt_wizard._default_dispatch`'s web path to forward the brief via `run_auto(context=[…])` (the param now
> exists post-merge), drop the now-stale "awaits the auto --context feature" comment, and monkeypatch the 4
> `test_hunt_wizard.py` tests that leak keys into the pytest-process env. The **TOP** below
> (capture_confirm solve/auth-success prover) is unchanged and still the highest-value next build.


> **STATE 2026-10-12 (branch `feat/security-audit-suite`, 32 commits over `main`; NOT merged, NOT
> pushed):** the security-audit plan is COMPLETE and every build+self-test item below is DONE. Found and
> fixed SEC-001/002/003/006/007/008/009/010/011 (see `SECURITY_AUDIT.md`), plus a principal-handle
> substring bug (the 7/40 flake), a `brukal hunt` dispatch crash (circular import at the wizard's last
> step), the wizard dropping `--context`, the preflight `http://https://`, the MANUAL `via:browser`
> line, rich-menu WEB options that did nothing, and `curl -A` escalating. New prover: credential-
> disclosure → successful login (the old TOP). New tool: `benchmarks/replay_gate_corpus.py <ref>` —
> replays 1,501 historically approved commands; required 0 NEW / 0 LOST / 0 UNSEEN / 0 looser for every
> gate/risk change (it caught a real 33-command capability regression in this branch's own first fix).
> Suite 2644 pass / 1 skip / 1 xfail (documented design limit); four metrics unchanged.
> One fresh session per change. Take the **TOP** item only, ship it as a tested milestone under
> the five invariants, commit, then rewrite this file with the new top item. BUILD + SELF-TEST
> ONLY — never a live pentest, never a real/external target, never a Docker/crAPI/DVWA run,
> never a push. Anything under "HUMAN-GATED" is NOT for the autonomous loop.

## ★ FOLLOW-UPS from the first live run (2026-09-30 — human/operator to prioritise)
- **Finding-CAPTURE gap (highest value):** the briefed run SOLVED the lab but recorded **0 findings** — the
  verify/finding detector did not recognise the PortSwigger `is-solved` banner (or the released-vs-unreleased
  product differential) as a confirmed finding. Brukal *performed* the solving exploit but did not *register*
  the win. A prover/verify signal for "the boolean-SQLi differential changed the result set" (and/or a
  lab-solved banner recogniser) would close the loop for this whole lab class.
- **Exploit-as-manual gap:** the strategist framed the injection as "next step is yours (intrusive)" even
  though the recon/INPUT-VALIDATION agent had already rendered the payload. `--full-send` did not change this
  (the model self-classified the exploit as a MANUAL note, not an executable web action). The exploit agent
  should translate an identified payload into a governed request, not prose.
- **Chrome-CDP + capture milestone (operator-directed) — DONE 2026-10-01, see DONE below.** Built,
  self-tested and suite/benchmark-verified on `feat/chrome-cdp-capture`. Still needs the HUMAN-GATED
  live validation (cage rebuild + fresh-lab live CDP run) before merge.
- **Per-target briefing is now a first-class expectation:** `auto` warns when no `--context` is given. Consider
  making the brief richer (feed it to prover selection / the web methodology, not only the strategist prompt).
- **Cosmetic:** preflight builds `http://` + the already-`https://` target → `http://https://…` (non-fatal,
  it continues). One-line fix in the preflight URL assembly.
- **Domain-scope command-gate:** raw shell tools (nmap/whatweb/`curl -k`) are DENIED against a domain scope
  (correct — only the governed web door reaches a domain host), but recon has *no* fingerprint tooling then.
  Consider a domain-scope-aware recon that uses the web cage instead of shell scanners.

> One fresh session per change. Take the **TOP** item only, ship it as a tested milestone under
> the five invariants, commit, then rewrite this file with the new top item. BUILD + SELF-TEST
> ONLY — never a live pentest, never a real/external target, never a Docker/crAPI/DVWA run,
> never a push. Anything under "HUMAN-GATED" is NOT for the autonomous loop.

## TOP (do this next)
- **Response visibility (Part 1 of "finish the chain") — SHIPPED 2026-10-12** on branch
  `feat/response-visibility` (see DONE). What remains of this TOP is **Part 2 — chain state**
  (values returned by a target reused in later steps + its approval rule): the maintainer's governance
  decisions are in the vault; it needs a design pass WITH the maintainer before any build.
- **Exploit-as-manual + multi-step chaining (capability milestone — needs a design pass with the
  maintainer first).** The two live runs show the ceiling is no longer the gate: the model identifies
  the payload but frames it as MANUAL ("next step is yours"), and nothing carries state from one step to
  the next (UNION dump → creds → login). Brukal now CONFIRMS the chain when it happens
  (`credential_disclosure_login`), but nothing DRIVES it. Proposed shape (to brainstorm, not build
  blind): a deterministic "lead → governed action" translator for identified payloads, plus a small
  chain state (harvested credentials / tokens as typed facts the planner is shown). Every step still
  through the gate; no LLM inside it.

## QUEUE (safe, tested, autonomous — promote to TOP when the current one lands)
- **Untrusted-data fence in strategist prompts:** raw target output is inlined under `RECENT
  ACTIVITY` next to `OPERATOR JUST SAID:` (`strategist.py:_context_parts`). Fence + label it — but
  ship only with the E2 A/B from `RESEARCH_FINDINGS.md` (human-gated live run), since it changes what
  the model proposes.
- **Stale evidence in `capture_confirm`:** add a run id / timestamp to `CapturedRequest` so evidence
  from another run is distinguishable (recorded NOT-TESTABLE in `SECURITY_AUDIT.md`).

## DONE (most recent first — for the next session's context, not an action item)
- **2026-10-12** Response visibility, Part 1 (branch `feat/response-visibility`, spec + plan under
  `docs/superpowers/`): `d6a8e3e` new pure `brukal/response_view.py` (`salient_view`: changed region vs
  an earlier 2xx response to the same endpoint, else head+tail; markers inside the budget; never
  raises) · `0d3d8ba` capture store keeps head 2,400 + tail within the same 4,000 (bodies ≤ 4,000
  byte-identical; redaction still on the full body; dynamic-tail trade-off pinned by a test) ·
  `b0a09a1` model note (600) + vault summary (800) use the view, baselines in a bounded in-memory map
  (≤ 64 endpoints × 3 bodies × 200k chars) · `7738380` one MANUAL rule in the strategist prompt · `e14b69e` final-review fixes (fixed capture
  marker so a middle-echoed payload no longer breaks the boolean differential; an over-budget diff
  shows start+end with a marker instead of a silent cut). Suite 2673 pass / 1 skip / 1 xfail; four metrics unchanged; gate files untouched; replay 0 NEW / 0 LOST /
  0 UNSEEN / 0 looser. Resolves the old QUEUE item "capture size vs prover accuracy". Build+self-test
  only; no live run, no merge, no push.
- **2026-10-11/12** Security-audit plan complete + follow-ups (branch `feat/security-audit-suite`):
  `2a59273` results harness · `8da7932`+`b21881c` SEC-001/002 (+ quote-aware lexer, regression caught by
  replay) · `5fe9f3a` SEC-007 · `4f4ccc0` SEC-006 · `db2f6e1` SEC-003 · `807d58d` principal-handle bug ·
  `8db55e4` Task 7 baseline · `528a5b8` SEC-008 · `f61b171` SEC-009/010 · `c09c44f` `-A` nmap-only ·
  `2964f10` SECURITY_AUDIT/THREAT_MODEL/RESEARCH_FINDINGS · `8e6a139` SEC-011 · `fc9c9e8` preflight
  scheme · `66a93ec` wizard crash + brief · `48d70c3` credential-disclosure-login prover · `ee73c9f`
  typed/picked WEB actions. All build+self-test; no live run, no merge, no push.
- **2026-10-01** **Chrome-CDP + full-capture milestone** (branch `feat/chrome-cdp-capture`, 14 commits,
  Tasks 1–11 of its own SDD plan — `.superpowers/sdd/2026-09-30-chrome-cdp-capture/`). Real stdlib
  CDP-over-WebSocket client (`brukal/cdp.py`: RFC6455 handshake + client-masked framing, call
  id-matching + event demux, `Network.*` capture accumulator with base64-body decode and in-flight
  exclusion, fail-closed on an oversized frame) replaces the old navigate/screenshot-only CDP use.
  `ChromeCage.drain_capture` + `FakeCDP` emit real `Network.*` pairs. Door-level full request/response
  capture now works for BOTH raw and CDP paths: `CapturedRequest.resp_headers` (credential-stripped +
  redacted, e.g. `Set-Cookie`) and `_record` support in `brukal/capture.py` (`write_har` fills
  response headers); `GovernedBrowser`'s door stores response body/headers and folds in-scope CDP
  `Network.*` pairs via `_record`, re-applying scope + redaction (an out-of-scope pair is dropped, not
  folded). `WebAction.via` (`auto|raw|browser`) routes `CompositeWebCage` between the curl-equivalent
  door and the real browser per-need; the gate ignores `via` (routing is not a security boundary — the
  web door's scope check is). LLM-free, capture-driven finding registration
  (`brukal/capture_confirm.py`): is-solved banner, boolean-SQLi differential, and reflected-XSS provers,
  each positive-control-enforced (two false-positive/negative rounds fixed pre-merge). Always-on wiring
  in `brukal/assist_confirm.py`/`assist_cli.py`: `_confirm_from_capture` runs after every hunt round,
  deduped per `Finding.signature()`, fixed to not re-emit the same capture every round; it only reads
  what the gated door already captured — it never proposes or issues a request. A live CDP render cage
  with `DockerChromeCage`-primary / subprocess fallback was built for the always-on path. `docker/`:
  proxied debuggable chromium launched as the unprivileged `brukalop` uid (nftables-enforced, not the
  `--proxy-server` flag) with `--proxy-bypass-list="<-loopback>"` — **a security requirement, not a
  convenience flag**, closing an SSRF→CDP hole (a hostile page could otherwise reach loopback `:9222`
  directly and drive devtools itself); CDP published `127.0.0.1:9222:9222` host-loopback-only; a shape
  test asserts the flag is present; bring-up documented in `docs/HANDOFF-chrome-cdp-bringup.md`.
  **Task 11 verification (this session):** full suite **2072 green**. Four-metric benchmark
  (`run_experiments.py`) is **bit-identical** branch-vs-baseline-`b3af852` (`interception_rate=1.0`,
  `unsafe_actions_prevented=5`, `context_reduction=0.976`, `adaptive_trust_final=0.343`) — confirmed
  both empirically (throwaway worktree A/B) and structurally (`experiment.py` imports only `FakeKali`,
  never builds a `GovernedBrowser`, so `_confirm_from_capture` cannot fire on it; the always-on
  registration prover is correctly inert on the fake-cage harness). A ±2-3 byte wobble in the
  intermediate `context_bytes_multi` diagnostic is pre-existing `time.time()`-serialization noise
  (reproduced on a single commit across repeated runs), not a milestone effect. pyflakes clean on
  every file this milestone touched (`cdp.py`, `capture_confirm.py`, `web.py`, `chrome.py`,
  `capture.py`, `assist_confirm.py`, `assist_cli.py`); 2 pre-existing warnings (one each in
  `capture.py`/`assist_confirm.py`, dated 2026-09-21 and 2026-09-25, both before this milestone) are
  not new and not touched. Spec correction: `docs/superpowers/specs/2026-09-30-chrome-cdp-capture-
  design.md` §4.5 corrected — the loopback proxy-bypass was wrongly documented as "harmless and left
  as-is"; now states the `--proxy-bypass-list="<-loopback>"` requirement and the SSRF→CDP rationale,
  matching what `docker/entrypoint.sh` actually implements. **Build+self-test only. NOT merged to
  main, NOT pushed, cage NOT rebuilt/recreated from the new image.** All five safety invariants intact
  (no LLM inside the gate — the new provers are deterministic string/regex/diff checks over already-
  captured text; `via` routing and CDP capture are pre-gate/post-gate plumbing, not gate logic).
- **2026-09-30** `auto --context/--focus` — per-target planner brief (the distraction fix). Free-text lines
  (`_context_objectives` normalise → `_apply_context` seeds the strategist objective channel) steer what the
  model PROPOSES; the deterministic gate is untouched so a brief can never widen scope. `auto` warns when no
  brief is given. `assist_cli.py` + `cli.py`; test `tests/test_auto_context_brief.py` (3). **Validated LIVE:**
  briefed deepseek went straight to the category-filter SQLi and solved the lab; unbriefed it had wandered.
  Suite 2028 green. NOT committed (operator to review/commit).
- **2026-09-30** `auto`/`solve` accept a single-exact-host DOMAIN scope. `_target_authorised` (host-aware,
  membership-only) replaces the IP-only `scope.contains_ip(target)` at the `_prepare_session` target gate, so
  a pure domain scope (authorized_hosts, no CIDRs — a PortSwigger lab behind a CDN) is used as-is: no `/32`
  "authorise this host?" prompt, and NO `--host` `_vhost_names` `*.parent` wildcard (which would authorise
  other users' instances). Deterministic gate unchanged. `assist_cli.py`; test
  `tests/test_auto_domain_target.py` (5). NOT committed.
- **2026-09-29** SP-C **slice-2** — kernel-mandatory in-cage egress proxy. `66601d0` (infra) + `e90d1c7`
  (proxy-connects-to-authorised-private-lab-IP fix + test). Dockerfile bakes the minimal stdlib proxy
  package + `egress_proxy_cli.py` + a `brukalproxy` user (build context → repo root, `.dockerignore`
  added); entrypoint starts the proxy as `brukalproxy` then builds **uid-segmented nftables** (only that
  uid egresses to public tcp {80,443}, private/metadata dropped even for it; every other uid gets lo+DNS
  only ⇒ a tool that ignores `HTTP(S)_PROXY` cannot reach a target); compose sets the proxy env. Domain
  hosts are proxy-enforced per-request (no longer IP-pinned). **V1–V5 all passed on a throwaway image**
  (brukal-kali untouched). Suite 2020 green. **Committed local, NOT pushed; operator rebuilds+recreates
  the cage and pushes.** HANDOFF `docs/HANDOFF-sp-c-slice2.md` is now spent.
- **2026-09-28** `scope._norm_host` port predicate pinned to ASCII digits (`.isascii() and
  .isdigit()`), so a non-ASCII-digit port like `[::1]:80²` rejects to `""` instead of normalizing to
  `::1`. No security consequence (port discarded, inner IP still gated) — RFC-shaping nicety from the
  2nd review's informational note. `5b9ebca`.
- **2026-09-28** `cvss.grade()` no-raise contract made real: it now catches the `ValueError`
  `score_from_vector` raises on an incomplete (facts-modified or table) vector and falls back to the
  class-based `knowledge.enrich` number with a "class-based fallback" basis, instead of propagating.
  Docstring updated. Unreachable with today's complete table — a guard. From `/code-review high`.
  `484b4a5`.
- **2026-09-28** `scope._norm_host` now rejects junk after a closing bracket: only an empty
  remainder or a numeric `:port` may follow `]`, so `[::1]evil.com` / `[::1]:` / `[::1]:80x` fail
  closed to `""` instead of truncating to `::1`. Valid `[::1]`/`[::1]:8443` unchanged. Defense in
  depth (not reachable via the web door). From `/code-review high`. `82263f8`.
- **2026-09-28** `scope.contains_host` now normalizes through `_norm_host` (one path with
  `in_scope`), so a direct `contains_host("[::1]:8443")` authorizes an in-scope IPv6 host instead of
  denying it; regressions preserved and trailing-dot FQDNs now align with `in_scope`. Fail-closed
  direction unchanged. From `/code-review high`. `2896761`.
- **2026-09-28** `findings.FindingStore._absorb` evidence-CVSS merge corrected from first-wins to
  STRONGEST-wins (fix of `c144ea3`, found by `/code-review high`): a stronger comparator arriving
  second now raises the grade and swaps the whole triple, so the score no longer contradicts an
  upgraded severity/evidence; weaker/absent later scores never lower or clear it, ties keep the
  first. +2 tests (stronger-second, tie). `e6e77c7`.
- **2026-09-28** `findings.FindingStore._absorb` now merges the evidence CVSS triple
  (`cvss`/`cvss_vector`/`cvss_basis`) all-or-nothing on dedup: a late comparator-graded confirmation
  fills a score an earlier un-comparatored sighting lacked (first-write-wins used to drop it), while
  an existing evidence CVSS is never overwritten or cleared. Severity/dedup untouched. 5 tests incl.
  reload. `c144ea3`.
- **2026-09-28** `bugclass.gated_by_class` docstring clarified: a `None` scope means UNRESTRICTED
  (prover runs), which is not a scope bypass — authorization + host/path scope are enforced at the
  web door (`web.check_web`/the gate) on every request, so this decorator is only a class-selection
  tuner, not a security boundary. Docstring only. `cf8d738`.
- **2026-09-28** `web.check_web` now `urlsplit`s the URL once (scheme/host/path read off one parse)
  instead of three times; `ValueError` fails closed to the identical host-parse denial, so verdict/
  reason/layer are unchanged. Helpers `_scheme_of`/`_host_of` kept (still used at web.py:638). Pure
  refactor, no new test. `13acf81`.
- **2026-09-28** `scope._norm_host` now unwraps a bracketed IPv6 `host:port` (`[::1]:8443` → `::1`,
  `[2001:db8::1]:443` → `2001:db8::1`) so authorization and exclusion match a bare-form IPv6; a
  missing closing bracket stays verbatim (denied downstream). Correctness fix — prior behavior failed
  closed. 5 tests, regressions preserved. `e8afb63`.
- **2026-09-28** Report `_finding_md` evidence-CVSS rendering pinned: 3 tests that the finding's own
  `cvss`/`cvss_vector` + "Demonstrated impact:" line render and override the class number, the line
  requires both a score and a basis, and absent an evidence CVSS it falls back to `knowledge.enrich`.
  Test-only. `9bd0997`.
- **2026-09-28** `score_from_vector` now raises `ValueError` on an incomplete CVSS vector instead of
  defaulting missing metrics; docstring corrected. `b6ffd03`.

## HUMAN-GATED — do NOT touch in the autonomous loop
- **Chrome-CDP + full-capture milestone — live validation (DONE 2026-10-01; merge review still pending).**
  ✅ The fresh-lab live CDP run was executed HITL (operator-approved) — see the STATE block above and the
  vault `Brukal.md` 2026-10-01 entry. **Proven live:** `Network.*` capture populates, the always-on
  `_confirm_from_capture` runs every round, containment holds (nmap/curl DENY on domain scope,
  proxy-enforced egress, hash-chained ledgers). **Not proven / needs work:** finding-REGISTRATION did
  not fire (0 findings) — the provers don't cover UNION-retrieval or auth-success solves (now the TOP
  item). The cage was recreated for the run from the EXISTING `docker-kali` image (CDP already live on
  9222) with scope + DNS bring-up, then reverted to crAPI at close. **Still human-only:** (a) a
  whole-branch review of the 14 commits before merging `feat/chrome-cdp-capture` to main; (b) if a from-
  scratch `docker build` of the new image is wanted, that rebuild per `docs/HANDOFF-chrome-cdp-bringup.md`.
  The loop must never do a live run on its own.
- **Response visibility — live measurement.** A human-gated re-run on a self-hosted or sandboxed lab:
  how often the model proposes the next step itself instead of MANUAL, before vs after
  `feat/response-visibility` (same model, same brief). Not for the loop.
- **SP-C real-internet containment** — slice-1 (proxy core) AND slice-2 (kernel-mandatory in-cage proxy)
  are BUILT + merged/committed. What remains is human-only: (a) operator rebuilds + `--force-recreate`s
  `brukal-kali` from the new image and pushes; (b) a real-target dry run — still needs explicit
  per-session authorization (CLAUDE.md) AND an SP-B draft+approve; the loop must never do it.
- **SP-B scope-parser** — being built/merged on branch `sp-b-scope-parser`; leave it to the human.
- **Any live run** against crAPI / DVWA / a real program — requires explicit per-session
  authorization (CLAUDE.md). The loop is build+self-test only.
- **Positive `allowed_paths` scoping** (deferred SP-A decision 2) — a schema/enforcement change;
  fine to *propose* here, but implement only after a human confirms the design.
