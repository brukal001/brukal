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
- **Chrome-CDP + capture milestone (operator-directed):** web hunting used the raw-HTTP cage
  (`DockerHttpWebCage`, curl-equivalent) for crawl/requests; Chrome (`DockerChromeCage`, real CDP) was used
  only for navigate/screenshot. No live mitmproxy-style full request/response capture exists (`--capture` only
  INGESTS an external HAR). Operator wants web hunting driven through Chrome CDP with full traffic capture so
  provers work off real request/response. Design as its own tested milestone.
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
- **_Queue drained 2026-09-28 (2nd review's only note handled; that pass was otherwise clean)._** No
  autonomous item is queued. **Refill before the loop can run again**: take the top of a fresh
  `/code-review` pass or a coverage sweep, confirm it is build+self-test only (nothing under
  HUMAN-GATED), and write it here as the new TOP. The loop MUST NOT invent scope-relevant work on its
  own — a human or a review supplies the next item.

## QUEUE (safe, tested, autonomous — promote to TOP when the current one lands)
_(empty — refill from a review or a fresh coverage pass)_

## DONE (most recent first — for the next session's context, not an action item)
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
- **SP-C real-internet containment** — slice-1 (proxy core) AND slice-2 (kernel-mandatory in-cage proxy)
  are BUILT + merged/committed. What remains is human-only: (a) operator rebuilds + `--force-recreate`s
  `brukal-kali` from the new image and pushes; (b) a real-target dry run — still needs explicit
  per-session authorization (CLAUDE.md) AND an SP-B draft+approve; the loop must never do it.
- **SP-B scope-parser** — being built/merged on branch `sp-b-scope-parser`; leave it to the human.
- **Any live run** against crAPI / DVWA / a real program — requires explicit per-session
  authorization (CLAUDE.md). The loop is build+self-test only.
- **Positive `allowed_paths` scoping** (deferred SP-A decision 2) — a schema/enforcement change;
  fine to *propose* here, but implement only after a human confirms the design.
