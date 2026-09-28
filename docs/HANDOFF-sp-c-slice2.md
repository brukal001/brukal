# New-session prompt — resume Brukal SP-C slice-2

Paste the block below as the FIRST message of a fresh Claude Code session (run it from the repo
`/mnt/c/Users/ashis/Desktop/Brukal/brukal`). It is self-contained; the durable state is git + the vault.

---

Read `CLAUDE.md` (the five safety invariants + build discipline — LAW) and the vault note
`/mnt/c/Users/ashis/Desktop/Brukal's Memory/Brukal.md` first; this session must obey them. Then read
`docs/superpowers/specs/2026-09-29-egress-proxy-slice2-design.md` (the task) and
`docs/superpowers/specs/2026-09-29-egress-proxy-design.md` (slice-1, already merged). `git log --oneline -15`.

**Where we are (all merged to `main`/`origin`, suite 2020 green):** this arc shipped, in order — item-F
status-oracle SQLi prover (crAPI #13, recall 3→4); **SP-A** rich scope schema + deterministic enforcement
(path/exclusion scoping, bug-class gating on 47 provers, testing-policy envelope); evidence-based CVSS;
**SP-B** free-text-program → draft `scope.json` + `scope_rules.md` with a human `scope approve` gate;
a fresh-session self-improve loop (`brukal-improve-loop.sh` + `NEXT.md`); **SP-C slice-1** = the
scope-aware egress **proxy core** (`brukal/egress.py`, `brukal/egress_proxy.py`) with an anti-SSRF/rebinding
IP guard, a HARD `is_authorized()` gate in the shared `enforce_authorization` (an unapproved scope cannot
drive `auto`/`solve`), and mandatory `tls_verify` for domain scopes; plus a slice-2 prep fix so
`egress_decision` allows an explicitly-authorised private CIDR (lab targets) while still denying rebinding.

**YOUR TASK — SP-C slice-2 (build the kernel-mandatory in-cage egress proxy), per its spec:**
1. Add the minimal stdlib-only proxy package (`scope.py`, `hostmatch.py`, `bugclass.py`, `egress.py`,
   `egress_proxy.py` + an empty package `__init__.py`) and a small `egress_proxy_cli.py`
   (loads `/scope.json`, runs `run_proxy` on `127.0.0.1:8888`) into the cage image via `docker/Dockerfile.kali`,
   plus a dedicated `brukalproxy` user.
2. In `docker/entrypoint.sh`: start the proxy as `brukalproxy`, then build **uid-segmented nftables** —
   only `meta skuid brukalproxy` may egress to the internet (still dropping private/link-local/metadata
   ranges); every other uid (the tool user `brukalop`) gets loopback + DNS only, so tools CANNOT bypass the
   proxy. Keep the existing IP-scope CIDR accepts (lab compat) and the fail-closed drop-all on missing scope.
3. `docker/docker-compose.yml`: add `HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy=http://127.0.0.1:8888`
   so the cage's curl (DockerHttpWebCage) routes through the proxy.
4. **Requires Docker running.** `docker build` the image, then run **V1–V5 on a THROWAWAY container**
   (V1 direct-bypass dropped · V2 in-scope-via-proxy works, out-of-scope 403 · V3 private/metadata IP denied
   · V4 no-scope → drop-all, proxy refuses · V5 an IP-scope lab like `scope.crapi.json` still reaches its /32
   via the proxy — NO regression). Iterate to green. **Do NOT recreate `brukal-kali`** (the live crAPI lab) —
   the operator does that deliberately once V1–V5 pass on the throwaway image.
5. Keep the full suite green; preserve all five invariants; commit per milestone; update the vault + NEXT.md;
   **push nothing to a remote without the operator**, and **run against NO real/external target** — a real
   dry-run still needs explicit per-session authorization (CLAUDE.md) AND SP-B draft+approve, and is a
   SEPARATE later step.

**Blocker last session:** Docker Desktop was unresponsive (`docker info`/`ps` hung), so the image
build + V1–V5 could not run. First thing: confirm `docker ps` responds; if not, ask the operator to start
Docker Desktop before building.

**Method:** brainstorm/spec is done (the slice-2 spec IS the design); this is a build. Use TDD where offline
(the egress core is already tested); the V1–V5 procedure is the integration test for the cage bits. Prefer
validating on a throwaway container over ever touching `brukal-kali`.
