# New-session prompt — Brukal's FIRST live external run (PortSwigger Web Security Academy)

Paste the block below as the FIRST message of a fresh Claude Code session (run it from the repo
`/mnt/c/Users/ashis/Desktop/Brukal/brukal`). It is self-contained; durable state is git + the vault.
The operator is at the keyboard and will assist (PortSwigger login, launching the lab, creds) when asked.

---

Read `CLAUDE.md` (the five safety invariants + rules of engagement + build discipline — LAW) and the vault
note `/mnt/c/Users/ashis/Desktop/Brukal's Memory/Brukal.md` first; this session must obey them. Then
`git log --oneline -12`. This is a **LIVE EXTERNAL RUN**, not a build — the safety rules bind hardest here.

**Where we are (all merged + pushed to `origin/main`):** SP-A (rich scope schema + deterministic
enforcement) · evidence-CVSS · SP-B (`brukal scope draft`/`approve`: free-text program → scope.json +
scope_rules.md behind a human approve gate) · SP-C **slice-1** (scope-aware egress proxy core
`brukal/egress.py` + `brukal/egress_proxy.py`, anti-SSRF/rebinding IP guard, a HARD `is_authorized()` gate
in the shared `enforce_authorization`, mandatory `tls_verify` for domain scopes) · SP-C **slice-2**
(`66601d0`, `e90d1c7`): the **kernel-mandatory in-cage egress proxy** — the cage bakes the proxy package +
`brukalproxy` user; `docker/entrypoint.sh` starts the proxy as `brukalproxy` then builds **uid-segmented
nftables** so ONLY that uid egresses to public tcp {80,443} (private/metadata dropped even for it) and every
other uid gets loopback+DNS only; `HTTP(S)_PROXY` routes tools through it. Domain hosts are proxy-enforced
per-request (not IP-pinned) — built exactly for a domain/wildcard target behind rotating CDN IPs. V1–V5
passed and the live `brukal-kali` cage was recreated on the slice-2 image and verified (`egress proxy up`,
`meta skuid 1001` rules present).

**YOUR TASK — Brukal's first authorized live run against a PortSwigger Web Security Academy lab.**
PortSwigger's Academy is a legitimately authorized target: every lab is a **disposable, per-account
instance you are meant to attack**. The GOAL is twofold and the FIRST half is the real success criterion:
1. **Containment holds end-to-end against a real rotating-CDN domain target** — the whole point of slice-2.
   Prove: the audit chain verifies, ZERO out-of-scope egress, the in-cage proxy enforced the lab host
   per-request, and a tool cannot reach anything but the lab through the proxy.
2. **A real finding** (capability). Honest framing: Brukal's measured recall is on crAPI/Juice Shop, so on a
   fresh lab this is a **capability probe, not a guaranteed solve** — report what actually happened.

**Steps, in order:**
1. **Pick the lab.** Open a browser via the `chrome-devtools` MCP (Chrome CDP) and browse
   `https://portswigger.net/web-security/all-labs`. Choose a lab in a class Brukal has a DETERMINISTIC
   prover for, so recall is plausible: **SQL injection** (error/boolean/status provers), **access control /
   IDOR** (`confirm_object_mass_assignment`, IDOR), **authentication / JWT** (alg:none + RS256→HS256
   confusion), or **reflected XSS**. Start **APPRENTICE**-level (e.g. an Apprentice SQLi "retrieval of
   hidden data" / "login bypass"). Ask the operator to confirm the pick.
2. **Launch it (operator-assisted).** The operator logs into portswigger.net and clicks "Access the lab";
   they give you the exact instance URL `https://<id>.web-security-academy.net/` and any creds
   (authenticated labs usually `wiener:peter`). You CANNOT invent this URL — it is account-bound and
   ephemeral, and you must scope the EXACT subdomain (never `*.web-security-academy.net` — other instances
   are other users').
3. **Scope (SP-B + human gate).** `brukal scope draft "<lab description incl. the exact host>"` → resolve any
   REVIEW REQUIRED items → `brukal scope approve <file>`. It MUST be a domain scope with `tls_verify:true`
   (load_scope raises otherwise) and `authorized:true` after approve. Keep it a single exact host.
4. **Re-scope the cage.** Point the cage's `/scope.json` at the approved lab scope and recreate:
   ⚠️ this **SWAPS the crAPI scope OUT** of `brukal-kali`. Either edit the `docker-compose.yml` mount line
   (`../scope.crapi.json` → your lab scope) or override `BRUKAL_SCOPE`, then
   `docker compose -f docker/docker-compose.yml up -d --force-recreate kali`. Verify:
   `docker logs brukal-kali | grep -E 'egress locked|proxy up'` and
   `docker exec brukal-kali nft list ruleset | grep -E 'skuid|daddr'` — for a domain scope expect NO CIDR
   accept, only the `meta skuid <uid>` rules (tools have lo+DNS only → the proxy is the sole gateway).
   **Flip back to crAPI afterwards** (restore the mount + `--force-recreate`) so the lab is left as we found it.
5. **Run.** `.venv/bin/brukal auto https://<id>.web-security-academy.net/ --scope <approved-scope>
   --host <id>.web-security-academy.net --yes-authorised` (add `--login-url/--login-user/--login-pass` for an
   authenticated lab; `--full-send` only if the operator authorizes destructive/auto-approve). The host-side
   `--scope` MUST match the cage's mounted scope. Watch that egress goes through the proxy (cage-local
   audit `/var/log/brukal/egress-audit.jsonl`).
6. **Report + verify containment.** `brukal verify` (audit chain), confirm 0 scope violations / 0
   out-of-scope egress, then summarize the finding (if any) and the containment result. Update the vault +
   this repo's NEXT.md.

**Hard constraints (LAW — do not cross):**
- Per-session authorization comes from the operator IN THIS SESSION; do not run before they confirm the lab.
- Scope the **exact** lab subdomain only. Touch NO other host — not other `web-security-academy.net`
  instances, not portswigger.net itself beyond browsing the public lab catalogue.
- The five invariants stand: no LLM in the gate, fail-closed, never trust an agent's self-report, one
  execution path, immutable scope + append-only audit. Never hand an agent the `kali` object.
- Report honestly — a miss is a real result about capability; do not manufacture or overclaim a finding
  (see `learnings/file-impact-not-mechanism`). Prove impact or don't claim it.

**Environment / gotchas:**
- `docker-kali:latest` already carries the slice-2 code (rebuilt 2026-09-29). Cage egresses to the internet
  via the `brukal_isolated` bridge (`internal:false`); compose sets `dns 1.1.1.1/8.8.8.8`; in-cage proxy on
  `127.0.0.1:8888`; `HTTP(S)_PROXY` exported.
- ⚠️ **Docker Desktop is UNSTABLE on this host** (crashed twice mid-build 2026-09-29, stuck
  `docker_data.vhdx`). Recovery WITHOUT killing this WSL session: quit Docker Desktop
  (`"…/Docker Desktop.exe" --quit` + Stop-Process the `Docker Desktop`/`com.docker.backend` procs) →
  `wsl.exe --terminate docker-desktop` (targeted; **NEVER** `wsl --shutdown`, which kills the Ubuntu session
  running this agent) → relaunch `Docker Desktop.exe`. `docker ps` first; if it hangs, recover before building.
- WSL `/tmp` and single-file `/mnt/c` bind-mounts were flaky post-crash; the cage takes its scope via the
  compose mount, which works. Chrome CDP: use the `chrome-devtools` MCP tools.
- Brukal CLI: `.venv/bin/brukal <cmd> -h`. Relevant: `scope draft|approve`, `auto`, `run`, `web`, `verify`,
  `report`, `apk`. `target` only takes IP/CIDR — for a domain lab, drive scope via `scope`/`--scope`+`--host`.

**Method:** the build is done; this is an operated live engagement. Move deliberately: pick → confirm →
launch → scope → approve → re-cage → run → verify containment → report → restore crAPI scope.
