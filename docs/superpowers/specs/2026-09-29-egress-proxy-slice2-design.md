# SP-C slice-2 — make the egress proxy kernel-mandatory in the cage (design)

**Date:** 2026-09-29 · Follows slice-1 (merged `1bff533`). This is the infra half.

## Goal
Route the live cage's target egress THROUGH the slice-1 proxy, and make that **kernel-mandatory**
(a tool cannot bypass it), so a domain/wildcard real-program scope is contained despite rotating IPs.

## The constraint slice-2 must solve (why it's bigger than "wire it up")
The proxy must run **inside the cage** (it is the cage's gateway to the internet). But the Kali cage
image (`docker/Dockerfile.kali`) does not ship the brukal Python package — brukal runs on the HOST.
So slice-2 needs the proxy code + a small CLI IN THE IMAGE, plus an nftables model that forces tools
through it, plus a cage recreate to verify. None of it is offline-unit-testable.

## Design (kernel-mandatory via UID segmentation)
1. **Proxy in the image** (`Dockerfile.kali`): copy `brukal/egress.py` + `brukal/egress_proxy.py` +
   a tiny `egress_proxy_cli.py` (loads the mounted `/scope.json`, runs `run_proxy` on `127.0.0.1:8888`,
   appends decisions to a cage-local audit) into the image; ensure python3 present (Kali has it).
   Create a dedicated unprivileged user `brukalproxy`.
2. **entrypoint.sh:** after the (existing) scope parse, START the proxy as `brukalproxy` on
   `127.0.0.1:8888` with `/scope.json`. Then build the nftables ruleset **uid-segmented**:
   - default-drop output (unchanged).
   - allow loopback (so tools reach the proxy on 127.0.0.1:8888) and DNS to the one resolver.
   - **only `meta skuid brukalproxy`** may egress to the internet, and even then `ip daddr` in the
     private/link-local/metadata/ULA ranges is DROPPED (defense-in-depth with slice-1's `is_blocked_ip`).
     Everything on `{80,443}` to public space from that uid is allowed.
   - every OTHER uid gets NO non-loopback egress → a tool that ignores the proxy env cannot send a
     packet to a target directly; it MUST use the proxy. That is the kernel-mandatory guarantee.
   - a missing/unparseable scope → drop-all (unchanged fail-closed) and the proxy refuses (no scope).
3. **Route tools through it** (`docker-compose.yml` env): `HTTP_PROXY=http://127.0.0.1:8888`,
   `HTTPS_PROXY=http://127.0.0.1:8888`, `http_proxy`/`https_proxy` too — so the cage's `curl`
   (DockerHttpWebCage / the GovernedBrowser) and other tools route through the proxy. (curl honours these.)
4. **Domain scopes:** for a wildcard/domain scope there are NO CIDRs to pin — that's the whole point;
   the proxy enforces the host per request, and the uid-nftables bounds egress to public 80/443 minus
   private ranges. The existing CIDR-accept path stays for IP scopes (labs) so crAPI/DVWA are unchanged
   in behavior (their tools can still reach the /32 — but now also only via the proxy uid; a lab scope
   run continues to work because the proxy allows the in-scope IP too).

## Verification (MUST pass before deploying to the real `brukal-kali`)
Validate on a THROWAWAY container from the rebuilt image (do NOT disturb `brukal-kali` until green):
- V1: a `curl` (non-proxy uid) DIRECT to a public host (e.g. `http://1.1.1.1`) is DROPPED (kernel).
- V2: a `curl` VIA the proxy to an IN-SCOPE host succeeds; to an OUT-OF-SCOPE host gets 403 from the proxy.
- V3: any request that resolves to a private/metadata IP is denied (proxy + nftables).
- V4: with no scope mounted → drop-all, proxy refuses; container does not come up "open".
- V5: an existing IP-scope lab (crAPI `scope.crapi.json`) still reaches its /32 via the proxy (no regression).
Only after V1–V5 pass on the throwaway image does the operator recreate `brukal-kali`.

## Risk / honesty
- High blast radius: this rewrites the cage image + entrypoint that crAPI/DVWA depend on. Validated on a
  throwaway container first; `brukal-kali` is recreated only on green.
- Not offline-unit-testable (it's live kernel/network); the V1–V5 procedure IS the test.
- A real-target run STILL needs explicit per-session authorization (CLAUDE.md) AND SP-B draft+approve —
  slice-2 only builds the containment, it authorizes nothing.

## Build plan
1. `Dockerfile.kali`: add proxy code + `brukalproxy` user + `egress_proxy_cli.py`.
2. `entrypoint.sh`: start proxy + uid-segmented nftables (keep the existing IP-scope accepts).
3. `docker-compose.yml`: proxy env vars.
4. Build the image; run V1–V5 on a throwaway container; iterate until green.
5. Report; operator recreates `brukal-kali` when ready.
