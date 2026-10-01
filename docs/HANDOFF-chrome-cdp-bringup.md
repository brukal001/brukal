# HANDOFF — bringing up the proxied, debuggable chromium (Task 10)

Status: **built + shape-tested only**. Nothing in this doc has been executed this
session. Rebuilding/recreating the cage and any live CDP connection are
**HUMAN-GATED** — per `CLAUDE.md` ("build and self-test only; pause for sign-off
before any live execution") and `NEXT.md`. This session edited `docker/entrypoint.sh`,
`docker/docker-compose.yml`, and added a text-only shape test; it did not run Docker.

## What changed

- `docker/entrypoint.sh` now launches headless chromium, in the background, as the
  unprivileged `brukalop` user — **after** the scope-aware egress proxy (`brukalproxy`)
  is confirmed up and **after** the uid-segmented nftables lock has been applied. If
  `brukalop` or the `chromium` binary is missing, the launch is skipped (not an error),
  mirroring how the proxy start already degrades gracefully in environments without it.
- `docker/docker-compose.yml` now publishes `127.0.0.1:9222:9222` on the `kali` service —
  the CDP control channel only, bound to the **host's** loopback interface. This is not
  a target-egress path: egress is still governed entirely by the nftables uid lock plus
  the in-cage proxy, unchanged by this port.
- `tests/test_docker_chromium_launch.py` — a deterministic, Docker-free shape/lint test
  that reads both files as text and asserts the launch flags and the published port are
  present, and that `--ignore-certificate-errors` is absent.

## Chromium launch line (as shipped)

```sh
runuser -u brukalop -- \
    chromium --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0 \
    --proxy-server="http://127.0.0.1:${PROXY_PORT}" \
    --proxy-bypass-list="<-loopback>" \
    about:blank \
    >/var/log/brukal/chromium.log 2>&1 &
```

`PROXY_PORT` is the SAME variable the egress proxy binds (`BRUKAL_PROXY_PORT`, default
`8888` — not `8080`), so the browser and the proxy never disagree about the port.

### Why `--proxy-bypass-list="<-loopback>"` is not optional

Chromium's default behaviour bypasses whatever proxy is configured when the request
target is loopback. With CDP listening on `9222`, that default would let a hostile page
loaded in the browser do `fetch('http://127.0.0.1:9222/json')` straight from page JS —
bypassing the proxy entirely — and from there reach the devtools websocket, i.e. an
SSRF-into-CDP path that turns a malicious target page into control of the browser
itself. `<-loopback>` removes the implicit loopback exemption so even a page's
loopback-targeted request is sent through `127.0.0.1:${PROXY_PORT}`, whose egress guard
denies loopback/private destinations outright — closing the hole. This only affects how
page-originated **request targets** are routed; chromium's own connection to the proxy
process is always made directly, as it must be to reach the proxy at all.

This session cannot confirm chromium honours the exact `<-loopback>` token without a
live run (human-gated); the flag is asserted present by the shape test, and the intent
is documented in a comment directly above the launch in `entrypoint.sh` so it survives
future edits.

No `--ignore-certificate-errors` is passed anywhere — certificate verification stays ON
in the image. TLS relaxation, if ever needed, is a Brukal-side `scope.tls_verify`
decision made by the host-side code, never something baked into the cage.

## Bring-up recipe (human-gated — do not run from an autonomous loop)

1. Confirm Docker is responsive: `docker ps`.
2. Rebuild the image (chromium's launch line lives in `entrypoint.sh`, baked into the
   image at build time) and recreate the container — **not** a plain `restart`, which
   reuses the existing container and its stale entrypoint run:

   ```sh
   docker compose -f docker/docker-compose.yml up -d --build --force-recreate kali
   ```

3. Tail the chromium log inside the cage to confirm it started:

   ```sh
   docker exec brukal-kali sh -c 'tail -n 40 /var/log/brukal/chromium.log'
   ```

4. Liveness check from the host, over the published loopback port:

   ```sh
   curl -s 127.0.0.1:9222/json
   ```

   Expect a JSON array describing the `about:blank` target. No response (connection
   refused) means either chromium did not start (check the log in step 3) or the image
   was not rebuilt with this change.

5. Confirm containment did not regress — the egress lock and proxy still apply to the
   browser's own uid exactly as they do to every other tool:

   ```sh
   docker exec brukal-kali nft list ruleset | grep -A2 daddr
   docker exec brukal-kali ps -o pid,user,cmd -C chromium
   ```

   The `chromium` process should be owned by `brukalop`, not `brukalproxy` or `root`.

## What this session did NOT do

- Did not run `docker build` or any `docker compose` command.
- Did not start a live chromium process or connect to port 9222.
- Did not touch `NEXT.md` (owned by Task 11).

Any step under "Bring-up recipe" above requires explicit per-session operator
authorization before it is run, per `CLAUDE.md`'s rules of engagement.
