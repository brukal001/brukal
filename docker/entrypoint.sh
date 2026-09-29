#!/bin/sh
# Cage entrypoint. Order matters:
#   1. bring the VPN up (needs open egress to reach the VPN server),
#   2. resolve the authorised vhosts ONCE (scope-time pin, never at runtime),
#   3. lock egress to scope with nftables (kernel-enforced default-drop),
#   4. idle so the executor can `docker exec` approved commands in.
#
# The nftables lock is the STRUCTURAL guarantee behind the paper's claim: even a
# command that slips past the Python text-gate cannot send a packet to a host
# outside scope, because the kernel drops it. Fail-closed: a missing/unparseable
# scope installs a drop-all ruleset and the container exits non-zero, so the cage
# never comes up "open". Set BRUKAL_EGRESS_LOCK=0 only on a kernel without
# nftables support (you then lose the structural guarantee — software gate only).
set -e

SCOPE_FILE="${BRUKAL_SCOPE:-/scope.json}"
LOCKDOWN="${BRUKAL_EGRESS_LOCK:-1}"
# DNS resolver to permit (only this one) — defaults to the container's configured
# nameserver (Docker's embedded DNS, usually 127.0.0.11). Lookups work; arbitrary
# DNS-tunnel egress to any other resolver is dropped.
RESOLVER="${BRUKAL_DNS:-$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)}"
RESOLVER="${RESOLVER:-127.0.0.11}"

# SP-C slice-2: the in-cage scope-aware egress proxy. Its uid is the ONLY one the
# nftables ruleset lets egress to the wider internet, so a tool that ignores the
# HTTP(S)_PROXY env cannot reach a target directly — it MUST use the proxy.
PROXY_UID="$(id -u brukalproxy 2>/dev/null || true)"
PROXY_PORT="${BRUKAL_PROXY_PORT:-8888}"

_family() {   # echo "ip" or "ip6" for an address/CIDR
    case "$1" in *:*) echo ip6 ;; *) echo ip ;; esac
}

start_egress_proxy() {
    # Launch the scope-aware egress proxy as the unprivileged brukalproxy user.
    # It loads /scope.json through the SAME deterministic, fail-closed loader the
    # host uses and REFUSES (exits non-zero) on a missing/unparseable/unauthorized
    # scope — so a failure to come up is meaningful, not noise. Binds 127.0.0.1
    # only; the cage's HTTP(S)_PROXY env points tools at it.
    # Not a proxy-capable environment — no brukalproxy user or the CLI is not
    # baked in (e.g. the offline entrypoint test runs the RAW script with no
    # image). Nothing to start, and NOT an error: the nftables lock stands on its
    # own. In the real image both are always present (the Dockerfile build-checks
    # the package), so a genuine failure below is still fatal under the lock.
    if [ -z "$PROXY_UID" ] || ! id brukalproxy >/dev/null 2>&1 \
            || [ ! -f /opt/brukalproxy/egress_proxy_cli.py ]; then
        echo "[cage] egress proxy not installed in this environment — skipping (nft lock stands)."
        return 0
    fi
    mkdir -p /var/log/brukal 2>/dev/null || true
    chown brukalproxy /var/log/brukal 2>/dev/null || true
    echo "[cage] starting scope-aware egress proxy as brukalproxy on 127.0.0.1:$PROXY_PORT ..."
    runuser -u brukalproxy -- \
        python3 /opt/brukalproxy/egress_proxy_cli.py "$SCOPE_FILE" \
        >/var/log/brukal/egress-proxy.log 2>&1 &
    PROXY_PID=$!
    i=0
    while [ "$i" -lt 20 ]; do
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "[cage] egress proxy exited during startup (fail-closed on scope). Log:"
            sed 's/^/[proxy] /' /var/log/brukal/egress-proxy.log 2>/dev/null
            return 1
        fi
        if python3 -c "import socket; socket.create_connection(('127.0.0.1', $PROXY_PORT), 0.5).close()" 2>/dev/null; then
            echo "[cage] egress proxy up (pid $PROXY_PID)."
            return 0
        fi
        i=$((i + 1)); sleep 0.5
    done
    echo "[cage] egress proxy did not bind 127.0.0.1:$PROXY_PORT in time. Log:"
    sed 's/^/[proxy] /' /var/log/brukal/egress-proxy.log 2>/dev/null
    return 1
}

lock_drop_all() {
    # Fail-closed ruleset: drop ALL egress except loopback.
    nft flush ruleset 2>/dev/null || true
    nft -f - <<'NFT'
table inet brukal {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    log prefix "brukal-egress-drop " counter drop
  }
}
NFT
}

apply_egress_lock() {
    if ! command -v nft >/dev/null 2>&1; then
        echo "[cage] FATAL: nftables (nft) not installed."; return 1
    fi
    if [ ! -f "$SCOPE_FILE" ]; then
        echo "[cage] FATAL: scope file $SCOPE_FILE not found — installing drop-all egress."
        lock_drop_all; return 1
    fi

    # Extract authorised CIDRs + hosts with python3 (present in the image). Emits
    # shell-safe assignments, or ERROR= on a malformed policy.
    PARSED="$(python3 - "$SCOPE_FILE" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    cidrs = [str(c).strip() for c in d.get("authorized_cidrs", []) if str(c).strip()]
    hosts = [str(h).strip() for h in d.get("authorized_hosts", []) if str(h).strip()]
    # basic sanity: allow only chars we expect in CIDRs / hostnames
    ok = lambda s, extra: all(c.isalnum() or c in extra for c in s)
    if not all(ok(c, ".:/") for c in cidrs) or not all(ok(h, ".-") for h in hosts):
        raise ValueError("unexpected characters in scope")
    print("CIDRS='" + " ".join(cidrs) + "'")
    print("HOSTS='" + " ".join(hosts) + "'")
except Exception as e:
    print("ERROR='" + str(e).replace("'", "") + "'")
PY
)"
    case "$PARSED" in
        *ERROR=*) echo "[cage] FATAL: scope unparseable: $PARSED"; lock_drop_all; return 1 ;;
    esac
    eval "$PARSED"

    # Resolve each authorised vhost ONCE, now, while egress is still open — pin the
    # result as a /32 (or /128) allow rule. This is scope-TIME resolution: a hostile
    # DNS answer later cannot widen the pinned set (the ruleset is fixed until the
    # cage is restarted). Matches Brukal's "resolve at scope-time, never at runtime".
    # SP-C slice-2: authorised DOMAIN/vhost assets are NO LONGER IP-pinned. A real
    # program lives behind rotating CDN IPs, so a scope-time /32 pin is both stale
    # (rotation breaks reachability) AND a direct bypass path for a tool (it could
    # dial the pinned IP without the proxy). Instead the egress proxy (brukalproxy
    # uid) enforces the host PER REQUEST — surviving rotation — and the
    # uid-segmented rules below bound it to public 80/443 minus private ranges.
    # Only IP scopes (labs) still get a kernel CIDR accept (the $CIDRS loop above).
    # PINNED stays empty on purpose; the loop below is then a no-op.
    PINNED=""
    for h in $HOSTS; do
        echo "[cage] domain asset $h — enforced per-request by the egress proxy (not IP-pinned; survives CDN rotation)."
    done

    # Build the ruleset. Default-drop output; allow loopback, established flows, DNS
    # to the one resolver, the authorised CIDRs, and the pinned host IPs; log+drop
    # the rest.
    rf="$(_family "$RESOLVER")"
    # Only emit the tunnel rule when tun0 actually exists. nftables aborts the WHOLE
    # load on an unknown interface, so on a local (no-VPN) target an unconditional
    # `oif "tun0" accept` installs NOTHING while the cage still reports itself locked.
    TUN=""
    if ip link show tun0 >/dev/null 2>&1; then
        TUN="    oif \"tun0\" accept
"
    fi
    RULES="table inet brukal {
  chain output {
    type filter hook output priority 0; policy drop;
    oif \"lo\" accept
$TUN    ct state established,related accept
    $rf daddr $RESOLVER udp dport 53 accept
    $rf daddr $RESOLVER tcp dport 53 accept
"
    # The lab is reached THROUGH the VPN tunnel, so allow output on tun0 (HTB only
    # pushes routes for the lab range, so nothing else goes there) AND pin the VPN
    # server itself so the encrypted control channel can (re)connect — a scope lock
    # that drops the VPN's own server would kill the tunnel it depends on.
    for host in $(awk '/^[[:space:]]*remote[[:space:]]/{print $2}' "$CFG" 2>/dev/null); do
        for ip in $(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
            RULES="$RULES    ip daddr $ip accept
"
            echo "[cage] pinned VPN server $host -> $ip"
        done
    done
    for cidr in $CIDRS; do
        RULES="$RULES    $(_family "$cidr") daddr $cidr accept
"
    done
    for ip in $PINNED; do
        RULES="$RULES    $(_family "$ip") daddr $ip accept
"
    done
    # --- SP-C slice-2: uid-segmented egress -----------------------------------
    # Everything above is uid-agnostic: loopback, return traffic, DNS to the one
    # resolver, the VPN server, and the explicitly-authorised lab CIDRs / pinned
    # host IPs. A lab IP scope therefore keeps working EXACTLY as before (V5, no
    # regression). But a tool (running as brukalop) now has NO path to an
    # arbitrary target: only the loopback proxy and those authorised lab IPs.
    #
    # ONLY the brukalproxy uid may reach the wider internet — and even then any
    # private / loopback / link-local / metadata / CGNAT / ULA / reserved daddr is
    # DROPPED (defence in depth with slice-1's is_blocked_ip; the authorised lab
    # CIDRs above already matched first, so an authorised private /32 is
    # unaffected). Public egress is bounded to tcp {80,443}. This is the
    # kernel-mandatory guarantee: a domain/wildcard scope is contained despite
    # rotating CDN IPs, and a tool that ignores HTTP(S)_PROXY simply cannot send.
    if [ -n "$PROXY_UID" ]; then
        RULES="$RULES    meta skuid $PROXY_UID ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, 0.0.0.0/8, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 } drop
    meta skuid $PROXY_UID ip6 daddr { ::1, ::/128, fe80::/10, fc00::/7, ff00::/8, 2001:db8::/32 } drop
    meta skuid $PROXY_UID tcp dport { 80, 443 } accept
"
    else
        echo "[cage] WARNING: brukalproxy uid not found — emitting NO internet egress path (fully contained)."
    fi
    RULES="$RULES    log prefix \"brukal-egress-drop \" counter drop
  }
}
"
    nft flush ruleset 2>/dev/null || true
    printf '%s' "$RULES" | nft -f -
    # VERIFY the ruleset actually loaded before claiming it did. nft aborts the whole
    # load on any parse error, and this function runs in an `if !` condition where
    # `set -e` does not apply, so an unchecked failure leaves egress WIDE OPEN under a
    # "locked" message. Fail closed instead.
    if ! nft list ruleset 2>/dev/null | grep -q 'policy drop'; then
        echo "[cage] FATAL: egress ruleset did not load (no default-drop policy present)."
        lock_drop_all; return 1
    fi
    echo "[cage] egress locked to scope. Ruleset:"
    nft list ruleset
}

# --- 1. VPN (open egress needed to reach the VPN server) ---------------------
CFG="${VPN_CONFIG:-/vpn/config.ovpn}"
if [ -f "$CFG" ]; then
    echo "[cage] starting OpenVPN from $CFG ..."
    openvpn --config "$CFG" --daemon --log /var/log/openvpn.log
    i=0
    while [ "$i" -lt 30 ]; do
        if ip addr show tun0 >/dev/null 2>&1; then
            echo "[cage] VPN up (tun0):"; ip -brief addr show tun0; break
        fi
        i=$((i + 1)); sleep 1
    done
    ip addr show tun0 >/dev/null 2>&1 || \
        echo "[cage] WARNING: tun0 not up — see /var/log/openvpn.log"
else
    echo "[cage] no VPN config at $CFG — local mode (drop an .ovpn in docker/vpn/config.ovpn for HTB)."
fi

# --- 2+3. Egress lock (fail-closed) -----------------------------------------
if [ "$LOCKDOWN" = "1" ]; then
    if ! apply_egress_lock; then
        echo "[cage] FATAL: could not apply the scope egress lock — refusing to run open."
        echo "[cage] (on a kernel without nftables support, set BRUKAL_EGRESS_LOCK=0 to run"
        echo "[cage]  software-gate-only; you then lose the kernel-enforced scope guarantee.)"
        exit 1
    fi
    # The uid-segmented lock makes the proxy the ONLY internet gateway, so it is
    # mandatory when the lock is on: if it refuses (bad/unauthorized scope), fall
    # back to drop-all and refuse to run rather than come up half-open.
    if ! start_egress_proxy; then
        echo "[cage] FATAL: the egress proxy is mandatory under the kernel lock — refusing to run."
        lock_drop_all
        exit 1
    fi
else
    echo "[cage] WARNING: BRUKAL_EGRESS_LOCK=0 — egress NOT locked (software gate only)."
    # HTTP(S)_PROXY still points tools at the proxy; start it best-effort so they
    # have a working gateway. In this degraded mode a proxy failure is not fatal.
    if ! start_egress_proxy; then
        echo "[cage] WARNING: egress proxy did not start — HTTP(S)_PROXY tools will fail until the scope is valid."
    fi
fi

# --- 4. Idle so the executor can exec approved commands in -------------------
exec sleep infinity
