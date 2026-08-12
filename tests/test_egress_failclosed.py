"""
test_egress_failclosed.py — the cage must never come up claiming a kernel egress
lock it does not have.

THE PROPERTY
    nftables aborts the WHOLE load on a single parse error: one bad rule means NO
    rules, not fewer rules. So "nft returned" is not evidence that the lock exists.
    The entrypoint must VERIFY the default-drop policy is actually loaded before it
    reports "egress locked to scope", and must fail closed — exit non-zero, never
    reaching the idle step — when it is not.

THE DEFECT THIS PINS (HARDENING_ROADMAP P1 #1, observed 2026-08-08 during Cap setup)
    The ruleset carried an unconditional `oif "tun0" accept`. OpenVPN had not yet
    brought the tunnel up, so that rule failed to parse, the entire load aborted, and
    `nft list ruleset` returned EMPTY — not drop-all, not degraded, empty. The
    container started anyway with BRUKAL_EGRESS_LOCK=1 and unrestricted egress while
    printing "[cage] egress locked to scope." A fail-OPEN on the one control the
    paper calls kernel-enforced. It was harmless only because there was no tunnel to
    reach anything through; the same failure with a tunnel already up leaves the cage
    able to egress anywhere while reporting itself locked.

    Two things were wrong and both are pinned here: the success message was printed
    without checking (test 1), and a not-yet-existent interface could abort the whole
    default-drop policy (tests 2 and 3).

HOW IT IS TESTED
    By running the real docker/entrypoint.sh under stub `nft`, `ip` and `sleep` on
    PATH. The stubs make the failure reproducible in milliseconds with no Docker, no
    NET_ADMIN and no kernel nftables — and the file under test is the one that ships,
    not a copy of its logic.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ENTRYPOINT = Path(__file__).resolve().parents[1] / "docker" / "entrypoint.sh"

# The stub nft refuses to load any ruleset mentioning this, standing in for the real
# "Interface does not exist" / unresolvable-address parse error that aborts the load.
UNLOADABLE = "203.0.113.7"

_NFT_STUB = """#!/bin/sh
# Stub nft. Records what it was asked to load; only a load that SUCCEEDS becomes the
# live ruleset, exactly like the real thing (a parse error installs nothing at all).
case "$1" in
  flush) exit 0 ;;
  -f)
    cat > "$FAKE_NFT_STATE.attempt"
    if [ -n "$FAKE_NFT_REJECT" ] && grep -q "$FAKE_NFT_REJECT" "$FAKE_NFT_STATE.attempt"; then
        echo "/dev/stdin:8:14-28: Error: Could not resolve hostname" >&2
        exit 1
    fi
    cp "$FAKE_NFT_STATE.attempt" "$FAKE_NFT_STATE.loaded"
    exit 0 ;;
  list)
    [ -f "$FAKE_NFT_STATE.loaded" ] && cat "$FAKE_NFT_STATE.loaded"
    exit 0 ;;
esac
exit 0
"""

_IP_STUB = """#!/bin/sh
# Stub ip. tun0 exists only when the test says so.
[ "$FAKE_TUN0" = "1" ] && { echo "tun0 UNKNOWN 10.10.15.169/23"; exit 0; }
exit 1
"""

# The entrypoint's last act on success is `exec sleep infinity`. Stubbing sleep both
# stops the test hanging and gives us the evidence that matters: whether the cage
# reached its idle step at all.
_SLEEP_STUB = """#!/bin/sh
touch "$FAKE_NFT_STATE.idled"
exit 0
"""


def _run_entrypoint(tmp_path, *, cidr: str, reject: str = "", tun0: bool = False):
    """Run the real entrypoint with stubbed nft/ip/sleep. Returns (proc, state_prefix)."""
    binder = tmp_path / "bin"
    binder.mkdir()
    for name, body in (("nft", _NFT_STUB), ("ip", _IP_STUB), ("sleep", _SLEEP_STUB)):
        p = binder / name
        p.write_text(body)
        p.chmod(0o755)

    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "engagement": "failclosed-probe",
        "authorized_cidrs": [cidr],
        "allowlisted_tools": "all",
        "rate_limit_per_min": 10,
    }))

    state = tmp_path / "nft"
    env = {
        **os.environ,
        "PATH": f"{binder}{os.pathsep}{os.environ['PATH']}",
        "BRUKAL_SCOPE": str(scope),
        "BRUKAL_EGRESS_LOCK": "1",
        "BRUKAL_DNS": "1.1.1.1",              # deterministic: no /etc/resolv.conf read
        "VPN_CONFIG": str(tmp_path / "no-such.ovpn"),
        "FAKE_NFT_STATE": str(state),
        "FAKE_NFT_REJECT": reject,
        "FAKE_TUN0": "1" if tun0 else "0",
    }
    proc = subprocess.run(["sh", str(ENTRYPOINT)], env=env, timeout=60,
                          capture_output=True, text=True)
    return proc, state


def _loaded(state: Path) -> str:
    f = Path(f"{state}.loaded")
    return f.read_text() if f.exists() else ""


# --------------------------------------------------------------------------- #
# 1. The fail-open itself
# --------------------------------------------------------------------------- #

def test_a_ruleset_that_does_not_load_fails_closed(tmp_path):
    """THE DEFECT. A scope that parses fine but whose ruleset nft refuses must stop
    the cage — not start it with no rules under a 'locked' banner."""
    proc, state = _run_entrypoint(tmp_path, cidr=f"{UNLOADABLE}/32", reject=UNLOADABLE)

    assert proc.returncode != 0, (
        "the cage exited 0 after its ruleset failed to load — it came up OPEN\n"
        f"stdout:\n{proc.stdout}")
    assert "egress locked to scope" not in proc.stdout, (
        "the cage claimed a lock it does not have — this is the exact Cap-setup "
        f"fail-open\nstdout:\n{proc.stdout}")
    assert not Path(f"{state}.idled").exists(), (
        "the cage reached its idle step, so the executor could have run commands "
        "in it with egress unrestricted")
    assert UNLOADABLE not in _loaded(state), (
        "the scope ruleset is reported as live even though nft rejected it")


# --------------------------------------------------------------------------- #
# 2 + 3. The root cause: one absent interface must not abort the whole policy
# --------------------------------------------------------------------------- #

def test_an_absent_tun0_does_not_abort_the_default_drop_policy(tmp_path):
    """The rule that broke the load on Cap is emitted only when the interface is
    really there, so a local (no-VPN) target still gets a full default-drop lock."""
    proc, state = _run_entrypoint(tmp_path, cidr="172.20.0.3/32", tun0=False)
    live = _loaded(state)

    assert 'oif "tun0"' not in live, (
        "an interface that does not exist was still written into the ruleset — "
        f"nft aborts the whole load on that\n{live}")
    assert "policy drop" in live, f"no default-drop policy was installed\n{live}"
    assert "172.20.0.3" in live, f"the authorised scope is not in the ruleset\n{live}"
    assert proc.returncode == 0 and "egress locked to scope" in proc.stdout, proc.stdout
    assert Path(f"{state}.idled").exists(), "the cage did not reach its idle step"


def test_a_present_tun0_still_gets_its_rule(tmp_path):
    """The fix is a condition, not a deletion: with a tunnel up the rule is still
    emitted, so VPN-reached labs keep working."""
    _proc, state = _run_entrypoint(tmp_path, cidr="10.129.101.3/32", tun0=True)
    live = _loaded(state)

    assert 'oif "tun0"' in live, f"the tunnel rule was dropped entirely\n{live}"
    assert "policy drop" in live, f"no default-drop policy was installed\n{live}"
