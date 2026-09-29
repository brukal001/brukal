#!/usr/bin/env python3
"""
egress_proxy_cli.py — the in-cage entry point for the scope-aware egress proxy
(SP-C, slice 2). It is copied into the Kali image and run by the entrypoint as
the unprivileged `brukalproxy` user; it is the cage's ONLY gateway to a target.

It does the smallest possible thing on top of the slice-1 core:

  1. load the mounted `/scope.json` through `brukal.scope.load_scope` — the SAME
     deterministic, fail-closed loader the host engagement uses (so a domain
     scope without tls_verify RAISES here too, and a malformed policy refuses);
  2. refuse to start on an unauthorized scope (defense in depth with the host's
     `engagement.run` authorization gate — a drafted/unauthorized scope must not
     be given a working egress path);
  3. run `brukal.egress_proxy.run_proxy` on 127.0.0.1:8888, appending every
     decision to a cage-local append-only JSONL audit.

Fail-closed (invariant 2): anything wrong with the scope — missing, unparseable,
tls-mandatory-violated, or unauthorized — exits non-zero and starts NO proxy, so
the entrypoint can keep the cage from coming up with an open (or half-open) path.
The host keeps the authoritative hash-chained audit; this cage-local file is a
best-effort convenience record and never blocks or crashes the proxy.

Stdlib only — the image ships just the minimal brukal package
(scope/hostmatch/bugclass/egress/egress_proxy + an empty __init__), never the
pydantic-heavy full package.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import threading
import time
from pathlib import Path

# The minimal package sits next to this file (…/brukal/) — make it importable
# whatever directory the entrypoint launches us from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from brukal import egress_proxy                       # noqa: E402
from brukal.scope import load_scope                    # noqa: E402

_DEFAULT_SCOPE = os.environ.get("BRUKAL_SCOPE", "/scope.json")
_DEFAULT_PORT = int(os.environ.get("BRUKAL_PROXY_PORT", "8888") or "8888")
_DEFAULT_AUDIT = os.environ.get(
    "BRUKAL_EGRESS_AUDIT", "/var/log/brukal/egress-audit.jsonl")


class JsonlAudit:
    """A tiny append-only audit sink matching the shape `run_proxy` expects
    (`append(kind, data)`), writing one JSON object per line. Best-effort: an
    audit write must never take the proxy down, so every error is swallowed
    after a single stderr warning. The authoritative, hash-chained audit lives
    on the host; this is the cage-local convenience copy."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._warned = False
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def append(self, kind: str, data) -> None:
        try:
            payload = dataclasses.asdict(data) if dataclasses.is_dataclass(data) \
                else {"value": str(data)}
        except Exception:
            payload = {"value": repr(data)}
        record = {"ts": time.time(), "kind": kind, **payload}
        try:
            line = json.dumps(record, sort_keys=True)
        except (TypeError, ValueError):
            return
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                if not self._warned:
                    print(f"[egress-proxy] WARNING: audit write failed ({exc}); "
                          f"continuing without a cage-local audit.", file=sys.stderr)
                    self._warned = True


def _refuse(msg: str, code: int) -> int:
    print(f"[egress-proxy] REFUSING TO START: {msg}", file=sys.stderr)
    return code


def main(argv: list | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    scope_path = argv[0] if argv else _DEFAULT_SCOPE

    # (1) Load the scope through the deterministic, fail-closed loader. A
    # missing file, malformed JSON/policy, or a domain scope without tls_verify
    # all raise here — refuse rather than run on a scope we cannot trust.
    try:
        scope = load_scope(scope_path)
    except FileNotFoundError:
        return _refuse(f"scope file {scope_path!r} not found (fail-closed)", 3)
    except Exception as exc:                            # ValueError, JSON errors, …
        return _refuse(f"scope {scope_path!r} unparseable/invalid: {exc} (fail-closed)", 3)

    # (2) An unauthorized scope must not be given a working egress path — the
    # same gate the host enforces at engagement.run, applied here in the cage.
    if not scope.is_authorized():
        return _refuse(
            f"scope {scope_path!r} is not authorized (no authorization statement)", 4)
    if scope.is_expired():
        return _refuse(f"scope {scope_path!r} is expired", 4)

    audit = JsonlAudit(_DEFAULT_AUDIT)
    print(f"[egress-proxy] scope {scope_path!r} loaded (engagement="
          f"{scope.engagement!r}, fingerprint={scope.fingerprint()}); "
          f"binding 127.0.0.1:{_DEFAULT_PORT}", file=sys.stderr)
    # (3) Serve forever on loopback only — the cage's HTTP(S)_PROXY points here.
    egress_proxy.run_proxy(scope, _DEFAULT_PORT, audit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
