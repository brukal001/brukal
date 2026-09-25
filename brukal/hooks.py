"""
hooks.py — a deterministic event bus around the loop (roadmap §1.1).

Claude Code's lesson is that most of the useful engineering lives in the systems AROUND
the agent loop, reached through named lifecycle events where deterministic code can watch
what the loop does and, at the right boundaries, stop it. This is Brukal's version: a tiny
registry of callables keyed by event name, so a reflex, an external integration, or a
site-specific rule ("never touch /createdb on this engagement") is a registered unit rather
than another branch welded into loop.py.

THE SAFETY CONTRACT — why a hook cannot weaken the five invariants:

  * A hook is handed STRINGS and read-only payloads. It is NEVER handed the `kali` object
    or the executor, so it has no way to run anything (invariant 4: one execution path).
  * A hook can only SUBTRACT. `veto()` lets a `pre_action` hook return a reason to SKIP an
    action; there is no "allow" — a hook can never turn a gate DENY into a run, never widen
    scope, never authorise what the deterministic gate refused (invariants 1, 2, 5). The
    gate still runs on every non-vetoed action and remains the sole authority.
  * A hook that raises is swallowed. For an observational event that just drops the
    notification; for a veto it means "this hook did not veto" — which is safe, because the
    gate is still the authority and a failed hook can only fail to ADD a restriction, never
    remove one. A broken hook can slow nothing and open nothing.

Standard library only; no I/O of its own.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable


class HookBus:
    """A registry of callables keyed by event name. Observational events fire through
    `emit`; the one veto-capable event (`pre_action`) fires through `veto`."""

    def __init__(self) -> None:
        self._hooks: dict[str, list[Callable]] = defaultdict(list)

    def on(self, event: str, fn: Callable) -> "HookBus":
        """Register `fn` for `event`. Returns self so registrations can chain."""
        if callable(fn):
            self._hooks[event].append(fn)
        return self

    def emit(self, event: str, **ctx) -> None:
        """Fire every hook registered for an OBSERVATIONAL event. Return values are
        ignored; an exception in one hook never derails the loop or the other hooks."""
        for fn in self._hooks.get(event, ()):
            try:
                fn(**ctx)
            except Exception:
                pass                          # a watcher must not be able to end a run

    def veto(self, event: str, **ctx) -> str | None:
        """Fire the veto hooks for `event`; return the FIRST non-empty reason string (the
        action must be SKIPPED), or None (proceed to the gate as normal). A hook can only
        answer 'skip, because ...' or stay silent — never 'allow' — so it can only ADD a
        restriction on top of the gate, never remove one. A raising hook is treated as
        silent (no veto), because the gate remains the authority and a failed hook must
        never be able to open a path."""
        for fn in self._hooks.get(event, ()):
            try:
                reason = fn(**ctx)
            except Exception:
                continue                      # a failed veto hook cannot OPEN anything
            if reason:
                return str(reason)
        return None

    def registered(self, event: str) -> int:
        """How many hooks are registered for an event (for tests / introspection)."""
        return len(self._hooks.get(event, ()))
