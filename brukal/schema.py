"""
schema.py — the Action Request: the structured "note" an agent slides under the
door. This is the ONLY shape an agent may use to propose touching the target.

Why structured (not free chat text)? Because you can only check, gate, log, and
count something that has named fields. This is also the boundary where a
malformed proposal dies BEFORE it ever reaches the gate — fail-closed at the
door as well as at the guard.

Requires pydantic (install with:  pip install "brukal[agents]").
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from pydantic import BaseModel, ValidationError

# Allowed intents. Anything outside this set is rejected — an agent cannot
# invent a new kind of action.
_INTENTS = {"enumerate", "exploit", "verify", "cleanup"}


class ActionRequest(BaseModel):
    """Exactly what an agent must emit to propose an action."""
    proposing_agent: str
    intent: str
    command: str
    target_host: str
    target_port: Optional[int] = None
    justification: str = ""

    def is_intent_valid(self) -> bool:
        return self.intent in _INTENTS


# Tools that resolve names by default, and the flag that stops them. Under the cage's
# egress lock a resolver is unreachable BY CONSTRUCTION — the lock permits tun0, the
# pinned VPN server and the scope IP, nothing else — so the lookup cannot succeed, only
# hang until Executor.run kills the command at its 180s cap. The result (`exit 124`,
# "Starting Nmap ..." and nothing else) is indistinguishable from an unreachable host,
# so an agent reads the silence as "nothing there" and moves on.
#
# This is an EXPLICIT allowlist of tool -> flag, never a guess at what flag a tool might
# have. masscan is deliberately absent: it takes addresses and does not resolve, and its
# failures in the same runs had a different cause.
_NO_RESOLVE_FLAGS = {"nmap": "-n"}


def _egress_locked() -> bool:
    """The lock is on unless explicitly disabled, matching docker/entrypoint.sh's
    default. Fail-closed: an unset or unreadable value means locked."""
    return (os.environ.get("BRUKAL_EGRESS_LOCK") or "1").strip() != "0"


def apply_no_resolve(command: str) -> str:
    """Add the no-resolve flag to a proposed command that needs one, idempotently.

    Deterministic command normalisation with no model in the path. The model has been
    told to pass `-n` and forgot on three separate engagements; on 10.129.101.3 that
    cost every one of 14 commands and the run never reached the application. A
    correctness property a model must remember is not a property.

    This shapes how a command is CONSTRUCTED. It is not a gate and not an execution
    path: the gate still re-reads the command it is given, and nothing here can widen
    scope, authorise a tool, or turn a DENY into an ALLOW.
    """
    if not command or not command.strip():
        return command
    if not _egress_locked():
        # A reachable resolver makes resolution a legitimate choice; do not override it.
        return command
    prog = re.match(r"\s*(\S+)", command)
    if not prog:
        return command
    flag = _NO_RESOLVE_FLAGS.get(prog.group(1).rsplit("/", 1)[-1])
    if flag is None:
        return command
    if flag in command.split()[1:]:                      # already asked for; idempotent
        return command
    # Insert straight after the program so the rest of the command is untouched — no
    # re-quoting, no whitespace collapsing.
    return f"{command[:prog.end()]} {flag}{command[prog.end():]}"


def parse_action_request(text: str) -> Optional[ActionRequest]:
    """Turn raw model text into a validated ActionRequest, or None.

    Defensive by design: models sometimes wrap JSON in prose or code fences.
    We extract the first JSON object, validate it against the schema, and
    return None on ANY problem. None means "no valid proposal" — the caller
    treats it as a no-op and never guesses what the model meant.
    """
    if not text:
        return None

    # Strip common code-fence wrappers.
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()

    # Grab the first {...} block if there is surrounding prose.
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return None

    try:
        data = json.loads(match.group(0))
        if isinstance(data, dict) and isinstance(data.get("command"), str):
            data["command"] = apply_no_resolve(data["command"])
        req = ActionRequest(**data)
    except (json.JSONDecodeError, ValidationError, TypeError):
        return None

    if not req.is_intent_valid():
        return None
    return req
