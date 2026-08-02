"""
chains.py — turn a findings LIST into an assessment.

A competing white-box tool scored one finding more than Brukal on the same target and
read as far more serious, because it did not stop at enumerating flaws. It said what
they added up to: *"numerous independent, fully unauthenticated paths to complete admin
account takeover and database destruction."* Brukal had found the same JWT forgery, the
same mass assignment, the same credential leak — and never once said that any of them
alone hands you the whole application.

That gap is a reporting-layer problem, not a detection one, and this module is the fix.

Two rules make it safe to do deterministically:

  * **It composes, it never infers.** Every node in a chain is a finding that already
    carries a deterministic proof. Nothing here can create a finding, raise a severity,
    or claim an exploit that was not executed — so the load-bearing distinction between
    confirmed and lead survives intact.
  * **No model is involved.** Chain-building is table lookup and a walk over a tiny
    graph, for the same reason the gate has no LLM in it: a conclusion that a hostile
    target could talk its way into is not a conclusion.

The model is deliberately small. Each finding is read as a capability transition — what
an attacker must already hold to use it, and what holding it then grants:

    requires:  nothing | account | admin
    grants:    credentials | account | admin | read_any | destroy

A chain is any path from `nothing` to a terminal capability. The interesting number for
a reader is not how many chains exist but how many INDEPENDENT ones do: five separate
unauthenticated routes to admin is a different sentence from one route with five steps.
"""
from __future__ import annotations

import re

# Capability lattice. `nothing` is an anonymous stranger; holding `admin` subsumes
# `account`. Kept tiny on purpose — a richer model would need judgement, and judgement
# is what this module is designed not to exercise.
_HOLDS = {"nothing": 0, "account": 1, "admin": 2}

TERMINAL = ("admin", "destroy", "read_any")

# (pattern, requires, grants, one-line role). Matched against a finding's title, which
# Brukal controls — these are its own detector titles, not target-supplied text.
_TRANSITIONS = (
    (r"exposure of credentials|plaintext password",
     "nothing", "credentials", "hands a stranger working credentials"),
    (r"sql injection",
     "nothing", "credentials", "dumps the credential store to a stranger"),
    (r"interactive debug console",
     "nothing", "admin", "exposes a remote console and the signing secret"),
    (r"guessable secret|weak.*(jwt|secret|key)",
     "nothing", "credentials", "lets any token be minted offline"),
    (r"forged jwt|authentication bypass",
     "nothing", "admin", "mints an administrator session without logging in"),
    (r"mass assignment",
     "nothing", "admin", "self-registers an account that is already privileged"),
    (r"function-level authorization|account takeover",
     "account", "admin", "takes over another account from an ordinary one"),
    (r"object-level authorization|bola|idor",
     "account", "read_any", "reads other principals' objects"),
    (r"exposure of personal data",
     "nothing", "read_any", "discloses other principals' records to a stranger"),
    (r"state-destroying endpoint",
     "nothing", "destroy", "destroys application state without authenticating"),
    (r"session not revoked",
     "account", "account", "keeps a stolen session alive after the password changes"),
    (r"no rate limiting",
     "nothing", "account", "allows credentials to be brute-forced"),
    (r"username enumeration",
     "nothing", "nothing", "narrows a brute-force to real accounts"),
)

_COMPILED = tuple((re.compile(p, re.I), req, grants, role)
                  for p, req, grants, role in _TRANSITIONS)


def classify(finding):
    """(requires, grants, role) for a finding, or None if it is not a step in a chain.

    A missing security header is a real finding and not a rung on a ladder; returning
    None for it keeps the narrative honest rather than padded."""
    title = getattr(finding, "title", "") or ""
    for rx, requires, grants, role in _COMPILED:
        if rx.search(title):
            return requires, grants, role
    return None


def _reachable(held: str, requires: str) -> bool:
    return _HOLDS.get(held, 0) >= _HOLDS.get(requires, 0)


def compose(findings, max_chains: int = 12):
    """Independent attack chains over CONFIRMED findings, shortest first.

    Only confirmed findings participate. A chain built partly from a lead would read as
    proven when it is not, which is precisely the blur the whole report exists to avoid.
    """
    steps = []
    for f in findings:
        if not getattr(f, "confirmed", False):
            continue
        c = classify(f)
        if c is not None:
            steps.append((f, *c))

    chains: list[list] = []
    seen_terminals: dict[str, int] = {}

    # Single-step chains first: a flaw that takes a stranger straight to a terminal
    # capability is the strongest thing a report can say, and burying it inside a longer
    # path would understate it.
    for f, requires, grants, _role in steps:
        if requires == "nothing" and grants in TERMINAL:
            chains.append([(f, grants)])

    # Then two-step: something a stranger can use, whose grant unlocks a second step.
    for f1, req1, grant1, _r1 in steps:
        if req1 != "nothing" or grant1 in TERMINAL:
            continue
        held = "account" if grant1 in ("account", "credentials") else grant1
        for f2, req2, grant2, _r2 in steps:
            if f2 is f1 or grant2 not in TERMINAL:
                continue
            # The second step must actually NEED what the first grants. Without this,
            # any unauthenticated foothold pairs with any unauthenticated terminal and
            # the report fills with sentences like "credential exposure enables JWT
            # forgery" — two independent findings concatenated and presented as a path.
            # A terminal that already requires nothing is a one-step chain and is
            # reported as one; extending it adds a premise the attacker never needed.
            if req2 == "nothing":
                continue
            if _reachable(held, req2):
                chains.append([(f1, grant1), (f2, grant2)])

    # Independence is what the reader cares about: N separate ways in, not N variations
    # on one. Keep the shortest chain per (entry finding, terminal) pair.
    unique, keys = [], set()
    for chain in sorted(chains, key=len):
        key = (id(chain[0][0]), chain[-1][1])
        if key in keys:
            continue
        keys.add(key)
        unique.append(chain)
        seen_terminals[chain[-1][1]] = seen_terminals.get(chain[-1][1], 0) + 1
        if len(unique) >= max_chains:
            break
    return unique


_OUTCOME = {
    "admin": "complete administrator takeover",
    "destroy": "destruction of application state",
    "read_any": "disclosure of every principal's data",
}


def summarise(chains) -> str:
    """The paragraph a reader wants before the finding list: what these add up to."""
    if not chains:
        return ""
    unauth = [c for c in chains if classify(c[0][0])[0] == "nothing"]
    outcomes = sorted({_OUTCOME.get(c[-1][1], c[-1][1]) for c in chains})
    lead = (f"{len(chains)} independent attack chain(s) were composed from the confirmed "
            f"findings")
    if unauth:
        lead += (f", of which {len(unauth)} require no credentials at all")
    return f"{lead}. Together they reach {', and '.join(outcomes)}."


def render(chains) -> str:
    """Markdown for the report. Every step names the finding that proves it."""
    if not chains:
        return ""
    out = ["## Attack chains", "",
           "Composed deterministically from CONFIRMED findings only — each step below "
           "carries its own proof, and nothing here is inferred.", "",
           summarise(chains), ""]
    for i, chain in enumerate(chains, 1):
        terminal = _OUTCOME.get(chain[-1][1], chain[-1][1])
        entry = "unauthenticated" if classify(chain[0][0])[0] == "nothing" \
            else "any authenticated user"
        out.append(f"**Chain {i} — {entry} → {terminal}**")
        for step, _grant in chain:
            role = classify(step)[2]
            out.append(f"  1. *{step.title}* — {role}")
        out.append("")
    return "\n".join(out)
