"""
seed.py — give a principal something to own, so a cross-account question can be asked.

THE MEASURED PROBLEM (CR1 runs 1-4, crAPI)
    Six of the twelve missed challenges fail for one reason, and it is not intelligence:

        GET /identity/api/v2/vehicle/vehicles?id=1  ->  []

    A fresh crAPI account owns no vehicle, no video, no order. Every cross-account
    comparator needs OUR resource and THEIRS; with nothing on our side the control is
    empty and the experiment cannot hold, however well the model proposes it.

WHY THIS IS A RECIPE ENGINE AND NOT A crAPI FUNCTION
    Onboarding is target-specific by nature — it is "run this application's own signup
    flow to its end". The mistake this project keeps making is encoding one application's
    shape as the harness's behaviour, so the SHAPE lives here as data and the MECHANISM
    is general:

      * a recipe activates only when routes it names are CONFIRMED to exist on the target
        (see webmap route confirmation) — never on a guess about what an app might expose;
      * every step goes through the governed browser, so it is gated, rate-limited and
        audited exactly like any other request;
      * what the principal ends up owning is recorded on the ownership ledger, which is
        what the comparator reads.

    Adding a target means adding a recipe, and `tests/test_portability_profiles.py` is
    where that claim gets checked.

FAIL-CLOSED
    Seeding CREATES state on a live target. It runs only when the operator authorised
    state-changing work for the engagement (`scope.destructive_allowed`), only against
    routes the target confirmed, and a step that does not answer as its recipe expects
    stops the sequence and records why — a half-seeded principal is worse than an
    unseeded one, because the comparator would reason about a resource that may not exist.
"""
from __future__ import annotations

import json
import re


class SeedStep:
    """One request in a recipe, and what to take from its answer.

    `binds` maps a name to a JSON path (dotted) or a regex with one group, applied to the
    response body. Later steps reference a bound value as {name}. Nothing here executes
    anything the target said — a bound value is substituted into a field of a request the
    RECIPE defined, never into a URL path or a header name.
    """

    __slots__ = ("method", "path", "body", "binds", "expect", "note")

    def __init__(self, method, path, body=None, binds=None, expect=(200, 201), note=""):
        self.method = method
        self.path = path
        self.body = body or {}
        self.binds = binds or {}
        self.expect = tuple(expect)
        self.note = note


class SeedRecipe:
    """An application's own onboarding, as data."""

    __slots__ = ("name", "requires", "steps", "owns", "describe")

    def __init__(self, name, requires, steps, owns, describe=""):
        self.name = name
        self.requires = tuple(requires)     # paths that must be CONFIRMED on the target
        self.steps = tuple(steps)
        self.owns = owns                    # the resource kind this recipe produces
        self.describe = describe


def _dotted(obj, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def extract(body: str, spec: str):
    """A bound value from a response: a dotted JSON path, or `re:<pattern>` with one group.

    Both forms are needed by real onboarding flows: crAPI's vehicle details arrive as
    PROSE in an email body, not as JSON fields, so a path expression alone cannot reach
    them."""
    if not body or not spec:
        return None
    if spec.startswith("re:"):
        m = re.search(spec[3:], body, re.I | re.S)
        return m.group(1).strip() if m else None
    try:
        return _dotted(json.loads(body), spec)
    except Exception:
        return None


def recipe_for(confirmed_routes, recipes=None):
    """The first recipe whose required routes are all CONFIRMED on this target, or None.

    Confirmed, not mined: a recipe that fires on a path nobody proved exists would spend
    state-changing requests on a guess."""
    have = set(confirmed_routes or ())
    for r in (recipes if recipes is not None else RECIPES):
        if all(any(req in route for route in have) for req in r.requires):
            return r
    return None


def _substitute(value, bound: dict):
    """Bound values go into request BODY FIELDS only — never into a path, a header name,
    or a method. A value the target supplied must not be able to redirect where the next
    request goes, which is what substituting into a URL would allow."""
    if isinstance(value, str):
        for name, got in bound.items():
            value = value.replace("{" + name + "}", str(got))
        return value
    if isinstance(value, dict):
        return {k: _substitute(v, bound) for k, v in value.items()}
    return value


def run_seed(session, who: str = "self", recipe=None) -> dict:
    """Run an onboarding recipe for one principal, through the gate.

    Returns {"recipe", "owned", "bound", "reason"} — `owned` is the resource identifier
    the principal now holds, or "" with `reason` saying why not.

    Requires `allow_intrusive` (--full-send): every step CREATES state, which is exactly
    what an experiment's setup steps already do under that flag. Destruction is not part
    of any recipe and stays governed by the destructive path rules.
    """
    from .web import WebAction
    out = {"recipe": "", "owned": "", "bound": {}, "reason": ""}
    browser = getattr(session, "browser", None)
    if browser is None:
        out["reason"] = "no governed browser"
        return out
    if not getattr(session, "allow_intrusive", False):
        out["reason"] = "seeding creates state and needs --full-send"
        return out
    surface = getattr(session, "surface", None)
    confirmed = list(getattr(surface, "confirmed_routes", []) or []) if surface else []
    recipe = recipe or recipe_for(confirmed)
    if recipe is None:
        out["reason"] = ("no seed recipe matches this target's confirmed routes "
                         f"({len(confirmed)} confirmed)")
        return out
    out["recipe"] = recipe.name
    base = (getattr(surface, "seed", "") or f"http://{session.target}/").rstrip("/")
    bound: dict = {}
    for i, step in enumerate(recipe.steps):
        body = _substitute(step.body, bound)
        action = WebAction("request", method=step.method, url=base + step.path,
                           body=json.dumps(body) if body else "",
                           headers={"Content-Type": "application/json"} if body else {})
        try:
            with session._as_identity(who, "setup", action.url):
                _d, r = browser.run(action)
        except Exception as exc:
            out["reason"] = f"step {i} ({step.note or step.path}) raised: {exc}"
            return out
        status = getattr(r, "status", None)
        if status not in step.expect:
            # STOP. A half-seeded principal is worse than an unseeded one: the comparator
            # would reason about a resource that may not exist.
            out["reason"] = (f"step {i} ({step.note or step.path}) answered {status}, "
                             f"expected {step.expect}")
            return out
        for name, spec in step.binds.items():
            got = extract(getattr(r, "body", "") or "", spec)
            if got is None:
                out["reason"] = (f"step {i} ({step.note or step.path}) answered {status} "
                                 f"but carried no '{name}'")
                return out
            bound[name] = got
    out["bound"] = dict(bound)
    out["owned"] = str(bound.get(recipe.owns, "")) or "created"
    try:
        session.note(f"[seed] {recipe.name}: {who} now owns {recipe.owns}="
                     f"{out['owned']}")
        audit = getattr(getattr(session, "executor", None), "_audit", None)
        if audit is not None:
            audit.append("seed", {"recipe": recipe.name, "principal": who,
                                  "owns": recipe.owns, "value": out["owned"],
                                  "target": session.target})
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------- #
# Recipes. DATA, and each one is added only after the flow was measured live against
# the application — never from its documentation.
# --------------------------------------------------------------------------- #
RECIPES: tuple = ()
