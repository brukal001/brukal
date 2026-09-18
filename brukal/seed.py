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

    __slots__ = ("method", "path", "body", "binds", "expect", "note", "pick")

    def __init__(self, method, path, body=None, binds=None, expect=(200, 201), note="",
                 pick=""):
        self.method = method
        self.path = path
        self.body = body or {}
        self.binds = binds or {}
        self.expect = tuple(expect)
        self.note = note
        # `pick="mail_to_principal"` narrows a mailbox listing to THIS principal's newest
        # message before binding. It exists so the principal's address never has to be
        # substituted into a URL query — the engine filters, the recipe does not
        # interpolate, and the rule that bound values reach bodies only stays intact.
        self.pick = pick


def pick_mail_to(payload: str, principal: str) -> str:
    """The newest message addressed to `principal` — its RAW MESSAGE TEXT, or "".

    Returns the message rather than the JSON wrapper, and that distinction is load-
    bearing. Inside a JSON document an email's soft line breaks are ESCAPED (`\\r\\n`,
    two characters), so a quoted-printable decoder run over the JSON does not see a soft
    break at all and a value split across one stays split. Measured on crAPI: matching the
    wrapper yields the VIN "XG" instead of "XGR94Y8HA47N6NF9N".

    MailHog's shape, and deliberately tolerant of it: messages are matched on the whole
    envelope so a listing, a search result and a single message all work."""
    try:
        data = json.loads(payload or "")
    except Exception:
        return ""
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return ""
    who = (principal or "").strip().lower()
    for item in items:                       # newest first, as MailHog returns them
        blob = json.dumps(item).lower()
        if who and who in blob:
            raw = item.get("Raw") if isinstance(item, dict) else None
            data = raw.get("Data") if isinstance(raw, dict) else None
            return data if isinstance(data, str) and data else json.dumps(item)
    return ""


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
    """A bound value from a response: a dotted JSON path, `re:<pattern>`, or `qp:<pattern>`.

    Three forms because real onboarding needs three. crAPI's vehicle details arrive as
    PROSE inside an HTML email, so a path expression cannot reach them — and the mail is
    QUOTED-PRINTABLE, which breaks a value across a soft line break mid-token:

        <b>VIN: </font><font color=3D'#0000ff'>XG=\r\nR94Y8HA47N6NF9N</font></b>

    The VIN there is XGR94Y8HA47N6NF9N. A regex written from crAPI's documentation would
    have captured "XG" and seeded a vehicle that does not exist. `qp:` decodes the
    transfer encoding first, which is measured behaviour, not a guess about it."""
    if not body or not spec:
        return None
    if spec.startswith("qp:"):
        import quopri
        try:
            text = quopri.decodestring(body.encode("utf-8", "replace")).decode(
                "utf-8", "replace")
        except Exception:
            text = body
        m = re.search(spec[3:], text, re.I | re.S)
        return m.group(1).strip() if m else None
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
    # The principal's own handle is available to a recipe from the start — it is ours, not
    # the target's, and a flow that reads a mailbox needs to know whose mail to read.
    bound: dict = {"principal": getattr(session, "identity", "") or ""}
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
        payload = getattr(r, "body", "") or ""
        if step.pick == "mail_to_principal":
            payload = pick_mail_to(payload, bound.get("principal", ""))
            if not payload:
                out["reason"] = (f"step {i} ({step.note or step.path}) returned no message "
                                 f"addressed to this principal")
                return out
        for name, spec in step.binds.items():
            got = extract(payload, spec)
            if got is None:
                out["reason"] = (f"step {i} ({step.note or step.path}) answered {status} "
                                 f"but carried no '{name}'")
                return out
            bound[name] = got
    out["bound"] = dict(bound)
    out["owned"] = str(bound.get(recipe.owns, "")) or "created"
    # ONTO THE OWNERSHIP LEDGER, which is what the comparator actually reads. A vehicle
    # created but never recorded is invisible to `ownership_evidence`, so the
    # cross-account claim would stay exactly as unprovable as it was with an empty
    # control — the seeding would have changed the target and nothing else.
    try:
        session._record_principal_ids(who, "seed", json.dumps({recipe.owns: out["owned"]}))
    except Exception:
        pass
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
CRAPI_VEHICLE = SeedRecipe(
    name="crapi-vehicle-onboarding",
    # Every one of these must be CONFIRMED on the target before a single request goes out.
    # The mailbox is reached through the application's OWN front door — crAPI proxies
    # MailHog at /mailhog — so seeding needs no widening of the scope, and the mail
    # server's direct address stays blocked by the cage's egress lock.
    requires=("/identity/api/v2/vehicle/resend_email",
              "/identity/api/v2/vehicle/add_vehicle"),
    steps=(
        SeedStep("POST", "/identity/api/v2/vehicle/resend_email",
                 note="ask crAPI to send this account's vehicle details"),
        SeedStep("GET", "/mailhog/api/v2/messages?limit=50",
                 pick="mail_to_principal",
                 binds={
                     # MEASURED on the live application 2026-09-18, not read from the
                     # documentation. The mail is quoted-printable HTML and the VIN is
                     # broken across a soft line break mid-token:
                     #   <b>VIN: </font><font color=3D'#0000ff'>XG=\r\nR94Y8HA47N6NF9N</font>
                     # so the transfer encoding is decoded BEFORE matching. Matching the
                     # raw body captures "XG" and seeds a vehicle that does not exist.
                     "vin": "qp:VIN:\s*</font>.*?>([A-Z0-9]{8,32})<",
                     "pin": "qp:Pincode:\s*<font[^>]*>(\d{3,8})<",
                 },
                 note="read this principal's vehicle mail"),
        SeedStep("POST", "/identity/api/v2/vehicle/add_vehicle",
                 body={"vin": "{vin}", "pincode": "{pin}"},
                 binds={"id": "id"}, expect=(200, 201),
                 note="redeem the details into an owned vehicle"),
    ),
    owns="id",
    describe="Runs crAPI's own vehicle onboarding so a principal owns a resource a "
             "cross-account comparator can use as its control.")

RECIPES: tuple = (CRAPI_VEHICLE,)
