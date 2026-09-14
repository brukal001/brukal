"""
hypothesis.py — let the model propose the experiment; let the code decide the result.

Brukal's coverage has always grown linearly with engineering effort: it finds what
someone wrote a detector for, and nothing else. Measured against agent-driven tools this
is its sharpest deficiency — 15 findings on the target its detectors were fitted to, and
2 on an unfamiliar one; every gap a competitor exposed had to be hand-built afterwards,
one detector at a time. An LLM agent generalises to flaw classes nobody enumerated. That
is the capability being closed here, and the whole difficulty is closing it without
giving the model the one thing it must never have: the power to declare something true.

The split:

    the model chooses WHAT to compare      — creative, unbounded, untrusted
    a fixed comparator decides IF it holds — deterministic, enumerated, trusted

A hypothesis is two gated requests and the NAME of a comparison. It is emphatically not
a predicate expression: model-supplied logic would have to be evaluated to be useful,
and `eval` over target-influenced text is the same class of mistake as putting an LLM
inside the gate. The comparator is selected from a closed set below; anything else is
refused, so the worst a hostile or confused proposal can do is waste two requests.

This preserves every invariant. Requests go through the same governed browser and the
same scope gate. The model still emits only text. `confirmed` is set by the comparator,
never by the proposal — a hypothesis the evidence does not support is discarded silently
rather than downgraded to a lead, because an unproven guess from a model is not a lead,
it is noise.
"""
from __future__ import annotations

import json
import re

# The closed set of ways two responses may be compared. Each is a pure function of two
# observed results — no model text is executed, and adding one is a deliberate act by a
# maintainer rather than something a proposal can do at runtime.
#
# Each entry: name -> (predicate, what a hit MEANS in evidence).
_COMPARATORS = {
    "status_differs": (
        lambda a, b: a.status != b.status and a.status and b.status,
        "the two requests were answered with different status codes"),
    "a_denied_b_allowed": (
        lambda a, b, p=None: (_denied(a, p) and b.status == 200
                              and _substantive(b, p)),
        "the control was refused and the variant was accepted"),
    "b_reveals_more": (
        lambda a, b: (b.status == 200 and a.status == 200
                      and len(b.body or "") > len(a.body or "") * 2
                      and len(b.body or "") > 200),
        "the variant returned substantially more data than the control"),
    # NOTE: judged against the REQUESTS as well as the responses — see judge().
    "bodies_differ": (
        lambda a, b: (a.status == b.status and a.status
                      and _norm(a.body) != _norm(b.body)),
        "identical requests but for one changed value produced different bodies"),
    "b_errors_a_does_not": (
        lambda a, b: (a.status == 200 and b.status is not None and b.status >= 500),
        "the variant drove the application into a server error the control did not"),
    # THE CANONICAL BOLA SHAPE, and the only comparator that reads the LEDGER rather than
    # only the two responses. See `_cross_account_resource`.
    "cross_account_resource": (
        lambda a, b, p=None, ctx=None: _cross_account_resource(a, b, ctx),
        "the variant reached a resource the ledger records as owned by a different "
        "registered principal"),
}

# Comparators that need the recorded ownership map, not just the two responses. An
# EXPLICIT set rather than exception-based arity sniffing: `judge` used to pick a
# signature by catching TypeError, which cannot tell "this predicate takes two arguments"
# from "this predicate raised TypeError on line 3", and a comparator that silently
# degraded to a two-argument call would be judging on less than it was given.
_CONTEXT_COMPARATORS = ("cross_account_resource",)

# Which principals are ACCOUNTS. `anonymous` is the absence of one, so it can never be the
# recorded owner of anything — the restated milestone (2026-09-14) turns on exactly this
# distinction, because CM3 passed the old wording with an anonymous control.
_REGISTERED_PRINCIPALS = ("self", "second")


def _succeeded(r) -> bool:
    """A 2xx. The BOLA shape is BOTH SIDES ALLOWED, so 'allowed' has to mean something."""
    s = getattr(r, "status", None)
    return isinstance(s, int) and 200 <= s < 300


def foreign_owned_ids(body, ownership, variant_as: str) -> list:
    """[(path, value, owner)] — identifiers in `body` that a DIFFERENT registered
    principal owns, according to the ownership map the ledger records.

    Deterministic and FAIL CLOSED in every direction: no map, no ids, an id the map does
    not cover, or an owner that is not a registered account all yield []. Nothing is
    inferred about ownership that was not recorded, which is the whole point — the
    defect this closes (`1940f09`) was a cross-account title asserted over object ids
    nothing in the record tied to any owner.

    Matching is by VALUE, not by field name, and that is deliberate. CM3's basket body
    calls it `data.id = 8` while the ownership record learned it from a login reply that
    called it `bid = 8`; requiring the names to agree would have missed the one case this
    exists for. The cost is that two resources of different types sharing an integer could
    collide — which is why the matched id, its path, and the captured body are all on the
    ledger beside the claim, so a reader can see the match rather than trust it."""
    found = own_identifiers(body)
    if not found:
        return []
    index: dict = {}
    for who, vals in (ownership or {}).items():
        if who not in _REGISTERED_PRINCIPALS:
            continue
        for _key, value in (vals or {}).items():
            index.setdefault(str(value), who)
    out = []
    for path, value in found.items():
        owner = index.get(str(value))
        if owner and owner != variant_as:
            out.append((path, value, owner))
    return out


def addressed_identifiers(spec) -> set:
    """The values a request ADDRESSED: URL path segments, query values, request-body ids.

    "Addressed" is the whole of the tightening. Ownership is matched by VALUE (see
    `foreign_owned_ids`), and on a target whose id spaces overlap — Juice Shop's baskets,
    users and products are all small integers — an unrelated integer in a response body
    will eventually equal some other principal's owned id. Matching the body alone
    therefore confirms a cross-account read that never happened, at HIGH severity, which
    is the `1940f09` defect arrived at from the other direction.

    What a request ADDRESSED is not a coincidence: it is what the experiment chose to
    reach for. `/rest/basket/8` addresses 8; a body of `{"BasketId": 8}` addresses 8; a
    product listed inside the response addresses nothing."""
    spec = spec or {}
    out: set = set()
    url = str(spec.get("url") or "")
    # Path and query only — never the netloc, or a port would be an "addressed id".
    tail = url.split("://", 1)[-1]
    path = tail.split("/", 1)[1] if "/" in tail else ""
    for seg in re.split(r"[/?&=#]", path):
        seg = seg.strip()
        if seg:
            out.add(seg)
    body = spec.get("body")
    if body:
        for _p, value in own_identifiers(body).items():
            out.add(str(value))
    return out


def ownership_evidence(spec, body, ownership, variant_as: str) -> dict:
    """What the record can SHOW about a cross-account claim, rather than assert.

    Returns the matched identifier, its path in the response body, whether it was the
    ADDRESSED resource, and the recorded owner — so the ledger carries the match itself
    and a reader can check it instead of trusting it.

    `owner` is set ONLY when the addressed identifier is the one a different registered
    principal owns. A body-only match is reported as corroboration and never as the
    claim: it is exactly the coincidence this function exists to refuse."""
    addressed = addressed_identifiers(spec)
    corroborating = foreign_owned_ids(body, ownership, variant_as)
    index: dict = {}
    for who, vals in (ownership or {}).items():
        if who not in _REGISTERED_PRINCIPALS:
            continue
        for _key, value in (vals or {}).items():
            index.setdefault(str(value), who)
    owner, value = "", ""
    for candidate in sorted(addressed):
        who = index.get(candidate)
        if who and who != variant_as:
            owner, value = who, candidate
            break
    # The body path for the SAME value, when the response corroborates the addressed id.
    path = ""
    for p, v, _own in corroborating:
        if str(v) == str(value):
            path = p
            break
    return {"owner": owner, "value": value, "addressed": bool(owner), "path": path,
            "corroborating": [(p, v, o) for p, v, o in corroborating]}


def _cross_account_resource(a, b, ctx=None) -> bool:
    """Both sides allowed, and the VARIANT read or wrote somebody else's resource.

    Run CM3 issued `GET /api/Users/27` as the second principal and as self and got
    200/329B on both sides. `a_denied_b_allowed` needs a refusal and `b_reveals_more`
    needs a 2x size difference, so the experiment was correctly not confirmed — and
    principal A had just read principal B's resource. **The canonical BOLA shape is both
    sides allowed**, and until this existed nothing in the closed set could ask whether an
    allowed read was allowed WRONGLY. The milestone was literally unaskable.

    The decision is made from recorded facts — the ownership map (`principal_ownership`),
    the request the experiment issued, and the captured body (`experiment_result`) — and
    no model text is consulted anywhere in it.

    THREE conditions, and each one refuses a specific false positive:

    1. **Both sides succeeded.** The BOLA shape is both-allowed, so "allowed" must mean
       something.
    2. **The ADDRESSED identifier is the foreign one.** Not merely an identifier somewhere
       in the response: on a target whose id spaces overlap, a product id equal to another
       principal's basket id would otherwise confirm a read that never happened. The body
       CORROBORATES; it does not carry the claim alone.
    3. **The variant response is substantive.** A 200 with an empty body does not
       demonstrate that a resource was READ, and the milestone asks for a read or a write
       of a resource, not for an accepted request. This FAILS CLOSED, and the cost is
       stated rather than hidden: a blind write that returns nothing will be missed."""
    ctx = ctx or {}
    if not (_succeeded(a) and _succeeded(b)):
        return False
    if not _substantive(b, ctx.get("profile")):
        return False
    ev = ownership_evidence(ctx.get("variant_spec"), getattr(b, "body", ""),
                            ctx.get("ownership"), ctx.get("variant_as", ""))
    return bool(ev["owner"])

# WHO a request is issued as. A closed set, for exactly the reason the comparators are
# one: the model names a principal, deterministic code decides what that means. Without
# this the model held a single session, so `a_denied_b_allowed` — the comparator built
# for authorization — was unconstructible, and the whole authorization space was closed
# to model-proposed experiments and reachable only by hand-written detectors.
_IDENTITIES = ("self", "second", "anonymous")


# What each comparator can establish ON ITS OWN, and the severity ceiling that follows.
# A closed table beside the comparators themselves, because the two must never drift: a
# comparator that gains a meaning has to gain a bound in the same edit.
#
# WHY THIS EXISTS. On 2026-08-22 `bodies_differ` confirmed twice and both findings were
# published as HIGH cross-account reads — from a single principal, against object ids
# nothing in the record tied to any owner. The verdicts were sound; the titles were not.
# `title` and `severity` came straight off the model's proposal and reached the record
# unexamined, so a true measurement went out under a sentence nobody verified.
#
# `authz` marks the ONE class that can speak about authorization, and even then only
# when two DIFFERENT principals were actually recorded — a refusal and an acceptance
# from the same session says nothing about who may reach what.
_EVIDENCE_CLASS = {
    "status_differs": (
        "two requests differing in one value were answered with different status codes",
        "low", False),
    "bodies_differ": (
        "two requests differing in one value returned different response bodies",
        "low", False),
    "b_reveals_more": (
        "one request returned substantially more data than its near-identical control",
        "medium", False),
    "b_errors_a_does_not": (
        "one request drove the application into a server error its control did not",
        "medium", False),
    "a_denied_b_allowed": (
        "one principal was refused and a different principal was accepted for the same "
        "request",
        "high", True),
    # EARNS the cross-account claim, and at full severity, because it is grounded in
    # RECORDED ownership rather than in a model's sentence. That is the exact distinction
    # `1940f09` was written for: the 2026-08-22 findings were published as HIGH
    # cross-account reads off `bodies_differ` with one principal on both sides and no
    # owner recorded anywhere. Here the owner is on the ledger with its provenance, the
    # id is in a captured body, and the match is deterministic.
    "cross_account_resource": (
        "one principal read or wrote a resource the ledger records as owned by a "
        "different registered principal",
        "high", True),
}

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# The readable half of a derived title, per evidence class. Assembled from LEDGER FACTS
# only — endpoints, statuses, body sizes, principals — never from model prose. A generic
# label was the first cut and it was honest but unreadable: every `bodies_differ` finding
# rendered identically, which is its own reporting failure, because a reader cannot triage
# a list of identical rows.
_HEADLINE = {
    "status_differs":      "Different status codes for {c} vs {v}",
    "bodies_differ":       "Different response bodies for {c} vs {v}",
    "b_reveals_more":      "Larger response from {v} than {c}",
    "b_errors_a_does_not": "Server error from {v}, not from {c}",
}


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit
    return (urlsplit(url or "").path or "/") if url else "?"


def derive_claim(comparator: str, control_as: str, variant_as: str,
                 control: dict | None = None, variant: dict | None = None) -> dict:
    """The strongest claim an evidence class supports, derived — never model text.

    `control`/`variant` are plain fact dicts: `{"url":…, "status":…, "size":…}`, all of
    which the ledger already holds. Pure function: same facts in, same sentence out, no
    session, no I/O and no model output anywhere in it — invariant 1 applied to the
    record rather than to the gate, which is the right framing, because this control
    exists precisely because a model authored a claim it had not earned.

    The bound is deliberately not a filter. `a_denied_b_allowed` between two genuinely
    distinct principals keeps the full authorization claim at full severity — that is the
    finding the whole second-principal effort exists to produce, and flattening it would
    trade one blindness for another."""
    control, variant = control or {}, variant or {}
    claim, cap, authz = _EVIDENCE_CLASS.get(
        comparator, ("an experiment comparator reported a difference", "low", False))
    if comparator == "cross_account_resource":
        # This class's distinctness is NOT between the two sides. Both may legitimately be
        # the same principal — the claim is about the variant's principal versus the
        # RECORDED OWNER of what it reached, so that is the pair the bound must test.
        owner = str(variant.get("owner") or "")
        if not (owner and variant_as and owner != variant_as
                and owner in _REGISTERED_PRINCIPALS):
            # FAIL CLOSED. No recorded owner means no ownership claim, whatever the
            # comparator reported: a derived claim may never assert what the record does
            # not carry, which is the entire reason this function exists.
            return {"title": (f"a resource was returned to {variant_as or 'a principal'} "
                              f"at {_path_of(variant.get('url'))}, with no recorded owner"),
                    "claim": "no ownership could be established from the record",
                    "severity_cap": "low", "evidence_class": comparator, "authz": False,
                    "principals": f"{variant_as or 'self'} (no recorded owner)"}
        who = f"{variant_as} vs {owner} (recorded owner)"
        vp = _path_of(variant.get("url"))
        obs = (f"{control.get('status')}/{control.get('size')}B vs "
               f"{variant.get('status')}/{variant.get('size')}B")
        return {"title": (f"{variant_as} reached {vp}, which the ledger records as owned "
                          f"by {owner} — {who}, {obs}"),
                "claim": claim, "severity_cap": cap, "evidence_class": comparator,
                "authz": True, "principals": who}
    distinct = bool(control_as and variant_as and control_as != variant_as)
    if authz and not distinct:
        # The authorization comparator fired, but both sides were the same session, so it
        # cannot be about who may reach what. Say what it does show, and drop the cap.
        claim = "the same principal was refused for one request and accepted for another"
        cap, authz = "medium", False
    who = (f"{control_as} vs {variant_as}" if distinct
           else f"same principal ({control_as or 'self'})")
    cp, vp = _path_of(control.get("url")), _path_of(variant.get("url"))
    if authz:
        head = f"{control_as} refused, {variant_as} accepted at {vp}"
    elif comparator == "a_denied_b_allowed":
        head = f"One request refused, another accepted for {cp} vs {vp}"
    else:
        head = _HEADLINE.get(comparator,
                             "Observed difference [{k}] for {{c}} vs {{v}}".format(
                                 k=comparator)).format(c=cp, v=vp)
    obs = (f"{control.get('status')}/{control.get('size')}B vs "
           f"{variant.get('status')}/{variant.get('size')}B")
    return {"title": f"{head} — {who}, {obs}", "claim": claim, "severity_cap": cap,
            "evidence_class": comparator, "authz": authz, "principals": who}


def cap_severity(model_severity: str, cap: str) -> str:
    """The model's severity, never above what the evidence class allows.

    It may ask for LESS — a model that judges its own finding minor is not overreaching
    and there is no reason to inflate it."""
    ms = (model_severity or "medium").lower()
    if ms not in _SEV_RANK:
        ms = "medium"
    return ms if _SEV_RANK[ms] <= _SEV_RANK.get(cap, 1) else cap

def _substantive(result, profile=None) -> bool:
    """Whether a response carries real content, as THIS application measures it.

    `len(body) > 0` is the usual test and it is wrong on any app that renders a full
    template around an empty result: its "nothing here" page is several kilobytes. Judged
    against the learned MISSING baseline when there is one."""
    if profile is not None:
        verdict = profile.is_substantive(result)
        if verdict is not None:
            return verdict
    return len(getattr(result, "body", "") or "") > 0


_MAX_HYPOTHESES = 6


def _norm(text) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


# Where a server sends someone it has refused. A redirect to the login page is how
# nearly every server-rendered application denies an unauthenticated request; only an
# API answers 401/403.
_LOGIN_LOCATION_RE = re.compile(
    r"/(?:login|log-in|signin|sign-in|auth|authenticate|session|sso|account/login)",
    re.I)


def _denied(result, profile=None) -> bool:
    """Whether a response REFUSED the caller.

    Recognising only 401 and 403 cost a confirmed critical. On DVNA the model proposed
    exactly the right experiment — anonymous versus a non-admin account against
    /app/admin/usersapi — and it executed perfectly: the stranger got 302 to /login, the
    account got 200 with 9,978 bytes of the user table. The comparator said no, because
    302 is not 401. That is textbook broken function-level authorization, thrown away
    for being phrased the way most of the web phrases it.

    A redirect only counts when it points somewhere that looks like authentication: a
    302 to /dashboard after a successful action is not a refusal, and treating every
    redirect as one would confirm a flaw on any endpoint that redirects at all."""
    # The application's OWN answer, when we have learned it. A hardcoded list of status
    # codes is a statement about the apps this tool was written against; a baseline
    # taken from THIS target is a statement about this target. Calibration may only add
    # certainty — an uncalibrated run falls through to the rules below unchanged.
    if profile is not None:
        verdict = profile.is_denied(result)
        if verdict is not None:
            return verdict
    status = getattr(result, "status", None)
    if status in (401, 403):
        return True
    if status in (301, 302, 303, 307, 308):
        headers = getattr(result, "headers", None) or {}
        loc = headers.get("location") or headers.get("Location") or ""
        return bool(_LOGIN_LOCATION_RE.search(loc))
    return False


class UnresolvedReference(ValueError):
    """A `{{setup.i.path}}` reference nothing in the setup responses can satisfy."""


class SetupRequestFailed(UnresolvedReference):
    """A reference could not be satisfied because its SETUP REQUEST failed.

    A subclass on purpose: every caller that aborts on `UnresolvedReference` must go on
    aborting, because the state the experiment is about was never established either way.
    What changes is the sentence the next round is handed. "The reference is unresolvable"
    and "the setup request failed" name two different repairs, and a model shown only the
    first has no reason to fix the request that actually broke — in run CM1 a `POST
    /api/Addresses` answered 500 and the model was told its dotted path was wrong.
    """


class PrincipalNotAuthenticated(ValueError):
    """The principal an experiment named holds a session this target does not honour.

    Sibling of `SecondPrincipalUnavailable`, and for the same reason: the comparator the
    experiment selected is UNCONSTRUCTIBLE, so any verdict it reached would be a claim
    about Brukal wearing the costume of a claim about the application. An `as: self`
    request from a session the target reads as a stranger is not "self" — it is exactly
    `anonymous`, which is the collapse `c829482` closed from our side and this closes
    from the target's.

    Raised by `_as_identity` BEFORE the request is built, so the degraded request cannot
    exist and nothing is attributed to one that never happened.
    """


class SecondPrincipalUnavailable(ValueError):
    """An experiment named `as: second` on a target where no second account exists.

    Sibling of `UnresolvedReference`, for the same reason and with the same contract:
    the experiment is NOT run and NOT judged. `_as_identity` used to resolve a missing
    second principal to empty cookies and an empty auth header — byte-identical to
    `anonymous` — so the request went out as a stranger and the comparator scored it.
    Both directions were wrong: `self` vs `second→anonymous` under `a_denied_b_allowed`
    filed a clean-looking NOT CONFIRMED, and `second→anonymous` vs `self` HELD and filed
    a CONFIRMED finding meaning only that an authenticated request succeeds where an
    anonymous one does not.

    A missing principal is a missing capability, never a quieter principal."""


# The documented way to USE what setup created. `{{setup.<i>.<dotted.path>}}` reads field
# `path` out of the JSON body of setup response `i` (0-based). The path may walk objects
# and arrays: `{{setup.0.data.items.0.id}}`.
_SETUP_REF_RE = re.compile(r"\{\{\s*setup\.(\d+)\.([A-Za-z0-9_][A-Za-z0-9_.\-]*)\s*\}\}")

# Braces are DOUBLED because this is spliced into the two prompt templates below, which
# are `.format()`-ed for the comparator list — so `{{{{` here is the `{{` the model sees.
SETUP_REF_SYNTAX = (
    "To USE something a setup response returned, write {{{{setup.<i>.<field>}}}} in a "
    "later url, body, or header — `i` is the 0-based setup index and `<field>` a dotted "
    "path into that response's JSON body, e.g. {{{{setup.0.BasketId}}}} or "
    "{{{{setup.0.data.items.0.id}}}}. It is substituted by deterministic code before the "
    "request is sent. Reference ONLY a field the response actually carries: an "
    "unresolvable reference aborts the experiment rather than being sent as text.")


def _lookup(body, path: str, ref: str):
    """Walk a dotted path into a setup response body. Deterministic, no eval.

    Refuses rather than guesses at every step: a body that is not JSON, a segment that
    names nothing, and a value that is not inlinable are all UnresolvedReference. The
    alternative — leaving the braces in the request — is the failure this exists to stop,
    because it produces a request that runs, answers, and is judged as a negative."""
    try:
        cur = json.loads(body or "")
    except ValueError:
        raise UnresolvedReference(
            f"{ref}: setup response body is not JSON") from None
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            raise UnresolvedReference(f"{ref}: no field '{seg}' in the setup response")
    if isinstance(cur, bool):
        return "true" if cur else "false"
    if isinstance(cur, (str, int, float)):
        return str(cur)
    # An object, an array, or null. Inlining one into a URL would produce a request the
    # model did not describe, so it is refused like any other unsatisfiable reference.
    raise UnresolvedReference(f"{ref}: resolves to {type(cur).__name__}, not a value")


def _resolve_text(value: str, setup_results: list) -> str:
    def sub(m):
        idx, path = int(m.group(1)), m.group(2)
        ref = m.group(0)
        if idx >= len(setup_results) or setup_results[idx] is None:
            raise UnresolvedReference(f"{ref}: no setup response at index {idx}")
        result = setup_results[idx]
        # BEFORE the body is walked: a setup that failed did not establish the state this
        # experiment is about, so nothing about its body is worth reporting. Checked here
        # rather than in `_lookup` because the status is a fact about the REQUEST, and
        # `_lookup` is only ever given a body.
        status = getattr(result, "status", None)
        if status is None:
            raise SetupRequestFailed(
                f"{ref}: setup request {idx} got NO ANSWER (status None) — it was refused "
                f"by the gate or the target did not reply, so the state this experiment "
                f"needs was never established. Fix that request, not the reference.")
        if status >= 400:
            raise SetupRequestFailed(
                f"{ref}: setup request {idx} FAILED with HTTP {status} — the state this "
                f"experiment needs was never established. Fix that request (method, path, "
                f"body, or the principal it runs as), not the reference.")
        return _lookup(getattr(result, "body", None), path, ref)
    return _SETUP_REF_RE.sub(sub, value)


def resolve_setup_refs(spec: dict, setup_results: list) -> dict:
    """A request spec with its `{{setup.*}}` references replaced by observed values.

    Deterministic template resolution over recorded setup responses — no model in the
    path, exactly like the comparators. Raises UnresolvedReference if any reference
    cannot be satisfied; the caller must abort the experiment, never dispatch the spec.
    """
    out = dict(spec)
    for key in ("url", "body"):
        if isinstance(out.get(key), str):
            out[key] = _resolve_text(out[key], setup_results)
    headers = out.get("headers")
    if isinstance(headers, dict):
        out["headers"] = {k: _resolve_text(v, setup_results) if isinstance(v, str) else v
                          for k, v in headers.items()}
    return out


# How much of a setup response's SHAPE the next round is shown. Bounds, not guesses:
# a response body is target data of unknown size, and an unbounded key dump would push
# the results it is meant to explain out of the prompt. Both caps are announced when
# they bite — see `key_paths`'s second return value.
_SHAPE_MAX_DEPTH = 4                # `user.addresses.0.id` is four segments, and real
_SHAPE_MAX_PATHS = 40               # APIs rarely bury an id deeper than that
SETUP_SHAPE_MAX_LINES = 8           # distinct setup responses described per round

# How much of an experiment's response body reaches the ledger. Run CM3 recorded
# `{"status":200,"url":".../rest/basket/8","note":"","bytes":154}` for the request that IS
# the capability milestone — principal A reading a basket whose body said `"UserId":27` —
# and threw the body away, so the one field carrying the claim was never written down.
#
# BOUNDED because a response is untrusted target data of unknown size, and a ledger that
# inlines whole pages stops being readable. 2 KiB holds the JSON object an API returns for
# one resource — CM3's were 154 and 329 bytes — while refusing to absorb a rendered page.
EXPERIMENT_BODY_MAX = 2048


def body_excerpt(body, limit: int = EXPERIMENT_BODY_MAX) -> tuple[str, bool]:
    """(excerpt, truncated) for one response body.

    Truncation is RETURNED rather than applied silently, because a reader who cannot tell
    a short body from a cut one cannot tell a missing field from an absent one — and the
    whole point of capturing the body is to let a later claim be checked against it."""
    text = body or ""
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text, False
    return text[:limit], True


# Keys a RESPONSE itself names as an identifier. Not a guess at what an id might be
# called: `id`, `<thing>Id`, `<thing>_id`, and `bid`, which is what a login reply calls the
# basket it just issued. A looser rule would sweep in every scalar and a tighter one would
# miss the field the endpoints are actually parameterised by.
_ID_KEY_RE = re.compile(r"^(?:id|bid|[A-Za-z][A-Za-z0-9]*(?:Id|_id))$")

# Bounds, announced rather than silent, for the same reason `key_paths` has them: a
# response is target data of unknown size and an unbounded dump would push the surface it
# is meant to explain out of the prompt.
_ID_MAX_DEPTH = 4
_ID_MAX_VALUES = 12

PRINCIPAL_IDS_HEADER = (
    "Known identifiers, per principal \u2014 these are objects each account ALREADY OWNS, "
    "read from its own authenticated responses. Use them directly in a url: a "
    "cross-account experiment needs NO setup step when the id is already here. Values "
    "only, no credentials. An identifier listed under one principal belongs to that "
    "principal and to no other.")


def own_identifiers(body, max_depth: int = _ID_MAX_DEPTH,
                    max_values: int = _ID_MAX_VALUES) -> dict:
    """The identifier-shaped scalars a response carried, as {dotted path: value}.

    Deterministic, no model, and no invention: every value returned was present in a body
    the harness actually received. That is the same guarantee `key_paths` gives the setup
    disclosure — it may not name something the model cannot use — applied to values rather
    than to paths. A body that carries no identifier yields {}, which is how a target that
    discloses nothing degrades: to silence, never to a fabricated id."""
    try:
        doc = json.loads(body or "")
    except (ValueError, TypeError):
        return {}
    found: dict = {}

    def walk(node, prefix: str, depth: int):
        if len(found) >= max_values or depth > max_depth:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (str, int)) and not isinstance(v, bool) \
                        and _ID_KEY_RE.match(k):
                    # A long string under an id-shaped key is a token, not an id. The
                    # redaction funnel is the real guard; this keeps the obvious case out
                    # of the prompt in the first place.
                    if isinstance(v, int) or (0 < len(v) <= 64):
                        found[path] = v
                elif isinstance(v, (dict, list)):
                    walk(v, path, depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node[:3]):
                walk(v, f"{prefix}.{i}", depth + 1)

    walk(doc, "", 1)
    return found


SETUP_SHAPE_HEADER = (
    "What the PREVIOUS round's setup requests returned. These are FIELD PATHS ONLY "
    "\u2014 no values are shown \u2014 shown so you know which paths those requests "
    "yield. Those responses are NOT still addressable: they belonged to the round that "
    "has finished, and a {{setup.<i>.<path>}} reference always addresses the setup list "
    "of the proposal it appears in. To use any of these paths, REPEAT the setup request "
    "in your own proposal's `setup`. Arrays are listed at index 0; other indices have "
    "the same shape. A line marked TRUNCATED is incomplete: more paths exist than are "
    "listed, so a field you expect and cannot see here may still be present.")


def key_paths(body, max_depth: int = _SHAPE_MAX_DEPTH,
              max_paths: int = _SHAPE_MAX_PATHS):
    """(paths, truncation) \u2014 the dotted paths into a setup response body that a
    `{{setup.i.<path>}}` reference could actually resolve.

    Deterministic walk, no eval and no model (invariant 1), and the mirror image of
    `_lookup`: it lists a path if and only if `_lookup` would return a value for it. So
    only INLINABLE LEAVES appear \u2014 an object, an array, a `null` and an empty
    container are all `UnresolvedReference` there, and listing one here would point the
    model at a reference that then aborts its own experiment. What the model is shown is
    exactly what the model may use; the two are pinned to each other by test.

    This exists because run 2C4 lost all nine experiments to `{{setup.0.id}}` against a
    body of `{"user": {"id": 25, ...}}`. The model was documented the reference GRAMMAR
    and never the SCHEMA of the response it was referencing \u2014 it cannot name a field
    it has never been shown, and the harness was holding the response.

    `truncation` is "" when the whole shape fits, and otherwise says which bound bit and
    by how much. It is not decoration: a partial list read as a complete one is a model
    concluding a field is absent when it was merely cut, which is the same silent-failure
    class this disclosure was built to end.
    """
    try:
        doc = json.loads(body or "")
    except ValueError:
        return [], ""
    paths: list = []
    total = 0
    depth_capped = False

    def walk(node, prefix: str, depth: int):
        nonlocal total, depth_capped
        if isinstance(node, dict):
            children = list(node.items())
        elif isinstance(node, list):
            # Index 0 only. Sibling elements of a JSON array repeat the same shape, so
            # walking all of them multiplies the list without adding information \u2014
            # and an array of a thousand rows would spend the entire budget on one field.
            children = [("0", node[0])] if node else []
        else:
            # A leaf. `bool` is caught by the `int` arm, exactly as `_lookup` catches it.
            if prefix and isinstance(node, (str, int, float)):
                total += 1
                if len(paths) < max_paths:
                    paths.append(prefix)
            return
        if depth >= max_depth:
            if children:
                depth_capped = True
            return
        for key, value in children:
            walk(value, f"{prefix}.{key}" if prefix else str(key), depth + 1)

    walk(doc, "", 0)
    notes = []
    if len(paths) < total:
        notes.append(f"{len(paths)} of {total} field paths listed (cap {max_paths})")
    if depth_capped:
        notes.append(f"fields nested deeper than {max_depth} levels are not listed")
    return paths, "; ".join(notes)


def describe_setup_shape(index: int, step: dict, result,
                         max_depth: int = _SHAPE_MAX_DEPTH,
                         max_paths: int = _SHAPE_MAX_PATHS) -> str:
    """One line describing what setup response `index` carries, for the next round.

    `step` is the model's OWN request text, deliberately not the resolved spec: a
    resolved url has values from an earlier setup response substituted into it, and this
    line must be derivable from structure alone. Naming the request matters as much as
    the paths \u2014 an index means nothing until the model knows which of its own
    requests wore it."""
    paths, truncation = key_paths(getattr(result, "body", None), max_depth, max_paths)
    fields = ", ".join(paths) if paths else (
        "(none \u2014 the body is not JSON, or carries no inlinable value)")
    line = (f"setup.{index} {(step.get('method') or 'GET').upper()} "
            f"{step.get('url', '')} -> HTTP {getattr(result, 'status', None)}; "
            f"field paths: {fields}")
    return f"{line} [TRUNCATED: {truncation}]" if truncation else line


class Hypothesis:
    """One proposed experiment: optional setup, a control, a variant, and a comparator.

    `setup` is what makes a STATEFUL flaw reachable. A two-request differential can only
    ask questions about a stateless endpoint; the flaws that actually cost money —
    workflow bypass, a price recalculated after approval, a coupon reused, a state
    machine entered sideways — need a sequence to arrive at the interesting moment
    first. Setup requests are EXECUTED but never judged: they establish the world, and
    the comparator still decides everything on the control/variant pair alone."""

    __slots__ = ("title", "severity", "comparator", "setup", "control", "variant",
                 "rationale")

    def __init__(self, title, severity, comparator, control, variant, rationale="",
                 setup=None):
        self.title = title
        self.severity = severity
        self.comparator = comparator
        self.setup = list(setup or [])
        self.control = control
        self.variant = variant
        self.rationale = rationale


def _salvage(text: str) -> list:
    """Complete objects from a TRUNCATED array.

    A reply that runs out of tokens mid-array is not garbage — the experiments before
    the cut are intact, and discarding them silently made this mechanism produce nothing
    at all on its first live run. Models with adaptive thinking spend part of the output
    allowance before emitting any JSON, so a truncated tail is the normal case rather
    than an error, and the same repair already exists for truncated commands elsewhere
    in this codebase.

    Scans for balanced top-level objects and stops at the first incomplete one; the
    partial object is dropped, never repaired, because guessing at half a request spec
    is exactly the kind of invention this module exists to prevent."""
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    out.append(json.loads(text[start:i + 1]))
                except ValueError:
                    pass
                start = None
    return out


def _clean_request(raw) -> dict | None:
    """A request spec reduced to what the governed browser accepts. Anything the schema
    does not name is dropped rather than passed through — a proposal must not be able to
    smuggle a field into the web layer."""
    if not isinstance(raw, dict):
        return None
    url = raw.get("url")
    if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
        return None
    method = str(raw.get("method", "GET")).upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return None
    out = {"url": url, "method": method}
    who = str(raw.get("as", "self")).strip().lower()
    out["as"] = who if who in _IDENTITIES else "self"   # unknown principal: refuse, don't guess
    body = raw.get("body")
    if isinstance(body, (dict, list)):
        out["body"] = json.dumps(body)
    elif isinstance(body, str):
        out["body"] = body
    headers = raw.get("headers")
    if isinstance(headers, dict):
        out["headers"] = {str(k): str(v) for k, v in list(headers.items())[:12]
                          if isinstance(k, str)}
    return out


def parse(text: str, max_hypotheses: int = _MAX_HYPOTHESES) -> list:
    """Hypotheses from a model reply. Malformed entries are skipped, never guessed at.

    Accepts a JSON array, optionally inside a ```json fence, because that is what models
    reliably produce. Everything is validated: an unknown comparator is refused outright
    rather than defaulted, since defaulting would let a vague proposal borrow the
    authority of a strict one."""
    if not text:
        return []
    block = text
    fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)
    if fence:
        block = fence.group(1)
    else:
        start, end = block.find("["), block.rfind("]")
        if start == -1:
            return []
        # A truncated reply has an opening bracket and no closing one. Returning early
        # there is what made this mechanism yield nothing on its first live run: the
        # guard fired before the salvage below could recover the intact experiments.
        block = block[start:end + 1] if end > start else block[start:]
    try:
        doc = json.loads(block)
    except ValueError:
        doc = _salvage(block)
    if not isinstance(doc, list):
        return []

    out = []
    for item in doc[:max_hypotheses * 3]:
        if not isinstance(item, dict):
            continue
        comparator = str(item.get("comparator", "")).strip()
        if comparator not in _COMPARATORS:
            continue                       # unknown comparison: refuse, do not default
        title = str(item.get("title", "")).strip()
        if not title or len(title) > 140:
            continue
        control = _clean_request(item.get("control"))
        variant = _clean_request(item.get("variant"))
        if control is None or variant is None:
            continue
        if control == variant:
            continue                       # a differential against itself proves nothing
        severity = str(item.get("severity", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        # At most three setup requests: enough to reach a non-trivial state, few
        # enough that a confused proposal cannot turn into a crawl of the target.
        setup = [r for r in (_clean_request(x) for x in (item.get("setup") or [])[:3])
                 if r is not None]
        out.append(Hypothesis(title, severity, comparator, control, variant,
                              str(item.get("rationale", ""))[:300], setup))
        if len(out) >= max_hypotheses:
            break
    return out


def judge(hypothesis, control_result, variant_result, profile=None, context=None):
    """(holds, meaning) for an executed hypothesis.

    The only place a proposal becomes a finding, and it consults the comparator rather
    than anything the model said. A missing response is not a pass: an unreachable
    target proves nothing, and treating silence as a result is how a scanner invents
    vulnerabilities."""
    if control_result is None or variant_result is None:
        return False, ""
    entry = _COMPARATORS.get(hypothesis.comparator)
    if entry is None:
        return False, ""
    predicate, meaning = entry
    try:
        if hypothesis.comparator in _CONTEXT_COMPARATORS:
            # Named explicitly, never sniffed: a context comparator that fell through to a
            # two-argument call would judge on less than it was given and quietly answer a
            # different question.
            held = predicate(control_result, variant_result, profile, context)
        else:
            try:
                held = predicate(control_result, variant_result, profile)
            except TypeError:
                held = predicate(control_result, variant_result)   # comparator ignores it
        if not held:
            return False, ""
    except Exception:
        return False, ""
    if hypothesis.comparator == "bodies_differ":
        # An endpoint that ECHOES what it was given differs on every pair of distinct
        # requests. On a live target this fired on two registrations whose bodies
        # differed by two bytes — the echoed username — and reported mass-assignment
        # role escalation that had not been demonstrated at all. So the values WE
        # supplied are removed from both responses before they are compared, exactly as
        # the username-enumeration check does; what remains is the part of the answer
        # the server chose.
        submitted = _submitted_values(hypothesis)
        if _strip(control_result.body, submitted) == _strip(variant_result.body,
                                                            submitted):
            return False, ""
    return True, meaning


def _submitted_values(hypothesis) -> list:
    """Every scalar this experiment put into either request — the strings an echoing
    endpoint will hand straight back."""
    out: list = []
    for spec in (hypothesis.control, hypothesis.variant):
        for key in ("url", "body"):
            raw = spec.get(key) or ""
            try:
                doc = json.loads(raw) if key == "body" else None
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                out.extend(str(v) for v in doc.values()
                           if isinstance(v, (str, int, float)) and len(str(v)) >= 3)
            elif key == "url":
                out.extend(part for part in re.split(r"[/?&=]", raw) if len(part) >= 3)
    return out


def _strip(text: str, values) -> str:
    out = text or ""
    for v in values:
        if v:
            out = out.replace(str(v), "")
    return _norm(out)


def comparator_names() -> tuple:
    """The closed set, for the prompt. The model must pick from these by name."""
    return tuple(sorted(_COMPARATORS))


REFINE_PROMPT = """Your previous experiments were executed. Results below.

A result of NOT CONFIRMED usually means the experiment was aimed slightly wrong — a \
path that does not exist, a request the app rejected before reaching the logic, a \
comparison too weak to separate the two answers — not that the application is sound. \
Read the observed status codes and sizes and propose a better round.

Do not repeat an experiment unchanged. If a control and variant both returned the same \
error, the endpoint or the payload shape is wrong; fix that first. If both returned 200 \
with near-identical sizes, the change you made had no effect and a different rule needs \
testing.

Reply with ONLY a JSON array, using EXACTLY these keys — the same ones as before:
  title       short name for the flaw if the experiment succeeds
  severity    critical | high | medium | low
  comparator  one of: {comparators}
  setup       OPTIONAL list of up to 3 requests run first, never judged
  control     {{"url": "...", "method": "GET", "headers": {{}}, "body": ...,
               "as": "self" | "second" | "anonymous"}}
  variant     same shape, one thing changed
  rationale   one sentence on what the difference would prove

""" + SETUP_REF_SYNTAX + """

Do NOT rename them. A refined round that answered with "name" and "type" instead of \
"title" and "comparator" was discarded in full, so the second round contributed nothing \
at all and the first round's results were wasted.

Every {{setup.<i>.<path>}} reference addresses YOUR OWN setup list, in THIS proposal. \
The previous round's setup responses are gone: if you want a value one of them returned, \
put that request back in your own setup and reference it at its index there. All three \
proposals in one measured round referenced setup.0 while supplying no setup at all, and \
all three were refused without ever being run.

Reply [] if the results suggest nothing worth another try.
"""


PROMPT = """You are proposing EXPERIMENTS, not findings. You cannot declare anything \
true: each proposal is two HTTP requests that deterministic code will execute and \
compare, and only the comparison decides whether a vulnerability exists.

Propose experiments that a generic scanner would miss — business-logic flaws, \
authorization gaps specific to THIS application's domain, state transitions that should \
be impossible, parameters whose meaning implies a rule the server may not enforce.

Each experiment is a CONTROL request (the behaviour that should happen) and a VARIANT \
(the same request with one thing changed that ought to be rejected). Change exactly one \
thing, or the comparison means nothing.

Reply with ONLY a JSON array. Each element:
  title       short name for the flaw if the experiment succeeds
  severity    critical | high | medium | low
  comparator  one of: {comparators}
  setup       OPTIONAL list of up to 3 requests run FIRST to reach an interesting
              state (create an order, apply a coupon, start a workflow). They are
              executed but never judged.
  control     {{"url": "...", "method": "GET", "headers": {{}}, "body": ...,
               "as": "self" | "second" | "anonymous"}}
  variant     same shape, one thing changed
  rationale   one sentence on what the difference would prove

`as` chooses WHICH PRINCIPAL issues the request, and it is the most valuable field \
here. "self" is the account you hold, "second" is a different real account that also \
exists, "anonymous" is a stranger with no session. Authorization flaws are precisely a \
disagreement between these: an object one account may read and another may not, an \
action a stranger should be refused. A control and a variant that differ ONLY in `as` \
is the cleanest experiment you can propose.

""" + SETUP_REF_SYNTAX + """

Prefer experiments that need setup — a stateless endpoint has usually been checked \
already by deterministic probes, whereas a rule that only exists partway through a \
workflow has not.

Rules: URLs must be on the authorised target. Do not propose anything destructive \
(no DELETE of data you did not create, no password changes to accounts you do not own, \
no endpoints named reset/drop/wipe). If you have no good experiment, reply [].
"""
