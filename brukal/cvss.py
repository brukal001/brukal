"""
cvss.py — evidence-based CVSS 3.1 scoring for CONFIRMED differentials (stdlib-only,
deterministic, no LLM anywhere).

`knowledge.py` scores a finding from its TITLE — a class-based, hardcoded lookup that
is the same for every "SQL injection" regardless of what was actually proven. That is
fine as a fallback, but it cannot tell a status-only SQLi (injectability proven, no
data read) from a full boolean-read SQLi, and it cannot tell either from an RCE. Both
get the class's number.

This module scores from the COMPARATOR instead — the same string a `confirm_*` prover
already passes to `_record_confirmed(..., comparator=...)` to name the differential
that proved the bug. Each comparator maps to a CVSS 3.1 vector chosen to reflect
exactly what that differential demonstrated (and nothing more): a status-code
differential gets a low-impact vector: no read, no write, no code execution, an
error-based leak gets a bit more, a full command-execution proof gets C:H/I:H/A:H.

The anti-overclaim property this exists for: `grade("sqli_error_status_differential")`
must score strictly BELOW `grade("os_command_injection_differential")`,
`grade("sqli_boolean_differential")` and `grade("mass_assignment_differential")` — a
status differential is real, but it did not read data or execute code, and its score
must say so.

`score_from_vector` implements the published CVSS 3.1 base-score formula exactly
(https://www.first.org/cvss/v3.1/specification-document §7.4), so any vector — table
or facts-modified — gets a spec-correct number; `knowledge.py` keeps its own
hardcoded numbers untouched and is used only as `grade()`'s fallback for a comparator
this table does not know.
"""
from __future__ import annotations

# --- CVSS 3.1 base-score formula -------------------------------------------

_AV_W = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_W = {"L": 0.77, "H": 0.44}
_PR_W = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
         "C": {"N": 0.85, "L": 0.68, "H": 0.50}}
_UI_W = {"N": 0.85, "R": 0.62}
_CIA_W = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict:
    """Parse a CVSS 3.1 vector string ('AV:N/AC:L/.../A:H', an optional leading
    'CVSS:3.1/' tolerated) into a {metric: value} dict. Unknown segments are
    ignored rather than raising — this is a metrics table, not a validator."""
    v = (vector or "").strip()
    if v.upper().startswith("CVSS:"):
        v = v.split("/", 1)[1] if "/" in v else ""
    out = {}
    for part in v.split("/"):
        if ":" not in part:
            continue
        k, _, val = part.partition(":")
        if k in _METRICS:
            out[k] = val
    return out


def roundup(x: float) -> float:
    """The CVSS 3.1 spec's own Roundup(x): ceil to 1 decimal place, computed on
    integer cents to dodge float noise (`round(x*10)/10` is NOT the spec function —
    it rounds nearest, not up)."""
    import math
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def score_from_vector(vector: str) -> float:
    """CVSS 3.1 base score computed exactly per the published formula. Raises
    `ValueError` if any of the eight base metrics (AV/AC/PR/UI/S/C/I/A) is
    missing — fail-closed, since defaulting a missing metric would silently
    score an incomplete vector rather than refuse it."""
    m = parse_vector(vector)
    missing = [k for k in _METRICS if k not in m]
    if missing:
        raise ValueError(
            f"incomplete CVSS vector, missing {missing}: {vector!r}")
    scope = m["S"]
    av = _AV_W.get(m["AV"], _AV_W["N"])
    ac = _AC_W.get(m["AC"], _AC_W["L"])
    pr = _PR_W.get(scope, _PR_W["U"]).get(m["PR"], 0.85)
    ui = _UI_W.get(m["UI"], _UI_W["N"])
    c = _CIA_W.get(m["C"], 0.0)
    i = _CIA_W.get(m["I"], 0.0)
    a = _CIA_W.get(m["A"], 0.0)

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope == "C":
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


# --- comparator → (vector, basis) table -------------------------------------
#
# Graded on DEMONSTRATED impact only. `basis` is a one-line statement of what the
# differential proved and — for the deliberately-conservative ones — what it did
# NOT prove, so a reader (or `report.py`) can see the anti-overclaim reasoning
# next to the number rather than having to trust it.

COMPARATOR_CVSS: dict[str, tuple[str, str]] = {
    "forged_token_accepted":
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
         "a forged token was accepted — authentication bypass demonstrated"),
    "os_command_injection_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
         "command output returned — code execution demonstrated"),
    "blind_cmdi_out_of_band":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
         "out-of-band callback — blind command execution demonstrated"),
    "ssti_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
         "template expression evaluated — server-side template injection"),
    "deserialization_rce":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
         "gadget executed — deserialization RCE demonstrated"),
    "mass_assignment_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
         "client set a privileged property at creation — differential vs control"),
    "object_mass_assignment_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
         "client wrote a server-internal object property (read-back confirmed)"),
    "bola_cross_account":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         "another user's object was read across the account boundary"),
    "cross_account_resource":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         "a cross-account resource was returned"),
    "a_denied_b_allowed":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         "access-control differential: B allowed what A was denied"),
    "unauthenticated_exposure":
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         "sensitive data returned to an unauthenticated caller"),
    "unauthenticated_access":
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "a protected endpoint answered without authentication"),
    "ssrf_out_of_band":
        ("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N",
         "server made an out-of-band request to an attacker host; internal impact not demonstrated"),
    "ssrf_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N",
         "server-side request differential; internal impact not demonstrated"),
    "nosql_operator_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
         "a client-supplied operator bypassed the filter (e.g. free coupon)"),
    "sqli_boolean_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         "boolean SQL injection — data is inferable via the differential"),
    "sqli_error_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
         "error-based SQL injection; a DB error leaks, data read not demonstrated"),
    "sqli_error_status_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
         "SQL injection proven by a status differential; data read/modify NOT demonstrated"),
    "lfi_path_traversal_differential":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
         "a file outside the web root was read"),
    "reflected_xss_differential":
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         "script executed in a victim browser (reflected)"),
    "open_redirect_differential":
        ("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
         "redirect to an attacker-controlled host"),
    "state_changed":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
         "a state-changing action was confirmed to take effect"),
    "repeat_accepted":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
         "a replayed request was accepted a second time"),
    "status_differs":
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
         "a behavioral status differential; concrete impact not demonstrated"),
}


def _set_metric(vector: str, metric: str, value: str) -> str:
    """Return `vector` with `metric` set to `value`, preserving the order/presence
    of every other metric. Appends the metric if it was absent."""
    parts = vector.split("/")
    out = []
    found = False
    for p in parts:
        k, _, _v = p.partition(":")
        if k == metric:
            out.append(f"{metric}:{value}")
            found = True
        else:
            out.append(p)
    if not found:
        out.append(f"{metric}:{value}")
    return "/".join(out)


def grade(comparator: str, facts: dict | None = None, title: str = "",
          severity: str = "") -> dict:
    """Grade a CONFIRMED differential's impact. Returns {"cvss", "vector", "basis"}.

    `comparator` known → the table vector, with deterministic `facts` modifiers
    applied (each one raises impact only in the direction the fact justifies, never
    lowers it below the table baseline):
      - facts["auth_required"] is False → PR:N (no privilege was actually needed)
      - facts["credentials_leaked"]     → C:H  (confidentiality impact is total)
      - facts["cross_scope"]            → S:C  (the impact crossed a security scope)

    `comparator` unknown → falls back to the class-based `knowledge.enrich(title,
    severity)`, exactly like every finding did before this module existed. Never
    raises: an unmapped comparator, a bad title/severity, OR a comparator whose
    (possibly facts-modified) vector is incomplete all still return a dict — the last
    of these falls back to the class number rather than propagating the ValueError
    that `score_from_vector` now raises. Today every COMPARATOR_CVSS vector is complete
    so that path is unreachable, but the no-raise guarantee is now enforced here rather
    than merely contingent on the table staying complete."""
    entry = COMPARATOR_CVSS.get(comparator)
    if entry is None:
        from . import knowledge
        kb = knowledge.enrich(title, severity)
        return {"cvss": kb["cvss"], "vector": kb["vector"],
                "basis": "class-based (comparator unmapped)"}
    vector, basis = entry
    final_vector = vector
    if facts:
        if facts.get("auth_required") is False:
            final_vector = _set_metric(final_vector, "PR", "N")
        if facts.get("credentials_leaked"):
            final_vector = _set_metric(final_vector, "C", "H")
        if facts.get("cross_scope"):
            final_vector = _set_metric(final_vector, "S", "C")
    try:
        cvss = score_from_vector(final_vector)
    except ValueError:
        # A table vector (or a facts-modified one) that is somehow incomplete must not
        # crash the grading pipeline: fall back to the class-based number, the same path
        # an unmapped comparator takes, so grade()'s no-raise contract holds. Unreachable
        # with today's complete COMPARATOR_CVSS table — a guard, not a live branch.
        from . import knowledge
        kb = knowledge.enrich(title, severity)
        return {"cvss": kb["cvss"], "vector": kb["vector"],
                "basis": f"{basis} (vector incomplete; class-based fallback)"}
    return {"cvss": cvss, "vector": final_vector, "basis": basis}
