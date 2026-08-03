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
        lambda a, b: (a.status in (401, 403)) and (b.status == 200),
        "the control was refused and the variant was accepted"),
    "b_reveals_more": (
        lambda a, b: (b.status == 200 and a.status == 200
                      and len(b.body or "") > len(a.body or "") * 2
                      and len(b.body or "") > 200),
        "the variant returned substantially more data than the control"),
    "bodies_differ": (
        lambda a, b: (a.status == b.status and a.status
                      and _norm(a.body) != _norm(b.body)),
        "identical requests but for one changed value produced different bodies"),
    "b_errors_a_does_not": (
        lambda a, b: (a.status == 200 and b.status is not None and b.status >= 500),
        "the variant drove the application into a server error the control did not"),
}

_MAX_HYPOTHESES = 6


def _norm(text) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


class Hypothesis:
    """One proposed experiment: a control request, a variant, and how to judge them."""

    __slots__ = ("title", "severity", "comparator", "control", "variant", "rationale")

    def __init__(self, title, severity, comparator, control, variant, rationale=""):
        self.title = title
        self.severity = severity
        self.comparator = comparator
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
        out.append(Hypothesis(title, severity, comparator, control, variant,
                              str(item.get("rationale", ""))[:300]))
        if len(out) >= max_hypotheses:
            break
    return out


def judge(hypothesis, control_result, variant_result):
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
        return bool(predicate(control_result, variant_result)), meaning
    except Exception:
        return False, ""


def comparator_names() -> tuple:
    """The closed set, for the prompt. The model must pick from these by name."""
    return tuple(sorted(_COMPARATORS))


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
  control     {{"url": "...", "method": "GET", "headers": {{}}, "body": ...}}
  variant     same shape, one thing changed
  rationale   one sentence on what the difference would prove

Rules: URLs must be on the authorised target. Do not propose anything destructive \
(no DELETE of data you did not create, no password changes to accounts you do not own, \
no endpoints named reset/drop/wipe). If you have no good experiment, reply [].
"""
