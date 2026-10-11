"""
response_view.py — what the model is SHOWN of a web response.

NOT a gate component: it decides only how much of an already-received, gate-approved
response the model reads, never whether anything runs (invariant 1 is untouched).

Why it exists (2026-10-01 live run): the decisive response was 4,447 bytes with the
result near the END. The model was shown `body[:600]` — the page header — and handed the
step back as MANUAL ("view the page source to find the values"). It was not unwilling;
it was blind to its own result.

`salient_view` shows, within the same budget:
  * the region that CHANGED versus an earlier response to the same page, when that diff
    is informative; otherwise
  * the start AND the end of the page (`head_tail`).
Stdlib only, deterministic, never raises.
"""
from __future__ import annotations

import difflib

_HEAD_SHARE = 0.6            # of the budget, for head_tail
_MAX_DIFF_LINES = 4000       # larger pages skip the diff (bounded work)
_UNINFORMATIVE = 0.8         # changed-line share above which a diff says nothing useful


def head_tail(body: str, budget: int) -> str:
    """The first ~60% and last ~40% of `body` with an omission marker, never longer than
    `budget` (marker included). A body within budget is returned unchanged."""
    if budget <= 0:
        return ""
    if len(body) <= budget:
        return body
    widest = f"\n… [{len(body)} chars omitted] …\n"
    room = budget - len(widest)
    if room <= 0:
        return body[:budget]
    head = int(room * _HEAD_SHARE)
    tail = room - head
    marker = f"\n… [{len(body) - head - tail} chars omitted] …\n"
    return body[:head] + marker + (body[-tail:] if tail > 0 else "")


def _diff_view(body: str, baseline: str, budget: int) -> str:
    """The lines of `body` inserted or replaced versus `baseline`, in order, each region
    introduced by a marker; '' when the diff is empty, too large, or uninformative."""
    new, old = body.splitlines(), baseline.splitlines()
    if not new or len(new) > _MAX_DIFF_LINES or len(old) > _MAX_DIFF_LINES:
        return ""
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    regions = [(j1, j2) for tag, _i1, _i2, j1, j2 in sm.get_opcodes()
               if tag in ("insert", "replace") and j2 > j1]
    changed = sum(j2 - j1 for j1, j2 in regions)
    if not regions or changed > _UNINFORMATIVE * len(new):
        return ""
    out: list[str] = []
    for j1, j2 in regions:
        lines = [ln.strip() for ln in new[j1:j2] if ln.strip()]
        if lines:
            out.append(f"… [changed region, line {j1 + 1}] …\n" + "\n".join(lines) + "\n")
    text = "".join(out)
    if len(text) <= budget:
        return text
    # Too long to show whole: keep the start AND end of the changed text, with a visible
    # marker. Cutting at the budget dropped every later region — often the result, behind
    # per-load churn (nonces) or one huge minified line.
    if budget <= len(f"\n… [{len(text)} chars omitted] …\n"):
        return ""
    return head_tail(text, budget)


def salient_view(body, baseline, budget: int) -> str:
    """What the model should read of `body` in `budget` characters (markers included).
    See the module docstring. Never raises; on error returns `body[:budget]`."""
    try:
        if budget is None or budget <= 0:
            return ""
        text = body if isinstance(body, str) else ("" if body is None else str(body))
        if len(text) <= budget:
            return text
        if baseline:
            view = _diff_view(text, str(baseline), budget)
            if view:
                return view
        return head_tail(text, budget)
    except Exception:
        try:
            return ("" if body is None else str(body))[:max(int(budget or 0), 0)]
        except Exception:
            return ""
