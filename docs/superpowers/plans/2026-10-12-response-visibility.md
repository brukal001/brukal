# Response Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The model and the deterministic provers see the part of a web response that matters (the changed region, or the start AND end of a long page) instead of only its first 600 / 4,000 characters.

**Architecture:** A new pure module `brukal/response_view.py` computes a fixed-budget view (diff vs an earlier full response to the same endpoint, else head+tail). `AssistSession._absorb_web` uses it for the model note (600) and vault summary (800), with baselines held in a small bounded in-memory map. `capture._record` stores long responses as head+tail within the same 4,000 budget. The strategist prompt gets one consistent MANUAL rule. The gate is not touched.

**Tech Stack:** Python 3.12 stdlib (`difflib`), pytest. Run tests with `.venv/bin/python -m pytest`.

**Spec:** `docs/superpowers/specs/2026-10-12-response-visibility-design.md`

## Global Constraints

- No change to `brukal/gate.py`, `brukal/hostmatch.py`, `brukal/scope.py`, `brukal/risk.py`, `brukal/executor.py`, `brukal/audit.py` (invariants 1–5; the replay corpus must therefore stay 0 NEW / 0 LOST / 0 UNSEEN / 0 looser).
- Budgets unchanged: model note 600 chars, vault summary 800 chars, capture store 4,000 chars — markers INCLUDED in each budget.
- A body within budget is returned / stored byte-identical to today.
- Redaction runs on the FULL body before any slicing (unchanged order in `capture._record`).
- `salient_view` never raises; on any error it returns `body[:budget]`.
- No new requests are issued; baselines come only from responses already received.
- Stdlib only in `brukal/response_view.py`; no LLM anywhere in this change.

## Review Focus

1. **Minified / single-line pages** — a diff over one huge line marks everything changed; expect the head+tail fallback, not a 600-char slice of noise. (Task 1 test `test_single_line_page_falls_back_to_head_tail`.)
2. **Baseline is a totally different page** (e.g. an error page vs a product page) — most lines changed; expect head+tail, not a diff dump. (Task 1 test `test_mostly_changed_diff_falls_back`.)
3. **Repeating the exact same request** — must not use itself as its own baseline (empty diff); expect the previous DIFFERENT request as baseline. (Task 3 test `test_same_request_is_not_its_own_baseline`.)
4. **Non-2xx responses** (a 500 from a probe) must not become the baseline for the next request. (Task 3 test `test_error_responses_are_not_baselines`.)
5. **Memory growth over a long run** — the baseline map stays bounded (≤ 64 endpoints, ≤ 3 bodies each, each ≤ 200,000 chars). (Task 3 test `test_baseline_memory_is_bounded`.)

---

### Task 1: `salient_view` — the pure response view

**Files:**
- Create: `brukal/response_view.py`
- Test: `tests/test_response_view.py`

**Interfaces:**
- Produces: `salient_view(body: str, baseline: str | None, budget: int) -> str` and `head_tail(body: str, budget: int) -> str`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_response_view.py
"""salient_view — what the model is SHOWN of a response (not a gate component).

The 2026-10-01 live run: a 4,447-byte response with the result near the END; the model
saw body[:600] (the page header) and handed the step back as MANUAL. The view must show
the changed region (vs an earlier response to the same page) or the start AND end."""
from __future__ import annotations

from brukal.response_view import head_tail, salient_view

HEADER = "\n".join(f"<div class='nav-{i}'>navigation item {i}</div>" for i in range(90))
NORMAL = HEADER + "\n<table>\n<tr><td>Product A</td></tr>\n<tr><td>Product B</td></tr>\n</table>"
RESULT = HEADER + ("\n<table>\n<tr><td>RESULT-ROW-1</td><td>value-7f3a</td></tr>\n"
                   "<tr><td>RESULT-ROW-2</td><td>value-91bc</td></tr>\n</table>")


def test_within_budget_is_identity():
    assert salient_view("short body", None, 600) == "short body"
    assert salient_view("short body", "other", 600) == "short body"


def test_head_tail_keeps_start_and_end_within_budget():
    body = "S" * 3000 + "MIDDLE" + "E" * 3000
    v = head_tail(body, 600)
    assert len(v) <= 600
    assert v.startswith("S") and v.endswith("E")
    assert "chars omitted" in v and "MIDDLE" not in v


def test_no_baseline_long_body_uses_head_tail_and_sees_the_end():
    v = salient_view(RESULT, None, 600)
    assert len(v) <= 600
    assert "RESULT-ROW-2" in v                     # the end of the page is visible


def test_baseline_diff_surfaces_the_changed_region_at_the_end():
    assert len(RESULT) > 600
    v = salient_view(RESULT, NORMAL, 600)
    assert len(v) <= 600
    assert "RESULT-ROW-1" in v and "RESULT-ROW-2" in v
    assert "changed region" in v
    assert "navigation item 0" not in v            # the unchanged header is not repeated


def test_old_head_slice_would_have_missed_it():
    assert "RESULT-ROW-1" not in RESULT[:600]      # documents the defect being fixed


def test_empty_diff_falls_back_to_head_tail():
    v = salient_view(RESULT, RESULT, 600)
    assert len(v) <= 600 and "chars omitted" in v


def test_single_line_page_falls_back_to_head_tail():
    a = "<html>" + "x" * 5000 + "A-END</html>"
    b = "<html>" + "y" * 5000 + "B-END</html>"
    v = salient_view(a, b, 600)
    assert "chars omitted" in v and v.endswith("A-END</html>")


def test_mostly_changed_diff_falls_back():
    other = "\n".join(f"<p>error line {i}</p>" for i in range(120))
    v = salient_view(RESULT, other, 600)
    assert "chars omitted" in v and "changed region" not in v


def test_budget_is_never_exceeded():
    for budget in (1, 10, 50, 600, 800):
        for base in (None, NORMAL, RESULT):
            assert len(salient_view(RESULT, base, budget)) <= budget


def test_deterministic_and_never_raises():
    assert salient_view(RESULT, NORMAL, 600) == salient_view(RESULT, NORMAL, 600)
    assert salient_view(None, None, 600) == ""
    assert salient_view(12345, None, 3) == "123"
    assert salient_view("abc", None, 0) == ""
    assert salient_view("abc", None, -5) == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_response_view.py -q -p no:cacheprovider`
Expected: ERROR — `ModuleNotFoundError: No module named 'brukal.response_view'`

- [ ] **Step 3: Write the implementation**

```python
# brukal/response_view.py
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
    used = 0
    for j1, j2 in regions:
        lines = [ln.strip() for ln in new[j1:j2] if ln.strip()]
        if not lines:
            continue
        piece = f"… [changed region, line {j1 + 1}] …\n" + "\n".join(lines) + "\n"
        if used + len(piece) > budget:
            if budget - used > 40:
                out.append(piece[:budget - used])
            break
        out.append(piece)
        used += len(piece)
    return "".join(out)[:budget]


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_response_view.py -q -p no:cacheprovider`
Expected: all PASS. Also `.venv/bin/python -m pyflakes brukal/response_view.py tests/test_response_view.py` → no output.

- [ ] **Step 5: Commit**

```bash
git add brukal/response_view.py tests/test_response_view.py
git commit -m "feat(view): salient_view -- show the changed region or the start AND end of a response"
```

---

### Task 2: Capture store keeps head and tail

**Files:**
- Modify: `brukal/capture.py:150-181` (`_MAX_RESPONSE_KEPT` block and the two `safe_response` slices in `_record`)
- Test: `tests/test_capture_head_tail.py`

**Interfaces:**
- Consumes: `head_tail` is NOT used here (capture needs a fixed 2,400 head, not a 60% share); this task adds its own `_keep_head_tail(text: str) -> str` in `capture.py`.
- Produces: `capture._keep_head_tail(text: str) -> str`; `CapturedRequest.response` for long bodies = head (2,400) + marker + tail, total ≤ 4,000.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_capture_head_tail.py
"""The capture store keeps the START and END of a long response.

2026-10-01: the decisive response was 4,447 bytes with the result near the end; the
capture store kept [:4000], so the deterministic provers never saw the result.
Bodies <= 4,000 chars are stored byte-identical to before."""
from __future__ import annotations

from pathlib import Path

from brukal import capture, redact
from brukal import capture_confirm as cc
from brukal.scope import load_scope

SCOPE = load_scope(Path(__file__).resolve().parent / "fixtures" / "scope.json")
URL = "http://10.10.10.5/filter"


def _rec(response, q="", body=None, method="GET"):
    return capture._record(method, URL + (("?" + q) if q else ""), {}, body, 200,
                           len(response), "text/html", SCOPE, capture.IngestReport(),
                           "self", response=response)


def test_short_body_is_byte_identical():
    body = "x" * 4000
    assert _rec(body).response == body


def test_long_body_keeps_its_end_within_budget():
    body = "H" * 4000 + "<td>RESULT-ROW-END</td>"
    stored = _rec(body).response
    assert len(stored) <= 4000
    assert stored.startswith("H" * 2400)
    assert stored.endswith("<td>RESULT-ROW-END</td>")
    assert "chars omitted" in stored


def test_the_2026_10_01_shape_keeps_the_result():
    page = "<div>nav</div>\n" * 260 + "<table><tr><td>RESULT-ROW-1</td></tr></table>"
    assert 4000 < len(page) < 4500
    assert "RESULT-ROW-1" in _rec(page).response


def test_redaction_still_applies_to_text_landing_in_the_tail():
    secret = "S3cretValue-For-Test-0001"
    redact.register(secret)
    try:
        stored = _rec("H" * 5000 + secret).response
        assert secret not in stored and "[REDACTED:" in stored
    finally:
        redact.clear()


def test_boolean_differential_now_sees_a_tail_only_difference():
    head = "<p>same header</p>\n" * 300            # > 4,000 chars of identical start
    rows = "<tr><td>row one</td></tr>"
    caps = [_rec(head + rows, q="category=Gifts"),
            _rec(head + rows, q="category=Gifts' AND '1'='1"),
            _rec(head + "<tr><td>no rows</td></tr>", q="category=Gifts' AND '1'='2")]
    assert [f["param"] for f in cc.boolean_sqli_differential(caps)] == ["category"]


def test_dynamic_tail_content_is_now_compared_too():
    """Stated trade-off: a value that changes on every load, placed at the END of a long
    page, is now part of the comparison, so truthy != baseline and nothing is confirmed.
    Pinned so the effect is explicit."""
    head = "<p>same header</p>\n" * 300
    caps = [_rec(head + "<i>t=1</i>", q="category=Gifts"),
            _rec(head + "<i>t=2</i>", q="category=Gifts' AND '1'='1"),
            _rec(head + "<i>t=3</i>", q="category=Gifts' AND '1'='2")]
    assert cc.boolean_sqli_differential(caps) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_capture_head_tail.py -q -p no:cacheprovider`
Expected: FAIL — `test_long_body_keeps_its_end_within_budget`, `test_the_2026_10_01_shape_keeps_the_result`, `test_redaction_still_applies_to_text_landing_in_the_tail`, `test_boolean_differential_now_sees_a_tail_only_difference` fail (end of body is cut). `test_short_body_is_byte_identical` and `test_dynamic_tail_content_is_now_compared_too` pass already.

- [ ] **Step 3: Implement**

In `brukal/capture.py`, replace the line `_MAX_RESPONSE_KEPT = 4000` with:

```python
_MAX_RESPONSE_KEPT = 4000
# A long response keeps its START and its END within the same budget. 2026-10-01: the
# decisive response was 4,447 bytes with the result near the end, and keeping only the
# first 4,000 hid it from every prover. Bodies within budget are stored unchanged.
_HEAD_KEPT = 2400


def _keep_head_tail(text: str) -> str:
    """`text` if it fits; else the first 2,400 chars + an omission marker + the end,
    never longer than _MAX_RESPONSE_KEPT (marker included)."""
    if len(text) <= _MAX_RESPONSE_KEPT:
        return text
    tpl = "\n… [{} chars omitted] …\n"
    tail = _MAX_RESPONSE_KEPT - _HEAD_KEPT - len(tpl.format(len(text)))
    omitted = len(text) - _HEAD_KEPT - tail
    return text[:_HEAD_KEPT] + tpl.format(omitted) + text[-tail:]
```

and in `_record`, replace the two slicing lines:

```python
            safe_response = redact.text(str(response))[:_MAX_RESPONSE_KEPT]
        except Exception:
            safe_response = str(response)[:_MAX_RESPONSE_KEPT]
```

with:

```python
            safe_response = _keep_head_tail(redact.text(str(response)))
        except Exception:
            safe_response = _keep_head_tail(str(response))
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_capture_head_tail.py tests/test_capture_confirm.py tests/test_capture_auth_success.py tests/test_boolean_sqli_correlation.py tests/test_capture_consumers.py -q -p no:cacheprovider`
Expected: all PASS. `.venv/bin/python -m pyflakes brukal/capture.py tests/test_capture_head_tail.py` → only the pre-existing warning in `capture.py` (if any), nothing new.

- [ ] **Step 5: Commit**

```bash
git add brukal/capture.py tests/test_capture_head_tail.py
git commit -m "fix(capture): keep the start AND end of long responses (same 4,000 budget)"
```

---

### Task 3: The model note and vault summary use the view

**Files:**
- Modify: `brukal/assist_web.py` — `_absorb_web` (the `body[:600]` line ~832 and the `body[:800]` line ~844) and add helper `_web_baseline` to the same class
- Modify: `docs/superpowers/specs/2026-10-12-response-visibility-design.md` §3.2 (baseline source amendment)
- Test: `tests/test_web_note_view.py`

**Interfaces:**
- Consumes: `brukal.response_view.salient_view(body, baseline, budget) -> str` (Task 1).
- Produces: `AssistSession._web_baseline(action, status: int | None, body: str) -> str | None` (records `body` as a future baseline when `status` is 2xx; returns the most recent earlier 2xx body for the same scheme+host+path from a DIFFERENT request, or None).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_web_note_view.py
"""The model-facing note and the vault summary show the changed region / start+end.

2026-10-01: after rendering the decisive request the model was shown body[:600] — the
page header — and handed the step back as MANUAL. Baselines are the last few FULL 2xx
bodies per endpoint, held in memory only (bounded)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents.strategist import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebAction, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
BASE = "http://10.10.10.5/filter"
HEADER = "\n".join(f"<div class='nav-{i}'>navigation item {i}</div>" for i in range(90))
NORMAL = HEADER + "\n<table>\n<tr><td>Product A</td></tr>\n</table>"
RESULT = HEADER + "\n<table>\n<tr><td>RESULT-ROW-1</td><td>value-7f3a</td></tr>\n</table>"


class _Cage:
    def __init__(self, pages):
        self.pages = pages

    def run(self, action):
        status, body = self.pages.get(action.url, (404, "nope"))
        return WebResult(status=status, url=action.url, headers={}, body=body)


class _LLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


def _session(pages):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_LLM()),
                         browser=GovernedBrowser(scope, _Cage(pages), audit))


def test_note_shows_the_result_region_after_a_normal_request():
    q_normal, q_probe = f"{BASE}?category=Gifts", f"{BASE}?category=Gifts%27+UNION"
    s = _session({q_normal: (200, NORMAL), q_probe: (200, RESULT)})
    s.run_web(f"get {q_normal}")
    s.run_web(f"get {q_probe}")
    note = s.notes[-1]
    assert "RESULT-ROW-1" in note
    assert "navigation item 0" not in note.split("\n", 2)[-1]


def test_without_a_baseline_the_end_of_the_page_is_visible():
    q = f"{BASE}?category=x"
    s = _session({q: (200, RESULT)})
    s.run_web(f"get {q}")
    assert "RESULT-ROW-1" in s.notes[-1]


def test_same_request_is_not_its_own_baseline():
    q_normal, q_probe = f"{BASE}?category=Gifts", f"{BASE}?category=Gifts%27+UNION"
    s = _session({q_normal: (200, NORMAL), q_probe: (200, RESULT)})
    s.run_web(f"get {q_normal}")
    s.run_web(f"get {q_probe}")
    s.run_web(f"get {q_probe}")                     # repeated: baseline is still NORMAL
    assert "RESULT-ROW-1" in s.notes[-1] and "changed region" in s.notes[-1]


def test_error_responses_are_not_baselines():
    s = _session({})
    a1 = WebAction(kind="get", url=f"{BASE}?category=bad")
    a2 = WebAction(kind="get", url=f"{BASE}?category=Gifts")
    assert s._web_baseline(a1, 500, "<h1>Internal Server Error</h1>") is None
    assert s._web_baseline(a2, 200, NORMAL) is None   # the 500 was not remembered


def test_short_bodies_are_unchanged_in_the_note():
    q = f"{BASE}?category=short"
    s = _session({q: (200, "<p>tiny</p>")})
    s.run_web(f"get {q}")
    assert s.notes[-1].endswith("<p>tiny</p>")


def test_baseline_memory_is_bounded():
    s = _session({})
    for i in range(100):
        for j in range(5):
            a = WebAction(kind="get", url=f"http://10.10.10.5/p{i}?v={j}")
            s._web_baseline(a, 200, "x" * 300_000)
    store = s._endpoint_bodies
    assert len(store) <= 64
    assert all(len(v) <= 3 for v in store.values())
    assert all(len(b) <= 200_000 for v in store.values() for _k, b in v)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_web_note_view.py -q -p no:cacheprovider`
Expected: FAIL — `RESULT-ROW-1` not in the note (head slice), and `AttributeError: ... '_web_baseline'`.

- [ ] **Step 3: Implement**

In `brukal/assist_web.py`, add this method to the same class that defines `_absorb_web` (directly above `_absorb_web`):

```python
    _BASELINE_ENDPOINTS = 64
    _BASELINE_PER_ENDPOINT = 3
    _BASELINE_MAX_CHARS = 200_000

    def _web_baseline(self, action, status, body: str):
        """The most recent earlier 2xx body for the same scheme+host+path from a
        DIFFERENT request (method/url/body), or None — and remember `body` for later
        when `status` is 2xx. In memory only, bounded; it holds response bodies this
        session already received (as `result.body` does) and is never persisted."""
        from urllib.parse import urlsplit
        url = getattr(action, "url", "") or ""
        try:
            p = urlsplit(url)
        except ValueError:
            return None
        if not p.scheme or not p.netloc:
            return None
        endpoint = f"{p.scheme}://{p.netloc}{p.path}"
        key = (str(getattr(action, "method", "") or "GET").upper(), url,
               str(getattr(action, "body", "") or ""))
        store = getattr(self, "_endpoint_bodies", None)
        if store is None:
            store = self._endpoint_bodies = {}
        prior = store.get(endpoint, [])
        baseline = next((b for k, b in reversed(prior) if k != key), None)
        if isinstance(status, int) and 200 <= status < 300:
            kept = [(k, b) for k, b in prior if k != key]
            kept.append((key, (body or "")[:self._BASELINE_MAX_CHARS]))
            store.pop(endpoint, None)
            store[endpoint] = kept[-self._BASELINE_PER_ENDPOINT:]
            while len(store) > self._BASELINE_ENDPOINTS:
                store.pop(next(iter(store)))
        return baseline
```

In `_absorb_web`, inside `if result is not None:`, directly after `body = (result.body or "").strip()` add:

```python
            from .response_view import salient_view
            try:
                baseline = self._web_baseline(action, getattr(result, "status", None), body)
            except Exception:
                baseline = None
```

replace

```python
            self.notes.append(f"[web] {action.describe()}\n{head}\n{body[:600]}")
```

with

```python
            # What the model READS of the response: the changed region vs an earlier
            # response to the same page, else its start AND end — not body[:600], which
            # on 2026-10-01 showed only a page header while the result sat at the end.
            self.notes.append(f"[web] {action.describe()}\n{head}\n"
                              f"{salient_view(body, baseline, 600)}")
```

and replace

```python
            summary = f"{lead}\n{body[:800]}" if body else lead
```

with

```python
            summary = f"{lead}\n{salient_view(body, baseline, 800)}" if body else lead
```

In the spec, replace the §3.2 bullet that begins `- **Baseline selection**` with:

```markdown
- **Baseline selection** (helper `AssistSession._web_baseline`): the most recent earlier 2xx
  response body for the same scheme+host+path from a DIFFERENT request (method, URL or body),
  held in a bounded in-memory map (≤ 64 endpoints, ≤ 3 bodies each, each ≤ 200,000 chars; never
  persisted). *Amended during planning:* the capture store cannot serve as the baseline because it
  now holds head+tail only, and diffing a full body against a head+tail baseline reports the
  missing middle as "changed" noise ahead of the real result. A diff that marks more than 80% of
  lines changed falls back to head+tail (it says nothing useful).
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_web_note_view.py tests/test_finding_body_capture.py tests/test_manual_web_line.py tests/test_session_shape.py -q -p no:cacheprovider`
Expected: all PASS. `.venv/bin/python -m pyflakes tests/test_web_note_view.py` → no output.

- [ ] **Step 5: Commit**

```bash
git add brukal/assist_web.py tests/test_web_note_view.py docs/superpowers/specs/2026-10-12-response-visibility-design.md
git commit -m "feat(web): the model note and vault summary show the changed region / start+end"
```

---

### Task 4: One consistent MANUAL rule in the strategist prompt

**Files:**
- Modify: `brukal/agents/strategist.py:126-127`
- Test: `tests/test_strategist_manual_rule.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `STRATEGIST_SYSTEM` text with the new rule sentence.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_strategist_manual_rule.py
"""The strategist prompt states ONE rule for MANUAL.

It said both 'give MANUAL for intrusive/interactive work' and, later, 'use MANUAL ONLY
for steps the cage truly cannot do' — a model following the first sentence hands
in-scope exploitation back. Risky steps reach the operator through the gate's
ESCALATE path anyway."""
from brukal.agents.strategist import STRATEGIST_SYSTEM


def test_old_contradictory_sentence_is_gone():
    assert "give MANUAL for intrusive/interactive" not in STRATEGIST_SYSTEM


def test_new_rule_says_risky_steps_are_paused_by_the_gate():
    assert "Give RUN or WEB for in-scope actions, including exploitation" in STRATEGIST_SYSTEM
    assert "Give MANUAL only for steps the cage cannot perform" in STRATEGIST_SYSTEM


def test_the_detailed_manual_guidance_is_still_present():
    assert "Use MANUAL ONLY for steps the cage truly cannot do" in STRATEGIST_SYSTEM
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_strategist_manual_rule.py -q -p no:cacheprovider`
Expected: FAIL on the first two tests.

- [ ] **Step 3: Implement**

In `brukal/agents/strategist.py` replace

```python
    "Give RUN for safe in-scope enumeration; give MANUAL for intrusive/interactive "
    "work. Prefer ONE clear next step. A separate gate still rules on any RUN.\n\n"
```

with

```python
    "Give RUN or WEB for in-scope actions, including exploitation — the gate pauses "
    "risky or irreversible steps for the operator's sign-off. Give MANUAL only for "
    "steps the cage cannot perform (see the end of these instructions). Prefer ONE "
    "clear next step. A separate gate still rules on any RUN or WEB.\n\n"
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_strategist_manual_rule.py tests/test_assist.py -q -p no:cacheprovider`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add brukal/agents/strategist.py tests/test_strategist_manual_rule.py
git commit -m "fix(prompt): one consistent MANUAL rule -- risky steps go through the gate's ESCALATE"
```

---

### Task 5: Whole-change verification

**Files:** none modified unless a check fails.

- [ ] **Step 1: Full suite** — `.venv/bin/python -m pytest -q -p no:cacheprovider` → expect `2644 + new tests passed, 1 skipped, 1 xfailed`, no failures.
- [ ] **Step 2: Four metrics** — `.venv/bin/python run_experiments.py | grep -E 'interception_rate|unsafe_actions_prevented|context_reduction|adaptive_trust_final'` → `1.0`, `5`, `0.976`, `0.343` (unchanged).
- [ ] **Step 3: Gate untouched** — `git diff main --stat -- brukal/gate.py brukal/hostmatch.py brukal/scope.py brukal/risk.py brukal/executor.py brukal/audit.py` → empty; `.venv/bin/python benchmarks/replay_gate_corpus.py main | tail -1` → `0 NEW, 0 LOST, 0 UNSEEN … 0 stricter, 0 looser`.
- [ ] **Step 4: pyflakes** on every touched file → no new warnings.
- [ ] **Step 5: Record** — append a dated entry to the vault `Brukal.md` running log and update `NEXT.md` (DONE entry; TOP → Part 2 design remains with the maintainer; queue: human-gated live re-run measuring MANUAL hand-backs before/after on a self-hosted lab). Commit `NEXT.md`:

```bash
git add NEXT.md
git commit -m "docs(next): response visibility shipped (part 1)"
```
