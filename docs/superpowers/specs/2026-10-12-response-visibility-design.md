# Design — Response visibility (Part 1 of "finish the chain")

*2026-10-12. Status: DRAFT for maintainer review. Target environments: self-hosted labs and
sandboxed test targets. Build + self-test only; any live validation is human-gated.*

## 1. Problem (measured, not assumed)

In the 2026-10-01 live run against a PortSwigger UNION lab, the model ran the decisive request
itself (`/filter?category=…UNION SELECT…`) and then handed the next step back as MANUAL:
*"view the page source to find the values"*. The ledger shows why:

- the response was **4,447 bytes** and the result rows sit near the **end** of the page;
- the model is shown `body[:600]` (`brukal/assist_web.py:832`) — the page header only;
- the vault summary keeps `body[:800]` (`assist_web.py:844`);
- the capture store keeps `[:4000]` (`brukal/capture.py:150,178`) — it also cut the end, so the
  deterministic provers in `capture_confirm.py` never saw the result either.

A secondary cause: the strategist prompt says both *"give MANUAL for intrusive/interactive work"*
(`brukal/agents/strategist.py:126`) and, later, *"use MANUAL ONLY for steps the cage truly cannot
do"*. A model following the first sentence hands exploitation back.

**The model was not unwilling; it was blind to its own result.**

## 2. Goal and success criteria

Goal: the model and the provers see the part of a response that matters, within today's budgets.

Success (all offline, deterministic):
1. For a page shaped like the 2026-10-01 response (≈4.4 kB, result near the end, a normal response
   to the same page captured earlier), the text the model is shown contains the result region.
2. The capture store retains the end of a long page, so a prover reading `cap.response` can see it.
3. The strategist prompt states one rule for MANUAL; no sentence tells the model to hand back
   intrusive work.
4. No existing test regresses; the four benchmark metrics are unchanged; the gate is untouched
   (the replay corpus therefore stays 0 NEW / 0 LOST / 0 UNSEEN / 0 looser by construction).

Out of scope (Part 2, not specified here): storing values returned by a target for reuse in later
steps, and any approval rule around such reuse. The maintainer's governance decisions for that
work are recorded in the vault and are not changed by this design.

## 3. Components

### 3.1 `brukal/response_view.py` (new, pure, stdlib-only)

```
salient_view(body: str, baseline: str | None, budget: int) -> str
```
- **With a baseline** (an earlier response to the same endpoint): line-level diff
  (`difflib.SequenceMatcher` over lines). Emit the lines that are inserted or replaced in `body`,
  in order, each region prefixed by a one-line marker `… [changed region, line N] …`, until
  `budget` characters. If the diff is empty, fall through to the no-baseline case.
- **Without a baseline, or nothing changed:** head + tail — the first ~60% of the budget, a marker
  `… [N chars omitted] …`, then the last ~40%. A body within budget is returned unchanged.
- The returned text, markers included, is never longer than `budget`.
- Deterministic, no I/O, no LLM, never raises (bad input returns the head-only slice).
- Bounded work: a page with more than 4,000 lines (either side) skips the diff and uses head+tail;
  a diff marking more than 80% of lines changed is uninformative and also falls back to head+tail.

### 3.2 Model-facing note and vault summary (`brukal/assist_web.py`)

- `_absorb_web` replaces `body[:600]` with `salient_view(body, baseline, 600)` and `body[:800]`
  with `salient_view(body, baseline, 800)`. Budgets are unchanged, so prompt size is unchanged.
- **Baseline selection** (helper `AssistSession._web_baseline`): the most recent earlier 2xx
  response body for the same scheme+host+path from a DIFFERENT request (method, URL or body),
  held in a bounded in-memory map (≤ 64 endpoints, ≤ 3 bodies each, each ≤ 200,000 chars; never
  persisted). *Amended during planning:* the capture store cannot serve as the baseline because it
  now holds head+tail only, and diffing a full body against a head+tail baseline reports the
  missing middle as "changed" noise ahead of the real result. A diff that marks more than 80% of
  lines changed falls back to head+tail (it says nothing useful).

### 3.3 Capture store keeps head and tail (`brukal/capture.py`)

- `_record` keeps `_MAX_RESPONSE_KEPT` (4,000) characters as head (2,400) + marker + tail (1,600)
  instead of the first 4,000; the stored text, marker included, never exceeds 4,000 characters. Redaction still runs on the FULL body before slicing (unchanged order).
- Provers read `cap.response` exactly as before. A body ≤ 4,000 characters is stored byte-identical
  to today, so every existing prover test is unaffected.
- Known trade-off (stated, tested): for long pages the boolean differential now compares head+tail
  instead of head only. Dynamic content in the tail (a timestamp, a token) can make a truthy and a
  baseline response differ, turning a confirm into a miss; equally, a result that differs only in
  the tail is now visible, turning a miss into a confirm. Both directions get a test so the effect is
  explicit, not accidental.

### 3.4 Prompt fix (`brukal/agents/strategist.py`)

Replace line 126's rule with: *"Give RUN or WEB for in-scope actions, including exploitation — the
gate pauses risky or irreversible steps for the operator's sign-off. Give MANUAL only for steps the
cage cannot perform (see the end of these instructions)."* Nothing else in the prompt changes.

## 4. Data flow

```
model proposes WEB → gate (unchanged) → GovernedBrowser runs it
   → capture._record: redact(full body) → head+tail (≤4,000) → capture store
   → _absorb_web: baseline = _baseline_for(url) from the capture store
        → note   = salient_view(body, baseline, 600)  → strategist RECENT ACTIVITY
        → vault  = salient_view(body, baseline, 800)
   → provers (_confirm_from_capture) read the capture store, now including the tail
```

## 5. Safety invariants

- **No LLM in the gate:** the gate is not touched. `salient_view` is not a gate component.
- **Fail-closed:** unchanged; `salient_view` failing degrades to a head slice (today's behaviour).
- **Self-report never trusted:** the view is computed from real gated output only.
- **One execution path:** no new requests; baseline selection reads existing captures.
- **Immutable scope / append-only audit:** untouched. Redaction order is preserved, so no secret
  reaches a record through the new tail.

## 6. Error handling

- `salient_view`: catches every exception internally and returns `body[:budget]`.
- `_baseline_for`: any error → None → head+tail view.
- Capture slicing: pure string operations on an already-redacted string.

## 7. Testing

1. `tests/test_response_view.py` — head+tail shape and marker; within-budget identity; baseline diff
   surfaces an inserted region at the end of a long page; empty diff falls back; budget never
   exceeded; deterministic; garbage input never raises.
2. **The 2026-10-01 shape:** a synthetic 4,447-byte page with a result table near the end, plus an
   earlier normal response to the same path → the model-facing note contains the table rows
   (red before: `body[:600]` does not).
3. Capture store: a 4,447-byte body keeps its tail; a ≤4,000-byte body is byte-identical to today;
   redaction still applied to text that lands in the tail.
4. Prover interaction, both directions: (a) a result that differs only in the tail is now confirmed
   by `boolean_sqli_differential`; (b) dynamic tail content (a changing timestamp) — the test pins the
   new behaviour explicitly and documents it.
5. Prompt: a test asserts the old "give MANUAL for intrusive" sentence is gone and the MANUAL rule
   appears once.
6. Full suite, `run_experiments.py` four metrics, pyflakes on touched files;
   `benchmarks/replay_gate_corpus.py` unchanged (no gate change).

## 8. Follow-on (not in this design)

- A human-gated live re-run on a self-hosted or sandboxed lab to measure: how often the model now
  proposes the next step itself instead of MANUAL, with and without this change (same model/seed).
- Correct `NEXT.md`: the earlier note that "the capture store was fine" was wrong (4,447 > 4,000).
