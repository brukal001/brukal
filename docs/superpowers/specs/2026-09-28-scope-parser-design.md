# SP-B — LLM/TypeSafe scope-parser (design spec)

**Date:** 2026-09-28 · **Status:** design → build · **Part B of the A→B→C scope pipeline.**

## 1. Intent
A user pastes a free-text bug-bounty program description (e.g. the CoinDCX page). Brukal produces a
**draft `scope.json` (SP-A schema, `authorized:false`) + a human-readable `scope_rules.md`** with a
**REVIEW REQUIRED** list; a human approves; then SP-A's deterministic gate enforces the frozen result.
This is the "ML converts random text → JSON" step.

## 2. The invariant that shapes everything (agreed reframe)
- The model/TypeSafe runs **once, at authoring time, model-side** — it only **drafts**.
- The draft is **deterministically validated + normalized** (fail-closed: ambiguous/unparseable → NOT
  in scope) and stays **`authorized:false`** until a **human approves** it. An unauthorized scope is
  already refused by the run path (SP-A/CLAUDE.md), so a bad draft cannot drive a live run.
- **No model output ever reaches the runtime gate.** A poisoned/ambiguous description can only mis-draft
  (surfaced for review); human approval + deterministic validation + the frozen JSON contain it.

## 3. Decisions (maintainer, 2026-09-28)
1. **Engine:** TypeSafe System One (Jev) **primary**, with a deterministic/LLM **fallback** when the
   TypeSafe key/endpoint is absent. Keys server-side.
2. **Approval:** a **`brukal scope approve <file>`** command sets `authorized:true` + records
   approver+timestamp; the human reviews `scope_rules.md` first.
3. **Tests:** a **stub judge** (no live TypeSafe call, no spend, deterministic) drives the suite, plus a
   **documented manual live check**. No live call in CI.

## 4. TypeSafe contract (grounding for the adapter)
`POST https://api.typesafe.ai/v1/systemone`, `Authorization: Bearer <key>`, body
`{state, model:"jev-latest", questions:{id:{type,instructions,criteria}}}`:
- **noul** `criteria:{true,desc; false,desc}` → answer `{noul: <prob 0..1>}`
- **choice** `criteria:{opt:desc,…}` → answer `{choice, probabilities, confidence}`
- **score** `criteria:[levels…]` → answer `{score, legend, probabilities, confidence}`
Response `{model, answers:{id:…}, usage}`.

## 5. Components
- **`brukal/scope_judge.py`** — a judge interface `Judge.ask(state, questions) -> answers` returning
  normalized typed answers `{id: {"kind","value","confidence"}}` (noul→value=prob, choice→value+conf,
  score→value+conf). Two impls: `TypeSafeJudge` (POSTs the contract above; key from `TYPESAFE_API_KEY`;
  network/parse errors raise `JudgeUnavailable`), and `DeterministicJudge` (a keyword fallback used when
  no key / on `JudgeUnavailable`, and as the test stub). Selection: `make_judge()` → TypeSafe if key
  present else Deterministic; a `StubJudge(scripted_answers)` for tests.
- **`brukal/scope_parse.py`** — the deterministic scaffold:
  1. `segment(description) -> Segments` — pull candidate spans in CODE: asset rows (from a Scopes/Type
     table or bulleted list), out-of-scope lines, qualifying-vuln list, non-qualifying list,
     testing-policy bullets, account/login lines. Regex/heuristic; never invents a value.
  2. `build_questions(segments) -> questions` — per candidate: Choice(asset type ∈
     {wildcard,domain,api,android,ios}), Choice(asset value ∈ {low,medium,high,critical}); Noul per
     out-of-scope line ("host exclusion?" / "path exclusion?"); Noul per testing-policy bullet mapped to
     an envelope flag (`no_automated_scanners`, `no_high_traffic`, `read_only`, `pii_redaction`) and to
     `forbidden:dos`. Vuln-class names are normalized by **SP-A's deterministic
     `bugclass.normalize_class`** first; the judge is only asked where a name is ambiguous.
  3. `assemble(segments, answers) -> (scope_dict, provenance)` — build the SP-A schema:
     `assets`/`authorized_hosts` (literal patterns copied from the text), `exclusions` (host + `{host,
     path_prefix}`), `allowed_classes`/`forbidden_classes` (normalized), `envelope`. `authorized:false`.
     A `_provenance` block records per field: source span + engine + confidence.
  4. `validate(scope_dict) -> (clean_dict, review_items)` — fail-closed: every asset pattern must parse;
     unknown class names DROP (never invent); any low-confidence (< threshold) or unparseable item is a
     **review_item**, excluded from the enforced fields until the human confirms. An asset that fails to
     validate authorizes nothing.
  5. `render_rules_md(scope_dict, provenance, review_items) -> str` — the human-readable mirror + a
     `## REVIEW REQUIRED` section listing every flagged item with its span + confidence.
- **CLI (`brukal scope …` in the CLI layer):**
  - `brukal scope draft <description-file> [--out scope.<program>.json]` → writes the JSON
    (`authorized:false`) + `scope_rules.md`; prints the REVIEW REQUIRED count.
  - `brukal scope approve <scope.json> [--as <name>]` → after the human has read the rules, sets
    `authorized:true`, stamps `approved_by`/`approved_at`, re-validates, and rewrites the file. Refuses
    if any review_item is still unresolved (fail-closed).

## 6. Output contract
- `scope.<program>.json` — SP-A schema, `authorized:false` until approved, `_provenance` block.
- `scope_rules.md` — human mirror + REVIEW REQUIRED.

## 7. Governance guardrails
- SP-B performs **no network/live action against a target** and never touches the cage, gate, executor,
  or audit spine. It reads text and writes two files.
- The parse is advisory; the deterministic validator + human `approve` are the authority.
- TypeSafe/LLM call is model-side only; key server-side; on any judge error → deterministic fallback,
  never a crash, and low-confidence → review, never silent inclusion.

## 8. Tests (offline, stub judge)
Feed a CoinDCX-like description; assert the produced `scope.json`: assets include `*.coindcx.com` +
`api.coindcx.com` + the two mobile apps; `exclusions` include `info.coindcx.com`, `otcdesk.coindcx.com`,
`careers.coindcx.com`, and `{coindcx.com,/blog}`; `allowed_classes` ⊇ {sqli,xss,rce,idor,ssrf,csrf,
open_redirect,business_logic}; `forbidden_classes` ⊇ {dos}; `envelope` ⊇ {no_automated_scanners,
read_only}; `authorized:false`; a non-empty REVIEW REQUIRED list. Assert `scope approve` flips
`authorized:true` + stamps approver, and refuses while a review_item is unresolved. Assert an
unapproved (`authorized:false`) scope is refused by the run/authorization path. `TypeSafeJudge` unit-
tested against a mocked HTTP response (no live call); `make_judge()` returns Deterministic when the key
is absent. Full existing suite stays green.

## 9. Out of scope for SP-B
- SP-C real-internet containment (separate). Actually running against a real program. Non-web asset
  (mobile app) *testing* — SP-B only records the asset. A perfect NL parser — ambiguity goes to REVIEW.
