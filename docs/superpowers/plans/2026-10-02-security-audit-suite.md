# Security-Audit Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline adversarial test suite that red-teams Brukal's deterministic authorization core, run it (TRY), root-cause every bypass (ANALYZE), save it all as a committed "before" baseline (SAVE), then fix each genuine bypass (FIX) — turning the "model proposes, deterministic gate disposes" claim into a tested, evidenced result.

**Architecture:** A `tests/security/` pytest package, one module per invariant/attack-class, each exercising the REAL `scope`/`gate`/`web.check_web`/`audit`/`capture_confirm`/`risk` with `FakeKali`/`FakeCDP` (no live model/target/Docker/network). A shared harness records every case to `security_results.json`. Any input that defeats a safe outcome is a documented FINDING (marked `xfail(strict)` so the suite stays green while the bypass is recorded), fixed only in Phase 4 as its own commit after the finding is committed.

**Tech Stack:** Python 3.12 stdlib + pytest. Static-analysis modules use `ast`/`importlib`. No new third-party deps.

**Spec:** `docs/superpowers/specs/2026-10-02-security-audit-suite-design.md`

## Global Constraints

- **Offline, deterministic, build+self-test ONLY.** No live model, target, Docker, or network. Every test uses the real `brukal` security modules + `FakeKali`/`FakeCDP`. Run with `.venv/bin/python -m pytest tests/security/ -v`.
- **Read-only on `brukal/` security code through Phases 1–3.** Only Phase-4 FIX tasks may modify security modules, and only to fix a bypass already reproduced + documented + committed, preserving all five invariants (deterministic gate, fail-closed, no agent→kali, immutable scope, append-only audit).
- **The bypass/xfail convention (how a red stays honest AND keeps the suite green):** a test asserts the SAFE outcome. If it is red: root-cause it. (a) A genuine bypass → mark the test `@pytest.mark.xfail(strict=True, reason="FINDING SEC-NNN: <one line>; see SECURITY_AUDIT.md")` and record the finding — the suite stays green (xfail is expected), the bypass is captured in `security_results.json` as `result:"FAIL"`, and Phase 4's fix later REMOVES the xfail so the test genuinely passes (the xfail→pass transition is the before/after). (b) A red caused by a bug in the test itself → fix the test. **Never weaken an assertion to match buggy behavior; never `xfail` a red whose root cause you have not confirmed is a real bypass — if ambiguous, stop and ask.**
- **Every module carries a POSITIVE CONTROL** — a genuinely in-scope / well-formed / correctly-confirmed input the system SHOULD allow/confirm — so the module cannot pass by trivially denying everything.
- **`security_results.json` is generated**, never hand-written: `record` is a **conftest fixture** (not a package import — avoids pytest import-path fragility); every test takes `record` as a parameter and calls it once per case; a `pytest_sessionfinish` hook writes the file from the accumulator.
- **Verify the REAL signatures** of `gate`/`scope`/`web.check_web`/`audit`/`capture_confirm`/`risk` before asserting (a stub would misrepresent the system). Read each module first.
- Keep the existing full suite green; pyflakes clean on new files. Branch `feat/security-audit-suite`.
- **Commit messages end with:**
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Proevkjj8tujNYeExuys6m
  ```
  (per-task commits abbreviate it as `<attribution>`.)

## Review Focus

Failure modes the suite itself could have — pinned to owning tasks:
1. **Trivially-green module** (asserts denial of everything, no positive control) → false confidence. Each module's positive control (Tasks 1–7) guards this; the reviewer checks the control actually exercises an ALLOW/CONFIRM path.
2. **Stub instead of real component** → the test misrepresents the system. Tasks 1–7: assert the import is the real `brukal.*` object, not a local fake of the gate/scope.
3. **Static-scan allowlist wrong** → false-fail on legitimate executor sites OR false-pass missing a new exec path. Task 4: the scan includes a self-test that an injected violation IS caught.
4. **`security_results.json` drifts from the run** → Task 1: the hook writes from the live accumulator; a test asserts the file's counts equal the collected records.
5. **`xfail` masking a test-bug red as a "finding"** → mislabeled result. Tasks 1–7 + Task 8: an `xfail` is only added after a confirmed genuine bypass; Task 8's audit cross-checks every `xfail` reason against a real root cause.

---

### Task 1: harness + `conftest` results-collector + `test_scope_escape.py` (reference module)

**Files:**
- Create: `tests/security/conftest.py`, `tests/security/test_scope_escape.py`

**Interfaces:**
- Produces: a `record` pytest fixture (function-scoped) returning a callable `record(test_id, category, invariant, input_repr, expected, actual, severity) -> bool` that appends a dict to a session accumulator (`result` = `"PASS" if expected==actual else "FAIL"`); a `pytest_sessionfinish` hook writing `security_results.json` (repo root). Later tasks take the `record` fixture as a test parameter (no import).

- [ ] **Step 1: Read the real `scope` API.** Read `brukal/scope.py` — note the exact constructor and membership calls (`Scope(...)`, `in_scope`/`contains_ip`/`contains_host`, `_norm_host`) and how a `Scope` is built from `authorized_cidrs`/`authorized_hosts`. Note how `web.check_web` is called (read `brukal/web.py`). Do not assume — use what the code shows.

- [ ] **Step 2: Write `conftest.py`** (the `record` fixture + the json-writing hook; auto-discovered by pytest, so no import-path issues).

```python
# tests/security/conftest.py
import json, pathlib
import pytest

_RESULTS: list[dict] = []

@pytest.fixture
def record():
    def _record(test_id, category, invariant, input_repr, expected, actual, severity):
        _RESULTS.append({
            "test_id": test_id, "attack_category": category, "security_invariant": invariant,
            "input": input_repr, "expected_result": expected, "actual_result": actual,
            "severity": severity, "result": "PASS" if expected == actual else "FAIL",
            "reproducible": True,
        })
        return actual == expected
    return _record

def pytest_sessionfinish(session, exitstatus):
    out = pathlib.Path(__file__).resolve().parents[2] / "security_results.json"
    try:
        out.write_text(json.dumps({"records": _RESULTS, "total": len(_RESULTS),
                                   "failed": sum(1 for r in _RESULTS if r["result"] == "FAIL")},
                                  indent=2), encoding="utf-8")
    except OSError:
        pass
```

- [ ] **Step 3: Write `test_scope_escape.py`** — the reference module (corpus + positive control + record + the real Scope).

```python
# tests/security/test_scope_escape.py   (test fns take the `record` conftest fixture — no import)
import pytest
from brukal.scope import Scope

# One in-scope host and one in-scope CIDR; everything in OUT must NOT be authorized.
IN_HOST = "app.in-scope.example"
IN_CIDR = "10.10.10.0/24"

def _scope():
    return Scope(authorized_cidrs=[IN_CIDR], authorized_hosts=[IN_HOST])  # adjust to real ctor

OUT = [
    ("localhost", "loopback alias"), ("127.0.0.1", "loopback"), ("0.0.0.0", "any"),
    ("::1", "v6 loopback"), ("::ffff:127.0.0.1", "v4-mapped v6"),
    ("2130706433", "decimal IP for 127.0.0.1"), ("0x7f000001", "hex IP"),
    ("0177.0.0.1", "octal IP"), ("app.in-scope.example.", "trailing dot"),
    ("APP.IN-SCOPE.EXAMPLE.evil.com", "subdomain confusion"),
    ("10.10.11.0", "CIDR off-by-one (adjacent /24)"),
    ("10.10.10.255", "CIDR broadcast still in /24 — IN, control below"),
    ("evil.example", "unrelated host"),
]

@pytest.mark.parametrize("host,desc", [(h, d) for h, d in OUT if h not in (IN_HOST, "10.10.10.255")])
def test_out_of_scope_representations_are_denied(record, host, desc):
    s = _scope()
    actual = "ALLOW" if s.in_scope(host) else "DENY"   # use the real membership call
    record(f"scope-escape::{host}", "scope-escape", "I3/I5", f"{host} ({desc})",
           "DENY", actual, "critical")
    assert actual == "DENY", f"out-of-scope {host!r} ({desc}) was authorized"

def test_positive_control_in_scope_host_is_allowed(record):
    s = _scope()
    actual = "ALLOW" if s.in_scope(IN_HOST) else "DENY"
    record("scope-escape::positive-host", "scope-escape", "I3/I5", IN_HOST, "ALLOW", actual, "n/a")
    assert actual == "ALLOW", "the genuine in-scope host must remain authorized (no false-deny)"

def test_positive_control_in_cidr_ip_is_allowed(record):
    s = _scope()
    actual = "ALLOW" if s.in_scope("10.10.10.42") else "DENY"
    record("scope-escape::positive-cidr", "scope-escape", "I3/I5", "10.10.10.42", "ALLOW", actual, "n/a")
    assert actual == "ALLOW"
```

- [ ] **Step 4: Run it and triage**

Run: `.venv/bin/python -m pytest tests/security/test_scope_escape.py -v`
For any failing out-of-scope case: confirm whether `brukal/scope.py` genuinely authorizes it (a real bypass) or the test used the wrong membership call. Genuine bypass → add `@pytest.mark.xfail(strict=True, reason="FINDING SEC-001: <host> authorized; see SECURITY_AUDIT.md")` to that param case and note it; test error → fix the call. Positive controls MUST pass. Expected: file written at `security_results.json` with the records.

- [ ] **Step 5: Commit**

```bash
git add tests/security/conftest.py tests/security/test_scope_escape.py
git commit -m "test(security): results harness + scope-escape adversarial module (I3/I5)

<attribution>"
```

---

### Task 2: `test_parser_target_smuggling.py` (I3)

**Files:** Create `tests/security/test_parser_target_smuggling.py`
**Interfaces:** Consumes the `record` conftest fixture (test fns take it as a param); the REAL gate command-check entry (read `brukal/gate.py` for how a shell command is gated and where it extracts targets — use that exact call).

- [ ] **Step 1: Read `brukal/gate.py`** — find the command-gating entry and the target-extraction (the "re-scan every IP in the command" logic, CLAUDE.md). Note the decision object (verdict field values).

- [ ] **Step 2: Write the module** — declared target in-scope, command text reaches an out-of-scope target; gate must DENY (or fail closed). Positive control: a clean in-scope single-target command ALLOWs.

```python
# tests/security/test_parser_target_smuggling.py   (test fns take the `record` conftest fixture)
import pytest
# from brukal.gate import <the real command-gate entry>  # fill from Step 1
# from brukal.scope import Scope

IN = "10.10.10.10"; OUT = "10.10.10.11"   # OUT is NOT in a single-host scope of IN
CASES = [
    (f"nmap {IN} {OUT}", "second positional target"),
    (f"nmap {IN}; curl {OUT}", "; chain"),
    (f"nmap {IN} && nc {OUT} 80", "&& chain"),
    (f"nmap {IN} | tee /tmp/x; curl {OUT}", "pipe + chain"),
    (f"bash -c 'curl {OUT}'", "nested shell"),
    (f"curl $(echo {OUT})", "command substitution"),
    (f"curl `echo {OUT}`", "backtick substitution"),
    (f"nmap {IN} 10.10.10.0/24", "CIDR expands past single host"),
    (f"curl http://{OUT}/", "url target"),
]

@pytest.mark.parametrize("cmd,desc", CASES)
def test_smuggled_out_of_scope_target_is_denied(record, cmd, desc):
    # gate the command against a single-host scope of IN; verdict must not be ALLOW
    verdict = _gate_verdict(cmd, scope_host=IN)   # helper wrapping the real gate, from Step 1
    record(f"parser::{desc}", "parser-target-smuggling", "I3", cmd, "not ALLOW", verdict, "critical")
    assert verdict != "ALLOW", f"smuggled OUT target via {desc!r} was ALLOWed: {cmd!r}"

def test_positive_control_clean_in_scope_command_allows(record):
    verdict = _gate_verdict(f"nmap {IN}", scope_host=IN)
    record("parser::positive", "parser-target-smuggling", "I3", f"nmap {IN}", "ALLOW", verdict, "n/a")
    assert verdict == "ALLOW", "a clean single in-scope target must be allowed (no false-deny)"
```
(Write `_gate_verdict` as a thin local helper that calls the REAL gate and maps its decision object to `"ALLOW"`/`"DENY"`/`"ESCALATE"`/`"ERROR"` — not a reimplementation of the gate.)

- [ ] **Step 3: Run + triage** — `.venv/bin/python -m pytest tests/security/test_parser_target_smuggling.py -v`. Any ALLOW on a smuggled target = genuine I3 bypass → xfail(strict, FINDING SEC-NNN) + note. Unparseable that ERRORs is fine (fail-closed). Positive control passes.

- [ ] **Step 4: Commit** `git add … && git commit -m "test(security): parser target-smuggling adversarial module (I3)\n\n<attribution>"`

---

### Task 3: `test_fail_closed.py` (I2)

**Files:** Create `tests/security/test_fail_closed.py`
**Interfaces:** Consumes the `record` conftest fixture (test fns take it as a param); the REAL action-request schema/validation + gate (read how an Action Request is parsed/validated — `brukal/schema.py` + gate).

- [ ] **Step 1: Read the action schema + validation path** (`brukal/schema.py` / wherever the pydantic Action Request lives, and how the gate receives it).

- [ ] **Step 2: Write the module** — malformed inputs must resolve to DENY or a handled ERROR, never ALLOW/execute. Positive control: a well-formed benign in-scope action ALLOWs.

```python
# tests/security/test_fail_closed.py   (test fns take the `record` conftest fixture)
import pytest
MALFORMED = [
    ("bad json", "{not json"), ("missing required field", {"action": "web"}),
    ("unexpected extra field", {"...valid...": "...", "evil": "x"}),
    ("null value", {"target": None}), ("type confusion", {"target": 12345}),
    ("invalid enum", {"kind": "no_such_kind"}), ("oversized", {"target": "A" * 100000}),
    ("unicode trick", {"target": "10.10.10.10 ; rm -rf /"}), ("empty", {}),
]
@pytest.mark.parametrize("desc,payload", MALFORMED)
def test_malformed_action_never_allows(record, desc, payload):
    outcome = _resolve(payload)   # parse+gate via the REAL path; returns ALLOW/DENY/ESCALATE/ERROR
    record(f"fail-closed::{desc}", "fail-closed", "I2", repr(payload)[:120],
           "not ALLOW", outcome, "critical")
    assert outcome in ("DENY", "ESCALATE", "ERROR"), f"{desc} resolved to {outcome}"

def test_positive_control_wellformed_in_scope_action_allows(record):
    outcome = _resolve(_valid_in_scope_action())   # a genuine valid action
    record("fail-closed::positive", "fail-closed", "I2", "<valid in-scope action>", "ALLOW", outcome, "n/a")
    assert outcome == "ALLOW"
```
(`_resolve`/`_valid_in_scope_action` wrap the real parse+gate path from Step 1.)

- [ ] **Step 3: Run + triage** — any malformed input that ALLOWs/executes = critical I2 bypass → xfail(strict, FINDING) + note. Positive control passes.
- [ ] **Step 4: Commit** `test(security): fail-closed adversarial module (I2)`

---

### Task 4: `test_executor_single_path.py` (I4) + `test_i1_no_llm_in_gate.py` (I1) — static modules (batched)

**Files:** Create `tests/security/test_executor_single_path.py`, `tests/security/test_i1_no_llm_in_gate.py`
**Interfaces:** Consumes the `record` conftest fixture (test fns take it as a param); uses `ast`/`importlib` over the `brukal/` package.

- [ ] **Step 1: Enumerate the legitimate exec/socket sites.** Grep `brukal/` for `subprocess`, `os.system`, `os.exec`, `eval(`, `exec(`, `shell=True`, `socket.socket`. Record which modules legitimately contain them (expected: `executor.py`, `kali.py`, the cage/door modules, `oob.py`, `cdp.py`) — this becomes the `ALLOWED_EXEC_MODULES` allowlist. Identify the gate/scope/executor-decision modules for the I1 import check.

- [ ] **Step 2: Write `test_executor_single_path.py`** (I4): an AST walk over every `brukal/*.py` asserting no `subprocess`/`os.system`/`os.exec*`/`eval`/`exec`/`shell=True`/`socket.socket` outside `ALLOWED_EXEC_MODULES`; plus: agent modules (`brukal/agents/*.py`) do not import `brukal.kali`. Include a **self-test** (Review Focus #3): run the same AST check over a tiny inline snippet containing `os.system("x")` and assert the checker flags it (proves the scan isn't vacuously passing).

```python
# tests/security/test_executor_single_path.py  (sketch — fill ALLOWED_EXEC_MODULES from Step 1; test fns take `record`)
import ast, pathlib
ALLOWED_EXEC_MODULES = {"executor.py", "kali.py", "chrome.py", "cdp.py", "oob.py", "web.py"}  # confirm
BANNED = {"system", "popen"}  # os.system/os.popen; plus subprocess.*, eval, exec, shell=True, socket.socket
def _violations(src, modname): ...  # AST: flag banned calls / shell=True kw / socket.socket
def test_no_exec_path_outside_executor(record):
    bad = []
    for p in pathlib.Path("brukal").glob("**/*.py"):
        if p.name in ALLOWED_EXEC_MODULES: continue
        bad += [(p.name, v) for v in _violations(p.read_text(), p.name)]
    record("i4::exec-scan", "executor-single-path", "I4", f"{len(bad)} violations", "0", str(len(bad)), "critical")
    assert not bad, f"exec/socket outside executor path: {bad}"
def test_self_test_checker_catches_injected_violation():
    assert _violations("import os\nos.system('x')\n", "fake.py"), "checker is vacuous"
def test_agents_do_not_import_kali(record):
    ...  # AST import scan over brukal/agents/*.py asserting no `import brukal.kali`
```

- [ ] **Step 3: Write `test_i1_no_llm_in_gate.py`** (I1): build the transitive import set of `brukal.gate`, `brukal.scope`, and the decision path of `brukal.executor`, and assert none transitively import an LLM/model module (`llm`, `anthropic`, `openai`, `openrouter`, model clients). Self-test: assert the import-graph helper DOES report a known LLM import when pointed at an agent module that legitimately uses one.

- [ ] **Step 4: Run + triage** — a violation is a genuine I4/I1 finding → xfail(strict, FINDING) + note (do NOT edit the allowlist to hide a real new exec path; only list genuinely-legitimate pre-existing sites). Self-tests must pass.
- [ ] **Step 5: Commit** `test(security): executor single-path (I4) + no-LLM-in-gate (I1) static modules`

---

### Task 5: `test_audit_integrity.py` (I5)

**Files:** Create `tests/security/test_audit_integrity.py`
**Interfaces:** Consumes the `record` conftest fixture (test fns take it as a param); the REAL `brukal/audit.py` (hash-chained ledger + `verify()` + append API).

- [ ] **Step 1: Read `brukal/audit.py`** — the record shape, append call, hash-chain fields, `verify()`.
- [ ] **Step 2: Write the module** — build a valid chained ledger (positive control: `verify()` True), then each tamper must make `verify()` False: edit a field in a middle record, reorder two records, delete a middle record, truncate the tail, corrupt a hash.

```python
# tests/security/test_audit_integrity.py  (sketch — use the real append/verify API from Step 1; test fns take `record`)
def test_positive_control_intact_chain_verifies(record):
    log = _build_chain(5)
    record("i5::intact", "audit-integrity", "I5", "5 valid records", "VERIFY_OK", "VERIFY_OK" if log.verify() else "VERIFY_FAIL", "n/a")
    assert log.verify()
def test_edited_field_breaks_verify(): ...   # mutate a recorded field -> verify() False
def test_reorder_breaks_verify(): ...
def test_delete_breaks_verify(): ...
def test_truncate_breaks_verify(): ...
```
Each tamper test records expected `"VERIFY_FAIL"` vs actual and asserts `not log.verify()`.

- [ ] **Step 3: Run + triage** — a tamper that `verify()` still passes = I5 finding → xfail(strict, FINDING) + note. Positive control passes.
- [ ] **Step 4: Commit** `test(security): audit-integrity adversarial module (I5)`

---

### Task 6: `test_confirmation_integrity.py` (confirmation invariant)

**Files:** Create `tests/security/test_confirmation_integrity.py`
**Interfaces:** Consumes the `record` conftest fixture (test fns take it as a param); the REAL `brukal/capture_confirm.py` provers + `CapturedRequest`. Read the existing `tests/test_a_captured_model_cannot_move_the_gate.py` to avoid duplication and reuse its construction helpers.

- [ ] **Step 1: Read `capture_confirm.py`** — the provers (`is_solved_banner`, boolean-SQLi differential, reflected) and their positive-control requirement; how a confirmed finding is produced.
- [ ] **Step 2: Write the module** — a transcript that *claims* success but should NOT confirm: (a) missing positive control, (b) stale/another-run evidence, (c) target/param mismatch, (d) replayed evidence. Positive control: a genuinely-valid differential/banner WITH its control DOES confirm.

```python
# tests/security/test_confirmation_integrity.py  (sketch)
# each test fn below takes the `record` conftest fixture as a parameter
def test_no_control_does_not_confirm(): ...      # boolean differential w/o a working baseline -> no finding
def test_mismatched_target_does_not_confirm(): ...
def test_stale_evidence_does_not_confirm(): ...
def test_positive_control_valid_differential_confirms(): ...  # the SHOULD-confirm case
```
Each records expected `"NO_CONFIRM"`/`"CONFIRM"` vs actual.

- [ ] **Step 3: Run + triage** — any unsupported CONFIRM = finding → xfail(strict, FINDING). Positive control confirms.
- [ ] **Step 4: Commit** `test(security): confirmation-integrity adversarial module`

---

### Task 7: `test_risk_not_gameable.py` (risk invariant)

**Files:** Create `tests/security/test_risk_not_gameable.py`
**Interfaces:** Consumes the `record` conftest fixture (test fns take it as a param); the REAL `brukal/risk.py` `assess`.

- [ ] **Step 1: Read `brukal/risk.py`** — `assess` inputs (how reversibility/blast-radius are derived) and the score→ALLOW/ESCALATE/DENY mapping.
- [ ] **Step 2: Write the module** — an action with model-declared LOW risk but deterministically irreversible / wide blast radius must still ESCALATE/DENY (risk computed from trusted signals); NaN/inf/negative/overflow risk metadata → fail-closed (not ALLOW). Positive control: a genuinely low-risk reversible in-scope action scores low.

```python
# tests/security/test_risk_not_gameable.py  (sketch)
# each test fn below takes the `record` conftest fixture as a parameter
def test_declared_low_but_irreversible_escalates(): ...
def test_nan_inf_negative_metadata_fails_closed(): ...
def test_positive_control_low_risk_action_scored_low(): ...
```

- [ ] **Step 3: Run + triage** — a gamed LOW that yields ALLOW on a high-impact action = finding → xfail(strict, FINDING). Positive control passes.
- [ ] **Step 4: Commit** `test(security): risk-not-gameable adversarial module`

---

### Task 8: TRY-run + ANALYZE + SAVE — the audit docs (the "before" baseline)

**Files:** Create `SECURITY_AUDIT.md`, `THREAT_MODEL.md`, `RESEARCH_FINDINGS.md` (repo root). Regenerate `security_results.json`.

- [ ] **Step 1: Run the whole suite** `.venv/bin/python -m pytest tests/security/ -v` and confirm `security_results.json` is written with every case. Note the green/xfail split; the xfails ARE the bypasses (each has a `FINDING SEC-NNN` reason).

- [ ] **Step 2: Write `SECURITY_AUDIT.md`** — for each invariant (I1–I5 + confirmation + risk): PASS / FAIL / PARTIAL / NOT-TESTABLE with the case count and representative evidence. A Findings section: for each `xfail` bypass, an entry `{SEC-NNN, severity, component, minimal repro, root cause (verified in code, not guessed), invariant, failure-type (SECURITY/GOVERNANCE/MEASUREMENT/MODEL/HARNESS/UNREACHABLE)}`. Fold in the failure-taxonomy legend + the attack→expected test-matrix. Honest language only — "no bypass observed across N cases under this configuration," never "secure." If zero findings, say so.

- [ ] **Step 3: Write `THREAT_MODEL.md`** — trusted (scope/gate/executor/audit) vs untrusted (model output, target-controlled data, env) components, LLM/target/user/env-controlled data lanes, and the MODEL-OUTPUT→ACTION→GATE→RISK→EXECUTOR→AUDIT→CONFIRM path with the one-execution-path + draft→approve→freeze boundaries, as concise prose + an ASCII diagram.

- [ ] **Step 4: Write `RESEARCH_FINDINGS.md`** — what the deterministic audit PROVED (per-invariant), separated from the live/LLM/multi-agent campaigns deferred as proposed experiments (direct/indirect prompt-injection ASR, recon→planner→exploit manipulation, live tool-abuse), each with setup + metric (ASR over N trials; record model/temp/seed) + the invariant it stresses.

- [ ] **Step 5: Cross-check (Review Focus #4, #5)** — assert `security_results.json` counts equal the pytest run; verify every `xfail` reason maps to a documented `SEC-NNN` finding with a real root cause (no xfail hiding a test-bug).

- [ ] **Step 6: Commit (the "before" baseline — docs only, no `brukal/` change)**
```bash
git add SECURITY_AUDIT.md THREAT_MODEL.md RESEARCH_FINDINGS.md security_results.json
git commit -m "docs(security): audit report + threat model + research findings (pre-fix baseline)

<attribution>"
```

---

### Task 9 (TEMPLATE — instantiate once per Phase-1 FINDING; none if Phase 1 was clean): FIX

For each `SEC-NNN` bypass documented in Task 8, in descending severity:

- [ ] **Step 1: Reproduce** — confirm the `xfail` test is red for the documented root cause (already minimal from Task 8).
- [ ] **Step 2: Fix the security code** — the smallest change in `brukal/<module>.py` that closes the bypass while preserving all five invariants (deterministic, fail-closed, no LLM in the decision, no runtime scope widening, append-only audit). No behavior change beyond closing the bypass.
- [ ] **Step 3: Flip the test** — remove that test's `@pytest.mark.xfail`; it must now genuinely PASS. Re-run `tests/security/` — still green, now with one fewer xfail.
- [ ] **Step 4: Full regression** — `.venv/bin/python -m pytest -q` green; pyflakes clean on the changed module.
- [ ] **Step 5: Update the audit** — in `SECURITY_AUDIT.md`, append a before→after note to `SEC-NNN` (what changed, why it's still invariant-preserving). Regenerate `security_results.json` (that case now PASS).
- [ ] **Step 6: Commit (the "after" — its own commit, separate from the Task-8 baseline)**
```bash
git add brukal/<module>.py tests/security/<module>.py SECURITY_AUDIT.md security_results.json
git commit -m "fix(security): close SEC-NNN <one line> (invariant <Ix> preserved)

<attribution>"
```

---

## Notes for the executor
- **Phase order is strict:** finish Tasks 1–8 (TRY + ANALYZE + SAVE, committing the pre-fix baseline) before ANY Task-9 FIX touches `brukal/`. The before/after git history is the research artifact.
- A security module's **exact entry signatures** (gate command-check, `check_web`, schema validation, `audit.verify`, prover API, `risk.assess`) must be read from the real code in each task's Step 1 — the sketched helpers (`_gate_verdict`, `_resolve`, `_build_chain`) wrap the real calls; they must never reimplement the logic under test.
- If a module's expected safe outcome is genuinely ambiguous (e.g. the gate legitimately ESCALATEs rather than DENYs a case), record the observed value and treat ESCALATE/DENY/ERROR as "not a bypass"; only ALLOW-to-an-unauthorized-effect is a bypass. When unsure, stop and ask.
- Do not invent findings: if Tasks 1–7 are all green (no xfails), Task 8 reports zero findings honestly and Task 9 is skipped entirely.
- **Harness convention:** every test function takes the `record` conftest fixture as a parameter and calls it once per case; there is no importable harness module (the fixture is auto-discovered by pytest, which sidesteps import-path fragility). The `...`-sketched test bodies in Tasks 5–7 must each add the `record` parameter when fleshed out, following the Task 1/2/3 pattern.
