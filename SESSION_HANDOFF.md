# Brukal — session handoff (2026-08-04 → 08-07)

Paste this into a new session. Canonical long-term memory is still the vault note
`Desktop/Brukal's Memory/Brukal.md` (read its tail, append at session end).

---

## 1. State right now

- **HEAD `c6fae09`**, working tree clean. **767 tests pass**, 1 skipped (~18s).
- Repo `Desktop/Brukal/brukal`. `CLAUDE.md` is law — five invariants, never give an agent
  the `kali` object.
- Key spend: ~$20 top-up plus a later top-up. Brukal runs cost $0.07–$0.55 each.
  **Shannon costs ~$7.37 per run** — that is the expensive side.

### Commits this session (newest first)
```
c6fae09  llm: an answer spent entirely on thinking is not an absence of an answer
9cde2d5  crawl: read-only in EFFECT, not merely in method
5918d63  spa: a single-page application has an attack surface — find it
5bc27f5  calibrate: learn what this application's answers mean, instead of assuming
5127544  crawl: reach endpoints nothing links to; cover deserialization
5a69882  preflight: probe the origin the run will use, not port 80
89857de  authz: close the four classes a competitor held alone
3cd6757  audit: three dead detectors, five silent coverage gaps, one duplicated rule
96854f7  login: require positive evidence of a session, not the absence of a form
9d83a0a  session: one concept, however it is carried — the root of five defects
85ad5e7  hypothesis: the model now produces confirmed findings on an unfamiliar target
e2126a6  authz: remember the login URL, or every cross-account proof fails silently
72e45f5  authz: horizontal account takeover through a body-named victim
5f48efa..4921d2b  (cookie-session authz family, coverage, breadth-first probing)
```

---

## 2. Measured results

| Target | Shape | Result | Cost |
|---|---|---|---|
| **DVNA** `172.20.0.10:9090` | Express, cookie session, forms | **14 findings, 13 confirmed, 5 critical, 0 FP** | $0.18 |
| **Juice Shop** `172.20.0.4:3000` | Angular SPA, RS256 JWT, REST | **6 confirmed** (CRITICAL SQLi, HIGH prompt injection) | $0.07 |
| **DVGA** `172.20.0.5:5013` | GraphQL | **8 findings, 7 confirmed** | $0.55 |
| Shannon on DVNA | white-box, source mounted | 13 reported + 1 proven-but-unreported | **$7.37** |

**Brukal matches every critical class Shannon found on DVNA, black-box, at ~40x less cost.**
Shannon still uniquely holds `/app/modifyproduct` IDOR (Brukal has it as a candidate).

⚠️ **DVNA and Juice Shop numbers are NOT cold** — Brukal was tuned against both.
**DVGA was the genuine cold test** (pre-registered, code frozen): predicted 0–2 findings
and "GraphQL produces nothing" — **both predictions were WRONG**, it got 7 confirmed
including 2 GraphQL. That is the real evidence the generalisation work transferred.

---

## 3. The big architectural changes (these are what generalise)

1. **`calibrate.py` (NEW)** — learns what THIS app's answers mean before judging any.
   Four read-only requests establish `ok` / `missing` / `denied` baselines.
   - Compares **structure not prose** (tag skeletons, JSON key sets; CSRF/timestamps
     stripped). A page *saying* "Access denied" while serving secrets is NOT refused —
     invariant 1 reaches the classifier.
   - An unlearned baseline returns **None, not False** → may only ADD certainty.
   - Discards `missing` when it resembles a real page (catch-all/SPA hosts).
   - Skipped below 60 req/min: overhead must not starve the work.

2. **Session abstraction** — `has_session()` / `session_token()`. Code used to ask
   `if self.last_jwt` when it meant "am I logged in". **Five defects traced to that one
   substitution.**

3. **SPA surface** — three separate causes hid every single-page app:
   - `probeable_surface()` required a form/param/templated route
   - `sorted(links)` put `chunk-*.js` before `main.js`
   - **`HttpWebCage.max_body = 20000`** truncated a 1MB bundle → 0 routes from a file
     containing 40. Scripts now get 2MB.

4. **Read-only crawl** — `_changes_target_state()` + `_is_irreversible_path` applied to
   every link. Brukal had been **reconfiguring targets** (`GET /difficulty/hard`).

5. **Thinking-budget retry** — `stop_reason='max_tokens'`, `blocks=['thinking']` →
   empty reply, full price. Affected **every** `propose()` including the strategist.

---

## 4. Standing lessons (the paper's real contribution)

- **A green test suite is nearly worthless for validating a security tool** — the
  fixtures encode the same misunderstanding as the code. **~12 instances this session**
  of tests asserting a mistaken belief. Every real defect came from reading live output.
- **Always verify a new test FAILS when its fix is reverted.** One test passed against
  broken code by luck (nondeterministic fixture).
- **Silence is the dominant failure mode.** Dead detectors, unreportable coverage
  classes, checks structurally unable to fire — all while emitting a coverage row.
- **A guard that fails closed for the WRONG REASON is worse than no guard.** The
  preflight blocked two healthy runs and prevented zero wasted ones.
- **Echo-immunity is a property every differential detector needs**, not a bug you fix
  once (hit in hypothesis, SSRF, recovery-enumeration).
- **Measure before attributing.** I blamed my own code for a 9x slowdown that was the
  `/mnt/c` mount.
- **Cost discipline:** validate detectors with **direct scripts, zero model calls**.
  Paid runs only for integration checkpoints.

---

## 5. Environment (fragile — check first every session)

```bash
# Docker Desktop WSL integration drops out. If `docker ps` fails:
nohup wsl.exe -d Ubuntu -u root -e \
  /mnt/wsl/docker-desktop/docker-desktop-user-distro proxy --distro-name Ubuntu &

# Targets need a loopback alias (bridge IPs are unreachable from WSL):
wsl.exe -d Ubuntu -u root -e ip addr add 172.20.0.10/32 dev lo   # DVNA
wsl.exe -d Ubuntu -u root -e ip addr add 172.20.0.4/32  dev lo   # Juice Shop
wsl.exe -d Ubuntu -u root -e ip addr add 172.20.0.5/32  dev lo   # DVGA

# scope.json MUST exist at repo root (cage bind-mount) and MUST stay 127.0.0.1/32
# (test_shipped_scope_is_narrow). Engagement scopes live in runs/*.json.
docker start dvna juice-shop dvga brukal-kali
```

**Credentials:** DVNA `brkeval` / `BrkEval1!` (login field is the *login* column, not
email). Juice Shop `brk@eval.local` / `BrkEval1!` (`--login-type json --login-field-user
email`). API key at `runs/anthropic.env` — **never paste it into chat**.

**Run from the repo root**, use `.venv/bin/brukal`, and always `set -a && . runs/anthropic.env && set +a`.

---

## 6. Open items

1. **Shannon vs Brukal on a truly cold target** — the only comparison that would settle
   "better than Shannon". ~$7. Brukal's side is ready.
2. **Remaining unvalidated classes:** blind OOB, default credentials, deserialization —
   wired and tested but never fired on a live target.
3. **`known CVE` HIGH candidate** on DVGA is unconfirmed noise — worth triaging.
4. **Candidate noise** — e.g. `Potential IDOR on /app/calc param 'eqn'` (a calculator
   expression, not an object id).
5. **⚠️ ROTATE THE LEAKED NVIDIA KEY** — `nvapi-54QQ...` appeared in an earlier
   transcript.
6. `graphify` skill installed (`~/.claude/skills/graphify`, CLI `graphify` 0.9.34) —
   likely useful for navigating `assist.py` (~5k lines).
