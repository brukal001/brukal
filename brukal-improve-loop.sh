#!/usr/bin/env bash
# brukal-improve-loop.sh — autonomous Brukal self-improvement in FRESH sessions.
#
# Each iteration spawns a BRAND-NEW `claude -p` session (clean context). That session reads
# the persisted state — git history + the vault note Brukal.md + PROJECT_STATE.md + NEXT.md —
# advances Brukal by ONE tested milestone under the five safety invariants, commits, updates
# the state and NEXT.md, and exits. State lives in git + the vault BETWEEN sessions; the loop
# re-invokes fresh, so context never accumulates across changes. That is the whole point:
# "save the improvement, then start a new session for the next change."
#
# ── SAFETY ────────────────────────────────────────────────────────────────────────────────
#  * BUILD + SELF-TEST ONLY. Never a live pentest, never traffic to a real/external target,
#    never a Docker cage / crAPI / DVWA run (CLAUDE.md forbids that without explicit
#    per-session human authorization). The per-session prompt enforces these HARD LIMITS.
#  * Commits go to a DEDICATED branch and are NEVER pushed — you review and merge.
#  * The loop STOPS if the test suite goes red, if no commit was made (nothing queued), or if
#    the stop-file exists.
#  * It runs `claude --dangerously-skip-permissions` so the fresh session can edit/test/commit
#    unattended. That bypasses per-tool approval — the guardrails above (dedicated no-push
#    branch, build-only prompt, red-suite stop, iteration cap) are what keep it bounded. Read
#    the prompt below and the branch's commits before merging anything.
#
# ── USAGE ───────────────────────────────────────────────────────────────────────────────────
#   bash brukal-improve-loop.sh                 # 5 iterations, model=sonnet, branch=auto-improve
#   BRUKAL_LOOP_ITERS=3 BRUKAL_LOOP_MODEL=opus bash brukal-improve-loop.sh
#   touch .stop-improve-loop                     # ask the loop to stop after the current iteration
set -uo pipefail

REPO="${BRUKAL_REPO:-/mnt/c/Users/ashis/Desktop/Brukal/brukal}"
PY="${BRUKAL_PY:-/home/brute/brukal-venv/bin/python}"
MODEL="${BRUKAL_LOOP_MODEL:-sonnet}"
MAX_ITERS="${BRUKAL_LOOP_ITERS:-5}"
BRANCH="${BRUKAL_LOOP_BRANCH:-auto-improve}"
STOPFILE="$REPO/.stop-improve-loop"
LOGDIR="$REPO/runs/auto-improve-logs"

cd "$REPO" || { echo "[loop] no repo at $REPO"; exit 1; }
command -v claude >/dev/null 2>&1 || { echo "[loop] 'claude' CLI not found on PATH"; exit 1; }
git rev-parse --git-dir >/dev/null 2>&1 || { echo "[loop] $REPO is not a git repo"; exit 1; }
[ -x "$PY" ] || { echo "[loop] python not found at $PY (set BRUKAL_PY)"; exit 1; }
mkdir -p "$LOGDIR"

# Dedicated branch off the current HEAD. Never auto-commit to main. If you start this from
# main, the loop's work lands on 'auto-improve' for you to review/merge.
git switch -c "$BRANCH" 2>/dev/null || git switch "$BRANCH" || {
  echo "[loop] could not switch to branch $BRANCH (commit/stash your working tree first)"; exit 1; }
echo "[loop] working on branch '$BRANCH' (off $(git rev-parse --short HEAD)). Nothing is pushed."

PROMPT=$(cat <<'EOP'
You are ONE FRESH session of an autonomous Brukal self-improvement loop. You have NO memory of
any prior iteration — the durable state is git + the vault. Do the following, then EXIT.

1. READ, in order: ./CLAUDE.md (the FIVE SAFETY INVARIANTS + build discipline — this is LAW),
   the vault note "/mnt/c/Users/ashis/Desktop/Brukal's Memory/Brukal.md", ./PROJECT_STATE.md,
   ./NEXT.md (the queued next improvement), and `git log --oneline -15`.
2. PICK the SINGLE next improvement from ./NEXT.md. If NEXT.md is empty/missing, or its top
   item is ambiguous, blocked, or would require anything under HARD LIMITS below: DO NOT write
   code — propose the next concrete safe improvement, write it into ./NEXT.md, and exit.
3. IMPLEMENT that ONE improvement as a TESTED milestone: test-driven, keep the FULL suite green
   (/home/brute/brukal-venv/bin/python -m pytest -q), preserve ALL FIVE invariants (no LLM in the
   deterministic gate; fail-closed; never trust an agent self-report; one execution path through
   the executor; immutable scope + append-only audit), and do not over-build. If the item is
   large, ship the smallest coherent slice and queue the remainder in NEXT.md.
4. HARD LIMITS — never cross these: BUILD + SELF-TEST ONLY. Do NOT run any live pentest; do NOT
   send traffic to any real or external target; do NOT start/relaunch Docker cages or hit
   crAPI/DVWA/any lab; do NOT push to any git remote; do NOT weaken the deterministic gate or any
   invariant. If a step needs any of these, stop and record it in NEXT.md as human-gated instead.
5. WHEN GREEN: `git add` ONLY your changed files and commit with a clear message ending in a line
   "Auto-improve loop (fresh session)". Then update ./PROJECT_STATE.md, append a dated line to the
   vault Brukal.md running log, and REWRITE ./NEXT.md with the next improvement (or the single word
   "empty" if you cannot identify a safe next step).
6. IF THE SUITE IS RED and you cannot fix it in a few steps: `git checkout -- .` to discard your
   uncommitted changes, record the blocker in NEXT.md, and exit WITHOUT committing red.
Keep it to ONE milestone — the loop starts a fresh session for the next one.
EOP
)

for i in $(seq 1 "$MAX_ITERS"); do
  if [ -f "$STOPFILE" ]; then echo "[loop] stop-file present — stopping."; rm -f "$STOPFILE"; break; fi
  stamp="$(date +%y%m%d_%H%M%S)"; log="$LOGDIR/iter_${i}_${stamp}.log"
  before="$(git rev-parse HEAD)"
  echo "[loop] ===== iteration $i/$MAX_ITERS — FRESH session — log: $log ====="
  # Fresh session: NO --resume / --continue. Unattended: skip per-tool approval prompts.
  # `env -u ANTHROPIC_API_KEY`: a depleted ANTHROPIC_API_KEY in the environment takes
  # precedence and fails the child with "Credit balance is too low"; unsetting it lets the
  # child use the claude.ai login instead. (Set BRUKAL_LOOP_KEEP_KEY=1 to keep the key.)
  KEYENV=(env); [ "${BRUKAL_LOOP_KEEP_KEY:-0}" = "1" ] || KEYENV=(env -u ANTHROPIC_API_KEY)
  "${KEYENV[@]}" claude -p "$PROMPT" --model "$MODEL" --add-dir "$REPO" \
    --dangerously-skip-permissions > "$log" 2>&1
  rc=$?
  after="$(git rev-parse HEAD)"
  if [ "$rc" -ne 0 ]; then echo "[loop] claude exited $rc (see $log) — stopping."; break; fi
  if ! "$PY" -m pytest -q >/dev/null 2>&1; then
    echo "[loop] SUITE RED after iteration $i — stopping for human review on '$BRANCH'."; break; fi
  if [ "$before" = "$after" ]; then
    echo "[loop] no new commit (NEXT empty/blocked or proposal-only) — stopping."; break; fi
  echo "[loop] iteration $i committed $(git rev-parse --short "$after"); NEXT.md updated."
done
echo "[loop] finished. Review branch '$BRANCH' (git log --oneline), merge what you want."
echo "[loop] Nothing was pushed; no live target was touched."
