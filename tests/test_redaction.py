"""
test_redaction.py — the redaction boundary: session material must never reach a
RECORD in cleartext.

Found live on Juice Shop (docs/CASE_STUDY_JUICESHOP_2B.md): with a real JWT session
carried by the governed browser, the token appeared in cleartext on 5 of 6 surfaces —
the audit log, the checkpoint, EVERY model prompt, findings.jsonl and the blackboard.
Juice Shop's JWT payload is the user row, so what leaked was an account id, an email,
a role AND a password hash: PII plus a credential to crack, not merely a token.

The injection site (`AssistSession._session_auth_for`) appends the bearer header to a
shell command BEFORE the gate, and that MUST stay — the gate has to judge the bytes
that will really execute (invariant 3). So this pins the fix at every point of RECORD:

  * each surface records the PLACEHOLDER, never the secret;
  * the record keeps its STRUCTURE — the command and the header NAME survive, so an
    audit line still shows what was judged and a gate decision stays auditable;
  * a command carrying no secret is recorded BYTE-IDENTICAL (the redactor knows the
    engagement's injected credentials; it never pattern-guesses at what a secret is);
  * a DENIED command is redacted too — a denial is not a containment of the log;
  * the report, which was already clean, stays clean.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal import redact
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.findings import Finding, FindingStore
from brukal.web import GovernedBrowser

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"

# A Juice-Shop-shaped JWT: the payload IS the user row.
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImlkIjoyNSwiZW1haWwiOiJicnVrYWwtYUBqdWlj"
       "ZS1zaC5vcCIsInBhc3N3b3JkIjoiZWMwODRjZmFmNSIsInJvbGUiOiJjdXN0b21lciJ9fQ."
       "c3RhbmQtaW4tc2lnbmF0dXJl")

TARGET = "10.10.10.5"
CMD = f"nuclei -u http://{TARGET}/rest/products"
OFF_SCOPE = "nuclei -u http://9.9.9.9/rest/products"      # denied: hard:scope


@pytest.fixture(autouse=True)
def _clean_registry():
    """The credential set is per-engagement process state; no test may inherit it."""
    redact.clear()
    yield
    redact.clear()


class _NullLLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


class _Cage:
    def run(self, action):
        from brukal.web import WebResult
        return WebResult(status=200, url=action.url, body="")


def _engagement(tmp: Path, *, cookies=None):
    """An authenticated engagement wired to real writers on disk."""
    scope = load_scope(FIXTURE)
    audit_path = tmp / "audit.jsonl"
    audit = AuditLog(audit_path)
    kali = FakeKali()
    ex = Executor(Gate(scope), kali, audit)
    browser = GovernedBrowser(scope, _Cage(), audit)
    if cookies:
        browser._cookies = dict(cookies)
    else:
        browser.auth_header = f"Bearer {JWT}"
    bb = Blackboard(tmp / "vault", scope)
    sess = AssistSession(TARGET, ex, StrategistAgent(_NullLLM()),
                         browser=browser, blackboard=bb)
    sess.authenticated = True
    sess.findings = FindingStore(tmp / "vault" / "findings.jsonl")
    return sess, audit_path, tmp / "vault", kali


def _tree_text(root: Path) -> str:
    """Everything written under `root`, concatenated — so a surface cannot hide in a
    file the test forgot to name."""
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)


# --- 1. per-surface: the token must not be recorded in cleartext ------------ #

def test_the_audit_log_does_not_record_the_session_token():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, _vault, kali = _engagement(tmp)
        sess.run(CMD)
        assert JWT in kali.executed[0], "the cage must still run the REAL bytes"
        text = audit_path.read_text(encoding="utf-8")
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text


def test_the_checkpoint_does_not_record_the_session_token():
    from brukal import checkpoint
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, _vault, _k = _engagement(tmp)
        sess.run(CMD)
        cp = tmp / "checkpoint.json"
        checkpoint.save(cp, sess, steps_done=1)
        text = cp.read_text(encoding="utf-8")
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text


def test_no_model_prompt_carries_the_session_token():
    from brukal.llm import LLMClient, UsageMeter

    class _Capture:
        def __init__(self):
            self.seen = []

        def propose(self, system, user, max_tokens):
            self.seen.append(system + "\n" + user)
            return ""

    redact.register(JWT)
    cap = _Capture()
    c = LLMClient.__new__(LLMClient)
    c.provider, c.model, c._backend, c.usage = "anthropic", "m", cap, UsageMeter("m")
    c.propose("you are a strategist",
              f"ALREADY TRIED (do NOT repeat these):\n- {CMD} -H 'Authorization: Bearer {JWT}'")
    assert JWT not in cap.seen[0]
    assert redact.placeholder_for(JWT) in cap.seen[0]


def test_the_findings_evidence_does_not_carry_the_session_token():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, vault, _k = _engagement(tmp)
        authed = sess._session_auth_for(CMD)
        assert JWT in authed, "precondition: the injected command carries the token"
        sess._record_vuln_finding(authed, "high", "SQL injection", "is vulnerable")
        text = (vault / "findings.jsonl").read_text(encoding="utf-8")
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text


def test_the_blackboard_does_not_carry_the_session_token():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, vault, _k = _engagement(tmp)
        sess.run(CMD)
        sess._persist_finding("shell", sess.executed_cmds[-1], "ran", "scan done", [])
        text = _tree_text(vault)
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text


def test_a_cookie_session_is_redacted_on_every_surface():
    """The credential set is not only bearer tokens — a session COOKIE is the same
    material and reaches the same records."""
    sid = "s%3Aab12cd34ef56gh78ij90kl"
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, vault, _k = _engagement(tmp, cookies={"connect.sid": sid})
        sess.run(f"curl -s http://{TARGET}/rest/basket/6")
        sess._persist_finding("shell", sess.executed_cmds[-1], "ran", "read basket", [])
        assert sid not in audit_path.read_text(encoding="utf-8")
        assert sid not in _tree_text(vault)


# --- 2. the record keeps its structure -------------------------------------- #

def test_the_redacted_audit_line_still_shows_the_command_and_the_header_name():
    """Masking the secret, not deleting the command: an operator must still be able to
    read WHAT was judged and WHY the gate ruled as it did."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, _v, _k = _engagement(tmp)
        sess.run(CMD)
        actions = [json.loads(l)["data"].get("action", "")
                   for l in audit_path.read_text(encoding="utf-8").splitlines()
                   if json.loads(l)["kind"] == "decision"]
        line = actions[0]
        assert line.startswith(CMD), "the command itself must survive redaction"
        assert "Authorization: Bearer" in line, "the header NAME is not a secret"
        assert redact.placeholder_for(JWT) in line
        assert JWT not in line


# --- 3. a command with no secret is untouched ------------------------------- #

def test_a_command_carrying_no_secret_is_recorded_byte_identical():
    plain = f"nmap -n -sV {TARGET}"
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, _v, _k = _engagement(tmp)
        sess.run(plain)
        actions = [json.loads(l)["data"].get("action", "")
                   for l in audit_path.read_text(encoding="utf-8").splitlines()
                   if json.loads(l)["kind"] == "decision"]
        assert actions[0] == plain


def test_the_redactor_never_touches_text_that_holds_no_registered_secret():
    redact.register(JWT)
    for s in ("", "nmap -n -sV 10.10.10.5", "Authorization: Bearer",
              "eyJhbGciOiJIUzI1NiJ9", "a" * 500):
        assert redact.text(s) == s


def test_a_short_value_is_never_registered_as_a_secret():
    """A one- or two-character cookie value is not a secret, and redacting it would
    shred every ordinary record it happens to appear in."""
    redact.register("1", "ab", "abc")
    assert redact.text("a table of abc values, ab, 1") == "a table of abc values, ab, 1"


def test_the_placeholder_is_stable_for_the_same_secret():
    redact.register(JWT)
    assert redact.text(f"x {JWT} y") == redact.text(f"x {JWT} y")
    assert redact.placeholder_for(JWT) != redact.placeholder_for(JWT + "z")


# --- 4. a DENIED command is recorded too, so it must be redacted too -------- #

def test_a_denied_token_bearing_command_is_redacted_on_every_surface():
    """The 2B run leaked through a DENIED command: the gate refused it, the ledger
    kept the token anyway. Denial is not containment of the log."""
    from brukal import checkpoint
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, vault, kali = _engagement(tmp)
        decision, result, _hl = sess.run(OFF_SCOPE)
        assert decision.verdict == "DENY" and result is None
        assert kali.executed == [], "a denied command must never reach the cage"
        sess._persist_finding("shell", sess._session_auth_for(OFF_SCOPE),
                              "denied", "blocked by scope", [])
        cp = tmp / "checkpoint.json"
        checkpoint.save(cp, sess, steps_done=1)
        for text in (audit_path.read_text(encoding="utf-8"),
                     cp.read_text(encoding="utf-8"),
                     _tree_text(vault)):
            assert JWT not in text
        assert redact.placeholder_for(JWT) in audit_path.read_text(encoding="utf-8")


# --- 5. the report was already clean and stays clean ------------------------ #

def test_the_report_and_its_exports_stay_clean():
    """report.md/report.json/brukal.sarif were the one surface that held in the 2B run.
    They carry `Finding.source` as a `reproduce` field, so they were one confirmed,
    token-bearing finding away from leaking — this pins them shut."""
    from brukal import export
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        redact.register(JWT)
        f = Finding(title="SQL injection", severity="high", target=f"http://{TARGET}/x",
                    evidence="is vulnerable", confirmed=True,
                    source=f"{CMD} -H 'Authorization: Bearer {JWT}'")
        out = tmp / "report"
        export.write([f], out)
        text = _tree_text(out)
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text, \
            "clean must mean redacted, not silently dropped"


# --- 6. the two surfaces the case study did not observe --------------------- #
# The 2B run measured five leaking surfaces. Walking every persistence call in the
# package found two more that the run simply never exercised — the same lesson the
# `-n` fix taught: a record site can hide from a live run without being safe.

def test_the_lesson_store_does_not_carry_the_session_token():
    """A lesson's provenance holds the command that earned it, and the lesson store
    OUTLIVES the engagement — an unredacted token here is fed into the prompts of a
    later run against a different target."""
    from brukal.lessons import LessonStore
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        redact.register(JWT)
        store = LessonStore(tmp / "lessons.jsonl")
        store.record_verified_success(
            target=TARGET, service="http",
            command=f"{CMD} -H 'Authorization: Bearer {JWT}'",
            outcome="confirmed", tags=["web"])
        text = _tree_text(tmp)
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text


def test_the_task_tree_page_does_not_carry_the_session_token():
    """The orchestrator writes the task tree to the vault; a task's recorded digests
    carry the command that produced them."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        redact.register(JWT)
        bb = Blackboard(tmp / "vault", load_scope(FIXTURE))
        bb.save_task_tree(f"# Pentesting Task Tree\n\n- [x] `t1` (recon/done) "
                          f"{CMD} -H 'Authorization: Bearer {JWT}'\n")
        text = _tree_text(tmp / "vault")
        assert JWT not in text
        assert redact.placeholder_for(JWT) in text


# --- 7. the boundary itself ------------------------------------------------- #

def test_the_executor_still_runs_the_real_bytes():
    """The whole design rests on this: redaction is at RECORD, never at injection, so
    the gate judges — and the cage runs — exactly what would really execute."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, _v, kali = _engagement(tmp)
        sess.run(CMD)
        assert kali.executed == [f"{CMD} -H 'Authorization: Bearer {JWT}'"]
