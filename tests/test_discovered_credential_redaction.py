"""
test_discovered_credential_redaction.py — the redaction contract is SYMMETRIC.

`test_redaction.py` pins the half that shipped: a credential Brukal INJECTS is registered
by `_session_auth_for` at the moment it is read off the browser, and the eight write
funnels mask it everywhere. That contract has a hole shaped exactly like its own source
of truth — "the credential set this engagement actually injected". A credential the
TARGET discloses was never injected, so nothing registers it, so every funnel records it
verbatim.

Run 2C4 wrote a live admin JWT — `alg=RS256`, `role=admin`, `sub=admin@juice-sh.op`, no
`exp` — in cleartext across ten artifact files. That bundle is therefore unpublishable,
and it cannot be retrofitted: the records are hash-chained, so masking one afterwards
breaks the chain from that entry on and destroys the tamper-evidence that was the whole
reason to publish it. **The fix has to happen at WRITE time or not at all.**

Two properties, and the second is what stops the fix being a shredder:

  * the VALUE is masked on every surface, at the FIRST write, not the second;
  * the STRUCTURE survives — `alg`, the claim KEYS, the absent `exp` and the endpoint it
    came from all stay on the record, so a reader can see why it is a finding without
    being able to use the token. A record that says only `[REDACTED:…]` has protected
    the credential by destroying the evidence.

Recognition is DETERMINISTIC and is not a pattern guess: a JWT either decodes as three
base64url segments whose first two are JSON objects, or it is not a JWT. That is the same
standard the injected half holds itself to — never a regex deciding what a secret looks
like — and it is why a lookalike that does not decode must be left strictly alone.
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
from brukal.findings import FindingStore
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"

# The run-2C4 shape, verbatim in structure: RS256, an admin role, an identifying
# subject, and NO `exp`. Nothing here is a real credential — the signature segment is
# ASCII — but it decodes exactly like the one that leaked.
#   header  {"alg":"RS256","typ":"JWT"}
#   payload {"sub":"admin@juice-sh.op","role":"admin","iat":1724400000,"id":1}
ADMIN_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyNDQwMDAwMCwi"
    "aWQiOjF9."
    "bm90LWEtcmVhbC1zaWduYXR1cmUtanVzdC1ieXRlcy1mb3ItdGhlLWZpeHR1cmU")

LEAK_URL = f"http://{TARGET}/rest/admin/application-configuration"
LEAK_BODY = json.dumps({"config": {"authenticatedUser": {"token": ADMIN_JWT}}})


@pytest.fixture(autouse=True)
def _clean_registry():
    """The credential set is per-engagement process state; no test may inherit it."""
    redact.clear()
    yield
    redact.clear()


class _NullLLM:
    def propose(self, system, user, max_tokens=1024):
        return ""


class _LeakingCage:
    """A target that hands back an admin token in a response body."""

    def __init__(self, body=LEAK_BODY):
        self.body = body

    def run(self, action):
        return WebResult(status=200, url=action.url, body=self.body)


class _EchoKali(FakeKali):
    """A cage whose tool output carries whatever the command asked for — the shell
    twin of a leaking response, and the path where the AUDIT record is written by the
    executor before any session-level hook could run."""

    def __init__(self, stdout):
        super().__init__()
        self._stdout = stdout

    def run(self, command: str) -> ExecResult:
        self.executed.append(command)
        return ExecResult(command, 0, self._stdout, "")


def _engagement(tmp: Path, *, kali=None):
    scope = load_scope(FIXTURE)
    audit_path = tmp / "audit.jsonl"
    audit = AuditLog(audit_path)
    kali = kali or FakeKali()
    ex = Executor(Gate(scope), kali, audit)
    browser = GovernedBrowser(scope, _LeakingCage(), audit)
    bb = Blackboard(tmp / "vault", scope)
    sess = AssistSession(TARGET, ex, StrategistAgent(_NullLLM()),
                         browser=browser, blackboard=bb)
    sess.findings = FindingStore(tmp / "vault" / "findings.jsonl")
    return sess, audit_path, tmp / "vault", kali


def _tree_text(root: Path) -> str:
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)


# --- 1. every surface ------------------------------------------------------- #

def test_a_discovered_token_is_masked_on_every_record_surface():
    """The named 2C4 failure. One discovered token, driven through the web path, the
    shell path, the finding store, the checkpoint, the report/SARIF export and the
    lesson store, and asserted absent from all of them by reading the files."""
    from brukal import checkpoint, export, report
    from brukal.lessons import LessonStore
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        # The follow-up an operator really makes: replay the leaked admin token.
        replay = f"curl -H 'Authorization: Bearer {ADMIN_JWT}' http://{TARGET}/rest/admin"
        sess, audit_path, vault, kali = _engagement(
            tmp, kali=_EchoKali(f"HTTP/1.1 200 OK\n\n{LEAK_BODY}"))
        sess.lessons = LessonStore(tmp / "lessons.jsonl")

        sess.run_web(f"get {LEAK_URL}")          # body -> notes + blackboard
        sess.scan_web_body(LEAK_URL, LEAK_BODY)  # the JWT-exposure finding
        sess.run(replay)                         # audit `execution` + executed_cmds
        # The lesson store outlives the engagement: an unmasked token here is fed into
        # the prompts of a LATER run against a different target. Provenance is the field
        # that carries a command, so drive that, exactly as the injected half is driven.
        sess.lessons.record_verified_success(
            target=TARGET, service="http", command=replay,
            outcome="confirmed", tags=["web"])
        cp = tmp / "checkpoint.json"
        checkpoint.save(cp, sess, steps_done=1)
        out = tmp / "report"
        export.write(list(sess.findings.all()), out)
        report.write_reports(sess.findings, {"target": TARGET}, out)

        assert ADMIN_JWT in kali.executed[0], "the cage must still run the REAL bytes"
        surfaces = {
            "audit": audit_path.read_text(encoding="utf-8"),
            "vault (findings.jsonl, agent notes, pages)": _tree_text(vault),
            "checkpoint": cp.read_text(encoding="utf-8"),
            "report + SARIF": _tree_text(out),
            "lesson store": (tmp / "lessons.jsonl").read_text(encoding="utf-8"),
        }
        placeholder = redact.placeholder_for(ADMIN_JWT)
        for name, text in surfaces.items():
            assert ADMIN_JWT not in text, f"the discovered token leaked to {name}"
            assert placeholder in text, \
                f"{name} dropped the credential instead of masking it"


# --- 2. the finding is still provable --------------------------------------- #

def test_the_masked_record_still_proves_why_the_token_matters():
    """Masking must not shred the evidence. A reader with only the artifacts has to be
    able to say WHAT was exposed — the algorithm, which claims it carried, that it never
    expires, and where it came from — while holding nothing they could send."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, vault, _k = _engagement(tmp)
        sess.scan_web_body(LEAK_URL, LEAK_BODY)
        text = _tree_text(vault) + "\n" + json.dumps(
            [f.to_dict() for f in sess.findings.all()])

        assert ADMIN_JWT not in text
        assert "RS256" in text, "the algorithm is the finding and must survive"
        for claim_key in ("sub", "role", "iat"):
            assert claim_key in text, f"the claim key {claim_key!r} did not survive"
        assert "exp" in text, "the ABSENCE of an expiry is the weakness; say so"
        assert LEAK_URL in text, "the source endpoint must survive"
        # And the values behind those keys must not.
        assert "admin@juice-sh.op" not in text, "a claim VALUE rode out with the keys"


def test_the_structural_record_is_a_finding_not_only_a_note():
    """It has to be in the machine-readable stream, not merely in prose an exporter
    might drop. `findings.jsonl` is what report.json and the SARIF are built from."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, _v, _k = _engagement(tmp)
        sess.scan_web_body(LEAK_URL, LEAK_BODY)
        ev = "\n".join(f.evidence for f in sess.findings.all())
        assert "RS256" in ev
        assert "role" in ev


# --- 3. the placeholder is the SAME stable form ----------------------------- #

def test_the_placeholder_is_the_same_stable_digest_form_as_an_injected_secret():
    """An operator correlates two records as the same credential by the marker. A
    discovered token that masked differently from an injected one would break that,
    and the marker is the only handle they have once the value is gone."""
    import re as _re
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, vault, _k = _engagement(tmp)
        sess.run_web(f"get {LEAK_URL}")
        sess.run_web(f"get {LEAK_URL}?again=1")      # the same token, twice
        text = _tree_text(vault)
        marker = redact.placeholder_for(ADMIN_JWT)
        assert _re.fullmatch(r"\[REDACTED:[0-9a-f]{8}\]", marker)
        assert text.count(marker) >= 2, "the same credential must read the same way"


# --- 4. MUST NOT BREAK: no credential, no rewrite --------------------------- #

def test_a_body_carrying_no_credential_is_recorded_byte_identical():
    """Over-redaction that shreds ordinary records is a regression, not caution. This
    is the property that stops the fix becoming a content filter."""
    clean = json.dumps({"products": [{"id": 1, "name": "Apple Juice"}],
                        "note": "eyes on the prize"})
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, vault, _k = _engagement(tmp)
        sess.browser._cage = _LeakingCage(clean)
        sess.run_web(f"get http://{TARGET}/rest/products")
        text = _tree_text(vault) + audit_path.read_text(encoding="utf-8")
        assert "Apple Juice" in text
        assert "[REDACTED:" not in text, "an ordinary body was rewritten"
        assert redact.known() == (), "an ordinary body registered a 'secret'"


@pytest.mark.parametrize("lookalike, why", [
    ("eyJhbGciOiJIUzI1NiJ9.this-is-not-base64-json.sig", "payload is not JSON"),
    ("eyJub3Rqc29uIg.eyJhIjoxfQ.sig", "header is not a JSON object"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ", "only two segments"),
    ("eyJhbGciOiJIUzI1NiJ9.WyJhbiIsImFycmF5Il0.sig", "payload is an array, not an object"),
])
def test_a_value_that_resembles_a_token_but_does_not_decode_is_left_alone(lookalike, why):
    """A JWT either decodes or it does not. Guessing by shape is exactly the thing the
    injected-credential redactor refuses to do, and this half must refuse it too."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, _a, vault, _k = _engagement(tmp)
        sess.browser._cage = _LeakingCage(json.dumps({"v": lookalike}))
        sess.run_web(f"get http://{TARGET}/rest/x")
        text = _tree_text(vault)
        assert lookalike in text, f"a non-token was redacted ({why})"
        assert "[REDACTED:" not in text


# --- 5. MUST NOT BREAK: the injected half is untouched ---------------------- #

def test_an_injected_credential_still_masks_exactly_as_before():
    """The discovered half must not disturb the half that already shipped."""
    injected = ("eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImlkIjoyNSwiZW1haWwiOiJicnVrYWwtYUBq"
                "dWljZS1zaC5vcCJ9fQ.c3RhbmQtaW4tc2lnbmF0dXJl")
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, _v, kali = _engagement(tmp)
        sess.browser.auth_header = f"Bearer {injected}"
        sess.authenticated = True
        cmd = f"nuclei -u http://{TARGET}/rest/products"
        sess.run(cmd)
        assert injected in kali.executed[0], "the cage must run the real bytes"
        audit = audit_path.read_text(encoding="utf-8")
        assert injected not in audit
        assert redact.placeholder_for(injected) in audit
        assert "Authorization: Bearer" in audit, "the structure must survive"


# --- 6. the ORDERING, which is the actual defect ---------------------------- #

def test_the_token_is_masked_on_the_FIRST_record_that_carries_it():
    """The defect is an order, not an omission.

    On the shell path `Executor.run` appends the `execution` record — stdout included —
    and only then returns to `_absorb_shell`. Any registration hook living at the
    session layer therefore runs AFTER the audit already holds the token in cleartext,
    and that entry is hash-chained: there is no second chance to fix it.

    So this asserts the ORDER, not the end state. The very first audit entry carrying
    the body must already be masked."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        sess, audit_path, _v, _k = _engagement(
            tmp, kali=_EchoKali(f"HTTP/1.1 200 OK\n\n{LEAK_BODY}"))
        sess.run(f"curl http://{TARGET}/rest/admin/application-configuration")
        lines = [json.loads(l) for l in
                 audit_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        carrying = [l for l in lines if "eyJ" in json.dumps(l)
                    or redact.placeholder_for(ADMIN_JWT) in json.dumps(l)]
        assert carrying, "the audit never recorded the body at all"
        first = json.dumps(carrying[0])
        assert ADMIN_JWT not in first, \
            "the FIRST record carrying the token holds it in cleartext — registration " \
            "happened after the write, which is unfixable once the chain is sealed"
        assert redact.placeholder_for(ADMIN_JWT) in first


def test_registration_happens_inside_the_write_funnel_not_at_a_call_site():
    """Fix the property, not the instance. A hook at one capture site leaves every
    other writer — present and future — free to record a discovered credential first.
    The redactor itself must recognise one, so the ordering defect is unrepresentable
    rather than merely unfixed at the two sites we happen to know about."""
    assert redact.known() == ()
    out = redact.text(f'{{"token": "{ADMIN_JWT}"}}')
    assert ADMIN_JWT not in out
    assert redact.placeholder_for(ADMIN_JWT) in out
    assert ADMIN_JWT in redact.known(), \
        "the funnel masked it without registering it, so the NEXT surface will leak"
