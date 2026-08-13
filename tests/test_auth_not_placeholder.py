"""
test_auth_not_placeholder.py — a REDACTION PLACEHOLDER IS NOT A CREDENTIAL.

The regression this pins was introduced by the redaction boundary itself (`66185da`) and
found while verifying it. It is the nastiest shape a defect can take here: it makes an
authenticated run silently unauthenticated, and the ledger cannot tell the difference.

The chain:
  1. `assist.py` put the REAL bearer token into the hypothesis prompt on purpose — an
     earlier bug had the model inventing `Bearer <userA_token>`, which the target
     rejected, so every authenticated experiment tested nothing.
  2. The redactor now masks that token at `LLMClient.propose`, so the model receives
     `Bearer [REDACTED:...]` instead.
  3. The model copies it into a proposed request, as it was told to.
  4. `GovernedBrowser._apply_cookies` attaches the real credential only when the request
     carries no Authorization header — so the placeholder SUPPRESSES the real session.
  5. The request goes out unauthenticated. No gate denial, no error, no note.

A Juice Shop business-logic run in that state would report "nothing found" while logged
OUT, and that result is indistinguishable in the ledger from a real one.

Two properties, fixed at two different levels:

  * **The model never handles the credential.** It does not need to: `_as_identity`
    already swaps the principal for `"as": "self" | "second" | "anonymous"`, and the
    governed browser attaches whatever that principal holds. Telling the model to set the
    header itself defeats that machinery even when the value is real.
  * **Redaction output is never accepted as input.** A `[REDACTED:...]` marker in an
    outgoing credential is a RECORD artifact that has looped back into an ACTION. It is
    recognised by shape (deterministic, no LLM — invariant 1) and dropped, so the real
    credential is attached in its place. Enforced on BOTH planes: the governed browser
    and the shell-command auth injector, which had the identical hole.

None of this weakens redaction: the token stays masked on every record surface. It stops
being something the model is ever shown or asked to carry.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope, redact
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebAction, WebResult

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImlkIjoyNSwiZW1haWwiOiJicnVrYWwtYUBqdWlj"
       "ZS1zaC5vcCIsInBhc3N3b3JkIjoiZWMwODRjZmFmNSJ9fQ.c3RhbmQtaW4tc2ln")
TARGET = "10.10.10.5"


@pytest.fixture(autouse=True)
def _clean_registry():
    redact.clear()
    yield
    redact.clear()


class _RecordingCage:
    """Records the action as it reached the network — headers included."""
    def __init__(self):
        self.sent: list = []

    def run(self, action):
        self.sent.append(action)
        return WebResult(status=200, url=action.url, body="<html></html>")


def _browser(cage=None):
    scope = load_scope(FIXTURE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    b = GovernedBrowser(scope, cage or _RecordingCage(), audit)
    b.auth_header = f"Bearer {JWT}"
    return b


# --- 1. the model is never handed the credential ---------------------------- #

class _CaptureLLM:
    """Stands in for the strategist's LLMClient at the point the prompt is BUILT, so
    this asserts what the builder puts in — not merely what the redactor later masks."""
    def __init__(self):
        self.prompts: list[str] = []
        self.last_stop_reason = ""
        self.last_block_kinds = []

    def propose(self, system, user, max_tokens=1024):
        self.prompts.append(f"{system}\n{user}")
        return ""


class _Surface:
    seed = f"http://{TARGET}/"
    soft_404 = False

    def summary(self):
        return "GET /rest/products\nGET /rest/basket/{id}"


def _hypothesis_prompt() -> str:
    cage = _RecordingCage()
    scope = load_scope(FIXTURE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    browser = _browser(cage)
    llm = _CaptureLLM()
    sess = AssistSession(TARGET, ex, StrategistAgent(llm), browser=browser)
    sess.authenticated = True
    sess.last_jwt = JWT
    sess.surface = _Surface()
    sess.run_hypotheses()
    assert llm.prompts, "the hypothesis prompt was never built"
    return llm.prompts[0]


def test_the_hypothesis_prompt_does_not_carry_the_session_token():
    """The model must never see the credential — not the real one, not a masked one."""
    prompt = _hypothesis_prompt()
    assert JWT not in prompt
    assert not redact.has_placeholder(prompt), \
        "a masked token in the prompt is worse than none: the model copies it verbatim"


def test_the_hypothesis_prompt_does_not_ask_the_model_to_set_an_auth_header():
    """Even a REAL token placed by the model defeats the principal machinery: a
    caller-set Authorization header suppresses whatever `as: second`/`anonymous` would
    have attached. Authentication is the governed layer's job, and only its job."""
    prompt = _hypothesis_prompt()
    low = prompt.lower()
    assert "use this header verbatim" not in low
    assert "authorization" not in low or "do not set" in low or "automatically" in low


# --- 2. the uncovered path: a placeholder must not suppress the real session - #

def test_a_placeholder_auth_header_does_not_suppress_the_real_credential():
    """THE regression. Today the placeholder is treated as a caller-set credential and
    the real session is withheld — the request goes out logged OUT, silently."""
    b = _browser()
    a = WebAction("request", url=f"http://{TARGET}/rest/basket/6", method="GET",
                  headers={"Authorization": "Bearer [REDACTED:ed82603d]"})
    b._apply_cookies(a)
    assert a.headers["Authorization"] == f"Bearer {JWT}"
    assert not redact.has_placeholder(a.headers["Authorization"])


def test_a_placeholder_cookie_does_not_suppress_the_real_jar():
    b = _browser()
    b.auth_header = ""
    b._cookies = {"connect.sid": "s%3Areal-session-value"}
    a = WebAction("request", url=f"http://{TARGET}/rest/basket/6", method="GET",
                  headers={"Cookie": "connect.sid=[REDACTED:ab12cd34]"})
    b._apply_cookies(a)
    assert a.headers["Cookie"] == "connect.sid=s%3Areal-session-value"


def test_the_real_credential_reaches_the_network_through_the_governed_path():
    """End to end through `run()` — the gate, then the cage. What the target actually
    receives is what matters; `_apply_cookies` in isolation could be right while the
    ordering around it was wrong."""
    cage = _RecordingCage()
    b = _browser(cage)
    a = WebAction("request", url=f"http://{TARGET}/rest/basket/6", method="GET",
                  headers={"Authorization": "Bearer [REDACTED:ed82603d]"})
    decision, result = b.run(a, agent="operator")
    assert decision.verdict == "ALLOW" and result is not None
    assert cage.sent, "the action never reached the cage"
    assert cage.sent[0].headers["Authorization"] == f"Bearer {JWT}"


def test_a_genuine_caller_set_header_is_still_not_overridden():
    """The boundary. `_apply_cookies` must keep honouring a deliberately set credential —
    that is how a cross-account prover issues a request as the OTHER principal. Only a
    redaction placeholder is treated as not-a-credential."""
    b = _browser()
    a = WebAction("request", url=f"http://{TARGET}/rest/basket/7", method="GET",
                  headers={"Authorization": "Bearer second-principal-token"})
    b._apply_cookies(a)
    assert a.headers["Authorization"] == "Bearer second-principal-token"


# --- 3. the same hole on the shell plane ------------------------------------ #

def test_a_placeholder_header_on_a_shell_command_does_not_block_real_injection():
    """`_session_auth_for` skips injection when the command already carries a header.
    A model-written command carrying a placeholder tripped that check the same way, so
    the shell plane ran unauthenticated too — the identical defect, second site."""
    scope = load_scope(FIXTURE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(_CaptureLLM()), browser=_browser())
    sess.authenticated = True
    out = sess._session_auth_for(
        f"nuclei -u http://{TARGET}/x -H 'Authorization: Bearer [REDACTED:ed82603d]'")
    assert JWT in out, "the real session must be carried"
    assert not redact.has_placeholder(out)


def test_a_shell_command_carrying_real_auth_is_still_left_alone():
    """Boundary, as above: a real header the caller set is not touched."""
    scope = load_scope(FIXTURE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    sess = AssistSession(TARGET, ex, StrategistAgent(_CaptureLLM()), browser=_browser())
    sess.authenticated = True
    cmd = f"curl -H 'Authorization: Bearer real-other-token' http://{TARGET}/x"
    assert sess._session_auth_for(cmd) == cmd


# --- 4. the marker is recognised by SHAPE, deterministically ---------------- #

def test_a_placeholder_is_recognised_without_consulting_the_registry():
    """A placeholder restored from an old checkpoint belongs to an engagement whose
    credential set is long gone. Recognition is by shape, so it still cannot be sent."""
    redact.clear()
    assert redact.has_placeholder("Bearer [REDACTED:00ff11aa]")
    assert not redact.has_placeholder("Bearer eyJhbGciOiJIUzI1NiJ9.abc")
    assert not redact.has_placeholder("see [REDACTED] in the docs")   # not the real shape
    assert not redact.has_placeholder("")
