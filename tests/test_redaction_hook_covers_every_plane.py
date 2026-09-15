"""
test_redaction_hook_covers_every_plane.py — every plane's responses meet the same hook.

THE MEASURED PROBLEM (bundle CM6, 2026-09-15)
    `observe_response` registered a discovered credential where target output entered the
    record — the cage's stdout/stderr (`Executor.run`) and a captured experiment body.
    **The governed browser's responses are neither.**

    `web_result` stores `{status, url, note, bytes}` and no body, so the LEDGER was clean —
    0 JWTs, 0 MD5-shaped, 0 passwords. But `_absorb_web` folds the response into the
    session's notes and findings, which DO reach the vault. CM6's agent issued

        GET /rest/user/change-password?current=&new=csrfPwn123&repeat=csrfPwn123
        -> 200 {"user":{"id":25,...,"password":"9b3ac032ab40e753f34cbfc8be1f1dd8",...}}

    and that hash — under the key `password`, exactly what the control exists to catch —
    landed in `vault/findings.jsonl` and `vault/agents/strategist/00081.md` unmasked.

    **A clean audit log beside an unclean vault is the partial result this project has been
    wrong about before.**

THE THIRD PLANE, found while mapping rather than from the CM6 symptom
    `GovernedSession.send` (`session.py:64`) is a SECOND door: the persistent `SESSION:` shell
    audits `session_execution` itself and never passes through `Executor.run`, so its
    output was unhooked too. CM5 and CM6 both opened live sessions.

THE PROPERTY
    Every plane that receives target output passes it through the SAME registration point,
    at that plane's single door — so a fourth plane added later inherits it instead of
    silently going unhooked, which is the failure mode this test exists for.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope, redact
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebAction, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"

# CM6's actual value and its actual shape.
CM6_HASH = "9b3ac032ab40e753f34cbfc8be1f1dd8"
CM6_BODY = json.dumps({"user": {"id": 25, "username": "", "email": "a@brukal.test",
                                "password": CM6_HASH, "role": "customer"}})
# A response that carries ONLY identifiers — the boundary the comparator depends on.
IDS_ONLY = json.dumps({"status": "success",
                       "data": {"id": 6, "UserId": 25, "BasketId": 9, "Products": []}})


class _Target:
    def run(self, action):
        url = action.url
        if "change-password" in url:
            return WebResult(status=200, url=url, headers={}, body=CM6_BODY)
        if "/rest/basket/" in url:
            return WebResult(status=200, url=url, headers={}, body=IDS_ONLY)
        return WebResult(status=200, url=url, headers={}, body='{"ok":true}')


class _Kali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _LLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return "[]"


def _session(tmp_path):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(_LLM()),
                      browser=GovernedBrowser(scope, _Target(), audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    return s, audit


def _vault_blob(tmp_path) -> str:
    out = []
    for f in (tmp_path / "vault").rglob("*"):
        if f.is_file():
            try:
                out.append(f.read_text(errors="replace"))
            except Exception:
                pass
    return "\n".join(out)


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_cm6s_case_is_masked_in_the_VAULT_not_only_the_ledger(tmp_path):
    """THE DEFECT, with CM6's request and CM6's body. The ledger was already clean; the
    vault was not, and the vault is what a reader opens."""
    s, audit = _session(tmp_path)
    s.browser.run(WebAction("request", method="GET",
                            url=f"{BASE}/rest/user/change-password"
                                f"?current=&new=csrfPwn123&repeat=csrfPwn123"))
    s.note("change-password probe returned: " + CM6_BODY)
    s._write_notebook()

    vault = _vault_blob(tmp_path)
    assert CM6_HASH not in vault, (
        "the secret the target NAMED reached the vault unmasked — this is CM6's P1")
    assert "[REDACTED:" in vault, "nothing was masked; the assertion above proves nothing"


def test_it_is_masked_across_every_vault_surface(tmp_path):
    """notes, findings and the rendered pages — one registration, every surface."""
    s, audit = _session(tmp_path)
    s.browser.run(WebAction("request", method="GET",
                            url=f"{BASE}/rest/user/change-password?new=csrfPwn123"))
    s.note("probe: " + CM6_BODY)
    s._persist_finding("note", "", "", CM6_BODY, [])
    s._write_notebook()

    for name in ("engagement.md", "findings.jsonl"):
        f = tmp_path / "vault" / name
        if f.exists():
            assert CM6_HASH not in f.read_text(errors="replace"), f"unmasked in {name}"


def test_the_live_shell_plane_is_hooked_too(tmp_path):
    """THE THIRD PLANE, found by mapping the doors rather than from CM6's symptom.

    `GovernedSession.send` audits `session_execution` itself and never passes through
    `Executor.run`, so its output was unhooked. CM5 and CM6 both opened live sessions."""
    from brukal.session import GovernedSession

    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")

    class _Backend:
        alive = True

        def send(self, line):
            return ExecResult(line, 0, CM6_BODY, "")

        def close(self):
            pass

    sess = GovernedSession(Gate(scope), _Backend(), audit, target=TARGET,
                       approver=lambda d: True)
    sess.send("curl -s http://10.10.10.5:3000/rest/user/change-password")
    assert redact.text(CM6_HASH) != CM6_HASH, (
        "the persistent shell's output was not registered — a second uncovered door")


# --------------------------------------------------------------------------- #
# BOUNDARY — the identifiers the milestone capability depends on
# --------------------------------------------------------------------------- #

def test_resource_identifiers_are_still_not_masked(tmp_path):
    """BOUNDARY, load-bearing: `cross_account_resource` matches ownership BY VALUE against
    ids read out of responses. Masking 6, 9 or 25 disables the capability CM5/CM6 proved."""
    s, audit = _session(tmp_path)
    s.browser.run(WebAction("request", method="GET", url=f"{BASE}/rest/basket/6"))
    s.note("basket: " + IDS_ONLY)
    s._write_notebook()

    vault = _vault_blob(tmp_path)
    assert '"id": 6' in vault or '"id":6' in vault or "/rest/basket/6" in vault
    assert "[REDACTED:" not in vault, "an identifier-only response was masked"


def test_cross_account_resource_still_confirms_after_the_hook(tmp_path):
    """The capability itself, end to end, with the new hook live."""
    from brukal import hypothesis as hyp
    s, audit = _session(tmp_path)
    s._record_principal_ids("self", "login", json.dumps({"authentication": {"bid": 6}}))
    s._record_principal_ids("second", "login", json.dumps({"authentication": {"bid": 9}}))
    h = hyp.Hypothesis(title="x", severity="high", comparator="cross_account_resource",
                       setup=[],
                       control={"method": "GET", "url": f"{BASE}/rest/basket/6",
                                "as": "self"},
                       variant={"method": "GET", "url": f"{BASE}/rest/basket/9",
                                "as": "self"})
    assert s._run_one_round([h], []) == 1, "the cross-account capability regressed"


def test_a_response_with_no_secret_is_byte_identical(tmp_path):
    """BOUNDARY. The hook must be invisible when there is nothing to register."""
    s, audit = _session(tmp_path)
    s.browser.run(WebAction("request", method="GET", url=f"{BASE}/rest/products"))
    s.note("plain: " + '{"ok":true}')
    s._write_notebook()
    vault = _vault_blob(tmp_path)
    assert '{"ok":true}' in vault
    assert "[REDACTED:" not in vault
