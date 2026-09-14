"""
test_principal_ownership_ledger.py — the LEDGER must record who owns what, and how it knows.

THE MEASURED PROBLEM (run CM3, 2026-09-14)
    Principal A read `/rest/basket/8`, which belongs to the second principal, and read that
    principal's profile. The model's claim was correct and the harness issued the requests
    that prove it. **No artifact can say so.**

    `5e7219a` taught the harness each principal's own identifiers and wrote them to the
    PROMPT. Grepped across every CM3 artifact, `Known identifiers, per principal` occurs
    ZERO times and no `bid` occurs anywhere in the ledger. The ownership map existed only
    in memory and in a model's context window, so a reader holding the bundle cannot
    evaluate an ownership claim at all.

THE PROPERTY
    When a principal's identifiers are learned, the LEDGER records them: which principal
    owns which identifier, and the PROVENANCE of each — the response that carried it.
    Deterministic, no model. Redaction is INHERITED from `audit.append` (which applies
    `redact.data` to every record), never re-implemented here.

    This is the August principal-provenance defect (`2fdbc7f`) in a new form: then it was
    which principal ISSUED a request, now it is which principal OWNS a resource.
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
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"
LOGIN = f"{BASE}/rest/user/login"
TOKEN_A = "tok-AAAA-1111-secret"
TOKEN_B = "tok-BBBB-2222-secret"
USER_A, PASS_A = "a@brukal.test", "Pw-A-1!"

OWNERSHIP = "principal_ownership"


class _Target:
    """Two accounts owning DIFFERENT objects. A double returning the same ids for both
    would let a crossed ownership record pass, which is one of the things under test.

    `token_under_id_key` puts the live session token under `sessionId` — an id-SHAPED key,
    so extraction takes it and the record must then be saved by the inherited redaction
    rather than by anything this feature writes.
    """

    ACCOUNTS = {USER_A: {"token": TOKEN_A, "id": 25, "bid": 6}}

    def __init__(self, ids: bool = True, token_under_id_key: bool = False):
        self.ids = ids
        self.token_under_id_key = token_under_id_key
        self.registered: dict = {}

    def _who(self, headers):
        raw = ""
        for k, v in (headers or {}).items():
            if k.lower() == "cookie":
                raw = v or ""
            if k.lower() == "authorization":
                t = (v or "")[7:]
                for mail, acc in {**self.ACCOUNTS, **self.registered}.items():
                    if acc["token"] == t:
                        return mail, acc
        for part in raw.split(";"):
            if "=" in part:
                _k, _, val = part.partition("=")
                for mail, acc in {**self.ACCOUNTS, **self.registered}.items():
                    if acc["token"] == val.strip():
                        return mail, acc
        return "", None

    def run(self, action):
        url, body = action.url, action.body or ""
        if url.endswith("/rest/user/login"):
            if action.method != "POST":
                return WebResult(status=500, url=url, headers={}, body="")
            try:
                sent = json.loads(body)
            except Exception:
                sent = {}
            acc = {**self.ACCOUNTS, **self.registered}.get(sent.get("email", ""))
            if not acc:
                return WebResult(status=401, url=url, headers={}, body='{"error":"no"}')
            payload = {"authentication": {"token": acc["token"], "umail": sent["email"]}}
            if self.ids:
                payload["authentication"]["bid"] = acc["bid"]
            return WebResult(status=200, url=url, headers={}, body=json.dumps(payload))
        if url.endswith("/api/Users") and action.method == "POST":
            sent = json.loads(body)
            n = 40 + len(self.registered)
            self.registered[sent["email"]] = {"token": TOKEN_B, "id": n, "bid": n + 1}
            data = {"email": sent["email"], "role": "customer"}
            if self.ids:
                data["id"] = n
            return WebResult(status=201, url=url, headers={},
                             body=json.dumps({"status": "success", "data": data}))
        if url.endswith("/rest/user/whoami"):
            _mail, acc = self._who(action.headers)
            if acc is None:
                return WebResult(status=200, url=url, headers={}, body='{"user":{}}')
            user = {"email": _mail}
            if self.ids:
                user["id"] = acc["id"]
            if self.token_under_id_key:
                user["sessionId"] = acc["token"]
            return WebResult(status=200, url=url, headers={},
                             body=json.dumps({"user": user}))
        if url.rstrip("/") in (BASE, f"http://{TARGET}:3000"):
            return WebResult(status=200, url=url, headers={"Content-Type": "text/html"},
                             body='<html><body><script>fetch("/api/Users");'
                                  'fetch("/rest/user/whoami");</script></body></html>')
        return WebResult(status=404, url=url, headers={}, body="nope")


class _Kali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _LLM:
    last_stop_reason = "end_turn"

    def propose(self, system, user, max_tokens=1024):
        return "[]"


def _session(tmp_path, target):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    s = AssistSession(TARGET, ex, StrategistAgent(_LLM()),
                      browser=GovernedBrowser(scope, target, audit))
    s.allow_intrusive = True
    return s, audit


def _establish_both(s):
    s.login(LOGIN, USER_A, PASS_A, user_field="email", login_type="json")
    s.confirm_authentication()
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    return s.establish_second_identity()


def _records(audit_path: Path) -> list[dict]:
    out = []
    for line in Path(audit_path).read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("kind") == OWNERSHIP:
            out.append(e.get("data", {}))
    return out


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_the_ledger_names_which_principal_owns_which_id(tmp_path):
    """THE DEFECT. CM3's ownership map reached the prompt and no artifact."""
    s, audit = _session(tmp_path, _Target())
    _establish_both(s)

    recs = _records(audit.path)
    assert recs, "no principal_ownership record reached the ledger"

    owned: dict = {}
    for r in recs:
        owned.setdefault(r["principal"], set()).add(str(r["value"]))

    assert "self" in owned and "second" in owned, f"both principals must appear: {owned}"
    # A owns id 25 / basket 6; B is registered as 40 and owns basket 41.
    assert "25" in owned["self"] and "6" in owned["self"], owned["self"]
    assert "40" in owned["second"], owned["second"]


def test_every_owned_id_carries_its_provenance(tmp_path):
    """An ownership map with no source is the 2C2 external-seeding defect wearing a hat."""
    s, audit = _session(tmp_path, _Target())
    _establish_both(s)

    recs = _records(audit.path)
    assert recs
    for r in recs:
        assert r.get("source"), f"no provenance on {r!r}"
        assert r["source"] in ("login", "whoami", "signup"), r["source"]
        assert r.get("path"), f"no field path on {r!r}"
        assert r.get("name"), f"no identifier name on {r!r}"


def test_owned_ids_are_never_crossed_between_principals(tmp_path):
    """A crossed ownership record is worse than none: every claim built on it inherits a
    false premise, and Fix 3 will CONFIRM findings off this map."""
    s, audit = _session(tmp_path, _Target())
    _establish_both(s)

    owned: dict = {}
    for r in _records(audit.path):
        owned.setdefault(r["principal"], set()).add(str(r["value"]))
    assert owned.get("self") and owned.get("second")
    assert not (owned["self"] & owned["second"]), (
        f"an identifier was attributed to BOTH principals: {owned}")


def test_no_credential_value_reaches_the_ownership_record(tmp_path):
    """DRIVEN, not assumed: the token is served under an id-SHAPED key (`sessionId`), so
    extraction takes it and only the INHERITED `redact.data` in `audit.append` can save
    it. Nothing in this feature may re-implement redaction."""
    s, audit = _session(tmp_path, _Target(token_under_id_key=True))
    _establish_both(s)

    blob = Path(audit.path).read_text(errors="replace")
    assert TOKEN_A not in blob, "the live session token reached the ledger in cleartext"
    assert TOKEN_B not in blob, "the second principal's token reached the ledger"

    # Control: the record surface is populated, so the absence above is redaction and not
    # an empty file.
    recs = _records(audit.path)
    assert recs, "no ownership record at all — the assertion proved nothing"

    # And the POSITIVE form: the id-shaped key was extracted and reached the record, where
    # the funnel MASKED it. Absence alone would also be satisfied by never extracting it,
    # which is a different (and weaker) guarantee than the one claimed.
    masked = [r for r in recs if r["name"] == "sessionId"]
    assert masked, f"the id-shaped key was never extracted, so nothing was masked: {recs}"
    assert str(masked[0]["value"]).startswith("[REDACTED:"), masked[0]


def test_a_target_with_no_discoverable_ids_records_nothing(tmp_path):
    """BOUNDARY. Silence, never a fabricated id: the disclosure and the record may only
    name values a real response carried."""
    s, audit = _session(tmp_path, _Target(ids=False))
    _establish_both(s)

    assert _records(audit.path) == [], "an ownership record was invented from nothing"
