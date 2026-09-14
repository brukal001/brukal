"""
test_principal_identifier_disclosure.py — the model cannot reference what it has never been shown.

THE MEASURED PROBLEM (run CM2, 2026-09-11)
    Five of seven proposals named the cross-account class. ALL FIVE died before dispatch:
    four on `POST /api/BasketItems` and `POST /rest/products/1/reviews` answering HTTP 500,
    one on an unresolved reference. Not one judged experiment used the second principal.

    The model reached for setup-heavy paths because it had no other way to name an object.
    What it is told about the two principals is **two email addresses** — plus the sentence
    *"Objects and identifiers belonging to '<email>' are the ones worth trying to reach from
    your own session, and vice versa"*, which asks it to reference objects it cannot name.
    Creating one first is the only route left, and creating one is the step that failed.

THE PROPERTY
    After each principal is established, the harness discloses THAT PRINCIPAL'S OWN
    IDENTIFIERS — drawn from its own authenticated responses, which are already held:
    the login reply, the identity probe, the signup reply. Structure and identifiers only,
    never a credential. Deterministic extraction, no model in the path, and no guessing at
    what an id is called: a key is an identifier because the RESPONSE named it one.

    Mirrors the setup-shape guarantee (`1e25473`): the disclosure may not name something
    the model cannot use. A shape line lists only paths a reference could resolve; an
    identifier line lists only values a real response actually carried.
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


class _Target:
    """Two real accounts with DIFFERENT owned objects, answering from the session it is
    given. A double that returned the same ids for both principals would let a crossed
    disclosure pass, which is one of the things under test."""

    ACCOUNTS = {
        USER_A: {"token": TOKEN_A, "id": 25, "bid": 6},
    }

    def __init__(self, echo_token: bool = False, ids: bool = True):
        self.echo_token = echo_token
        self.ids = ids
        self.registered: dict = {}
        self.seen: list = []

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
        self.seen.append((action.method, action.url))
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
            out = {"user": user}
            if self.echo_token:
                out["token"] = acc["token"]
            return WebResult(status=200, url=url, headers={}, body=json.dumps(out))
        if "/rest/basket/" in url:
            _mail, acc = self._who(action.headers)
            want = url.rsplit("/", 1)[-1]
            if acc is None:
                return WebResult(status=401, url=url, headers={}, body='{"error":"no"}')
            owned = str(acc["bid"]) == want
            return WebResult(status=200 if owned else 403, url=url, headers={},
                             body=json.dumps({"data": {"id": want, "owned": owned}}))
        if url.rstrip("/") in (BASE, f"http://{TARGET}:3000"):
            # A root the crawler can actually read, so `/api/Users` is discovered the way
            # it is on a real SPA — the JSON signup path is drawn from the CRAWL, never
            # guessed, so a double that served nothing would starve it.
            return WebResult(status=200, url=url, headers={"Content-Type": "text/html"},
                             body='<html><body><script>fetch("/api/Users");'
                                  'fetch("/rest/basket/1");fetch("/rest/user/whoami");'
                                  '</script></body></html>')
        return WebResult(status=404, url=url, headers={}, body="nope")


class _Kali:
    def run(self, command):
        return ExecResult(command, 0, "", "")


class _LLM:
    """Captures the prompt instead of answering it. The disclosure IS the deliverable."""
    last_stop_reason = "end_turn"

    def __init__(self):
        self.prompts: list[str] = []

    def propose(self, system, user, max_tokens=1024):
        self.prompts.append(user)
        return "[]"


def _session(tmp_path, target):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), _Kali(), audit, approver=lambda d: True)
    llm = _LLM()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, target, audit))
    s.allow_intrusive = True
    return s, llm, audit


def _establish_both(s, target):
    s.login(LOGIN, USER_A, PASS_A, user_field="email", login_type="json")
    s.confirm_authentication()
    s.crawl(seeds=[BASE + "/"], max_pages=5, max_depth=1)
    return s.establish_second_identity()


@pytest.fixture(autouse=True)
def _clean_redactor():
    redact.clear()
    yield
    redact.clear()


# --------------------------------------------------------------------------- #
# The defect
# --------------------------------------------------------------------------- #

def test_the_prompt_names_both_principals_own_ids(tmp_path):
    """THE DEFECT. Before this, the model was told two email addresses and asked to
    reference objects belonging to them."""
    target = _Target()
    s, llm, _ = _session(tmp_path, target)
    second = _establish_both(s, target)
    s.run_hypotheses()

    assert llm.prompts, "the experiment prompt was never built"
    prompt = llm.prompts[-1]
    assert "25" in prompt and "6" in prompt, f"principal A's own ids are absent:\n{prompt[-1200:]}"
    assert "40" in prompt or "41" in prompt, (
        f"the second principal's own ids are absent:\n{prompt[-1200:]}")
    assert second in prompt


def test_a_cross_account_experiment_needs_no_setup_step(tmp_path):
    """The point of the disclosure. CM2 lost five proposals to setups that 500'd; with the
    ids in hand the same question is two requests and no setup at all."""
    from brukal import hypothesis as hyp

    target = _Target()
    s, _llm, _ = _session(tmp_path, target)
    _establish_both(s, target)

    ids = s.principal_identifiers()
    a_basket = [v for k, v in ids["self"].items() if "bid" in k.lower()]
    assert a_basket, f"A's basket id was not disclosed: {ids}"

    h = hyp.Hypothesis(
        title="basket readable across accounts", severity="high",
        comparator="a_denied_b_allowed", setup=[],
        control={"method": "GET", "url": f"{BASE}/rest/basket/{a_basket[0]}", "as": "second"},
        variant={"method": "GET", "url": f"{BASE}/rest/basket/{a_basket[0]}", "as": "self"})
    outcomes: list = []
    s._run_one_round([h], outcomes)

    assert not any(o.startswith(("UNRESOLVED", "SETUP FAILED", "NOT AUTHENTICATED",
                                 "SECOND PRINCIPAL")) for o in outcomes), outcomes


def test_the_ids_are_per_principal_and_never_crossed(tmp_path):
    # ⚠ THIS TEST WAS GREEN THROUGHOUT RUN CM4, WHILE THE PROPERTY FAILED LIVE.
    # `_separate_identity` did not restore `last_jwt`, so a confirmation run after the
    # second principal existed probed as the SECOND principal and filed its id under
    # `self` — the map was crossed on the real target and not here. The double above
    # cannot reach it: its login is never asked for a token this code path would reuse,
    # and its identity oracle reads the Authorization header rather than a cookie, so
    # `confirm_authentication` never enters the branch that installs `session_token()`.
    # The reachable version lives in `tests/test_principal_switch_is_atomic.py`, whose
    # fixture carries the full session state and honours the cookie.
    # Kept because it still pins the per-principal extraction; it is NOT the guard for
    # the crossing defect, and should not be read as one.
    """A's ids under A, B's under B. Crossing them would hand the model a false premise
    and make every cross-account proposal built on it meaningless."""
    target = _Target()
    s, _llm, _ = _session(tmp_path, target)
    _establish_both(s, target)

    ids = s.principal_identifiers()
    assert set(ids) >= {"self", "second"}, ids
    a_vals = {str(v) for v in ids["self"].values()}
    b_vals = {str(v) for v in ids["second"].values()}
    assert "25" in a_vals and "6" in a_vals, ids["self"]
    assert not (a_vals & b_vals), f"the two principals share disclosed ids: {ids}"


def test_the_disclosed_ids_all_came_from_a_real_response(tmp_path):
    """Mirrors the setup-shape guarantee: the disclosure may not name something unusable.
    Every value offered must have been carried by a response the harness received."""
    target = _Target()
    s, _llm, _ = _session(tmp_path, target)
    _establish_both(s, target)

    ids = s.principal_identifiers()
    real = {"25", "6", "40", "41"}
    for who, found in ids.items():
        for path, value in found.items():
            assert str(value) in real, (
                f"{who}.{path}={value!r} was never in any response — a fabricated id")


# --------------------------------------------------------------------------- #
# No credential may ride along
# --------------------------------------------------------------------------- #

def test_no_credential_reaches_the_prompt(tmp_path):
    """Verified against a target that ECHOES the session token in the same body the ids
    are extracted from, because that is the body this code actually walks."""
    target = _Target(echo_token=True)
    s, llm, _ = _session(tmp_path, target)
    _establish_both(s, target)
    s.run_hypotheses()

    prompt = llm.prompts[-1]
    assert TOKEN_A not in prompt, "principal A's token reached the model"
    assert TOKEN_B not in prompt, "the second principal's token reached the model"
    assert PASS_A not in prompt


# --------------------------------------------------------------------------- #
# The boundary: a target that discloses nothing
# --------------------------------------------------------------------------- #

def test_a_target_with_no_discoverable_ids_degrades_quietly(tmp_path):
    """THE BOUNDARY. No ids anywhere in any response: the disclosure must be absent, not
    invented. A fabricated id is worse than none — it produces a confident experiment
    about an object that does not exist."""
    target = _Target(ids=False)
    s, llm, _ = _session(tmp_path, target)
    _establish_both(s, target)
    s.run_hypotheses()

    ids = s.principal_identifiers()
    assert all(not v for v in ids.values()), f"ids were invented from nothing: {ids}"
    prompt = llm.prompts[-1]
    assert "Known identifiers" not in prompt, (
        "an empty disclosure block was still emitted, which reads as 'this principal owns "
        "nothing' rather than 'we could not tell'")
