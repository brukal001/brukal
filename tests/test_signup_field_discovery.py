"""
test_signup_field_discovery.py — ask the endpoint what it wants; never guess.

THE MEASURED PROBLEM (CR1 portability tally, item 5)
    `_register_account_json` posted a FIXED body — {email, password, passwordRepeat,
    username} — confirmed live against Juice Shop in August. crAPI's signup also requires
    `name` and `number`, so the second principal was unreachable on the target chosen
    specifically because both principals can be verified there.

WHY NOT JUST ADD THE TWO FIELDS
    Because the next target has a third. A hardcoded list is the assumption that broke,
    and lengthening it does not stop it breaking — it only moves the break to the target
    after this one. The endpoint already answers the question: crAPI's own 400 NAMES both
    missing fields. So: post the minimal body, READ THE REFUSAL, add what it named, retry.

    Deterministic string work, no model — a registration payload is built from what the
    application said, and an application that names nothing gets a fail-closed refusal
    with a recorded reason rather than a guess.

THE REAL BODY, captured from crAPI at 172.20.0.12 on 2026-09-17.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.blackboard import Blackboard
from brukal.kali import ExecResult
from brukal.signup import missing_fields, synth_value
from brukal.web import GovernedBrowser, WebAction, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:3000"

CRAPI_400 = json.dumps({
    "message": "Validation failed",
    "details": ("org.springframework.validation.BeanPropertyBindingResult: 2 errors\n"
                "Field error in object 'signUpForm' on field 'number': rejected value "
                "[null]; codes [NotBlank.signUpForm.number,NotBlank.number,"
                "NotBlank.java.lang.String,NotBlank]; arguments [...]; default message "
                "[must not be blank]\n"
                "Field error in object 'signUpForm' on field 'name': rejected value "
                "[null]; codes [NotBlank.signUpForm.name,NotBlank.name,"
                "NotBlank.java.lang.String,NotBlank]; arguments [...]; default message "
                "[must not be blank]")})


# --------------------------------------------------------------------------- #
# The reader
# --------------------------------------------------------------------------- #

def test_crAPIs_real_refusal_names_its_missing_fields():
    assert set(missing_fields(CRAPI_400)) == {"name", "number"}


@pytest.mark.parametrize("body,want", [
    (json.dumps({"number": ["This field is required."]}), {"number"}),
    (json.dumps({"errors": {"phone": ["must not be blank"], "name": ["required"]}}),
     {"phone", "name"}),
    (json.dumps({"message": "name is required"}), {"name"}),
    (json.dumps({"message": "Missing required field: country_code"}), {"country_code"}),
    ('{"error":"the field \'dob\' must not be blank"}', {"dob"}),
])
def test_the_common_refusal_shapes_are_read(body, want):
    assert set(missing_fields(body)) >= want, body


@pytest.mark.parametrize("body", [
    json.dumps({"error": "bad request"}),
    json.dumps({"message": "Validation failed"}),
    "<html><body>400</body></html>",
    "",
])
def test_a_refusal_that_names_nothing_yields_nothing(body):
    """Fail-closed input to a fail-closed caller: no name, no guess."""
    assert missing_fields(body) == []


def test_fields_we_already_send_are_never_re_added():
    """The reader must not re-propose a field that is already in the body, or the loop
    spins forever on an endpoint that rejects for some other reason."""
    got = missing_fields(json.dumps({"email": ["is required"], "name": ["is required"]}),
                         already={"email"})
    assert got == ["name"]


def test_a_value_is_synthesised_by_the_FIELD_NAME_not_at_random():
    """crAPI validates `number` as a phone number. A field named for a phone gets digits;
    a field named for a person gets a name-shaped string."""
    assert synth_value("number", "abc123").isdigit()
    assert synth_value("phone", "abc123").isdigit()
    assert synth_value("name", "abc123").isalnum()
    assert "@" in synth_value("contact_email", "abc123")


# --------------------------------------------------------------------------- #
# The registration path
# --------------------------------------------------------------------------- #

class _Signup:
    """A signup endpoint that refuses until it has the fields it wants, then echoes the
    account back. `wants` is what this application requires beyond the base body."""

    def __init__(self, wants=(), refusal=CRAPI_400, echo=True, name_nothing=False):
        self.wants = set(wants)
        self.refusal = refusal
        self.echo = echo
        self.name_nothing = name_nothing
        self.posts: list = []

    def run(self, action):
        url = action.url
        if url.endswith("/signup") or url.endswith("/api/users"):
            body = json.loads(action.body or "{}")
            self.posts.append(body)
            missing = self.wants - set(body)
            if missing:
                if self.name_nothing:
                    return WebResult(status=400, url=url, body='{"error":"bad request"}')
                det = "\n".join(f"Field error in object 'f' on field '{m}': rejected "
                                f"value [null]; default message [must not be blank]"
                                for m in sorted(missing))
                return WebResult(status=400, url=url,
                                 body=json.dumps({"message": "Validation failed",
                                                  "details": det}))
            out = dict(body) if self.echo else {"ok": True}
            return WebResult(status=201, url=url, body=json.dumps(out))
        return WebResult(status=200, url=url, body="{}")


def _session(tmp_path, cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn",
                         "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit),
                      blackboard=Blackboard(tmp_path / "vault", scope))
    s.allow_intrusive = True
    s.surface = type("S", (), {"seed": BASE, "api_routes": ["/identity/api/auth/signup"],
                               "pages": {}})()
    return s


def test_crAPIs_shape_succeeds(tmp_path):
    """THE DEFECT: two fields named in a refusal, supplied, account created."""
    cage = _Signup(wants={"name", "number"})
    s = _session(tmp_path, cage)
    made = s._register_account_json()
    assert made is not None, "the second principal is still unreachable on crAPI's shape"
    email, _pw = made
    assert "@" in email
    final = cage.posts[-1]
    assert "name" in final and "number" in final
    assert final["number"].isdigit(), "crAPI validates `number`; a word would be refused"


def test_juice_shops_shape_is_unchanged(tmp_path):
    """BOUNDARY: a target that accepts the base body is asked exactly once. No extra
    POST, no extra account, no behaviour change on the surface this was built against."""
    cage = _Signup(wants=set())
    s = _session(tmp_path, cage)
    assert s._register_account_json() is not None
    assert len(cage.posts) == 1, cage.posts


def test_an_endpoint_that_names_nothing_FAILS_CLOSED_with_a_reason(tmp_path):
    cage = _Signup(wants={"name"}, name_nothing=True)
    s = _session(tmp_path, cage)
    assert s._register_account_json() is None
    assert getattr(s, "signup_refusal", ""), "it failed without recording why"
    assert "named no field" in s.signup_refusal.lower()
    assert any("not established" in n.lower() for n in s.notes), s.notes[-3:]


def test_the_discovery_loop_is_BOUNDED(tmp_path):
    """An endpoint that always names one more field must not be asked forever."""
    class _Endless(_Signup):
        def __init__(self):
            super().__init__(wants=set())
            self.n = 0
        def run(self, action):
            if action.url.endswith("/signup"):
                self.posts.append(json.loads(action.body or "{}"))
                self.n += 1
                return WebResult(status=400, url=action.url, body=json.dumps(
                    {"details": f"Field error in object 'f' on field 'extra{self.n}': "
                                f"default message [must not be blank]"}))
            return WebResult(status=200, url=action.url, body="{}")
    cage = _Endless()
    s = _session(tmp_path, cage)
    assert s._register_account_json() is None
    assert len(cage.posts) <= 4, f"{len(cage.posts)} POSTs to a signup endpoint"
    assert getattr(s, "signup_refusal", "")


def test_a_2xx_that_does_not_echo_the_account_is_still_rejected(tmp_path):
    """BOUNDARY: the SPA catch-all guard is untouched — a 2xx proves nothing on its own."""
    cage = _Signup(wants=set(), echo=False)
    s = _session(tmp_path, cage)
    assert s._register_account_json() is None
