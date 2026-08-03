"""
test_credstore.py — the last three findings Shannon had and Brukal did not.

Plaintext credential storage, unthrottled account creation, and an unauthenticated
database-reset endpoint. Each is provable without reading source and without invoking
anything destructive — which is the whole point, since Shannon reached the first by
reading the repository and the third by exploiting it.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

B = "http://127.0.0.1:5000"
REG = B + "/users/v1/register"
DEBUG = B + "/users/v1/_debug"


class _Api:
    def __init__(self, hashes: bool = False, throttle_after=None):
        self.hashes, self.throttle_after = hashes, throttle_after
        self.accounts: list = []

    def run(self, action):
        if action.url == REG and (action.method or "").upper() == "POST":
            if self.throttle_after is not None and len(self.accounts) >= self.throttle_after:
                return WebResult(status=429, url=action.url,
                                 body='{"message":"Too many requests"}')
            body = json.loads(action.body or "{}")
            self.accounts.append((body.get("username"), body.get("password")))
            return WebResult(status=200, url=action.url, body='{"status":"success"}')
        if action.url == DEBUG:
            rows = [{"username": u,
                     "password": ("$2b$hashed$" + str(abs(hash(p)))) if self.hashes else p}
                    for u, p in self.accounts]
            return WebResult(status=200, url=action.url, body=json.dumps({"users": rows}))
        return WebResult(status=404, url=action.url, body="{}")


def _sess(cage, intrusive=True, protected=(), routes=()):
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))
    sess.allow_intrusive = intrusive
    s = AttackSurface(seed=B + "/")
    s.add_routes(list(routes))
    s.protected_routes = list(protected)
    sess.surface = s
    return sess


# -- plaintext credential storage ---------------------------------------------

def test_a_planted_password_coming_back_verbatim_proves_recoverable_storage():
    """Finding *a* password proves an exposure; finding THE one we just chose proves
    storage, because a hash cannot reproduce it."""
    sess = _sess(_Api(hashes=False))
    assert sess.confirm_plaintext_password_storage(REG, [DEBUG]) is True
    f = sess.findings.all()[0]
    assert f.severity == "high" and "cannot reproduce" in f.evidence


def test_a_hashed_store_yields_no_finding():
    sess = _sess(_Api(hashes=True))
    assert sess.confirm_plaintext_password_storage(REG, [DEBUG]) is False
    assert not sess.findings.all()


def test_credential_probe_needs_authorisation_because_it_creates_an_account():
    api = _Api()
    sess = _sess(api, intrusive=False)
    assert sess.confirm_plaintext_password_storage(REG, [DEBUG]) is False
    assert api.accounts == []


# -- unthrottled account creation ---------------------------------------------

def test_repeated_signups_with_no_pushback_are_confirmed():
    sess = _sess(_Api())
    assert sess.confirm_unthrottled_registration(REG, attempts=4) is True
    assert "4 accounts" in sess.findings.all()[0].evidence


def test_an_app_that_throttles_signups_yields_nothing():
    sess = _sess(_Api(throttle_after=2))
    assert sess.confirm_unthrottled_registration(REG, attempts=6) is False
    assert not sess.findings.all()


# -- destructive endpoint, proved from the contract ---------------------------

def test_the_spec_declaring_it_open_is_evidence_without_invoking_it():
    """Shannon reported this by exploiting the endpoint. The application's own document
    already says it, and reading that harms nothing."""
    api = _Api()
    sess = _sess(api, protected=[("GET", "/me"), ("PUT", "/users/v1/{u}/email")],
                 routes=["/createdb", "/me", "/users/v1"])
    assert sess.confirm_destructive_endpoint_exposed(B + "/createdb", B + "/me") is True
    f = sess.findings.all()[0]
    assert "NOT requested" in f.source and "needs no authentication" in f.evidence


def test_a_spec_that_protects_nothing_is_no_evidence_at_all():
    """Without a baseline the omission says nothing — plenty of documents simply never
    use securitySchemes."""
    sess = _sess(_Api(), protected=[], routes=["/createdb"])
    assert sess._spec_says_unprotected(B + "/createdb") == ""


def test_a_destructive_route_the_spec_does_protect_is_not_reported():
    sess = _sess(_Api(), protected=[("POST", "/createdb"), ("GET", "/me")],
                 routes=["/createdb", "/me"])
    assert sess._spec_says_unprotected(B + "/createdb") == ""
