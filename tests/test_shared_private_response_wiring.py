"""
test_shared_private_response_wiring.py — the ENGINE half of the isolation comparator.

The comparator is proven in isolation in test_shared_private_response_comparator.py. This
drives the REAL experiment loop (`_run_one_round`) against a fake target that answers by
identity, and asserts:

  - the engine issues the anonymous PROBE for a `shared_private_response` experiment and,
    when the anonymous caller is refused while two distinct principals get the same private
    body, publishes a CONFIRMED finding — capped MEDIUM, not the model's HIGH;
  - when the endpoint is PUBLIC (the anonymous caller is served the same body), nothing is
    confirmed — the load-bearing guard, exercised through the real probe rather than a
    hand-set flag;
  - the probe is NOT issued for other comparators — it costs a request, so it must stay
    scoped to the one relation that needs it.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.hypothesis import Hypothesis

URL = "http://127.0.0.1:5000/api/me/dashboard"
PRIVATE = '{"balance":"4210.55","owner":"alice@example.com","statements":[1,2,3,4]}'


class _FakeLLM:
    def propose(self, system, user, max_tokens=1024):
        return "[]"


class _IdentityCage:
    """Answers by WHO is asking, read from the browser's live auth header.

    `served_to_anon` flips the endpoint between private (anonymous refused) and public
    (anonymous served the same body) without touching the authenticated behaviour."""

    def __init__(self, served_to_anon: bool):
        self.served_to_anon = served_to_anon
        self.browser = None
        self.seen: list = []

    def run(self, action):
        from brukal.web import WebResult
        self.seen.append(action.url)
        anon = not (getattr(self.browser, "auth_header", "") or "")
        if anon and not self.served_to_anon:
            return WebResult(status=403, url=action.url, body="")
        # Every authenticated principal — and, when public, the anonymous one too — is
        # handed the SAME private record. That identity is the whole finding.
        return WebResult(status=200, url=action.url, body=PRIVATE)


def _session(cage):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.blackboard import Blackboard
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    root = Path(tempfile.mkdtemp())
    audit = AuditLog(root / "a.jsonl")
    browser = GovernedBrowser(scope, cage, audit)
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_FakeLLM()), browser=browser)
    sess.blackboard = Blackboard(root / "vault", scope)
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    sess._root, sess._audit_path = root, root / "a.jsonl"
    # A held session for `self`, and a distinct second principal so `as: second` resolves.
    sess.browser.auth_header = "Bearer self-token"
    sess._second_identity = {"user": "brk2", "password": "x",
                             "cookies": {"session": "second-session"},
                             "auth": "Bearer second-token"}
    cage.browser = browser
    return sess


def _hyp(comparator="shared_private_response", control_as="self", variant_as="second"):
    return Hypothesis(
        "does every logged-in user get the same private dashboard?", "high", comparator,
        {"url": URL, "method": "GET", "as": control_as},
        {"url": URL, "method": "GET", "as": variant_as}, setup=[])


def _confirmed(sess):
    return [f for f in sess.findings.all() if f.confirmed and f.category == "logic"]


def test_engine_confirms_a_shared_private_response_and_caps_it_medium():
    cage = _IdentityCage(served_to_anon=False)   # private: anonymous is refused
    sess = _session(cage)
    confirmed = sess._run_one_round([_hyp()], [], [])
    assert confirmed == 1, "the engine did not confirm the isolation failure"
    found = _confirmed(sess)
    assert len(found) == 1
    f = found[0]
    assert f.evidence_class == "shared_private_response"
    assert f.severity == "medium", (
        f"the model proposed HIGH; the evidence class caps it MEDIUM, got {f.severity!r}")
    # The engine really issued the anonymous probe: the same url was fetched three times —
    # control (self), variant (second), and the anon probe.
    assert cage.seen.count(URL) == 3, cage.seen


def test_a_public_endpoint_is_not_confirmed_through_the_real_probe():
    cage = _IdentityCage(served_to_anon=True)    # public: anonymous is served too
    sess = _session(cage)
    confirmed = sess._run_one_round([_hyp()], [], [])
    assert confirmed == 0, "a public endpoint was mis-reported as an isolation leak"
    assert _confirmed(sess) == []
    # The probe still ran (that is HOW we learned it is public), so the url was seen thrice.
    assert cage.seen.count(URL) == 3, cage.seen


def test_the_anonymous_probe_is_scoped_to_this_comparator_only():
    # A different comparator must NOT pay for the extra anonymous request.
    cage = _IdentityCage(served_to_anon=False)
    sess = _session(cage)
    sess._run_one_round([_hyp(comparator="bodies_differ")], [], [])
    assert cage.seen.count(URL) == 2, (
        f"the anon probe fired for a non-isolation comparator: {cage.seen}")
