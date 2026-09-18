"""
test_oob_comparator.py — a third evidence class: the proof arrives OUT OF BAND.

WHY
    crAPI challenge 11 is "make crAPI send an HTTP call to an external host". The proof is
    not a response differential and not a state change: it is that the TARGET CONTACTED US.
    Brukal has had an OOB listener in the cage for months — `brukal/oob.py`, used by the
    hand-written deserialisation detector — and a model-proposed experiment could not
    reach it. There was no way for a proposal to reference the callback URL and no
    comparator that judged an interaction.

    So SSRF was a MODEL-LIMIT miss in every CR1 run: not because the model could not think
    of it, but because thinking of it led nowhere.

THE SHAPE
    A hypothesis writes `{{oob}}` wherever the payload URL belongs — the same idiom as
    `{{setup.0.field}}` — and deterministic code substitutes a callback URL carrying a
    token unique to that experiment. After dispatch the engine asks the listener whether
    that token was seen, and `oob_callback` judges on the answer.

FAIL-CLOSED
    No listener means no evidence, so the experiment ERRORS as a harness limit. It must
    never silently pass, and it must never be attributed to the target.
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
from brukal.hypothesis import Hypothesis, comparator_names, parse
from brukal.kali import ExecResult
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}"
CONTACT = f"{BASE}/workshop/api/merchant/contact_mechanic"


class _FakeListener:
    """The cage's OOB listener: it records what the target fetched."""

    def __init__(self, calls_back=True):
        self.calls_back = calls_back
        self.tokens: list = []
        self.fetched: set = set()

    def callback_url(self, token):
        self.tokens.append(token)
        return f"http://172.20.0.14:43526/{token}"

    def hit(self, token):
        return token in self.fetched


class _SSRFTarget:
    """Fetches any URL handed to it — crAPI's contact_mechanic, in miniature."""

    def __init__(self, listener, vulnerable=True):
        self.listener = listener
        self.vulnerable = vulnerable
        self.seen: list = []

    def run(self, action):
        self.seen.append(action.url + " " + (action.body or ""))
        blob = action.url + (action.body or "")
        if self.vulnerable and "43526/" in blob:
            token = blob.split("43526/")[1].split('"')[0].split("&")[0].strip()
            self.listener.fetched.add(token)
        return WebResult(status=200, url=action.url, body='{"status":"queued"}')


def _h():
    return Hypothesis(
        title="Mechanic contact endpoint fetches a caller-supplied URL",
        severity="high", comparator="oob_callback",
        control={"method": "POST", "url": CONTACT, "as": "self",
                 "body": json.dumps({"mechanic_api": "http://127.0.0.1/health"})},
        variant={"method": "POST", "url": CONTACT, "as": "self",
                 "body": json.dumps({"mechanic_api": "{{oob}}"})},
        rationale="challenge 11", setup=[])


def _session(tmp_path, cage, listener):
    scope = load_scope(SCOPE)
    audit = AuditLog(tmp_path / "a.jsonl")
    ex = Executor(Gate(scope), type("K", (), {"run": lambda s, c: ExecResult(c, 0, "", "")})(),
                  audit, approver=lambda d: True)
    llm = type("L", (), {"last_stop_reason": "end_turn", "propose": lambda s, *a, **k: "[]"})()
    s = AssistSession(TARGET, ex, StrategistAgent(llm),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s.identity = "us@brukal.test"
    s.surface = AttackSurface(seed=f"{BASE}/")
    s._oob_listener = listener              # the cage's listener, or None
    return s, audit


def _outcome(audit):
    rows = [json.loads(l)["data"] for l in open(audit.path)
            if json.loads(l)["kind"] == "experiment_outcome"]
    return rows[-1] if rows else None


# --------------------------------------------------------------------------- #

def test_the_comparator_is_offered_to_the_model():
    assert "oob_callback" in comparator_names()


def test_the_oob_reference_survives_parsing():
    got = parse(json.dumps([{
        "title": "t", "severity": "high", "comparator": "oob_callback",
        "control": {"method": "POST", "url": CONTACT, "body": "{}"},
        "variant": {"method": "POST", "url": CONTACT,
                    "body": json.dumps({"u": "{{oob}}"})}}]))
    assert got and "{{oob}}" in got[0].variant["body"]


def test_a_target_that_CALLS_BACK_is_a_finding(tmp_path):
    """THE POINT: challenge 11's proof is the interaction, not the reply — both responses
    here are an identical 200."""
    lis = _FakeListener()
    s, audit = _session(tmp_path, _SSRFTarget(lis), lis)
    s._run_one_round([_h()], [], [])
    out = _outcome(audit)
    assert out and out["outcome"] == "confirmed", out


def test_a_target_that_does_NOT_call_back_is_not_a_finding(tmp_path):
    """BOUNDARY: identical 200s and no interaction. The application accepted the field and
    did nothing with it, which is the application behaving."""
    lis = _FakeListener()
    s, audit = _session(tmp_path, _SSRFTarget(lis, vulnerable=False), lis)
    s._run_one_round([_h()], [], [])
    assert _outcome(audit)["outcome"] == "not_confirmed"


def test_the_token_is_unique_per_experiment(tmp_path):
    """Two experiments must not be able to claim each other's interaction."""
    lis = _FakeListener()
    s, _audit = _session(tmp_path, _SSRFTarget(lis), lis)
    s._run_one_round([_h()], [], [])
    s._run_one_round([_h()], [], [])
    assert len(set(lis.tokens)) == len(lis.tokens) >= 2, lis.tokens


def test_the_payload_url_actually_reaches_the_target(tmp_path):
    """`{{oob}}` is substituted by deterministic code before the request is sent — the
    literal braces going out is the `{{setup.*}}` defect all over again."""
    lis = _FakeListener()
    cage = _SSRFTarget(lis)
    s, _audit = _session(tmp_path, cage, lis)
    s._run_one_round([_h()], [], [])
    sent = " ".join(cage.seen)
    assert "{{oob}}" not in sent, sent
    assert "43526/" in sent, sent


def test_NO_listener_is_a_harness_limit_not_a_pass(tmp_path):
    """FAIL-CLOSED: without a listener there is no evidence. It must not silently pass,
    and it must never be recorded as the target refusing."""
    s, audit = _session(tmp_path, _SSRFTarget(_FakeListener()), None)
    s._run_one_round([_h()], [], [])
    out = _outcome(audit)
    assert out["outcome"] != "confirmed", out
    assert out["attribution"] == "HARNESS-LIMIT", out
