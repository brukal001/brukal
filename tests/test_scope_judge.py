"""
test_scope_judge.py — SP-B judge adapters (brukal/scope_judge.py).

TypeSafeJudge is unit-tested against a MOCKED HTTP response only (spec §8: "no live
TypeSafe call in tests"); nothing here makes a real network call. DeterministicJudge
and StubJudge are pure, offline, no-network by construction.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal.scope_judge import (DeterministicJudge, JudgeUnavailable, StubJudge,
                                TypeSafeJudge, make_judge)


# --------------------------------------------------------------------------- #
# TypeSafeJudge — construction
# --------------------------------------------------------------------------- #

def test_typesafe_judge_raises_when_key_missing(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(JudgeUnavailable):
        TypeSafeJudge(api_key=None)


def test_typesafe_judge_reads_key_from_env(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test-123")
    j = TypeSafeJudge()
    assert j.api_key == "sk-test-123"


# --------------------------------------------------------------------------- #
# TypeSafeJudge.ask — mocked HTTP only, no live call
# --------------------------------------------------------------------------- #

class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _mock_urlopen(monkeypatch, payload: dict, capture: dict | None = None):
    def _fake(req, timeout=None):
        if capture is not None:
            capture["url"] = req.full_url
            capture["headers"] = dict(req.header_items())
            capture["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse(json.dumps(payload).encode("utf-8"))
    monkeypatch.setattr("brukal.scope_judge.urllib.request.urlopen", _fake)


def test_typesafe_ask_normalizes_noul_choice_score(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")
    payload = {
        "model": "jev-latest",
        "answers": {
            "q_noul": {"noul": 0.92},
            "q_choice": {"choice": "wildcard", "probabilities": {"wildcard": 0.8}, "confidence": 0.8},
            "q_score": {"score": "high", "legend": ["low", "medium", "high"], "probabilities": {}, "confidence": 0.7},
        },
        "usage": {},
    }
    capture = {}
    _mock_urlopen(monkeypatch, payload, capture)
    j = TypeSafeJudge()
    questions = {
        "q_noul": {"type": "noul", "instructions": "is it?", "criteria": {"true": "a", "false": "b"}},
        "q_choice": {"type": "choice", "instructions": "which?", "criteria": {"wildcard": "x"}},
        "q_score": {"type": "score", "instructions": "how bad?", "criteria": ["low", "medium", "high"]},
    }
    out = j.ask({"description": "..."}, questions)

    # request shape matches the TypeSafe contract (spec §4)
    assert capture["url"] == "https://api.typesafe.ai/v1/systemone"
    assert capture["headers"]["Authorization"] == "Bearer sk-test"
    assert capture["body"]["model"] == "jev-latest"
    assert capture["body"]["questions"] == questions

    assert out["q_noul"]["value"] is True
    assert out["q_noul"]["confidence"] == pytest.approx(0.84, abs=1e-6)
    assert out["q_choice"]["value"] == "wildcard"
    assert out["q_choice"]["confidence"] == 0.8
    assert out["q_score"]["value"] == "high"
    assert out["q_score"]["confidence"] == 0.7
    assert all(a["engine"] == "typesafe" for a in out.values())


def test_typesafe_ask_raises_on_network_error(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")

    def _boom(req, timeout=None):
        raise OSError("connection refused")
    monkeypatch.setattr("brukal.scope_judge.urllib.request.urlopen", _boom)
    j = TypeSafeJudge()
    with pytest.raises(JudgeUnavailable):
        j.ask({}, {"q": {"type": "noul", "instructions": "x", "criteria": {}}})


def test_typesafe_ask_raises_on_unparseable_response(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")

    def _fake(req, timeout=None):
        return _FakeResponse(b"not json at all")
    monkeypatch.setattr("brukal.scope_judge.urllib.request.urlopen", _fake)
    j = TypeSafeJudge()
    with pytest.raises(JudgeUnavailable):
        j.ask({}, {"q": {"type": "noul", "instructions": "x", "criteria": {}}})


def test_typesafe_ask_raises_on_missing_answer(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")
    _mock_urlopen(monkeypatch, {"answers": {}})
    j = TypeSafeJudge()
    with pytest.raises(JudgeUnavailable):
        j.ask({}, {"q": {"type": "noul", "instructions": "x", "criteria": {}}})


# --------------------------------------------------------------------------- #
# make_judge selection
# --------------------------------------------------------------------------- #

def test_make_judge_returns_deterministic_when_no_key(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert isinstance(make_judge(), DeterministicJudge)


def test_make_judge_returns_typesafe_when_key_present(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")
    assert isinstance(make_judge(), TypeSafeJudge)


# --------------------------------------------------------------------------- #
# DeterministicJudge — keyword heuristics, no network
# --------------------------------------------------------------------------- #

def test_deterministic_noul_picks_true_on_keyword_match():
    j = DeterministicJudge()
    q = {"type": "noul",
        "instructions": "Is the line 'info.coindcx.com' a genuine host exclusion?",
        "criteria": {"true": "line names a host that is out of scope",
                     "false": "line is unrelated text"}}
    ans = j.ask({}, {"q": q})["q"]
    assert ans["value"] is True
    assert ans["confidence"] > 0
    assert ans["engine"] == "deterministic"


def test_deterministic_noul_abstains_with_no_signal():
    j = DeterministicJudge()
    q = {"type": "noul", "instructions": "completely unrelated filler text",
        "criteria": {"true": "zzz1 zzz2", "false": "zzz3 zzz4"}}
    ans = j.ask({}, {"q": q})["q"]
    assert ans["confidence"] == 0.0


def test_deterministic_choice_matches_table_hint():
    j = DeterministicJudge()
    q = {"type": "choice",
        "instructions": "Asset '*.coindcx.com' table type hint: 'Wildcard'. What type is it?",
        "criteria": {"wildcard": "a wildcard domain", "domain": "a single hostname",
                     "api": "an api host", "android": "an android app", "ios": "an ios app"}}
    ans = j.ask({}, {"q": q})["q"]
    assert ans["value"] == "wildcard"
    assert ans["confidence"] > 0


# --------------------------------------------------------------------------- #
# StubJudge — scripted, offline
# --------------------------------------------------------------------------- #

def test_stub_judge_returns_scripted_answers_and_abstains_otherwise():
    j = StubJudge({"q1": {"value": True, "confidence": 0.95}})
    questions = {
        "q1": {"type": "noul", "instructions": "x", "criteria": {}},
        "q2": {"type": "choice", "instructions": "y", "criteria": {}},
    }
    out = j.ask({}, questions)
    assert out["q1"]["value"] is True
    assert out["q1"]["confidence"] == 0.95
    assert out["q1"]["engine"] == "stub"
    assert out["q2"]["value"] is None
    assert out["q2"]["confidence"] == 0.0    # missing from script -> abstain, never invented
