"""
scope_judge.py — the model-side "judge" used ONLY at authoring time by
scope_parse.py to help DRAFT a scope.json from free text. It is never imported by
gate.py / executor.py / kali.py / audit.py / web.py and never sees a live target;
it only ever reads the operator-supplied program description text (see
docs/superpowers/specs/2026-09-28-scope-parser-design.md, invariant in §2: "The
model/TypeSafe runs once, at authoring time, model-side — it only drafts.").

Two real implementations:
  - TypeSafeJudge   — POSTs the TypeSafe System One ("Jev") contract (spec §4).
                       Raises JudgeUnavailable on a missing key, a network failure,
                       or a response that doesn't parse — NEVER crashes the caller.
  - DeterministicJudge — a no-network keyword fallback, used when no
                       TYPESAFE_API_KEY is set, or whenever TypeSafeJudge raises.
                       Deliberately conservative: an item it can't decide with a
                       clear keyword signal comes back at confidence 0.0 (an
                       "abstain"), which scope_parse.validate() then routes to
                       review rather than guessing wrong with false confidence.

`StubJudge` is a third, TEST-ONLY implementation: fully scripted, no heuristics,
no network — it is what drives the offline test suite (spec §8: "no live
TypeSafe call in tests").

Every judge answer is normalized to the same shape so scope_parse.py never has to
know which engine produced it:
    {"kind": "noul" | "choice" | "score", "value": ..., "confidence": <0..1>,
     "engine": "typesafe" | "deterministic" | "stub" | "rule"}
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone"
TYPESAFE_MODEL = "jev-latest"


class JudgeUnavailable(Exception):
    """Raised by TypeSafeJudge (missing key / network error / unparseable response).
    Callers (make_judge / scope_parse) catch this and fall back to
    DeterministicJudge — a judge failure must never crash a draft, and it must never
    be silently treated as a confident answer."""


class Judge:
    """ask(state, questions) -> {id: {"kind","value","confidence","engine"}}."""

    def ask(self, state: dict, questions: dict) -> dict:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# TypeSafe System One ("Jev") adapter
# --------------------------------------------------------------------------- #

class TypeSafeJudge(Judge):
    """POST https://api.typesafe.ai/v1/systemone with
    {state, model:"jev-latest", questions:{id:{type,instructions,criteria}}}.

    noul   -> answer {noul: <prob 0..1>}          normalized to value=bool(prob>=0.5),
                                                    confidence=abs(prob-0.5)*2, prob kept too.
    choice -> answer {choice, probabilities, confidence}   normalized value=choice.
    score  -> answer {score, legend, probabilities, confidence}  normalized value=score.

    Never called from the runtime gate — this class only ever runs at drafting time,
    invoked by `brukal scope draft`.
    """

    def __init__(self, api_key: str | None = None, url: str = TYPESAFE_URL,
                 timeout: float = 20.0):
        key = api_key if api_key is not None else os.environ.get("TYPESAFE_API_KEY", "")
        key = (key or "").strip()
        if not key:
            raise JudgeUnavailable("TYPESAFE_API_KEY is not set")
        self.api_key = key
        self.url = url
        self.timeout = timeout

    def _post(self, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                raw = resp.read()
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise JudgeUnavailable(f"TypeSafe request failed: {e}") from e
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise JudgeUnavailable(f"TypeSafe response unparseable: {e}") from e
        if not isinstance(payload, dict):
            raise JudgeUnavailable("TypeSafe response was not a JSON object")
        return payload

    def ask(self, state: dict, questions: dict) -> dict:
        if not questions:
            return {}
        body = {"state": state, "model": TYPESAFE_MODEL, "questions": questions}
        payload = self._post(body)
        answers = payload.get("answers")
        if not isinstance(answers, dict):
            raise JudgeUnavailable("TypeSafe response missing 'answers'")
        out = {}
        for qid, q in questions.items():
            a = answers.get(qid)
            if not isinstance(a, dict):
                raise JudgeUnavailable(f"TypeSafe response missing answer for '{qid}'")
            kind = q.get("type")
            try:
                if kind == "noul":
                    prob = float(a["noul"])
                    out[qid] = {"kind": "noul", "value": prob >= 0.5,
                                "confidence": abs(prob - 0.5) * 2.0,
                                "prob": prob, "engine": "typesafe"}
                elif kind == "choice":
                    out[qid] = {"kind": "choice", "value": a["choice"],
                                "confidence": float(a.get("confidence", 0.0)),
                                "probabilities": a.get("probabilities"), "engine": "typesafe"}
                elif kind == "score":
                    out[qid] = {"kind": "score", "value": a["score"],
                                "confidence": float(a.get("confidence", 0.0)),
                                "legend": a.get("legend"), "engine": "typesafe"}
                else:
                    raise JudgeUnavailable(f"unknown question type '{kind}' for '{qid}'")
            except (KeyError, TypeError, ValueError) as e:
                raise JudgeUnavailable(f"TypeSafe answer for '{qid}' unparseable: {e}") from e
        return out


# --------------------------------------------------------------------------- #
# Deterministic no-network fallback
# --------------------------------------------------------------------------- #

def _keywords(s: str) -> list:
    return [w for w in re.findall(r"[a-z0-9]+", str(s or "").lower()) if len(w) > 2]


class DeterministicJudge(Judge):
    """No-network fallback used when TYPESAFE_API_KEY is absent, or whenever
    TypeSafeJudge raises JudgeUnavailable. Reads only each question's own
    `instructions` text (scope_parse.py embeds the source span + any table hint
    there) and its `criteria` — never reaches out anywhere. Deliberately
    conservative: no keyword signal -> confidence 0.0 (an abstain), never a
    confident guess."""

    def ask(self, state: dict, questions: dict) -> dict:
        out = {}
        for qid, q in questions.items():
            qtype = q.get("type")
            text = str(q.get("instructions", "")).lower()
            if qtype == "noul":
                out[qid] = self._ask_noul(text, q)
            elif qtype == "choice":
                out[qid] = self._ask_choice(text, q)
            elif qtype == "score":
                out[qid] = self._ask_score(text, q)
            else:
                out[qid] = {"kind": qtype, "value": None, "confidence": 0.0,
                            "engine": "deterministic"}
        return out

    @staticmethod
    def _ask_noul(text: str, q: dict) -> dict:
        crit = q.get("criteria") or {}
        true_kw = _keywords(crit.get("true", ""))
        false_kw = _keywords(crit.get("false", ""))
        t_hits = sum(1 for w in true_kw if w in text)
        f_hits = sum(1 for w in false_kw if w in text)
        if t_hits and t_hits > f_hits:
            return {"kind": "noul", "value": True,
                    "confidence": min(0.5 + 0.15 * t_hits, 0.9), "engine": "deterministic"}
        if f_hits and f_hits > t_hits:
            return {"kind": "noul", "value": False,
                    "confidence": min(0.5 + 0.15 * f_hits, 0.9), "engine": "deterministic"}
        return {"kind": "noul", "value": False, "confidence": 0.0, "engine": "deterministic"}

    @staticmethod
    def _ask_choice(text: str, q: dict) -> dict:
        crit = q.get("criteria") or {}
        best, best_hits = None, 0
        for opt, desc in crit.items():
            hits = sum(1 for w in _keywords(f"{opt} {desc}") if w in text)
            if hits > best_hits:
                best, best_hits = opt, hits
        if best is not None and best_hits:
            return {"kind": "choice", "value": best,
                    "confidence": min(0.4 + 0.15 * best_hits, 0.85), "engine": "deterministic"}
        return {"kind": "choice", "value": None, "confidence": 0.0, "engine": "deterministic"}

    @staticmethod
    def _ask_score(text: str, q: dict) -> dict:
        levels = q.get("criteria") or []
        best, best_hits = None, 0
        for lvl in levels:
            hits = sum(1 for w in _keywords(str(lvl)) if w in text)
            if hits > best_hits:
                best, best_hits = lvl, hits
        if best is not None and best_hits:
            return {"kind": "score", "value": best,
                    "confidence": min(0.4 + 0.15 * best_hits, 0.85), "engine": "deterministic"}
        return {"kind": "score", "value": None, "confidence": 0.0, "engine": "deterministic"}


# --------------------------------------------------------------------------- #
# Test-only scripted judge
# --------------------------------------------------------------------------- #

class StubJudge(Judge):
    """Fully scripted, offline, deterministic — drives the test suite (spec §8: "no
    live TypeSafe call in tests"). `scripted` maps question id -> either a full
    normalized answer dict, or a bare value (wrapped with confidence=1.0). A question
    id missing from the script gets a confidence-0.0 abstain — never a silently
    invented high-confidence answer."""

    def __init__(self, scripted: dict | None = None):
        self.scripted = scripted or {}

    def ask(self, state: dict, questions: dict) -> dict:
        out = {}
        for qid, q in questions.items():
            if qid in self.scripted:
                raw = self.scripted[qid]
                if isinstance(raw, dict):
                    ans = dict(raw)
                    ans.setdefault("kind", q.get("type"))
                    ans.setdefault("confidence", 1.0)
                    ans.setdefault("engine", "stub")
                else:
                    ans = {"kind": q.get("type"), "value": raw, "confidence": 1.0,
                          "engine": "stub"}
            else:
                ans = {"kind": q.get("type"), "value": None, "confidence": 0.0,
                      "engine": "stub"}
            out[qid] = ans
        return out


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #

def make_judge() -> Judge:
    """TypeSafe if TYPESAFE_API_KEY is set, else the deterministic fallback. Never
    raises: a key that turns out to be bad only surfaces as JudgeUnavailable from
    `.ask()`, which scope_parse.py catches and falls back to DeterministicJudge for
    that draft (spec §7: "on any judge error -> deterministic fallback, never a
    crash")."""
    key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if not key:
        return DeterministicJudge()
    try:
        return TypeSafeJudge(api_key=key)
    except JudgeUnavailable:
        return DeterministicJudge()
