"""
test_predicate_grammar.py — the closed grammar the model composes, the code judges.

Two things must both hold, or the idea is worthless:
  - EXPRESSIVENESS: real comparators can be rebuilt as trees and evaluate correctly, so
    the model can reach flaw shapes nobody hand-wrote.
  - CONTAINMENT: anything outside the closed grammar is REFUSED WHOLE, no model text is
    executed, and every runtime slip fails closed to False.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import predicate_grammar as pg
from brukal.predicate_grammar import UnsafePredicate, evaluate, compile_predicate


class _R:
    def __init__(self, status=None, body="", headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}


# --------------------------------------------------------------------------- #
# EXPRESSIVENESS — existing comparators, rebuilt from blocks
# --------------------------------------------------------------------------- #

def _obs(name, of=None, arg=None):
    node = {"obs": name}
    if of is not None:
        node["of"] = of
    if arg is not None:
        node["arg"] = arg
    return node


def test_status_differs_rebuilt():
    ast = {"op": "and", "args": [
        {"op": "ne", "args": [_obs("status", "a"), _obs("status", "b")]},
        {"op": "gt", "args": [_obs("status", "a"), {"lit": 0}]},
        {"op": "gt", "args": [_obs("status", "b"), {"lit": 0}]}]}
    assert evaluate(ast, _R(200), _R(404)) is True
    assert evaluate(ast, _R(200), _R(200)) is False
    # a missing side is not a difference — the '> 0' guards fail closed.
    assert evaluate(ast, _R(None), _R(404)) is False


def test_b_reveals_more_rebuilt():
    ast = {"op": "and", "args": [
        _obs("succeeded", "a"), _obs("succeeded", "b"),
        {"op": "ratio_gt", "args": [_obs("body_len", "b"), _obs("body_len", "a"),
                                    {"lit": 2}]},
        {"op": "gt", "args": [_obs("body_len", "b"), {"lit": 200}]}]}
    assert evaluate(ast, _R(200, "x" * 100), _R(200, "y" * 500)) is True
    assert evaluate(ast, _R(200, "x" * 100), _R(200, "y" * 150)) is False   # ratio fails
    assert evaluate(ast, _R(200, "x" * 10), _R(200, "y" * 40)) is False     # < 200 floor
    assert evaluate(ast, _R(403, ""), _R(200, "y" * 500)) is False          # not allowed


def test_cors_credentialed_reflection_rebuilt():
    ast = {"op": "and", "args": [
        {"op": "eq", "args": [_obs("header", "a", "access-control-allow-origin"),
                              {"lit": "https://evil.example"}]},
        {"op": "eq", "args": [_obs("header", "a", "access-control-allow-credentials"),
                              {"lit": "true"}]}]}
    leaky = _R(200, headers={"Access-Control-Allow-Origin": "https://evil.example",
                             "Access-Control-Allow-Credentials": "true"})
    safe = _R(200, headers={"Access-Control-Allow-Origin": "https://self.example",
                            "Access-Control-Allow-Credentials": "true"})
    assert evaluate(ast, leaky, _R(200)) is True
    assert evaluate(ast, safe, _R(200)) is False


def test_isolation_shape_reads_engine_flags():
    # The #1 comparator's core, expressed in the grammar over ctx facts.
    ast = {"op": "and", "args": [
        _obs("ctx_flag", arg="distinct_principals"),
        _obs("ctx_flag", arg="anon_refused"),
        _obs("succeeded", "a"), _obs("succeeded", "b"),
        _obs("bodies_equal")]}
    ctx = {"distinct_principals": True, "anon_refused": True}
    assert evaluate(ast, _R(200, "P"), _R(200, "P"), ctx) is True
    assert evaluate(ast, _R(200, "P"), _R(200, "Q"), ctx) is False           # not equal
    assert evaluate(ast, _R(200, "P"), _R(200, "P"),
                    {"distinct_principals": True, "anon_refused": False}) is False


def test_a_boolean_observable_may_stand_as_the_whole_predicate():
    assert evaluate(_obs("denied", "a"), _R(401), _R(200)) is True
    assert evaluate(_obs("denied", "a"), _R(200), _R(200)) is False


# --------------------------------------------------------------------------- #
# CONTAINMENT — everything outside the grammar is refused whole
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ast, why", [
    ({"obs": "exfiltrate", "of": "a"}, "unknown observable"),
    ({"op": "system", "args": [{"lit": 1}, {"lit": 2}]}, "unknown operator"),
    ({"op": "__import__", "args": [{"lit": "os"}]}, "unknown operator"),
    ("denied", "a bare string is not a node"),
    ({"lit": {"nested": 1}}, "a non-scalar literal"),
    ({"lit": [1, 2, 3]}, "a list literal"),
    ({"obs": "status"}, "observable missing its side"),
    ({"obs": "status", "of": "c"}, "a side that is not a or b"),
    ({"obs": "bodies_equal", "of": "a"}, "a side on a side-less observable"),
    ({"obs": "header", "of": "a"}, "header without its arg"),
    ({"obs": "status", "of": "a", "arg": "x"}, "an arg on an argless observable"),
    ({"obs": "status", "of": "a", "junk": 1}, "an unexpected key"),
    ({"op": "not", "args": [{"lit": True}, {"lit": False}]}, "wrong arity"),
    ({"op": "and", "args": [{"lit": True}]}, "n-ary operator with one arg"),
    ({"op": "and", "args": "notalist"}, "args that are not a list"),
    ({"op": "gt", "args": [_obs("status", "a")]}, "gt with one arg"),
    ({"obs": "ctx_flag", "arg": "profile"}, "a ctx flag not on the allowlist"),
    ({"obs": "status", "of": "a"}, "a non-boolean observable as the root"),
    ({"lit": True}, "a bare literal as the root"),
])
def test_out_of_grammar_is_refused(ast, why):
    with pytest.raises(UnsafePredicate):
        evaluate(ast, _R(200), _R(200), {})


def test_depth_and_size_caps_refuse_a_pathological_tree():
    node = {"lit": True}
    for _ in range(pg.MAX_DEPTH + 2):
        node = {"op": "not", "args": [node]}
    with pytest.raises(UnsafePredicate):
        compile_predicate(node)
    wide = {"op": "and", "args": [{"lit": True}] * (pg.MAX_NODES + 5)}
    with pytest.raises(UnsafePredicate):
        compile_predicate(wide)


# --------------------------------------------------------------------------- #
# FAIL-CLOSED — a runtime slip never becomes a confirmation
# --------------------------------------------------------------------------- #

def test_comparisons_against_a_missing_value_are_false_not_an_error():
    ast = {"op": "gt", "args": [_obs("status", "a"), {"lit": 200}]}
    assert evaluate(ast, _R(None), _R(200)) is False


def test_ctx_flag_absent_reads_false():
    ast = _obs("ctx_flag", arg="oob_hit")
    assert evaluate(ast, _R(200), _R(200), {}) is False


def test_a_valid_tree_compiles_to_a_bounded_node_count():
    ast = {"op": "and", "args": [_obs("succeeded", "a"), _obs("succeeded", "b")]}
    assert compile_predicate(ast) == 3          # and + two observables


def test_evaluate_always_returns_a_real_bool():
    ast = {"op": "or", "args": [_obs("denied", "a"), _obs("succeeded", "b")]}
    out = evaluate(ast, _R(401), _R(200))
    assert out is True and isinstance(out, bool)
