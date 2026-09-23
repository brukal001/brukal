"""
predicate_grammar.py — a closed grammar the model composes, the code still judges.

Brukal's coverage grows linearly with hand-written comparators: it confirms what a
maintainer enumerated in `hypothesis._COMPARATORS` and nothing else. This module lifts
that ceiling without handing the model the one thing it must never have — the power to
declare something true, or to have text it authored executed.

The split is the same one the comparators already make, taken one level deeper:

    the model composes WHAT to measure  — a small AST of names, creative, untrusted
    the code decides IF the whole holds — a fixed interpreter over a CLOSED grammar

An expression is a tree of three node kinds and nothing else:

    {"lit": <scalar>}                          a string / number / boolean constant
    {"obs": <name>, "of": "a"|"b", "arg": …}   ONE reading of the two responses / ctx
    {"op":  <name>, "args": [<node>, …]}        a combinator over child nodes

Every observable and operator is drawn from a registry below; a name not in it, a node
of the wrong shape, a literal that is not a scalar, or a tree past the depth/size caps is
`UnsafePredicate` — REFUSED WHOLE. This is the scope gate's allowlist discipline applied
to predicates: `eval` over target-influenced text would be the same class of mistake as
putting an LLM inside the gate, so there is no `eval`, no `getattr` by name, no dynamic
dispatch on anything the model wrote — only enumerated Python functions run, and the only
model-supplied values that reach them are scalar literals compared, never executed.

Runtime failures FAIL CLOSED: a leaf that raises, or a comparison against a missing value,
yields False, never a confirmation. What this module does NOT do is decide severity — a
composed predicate that holds is an observation, and the bound it may carry is derived
elsewhere (2c), the same way a single comparator's bound lives beside it in
`hypothesis._EVIDENCE_CLASS`.
"""
from __future__ import annotations


class UnsafePredicate(ValueError):
    """A proposed predicate stepped outside the closed grammar — an unknown name, a
    malformed node, a non-scalar literal, or a tree too deep or too large. FAIL CLOSED:
    the caller confirms nothing and, ideally, feeds the message back so the next proposal
    stays inside the grammar."""


# Bounds on the tree itself, so a hostile or confused proposal cannot exhaust the stack or
# the interpreter. Small on purpose: a real predicate is a handful of nodes.
MAX_DEPTH = 8
MAX_NODES = 40

_SIDES = ("a", "b")

# The ONLY ctx keys an expression may read, so `ctx_flag` cannot reach `profile` or any
# other object the engine parks in the context. Each is an engine-established boolean.
_CTX_FLAGS = ("anon_refused", "distinct_principals", "oob_hit", "unauth_foreign",
              "baseline_stable", "acted")

# Literals are scalars only. A dict or list literal would be a place to smuggle structure
# the interpreter never validated.
_ALLOWED_LIT = (str, int, float, bool)


# --------------------------------------------------------------------------- #
# OBSERVABLES — pure readings that return a VALUE, never a verdict.
# Signature: (a, b, ctx, side, arg) -> value. `side` is "a"/"b" (or None), `arg` a scalar.
# --------------------------------------------------------------------------- #

def _result(a, b, side):
    return a if side == "a" else b


def _obs_status(a, b, ctx, side, arg):
    s = getattr(_result(a, b, side), "status", None)
    return s if isinstance(s, int) else None


def _obs_body_len(a, b, ctx, side, arg):
    return len(getattr(_result(a, b, side), "body", "") or "")


def _obs_substantive(a, b, ctx, side, arg):
    from .hypothesis import _substantive
    return bool(_substantive(_result(a, b, side), (ctx or {}).get("profile")))


def _obs_denied(a, b, ctx, side, arg):
    from .hypothesis import _denied
    return bool(_denied(_result(a, b, side), (ctx or {}).get("profile")))


def _obs_succeeded(a, b, ctx, side, arg):
    from .hypothesis import _succeeded
    return bool(_succeeded(_result(a, b, side)))


def _obs_header(a, b, ctx, side, arg):
    headers = getattr(_result(a, b, side), "headers", None) or {}
    want = str(arg).lower()
    for k, v in headers.items():
        if str(k).lower() == want:
            return str(v)
    return ""


def _obs_bodies_equal(a, b, ctx, side, arg):
    from .hypothesis import _norm
    return _norm(getattr(a, "body", "")) == _norm(getattr(b, "body", ""))


def _obs_ctx_flag(a, b, ctx, side, arg):
    if arg not in _CTX_FLAGS:
        raise UnsafePredicate(f"ctx flag {arg!r} is not on the allowlist")
    return bool((ctx or {}).get(arg))


# name -> (fn, needs_side, needs_arg, is_boolean). `is_boolean` marks the ones that may
# stand as a whole predicate (a root must be a verdict, not a bare number or string).
_OBSERVABLES = {
    "status":       (_obs_status, True, False, False),
    "body_len":     (_obs_body_len, True, False, False),
    "header":       (_obs_header, True, True, False),
    "substantive":  (_obs_substantive, True, False, True),
    "denied":       (_obs_denied, True, False, True),
    "succeeded":    (_obs_succeeded, True, False, True),
    "bodies_equal": (_obs_bodies_equal, False, False, True),
    "ctx_flag":     (_obs_ctx_flag, False, True, True),
}


# --------------------------------------------------------------------------- #
# OPERATORS — combinators over already-evaluated child values. Each returns a bool.
# --------------------------------------------------------------------------- #

def _num(x):
    # bool is an int subclass; exclude it so `gt(true, false)` is not a number comparison.
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def _cmp(vals, f):
    x, y = _num(vals[0]), _num(vals[1])
    if x is None or y is None:
        return False                      # FAIL CLOSED: a missing/non-numeric side
    return bool(f(x, y))


def _op_ratio_gt(vals):
    x, y, k = _num(vals[0]), _num(vals[1]), _num(vals[2])
    if x is None or y is None or k is None:
        return False
    return x > y * k


def _op_contains(vals):
    hay, needle = vals[0], vals[1]
    if not isinstance(hay, str) or not isinstance(needle, str) or needle == "":
        return False
    return needle in hay


# name -> (fn over the list of evaluated args, fixed arity or None for n-ary >= 2)
_OPERATORS = {
    "and":      (lambda v: all(bool(x) for x in v), None),
    "or":       (lambda v: any(bool(x) for x in v), None),
    "not":      (lambda v: not bool(v[0]), 1),
    "eq":       (lambda v: v[0] == v[1], 2),
    "ne":       (lambda v: v[0] != v[1], 2),
    "gt":       (lambda v: _cmp(v, lambda x, y: x > y), 2),
    "ge":       (lambda v: _cmp(v, lambda x, y: x >= y), 2),
    "lt":       (lambda v: _cmp(v, lambda x, y: x < y), 2),
    "le":       (lambda v: _cmp(v, lambda x, y: x <= y), 2),
    "ratio_gt": (_op_ratio_gt, 3),
    "contains": (_op_contains, 2),
}


# --------------------------------------------------------------------------- #
# VALIDATION — walk the tree once, refusing anything outside the grammar.
# --------------------------------------------------------------------------- #

def _validate(node, depth):
    """Return the node count of a valid subtree, or raise UnsafePredicate."""
    if depth > MAX_DEPTH:
        raise UnsafePredicate("predicate nested too deep")
    if not isinstance(node, dict):
        raise UnsafePredicate("every node must be a JSON object")

    if "lit" in node:
        if set(node) != {"lit"}:
            raise UnsafePredicate("a literal node takes only 'lit'")
        if not isinstance(node["lit"], _ALLOWED_LIT):
            raise UnsafePredicate("a literal must be a string, number or boolean")
        return 1

    if "obs" in node:
        name = node["obs"]
        if name not in _OBSERVABLES:
            raise UnsafePredicate(f"unknown observable {name!r}")
        _fn, needs_side, needs_arg, _is_bool = _OBSERVABLES[name]
        extra = set(node) - {"obs", "of", "arg"}
        if extra:
            raise UnsafePredicate(f"observable {name!r} has unexpected keys "
                                  f"{sorted(extra)}")
        if needs_side and node.get("of") not in _SIDES:
            raise UnsafePredicate(f"observable {name!r} needs 'of' in {_SIDES}")
        if not needs_side and "of" in node:
            raise UnsafePredicate(f"observable {name!r} takes no 'of'")
        if needs_arg and not isinstance(node.get("arg"), str):
            raise UnsafePredicate(f"observable {name!r} needs a string 'arg'")
        if not needs_arg and "arg" in node:
            raise UnsafePredicate(f"observable {name!r} takes no 'arg'")
        return 1

    if "op" in node:
        name = node["op"]
        if name not in _OPERATORS:
            raise UnsafePredicate(f"unknown operator {name!r}")
        if set(node) != {"op", "args"}:
            raise UnsafePredicate("an operator node takes exactly 'op' and 'args'")
        args = node["args"]
        if not isinstance(args, list) or not args:
            raise UnsafePredicate(f"operator {name!r} needs a non-empty 'args' list")
        _fn, arity = _OPERATORS[name]
        if arity is not None and len(args) != arity:
            raise UnsafePredicate(
                f"operator {name!r} takes {arity} args, got {len(args)}")
        if arity is None and len(args) < 2:
            raise UnsafePredicate(f"operator {name!r} needs at least 2 args")
        count = 1
        for child in args:
            count += _validate(child, depth + 1)
        return count

    raise UnsafePredicate("a node must be one of 'lit', 'obs' or 'op'")


def _is_boolean_root(node) -> bool:
    """A whole predicate must evaluate to a verdict. Operators all return bool; among
    observables only the boolean ones may stand alone (a bare `status` is not a verdict)."""
    if "op" in node:
        return True
    if "obs" in node:
        return bool(_OBSERVABLES[node["obs"]][3])
    return False


def compile_predicate(ast):
    """Validate `ast` against the closed grammar. Returns the node count on success;
    raises UnsafePredicate otherwise. Pure — it runs nothing from the tree, it only
    inspects its shape."""
    total = _validate(ast, 0)
    if total > MAX_NODES:
        raise UnsafePredicate(f"predicate has {total} nodes, over the {MAX_NODES} cap")
    if not _is_boolean_root(ast):
        raise UnsafePredicate("the whole predicate must evaluate to a boolean verdict")
    return total


def _eval(node, a, b, ctx):
    if "lit" in node:
        return node["lit"]
    if "obs" in node:
        fn, _needs_side, _needs_arg, _is_bool = _OBSERVABLES[node["obs"]]
        return fn(a, b, ctx, node.get("of"), node.get("arg"))
    fn, _arity = _OPERATORS[node["op"]]
    return fn([_eval(child, a, b, ctx) for child in node["args"]])


def evaluate(ast, a, b, ctx=None) -> bool:
    """Compile then evaluate `ast` over the two responses and the engine context.

    Returns a plain bool. A structural violation raises UnsafePredicate (the caller treats
    that as no-confirmation); any runtime error inside a leaf is contained and the verdict
    is False. NO model text is executed — only the enumerated observables and operators
    run, and the only model-supplied values reaching them are scalar literals."""
    compile_predicate(ast)                      # raises on anything outside the grammar
    try:
        return bool(_eval(ast, a, b, ctx or {}))
    except UnsafePredicate:
        raise
    except Exception:
        return False                            # FAIL CLOSED on any leaf error
