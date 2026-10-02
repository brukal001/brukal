# tests/security/test_i1_no_llm_in_gate.py
"""I1 - no LLM/model code in the authorization-decision path.

Static import graph over the brukal package (ast, no import-execution). Lazy
(function-level) imports are included: ast.walk sees every import statement.
"""
import ast
import pathlib

PKG = pathlib.Path(__file__).resolve().parents[2] / "brukal"

# Authorization-decision modules; executor.py's decision path is its gate call.
DECISION_MODULES = ["brukal.gate", "brukal.scope", "brukal.hostmatch", "brukal.executor"]
# Name patterns of LLM/model code (matched on dotted-path components, case-insensitive).
LLM_EXTERNAL = {"anthropic", "openai", "openrouter", "litellm", "langchain", "google.generativeai",
                "cohere", "mistralai", "transformers", "ollama", "httpx"}
LLM_INTERNAL = {"brukal.llm", "brukal.scope_judge", "brukal.agents"}
LLM_SUBSTR = ("llm", "anthropic", "openai", "openrouter")


def _mod_path(mod: str) -> pathlib.Path | None:
    rel = mod.split(".")[1:]
    f = PKG.joinpath(*rel).with_suffix(".py") if rel else PKG / "__init__.py"
    if f.exists():
        return f
    d = PKG.joinpath(*rel) / "__init__.py"
    return d if d.exists() else None


def _imports(src: str, modname: str) -> set[str]:
    """Absolute dotted names imported by `src` (every import statement, incl. lazy)."""
    pkg_parts = modname.split(".")
    is_pkg = modname.endswith(".__init__")
    base = pkg_parts[:-1] if not is_pkg else pkg_parts[:-1]
    out: set[str] = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import):
            out |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                anchor = base[: len(base) - (n.level - 1)] if n.level > 1 else base
                head = ".".join(anchor + ([n.module] if n.module else []))
            else:
                head = n.module or ""
            out.add(head)
            for a in n.names:
                out.add(f"{head}.{a.name}")   # may be a submodule; non-modules filtered later
    return out


def _is_llm(name: str) -> bool:
    low = name.lower()
    if name in LLM_INTERNAL or any(name.startswith(i + ".") for i in LLM_INTERNAL):
        return True
    if any(low == e or low.startswith(e + ".") for e in LLM_EXTERNAL):
        return True
    return any(s in c for c in low.split(".") for s in LLM_SUBSTR)


def transitive_llm_imports(root: str) -> dict[str, list[str]]:
    """Walk the brukal-internal import graph from `root`; return {llm_name: path-of-modules}."""
    seen: set[str] = set()
    found: dict[str, list[str]] = {}
    stack = [(root, [root])]
    while stack:
        mod, trail = stack.pop()
        if mod in seen:
            continue
        seen.add(mod)
        f = _mod_path(mod)
        if f is None:
            continue
        modname = mod + (".__init__" if f.name == "__init__.py" else "")
        for imp in _imports(f.read_text(encoding="utf-8"), modname):
            if _is_llm(imp):
                found.setdefault(imp, trail)
                continue
            # Explicit-import graph. The bare package (`brukal/__init__.py`) is deliberately NOT
            # followed: it eagerly re-exports the whole package (loop, assist, llm...), so Python
            # co-loads it with any submodule, but the gate's code does not depend on it. See report.
            if imp.startswith("brukal.") and _mod_path(imp) is not None:
                stack.append((imp, trail + [imp]))
    return found


def test_self_test_helper_detects_llm_import():
    # strategist agent legitimately imports brukal.llm; the helper must report it.
    assert "brukal.llm" in transitive_llm_imports("brukal.agents.strategist")
    # llm.py itself lazily imports the anthropic SDK.
    assert "anthropic" in transitive_llm_imports("brukal.llm")
    assert _is_llm("brukal.llm") and _is_llm("openai") and not _is_llm("brukal.hostmatch")


def test_decision_modules_exist():
    for m in DECISION_MODULES:
        assert _mod_path(m) is not None, m


def _check(mod: str, record):
    found = transitive_llm_imports(mod)
    record(f"i1::{mod}", "no-llm-in-gate", "I1", f"{len(found)} LLM imports", "0", str(len(found)),
           "critical")
    assert not found, f"{mod} transitively reaches LLM code: {found}"


def test_gate_has_no_llm(record):
    _check("brukal.gate", record)


def test_scope_has_no_llm(record):
    _check("brukal.scope", record)


def test_hostmatch_has_no_llm(record):
    _check("brukal.hostmatch", record)


def test_executor_decision_path_has_no_llm(record):
    _check("brukal.executor", record)
