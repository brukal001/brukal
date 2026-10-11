import types
import json
import os

from brukal.cage import FakeCageRunner
from brukal.hunt_wizard import run_hunt


import pytest


@pytest.fixture(autouse=True)
def _no_key_leak(monkeypatch):
    """run_hunt writes the resolved key into os.environ (by design: the engine reads it
    there). Register every provider variable with monkeypatch first, so teardown
    restores the process environment and a fake key never leaks into later tests."""
    for prov in ("anthropic", "openrouter", "openai", "deepseek", "gemini"):
        monkeypatch.delenv(f"{prov.upper()}_API_KEY", raising=False)


def _args(**kw):
    base = dict(mode=None, url=None, ovpn=None, context=None, provider="openrouter",
                model="m", scope="scope.hunt.json", vault="docker/vault",
                audit="runs/h.jsonl", container="brukal-kali", fake=False, yes=False,
                tui=False, base_url=None, log="runs/engagement.log")
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_web_path_freezes_then_executes_then_dispatches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers = iter(["web", "https://abc.web-security-academy.net/", "find sqli", "y"])
    runner = FakeCageRunner()
    dispatched = {}
    rc = run_hunt(_args(scope=str(tmp_path / "s.json")),
                  prompt=lambda _p: next(answers),
                  runner=runner,
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) and 0,
                  resolve_key=lambda _prov, **k: ("sk-x", None))
    assert rc == 0
    frozen = json.loads((tmp_path / "s.json").read_text())
    assert frozen["authorized"] is True
    assert frozen["_context"] == "find sqli"   # the operator's brief is persisted
    names = [c[0] for c in runner.calls]
    assert names[:2] == ["compose_recreate", "set_resolver"]   # executed
    assert dispatched["plan"].mode == "web"                     # dispatched last


def test_decline_aborts_with_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers = iter(["web", "https://abc.web-security-academy.net/", "ctx", "n"])
    runner = FakeCageRunner()
    dispatched = {}
    rc = run_hunt(_args(scope=str(tmp_path / "s.json")),
                  prompt=lambda _p: next(answers), runner=runner,
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) and 0,
                  resolve_key=lambda _prov, **k: ("sk-x", None))
    assert rc != 0
    assert runner.calls == [] and "plan" not in dispatched
    assert not (tmp_path / "s.json").exists()   # scope never frozen


def test_verify_failure_blocks_dispatch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers = iter(["web", "https://abc.web-security-academy.net/", "ctx", "y"])
    runner = FakeCageRunner(fail={"http_probe_via_proxy"})
    dispatched = {}
    rc = run_hunt(_args(scope=str(tmp_path / "s.json")),
                  prompt=lambda _p: next(answers), runner=runner,
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) and 0,
                  resolve_key=lambda _prov, **k: ("sk-x", None))
    assert rc != 0 and "plan" not in dispatched


def test_no_provider_does_not_crash_and_coalesces_to_anthropic(tmp_path, monkeypatch):
    # args.provider defaults to None on the real `hunt` parser. keys._env_var does
    # provider.upper(), so a bare `brukal hunt` with no --provider must not raise
    # AttributeError — the wizard coalesces it (same default the old _cmd_hunt used).
    monkeypatch.chdir(tmp_path)
    answers = iter(["web", "https://abc.web-security-academy.net/", "ctx", "y"])
    runner = FakeCageRunner()
    dispatched = {}
    rc = run_hunt(_args(provider=None, scope=str(tmp_path / "s.json")),
                  prompt=lambda _p: next(answers), runner=runner,
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) and 0,
                  resolve_key=lambda _prov, **k: ("sk-x", None))
    assert rc == 0
    assert dispatched["plan"].dispatch.provider == "anthropic"


def test_resolved_key_is_propagated_to_environ_before_dispatch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    answers = iter(["web", "https://abc.web-security-academy.net/", "ctx", "y"])
    runner = FakeCageRunner()
    seen = {}

    def _dispatch(plan):
        seen["key_at_dispatch"] = os.environ.get("OPENROUTER_API_KEY")
        return 0

    rc = run_hunt(_args(provider="openrouter", scope=str(tmp_path / "s.json")),
                  prompt=lambda _p: next(answers), runner=runner,
                  dispatch=_dispatch,
                  resolve_key=lambda prov, **k: ("sk-propagated", None))
    assert rc == 0
    assert seen["key_at_dispatch"] == "sk-propagated"
    assert os.environ["OPENROUTER_API_KEY"] == "sk-propagated"
    # run_hunt writes os.environ directly (not through monkeypatch); re-set it via
    # monkeypatch now so pytest's teardown restores/removes it, and no later test
    # can see a leaked key.
    monkeypatch.setenv("OPENROUTER_API_KEY", os.environ["OPENROUTER_API_KEY"])


def test_default_dispatch_forwards_the_brief_to_the_engine(monkeypatch):
    """The brief used to stop at the approval gate and the frozen scope; the engine
    never saw it. It must reach run_auto(context=[...])."""
    import brukal.assist as ac
    from brukal import envprep
    from brukal.hunt_wizard import _default_dispatch
    seen = {}
    monkeypatch.setattr(ac, "run_auto", lambda target, **kw: seen.update(kw) or 0)
    plan = envprep.plan_web("https://abc.web-security-academy.net/", "find the sqli",
                            "openrouter", "m", "s.json", "docker/vault", "runs/h.jsonl")
    _default_dispatch(_args(fake=True))(plan)
    assert list(seen["context"]) == ["find the sqli"]
    assert seen["mode"] == "web"


def test_default_dispatch_without_a_brief_passes_no_context(monkeypatch):
    import brukal.assist as ac
    from brukal import envprep
    from brukal.hunt_wizard import _default_dispatch
    seen = {}
    monkeypatch.setattr(ac, "run_auto", lambda target, **kw: seen.update(kw) or 0)
    plan = envprep.plan_web("https://abc.web-security-academy.net/", "",
                            "openrouter", "m", "s.json", "docker/vault", "runs/h.jsonl")
    _default_dispatch(_args(fake=True))(plan)
    assert list(seen["context"]) == []


def test_default_dispatch_imports_cleanly_in_a_fresh_process():
    """`brukal hunt` imports only brukal.cli before dispatch. Importing
    brukal.assist_cli directly from there raised the assist<->assist_cli circular
    ImportError at the wizard's final step; a fresh interpreter is the only faithful
    check (this test process already has the modules loaded)."""
    import subprocess
    import sys
    from pathlib import Path
    code = ("import types, brukal.cli\n"
            "from brukal.hunt_wizard import _default_dispatch\n"
            "_default_dispatch(types.SimpleNamespace(fake=True, container='c', "
            "base_url=None, tui=False))\n"
            "print('OK')\n")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=str(Path(__file__).resolve().parents[1]), timeout=120)
    assert out.stdout.strip() == "OK", out.stderr[-800:]
