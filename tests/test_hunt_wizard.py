import types
import json

from brukal.cage import FakeCageRunner
from brukal.hunt_wizard import run_hunt


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
