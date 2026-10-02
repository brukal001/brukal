# tests/security/test_executor_single_path.py
"""I4 - agents reach execution ONLY through the Executor/gate.

Static AST scan over the brukal package: no subprocess / os.system / os.popen /
os.exec* / os.spawn* / os.fork / eval / exec / shell=True / socket.socket /
socket.create_connection / pty outside the door/cage layer; and no agent module
imports ``brukal.kali`` (agents get the Executor, never the cage object).
"""
import ast
import pathlib

import pytest

PKG = pathlib.Path(__file__).resolve().parents[2] / "brukal"

# Legitimate door / executor / cage sites (enumerated from a grep of the package):
ALLOWED_EXEC_MODULES = {
    "kali.py",          # the cage object: docker exec / Popen for the run itself (Executor wraps it)
    "cage.py",          # host-side cage bring-up (docker compose etc.), pre-run only
    "chrome.py",        # headless-Chrome render via argv subprocess, door-layer
    "cdp.py",           # Chrome DevTools Protocol socket client, door-layer
    "oob.py",           # OOB listener control inside the cage (docker exec)
    "web.py",           # web tool door: argv subprocess (curl/render), door-layer
    "egress_proxy.py",  # the scope-enforcing egress proxy: sockets are its job
}
# Genuine non-door exec sites found by the scan: documented findings, NOT allowlisted.
KNOWN_FINDINGS = {
    "cli.py": "FINDING SEC-I4a: cli.py runs subprocess.run(['docker','cp',...]) outside the door",
    "skills.py": "FINDING SEC-I4b: skills.py install_pack runs subprocess.run(['git','clone',...]) outside the door",
}

_OS_BAD = {"system", "popen", "fork", "forkpty", "execv", "execve", "execl", "execle",
           "execlp", "execlpe", "execvp", "execvpe", "spawnl", "spawnv", "spawnlp",
           "spawnvp", "spawnve", "spawnle", "posix_spawn", "posix_spawnp"}
_SOCKET_BAD = {"socket", "create_connection", "create_server", "socketpair"}
_BANNED_MODULES = {"subprocess", "pty"}
_BANNED_BUILTINS = {"eval", "exec"}


def _violations(src: str, modname: str) -> list[str]:
    tree = ast.parse(src)
    out: list[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] in _BANNED_MODULES:
                    out.append(f"{modname}:{n.lineno} import {a.name}")
        elif isinstance(n, ast.ImportFrom):
            if (n.module or "").split(".")[0] in _BANNED_MODULES:
                out.append(f"{modname}:{n.lineno} from {n.module} import ...")
        elif isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id in _BANNED_BUILTINS:
                out.append(f"{modname}:{n.lineno} {f.id}()")
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                if f.value.id == "os" and f.attr in _OS_BAD:
                    out.append(f"{modname}:{n.lineno} os.{f.attr}")
                if f.value.id == "socket" and f.attr in _SOCKET_BAD:
                    out.append(f"{modname}:{n.lineno} socket.{f.attr}")
                if f.value.id in _BANNED_MODULES:
                    out.append(f"{modname}:{n.lineno} {f.value.id}.{f.attr}")
            for kw in n.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    out.append(f"{modname}:{n.lineno} shell=True")
    return out


def _pkg_files():
    return [p for p in sorted(PKG.rglob("*.py"))
            if not any(part.startswith(".") or part in ("__pycache__", "site-packages")
                       for part in p.relative_to(PKG).parts)]


def _scan(skip: set[str]):
    bad = []
    for p in _pkg_files():
        if p.name in skip:
            continue
        bad += [(p.name, v) for v in _violations(p.read_text(encoding="utf-8"), p.name)]
    return bad


def test_self_test_checker_catches_injected_violation():
    assert _violations("import os\nos.system('x')\n", "fake.py"), "checker is vacuous"
    assert _violations("import subprocess\n", "fake.py")
    assert _violations("f(shell=True)\n", "fake.py")
    assert _violations("import socket\nsocket.socket()\n", "fake.py")
    assert _violations("eval('1')\n", "fake.py")
    assert not _violations("import os\nos.path.join('a')\n", "fake.py")


def test_scanner_sees_the_package():
    files = _pkg_files()
    assert len(files) > 50
    for m in ALLOWED_EXEC_MODULES:
        assert (PKG / m).exists(), f"allowlisted module missing: {m}"
    # positive control: the scanner does find exec in the real door layer
    assert _violations((PKG / "kali.py").read_text(encoding="utf-8"), "kali.py")


def test_no_exec_path_outside_executor(record):
    """No NEW exec/socket site beyond the allowlist and the documented findings."""
    bad = _scan(ALLOWED_EXEC_MODULES | set(KNOWN_FINDINGS))
    record("i4::exec-scan", "executor-single-path", "I4", f"{len(bad)} new violations", "0",
           str(len(bad)), "critical")
    assert not bad, f"exec/socket outside executor path: {bad}"


def test_agents_have_no_exec_primitives(record):
    bad = []
    for p in sorted((PKG / "agents").glob("*.py")):
        bad += [(p.name, v) for v in _violations(p.read_text(encoding="utf-8"), p.name)]
    record("i4::agents-no-exec", "executor-single-path", "I4", f"{len(bad)} violations", "0",
           str(len(bad)), "critical")
    assert not bad, bad


def _imports_kali(src: str) -> list[int]:
    hits = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import):
            if any(a.name == "brukal.kali" or a.name.startswith("brukal.kali.") for a in n.names):
                hits.append(n.lineno)
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            if (n.level == 0 and (mod == "brukal.kali" or mod.startswith("brukal.kali."))) \
               or (n.level >= 1 and (mod == "kali" or mod.startswith("kali."))) \
               or (mod in ("brukal", "") and any(a.name == "kali" for a in n.names)):
                hits.append(n.lineno)
    return hits


def test_agents_do_not_import_kali(record):
    assert _imports_kali("from ..kali import DockerKali\n")          # self-test
    assert _imports_kali("import brukal.kali\n")
    assert _imports_kali("from brukal import kali\n")
    assert not _imports_kali("from ..executor import Executor\n")
    bad = []
    for p in sorted((PKG / "agents").glob("*.py")):
        bad += [(p.name, ln) for ln in _imports_kali(p.read_text(encoding="utf-8"))]
    record("i4::agents-no-kali", "executor-single-path", "I4", f"{len(bad)} kali imports", "0",
           str(len(bad)), "critical")
    assert not bad, f"agents import the kali object: {bad}"


@pytest.mark.xfail(strict=True, reason="FINDING SEC-I4a/SEC-I4b: cli.py (docker cp) and skills.py "
                   "(git clone) call subprocess outside the door; operator-side, not agent-reachable; "
                   "see SECURITY_AUDIT.md")
def test_known_non_door_exec_sites_absent(record):
    bad = _scan(ALLOWED_EXEC_MODULES)
    record("i4::non-door-exec-known", "executor-single-path", "I4", f"{len(bad)} violations", "0",
           str(len(bad)), "medium")
    assert not bad, bad
