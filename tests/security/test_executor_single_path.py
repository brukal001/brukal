# tests/security/test_executor_single_path.py
"""I4 - agents reach execution ONLY through the Executor/gate.

Static AST scan over the brukal package: no subprocess / os.system / os.popen /
os.exec* / os.spawn* / os.fork / eval / exec / shell=True / socket.socket /
socket.create_connection / pty outside the door/cage layer; and no agent module
imports ``brukal.kali`` (agents get the Executor, never the cage object).
"""
import ast
import pathlib

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
# Operator-CLI-only exec sites (GOVERNANCE observations, not I4 bypasses): argv, no shell,
# operator-typed input, unreachable from any agent/orchestrator/executor path (tested below).
OPERATOR_SIDE_EXEC = {
    "cli.py": "subprocess docker cp in _cmd_apk - operator `brukal apk` CLI only, no agent path",
    "skills.py": "subprocess git clone in install_pack - operator `brukal skills add` CLI only, no agent path",
}
# Pinned exec-site counts so a NEW stray exec in these files trips the test.
OPERATOR_SIDE_EXPECTED_COUNT = {"cli.py": 1, "skills.py": 1}

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
    """No exec/socket site outside {door allowlist} + {operator-side sites}."""
    bad = _scan(ALLOWED_EXEC_MODULES | set(OPERATOR_SIDE_EXEC))
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


def test_operator_side_exec_sites_pinned(record):
    """A new exec in cli.py/skills.py must trip this, not hide behind the file skip."""
    actual = {}
    for name in OPERATOR_SIDE_EXEC:
        # count real call sites (the `import subprocess` line itself is not a call site)
        actual[name] = len([v for v in _violations((PKG / name).read_text(encoding="utf-8"), name)
                            if " import " not in v])
    record("i4::operator-side-pin", "executor-single-path", "I4", str(actual),
           str(OPERATOR_SIDE_EXPECTED_COUNT), str(actual), "medium")
    assert actual == OPERATOR_SIDE_EXPECTED_COUNT, actual


def _imports_operator_side(src: str) -> list[str]:
    hits = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import):
            hits += [a.name for a in n.names if a.name in ("brukal.cli", "brukal.skills")]
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            full = mod if n.level == 0 else f"brukal.{mod}".rstrip(".")
            if full in ("brukal.cli", "brukal.skills"):
                hits.append(full)
            if full == "brukal" or (n.level and not mod):
                hits += [f"brukal.{a.name}" for a in n.names if a.name in ("cli", "skills")]
            if any(a.name == "install_pack" for a in n.names):
                hits.append("install_pack")
    return hits


def test_operator_side_exec_unreachable_from_agents(record):
    assert _imports_operator_side("from ..skills import install_pack\n")      # self-test
    assert _imports_operator_side("from .. import cli\n")
    assert _imports_operator_side("import brukal.cli\n")
    assert not _imports_operator_side("from ..llm import LLMClient\n")
    files = sorted((PKG / "agents").glob("*.py")) + [PKG / "orchestrator.py"]
    bad = [(p.name, h) for p in files for h in _imports_operator_side(p.read_text(encoding="utf-8"))]
    record("i4::operator-side-unreachable", "executor-single-path", "I4", f"{len(bad)} imports", "0",
           str(len(bad)), "high")
    assert not bad, f"agent/orchestrator reaches operator-side exec: {bad}"
