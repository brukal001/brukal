# Hunt Wizard + envprep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `brukal hunt` a guided, environment-adaptive bring-up (web: URL+context; VPN: .ovpn+targets) that auto-prepares scope/cage/DNS behind one approval and launches the run — no separate shell commands.

**Architecture:** A thin wizard (`hunt_wizard.run`, called by `cli._cmd_hunt`) orchestrates three new units: `keys.py` (provider-aware API-key resolution), `envprep.py` (pure `plan_web`/`plan_vpn` → a `BringUpPlan`, plus `execute`/`verify` that act only through an injected runner), and `cage.py` (the runner: the sole shell-out site, with a `FakeCageRunner` for Docker-free tests). Scope is built as a structured draft (`authorized:false`), shown, approved once, then frozen to `authorized:true` before anything touches the cage.

**Tech Stack:** Python 3.12 stdlib (`dataclasses`, `typing.Protocol`, `ipaddress`, `urllib.parse`, `subprocess`, `json`); pytest. No new third-party deps.

**Spec:** `docs/superpowers/specs/2026-10-02-hunt-wizard-envprep-design.md`

## Global Constraints

- **Five safety invariants hold.** No LLM in planning/scoping/gate (deterministic wizard). Fail-closed: any ambiguous/failed required step aborts. Agents never receive `kali`/`Executor`; `envprep`/`cage` are pre-run host orchestration only and must not import `brukal.kali`, `brukal.executor`, or any `brukal.agents.*`. Scope goes draft→approve→freeze; never widened at runtime.
- **Build + self-test ONLY.** Every test runs with `FakeCageRunner` / injected fakes — **no Docker, no network, no live target** in the suite. Live bring-up is human-gated and out of this plan.
- **Keep the existing suite green** (currently ~2072 tests) and **pyflakes clean on every new file.** Run the suite with the project's test venv (the one that already collects the full suite): `python -m pytest`.
- **Secrets never printed or logged.** The raw API key is never placed in any dataclass `repr`, log line, or `StepResult.detail`.
- **Branch:** `feat/hunt-wizard-envprep` (already created off `main`; the spec is committed there as `dc745f8`).
- **Commit discipline:** one commit per task, frequent. **Every commit message ends with the attribution block:**
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Proevkjj8tujNYeExuys6m
  ```
  (Per-task commit commands below abbreviate it as `<attribution>`.)
- **Scope file schema (verbatim fields):** `engagement`, `authorized_cidrs`, `authorized_hosts`, `allowlisted_tools` (`"all"`), `rate_limit_per_min`, `exclusions`, `forbidden_classes`, `tls_verify`, `authorization`, `authorized`, `expires`, `assets`, `accounts`, `approved_by`, `approved_at`.

## Review Focus

Inputs the spec implies but a naive task set won't exercise — each pinned to the owning task below:

1. **URL with no parseable host** (`"foo"`, `"https:///"`, empty) → `build_web_scope_draft` must raise, never emit a scope with an empty or `*` host. *(Task 3)*
2. **`.ovpn` with commented/multiple/zero `remote` lines** → `parse_ovpn_remote` picks the first *uncommented* `remote`, and raises on none — never pins a commented server. *(Task 3)*
3. **API key present in env AND file, or a file value with a trailing newline** → `resolve_key` prefers env, strips surrounding whitespace, and the key never appears in `repr(KeyResolution)`. *(Task 2)*
4. **`compose_recreate` returns non-zero** (Docker Desktop flaky exit 255) → `execute` stops at that step, marks the result not-ok, and runs no later step; the wizard then does **not** dispatch. *(Task 5, Task 6)*
5. **Over-broad VPN target** (`0.0.0.0/0`, a `/0`, or an obviously public single IP range) → `build_vpn_scope_draft` refuses to auto-authorize it (raises), rather than scoping the internet. *(Task 3)*

---

### Task 1: `cage.py` — runner protocol, fake, and docker impl

**Files:**
- Create: `brukal/cage.py`
- Test: `tests/test_cage.py`

**Interfaces:**
- Consumes: nothing (leaf module; stdlib only).
- Produces: `StepResult(ok: bool, name: str, detail: str="")`; `CageRunner` (Protocol) with methods `compose_recreate(scope_path, resolver)`, `set_resolver(ip)`, `stage_vpn(ovpn_src)`, `scope_matches(expect_substr)`, `cdp_probe()`, `http_probe_via_proxy(url)`, `tun_up()` — each returning `StepResult`; `FakeCageRunner(fail=frozenset())` recording `.calls` as `(name, tuple(args))`; `DockerCageRunner(compose_file, container, run=subprocess.run)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cage.py
import subprocess
from brukal.cage import StepResult, FakeCageRunner, DockerCageRunner

def test_fake_records_calls_and_honours_fail_set():
    r = FakeCageRunner(fail={"compose_recreate"})
    ok = r.set_resolver("1.1.1.1")
    bad = r.compose_recreate("scope.json", "1.1.1.1")
    assert ok == StepResult(True, "set_resolver", detail="1.1.1.1")
    assert bad.ok is False and bad.name == "compose_recreate"
    assert r.calls == [("set_resolver", ("1.1.1.1",)),
                       ("compose_recreate", ("scope.json", "1.1.1.1"))]

def test_docker_recreate_builds_force_recreate_argv_without_running_docker():
    seen = {}
    def fake_run(argv, **kw):
        seen["argv"] = argv
        class P: returncode = 0; stdout = ""; stderr = ""
        return P()
    r = DockerCageRunner(compose_file="docker/docker-compose.yml",
                         container="brukal-kali", run=fake_run)
    res = r.compose_recreate("scope.crapi.json", "1.1.1.1")
    assert res.ok is True
    assert seen["argv"][:3] == ["docker", "compose", "-f"]
    assert "--force-recreate" in seen["argv"] and "--no-build" in seen["argv"]
    assert "kali" in seen["argv"]

def test_docker_set_resolver_writes_resolv_conf_via_exec():
    seen = {}
    def fake_run(argv, **kw):
        seen["argv"] = argv
        class P: returncode = 0; stdout = ""; stderr = ""
        return P()
    r = DockerCageRunner(container="brukal-kali", run=fake_run)
    r.set_resolver("1.1.1.1")
    assert seen["argv"][:3] == ["docker", "exec", "brukal-kali"]
    assert "nameserver 1.1.1.1" in " ".join(seen["argv"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cage.py -v`
Expected: FAIL (`ModuleNotFoundError: brukal.cage`).

- [ ] **Step 3: Write minimal implementation**

```python
# brukal/cage.py
"""Host-side cage orchestration — the ONLY shell-out site for bring-up.
Pre-run only: this module never imports kali/executor/agents, and the run
itself still flows through Executor.run()."""
from __future__ import annotations
import subprocess
from dataclasses import dataclass, field
from typing import Protocol, Callable


@dataclass(frozen=True)
class StepResult:
    ok: bool
    name: str
    detail: str = ""        # short, human-readable; NEVER a secret


class CageRunner(Protocol):
    def compose_recreate(self, scope_path: str, resolver: str) -> StepResult: ...
    def set_resolver(self, ip: str) -> StepResult: ...
    def stage_vpn(self, ovpn_src: str) -> StepResult: ...
    def scope_matches(self, expect_substr: str) -> StepResult: ...
    def cdp_probe(self) -> StepResult: ...
    def http_probe_via_proxy(self, url: str) -> StepResult: ...
    def tun_up(self) -> StepResult: ...
    def target_routable(self, target: str) -> StepResult: ...


@dataclass
class FakeCageRunner:
    """Records calls; returns ok unless the method name is in `fail`."""
    fail: frozenset = frozenset()
    calls: list = field(default_factory=list)

    def _do(self, name, *args, detail=""):
        self.calls.append((name, args))
        return StepResult(name not in self.fail, name, detail=detail)

    def compose_recreate(self, scope_path, resolver):
        return self._do("compose_recreate", scope_path, resolver)
    def set_resolver(self, ip):
        return self._do("set_resolver", ip, detail=ip)
    def stage_vpn(self, ovpn_src):
        return self._do("stage_vpn", ovpn_src)
    def scope_matches(self, expect_substr):
        return self._do("scope_matches", expect_substr)
    def cdp_probe(self):
        return self._do("cdp_probe")
    def http_probe_via_proxy(self, url):
        return self._do("http_probe_via_proxy", url)
    def tun_up(self):
        return self._do("tun_up")
    def target_routable(self, target):
        return self._do("target_routable", target)


class DockerCageRunner:
    """Real runner. `run` is injected so argv construction is unit-testable
    without executing docker."""
    def __init__(self, compose_file="docker/docker-compose.yml",
                 container="brukal-kali", proxy="http://127.0.0.1:8888",
                 run: Callable = subprocess.run):
        self.compose_file = compose_file
        self.container = container
        self.proxy = proxy
        self._run = run

    def _sh(self, name, argv, detail=""):
        p = self._run(argv, capture_output=True, text=True)
        return StepResult(getattr(p, "returncode", 1) == 0, name, detail=detail)

    def compose_recreate(self, scope_path, resolver):
        # scope_path is mounted via compose; resolver is the BRUKAL_DNS default
        # already baked into the compose file. Recreate re-reads the scope.
        argv = ["docker", "compose", "-f", self.compose_file,
                "up", "-d", "--force-recreate", "--no-build", "kali"]
        return self._sh("compose_recreate", argv, detail=scope_path)

    def set_resolver(self, ip):
        argv = ["docker", "exec", self.container, "sh", "-c",
                f'printf "nameserver {ip}\\n" > /etc/resolv.conf']
        return self._sh("set_resolver", argv, detail=ip)

    def stage_vpn(self, ovpn_src):
        argv = ["cp", ovpn_src, "docker/vpn/config.ovpn"]
        return self._sh("stage_vpn", argv, detail=ovpn_src)

    def scope_matches(self, expect_substr):
        argv = ["docker", "exec", self.container, "grep", "-q", expect_substr, "/scope.json"]
        return self._sh("scope_matches", argv, detail=expect_substr)

    def cdp_probe(self):
        argv = ["curl", "-s", "--max-time", "3", "http://127.0.0.1:9222/json"]
        p = self._run(argv, capture_output=True, text=True)
        ok = getattr(p, "returncode", 1) == 0 and '"type": "page"' in (getattr(p, "stdout", "") or "")
        return StepResult(ok, "cdp_probe")

    def http_probe_via_proxy(self, url):
        argv = ["docker", "exec", self.container, "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}", "--max-time", "20", "-x", self.proxy, url]
        p = self._run(argv, capture_output=True, text=True)
        code = (getattr(p, "stdout", "") or "").strip()
        return StepResult(code[:1] in ("2", "3"), "http_probe_via_proxy", detail=code)

    def tun_up(self):
        argv = ["docker", "exec", self.container, "ip", "link", "show", "tun0"]
        return self._sh("tun_up", argv)

    def target_routable(self, target):
        # route exists to the target (via tun0) — deterministic; does not depend
        # on the box answering ICMP or any particular port being open.
        argv = ["docker", "exec", self.container, "ip", "route", "get", target]
        return self._sh("target_routable", argv, detail=target)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cage.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add brukal/cage.py tests/test_cage.py
git commit -m "feat(cage): host-side cage runner (protocol + fake + docker impl)

<attribution>"
```

---

### Task 2: `keys.py` — provider-aware API-key resolution

**Files:**
- Create: `brukal/keys.py`
- Test: `tests/test_keys.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `KeyResolution(provider: str, found: bool, source: str)` (NO key field); `resolve_key(provider, *, environ=os.environ, runs_dir="runs", prompt=input, save=True) -> tuple[str|None, KeyResolution]`.

- [ ] **Step 1: Write the failing test** *(covers Review Focus #3)*

```python
# tests/test_keys.py
from pathlib import Path
from brukal.keys import resolve_key, KeyResolution

def test_env_wins_over_file_and_is_stripped(tmp_path):
    (tmp_path / "openrouter.env").write_text("export OPENROUTER_API_KEY=fromfile\n")
    key, res = resolve_key("openrouter",
                           environ={"OPENROUTER_API_KEY": "  fromenv  "},
                           runs_dir=str(tmp_path))
    assert key == "fromenv"
    assert res == KeyResolution("openrouter", True, "env")

def test_file_used_when_env_absent_newline_stripped(tmp_path):
    (tmp_path / "openrouter.env").write_text("export OPENROUTER_API_KEY=sk-file-123\n")
    key, res = resolve_key("openrouter", environ={}, runs_dir=str(tmp_path))
    assert key == "sk-file-123" and res.source.startswith("file:")

def test_prompt_and_save_when_missing(tmp_path):
    key, res = resolve_key("openrouter", environ={}, runs_dir=str(tmp_path),
                           prompt=lambda _p: "sk-typed-xyz")
    assert key == "sk-typed-xyz" and res.source == "prompt"
    saved = (tmp_path / "openrouter.env").read_text()
    assert "sk-typed-xyz" in saved

def test_key_never_appears_in_resolution_repr(tmp_path):
    key, res = resolve_key("openrouter", environ={"OPENROUTER_API_KEY": "sk-secret"},
                           runs_dir=str(tmp_path))
    assert "sk-secret" not in repr(res)

def test_missing_and_declined_returns_none(tmp_path):
    key, res = resolve_key("openrouter", environ={}, runs_dir=str(tmp_path),
                           prompt=lambda _p: "")
    assert key is None and res.found is False and res.source == "none"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_keys.py -v`
Expected: FAIL (`ModuleNotFoundError: brukal.keys`).

- [ ] **Step 3: Write minimal implementation**

```python
# brukal/keys.py
"""Provider-aware API-key resolution for the hunt wizard. The raw key is
returned separately and is NEVER stored in KeyResolution (repr-safe)."""
from __future__ import annotations
import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KeyResolution:
    provider: str
    found: bool
    source: str   # "env" | "file:<path>" | "prompt" | "none"


def _env_var(provider: str) -> str:
    return f"{provider.upper()}_API_KEY"


def _read_file_key(path: Path, var: str) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(rf"^(?:export\s+)?{re.escape(var)}=(.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def resolve_key(provider, *, environ=None, runs_dir="runs", prompt=input, save=True):
    environ = os.environ if environ is None else environ
    var = _env_var(provider)
    env_val = (environ.get(var) or "").strip()
    if env_val:
        return env_val, KeyResolution(provider, True, "env")

    f = Path(runs_dir) / f"{provider.lower()}.env"
    file_val = _read_file_key(f, var)
    if file_val:
        return file_val, KeyResolution(provider, True, f"file:{f}")

    try:
        typed = (prompt(f"  {var} (blank to skip): ") or "").strip()
    except (EOFError, OSError):
        typed = ""
    if not typed:
        return None, KeyResolution(provider, False, "none")

    if save:
        try:
            Path(runs_dir).mkdir(parents=True, exist_ok=True)
            os.umask(0o077)
            f.write_text(f"export {var}={typed}\n", encoding="utf-8")
        except OSError:
            pass
    return typed, KeyResolution(provider, True, "prompt")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_keys.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add brukal/keys.py tests/test_keys.py
git commit -m "feat(keys): provider-aware API-key resolution (env/file/prompt, repr-safe)

<attribution>"
```

---

### Task 3: `envprep.py` data model + scope drafting + ovpn parse

**Files:**
- Create: `brukal/envprep.py`
- Test: `tests/test_envprep_draft.py`

**Interfaces:**
- Consumes: `brukal.cage.StepResult` (import only; not used yet here).
- Produces: dataclasses `Dispatch`, `BringUpPlan`, `BringUpResult`; `parse_ovpn_remote(text) -> str`; `build_web_scope_draft(url, *, rate=30) -> tuple[str, dict]`; `build_vpn_scope_draft(targets, vpn_server, *, rate=30) -> dict`; `freeze_scope(scope_path, draft, *, approver="operator") -> dict`.

- [ ] **Step 1: Write the failing test** *(covers Review Focus #1, #2, #5)*

```python
# tests/test_envprep_draft.py
import json, pytest
from brukal.envprep import (parse_ovpn_remote, build_web_scope_draft,
                            build_vpn_scope_draft, freeze_scope)

def test_parse_ovpn_remote_first_uncommented():
    txt = "# remote old.example.com 1194\nremote lab.hackbox.io 1337 udp\nremote alt 1194\n"
    assert parse_ovpn_remote(txt) == "lab.hackbox.io"

def test_parse_ovpn_remote_none_raises():
    with pytest.raises(ValueError):
        parse_ovpn_remote("# remote only.commented 1194\nclient\n")

def test_web_draft_host_and_fields():
    host, draft = build_web_scope_draft("https://abc123.web-security-academy.net/login?x=1")
    assert host == "abc123.web-security-academy.net"
    assert draft["authorized_hosts"] == ["abc123.web-security-academy.net"]
    assert draft["authorized_cidrs"] == [] and draft["tls_verify"] is True
    assert draft["authorized"] is False and draft["forbidden_classes"] == ["dos"]

@pytest.mark.parametrize("bad", ["foo", "https:///", "", "   "])
def test_web_draft_bad_url_raises(bad):
    with pytest.raises(ValueError):
        build_web_scope_draft(bad)

def test_vpn_draft_cidrs_and_server():
    draft = build_vpn_scope_draft(["10.10.11.5", "10.10.11.0/24"], "lab.hackbox.io")
    assert draft["authorized_cidrs"] == ["10.10.11.5/32", "10.10.11.0/24"]
    assert draft["authorized"] is False
    assert "lab.hackbox.io" in json.dumps(draft)   # server recorded for pinning

@pytest.mark.parametrize("bad", ["0.0.0.0/0", "::/0", "10.0.0.0/4"])
def test_vpn_draft_rejects_overbroad(bad):
    with pytest.raises(ValueError):
        build_vpn_scope_draft([bad], "lab.hackbox.io")

def test_freeze_sets_authorized_true_with_provenance(tmp_path):
    _h, draft = build_web_scope_draft("https://abc123.web-security-academy.net/")
    p = tmp_path / "scope.hunt.json"
    frozen = freeze_scope(str(p), draft, approver="operator-01")
    assert frozen["authorized"] is True and frozen["approved_by"] == "operator-01"
    assert frozen["approved_at"]
    on_disk = json.loads(p.read_text())
    assert on_disk["authorized"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_envprep_draft.py -v`
Expected: FAIL (`ModuleNotFoundError: brukal.envprep`).

- [ ] **Step 3: Write minimal implementation**

```python
# brukal/envprep.py  (part 1 of 2 — data model, drafting, parse; plan_/execute/verify added in Tasks 4-5)
"""Environment bring-up: pure planning + drafting here; side effects live in
execute()/verify() (Task 5) and go only through an injected cage runner.
Never imports kali/executor/agents."""
from __future__ import annotations
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from brukal.cage import StepResult  # noqa: F401  (used by execute/verify in Task 5)

_RATE_DEFAULT = 30


@dataclass(frozen=True)
class Dispatch:
    kind: str            # "auto_web" | "engagement"
    target: str
    context: str = ""
    provider: str = ""
    model: str = ""
    vault: str = ""
    audit: str = ""


@dataclass(frozen=True)
class BringUpPlan:
    mode: str                     # "web" | "vpn"
    scope_path: str
    scope_draft: dict             # authorized:false; frozen only after approval
    scope_summary: str
    cage_action: str              # "recreate" | "none"
    resolver: str
    vpn_file: str | None
    verify_steps: tuple
    dispatch: Dispatch


@dataclass(frozen=True)
class BringUpResult:
    ok: bool
    steps: tuple


def parse_ovpn_remote(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("remote ") and not s.startswith("#"):
            parts = s.split()
            if len(parts) >= 2:
                return parts[1]
    raise ValueError("no uncommented 'remote' line in .ovpn")


def _blank_draft(rate: int) -> dict:
    return {
        "engagement": "",
        "authorized_cidrs": [],
        "authorized_hosts": [],
        "allowlisted_tools": "all",
        "rate_limit_per_min": rate,
        "exclusions": [],
        "forbidden_classes": ["dos"],
        "tls_verify": True,
        "authorization": "",
        "authorized": False,
        "expires": "",
        "assets": [],
        "accounts": [],
        "approved_by": "",
        "approved_at": "",
    }


def build_web_scope_draft(url: str, *, rate: int = _RATE_DEFAULT):
    host = urlsplit(url if "://" in (url or "") else f"https://{url}").hostname
    if not host or "." not in host:
        raise ValueError(f"no parseable host in URL: {url!r}")
    d = _blank_draft(rate)
    d["engagement"] = f"hunt-web-{host}"
    d["authorized_hosts"] = [host]
    d["assets"] = [{"pattern": host, "type": "domain", "value": "low"}]
    d["authorization"] = f"guided hunt (web) against single host {host}; draft pending approval"
    return host, d


def _norm_cidr(t: str) -> str:
    net = ipaddress.ip_network(t.strip(), strict=False)
    if net.prefixlen <= 8:        # /0../8 is far too broad to auto-authorize
        raise ValueError(f"target too broad to auto-authorize: {t!r}")
    return str(net) if "/" in t else f"{net.network_address}/{net.max_prefixlen}"


def build_vpn_scope_draft(targets, vpn_server: str, *, rate: int = _RATE_DEFAULT):
    cidrs = [_norm_cidr(t) for t in targets if str(t).strip()]
    if not cidrs:
        raise ValueError("no targets given")
    d = _blank_draft(rate)
    d["engagement"] = f"hunt-vpn-{cidrs[0].replace('/', '_')}"
    d["authorized_cidrs"] = cidrs
    d["authorization"] = (f"guided hunt (vpn) via server {vpn_server}; targets {', '.join(cidrs)}; "
                          "draft pending approval")
    d["assets"] = [{"pattern": c, "type": "cidr", "value": "low"} for c in cidrs]
    d["_vpn_server"] = vpn_server      # recorded for the egress-lock pin
    return d


def freeze_scope(scope_path: str, draft: dict, *, approver: str = "operator") -> dict:
    frozen = dict(draft)
    now = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    frozen["authorized"] = True
    frozen["approved_by"] = approver
    frozen["approved_at"] = now
    frozen["authorization"] = frozen.get("authorization", "").replace(
        "draft pending approval", f"approved by {approver} on {now}")
    Path(scope_path).write_text(json.dumps(frozen, indent=2) + "\n", encoding="utf-8")
    return frozen
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_envprep_draft.py -v`
Expected: PASS (web bad-url 4 params + vpn overbroad 3 params + others).

- [ ] **Step 5: Commit**

```bash
git add brukal/envprep.py tests/test_envprep_draft.py
git commit -m "feat(envprep): scope drafting + ovpn parse + freeze (authorized:false->true)

<attribution>"
```

---

### Task 4: `envprep.plan_web` + `plan_vpn` (pure planners)

**Files:**
- Modify: `brukal/envprep.py` (append `plan_web`, `plan_vpn`)
- Test: `tests/test_envprep_plan.py`

**Interfaces:**
- Consumes: Task 3's `BringUpPlan`, `Dispatch`, `build_web_scope_draft`, `build_vpn_scope_draft`, `parse_ovpn_remote`.
- Produces: `plan_web(url, context, provider, model, scope_path, vault, audit, *, rate=30) -> BringUpPlan`; `plan_vpn(ovpn_path, targets, provider, model, scope_path, vault, audit, *, rate=30, read_text=None) -> BringUpPlan`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_envprep_plan.py
from brukal.envprep import plan_web, plan_vpn, Dispatch

def test_plan_web_shape():
    p = plan_web("https://abc.web-security-academy.net/", "find SQLi in /filter",
                 "openrouter", "deepseek/deepseek-v4-pro",
                 "scope.hunt.json", "docker/vault", "runs/hunt.jsonl")
    assert p.mode == "web" and p.cage_action == "recreate" and p.resolver == "1.1.1.1"
    assert p.vpn_file is None
    assert p.scope_draft["authorized_hosts"] == ["abc.web-security-academy.net"]
    assert p.verify_steps == ("cdp_probe", "scope_matches", "http_probe_via_proxy")
    assert p.dispatch == Dispatch("auto_web", "https://abc.web-security-academy.net/",
                                  "find SQLi in /filter", "openrouter",
                                  "deepseek/deepseek-v4-pro", "docker/vault", "runs/hunt.jsonl")

def test_plan_vpn_shape_reads_remote():
    ovpn = "client\nremote lab.hackbox.io 1337 udp\n"
    p = plan_vpn("my.ovpn", ["10.10.11.5"], "anthropic", "claude-sonnet-5-5",
                 "scope.hunt.json", "docker/vault", "runs/hunt.jsonl",
                 read_text=lambda _path: ovpn)
    assert p.mode == "vpn" and p.vpn_file == "my.ovpn" and p.cage_action == "recreate"
    assert p.scope_draft["authorized_cidrs"] == ["10.10.11.5/32"]
    assert p.scope_draft["_vpn_server"] == "lab.hackbox.io"
    assert p.verify_steps == ("tun_up", "scope_matches", "target_routable")
    assert p.dispatch.kind == "engagement" and p.dispatch.target == "10.10.11.5"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_envprep_plan.py -v`
Expected: FAIL (`ImportError: cannot import name 'plan_web'`).

- [ ] **Step 3: Write minimal implementation**

```python
# append to brukal/envprep.py

def _summary(draft: dict) -> str:
    where = draft["authorized_hosts"] or draft["authorized_cidrs"]
    return (f"{', '.join(where)} · tls_verify={draft['tls_verify']} · "
            f"{draft['rate_limit_per_min']}/min · forbidden={draft['forbidden_classes']}")


def plan_web(url, context, provider, model, scope_path, vault, audit, *, rate=_RATE_DEFAULT):
    _host, draft = build_web_scope_draft(url, rate=rate)
    return BringUpPlan(
        mode="web", scope_path=scope_path, scope_draft=draft,
        scope_summary=_summary(draft), cage_action="recreate", resolver="1.1.1.1",
        vpn_file=None,
        verify_steps=("cdp_probe", "scope_matches", "http_probe_via_proxy"),
        dispatch=Dispatch("auto_web", url, context, provider, model, vault, audit),
    )


def plan_vpn(ovpn_path, targets, provider, model, scope_path, vault, audit,
             *, rate=_RATE_DEFAULT, read_text=None):
    read_text = read_text or (lambda p: Path(p).read_text(encoding="utf-8"))
    server = parse_ovpn_remote(read_text(ovpn_path))
    draft = build_vpn_scope_draft(targets, server, rate=rate)
    return BringUpPlan(
        mode="vpn", scope_path=scope_path, scope_draft=draft,
        scope_summary=_summary(draft), cage_action="recreate", resolver="1.1.1.1",
        vpn_file=ovpn_path,
        verify_steps=("tun_up", "scope_matches", "target_routable"),
        dispatch=Dispatch("engagement", str(targets[0]), "", provider, model, vault, audit),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_envprep_plan.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add brukal/envprep.py tests/test_envprep_plan.py
git commit -m "feat(envprep): pure plan_web/plan_vpn builders

<attribution>"
```

---

### Task 5: `envprep.execute` + `verify` (fail-closed, via runner)

**Files:**
- Modify: `brukal/envprep.py` (append `execute`, `verify`)
- Test: `tests/test_envprep_execute.py`

**Interfaces:**
- Consumes: `BringUpPlan`, `BringUpResult`, `brukal.cage.FakeCageRunner`.
- Produces: `execute(plan, runner) -> BringUpResult` (assumes scope already frozen on disk); `verify(plan, runner) -> BringUpResult`.

- [ ] **Step 1: Write the failing test** *(covers Review Focus #4)*

```python
# tests/test_envprep_execute.py
from brukal.cage import FakeCageRunner
from brukal.envprep import plan_web, plan_vpn, execute, verify

def _web_plan():
    return plan_web("https://abc.web-security-academy.net/", "ctx", "openrouter",
                    "m", "scope.hunt.json", "docker/vault", "runs/h.jsonl")

def test_execute_web_runs_recreate_then_resolver_in_order():
    r = FakeCageRunner()
    res = execute(_web_plan(), r)
    assert res.ok is True
    names = [c[0] for c in r.calls]
    assert names == ["compose_recreate", "set_resolver"]

def test_execute_vpn_stages_ovpn_before_recreate():
    ovpn = "remote lab.hackbox.io 1337\n"
    p = plan_vpn("my.ovpn", ["10.10.11.5"], "anthropic", "m",
                 "scope.hunt.json", "docker/vault", "runs/h.jsonl",
                 read_text=lambda _p: ovpn)
    r = FakeCageRunner()
    execute(p, r)
    names = [c[0] for c in r.calls]
    assert names.index("stage_vpn") < names.index("compose_recreate")

def test_execute_aborts_on_failed_recreate_no_later_steps():
    r = FakeCageRunner(fail={"compose_recreate"})
    res = execute(_web_plan(), r)
    assert res.ok is False
    assert [c[0] for c in r.calls] == ["compose_recreate"]   # stopped; no set_resolver

def test_verify_runs_named_steps_and_fails_closed():
    r = FakeCageRunner(fail={"http_probe_via_proxy"})
    res = verify(_web_plan(), r)
    assert res.ok is False
    assert [c[0] for c in r.calls] == ["cdp_probe", "scope_matches", "http_probe_via_proxy"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_envprep_execute.py -v`
Expected: FAIL (`ImportError: cannot import name 'execute'`).

- [ ] **Step 3: Write minimal implementation**

```python
# append to brukal/envprep.py

def execute(plan: BringUpPlan, runner) -> BringUpResult:
    """Apply the plan via the runner, in order, stopping at the first failure.
    Assumes the scope file at plan.scope_path is ALREADY frozen (authorized:true)."""
    steps = []
    if plan.vpn_file:
        steps.append(runner.stage_vpn(plan.vpn_file))
        if not steps[-1].ok:
            return BringUpResult(False, tuple(steps))
    if plan.cage_action == "recreate":
        steps.append(runner.compose_recreate(plan.scope_path, plan.resolver))
        if not steps[-1].ok:
            return BringUpResult(False, tuple(steps))
        steps.append(runner.set_resolver(plan.resolver))
        if not steps[-1].ok:
            return BringUpResult(False, tuple(steps))
    return BringUpResult(all(s.ok for s in steps), tuple(steps))


def _scope_match_token(plan: BringUpPlan) -> str:
    hosts = plan.scope_draft.get("authorized_hosts") or []
    cidrs = plan.scope_draft.get("authorized_cidrs") or []
    return (hosts[0] if hosts else cidrs[0].split("/")[0])


def verify(plan: BringUpPlan, runner) -> BringUpResult:
    steps = []
    for name in plan.verify_steps:
        if name == "scope_matches":
            steps.append(runner.scope_matches(_scope_match_token(plan)))
        elif name == "http_probe_via_proxy":
            steps.append(runner.http_probe_via_proxy(plan.dispatch.target))
        elif name == "target_routable":
            steps.append(runner.target_routable(plan.dispatch.target))
        else:
            steps.append(getattr(runner, name)())
    return BringUpResult(all(s.ok for s in steps), tuple(steps))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_envprep_execute.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add brukal/envprep.py tests/test_envprep_execute.py
git commit -m "feat(envprep): execute/verify via injected runner, fail-closed in order

<attribution>"
```

---

### Task 6: `hunt_wizard.run` + `_cmd_hunt` rewrite + wiring

**Files:**
- Create: `brukal/hunt_wizard.py`
- Modify: `brukal/cli.py` (`_cmd_hunt` @127 → delegate to wizard; `hunt` parser @617 → add `--mode`, `--url`, `--ovpn`, `--context` optional args, keep existing ones)
- Test: `tests/test_hunt_wizard.py`

**Interfaces:**
- Consumes: `keys.resolve_key`, `envprep.plan_web`/`plan_vpn`/`freeze_scope`/`execute`/`verify`, `cage.DockerCageRunner`, and (at dispatch) `assist_cli.run_auto` / `run_engagement`.
- Produces: `run_hunt(args, *, prompt=input, runner=None, dispatch=None, resolve_key=None) -> int` (return code). `dispatch(plan) -> int` is injected in tests; in production it maps `Dispatch.kind` → `run_auto(..., web=True)` / `run_engagement(...)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hunt_wizard.py
import types
from brukal.cage import FakeCageRunner
from brukal.hunt_wizard import run_hunt

def _args(**kw):
    base = dict(mode=None, url=None, ovpn=None, context=None, provider="openrouter",
                model="m", scope="scope.hunt.json", vault="docker/vault",
                audit="runs/h.jsonl", container="brukal-kali", fake=False, yes=False,
                tui=False, base_url=None, log="runs/engagement.log")
    base.update(kw); return types.SimpleNamespace(**base)

def test_web_path_freezes_then_executes_then_dispatches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    answers = iter(["web", "https://abc.web-security-academy.net/", "find sqli", "y"])
    runner = FakeCageRunner()
    dispatched = {}
    rc = run_hunt(_args(scope=str(tmp_path / "s.json")),
                  prompt=lambda _p: next(answers),
                  runner=runner,
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) or 0,
                  resolve_key=lambda _prov, **k: ("sk-x", None))
    assert rc == 0
    import json
    assert json.loads((tmp_path / "s.json").read_text())["authorized"] is True
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
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) or 0,
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
                  dispatch=lambda plan: dispatched.setdefault("plan", plan) or 0,
                  resolve_key=lambda _prov, **k: ("sk-x", None))
    assert rc != 0 and "plan" not in dispatched
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_hunt_wizard.py -v`
Expected: FAIL (`ModuleNotFoundError: brukal.hunt_wizard`).

- [ ] **Step 3: Write minimal implementation**

```python
# brukal/hunt_wizard.py
"""The guided `brukal hunt` wizard: gather -> draft -> plan -> show -> ONE
approval -> freeze + execute + verify -> dispatch. Deterministic; no LLM.
All side effects go through the injected runner / dispatch."""
from __future__ import annotations
from brukal import envprep, keys as keys_mod
from brukal.cage import DockerCageRunner


def _ask(prompt, q, default=""):
    try:
        v = (prompt(q) or "").strip()
    except (EOFError, OSError):
        v = ""
    return v or default


def _default_dispatch(args):
    from brukal.assist_cli import run_auto, run_engagement

    def _dispatch(plan):
        d = plan.dispatch
        if d.kind == "auto_web":
            return run_auto(d.target, scope_path=plan.scope_path, web=True,
                            context=[d.context] if d.context else None,
                            provider=d.provider, model=d.model, vault_path=d.vault,
                            audit_path=d.audit, container=args.container,
                            yes_authorised=True)
        return run_engagement(d.target, scope_path=plan.scope_path,
                              yes_authorised=True, audit_path=d.audit,
                              vault_path=d.vault, container=args.container,
                              model=d.model, provider=d.provider)
    return _dispatch


def run_hunt(args, *, prompt=input, runner=None, dispatch=None, resolve_key=None) -> int:
    resolve_key = resolve_key or keys_mod.resolve_key
    runner = runner or DockerCageRunner(container=args.container)
    dispatch = dispatch or _default_dispatch(args)

    mode = (args.mode or _ask(prompt, "  Mode — web or vpn? ")).lower()
    if mode not in ("web", "vpn"):
        print("  unknown mode — choose web or vpn."); return 1

    key, _res = resolve_key(args.provider)
    if key is None:
        print("  no API key and none provided — aborting (set <PROVIDER>_API_KEY "
              "or use a local model)."); return 1

    if mode == "web":
        url = args.url or _ask(prompt, "  Target URL: ")
        context = args.context or _ask(prompt, "  One-line context (what to focus on): ")
        try:
            plan = envprep.plan_web(url, context, args.provider, args.model,
                                    args.scope, args.vault, args.audit)
        except ValueError as e:
            print(f"  cannot build web scope: {e}"); return 1
    else:
        ovpn = args.ovpn or _ask(prompt, "  Path to .ovpn: ")
        targets = [t for t in _ask(prompt, "  Target IP/CIDR(s), comma-separated: ").split(",") if t.strip()]
        try:
            plan = envprep.plan_vpn(ovpn, targets, args.provider, args.model,
                                    args.scope, args.vault, args.audit)
        except (ValueError, OSError) as e:
            print(f"  cannot build vpn scope: {e}"); return 1

    print("\n  SCOPE (to be frozen on approval):")
    print(f"    {plan.scope_summary}")
    print("  BRING-UP PLAN:")
    print(f"    recreate cage on {plan.scope_path} · resolver {plan.resolver}"
          + (f" · stage {plan.vpn_file}" if plan.vpn_file else ""))
    print(f"    then verify: {', '.join(plan.verify_steps)}")
    print(f"  DISPATCH: {plan.dispatch.kind} -> {plan.dispatch.target}")

    if _ask(prompt, "\n  Approve bring-up and start the run? [y/N] ").lower() not in ("y", "yes"):
        print("  aborted — nothing recreated."); return 1

    envprep.freeze_scope(plan.scope_path, plan.scope_draft, approver="operator")

    ex = envprep.execute(plan, runner)
    if not ex.ok:
        bad = next((s.name for s in ex.steps if not s.ok), "?")
        print(f"  bring-up failed at: {bad} — not dispatching."); return 1

    vf = envprep.verify(plan, runner)
    if not vf.ok:
        bad = next((s.name for s in vf.steps if not s.ok), "?")
        print(f"  verification failed at: {bad} — not dispatching."); return 1

    return dispatch(plan)
```

Then wire the CLI (keep the old `_cmd_hunt` body replaced with a thin delegate):

```python
# brukal/cli.py  — replace the body of _cmd_hunt (currently @127)
def _cmd_hunt(args) -> int:
    from brukal.hunt_wizard import run_hunt
    return run_hunt(args)
```

And extend the `hunt` parser (currently @617) with the new optional args (leave all existing ones — `--provider/--model/--scope/--audit/--vault/--container/--fake/--yes/--tui/--base-url/--log` — untouched):

```python
    ph.add_argument("--mode", choices=["web", "vpn"], default=None,
                    help="engagement mode; prompted if omitted")
    ph.add_argument("--url", default=None, help="web mode: target URL")
    ph.add_argument("--ovpn", default=None, help="vpn mode: path to .ovpn")
    ph.add_argument("--context", default=None, help="web mode: one-line planner brief")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_hunt_wizard.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full suite + pyflakes (no regressions)**

Run: `python -m pytest -q && python -m pyflakes brukal/cage.py brukal/keys.py brukal/envprep.py brukal/hunt_wizard.py brukal/cli.py`
Expected: full suite green (prior count + the new tests); pyflakes clean on the listed files.

- [ ] **Step 6: Commit**

```bash
git add brukal/hunt_wizard.py brukal/cli.py tests/test_hunt_wizard.py
git commit -m "feat(hunt): guided env-adaptive wizard (web/vpn) over envprep+cage+keys

<attribution>"
```

---

## Notes for the executor

- **Dispatch kwargs may need adjusting to the real signatures** of `assist_cli.run_auto` / `run_engagement` (read them before Task 6 Step 3). The tests inject `dispatch`, so a signature mismatch surfaces only in the thin `_default_dispatch`; verify its kwargs against the actual functions and fix names there — do not change the tested wizard flow.
- **Do not** touch `auto`/`solve`/`scope`/`run` commands or their tests.
- **Live validation is NOT part of this plan** — it is human-gated (per-session authorization + a real cage with the egress-proxy/CDP/VPN compose wiring, which this branch's `main` base may predate). Reconcile the base before any live run.
- If `run_engagement`/`run_auto` are not importable without side effects at module load, keep the import **inside** `_default_dispatch` (as written) so tests that inject `dispatch` never import them.
