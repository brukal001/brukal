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
        argv = ["docker", "exec", self.container, "grep", "-qF", expect_substr, "/scope.json"]
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
