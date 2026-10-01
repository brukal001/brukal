"""Environment bring-up: pure planning + drafting here; side effects live in
execute()/verify() (Task 5) and go only through an injected cage runner.
Never imports kali/executor/agents."""
from __future__ import annotations
import ipaddress
import json
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

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
