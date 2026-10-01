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
