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


def test_verify_vpn_runs_target_routable():
    ovpn = "remote lab.hackbox.io 1337\n"
    p = plan_vpn("my.ovpn", ["10.10.11.5"], "anthropic", "m",
                 "scope.hunt.json", "docker/vault", "runs/h.jsonl",
                 read_text=lambda _p: ovpn)
    r = FakeCageRunner()
    res = verify(p, r)
    assert res.ok is True
    assert [c[0] for c in r.calls] == ["tun_up", "scope_matches", "target_routable"]
