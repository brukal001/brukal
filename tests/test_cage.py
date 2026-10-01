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
