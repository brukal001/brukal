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
