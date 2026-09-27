# tests/test_scope_rules_enforcement.py
import json, tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brukal.scope import load_scope

def _scope(d):
    p = Path(tempfile.mkdtemp()) / "s.json"
    base = {"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
            "allowlisted_tools": "all"}
    base.update(d)
    p.write_text(json.dumps(base))
    return load_scope(p)

def test_new_fields_parse_and_default_empty():
    s = _scope({})
    assert s.exclusions == frozenset()
    assert s.allowed_classes == frozenset()
    assert s.forbidden_classes == frozenset()
    assert s.envelope == frozenset()

def test_exclusions_parse_host_and_path_forms():
    s = _scope({"exclusions": ["info.coindcx.com",
                               {"host": "coindcx.com", "path_prefix": "/blog"}]})
    assert "info.coindcx.com" in s.exclusions
    assert ("coindcx.com", "/blog") in s.exclusions

def test_forbidden_and_envelope_parse():
    s = _scope({"forbidden_classes": ["dos"], "envelope": {"read_only": True,
                                                           "no_high_traffic": False}})
    assert "dos" in s.forbidden_classes
    assert "read_only" in s.envelope and "no_high_traffic" not in s.envelope

def test_fingerprint_includes_new_fields():
    a = _scope({})
    b = _scope({"exclusions": ["info.coindcx.com"]})
    assert a.fingerprint() != b.fingerprint()

def test_with_host_preserves_new_fields():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all", "authorized_hosts": ["*.coindcx.com"],
                             "exclusions": ["info.coindcx.com"],
                             "allowed_classes": ["SQLi"], "forbidden_classes": ["DoS"],
                             "envelope": {"read_only": True}}))
    s = load_scope(p).with_host("extra.coindcx.com")
    assert "extra.coindcx.com" in s.authorized_hosts
    assert "info.coindcx.com" in s.exclusions          # not dropped
    assert "sqli" in s.allowed_classes
    assert "dos" in s.forbidden_classes
    assert "read_only" in s.envelope

def test_string_valued_list_field_is_coerced_not_char_iterated():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all",
                             "forbidden_classes": "dos", "exclusions": "info.coindcx.com"}))
    s = load_scope(p)
    assert s.forbidden_classes == frozenset({"dos"})          # not {'d','o','s'}
    assert s.exclusions == frozenset({"info.coindcx.com"})     # not single chars

def test_wrongly_typed_field_is_rejected_not_silently_dropped():
    import json, tempfile, pytest
    from pathlib import Path
    from brukal.scope import load_scope
    for bad in ({"forbidden_classes": {"dos": True}},      # dict where str/list expected
                {"exclusions": 5},
                {"envelope": ["read_only"]}):              # list where dict expected
        p = Path(tempfile.mkdtemp()) / "s.json"
        p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                                 "allowlisted_tools": "all", **bad}))
        with pytest.raises((ValueError, TypeError)):
            load_scope(p)

def _scope_hosts(hosts, exclusions):
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all", "authorized_hosts": hosts,
                             "exclusions": exclusions}))
    return load_scope(p)

def test_wildcard_in_scope_but_exclusion_wins():
    s = _scope_hosts(["*.coindcx.com"], ["info.coindcx.com"])
    assert s.in_scope("api.coindcx.com") is True
    assert s.in_scope("info.coindcx.com") is False          # exclusion beats wildcard

def test_host_normalization_matches_exclusion():
    s = _scope_hosts(["*.coindcx.com"], ["info.coindcx.com"])
    assert s.in_scope("Info.CoinDCX.com.") is False         # case + trailing dot
    assert s.in_scope("info.coindcx.com:443") is False      # host:port

def test_path_exclusion_prefix_boundary():
    s = _scope_hosts(["coindcx.com"], [{"host": "coindcx.com", "path_prefix": "/blog"}])
    assert s.in_scope("coindcx.com", "/api") is True
    assert s.in_scope("coindcx.com", "/blog") is False
    assert s.in_scope("coindcx.com", "/blog/post") is False
    assert s.in_scope("coindcx.com", "/blogger") is True    # boundary, not prefix substring
    assert s.in_scope("coindcx.com", "/blog?x=1") is False  # query stripped before match

def test_wildcard_exclusion_pattern():
    s = _scope_hosts(["*.coindcx.com"], ["*.wordpress.coindcx.com"])
    assert s.in_scope("cms.wordpress.coindcx.com") is False
    assert s.in_scope("api.coindcx.com") is True

def test_default_deny_unknown_host():
    s = _scope_hosts(["*.coindcx.com"], [])
    assert s.in_scope("evil.com") is False
    assert s.in_scope("") is False
