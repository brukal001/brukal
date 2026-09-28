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


def test_check_web_denies_excluded_path_and_subdomain():
    import json, tempfile
    from pathlib import Path
    from urllib.parse import urlsplit
    from brukal.scope import load_scope
    from brukal.web import check_web, WebAction
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all",
                             "authorized_hosts": ["*.coindcx.com", "coindcx.com"],
                             "exclusions": ["info.coindcx.com",
                                            {"host": "coindcx.com", "path_prefix": "/blog"}]}))
    scope = load_scope(p)
    ok = check_web(WebAction("get", url="https://api.coindcx.com/orders"), scope)
    blog = check_web(WebAction("get", url="https://coindcx.com/blog/post"), scope)
    sub = check_web(WebAction("get", url="https://info.coindcx.com/x"), scope)
    assert ok.verdict == "ALLOW"
    assert blog.verdict == "DENY" and "scope" in blog.layer
    assert sub.verdict == "DENY" and "scope" in sub.layer


# --- Task 4: bug-class taxonomy, prover->class registry, active_classes ---

def test_normalize_human_class_names():
    from brukal import bugclass as bc
    assert bc.normalize_class("SQL Injection") == "sqli"
    assert bc.normalize_class("open-redirect") == "open_redirect"
    assert bc.normalize_class("IDOR") == "idor"
    assert bc.normalize_class("telepathy") is None          # unknown -> None (fail-closed)


def test_active_classes_allowed_minus_forbidden():
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all",
                             "allowed_classes": ["SQLi", "XSS", "DoS"],
                             "forbidden_classes": ["DoS"]}))
    from brukal import bugclass as bc
    s = load_scope(p)
    act = bc.active_classes(s)
    assert "sqli" in act and "xss" in act and "dos" not in act   # forbidden wins


def test_active_classes_none_when_unrestricted():
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all"}))
    from brukal import bugclass as bc
    assert bc.active_classes(load_scope(p)) is None            # empty allowlist -> all active


def test_prover_enabled_respects_allowlist():
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all", "allowed_classes": ["NoSQLi"]}))
    from brukal import bugclass as bc
    s = load_scope(p)
    assert bc.prover_enabled(s, "confirm_nosqli") is True
    assert bc.prover_enabled(s, "confirm_sqli") is False       # sqli not allowed


def test_prover_enabled_always_sentinel_bypasses_allowlist():
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all", "allowed_classes": ["NoSQLi"]}))
    from brukal import bugclass as bc
    s = load_scope(p)
    assert bc.prover_enabled(s, "confirm_surface") is True
    assert bc.prover_enabled(s, "confirm_authentication") is True


def test_registry_covers_every_confirm_method():
    from brukal.assist_confirm import _ConfirmMixin
    from brukal import bugclass as bc
    methods = {n for n in dir(_ConfirmMixin)
               if n.startswith("confirm_") and callable(getattr(_ConfirmMixin, n))}
    assert methods == set(bc.PROVER_CLASSES), {
        "unregistered": sorted(methods - set(bc.PROVER_CLASSES)),
        "stale": sorted(set(bc.PROVER_CLASSES) - methods)}


# --- Task 5: @gated_by_class decorator applied to every confirm_* prover ---

def test_every_confirm_method_is_decorated():
    """No-blind-spot guarantee: every confirm_* on _ConfirmMixin must be wrapped by
    bugclass.gated_by_class (marked with __gated_by_class__), so a bug class a program
    forbids can never be actively probed."""
    from brukal.assist_confirm import _ConfirmMixin
    methods = [n for n in dir(_ConfirmMixin)
               if n.startswith("confirm_") and callable(getattr(_ConfirmMixin, n))]
    undecorated = [m for m in methods
                   if not getattr(getattr(_ConfirmMixin, m), "__gated_by_class__", False)]
    assert not undecorated, f"confirm_* provers missing @gated_by_class: {undecorated}"


def test_forbidden_class_prover_issues_zero_probes():
    # A scope allowing only nosqli must NOT let the SQLi status prover send anything.
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser, WebResult
    from brukal.assist import AssistSession
    from brukal.webmap import AttackSurface

    class _Spy:
        def __init__(self): self.calls = 0
        def run(self, action):
            self.calls += 1
            return WebResult(status=500, url=action.url, body="<h1>Server Error (500)</h1>")

    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.10.10.5/32"],
                             "allowlisted_tools": "all", "allowed_classes": ["NoSQLi"]}))
    scope = load_scope(p)
    root = Path(tempfile.mkdtemp()); audit = AuditLog(root / "a.jsonl")
    spy = _Spy()
    s = AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda s,*a,**k: "[]"})()),
                      browser=GovernedBrowser(scope, spy, audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed="http://10.10.10.5/")
    s._confirm_budget = 50
    out = s.confirm_sqli_status("http://10.10.10.5/x", "q", method="JSON")
    assert out is False
    assert spy.calls == 0, "a forbidden-class prover sent a probe"


def test_allowed_class_prover_still_runs():
    # Same setup but allow sqli -> the prover runs (issues probes).
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser, WebResult
    from brukal.assist import AssistSession
    from brukal.webmap import AttackSurface

    class _QB:
        def __init__(self): self.calls = 0
        def run(self, action):
            self.calls += 1
            code = str((json.loads(action.body or "{}")).get("q", ""))
            st = 500 if code.count("'") % 2 == 1 else 400
            return WebResult(status=st, url=action.url, body="x")
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.10.10.5/32"],
                             "allowlisted_tools": "all", "allowed_classes": ["SQLi"]}))
    scope = load_scope(p)
    root = Path(tempfile.mkdtemp()); audit = AuditLog(root / "a.jsonl")
    qb = _QB()
    s = AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda s,*a,**k: "[]"})()),
                      browser=GovernedBrowser(scope, qb, audit))
    s.allow_intrusive = True
    s.surface = AttackSurface(seed="http://10.10.10.5/")
    s._confirm_budget = 50
    s.confirm_sqli_status("http://10.10.10.5/x", "q", method="JSON")
    assert qb.calls > 0, "an allowed-class prover was blocked"


# --- Task 6: behavioral envelope wiring (no_automated_scanners, read_only) ---

def test_no_automated_scanners_narrows_the_sweep_to_zero_probes():
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser, WebResult
    from brukal.assist import AssistSession
    from brukal.webmap import AttackSurface

    class _Spy:
        def __init__(self): self.calls = 0
        def run(self, action):
            self.calls += 1
            return WebResult(status=200, url=action.url, body="ok")
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.10.10.5/32"],
                             "allowlisted_tools": "all",
                             "envelope": {"no_automated_scanners": True}}))
    scope = load_scope(p)
    root = Path(tempfile.mkdtemp()); audit = AuditLog(root / "a.jsonl")
    spy = _Spy()
    s = AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda s,*a,**k: "[]"})()),
                      browser=GovernedBrowser(scope, spy, audit))
    s.surface = AttackSurface(seed="http://10.10.10.5/")
    s.surface.confirmed_routes = ["/x"]
    n = s.confirm_surface()
    assert n == 0 and spy.calls == 0, "no_automated_scanners did not narrow the sweep"


def test_read_only_forces_non_intrusive():
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.assist import AssistSession
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.10.10.5/32"],
                             "allowlisted_tools": "all", "envelope": {"read_only": True}}))
    scope = load_scope(p)
    root = Path(tempfile.mkdtemp()); audit = AuditLog(root / "a.jsonl")
    s = AssistSession("10.10.10.5", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda s,*a,**k: "[]"})()),
                      browser=GovernedBrowser(scope, FakeKali(), audit))
    s.apply_envelope()             # explicit application hook (Step 3)
    assert s.allow_intrusive is False


def test_read_only_scope_overrides_full_send_flag():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    from brukal.assist_cli import _effective_full_send
    def scp(env):
        p = Path(tempfile.mkdtemp()) / "s.json"
        p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                                 "allowlisted_tools": "all", "envelope": env}))
        return load_scope(p)
    ro = scp({"read_only": True})
    open_ = scp({})
    assert _effective_full_send(True, ro) is False    # flag cannot unleash a read_only scope
    assert _effective_full_send(True, open_) is True   # normal scope honours the flag
    assert _effective_full_send(False, open_) is False
    assert _effective_full_send(True, None) is True    # None scope: no policy, honour flag


# --- Task 7: end-to-end integration guard, realistic (CoinDCX-like) scope ---

def test_end_to_end_coindcx_like_scope():
    # A realistic scope: wildcard + exclusions + allowed + forbidden classes + envelope.
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    from brukal.web import check_web, WebAction
    from brukal import bugclass as bc
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({
        "engagement": "coindcx-like", "authorized_cidrs": ["10.0.0.1/32"],
        "allowlisted_tools": "all",
        "authorized_hosts": ["*.coindcx.com", "coindcx.com", "api.coindcx.com"],
        "exclusions": ["info.coindcx.com", "otcdesk.coindcx.com", "careers.coindcx.com",
                       {"host": "coindcx.com", "path_prefix": "/blog"}],
        "allowed_classes": ["SQLi", "XSS", "RCE", "IDOR", "SSRF", "CSRF",
                            "Open Redirect", "Business Logic"],
        "forbidden_classes": ["DoS"],
        "envelope": {"no_automated_scanners": True, "read_only": True}}))
    s = load_scope(p)
    assert check_web(WebAction("get", url="https://api.coindcx.com/v1"), s).verdict == "ALLOW"
    assert check_web(WebAction("get", url="https://coindcx.com/blog"), s).verdict == "DENY"
    assert check_web(WebAction("get", url="https://info.coindcx.com/"), s).verdict == "DENY"
    act = bc.active_classes(s)
    assert "sqli" in act and "dos" not in act
    assert bc.prover_enabled(s, "confirm_sqli") is True
    assert "no_automated_scanners" in s.envelope


# --- spec §4.3 clause gap: read_only must force destructive_allowed=False ---

def test_read_only_envelope_forces_destructive_disallowed():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    p = Path(tempfile.mkdtemp()) / "s.json"
    # self-contradictory scope: read_only AND destructive_allowed:true
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all",
                             "envelope": {"read_only": True},
                             "destructive_allowed": True}))
    s = load_scope(p)
    assert s.destructive_allowed is False        # read_only policy wins over the flag
    # sanity: without read_only, destructive_allowed:true is honored
    p2 = Path(tempfile.mkdtemp()) / "s2.json"
    p2.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                              "allowlisted_tools": "all", "destructive_allowed": True}))
    assert load_scope(p2).destructive_allowed is True
