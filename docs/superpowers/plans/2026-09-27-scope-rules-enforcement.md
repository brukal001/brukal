# SP-A: Rich Scope Schema + Deterministic Enforcement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Brukal's frozen scope so a real bug-bounty program's shape — path-level out-of-scope exclusions that override in-scope wildcards, allowed/forbidden bug classes, and testing-policy behavior — is enforced deterministically, default-deny, with no LLM in the decision path.

**Architecture:** New immutable `Scope` fields (`exclusions`, `allowed_classes`, `forbidden_classes`, `envelope`) parsed by `load_scope`. Host+path scope is decided by a new `Scope.in_scope(host, path)` consulted at the web plane's single door (`web.check_web`). A new focused module `brukal/bugclass.py` holds a canonical bug-class taxonomy, a prover→class registry, an `active_classes(scope)` computation (allowed − forbidden, fail-closed), and a `@gated_by_class` decorator applied to every `confirm_*` prover so a disallowed class is never *tested*. Behavioral envelope flags wire to existing knobs.

**Tech Stack:** Python 3.12, dataclasses (frozen), pytest, pydantic (already present). Test interpreter: `/home/brute/brukal-venv/bin/python`.

**Spec:** `docs/superpowers/specs/2026-09-27-scope-rules-enforcement-design.md`

## Global Constraints

- **No LLM anywhere in SP-A.** Enforcement is deterministic (string/CIDR/path/set membership) over the frozen `Scope`. (Invariant 1)
- **Fail-closed.** Empty new fields → today's behavior; ambiguous/unparseable entry authorizes nothing; an exclusion always beats an in-scope wildcard. (Invariant 2)
- **Default-DENY (allow-list).** In scope iff asset-match ∧ ¬excluded ∧ (prover-side) class allowed ∧ ¬forbidden.
- **Do not touch** `executor.py`, `audit.py`, `kali.py`, or the cage handoff. (Invariants 4, 5)
- **Backward compatibility is a gate:** the full existing suite (`/home/brute/brukal-venv/bin/python -m pytest`) must stay green after every task; lab scopes (crapi/dvwa) with no new fields behave byte-identically.
- Run tests with `/home/brute/brukal-venv/bin/python -m pytest` from the repo root.
- `allowed_classes` accepts **human vuln names** (e.g. `sqli`, `xss`, `idor`), normalized deterministically to canonical bug classes at load; **unknown names authorize nothing** (never invent a class). (Decision 1)
- Path model = **exclusions only** for SP-A; positive `allowed_paths` is deferred. (Decision 2)
- `no_automated_scanners` = **narrow** the sweep to targeted checks, not disable Brukal. (Decision 3)

## Review Focus

- **Host normalization in exclusions/`in_scope`:** uppercase, trailing dot (`Info.CoinDCX.com.`), and `host:port` must match the same exclusion as the bare lowercase host. → test in Task 2.
- **Path prefix boundary:** `/blog` must exclude `/blog` and `/blog/x` but NOT `/blogger`; a query string (`/blog?x=1`) must still match. → test in Task 2.
- **Wildcard exclusion patterns:** an exclusion like `*.wordpress.coindcx.com` (not just an exact host) must match subdomains. → test in Task 2.
- **`allowed_classes` name robustness:** mixed case / spaces / hyphens (`SQL Injection`, `open-redirect`) must normalize; an unknown name (`telepathy`) must drop, not crash, and must not silently widen. → test in Task 4.
- **A prover emitting an unregistered comparator/class:** while an allowlist is active, an unmapped `confirm_*` must be skipped (fail-closed), and a completeness test must fail if any `confirm_*` is unregistered. → test in Task 5.

---

## File Structure

- `brukal/scope.py` — add fields, `in_scope`, `_excluded`, `load_scope` parsing, `fingerprint` update. (modify)
- `brukal/web.py` — `check_web` consults `(host, path)` via `scope.in_scope`. (modify)
- `brukal/bugclass.py` — canonical bug-class taxonomy, prover→class registry, `active_classes`, `@gated_by_class`. (create)
- `brukal/assist_confirm.py` — decorate every `confirm_*`; wire envelope (narrow sweep / read-only). (modify)
- `tests/test_scope_rules_enforcement.py` — all SP-A tests. (create)

---

### Task 1: Scope schema fields + parsing + fingerprint

**Files:**
- Modify: `brukal/scope.py` (the `Scope` dataclass, `load_scope`, `fingerprint`)
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Produces: `Scope.exclusions: frozenset` (each item a `str` host-pattern OR a `tuple[str, str]` `(host, path_prefix)`), `Scope.allowed_classes: frozenset[str]` (normalized canonical classes), `Scope.forbidden_classes: frozenset[str]` (normalized), `Scope.envelope: frozenset[str]` (flag names that are true). `load_scope` reads keys `exclusions`, `allowed_classes`, `forbidden_classes`, `envelope` (all optional). Normalization of class names uses `bugclass.normalize_class` (Task 4) — until Task 4 exists, Task 1 stores the raw lowercased strings and Task 4 rewires `load_scope` to normalize; see Step 3 note.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -v`
Expected: FAIL (`Scope` has no `exclusions` attribute / load_scope ignores the keys).

- [ ] **Step 3: Implement the schema + parsing**

In `brukal/scope.py`, add fields to the frozen `Scope` dataclass after `comparators`:

```python
    # Out-of-scope patterns that OVERRIDE an in-scope wildcard. Each entry is either a
    # host pattern (exact or "*.domain") or a (host, path_prefix) tuple for a path-level
    # exclusion (e.g. coindcx.com/blog). Deterministic membership; an exclusion always
    # wins over an in-scope match (fail-closed).
    exclusions: frozenset = frozenset()
    # Allowed / forbidden BUG CLASSES (canonical names, normalized at load). allowed is an
    # allowlist over provers (empty => all); forbidden is a hard-off denylist that wins.
    allowed_classes: frozenset = frozenset()
    forbidden_classes: frozenset = frozenset()
    # Testing-policy behavior flags that are TRUE for this program (e.g. read_only,
    # no_automated_scanners, no_high_traffic, pii_redaction).
    envelope: frozenset = frozenset()
```

In `load_scope`, before the `return Scope(...)`, parse the new keys:

```python
    excl = set()
    for e in data.get("exclusions", []) or []:
        if isinstance(e, str) and e.strip():
            excl.add(e.strip().lower())
        elif isinstance(e, dict) and str(e.get("host", "")).strip():
            excl.add((str(e["host"]).strip().lower(),
                      str(e.get("path_prefix", "/")).strip() or "/"))
    # class names are lowercased here; Task 4 rewires this to bugclass.normalize_class.
    allowed = frozenset(str(c).strip().lower() for c in data.get("allowed_classes", []) if str(c).strip())
    forbidden = frozenset(str(c).strip().lower() for c in data.get("forbidden_classes", []) if str(c).strip())
    env = frozenset(k for k, v in (data.get("envelope", {}) or {}).items() if v is True)
```

Add to the `Scope(...)` constructor call: `exclusions=frozenset(excl), allowed_classes=allowed, forbidden_classes=forbidden, envelope=env,`.

In `fingerprint`, add to the canon dict: `"exclusions": sorted(str(x) for x in self.exclusions), "allowed_classes": sorted(self.allowed_classes), "forbidden_classes": sorted(self.forbidden_classes), "envelope": sorted(self.envelope),`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Run the full suite (backward compat)**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS (no regressions; existing scopes ignore the new optional keys).

- [ ] **Step 6: Commit**

```bash
git add brukal/scope.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: add exclusions/allowed/forbidden/envelope scope fields + parsing"
```

---

### Task 2: `Scope.in_scope(host, path)` + `_excluded` (host + path, wildcard override)

**Files:**
- Modify: `brukal/scope.py`
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Consumes: `Scope.contains_host`, `Scope.contains_ip` (existing), `Scope.exclusions` (Task 1).
- Produces: `Scope.in_scope(host: str, path: str = "") -> bool`; `Scope._excluded(host: str, path: str) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k in_scope -v`
Expected: FAIL (`Scope` has no `in_scope`).

- [ ] **Step 3: Implement `in_scope` + `_excluded`**

In `brukal/scope.py`, add methods to `Scope`:

```python
    @staticmethod
    def _norm_host(host: str) -> str:
        h = (host or "").strip().lower().rstrip(".")
        if h.count(":") == 1 and not h.replace(":", "").isalpha():
            h = h.split(":", 1)[0]
        return h

    @staticmethod
    def _norm_path(path: str) -> str:
        p = (path or "/").split("?", 1)[0].split("#", 1)[0]
        if not p.startswith("/"):
            p = "/" + p
        return p

    def _host_matches(self, pattern: str, host: str) -> bool:
        if pattern == host:
            return True
        if pattern.startswith("*.") and host.endswith("." + pattern[2:]):
            return True
        return False

    def _excluded(self, host: str, path: str) -> bool:
        """True if (host, path) matches any exclusion. An exclusion always wins over an
        in-scope match (fail-closed). Path exclusions match on a /-boundary prefix."""
        h, p = self._norm_host(host), self._norm_path(path)
        for e in self.exclusions:
            if isinstance(e, tuple):
                eh, ep = e
                ep = self._norm_path(ep)
                if self._host_matches(eh, h) and (p == ep or p.startswith(ep.rstrip("/") + "/")):
                    return True
            else:
                if self._host_matches(e, h):
                    return True
        return False

    def in_scope(self, host: str, path: str = "") -> bool:
        """Deterministic default-DENY host+path scope: authorized asset AND not excluded.
        No DNS. Fail-closed on empty/unparseable."""
        h = self._norm_host(host)
        if not h:
            return False
        authorized = self.contains_host(h) or self.contains_ip(h)
        if not authorized:
            return False
        return not self._excluded(h, path)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k in_scope -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Full suite**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add brukal/scope.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: Scope.in_scope(host,path) with path-aware, wildcard-overriding exclusions"
```

---

### Task 3: `check_web` enforces path + exclusions at the web door

**Files:**
- Modify: `brukal/web.py` (`check_web`, around line 100)
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Consumes: `Scope.in_scope` (Task 2); `WebAction` (has `.url`, `.kind`).
- Produces: no new symbol — `check_web` now DENIES a web action whose URL host/path is out of scope by `in_scope`, with `layer="hard:scope"`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k check_web -v`
Expected: FAIL (`/blog` currently ALLOWs — host-level only, no path/exclusion check).

- [ ] **Step 3: Implement the path+exclusion check in `check_web`**

In `brukal/web.py`, inside `check_web`, find the existing host-scope check (the block that extracts the URL host and calls `scope.contains_host`). Immediately after the host is confirmed authorized, add the exclusion/path gate. Concretely, locate where `check_web` resolves the action's URL host (search for `contains_host` in `check_web`) and replace the bare host check with an `in_scope(host, path)` check:

```python
    from urllib.parse import urlsplit
    parts = urlsplit(getattr(action, "url", "") or "")
    host = parts.hostname or ""
    path = parts.path or "/"
    if not scope.in_scope(host, path):
        return deny(f"target out of scope: {host}{path}", layer="hard:scope")
```

Keep every other existing check in `check_web` (scheme http/https, unknown-action, capability) unchanged. If `check_web` already had a `contains_host`-only check, this REPLACES that one line's decision with the path-aware `in_scope` (which still enforces the host — `in_scope` calls `contains_host`/`contains_ip` internally), so host-level behavior is preserved and path/exclusion is added.

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k check_web -v`
Expected: PASS.

- [ ] **Step 5: Full suite (this touches the web door — watch for regressions)**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS. If any existing web test that used a bare in-scope host now fails, confirm it passes a path that is not excluded (it should, since no lab scope defines exclusions and `in_scope` with empty exclusions == the old host check). Fix only by ensuring `in_scope` returns identical results to the old `contains_host` path when `exclusions` is empty.

- [ ] **Step 6: Commit**

```bash
git add brukal/web.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: web door enforces path + exclusions via Scope.in_scope"
```

---

### Task 4: Bug-class taxonomy, prover→class registry, `active_classes`, normalization

**Files:**
- Create: `brukal/bugclass.py`
- Modify: `brukal/scope.py` (rewire `load_scope` class parsing to `bugclass.normalize_class`)
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Produces:
  - `bugclass.CANONICAL: frozenset[str]` — the canonical class names.
  - `bugclass.normalize_class(name: str) -> str | None` — human name → canonical class, or `None` if unknown (fail-closed).
  - `bugclass.PROVER_CLASSES: dict[str, frozenset[str]]` — `confirm_*` method name → the canonical bug class(es) it tests.
  - `bugclass.active_classes(scope) -> frozenset[str] | None` — allowed classes minus forbidden; `None` sentinel means "no restriction" (empty allowlist).
  - `bugclass.prover_enabled(scope, method_name: str) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
def test_normalize_human_class_names():
    from brukal import bugclass as bc
    assert bc.normalize_class("SQL Injection") == "sqli"
    assert bc.normalize_class("open-redirect") == "open_redirect"
    assert bc.normalize_class("IDOR") == "idor"
    assert bc.normalize_class("telepathy") is None          # unknown -> None (fail-closed)

def test_active_classes_allowed_minus_forbidden():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    from brukal import bugclass as bc
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all",
                             "allowed_classes": ["SQLi", "XSS", "DoS"],
                             "forbidden_classes": ["DoS"]}))
    s = load_scope(p)
    act = bc.active_classes(s)
    assert "sqli" in act and "xss" in act and "dos" not in act   # forbidden wins

def test_active_classes_none_when_unrestricted():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    from brukal import bugclass as bc
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all"}))
    assert bc.active_classes(load_scope(p)) is None            # empty allowlist -> all active

def test_prover_enabled_respects_allowlist():
    import json, tempfile
    from pathlib import Path
    from brukal.scope import load_scope
    from brukal import bugclass as bc
    p = Path(tempfile.mkdtemp()) / "s.json"
    p.write_text(json.dumps({"engagement": "t", "authorized_cidrs": ["10.0.0.1/32"],
                             "allowlisted_tools": "all", "allowed_classes": ["NoSQLi"]}))
    s = load_scope(p)
    assert bc.prover_enabled(s, "confirm_nosqli") is True
    assert bc.prover_enabled(s, "confirm_sqli") is False       # sqli not allowed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k "normalize or active_classes or prover_enabled" -v`
Expected: FAIL (`brukal.bugclass` does not exist).

- [ ] **Step 3: Implement `brukal/bugclass.py`**

```python
"""bugclass.py — canonical bug-class taxonomy that BOTH the human scope vocabulary and
the deterministic provers map into, so a program's allowed/forbidden classes gate which
confirm_* provers run. Deterministic; no LLM. The model's differential vocabulary
(_COMPARATORS in hypothesis.py) is a SEPARATE axis and is not touched here."""
from __future__ import annotations

CANONICAL = frozenset({
    "sqli", "nosqli", "xss", "rce", "cmdi", "idor", "ssrf", "cors", "csrf",
    "open_redirect", "auth_bypass", "business_logic", "lfi", "rfi", "xxe", "ssti",
    "mass_assignment", "exposed_secrets", "unauth_access", "dos", "clickjacking",
})

# Human name (normalized: lowercased, spaces/hyphens -> underscore) -> canonical class.
_ALIASES = {
    "sql_injection": "sqli", "sqli": "sqli",
    "nosql_injection": "nosqli", "nosqli": "nosqli",
    "cross_site_scripting": "xss", "xss": "xss",
    "remote_code_execution": "rce", "rce": "rce",
    "os_command_injection": "cmdi", "command_injection": "cmdi", "cmdi": "cmdi",
    "insecure_direct_object_reference": "idor", "idor": "idor",
    "server_side_request_forgery": "ssrf", "ssrf": "ssrf", "xspa": "ssrf",
    "cross_origin_resource_sharing": "cors", "cors": "cors",
    "cross_site_request_forgery": "csrf", "csrf": "csrf",
    "open_redirect": "open_redirect",
    "authentication_bypass": "auth_bypass", "auth_bypass": "auth_bypass",
    "broken_authentication": "auth_bypass", "privilege_escalation": "auth_bypass",
    "business_logic": "business_logic", "business_logic_errors": "business_logic",
    "local_file_inclusion": "lfi", "lfi": "lfi", "file_inclusion": "lfi",
    "remote_file_inclusion": "rfi", "rfi": "rfi",
    "xxe": "xxe", "xml_external_entity": "xxe",
    "ssti": "ssti", "template_injection": "ssti",
    "mass_assignment": "mass_assignment",
    "exposed_secrets": "exposed_secrets", "exposed_credentials": "exposed_secrets",
    "sensitive_information": "exposed_secrets",
    "unauthenticated_access": "unauth_access", "unauth_access": "unauth_access",
    "denial_of_service": "dos", "dos": "dos",
    "clickjacking": "clickjacking",
}

def normalize_class(name: str) -> str | None:
    """Human vuln name -> canonical class, or None if unrecognized (fail-closed: an
    unknown name authorizes NOTHING and never invents a class)."""
    key = "_".join((name or "").strip().lower().replace("-", " ").split())
    return _ALIASES.get(key)

# confirm_* method name -> the canonical class(es) it TESTS. Source of "running this
# prover tests these classes". Keep in sync with _ConfirmMixin; the completeness test
# (Task 5) fails if a confirm_* method is missing here.
PROVER_CLASSES: dict[str, frozenset[str]] = {
    "confirm_sqli": frozenset({"sqli"}),
    "confirm_sqli_error": frozenset({"sqli"}),
    "confirm_sqli_status": frozenset({"sqli"}),
    "confirm_nosqli": frozenset({"nosqli"}),
    "confirm_nosqli_sinks": frozenset({"nosqli", "sqli"}),
    "confirm_xss": frozenset({"xss"}),
    "confirm_cmdi": frozenset({"cmdi"}),
    "confirm_blind_rce": frozenset({"cmdi", "rce"}),
    "confirm_lfi": frozenset({"lfi"}),
    "confirm_ssti": frozenset({"ssti", "rce"}),
    "confirm_open_redirect": frozenset({"open_redirect"}),
    "confirm_ssrf": frozenset({"ssrf"}),
    "confirm_blind_ssrf": frozenset({"ssrf"}),
    "confirm_ssrf_sinks": frozenset({"ssrf"}),
    "confirm_idor": frozenset({"idor"}),
    "confirm_bola": frozenset({"idor"}),
    "confirm_bola_from_collection": frozenset({"idor"}),
    "confirm_mass_assignment": frozenset({"mass_assignment"}),
    "confirm_object_mass_assignment": frozenset({"mass_assignment"}),
    "confirm_object_mass_assignment_sinks": frozenset({"mass_assignment"}),
    "confirm_cors": frozenset({"cors"}),
    "confirm_data_exposure": frozenset({"exposed_secrets", "unauth_access"}),
    "confirm_unauth_access": frozenset({"unauth_access"}),
    "confirm_jwt_forgery": frozenset({"auth_bypass"}),
    "confirm_deserialization_rce": frozenset({"rce"}),
    "confirm_prompt_injection": frozenset({"business_logic"}),
}

def active_classes(scope):
    """Allowed classes minus forbidden, or None when unrestricted (empty allowlist)."""
    allowed = frozenset(getattr(scope, "allowed_classes", None) or ())
    forbidden = frozenset(getattr(scope, "forbidden_classes", None) or ())
    if not allowed and not forbidden:
        return None
    base = allowed if allowed else CANONICAL
    return frozenset(base) - forbidden

def prover_enabled(scope, method_name: str) -> bool:
    """True if this confirm_* prover may run under the scope's class policy. Empty policy
    => True. A forbidden-only policy still applies. An UNMAPPED method under an active
    policy => False (fail-closed: never probe a class we can't classify)."""
    active = active_classes(scope)
    if active is None:
        return True
    classes = PROVER_CLASSES.get(method_name)
    if not classes:
        return False
    return bool(classes & active)
```

Then rewire `brukal/scope.py` `load_scope` (from Task 1) to normalize class names through `bugclass`:

```python
    from . import bugclass as _bc
    def _norm_classes(key):
        out = set()
        for c in data.get(key, []) or []:
            n = _bc.normalize_class(str(c))
            if n:                       # unknown names drop (fail-closed)
                out.add(n)
        return frozenset(out)
    allowed = _norm_classes("allowed_classes")
    forbidden = _norm_classes("forbidden_classes")
```

(Replace the raw lowercasing from Task 1 Step 3 with these two lines.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k "normalize or active_classes or prover_enabled" -v`
Expected: PASS (4 tests). Note `test_forbidden_and_envelope_parse` from Task 1 still passes because `dos` normalizes to `dos`.

- [ ] **Step 5: Full suite**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add brukal/bugclass.py brukal/scope.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: canonical bug-class taxonomy + prover->class registry + active_classes"
```

---

### Task 5: `@gated_by_class` decorator, apply to every `confirm_*`, completeness test

**Files:**
- Modify: `brukal/bugclass.py` (add the decorator), `brukal/assist_confirm.py` (decorate methods; expose `self.scope`)
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Consumes: `bugclass.prover_enabled` (Task 4).
- Produces: `bugclass.gated_by_class(method)` decorator; `AssistSession.scope` property returning the frozen `Scope` (from `self.executor` gate or `self.browser._scope`); every `confirm_*` in `_ConfirmMixin` is decorated.

- [ ] **Step 1: Write the failing test**

```python
def test_completeness_every_confirm_method_is_registered():
    from brukal.assist_confirm import _ConfirmMixin
    from brukal import bugclass as bc
    methods = [n for n in dir(_ConfirmMixin)
               if n.startswith("confirm_") and callable(getattr(_ConfirmMixin, n))]
    missing = [m for m in methods if m not in bc.PROVER_CLASSES]
    assert not missing, f"unregistered confirm_* provers (bug-class gate blind spot): {missing}"

def test_forbidden_class_prover_issues_zero_probes():
    # A scope allowing only nosqli must NOT let the SQLi status prover send anything.
    import json, tempfile
    from pathlib import Path
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
    import json, tempfile
    from pathlib import Path
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
            import json as _j
            code = str((_j.loads(action.body or "{}")).get("q", ""))
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k "completeness or forbidden_class or allowed_class_prover" -v`
Expected: FAIL — completeness lists undecorated/unregistered methods; the zero-probes test fails because the prover currently runs regardless of class.

- [ ] **Step 3: Add the decorator and `AssistSession.scope`, then decorate**

In `brukal/bugclass.py`:

```python
import functools

def gated_by_class(method):
    """Skip a confirm_* prover (return False, send nothing) when the scope's class policy
    does not allow the class it tests. Fail-closed: an unmapped method under an active
    policy is skipped."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        scope = getattr(self, "scope", None)
        if scope is not None and not prover_enabled(scope, method.__name__):
            return False
        return method(self, *args, **kwargs)
    return wrapper
```

In `brukal/assist.py` (or wherever `AssistSession` is defined), add a `scope` property if one does not already exist:

```python
    @property
    def scope(self):
        """The frozen engagement Scope (from the executor's gate, else the browser)."""
        ex = getattr(self, "executor", None)
        gate = getattr(ex, "_gate", None) or getattr(ex, "gate", None)
        if gate is not None and getattr(gate, "scope", None) is not None:
            return gate.scope
        br = getattr(self, "browser", None)
        return getattr(br, "_scope", None)
```

(Verify the executor's gate attribute name first — `grep -n "self._gate\|self.gate\|Gate(" brukal/executor.py`. Use whichever exists; the property tries both.)

In `brukal/assist_confirm.py`, import the decorator at the top: `from .bugclass import gated_by_class`, and add `@gated_by_class` on the line above each `confirm_*` method in `_ConfirmMixin` that appears in `PROVER_CLASSES`. Do not decorate `_record_confirmed`, `_auto_confirm_reached`, or helper methods — only the `confirm_*` provers listed in `PROVER_CLASSES`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k "completeness or forbidden_class or allowed_class_prover" -v`
Expected: PASS. If completeness still lists a method, either add it to `PROVER_CLASSES` (with its class) or, if it is not a real vuln prover, rename it so it does not start with `confirm_` — do not leave it unregistered.

- [ ] **Step 5: Full suite (critical — every prover is now decorated)**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS. Existing prover tests use scopes with empty `allowed_classes`/`forbidden_classes`, so `active_classes` returns `None` and every prover runs exactly as before.

- [ ] **Step 6: Commit**

```bash
git add brukal/bugclass.py brukal/assist_confirm.py brukal/assist.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: gate every confirm_* prover by the scope's allowed bug classes"
```

---

### Task 6: Behavioral envelope wiring (`no_automated_scanners`, `read_only`, `no_high_traffic`)

**Files:**
- Modify: `brukal/assist_confirm.py` (`confirm_surface` honors `no_automated_scanners`); `brukal/assist.py` or the run wiring (`read_only` → `allow_intrusive=False`)
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Consumes: `Scope.envelope` (Task 1), `AssistSession.scope` (Task 5).
- Produces: `confirm_surface` returns early (0 confirmations, 0 probes) when `no_automated_scanners` is in `scope.envelope`; `read_only` forces `allow_intrusive=False`.

- [ ] **Step 1: Write the failing test**

```python
def test_no_automated_scanners_narrows_the_sweep_to_zero_probes():
    import json, tempfile
    from pathlib import Path
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
    import json, tempfile
    from pathlib import Path
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k "no_automated_scanners or read_only" -v`
Expected: FAIL (`confirm_surface` probes anyway; `apply_envelope` does not exist).

- [ ] **Step 3: Implement the envelope hooks**

In `brukal/assist_confirm.py`, at the very top of `confirm_surface` (after `if self.browser is None or self.surface is None: return 0`), add:

```python
        _scope = getattr(self, "scope", None)
        if _scope is not None and "no_automated_scanners" in getattr(_scope, "envelope", frozenset()):
            # Program forbids automated scanners: the breadth sweep is narrowed OFF; the
            # model's targeted, proof-carrying provers still run via their own dispatch.
            return 0
```

In `brukal/assist.py` (on `AssistSession`), add an explicit application method and call it where a run is set up (in the CLI run wiring, right after the session + scope are available):

```python
    def apply_envelope(self):
        """Apply the scope's testing-policy envelope to this session's behavior."""
        env = getattr(getattr(self, "scope", None), "envelope", frozenset()) or frozenset()
        if "read_only" in env:
            self.allow_intrusive = False
```

Wire the call: in `brukal/assist_cli.py` where the `AssistSession` is constructed for a run (search for `AssistSession(` in `assist_cli.py`), add `session.apply_envelope()` immediately after construction.

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k "no_automated_scanners or read_only" -v`
Expected: PASS.

- [ ] **Step 5: Full suite**

Run: `/home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add brukal/assist_confirm.py brukal/assist.py brukal/assist_cli.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: wire scope envelope (no_automated_scanners, read_only) to behavior"
```

---

### Task 7: `forbidden_classes` on the model side + an end-to-end scope fixture

**Files:**
- Modify: `brukal/hypothesis.py` (`active_comparators` also drops model comparators for forbidden classes, where a mapping exists)
- Test: `tests/test_scope_rules_enforcement.py`

**Interfaces:**
- Consumes: `Scope.forbidden_classes`.
- Produces: no new public symbol; `active_comparators` result excludes any model comparator whose class is forbidden. Since the model's `_COMPARATORS` are generic differential shapes (not vuln-class named), only the ones with a clear class map are dropped; the rest are unaffected. This is a defense-in-depth pass — the prover-side gate (Task 5) is the primary enforcement.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k coindcx -v`
Expected: PASS already if Tasks 1–5 are correct (this is the integration guard). If it fails, the failing assertion pinpoints the gap. The model-side change below is only needed if you also want `active_comparators` to reflect forbidden classes.

- [ ] **Step 3: (If desired) drop forbidden classes model-side**

In `brukal/hypothesis.py`, in `active_comparators(scope)`, after computing the requested set, subtract any model comparator whose class is forbidden. Only apply where a comparator has an unambiguous class (e.g. none of the 12 generic shapes map to `dos`, so in practice this is a no-op for DoS; keep the hook for future class-named model comparators):

```python
    forbidden = frozenset(getattr(scope, "forbidden_classes", None) or ())
    # (No generic differential shape maps to a forbidden class today; this hook keeps the
    #  model side honest if a class-named comparator is added later.)
```

- [ ] **Step 4: Run the integration test**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -k coindcx -v`
Expected: PASS.

- [ ] **Step 5: Full suite + the whole new file**

Run: `/home/brute/brukal-venv/bin/python -m pytest tests/test_scope_rules_enforcement.py -q && /home/brute/brukal-venv/bin/python -m pytest -q`
Expected: PASS both.

- [ ] **Step 6: Commit**

```bash
git add brukal/hypothesis.py tests/test_scope_rules_enforcement.py
git commit -m "SP-A: end-to-end scope-rules integration test + model-side forbidden hook"
```

---

## Self-Review

**1. Spec coverage:** schema fields (Task 1) · `in_scope` host+path exclusions (Task 2) · web-door enforcement (Task 3) · allowed/forbidden bug-class taxonomy + normalization (Task 4) · prover gating decorator + completeness (Task 5) · envelope wiring (Task 6) · default-deny + end-to-end (Task 7). The spec's "assets typed metadata" is stored (Task 1 `authorized_hosts` + optional `assets`); `assets[].value` CVSS mapping is explicitly deferred (spec §8). No spec requirement is left without a task.

**2. Placeholders:** none — every step has concrete code or an exact command. Two steps ask the implementer to `grep` for an existing attribute name (executor gate, `AssistSession(` call site) rather than guess it; both give the fallback behavior.

**3. Type consistency:** `active_classes` returns `frozenset | None` (None = unrestricted) and every caller (`prover_enabled`, decorator) handles None. `normalize_class` returns `str | None` and `load_scope` drops None. `in_scope(host, path="")` signature matches its `check_web` call.

**4. Review Focus:** host normalization (Task 2), path boundary + query strip (Task 2), wildcard exclusion (Task 2), class-name robustness/unknown-drop (Task 4), unregistered-prover fail-closed + completeness (Task 5) — each has an owning test above.

**5. Backward-compat gate** in every task's Step 5 (full suite green; empty new fields == today's behavior).
