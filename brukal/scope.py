"""
scope.py — loads and validates the engagement policy (the authorised scope).

This module is intentionally dependency-free (Python standard library only).
The scope is the single source of truth for what Brukal is allowed to touch.
It is loaded ONCE at startup and treated as read-only thereafter: nothing in
the running system may widen it. That property is what lets us prove the
"100% scope interception" claim by construction rather than by hope.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Scope:
    """An immutable view of the engagement policy.

    frozen=True means once built, its fields cannot be reassigned — a small
    guard against accidental runtime mutation of the authorised set.
    """
    engagement: str
    authorized_networks: tuple  # tuple of ipaddress network objects
    allowlisted_tools: frozenset
    rate_limit_per_min: int
    # Explicitly authorised hostnames (e.g. a HTB vhost like "nexus.htb"). Set at
    # scope time by the operator — NEVER resolved from DNS at runtime, so the scope
    # check stays deterministic and untrickable (a hostile DNS answer can't widen
    # scope). A web target is in scope iff its host is here OR its IP is in a CIDR.
    authorized_hosts: frozenset = frozenset()
    # Authorization as a first-class artifact (Phase 5). `authorization` is the
    # operator's written assertion that this engagement is authorised (who signed off,
    # a ticket/SOW reference — free text; its PRESENCE is the assertion). `expires` is
    # an ISO date/datetime after which the scope is stale and Brukal refuses to run.
    # Both are recorded into the audit chain at run start (see authorization_record).
    authorization: str = ""
    expires: str = ""
    # TLS verification for this engagement. DEFAULT TRUE (invariant 2, fail-closed):
    # certificates are validated unless the operator disclosed otherwise here, in the
    # scope, exactly as `rate_limit_per_min` is a disclosed parameter of a measurement.
    #
    # Why the parameter exists at all: crAPI, and nearly every lab appliance and a great
    # many internal hosts, serve a self-signed certificate. The alternative designs are
    # both worse. Retrying unverified on failure would be the harness widening its own
    # policy at runtime in response to what the target did — the shape invariant 5 forbids.
    # Refusing every such target outright would put most real internal engagements out of
    # reach. So the operator decides, once, in writing, and the ledger carries it.
    #
    # A verification failure is ALSO information about the target and is recorded as a
    # bounded observation either way — see GovernedBrowser. The parameter governs whether
    # the engagement proceeds, never whether the observation is kept.
    tls_verify: bool = True
    # May this engagement perform STATE-CHANGING / destructive work when the operator
    # approves it? DEFAULT FALSE (invariant 2). This does not authorise anything by
    # itself: with it true, a destructive experiment ESCALATES to the human approver
    # instead of being dropped, and the human still decides. With it false the approver
    # is never consulted and the proposal is recorded as refused.
    #
    # It exists because the two paths disagreed. A destructive COMMAND has always
    # escalated to the operator; a destructive EXPERIMENT was silently skipped, so crAPI
    # challenge 3 (reset another user's password) was proposed by the model and dropped
    # by the code with nobody asked. Capability is not traded for tidiness: where Brukal
    # needs authorisation it asks for it, and the record shows who answered.
    destructive_allowed: bool = False
    # PER-PROGRAM comparator SELECTION (an allowlist, never a denylist). When non-empty,
    # only these comparators are offered to the model and accepted from it — a subset of
    # the closed set, intersected with it fail-closed (an unknown name is dropped, never
    # invented). Empty (the default) means ALL comparators are active. This tunes Brukal to
    # a program's rules — enable the aggressive checks a program invites, drop the ones it
    # excludes — WITHOUT widening beyond the trusted set or touching any severity bound.
    comparators: frozenset = frozenset()
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

    def has_domain_asset(self) -> bool:
        """True if any `authorized_hosts` entry is a domain/wildcard asset — i.e.
        something DNS resolves, whose IP can therefore be rotated or poisoned —
        rather than an IP literal. Used by `load_scope` to require `tls_verify`
        for exactly the scopes where an unverified connection could be silently
        MITM'd by a poisoned resolution; an IP-only lab scope has no such asset
        and is unaffected."""
        for h in self.authorized_hosts:
            candidate = h[2:] if h.startswith("*.") else h
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return True   # does not parse as an IP -> it's a hostname
        return False

    def is_authorized(self) -> bool:
        """True if the scope file itself asserts authorization (a non-empty statement)."""
        return bool((self.authorization or "").strip())

    def expiry_date(self) -> "datetime.date | None":
        """The parsed expiry date, or None if unset. A SET-but-unparseable expiry
        returns None and is treated as expired by is_expired (fail-closed)."""
        s = (self.expires or "").strip()
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s[:10])   # accepts date or ISO datetime
        except ValueError:
            return None

    def is_expired(self, today: "datetime.date | None" = None) -> bool:
        """True if `expires` is set and today is past it. An unset expiry never expires;
        a set-but-unparseable expiry is treated as expired (fail-closed — refuse rather
        than run on a scope whose validity window we can't read)."""
        if not (self.expires or "").strip():
            return False
        d = self.expiry_date()
        if d is None:
            return True
        return (today or datetime.date.today()) > d

    def fingerprint(self) -> str:
        """A short, stable content hash of the authorised set — so an audit entry can
        pin exactly which scope authorised a run, and a later scope swap is visible."""
        canon = json.dumps({
            "engagement": self.engagement,
            "networks": sorted(str(n) for n in self.authorized_networks),
            "hosts": sorted(self.authorized_hosts),
            "tools": sorted(self.allowlisted_tools),
            "rate": self.rate_limit_per_min,
            "tls_verify": self.tls_verify,
            "destructive_allowed": self.destructive_allowed,
            "authorization": self.authorization,
            "expires": self.expires,
            "exclusions": sorted(str(x) for x in self.exclusions),
            "allowed_classes": sorted(self.allowed_classes),
            "forbidden_classes": sorted(self.forbidden_classes),
            "envelope": sorted(self.envelope),
        }, sort_keys=True)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]

    def contains_ip(self, ip_text: str) -> bool:
        """True only if ip_text is a valid IP inside an authorised network.

        Accepts dotted IPv4, IPv6 literals, AND integer/0x-hex/0o-octal encodings
        of an IP (canonicalised first) so a decimal/hex-smuggled host cannot slip
        past by numeric form. Fail-closed: anything that does not parse as an IP, or
        that falls outside every authorised network, returns False (out of scope).
        """
        from .hostmatch import canonical_ip
        canon = canonical_ip((ip_text or "").strip())
        if canon is None:
            return False
        try:
            ip = ipaddress.ip_address(canon)
        except ValueError:
            return False
        return any(ip in net for net in self.authorized_networks)

    def contains_host(self, host: str) -> bool:
        """True if `host` is an explicitly authorised hostname (or a subdomain of an
        authorised `*.domain` wildcard), or an in-scope IP. Deterministic set/CIDR
        membership only — no DNS. Fail-closed on anything empty or unrecognised.

        A wildcard `*.nexus.htb` matches any subdomain (`git.nexus.htb`,
        `FUZZ.nexus.htb`) but NOT a sibling like `nexus.htb.evil.com` — the suffix
        must match on a label boundary. This is what lets vhost fuzzing work: the
        candidate hosts are `Host:` header values sent to an in-scope IP, and the
        actual network destination is still governed by the IP/CIDR check and the
        cage's nftables egress lock. A wildcard cannot authorise a different IP."""
        # One normalization path with in_scope: _norm_host lowercases, drops a trailing
        # FQDN dot, unwraps a bracketed IPv6 literal ([::1]:8443 -> ::1), and strips a
        # host:port. Before this, contains_host had only the host:port strip, so a direct
        # contains_host("[::1]:8443") denied an authorized IPv6 host (fail-closed, but
        # inconsistent with in_scope, which normalizes first). Idempotent, so in_scope
        # calling this on an already-normalized host is harmless.
        h = self._norm_host(host)
        if not h:
            return False
        if h in self.authorized_hosts:
            return True
        for a in self.authorized_hosts:
            if a.startswith("*.") and h.endswith("." + a[2:]):   # subdomain of *.domain
                return True
        return self.contains_ip(h)

    def with_host(self, host: str) -> "Scope":
        """Return a NEW scope with one hostname added. This is a scope-TIME
        authorisation (like `brukal target`), not a runtime widen — the running
        Scope object stays immutable; callers install the returned scope before
        the engagement, exactly as they would a fresh scope."""
        h = (host or "").strip().lower()
        return Scope(engagement=self.engagement,
                     authorized_networks=self.authorized_networks,
                     allowlisted_tools=self.allowlisted_tools,
                     rate_limit_per_min=self.rate_limit_per_min,
                     authorized_hosts=self.authorized_hosts | ({h} if h else set()),
                     authorization=self.authorization,
                     expires=self.expires,
                     tls_verify=self.tls_verify,
                     destructive_allowed=self.destructive_allowed,
                     comparators=self.comparators,
                     exclusions=self.exclusions,
                     allowed_classes=self.allowed_classes,
                     forbidden_classes=self.forbidden_classes,
                     envelope=self.envelope)

    def tool_allowed(self, tool: str) -> bool:
        """True if the tool passes the ALLOWLIST layer. `"*"` in the allowlist means
        'broad mode': every tool passes this hard check, and the SOFT risk layer
        decides — read-only enumeration ALLOWs, while attack/irreversible or
        unrecognised tools ESCALATE to a human (and widen-blast ones DENY). Scope is
        still absolute; broad mode only moves the tool decision from a fixed list to
        'safe runs, dangerous asks a human'."""
        return "*" in self.allowlisted_tools or tool in self.allowlisted_tools

    @property
    def broad_tools(self) -> bool:
        return "*" in self.allowlisted_tools

    @staticmethod
    def _norm_host(host: str) -> str:
        h = (host or "").strip().lower().rstrip(".")
        # Bracketed IPv6 literal, with or without a port: [::1] / [::1]:8443 /
        # [2001:db8::1]:443 -> the bare address (::1, 2001:db8::1). Without this a
        # port-bearing bracketed request never matches an IPv6 exclusion or authorized
        # host written in bare form, so contains_ip fails to parse it and it is denied
        # as unauthorized rather than judged on its actual scope membership.
        if h.startswith("["):
            end = h.find("]")
            if end == -1:
                return h            # no closing bracket: malformed -> denied downstream
            # Only an empty remainder or a numeric :port may follow the bracket. Any
            # other trailing text ([::1]evil.com, [::1]:, [::1]:80x) is a malformed
            # authority: reject it (fail-closed to "") rather than silently truncating
            # to the inside, which would judge the junk host on the bracketed IP's scope.
            rest = h[end + 1:]
            # A valid port is ASCII digits only. `str.isdigit()` alone also accepts
            # non-ASCII digits (e.g. "80²"), which would let a malformed port slip
            # through; `.isascii()` pins it to 0-9. No security consequence either way
            # (the port is discarded and the inner IP must still be an authorized-network
            # member), but this keeps the accept/reject rule exactly RFC-shaped.
            port = rest[1:]
            if rest and not (rest[0] == ":" and port.isascii() and port.isdigit()):
                return ""
            return h[1:end]
        # host:port for IPv4 / hostname -> strip the port. Exactly one colon and the
        # rest is not all-alpha (so a bare word like "localhost" is kept and a bare
        # IPv6 literal, which has 2+ colons, is left untouched).
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


def load_scope(path: str | Path) -> Scope:
    """Read scope.json from disk and build an immutable Scope.

    Raises on a malformed policy — we would rather refuse to start than run
    with a scope we cannot trust.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    nets = []
    for cidr in data["authorized_cidrs"]:
        # strict=False lets you write a host address like 10.10.10.5/24
        nets.append(ipaddress.ip_network(cidr, strict=False))

    # allowlisted_tools may be a list, or the string "all" / "*" for broad mode
    # (every tool passes the allowlist; the risk layer + human sign-off govern the
    # dangerous ones). A list may itself contain "*" to the same effect.
    raw_tools = data["allowlisted_tools"]
    if isinstance(raw_tools, str):
        tools = frozenset({"*"}) if raw_tools.strip().lower() in ("all", "*") \
            else frozenset({raw_tools})
    else:
        tools = frozenset(raw_tools)

    def _as_list(name, v):
        """Normalize a list-shaped scope field. A bare string is a single item (a
        plausible scope.json typo like "forbidden_classes": "dos" must NOT be
        char-iterated into {'d','o','s'} — a silent denylist no-op). Absent/None
        is empty. Anything else (dict, int, ...) is a malformed policy and we
        raise rather than silently drop it (fail-closed, per this function's
        documented contract: refuse to start rather than run on a scope we
        cannot trust)."""
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return v
        raise ValueError(f"scope field '{name}' must be a string or list")

    def _as_dict(name, v):
        """Normalize the envelope field. Absent/None is empty; anything that
        isn't an object (a list, a string, ...) is malformed and rejected
        rather than silently dropped."""
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        raise ValueError(f"scope field '{name}' must be an object")

    excl = set()
    for e in _as_list("exclusions", data.get("exclusions")):
        if isinstance(e, str) and e.strip():
            excl.add(e.strip().lower())
        elif isinstance(e, dict) and str(e.get("host", "")).strip():
            excl.add((str(e["host"]).strip().lower(),
                      str(e.get("path_prefix", "/")).strip() or "/"))
    # Class names are normalized through the canonical bug-class taxonomy: a human
    # vocabulary (e.g. "SQL Injection", "open-redirect") maps to a canonical class
    # (e.g. "sqli", "open_redirect"); an unrecognized name is DROPPED, never invented
    # (fail-closed — see brukal.bugclass.normalize_class).
    from . import bugclass as _bc

    def _norm_classes(key):
        out = set()
        for c in _as_list(key, data.get(key)):
            n = _bc.normalize_class(str(c))
            if n:  # unknown names drop (fail-closed)
                out.add(n)
        return frozenset(out)

    allowed = _norm_classes("allowed_classes")
    forbidden = _norm_classes("forbidden_classes")
    env = frozenset(k for k, v in _as_dict("envelope", data.get("envelope")).items() if v is True)

    # Only an explicit `true` opts in. Anything else — absent, misspelled, a string —
    # leaves it off, because an unparseable authorisation is not an authorisation.
    destructive_allowed = data.get("destructive_allowed", False) is True
    # read_only is a program policy that must win over an explicit destructive_allowed:true
    # (same principle as _effective_full_send: policy beats the flag). Enforced at freeze
    # time so the frozen Scope is self-consistent (spec §4.3: read_only implies
    # destructive_allowed=False AND write-provers gated — this covers the first half).
    if "read_only" in env:
        destructive_allowed = False

    scope = Scope(
        engagement=str(data["engagement"]),
        authorized_networks=tuple(nets),
        allowlisted_tools=tools,
        rate_limit_per_min=int(data.get("rate_limit_per_min", 30)),
        authorized_hosts=frozenset(h.strip().lower()
                                   for h in data.get("authorized_hosts", []) if h.strip()),
        authorization=str(data.get("authorization", "")).strip(),
        expires=str(data.get("expires", "")).strip(),
        # Only an explicit `false` disables verification. Anything else — absent,
        # misspelled, a string, null — verifies, because an unparseable policy is a
        # policy we refuse to act on (invariant 2).
        tls_verify=data.get("tls_verify", True) is not False,
        destructive_allowed=destructive_allowed,
        # PER-PROGRAM comparator selection. A list of comparator names; anything not a
        # non-empty string is ignored, and the intersection with the closed set happens at
        # use (see hypothesis.active_comparators), so a name that is not a real comparator
        # simply never activates. Absent/empty => all comparators active (the default).
        comparators=frozenset(
            c.strip() for c in data.get("comparators", []) or []
            if isinstance(c, str) and c.strip()),
        exclusions=frozenset(excl),
        allowed_classes=allowed,
        forbidden_classes=forbidden,
        envelope=env,
    )

    # TLS-mandatory-for-domain-scopes (SP-C slice 1, fail-closed): a domain/wildcard
    # asset is reached through the egress proxy by HOST NAME, and its IP can rotate
    # (a CDN) or be poisoned (DNS). Without certificate verification a poisoned
    # resolution is an undetectable MITM. An IP-only scope (a lab appliance reached
    # by its literal address — crAPI, DVWA) has no such asset: its IP IS the
    # authorisation, so there is nothing for TLS to additionally pin, and `tls_verify`
    # stays whatever the operator disclosed (see the field's own docstring above).
    if scope.has_domain_asset() and not scope.tls_verify:
        raise ValueError(
            "a domain-scoped engagement must verify TLS (tls_verify:true) so a "
            "poisoned-IP MITM is caught — set tls_verify:true or remove the "
            f"domain/wildcard host(s) from authorized_hosts: {sorted(scope.authorized_hosts)}")

    return scope


def authorization_record(scope: Scope, target: str) -> dict:
    """A JSON-serialisable summary of the authorisation that permitted THIS run,
    appended to the audit chain at run start (see engagement.enforce_authorization).

    It pins, by content fingerprint, exactly which scope authorised the engagement,
    whether the operator asserted written authorisation, and the expiry state — so
    the ledger records what a run was permitted under, and a later scope swap is
    visible as a fingerprint change. Recorded regardless of the ALLOW/refuse outcome
    so even a refused stale run leaves a receipt."""
    return {
        "engagement": scope.engagement,
        "target": target,
        "scope_fingerprint": scope.fingerprint(),
        "authorization": scope.authorization,
        "authorized": scope.is_authorized(),
        "expires": scope.expires,
        "expired": scope.is_expired(),
        # Disclosed with the authorisation, not buried in a note: a run that did not
        # validate certificates says so in the same entry that says what permitted it.
        "tls_verify": scope.tls_verify,
        "destructive_allowed": scope.destructive_allowed,
    }
