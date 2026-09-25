"""
assist_auth.py — the _AuthMixin for AssistSession. Methods extracted verbatim
from assist.py (no logic change); composed back onto AssistSession in assist.py.
"""
from __future__ import annotations

from . import redact
from contextlib import contextmanager
import json
import re
from .assist_util import (
    _COOKIE_INJECT,
    _HEADER_INJECT,
    _PLACEHOLDER_AUTH_ARG_RE,
    _tool_of,
)


class _AuthMixin:

    # -- doing / recording (persisted to the vault) ------------------------- #

    def _session_auth_for(self, command: str) -> str:
        """When authenticated, give a shell WEB tool the session so it can test pages
        BEHIND the login (sqlmap/curl/ffuf/... otherwise run unauthenticated). Carries
        whichever auth the login produced: a bearer/basic Authorization HEADER (token
        APIs) or a session COOKIE. Only when the injected value has NO shell metacharacter
        (a single cookie / a token — the common case), because the gate rejects ';'/'&'
        in a raw command (invariant 1, unchanged); anything richer uses WEB actions,
        which carry the session natively. The gate still re-reads and governs the result."""
        if not self.authenticated or self.browser is None or "http" not in command:
            return command
        tool = _tool_of(command)
        # Already carrying auth? (NB: not -u/--user — sqlmap's -u is the target URL.)
        # A command carrying a REDACTION PLACEHOLDER is NOT carrying auth: the model was
        # shown a masked token in its history and copied it back. Treating that as a
        # credential skips the injection below and runs the tool logged OUT — the shell
        # twin of the same defect on the web plane. Strip the masked header instead, so
        # the real session is injected in its place. See redact.has_placeholder.
        if redact.has_placeholder(command):
            command = _PLACEHOLDER_AUTH_ARG_RE.sub("", command).rstrip()
        if re.search(r"(?:^|\s)(?:-b|--cookie|--cookie-string|-c|-H|--header)\b"
                     r"|Cookie:|Authorization:", command, re.I):
            return command
        # Reject only what would break out of the quoted arg or trip the gate: the
        # shell metacharacters (;|&`<>$) plus our single-quote wrapper. Spaces/colons
        # are fine inside '...' (a Bearer header has them).
        _bad = "'\";&|`$<>\n\r"
        # token / bearer / basic session -> Authorization header
        ah = getattr(self.browser, "auth_header", "") or ""
        # THE source of truth for "what is a secret": the credential set this engagement
        # actually injects, registered at the moment it is read off the browser — never
        # a regex guessing at what a token looks like. Registered unconditionally (not
        # only when injection succeeds) so any other path that records the same value is
        # covered too. The injection below is deliberately UNREDACTED: the gate must
        # judge, and the cage must run, the real bytes (invariant 3). Redaction happens
        # at each point of RECORD instead — see redact.py.
        redact.register_auth_header(ah)
        redact.register(*(getattr(self.browser, "_cookies", {}) or {}).values())
        if ah and not any(c in ah for c in _bad):
            tmpl = _HEADER_INJECT.get(tool)
            if tmpl:
                return f"{command} {tmpl.replace('{H}', 'Authorization: ' + ah)}"
        # cookie session
        jar = getattr(self.browser, "_cookies", {}) or {}
        if jar:
            cookies = "; ".join(f"{k}={v}" for k, v in jar.items())
            if not any(c in cookies for c in _bad):
                tmpl = _COOKIE_INJECT.get(tool)
                if tmpl:
                    return f"{command} {tmpl.replace('{C}', cookies)}"
        return command

    # -- stateful live sessions (Phase 2) ----------------------------------- #

    def _session_backend_factory(self, target):
        """Build the right stateful backend for a live session from the cage this
        engagement is already using: a real persistent `docker exec bash` when the
        one-shot cage is DockerKali, else the in-memory FakeSession for tests/--fake.
        Overridable (tests set this before the first session) for a scripted shell."""
        from .kali import DockerKali, DockerSession, FakeSession
        kali = getattr(self.executor, "_kali", None) if self.executor is not None else None
        if isinstance(kali, DockerKali):
            return DockerSession(container=kali.container, target=target)
        return FakeSession(target)

    def _ensure_sessions(self):
        """Lazily create the SessionManager, wired to the SAME gate, audit log and
        approver as the one-shot executor — so a session write is gated + logged
        identically and an ESCALATE honours the engagement's current approver
        (interactive / auto / full-send). Every write still goes through the one door."""
        if self.sessions is None:
            from .sessions import SessionManager
            self.sessions = SessionManager(
                self.executor._gate, self.executor._audit,
                backend_factory=self._session_backend_factory,
                approver=lambda d: self.executor._approver(d),
                on_state=self._mirror_session_state)
        return self.sessions

    def _mirror_session_state(self, st) -> None:
        """Persist per-session state to the blackboard so a resumed engagement can see
        what each live shell did (never the raw transcript into the model — just a
        digest)."""
        self.session_states[st.sid] = st
        if self.blackboard is None:
            return
        lines = ["# Live sessions", ""]
        for s in sorted(self.session_states.values(), key=lambda x: x.sid):
            status = ("closed" if s.closed and not s.orphaned else
                      "ORPHANED" if s.orphaned else "open")
            lines.append(f"## session {s.sid} — {s.target}  ({status})")
            lines.append(f"- lines run: {s.lines}   denied: {s.denied}")
            for cmd, verdict, rc in s.transcript[-12:]:
                lines.append(f"  - [{verdict}] `{cmd}`" + (f"  (rc {rc})" if rc is not None else ""))
            lines.append("")
        try:
            self.blackboard.write_page("sessions.md", "\n".join(lines))
        except Exception:
            pass

    def open_session(self, target: str | None = None) -> int:
        """Open a live governed shell on the (authorised) target and make it current."""
        sid = self._ensure_sessions().open(target or self.target)
        self.note(f"[session {sid}] opened a live shell on {target or self.target}")
        return sid

    def session_action(self, directive: str, agent: str = "operator"):
        """Interpret a SESSION directive from the planner and run it through the multi-
        session manager. Every send is gated via GovernedSession (check_session), so an
        out-of-scope/injected line is DENIED and never reaches the shell.

        Grammar:
          open [target]           open a new live shell (becomes current)
          close [N]               close session N (or the current one)
          [N] <line> / #N <line>  send <line> to session N
          <line>                  send to the current session (opening one if none)

        Returns (decision, result, sid, new_highlights). `result` is a REAL shell
        ExecResult (source=shell), so a flag/foothold in it is CONFIRMED by the Verifier
        — the capability that lets the loop finish a box, not just enumerate it."""
        mgr = self._ensure_sessions()
        d = (directive or "").strip()
        low = d.lower()
        if low == "open" or low.startswith("open "):
            tgt = d[4:].strip() or self.target
            return None, None, self.open_session(tgt), []
        if low == "close" or low.startswith("close"):
            rest = d[5:].strip()
            sid = int(rest) if rest.isdigit() else mgr.current_id
            if sid is not None:
                mgr.close(sid)
                self.note(f"[session {sid}] closed")
            return None, None, sid, []
        sid, line = None, d
        m = self._SESSION_ID_RE.match(d)
        if m and (m.group(1) or m.group(2)):
            sid, line = int(m.group(1) or m.group(2)), m.group(3).strip()
        if not line:
            return None, None, sid, []
        if sid is None:
            sid = mgr.current_id or mgr.open(self.target)
        decision, result = mgr.send(sid, line, agent=agent)
        # Fold the real shell outcome into session state exactly like a one-shot run,
        # so notes/highlights/lessons/findings all see it and the plan advances.
        decision, result, hl = self._absorb_shell(line, decision, result)
        return decision, result, sid, hl

    def close_sessions(self) -> None:
        """Close every live session (end-of-run cleanup / kill switch). Idempotent."""
        if self.sessions is not None:
            self.sessions.close_all()

    @staticmethod
    def _extract_token(body: str) -> str:
        """Kept on the session because tests call it directly, and so does the
        `whoami` closure inside `confirm_mass_assignment`. The implementation now
        lives with the strategies that need it."""
        from .auth import extract_token
        return extract_token(body)

    def login(self, login_url: str, username: str, password: str,
              user_field: str = "username", pass_field: str = "password",
              extra_fields: dict | None = None, login_type: str = "form") -> bool:
        """Authenticate to a web app THROUGH the governed browser so the crawl and every
        later web action run WITH the session. Handles the real-world spread rather than
        one platform:
          - form  (default): POST url-encoded form data; reads the login page's hidden/
                    submit fields (CSRF tokens etc.) and echoes them back. Cookie session.
          - json  : POST a JSON body {user_field, pass_field, ...}; extracts a bearer/JWT
                    token from the JSON response (token/access_token/...). Token session.
          - basic : HTTP Basic — no request; sets Authorization: Basic base64(user:pass).
        Cookie sessions AND token/bearer/basic auth are propagated (see GovernedBrowser).
        Gate untouched — each request passes check_web (scope+scheme), never a shell.
        Returns True if we appear authenticated."""
        from .auth import BasicAuth, Credentials, FormAuth, JsonAuth, SessionOracle
        if self.browser is None:
            self.notes.append("[login] no governed browser wired — cannot authenticate.")
            return False

        lt = (login_type or "form").lower()
        # Remember it BEFORE authenticating: an authenticated crawl cannot rediscover
        # the login page, and every cross-account proof needs somewhere to authenticate
        # a second principal.
        self._login_url = login_url
        # Capture the FIRST login URL session-wide (set-once): in the auto flow that is the
        # operator's own --login-url, applied before any second-principal login. Kept beside
        # the per-principal value so `_json_signup_candidates` can always reach it.
        if login_url and not self._operator_login_url:
            self._operator_login_url = login_url

        strategy = {"basic": BasicAuth(), "json": JsonAuth(),
                    "form": FormAuth()}.get(lt)
        if strategy is None:
            # Fail closed (invariant 2). The OLD code let an unknown type through
            # with form encoding but gated the cookie/redirect heuristics on
            # `lt == "form"`, so only a token could authenticate it. Routing it to
            # FormAuth instead flipped 18 of 140 measured cases from FAILED to
            # AUTHENTICATED. Refusing to guess removes that direction entirely, and
            # protects A2: a new strategy added but not yet wired here fails loudly
            # instead of silently inheriting form semantics.
            #
            # `_login_type` is deliberately NOT set on this path (see below) — it
            # stays whatever it was, so confirm_default_credentials's `or "form"`
            # fallback still recovers instead of being handed a type it also
            # refuses, which would fail closed on every attempt while still
            # emitting a coverage row that claims the detector ran.
            self.notes.append(
                f"[login] unrecognised login type {lt!r} — refusing to guess "
                f"(known: form, json, basic)")
            self.authenticated = False
            return False

        # Only recorded once the type is known to resolve to a real strategy — see
        # the comment on the refused branch above for why this must not move earlier.
        self._login_type = lt

        creds = Credentials(username=username, password=password,
                            user_field=user_field, pass_field=pass_field,
                            extra_fields=extra_fields)
        # No try/except here: a strategy exception (a read timeout, a bug inside
        # auth.py) must propagate as it did before the port, not be swallowed and
        # re-reported as "login may have FAILED — check creds". Erasing the
        # difference between "the credentials were wrong" and "the request itself
        # broke" is exactly the ambiguity this phase exists to remove.
        attempt = strategy.authenticate(self.browser, login_url, creds)

        ok = SessionOracle().judge(attempt)

        if attempt.token and strategy.name != "basic":
            # All three of these ran in the OLD login()'s token branch,
            # unconditionally — before the ok verdict, and for every non-basic
            # strategy including form. Restored verbatim.
            #
            # KNOWN LATENT BUG, DEFERRED ON PURPOSE: a 4xx body containing a
            # token-shaped string — `extract_token`'s regex fallback matches
            # `token: "<16+>"` anywhere — sets identity and a bearer header from a
            # REJECTED token. Not fixed here, because this phase's value is that a
            # regression has exactly one possible cause; the deliberate fix and its
            # own test are reserved for a later phase.
            self.browser.auth_header = f"Bearer {attempt.token}"
            self.identity = username
            self._login_password = password
            # The token the app just handed us is itself evidence: its header names
            # the algorithm and its signature exposes a weak key. Reading it costs
            # nothing and needs no further request.
            try:
                self._seen_jwts.add(attempt.token)
                self.last_jwt = attempt.token
                self.scan_jwt(attempt.token, source=login_url)
            except Exception:
                pass                  # analysis must never break authentication

        self.authenticated = ok
        self._ensure_principal().strategy = strategy.name
        if ok:
            # REGISTER THE CREDENTIAL THE MOMENT THE SESSION EXISTS, before anything can
            # record a response that echoes it. Registration used to happen lazily — when
            # a cage command was built (`_inject_auth`) or when a cookie was SET
            # (`confirm_authentication`) — so a bearer session that never built a command
            # held an UNREGISTERED token, and `redact` cannot mask material it has never
            # been shown. That was invisible while response bodies reached no record; the
            # ownership record below is the first thing to carry a value straight out of a
            # body, and a target that returns its own token under an id-shaped key
            # (`sessionId`) put it on the ledger in cleartext. Same two funnels as every
            # other site, moved to the point the credential is acquired rather than the
            # point it is first used.
            redact.register_auth_header(getattr(self.browser, "auth_header", "") or "")
            redact.register(*(getattr(self.browser, "_cookies", {}) or {}).values())
            # The login reply is already held (`AuthAttempt.body`), so this costs nothing.
            # `_separate_identity` is what makes `who` right: a second-principal login runs
            # inside it, and `self.identity` is that principal for the duration.
            _who = "second" if getattr(self, "_establishing_second", False) else "self"
            # The HANDLE we authenticated as, kept per principal. It is what makes a
            # confirmation checkable: an identity oracle that answers with somebody
            # else's handle has not proved OUR session, whatever else it proves.
            self._remember_handle(_who, username)
            self._record_principal_ids(_who, "login", getattr(attempt, "body", ""))

        if ok and not self.identity:
            # Who we are was once set ONLY in the token branch, so a cookie-session
            # login left `identity` empty — and every authz check that asks "whose
            # objects are ours" reads it. Those checks simply never ran.
            self.identity = username
            self._login_password = password

        if strategy.name == "basic":
            # Basic auth makes no request, so there is no cookie count or token to
            # describe — hence its own note. It DOES set identity above, like every
            # other strategy: leaving that empty made authz checks reason about the
            # wrong principal on Basic-auth targets.
            self.notes.append(
                f"[login] HTTP Basic as {username} → Authorization header set")
            return ok

        jar = len(getattr(self.browser, "_cookies", {}) or {})
        how = "bearer token" if attempt.token else f"{jar} cookie(s)"
        self.notes.append(
            f"[login] {login_url} as {username} ({lt}) → "
            f"{'AUTHENTICATED via ' + how if ok else 'login may have FAILED — check creds/field names/type'}")
        if ok:
            # Confirmation is OWED from here, not taken here. Probing inside login() cost
            # every caller extra requests, and ~5 detectors call login() per engagement —
            # the exact expense `13bc501` closed — while also perturbing the detectors
            # that reason about login's own request/cookie sequence (session fixation
            # compares the identifier across exactly this boundary). It is paid instead at
            # first authenticated USE, which is the only place the answer changes anything.
            pr = self._ensure_principal()
            pr.carriage, pr.confirmed = "", None
            self._carriage_memo = None
        return ok

    # ---- CONFIRMING the session, rather than assuming it -------------------------
    #
    # `login()` above returns True when the login endpoint accepted our credentials and
    # we stored something. That is a claim about the LOGIN endpoint. Every authorization
    # question we go on to ask is a claim about OTHER endpoints, and run CM1 measured the
    # gap between them: a valid Juice Shop token carried as `Authorization: Bearer` is
    # honoured by `/api/Users/25` and ignored by `/rest/user/whoami`, which answers the
    # authenticated caller and a stranger with the same bytes. Two experiments built
    # their setup on that endpoint and could not resolve their own id; a third would have
    # compared a stranger with a stranger and been judged.

    def _probe_identity(self, url: str, with_session: bool):
        """One gated GET at an identity endpoint, with or without our session.

        Returns the WebResult, or None when the target did not answer at all. Anonymous is
        issued through `_separate_identity`, which is the tested way to make a request as
        nobody without destroying our own session.

        A 404 IS AN ANSWER. It used to return None here, read as "this path does not
        exist" — which is true on most targets and false on the one endpoint that made
        crAPI worth choosing: its `/identity/api/v2/user/dashboard` answers 404 to a
        caller it does not recognise and 200 {"id":9,…} to a bearer it does (measured
        2026-09-17). Skipping on 404 meant the session was never tried there, so the
        oracle that closes the `variant_as: second` gap was unreachable no matter what the
        allowlist said. A 404 that DISCRIMINATES is an oracle; a 404 everyone gets is an
        absent path, and the caller still treats it as one."""
        from .web import WebAction
        action = WebAction("request", method="GET", url=url)
        try:
            if with_session:
                _d, r = self.browser.run(action)
            else:
                with self._separate_identity():
                    _d, r = self.browser.run(action)
        except Exception:
            return None
        if getattr(r, "status", None) is None:
            return None
        return r

    @staticmethod
    def _answers_differ(a, b) -> bool:
        return (getattr(a, "status", None) != getattr(b, "status", None)
                or (getattr(a, "body", "") or "") != (getattr(b, "body", "") or ""))

    def _settle_carriage(self, carriage: str, confirmed, probe_url: str) -> str:
        """Record which carriage this target honours, on the ledger and on the Principal.

        A cross-account claim rests on which principal saw what; "authenticated" with no
        record of HOW is the same unprovable shape `2fdbc7f` closed for experiments."""
        pr = self._ensure_principal()
        pr.carriage, pr.confirmed = carriage, confirmed
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is not None:
            audit.append("authentication_carriage", {
                "principal": self.identity or "self", "carriage": carriage,
                "confirmed": confirmed, "probe": probe_url, "target": self.target,
            })
        how = carriage or "none"
        verdict = {True: "CONFIRMED", False: "REFUTED", None: "UNTESTED"}[confirmed]
        self.notes.append(f"[login] session carriage {verdict} ({how})"
                          + (f" at {probe_url}" if probe_url else ""))
        return carriage

    def _remember_handle(self, who: str, handle: str) -> None:
        """The username/email each principal authenticated as, kept per principal.

        Survives `_separate_identity` because it is keyed by principal rather than being
        the CURRENT identity — which is the whole point: while the second principal is
        being established, `self.identity` IS the second principal, so "who are we" is
        the wrong question to ask of a single attribute."""
        store = getattr(self, "_principal_handles", None)
        if store is None:
            store = self._principal_handles = {}
        if handle:
            store[who] = handle

    def _answered_as_another_principal(self, body, who: str) -> str:
        """The handle of a DIFFERENT principal, found in an answer we asked for `who`.

        Deliberately NOT a pattern match for what "logged in" looks like — that is the
        guess `confirm_authentication` refuses to make. This looks for one specific
        string we already know: a handle we ourselves authenticated as, belonging to a
        principal that is not the one asking. Nothing is inferred; either another
        principal's own handle is in the answer or it is not.

        Run CM4 needed exactly this. The oracle answered with the SECOND principal's
        email while the FIRST principal was asking, and every layer above took the answer
        at face value because nothing compared it to anything."""
        text = body if isinstance(body, str) else str(body or "")
        if not text:
            return ""
        for other, handle in (getattr(self, "_principal_handles", None) or {}).items():
            if other == who or not handle:
                continue
            if handle in text:
                return handle
        return ""

    def _record_identity_mismatch(self, who: str, answered: str, url: str) -> None:
        """A confirmation that proved the WRONG principal, named and recorded.

        Never filed under the requesting principal: a carriage record is the evidence a
        cross-account claim rests on, and one that says "A is confirmed" on the strength
        of an answer naming B is worse than no record at all, because it reads as
        provenance. CM4 published a HIGH cross-account finding on top of one."""
        expected = (getattr(self, "_principal_handles", None) or {}).get(who, "") \
            or self.identity or who
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is not None:
            audit.append("authentication_mismatch", {
                "requested_as": expected, "answered_as": answered,
                "principal_key": who, "probe": url, "target": self.target,
            })
        self.notes.append(
            f"[login] identity oracle MISMATCH at {url}: asked as {expected}, the target "
            f"answered as {answered} — the session in effect is not this principal's, so "
            f"nothing is confirmed")

    def _record_principal_ids(self, who: str, source: str, body) -> None:
        """Merge the identifiers a response carried into that principal's own set.

        Called at the three points a principal's authenticated responses arrive — its
        login reply, its identity probe, its signup reply — so no extra request is made
        for any of this. `who` keys it, and nothing merges across keys: an identifier
        belongs to the account whose response carried it, and crossing them would hand
        the model a false premise that every cross-account proposal built on it inherits."""
        from . import hypothesis as _hyp
        found = _hyp.own_identifiers(body)
        if not found:
            return
        store = getattr(self, "_principal_ids", None)
        if store is None:
            store = self._principal_ids = {}
        bucket = store.setdefault(who, {})
        for path, value in found.items():
            key = f"{source}.{path}"
            if key in bucket:
                continue                 # already learned and already on the ledger
            bucket[key] = value
            self._record_ownership(who, source, path, value)

    def principal_identifiers(self) -> dict:
        """{principal: {source.path: value}} — what each account is known to own.

        Empty for a principal whose responses carried no identifier, which is the honest
        answer for a target that does not expose one. See `hypothesis.own_identifiers`."""
        store = dict(getattr(self, "_principal_ids", None) or {})
        for who in ("self", "second"):
            store.setdefault(who, {})
        return store

    @property
    def auth_carriage(self) -> str:
        return self._ensure_principal().carriage

    @property
    def auth_confirmed(self):
        return self._ensure_principal().confirmed

    # Identity/authentication facts live on `self.principal` (a `Principal`, in
    # auth.py); these keep the 40+ existing call sites and their tests working
    # unchanged. `Principal` was named `SessionState` until it collided with the
    # pre-existing, unrelated `brukal.sessions.SessionState` (live-shell state,
    # package-exported). Adding a new fact means adding it to `Principal`, not
    # adding a seventh attribute here.
    def _ensure_principal(self):
        """Lazily create `self.principal` for objects built via `__new__` (some
        pre-existing tests construct AssistSession this way, skipping __init__
        entirely). This is the ONLY place that constructs a `Principal` — normal
        `__init__` also calls this, rather than assigning separately, so there is
        no second creation path that could race it and get silently discarded."""
        s = getattr(self, "principal", None)
        if s is None:
            from .auth import Principal
            s = Principal()
            self.principal = s
        return s

    @property
    def identity(self) -> str:
        return self._ensure_principal().identity

    @identity.setter
    def identity(self, v: str) -> None:
        self._ensure_principal().identity = v or ""

    @property
    def authenticated(self) -> bool:
        return self._ensure_principal().authenticated

    @authenticated.setter
    def authenticated(self, v) -> None:
        self._ensure_principal().authenticated = bool(v)

    @property
    def last_jwt(self) -> str:
        return self._ensure_principal().last_jwt

    @last_jwt.setter
    def last_jwt(self, v: str) -> None:
        self._ensure_principal().last_jwt = v or ""

    @property
    def _login_url(self) -> str:
        return self._ensure_principal().login_url

    @_login_url.setter
    def _login_url(self, v: str) -> None:
        self._ensure_principal().login_url = v or ""

    @property
    def _login_type(self) -> str:
        return self._ensure_principal().login_type

    @_login_type.setter
    def _login_type(self, v: str) -> None:
        self._ensure_principal().login_type = v or ""

    @property
    def _login_password(self) -> str:
        return self._ensure_principal().login_password

    @_login_password.setter
    def _login_password(self, v: str) -> None:
        self._ensure_principal().login_password = v or ""

    def has_session(self) -> bool:
        """Whether we hold an authenticated session, HOWEVER it is carried.

        This is the question every authorization check actually needs, and none of them
        asked it. They asked `if self.last_jwt` instead, which is not "am I logged in"
        but "am I logged in to a JSON API that issues bearer tokens". On a cookie-session
        application the answer was always no, so the whole family — BFLA targeting, the
        BOLA sweep, the model's authentication briefing — silently did not run, while a
        coverage row claimed it had.

        Five separate defects this session traced to that one substitution. A cookie jar
        and a bearer token are two ways to carry the same fact, and code that is not
        about credentials has no business knowing which one it is looking at."""
        if self.last_jwt or getattr(self.browser, "auth_header", ""):
            return True
        if getattr(self.browser, "_cookies", None):
            return bool(self.authenticated)
        return False

    def session_token(self) -> str:
        """The bearer token, or "" when the session is carried some other way.

        Only the provers that are genuinely ABOUT a token — forging one, cracking its
        key — may branch on this. Anything asking merely whether a request will be
        authenticated must use `has_session()`; the governed browser replays whatever we
        hold without being told which kind it is."""
        if self.last_jwt:
            return self.last_jwt
        header = getattr(self.browser, "auth_header", "") or ""
        return header[7:] if header.lower().startswith("bearer ") else ""

    def _session_handle(self, resolved: str) -> str:
        """A stable, unrecoverable handle for the session a principal issues under.

        `redact.placeholder_for`'s sha256[:8] — deliberately the SAME form redaction
        emits everywhere else, so a handle here and a masked credential in some other
        record read identically and an operator can correlate two records as the same
        session without the value being recoverable from either. Identify, never
        credential: this field exists on record surfaces that redaction is there to
        police, so it must not become the hole in it.

        A stranger has no session, and says so with an empty handle rather than by
        omitting the field."""
        if resolved == "anonymous":
            return ""
        if resolved == "second":
            src = getattr(self, "_second_identity", None) or {}
            material = src.get("auth") or json.dumps(src.get("cookies") or {},
                                                     sort_keys=True)
        else:
            browser = self.browser
            material = (getattr(browser, "auth_header", "") or "") or json.dumps(
                getattr(browser, "_cookies", {}) or {}, sort_keys=True)
        return redact.placeholder_for(material) if material else ""

    def _record_principal(self, requested: str, resolved: str, role: str, url: str):
        """WHO issued one experiment request, onto the ledger.

        A cross-account finding's whole claim is which principal saw what, and until
        2026-08-22 no artifact recorded it — so a sound finding and a manufactured one
        were byte-identical, and the one confirmed experiment finding in the project's
        history is checkable only because the model happened to describe its intent in
        prose. An audit `kind` rather than a new writer, so it inherits `redact.data`
        like every other record.

        REQUESTED and RESOLVED are both kept although they are equal by construction
        today. That is the point: the defect this closes was a silent substitution, and
        a pair that can disagree makes the next one visible in the ledger instead of
        inferable only from the code of the day."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None:
            return
        audit.append("experiment_principal", {
            "role": role or "unknown", "requested": requested, "resolved": resolved,
            "session": self._session_handle(resolved),
            "url": url, "target": self.target,
        })

    @contextmanager
    def _as_identity(self, who: str, role: str = "", url: str = ""):
        """Issue requests as one of the three principals an experiment may name.

        The model chooses WHICH, from a closed set; this decides what each name means.
        Same split as the comparators, and for the same reason — a proposal must not be
        able to describe a credential, only to select one that already exists.

        The provenance record is written HERE rather than at each call site, because
        this is the one point every dispatch passes through: a fourth call site added
        later inherits the record instead of silently going unattributed, which is the
        failure mode that made five past runs permanently unresolvable."""
        browser = self.browser
        # FAIL CLOSED, and before anything is recorded: an empty second identity used to
        # fall through to empty cookies and an empty auth header, which is exactly the
        # `anonymous` branch below — so `as: second` silently became `as: anonymous`,
        # went out on the wire, and got judged. Raising before the browser is touched
        # means the degraded request cannot exist, and nothing is attributed to a
        # request that never happened.
        second = getattr(self, "_second_identity", None) or {}
        if who == "second" and not second:
            from . import hypothesis as _h        # local, as elsewhere in this file
            raise _h.SecondPrincipalUnavailable(
                "no second principal was established on this target "
                "(self-registration did not yield an account)")
        # Confirmation is owed before an authenticated request is issued, and this is the
        # single point every experiment dispatch passes through — the same argument the
        # provenance record is written here for. Memoised, so a round of four experiments
        # pays for one probe, not twelve. Instrumentation must never fail a run: a probe
        # that raises leaves the session UNTESTED (None), which is not a refusal.
        if who != "anonymous" and self._ensure_principal().confirmed is None:
            try:
                self.confirm_authentication()
            except Exception:
                self._settle_carriage("", None, "")
        # And the same refusal when the session we DO hold was proved not to be honoured.
        # `as: self` from a session the target reads as a stranger is not "self"; it is
        # byte-for-byte `anonymous`, so the comparison would be between two strangers and
        # the verdict would be about Brukal. Only a REFUTED session refuses — an untested
        # one (None) is not a disproof and must not read as one.
        if who != "anonymous" and self._ensure_principal().confirmed is False:
            from . import hypothesis as _h
            raise _h.PrincipalNotAuthenticated(
                f"this target does not honour the session we hold "
                f"(carriage tried: {self._ensure_principal().carriage or 'none'}), so "
                f"'{who}' would be issued as a stranger")
        self._record_principal(who, who, role, url)
        if who == "self" or browser is None:
            setattr(self.browser, '_in_experiment', True) if self.browser else None
            yield
            return
        saved_cookies = dict(getattr(browser, "_cookies", {}) or {})
        saved_auth = getattr(browser, "auth_header", "")
        try:
            if who == "anonymous":
                browser._cookies, browser.auth_header = {}, ""
            elif who == "second":
                browser._cookies = dict(second.get("cookies") or {})
                browser.auth_header = second.get("auth", "")
            setattr(self.browser, '_in_experiment', True) if self.browser else None
            yield
        finally:
            # The experiment machinery's own dispatch is already recorded as
            # `experiment_result` and judged by a comparator. Capturing it AGAIN fed
            # it back as a new experiment, which issued more requests: a mirror
            # pointed at itself. Cleared here, where every dispatch passes.
            setattr(getattr(self, 'browser', None) or type('x', (), {})(),
                    '_in_experiment', False)
            browser._cookies = saved_cookies
            browser.auth_header = saved_auth

    def establish_second_identity(self):
        """Create a SECOND real account and keep its session beside our own.

        Authorization is a disagreement between principals, so a tool holding one
        session can only ever ask half the question. Every hand-written authz prover had
        to build its own second account inline; giving the experiments one turns the
        whole class from something only a detector-author can reach into something the
        model can propose. Returns the username, or ""."""
        if getattr(self, "_second_identity", None):
            return self._second_identity.get("user", "")
        if self.browser is None or not self.allow_intrusive:
            return ""
        # The window in which a login or an identity probe belongs to the SECOND
        # principal. try/finally, not a trailing assignment: this method returns early on
        # four separate failure paths, and a flag left True would file the NEXT `self`
        # login under `second` — a crossed disclosure, which is the one thing worse than
        # no disclosure because every proposal built on it inherits a false premise.
        self._establishing_second = True
        try:
            return self._establish_second_identity_inner()
        finally:
            self._establishing_second = False

    def _establish_second_identity_inner(self):
        with self._separate_identity():
            # The FORM first: an account created through the application's own signup
            # form is self-evidently what it grants a stranger, which is what makes a
            # privilege claim sound. JSON is the fallback for a target that serves no
            # form at all — an SPA, where this whole class was previously unreachable.
            made = self._register_account() or self._register_account_json()
            if not made:
                # WHY there is no second principal, on the record. A cross-account claim
                # that silently never had one is the failure this note prevents.
                why = getattr(self, "signup_refusal", "")
                self.note("[experiment] second principal NOT established"
                          + (f": {why}" if why else
                             ": no reachable registration endpoint accepted an account"))
                return ""
            user, password = made
            # "No cookies" is not "no session". `_register_account_json` may already have
            # logged in to PROVE the account exists (rung 2 of its evidence ladder), which
            # on a token API arms a bearer and seeds no cookie at all — so this test sent
            # a second, form-encoded login over a session that was already good. Harmless
            # on a target that refuses it, wasteful always, and on a target that accepts
            # an unparsable login it replaces a real session with one belonging to nobody.
            # Either carriage counts as a session, for the same reason either counts
            # everywhere else in this file.
            if not ((getattr(self.browser, "_cookies", {}) or {})
                    or getattr(self.browser, "auth_header", "")):
                login_url = self._login_endpoint()
                if not login_url:
                    return ""
                ok = self.login(login_url, user, password)
                if not ok and "@" in user:
                    # A JSON signup authenticates by EMAIL, and `login`'s default user
                    # field is `username`. Confirmed live on 2026-08-22: registration
                    # answered 201 and the login straight after it was refused 401 for
                    # exactly this, which would have left a real account unusable and
                    # looked identical to a target that refuses self-registration.
                    ok = self.login(login_url, user, password,
                                    user_field="email", login_type="json")
                if not ok:
                    return ""
            cookies = dict(getattr(self.browser, "_cookies", {}) or {})
            auth = getattr(self.browser, "auth_header", "")
            # REGISTER THE MOMENT IT IS OBTAINED, exactly as `_session_auth_for` does for
            # the first identity. This session is about to be stored and then replayed on
            # every `as: second` request, so it reaches the same record surfaces the first
            # one does — and until now it was never registered at all, on either path.
            redact.register_auth_header(auth)
            redact.register(*cookies.values())
            # ASK THE TARGET WHO THIS IS, while we are still inside `_separate_identity`
            # and still holding only this principal's session. Everything needed was
            # already here and nothing called it: `confirm_authentication` keys its record
            # as `second` on `_establishing_second`, and this context saves and restores
            # the carriage memo so a confirmation performed here cannot memoise against
            # ours. Without this line every `variant_as: second` claim CM5, CM6 and four
            # CR1 pre-flights produced carried a disclosure that the second principal's
            # identity was never verified — the exact gap crAPI was chosen to close, and
            # what CR1's definition of done requires.
            #
            # Instrumentation, so it can never end an engagement: a probe that raises
            # leaves the principal UNTESTED, which is not a refusal, and the second
            # principal is still returned. A target with no identity oracle simply does
            # not get the claim made about it.
            try:
                self.confirm_authentication()
            except Exception:
                pass
            self._second_identity = {
                "user": user, "password": password,
                "cookies": cookies, "auth": auth,
            }
        self.note(f"[experiment] second principal available: {user}")
        return user

    # -- authorization on a COOKIE-SESSION application ------------------------ #
    #
    # Brukal's whole authorization family — BOLA, BFLA, mass assignment — was built
    # against a JSON API with a JWT and templated routes, and it is structurally blind
    # to anything else: `bfla_targets` returns None the moment `self.last_jwt` is empty,
    # and the BOLA sweep needs a `{param}` in a mined route. A cold run against DVNA, a
    # classic server-rendered Express app with a cookie session and form POSTs, probed
    # twelve classes and NONE of them was an authorization class. A competing tool found
    # six there, two of them critical, and both of the ones checked by hand were real.
    #
    # That is not a missing detector, it is a missing SHAPE. Most of the web authenticates
    # with a cookie and submits a form.

    @contextmanager
    def _separate_identity(self):
        """Make requests as SOMEBODY ELSE without destroying our own session.

        Token auth can hold two principals at once — you simply send a different
        Authorization header — which is why nothing needed this until now. A cookie jar
        cannot: registering or logging in as a second user absorbs their Set-Cookie over
        ours, and every later probe in the run silently becomes that other user. Any
        cross-account test on a cookie-session app needs this or it corrupts the session
        it is trying to reason about."""
        browser = self.browser
        # THE WHOLE PRINCIPAL, not a list of its fields.
        #
        # This used to save and restore eight things by name, and the list was a field
        # behind the object. `login()` sets `last_jwt` on EVERY login, including the
        # second principal's inside this very context, and `last_jwt` was not on the
        # list — so it leaked. `confirm_authentication` reads `session_token()`, which
        # returns `last_jwt` FIRST, so a confirmation run after a second principal
        # existed installed the SECOND principal's token as a cookie, asked the identity
        # oracle, was told the second principal, filed that id under `self`, recorded the
        # FIRST principal's carriage as confirmed on the strength of it, and left the
        # other token in the jar. Run CM4's only cross-account finding was the second
        # principal reading its own basket, recorded as `self` reading somebody else's.
        # `login_url` and `login_type` were missing from that list too.
        #
        # `Principal` already IS the structure — every one of these is reached through a
        # property that delegates to it — so snapshotting the object switches the fields
        # that exist today and the ones added later, which a by-name list cannot.
        saved_principal = self._ensure_principal().snapshot()
        saved_cookies = dict(getattr(browser, "_cookies", {}) or {})
        saved_auth = getattr(browser, "auth_header", "")
        # The carriage memo is keyed by (login_url, identity) and lives on the SESSION
        # rather than the principal, so it is the one piece of per-principal state the
        # snapshot above does not reach. Left behind, a confirmation performed as the
        # second principal memoises against our key.
        saved_memo = getattr(self, "_carriage_memo", None)
        try:
            browser._cookies = {}
            browser.auth_header = ""
            yield browser
        finally:
            self._ensure_principal().__dict__.update(saved_principal)
            browser._cookies = saved_cookies
            browser.auth_header = saved_auth
            self._carriage_memo = saved_memo

    def _login_proves_account(self, email: str, password: str) -> bool:
        """Can we actually USE the account the signup claims to have made?

        The decisive rung of the ladder above, and the reason the whole class of "did that
        registration work" question stops depending on a reply's shape. A JSON signup
        authenticates by EMAIL and `login`'s default user field is `username`, so the
        email form is tried first and the default second — the same order, and the same
        reason, as the caller's own retry.

        Runs inside `_separate_identity` (every caller of `_register_account_json` is), so
        the session it arms belongs to the SECOND principal and cannot leak into ours."""
        login_url = self._login_endpoint()
        if not login_url:
            return False
        try:
            if self.login(login_url, email, password,
                          user_field="email", login_type="json"):
                return True
            return bool(self.login(login_url, email, password))
        except Exception:
            return False

    def _login_endpoint(self) -> str:
        """The login URL, or "" — shared by every check that needs to authenticate, so
        they cannot disagree about where the login is.

        The URL the OPERATOR gave us wins. An authenticated crawl never mines a login
        route: a logged-in user is redirected away from /login exactly as they are from
        /register, so the surface has no login on precisely the runs that hold a
        session. Both cross-account provers then called login("") and quietly failed —
        the control passed for the wrong reason and the proof could never succeed, so a
        confirmed critical was reported as nothing at all. The signup form had the same
        problem; this is the same fix for the same cause."""
        if getattr(self, "_login_url", ""):
            return self._login_url
        # SESSION-LEVEL fallback. `_login_url` is per-principal and reads empty during
        # `_separate_identity`, where the second principal is proved by login — so without
        # this the proof called login("") and establishment failed intermittently even
        # after signup answered 200. The operator's URL is the same for every principal.
        if getattr(self, "_operator_login_url", ""):
            return self._operator_login_url
        surface = getattr(self, "surface", None)
        if surface is None:
            return ""
        from urllib.parse import urljoin as _urljoin
        base = getattr(surface, "seed", "") or f"http://{self.target}/"
        candidates = list(getattr(surface, "api_routes", []) or []) \
            + [p for p in (getattr(surface, "pages", {}) or {})] \
            + [getattr(f, "action", "") for f in (getattr(surface, "forms", []) or [])]
        for r in candidates:
            if not r or "{" in r:
                continue
            if any(w in r.lower() for w in ("login", "signin", "sign-in", "authenticate")):
                return r if r.startswith("http") else _urljoin(base, r)
        return ""

    def _other_principal(self, routes, base) -> str:
        """A username the app lists that is not the one we authenticated as."""
        from urllib.parse import urljoin as _urljoin
        from . import webmap
        from .web import WebAction
        if self.browser is None:
            return ""
        collection = next((r for r in routes
                           if "{" not in r and r.lower().rstrip("/").endswith("users")
                           or (("user" in r.lower()) and "{" not in r
                               and "login" not in r.lower()
                               and "register" not in r.lower())), None)
        if not collection:
            return ""
        url = collection if collection.startswith("http") else _urljoin(base, collection)
        try:
            _d, r = self.browser.run(WebAction("request", url=url, method="GET"))
        except Exception:
            return ""
        names = webmap.principals((r.body if r else "") or "")
        for n in names:
            if n and n != self.identity:
                return n
        return ""
