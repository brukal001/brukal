"""
assist_web.py — the _WebMixin for AssistSession. Methods extracted verbatim
from assist.py (no logic change); composed back onto AssistSession in assist.py.
"""
from __future__ import annotations

import re
from .assist_util import (
    _ASSET_RE,
    _FAMILY_QUOTA,
    _LIKELY_WEB_PORTS,
    _LOGOUT_RE,
    _MAX_NON_HTML,
    _MINING_READS,
    _PATH_SCANNERS,
    _TECH_HINTS,
    _UNSURE_SVC_RE,
    _WEB_PORT_RE,
    _bundle_rank,
    _changes_target_state,
    _is_raw_fetch,
    _looks_non_html,
    _norm_body,
    _outcome_feedback,
    _path_family,
    _tool_of,
    _url_in,
    highlight_findings,
)


class _WebMixin:

    def _curl_to_web_action(self, command: str):
        """Translate a curl/wget web request into a governed WEB request action. Lets a
        form/query/INJECTION payload whose '&' or ';' the shell gate rejects still run —
        through the HTTP client, no shell. Returns a WebAction or None."""
        import shlex

        from .web import WebAction
        if _tool_of(command) not in ("curl", "wget"):
            return None
        try:
            toks = shlex.split(command)
        except ValueError:
            return None
        method, url, body, headers = "GET", "", "", {}
        i = 1
        while i < len(toks):
            t = toks[i]
            if t in ("-X", "--request") and i + 1 < len(toks):
                method = toks[i + 1].upper(); i += 2; continue
            if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
                     "--data-ascii") and i + 1 < len(toks):
                body = toks[i + 1]; method = "POST" if method == "GET" else method; i += 2; continue
            if t in ("-H", "--header") and i + 1 < len(toks):
                h = toks[i + 1]
                if ":" in h:
                    k, v = h.split(":", 1); headers[k.strip()] = v.strip()
                i += 2; continue
            if t in ("-b", "--cookie") and i + 1 < len(toks):
                headers["Cookie"] = toks[i + 1]; i += 2; continue
            if t.startswith(("http://", "https://")):
                url = t
            i += 1
        return WebAction("request", url=url, method=method, body=body,
                         headers=headers or {}) if url else None

    def _pointless_path_scan(self, command: str) -> str:
        """A reason to refuse, or "" — path discovery against a catch-all host.

        Brukal already DOWNGRADES a path scanner's hits on a soft-404 host, because a
        server answering 200 for every path makes every hit false. It nonetheless ran
        the scan first and threw the results away, which is not merely wasted time: on
        an authorised Juice Shop the accumulated requests for paths that do not exist
        drove the target's own error handling to exhaust its heap, and the application
        died mid-engagement. A tool that knocks over what it was asked to assess has
        caused an outage, whatever its intent — and 'read-only' describes the method
        here, not the effect, exactly as it does for the credential brute-force probe.

        So the refusal is moved earlier: if the answer is going to be discarded, the
        requests are not worth making. The scan is skipped with a note, so the report
        says the class was deliberately not attempted rather than quietly omitting it."""
        if self.surface is None or not getattr(self.surface, "soft_404", False):
            return ""
        tool = _tool_of(command)
        if tool not in _PATH_SCANNERS:
            return ""
        return (f"[coverage] skipped {tool}: this host answers 200 for paths that do "
                f"not exist, so every hit would be false and was going to be discarded. "
                f"Sustained path discovery against such a host has exhausted a target's "
                f"memory and taken it down mid-engagement, so the requests are not made.")

    def run(self, command: str, target: str | None = None, agent: str = "strategist"):
        """Run a command through the gate/cage, record it, and surface the key
        results. Returns (decision, result, new_highlights). `agent` attributes the
        action to a role (recon/exploit/verify in multi-agent mode) so the gate's
        per-agent trust modulates its soft-risk score — it never changes the hard
        checks or the single execution path."""
        command = self._session_auth_for(command)       # authenticated exploitation
        skip = self._pointless_path_scan(command)
        if skip:
            self.notes.append(skip)
            self.highlights.append(("coverage", skip))
            return None, None, [skip]
        # A registered pre_action hook may VETO this action (roadmap §1.1) — a
        # site-specific rule like "never touch /createdb". It can only SKIP: the command
        # returns here, before executor.run, so it never reaches the gate or the cage, and
        # a hook can never make a denied command run. Absent bus -> no-op.
        if self.hooks is not None:
            veto = self.hooks.veto("pre_action", command=command,
                                   target=target or self.target, agent=agent)
            if veto:
                note = f"[hook] action vetoed before the gate: {veto}"
                self.notes.append(note)
                self.highlights.append(("hook", f"vetoed: {veto}"))
                return None, None, [note]
        decision, result = self.executor.run(command, target or self.target,
                                             agent=agent)
        # Auto-route a web request the shell gate rejected for a metacharacter ('&' in
        # form data, ';'/'|' in an injection payload) to the GOVERNED WEB path — same
        # scope+scheme gate, but the payload rides the HTTP client, never a shell. This
        # lets authenticated form/injection testing actually run without touching the
        # gate (invariant 1). Only for curl/wget web requests, only on hard:injection.
        if (result is None and getattr(decision, "layer", "") == "hard:injection"
                and self.browser is not None):
            wa = self._curl_to_web_action(command)
            if wa is not None:
                wdec, wres = self.browser.run(wa, agent=agent)
                if wres is not None:
                    self.executed_cmds.append(command)
                    self.notes.append(
                        f"[reroute] shell request blocked (shell metacharacter) → ran as "
                        f"a governed WEB {wa.method} instead:\n{wa.describe()} "
                        f"→ status={wres.status}")
                    body = wres.body or ""
                    from . import webprobe
                    new_hl = highlight_findings(body)
                    for _s, _l, _ln in (list(webprobe.scan_output(body))
                                        + list(webprobe.scan_exposures(body))):
                        self._record_vuln_finding(command, _s, _l, _ln)
                        h = (f"vuln/{_s}", f"{_l}: {_ln}")
                        if h not in new_hl:
                            new_hl.append(h)
                    self.highlights.extend(h for h in new_hl if h not in self.highlights)
                    self._advance_plan()
                    from .kali import ExecResult
                    return wdec, ExecResult(command, 0, body, ""), new_hl
        return self._absorb_shell(command, decision, result)

    def _absorb_shell(self, command, decision, result):
        """Fold one shell outcome into session state (notes/highlights/lessons/
        vault). Split out from `run` so the parallel runner can EXECUTE in worker
        threads (thread-safe backends) and ABSORB here on the main thread only —
        keeping session state single-threaded."""
        new_hl: list[tuple[str, str]] = []
        if result is not None:
            self.executed_cmds.append(command)   # fed back as ALREADY TRIED next turn
            # SHELL-PLANE CAPTURE. Self-capture hooks the web plane's single door, but
            # agents also reach the target with `curl`, and those requests were invisible
            # to it: four of eleven shell commands in CR2 run 1 were HTTP requests against
            # the target, each a control that answered and none a replay candidate. The
            # parser declines anything it cannot read confidently, because a misread
            # command would put a URL nobody issued into the surface.
            try:
                from . import capture as _capture
                _status = 200 if (result.returncode == 0
                                  and (result.stdout or "").strip()) else 0
                _cap = _capture.parse_curl(command, self.executor._gate.scope, _status,
                                           len((result.stdout or "")))
                if _cap is not None:
                    store = getattr(self, "_shell_captures", None)
                    if store is None:
                        store = self._shell_captures = []
                    if len(store) < 25:
                        store.append(_cap)
            except Exception as exc:
                # NOT a bare pass. The first version wrote `result.exit_code` — the field
                # is `returncode` — and a bare `except` swallowed the AttributeError, so
                # shell capture silently did nothing while reporting success. That is the
                # FIFTH such no-op in this session and the except was mine, written
                # minutes after naming the pattern. Capture still must not break a run,
                # so it is caught; it is no longer INVISIBLE.
                if not getattr(self, "_shell_capture_warned", False):
                    self._shell_capture_warned = True
                    self.note(f"[capture] shell capture is failing and is disabled for "
                              f"this run ({type(exc).__name__}: {str(exc)[:90]})")
            raw = (result.stdout or "").strip()
            # THE COMMAND PLANE'S OBSERVATION POINT. This is where CR1's finding was
            # seen and lost: the agent's curl returned another tenant's order and the
            # output became a note nobody could publish from.
            try:
                _u = _url_in(command)
                self._observe_record(_u, raw)
                # An HTTP status line in a raw fetch is the answer; without -i there is
                # none, and a body that came back at all is itself the evidence.
                _m = re.search(r"HTTP/[\d.]+\s+(\d{3})", raw or "")
                self._observe_answer(_u, int(_m.group(1)) if _m else (200 if raw else 0))
            except Exception:
                pass
            # CORROBORATE WHAT THE MODEL REACHED (capability lever #1): turn a bug the model
            # touched into a scored, proof-carrying CONFIRMED finding via the deterministic
            # differential, instead of an uncredited curl. Opt-in + bounded; see
            # _auto_confirm_reached / docs/AUTO_CONFIRM_REACHED.md.
            try:
                self._auto_confirm_reached(command)
            except Exception:
                pass
            new_hl = highlight_findings(raw)
            # Flag vulnerability signals in the output (sqlmap 'is vulnerable',
            # nuclei [critical], nikto findings, CVE ids) so a real bug surfaces as a
            # top highlight instead of scrolling past. Untrusted output; a hit is a
            # lead for the Verifier/operator, not an action.
            from . import webprobe
            for _sev, _label, _line in webprobe.scan_output(raw):
                h = (f"vuln/{_sev}", f"{_label}: {_line}")
                if h not in new_hl:
                    new_hl.append(h)
                self._record_vuln_finding(command, _sev, _label, _line)
            # Exposure/info-disclosure signatures in the RAW response body (leaked
            # secrets, .git/.env, keys, SQL errors, directory listings) — ONLY for
            # raw-fetch tools (curl/wget/...). A scanner (sqlmap/nikto/nuclei) echoes
            # payloads and technique names ("PostgreSQL AND error-based") that trip the
            # content signatures and manufacture false findings, so we never run the
            # raw-response detector on scanner output — scan_output above owns those.
            # Active Directory / internal: scan AD/SMB/Kerberos tool output for attack
            # indicators (roast hashes, SMB signing, null session, Pwn3d!, MS17-010, ...).
            from . import adscan
            if adscan.is_ad_tool(command):
                for _sev, _label, _line in adscan.scan_ad_output(raw):
                    h = (f"ad/{_sev}", f"{_label}: {_line}")
                    if h not in new_hl:
                        new_hl.append(h)
                    self._record_ad_finding(command, _sev, _label, _line)
            # Cloud / infrastructure: scan cloud recon output (HTTP or CLI) for public
            # storage, IMDS/SSRF creds, leaked cloud secrets, over-permissive IAM.
            from . import cloudscan
            if cloudscan.is_cloud_tool(command):
                for _sev, _label, _line in cloudscan.scan_cloud_output(raw):
                    h = (f"cloud/{_sev}", f"{_label}: {_line}")
                    if h not in new_hl:
                        new_hl.append(h)
                    self._record_cloud_finding(command, _sev, _label, _line)
            # AI / LLM: scan an LLM endpoint's RESPONSE for disclosure/jailbreak/leak.
            # Gated on the endpoint being an unambiguous AI feature — the AI tool set
            # includes curl, and running these signatures over every fetched page would
            # manufacture findings from ordinary prose ("you are ... do not share").
            from . import aiscan
            if aiscan.is_ai_tool(command) and (aiscan.looks_like_ai_feature(command)
                                               or aiscan.looks_like_ai_feature(raw)):
                for _sev, _label, _line in aiscan.scan_ai_output(raw):
                    h = (f"ai/{_sev}", f"{_label}: {_line}")
                    if h not in new_hl:
                        new_hl.append(h)
                    self._record_ai_finding(command, _sev, _label, _line)
            exposures = webprobe.scan_exposures(raw) if _is_raw_fetch(command) else []
            # Contributed detections apply to tool output too — an organisation's own
            # error strings surface in a scanner transcript far more often than in a
            # crawled page. Same recorder, so they dedupe and downgrade identically.
            if self.signature_packs:
                from . import packs as _packs
                exposures = list(exposures) + _packs.scan(raw, self.signature_packs)
            for _sev, _label, _line in exposures:
                h = (f"exposure/{_sev}", f"{_label}: {_line}")
                if h not in new_hl:
                    new_hl.append(h)
                self._record_vuln_finding(command, _sev, _label, _line)
            self.highlights.extend(h for h in new_hl if h not in self.highlights)
            # Turn a failure into an actionable LESSON the model sees next turn, so a
            # weak model course-corrects instead of repeating a bad move.
            feedback = _outcome_feedback(decision, result, raw)
            self.notes.append(f"[ran] {command}\n{feedback}")
            summary = ("; ".join(f"{t}: {l}" for t, l in new_hl[:6])
                       or feedback[:200])
            self._persist_finding("ran", command, decision.verdict, summary, new_hl)
            self._advance_plan()       # this step is done; move to the next
        else:
            # Blocked by the gate — tell the model WHY and exactly what to do instead,
            # keyed on WHICH hard check fired, so a weak model corrects in one turn
            # rather than re-trying the same shape. (Coaching only — the gate is
            # unchanged; these hints never relax a check.)
            layer = decision.layer or ""
            _web_data = ("-d " in command or "--data" in command
                         or re.search(r"https?://\S*\?\S*&", command) is not None)
            if (layer == "hard:injection" and _is_raw_fetch(command)
                    and "http" in command and _web_data):
                # A web request (curl/wget) with '&' in form data or a query string is
                # rejected because '&' is a shell operator in a raw command. The right
                # primitive is a WEB action: it sends the body through the browser/HTTP
                # client (no shell), and the browser keeps cookies + CSRF tokens across
                # requests — which is how you log in and test authenticated pages.
                hint = ("form data / query strings contain '&', which the shell gate "
                        "rejects in a raw command. Do NOT use curl for this — use a WEB "
                        "action: `WEB fill` the form fields then `WEB click` submit (the "
                        "browser carries cookies + the CSRF token), or `WEB request POST "
                        "<url> body=field1=v1&field2=v2`. The site map already lists the "
                        "form and its fields. This is how you authenticate and reach "
                        "pages behind a login.")
            elif layer == "hard:injection":
                hint = ("shell operators (&&  ||  ;  |  $(...)  backticks  >) are "
                        "rejected — issue ONE tool per step with no chaining or pipes. "
                        "To parse/inspect output or run multi-step LOCAL analysis in "
                        "the cage (read a dumped file, `git log`, grep for secrets), "
                        "use a SESSION action, not RUN.")
            elif layer == "hard:scope":
                hint = ("out of scope — stay on the authorised host; do not touch any "
                        "other address.")
            elif layer == "hard:allowlist":
                hint = ("that tool isn't allowlisted here — use an installed, "
                        "read-only equivalent for this step.")
            elif layer.startswith("hard"):
                hint = ("blocked by a hard check — stay on the authorised host and use "
                        "an allowlisted tool.")
            else:
                hint = "this needs sign-off; a lighter, more targeted command may pass"
            self.notes.append(f"[ran] {command}\nNOT RUN — {decision.verdict} "
                              f"({decision.layer}: {decision.reason}). {hint}")
            self._persist_finding("blocked", command, decision.verdict,
                                  f"{decision.layer}: {decision.reason}", [])
        # Learn from this outcome for FUTURE engagements (cross-session memory).
        if self.lessons is not None:
            tech = sorted({m.lower() for _t, ln in new_hl for m in _TECH_HINTS.findall(ln)})
            self.lessons.learn_from_outcome(command, decision, result, tech)
        return decision, result, new_hl

    def web_urls_from_findings(self) -> list[str]:
        """Deterministically pull web-service URLs out of the findings — open
        http/https ports (nmap) and web-server fingerprints — so a browser render
        can be triggered automatically the moment a web surface appears."""
        from urllib.parse import urlsplit
        urls: list[str] = []
        for _tag, line in self.highlights:
            for m in _WEB_PORT_RE.finditer(line):
                port, svc = m.group(1), m.group(2).lower()
                labelled_web = ("http" in svc or svc in ("https", "ssl/http", "http-alt",
                                                        "http-proxy", "www"))
                # An open port on a common web port that nmap could NOT identify is a
                # web candidate, not a dead end: costs one fetch, and skipping it loses
                # the whole surface when service detection fails (Juice Shop = "ppp?").
                maybe_web = (port in _LIKELY_WEB_PORTS
                             and (bool(_UNSURE_SVC_RE.search(svc)) or not svc))
                if not labelled_web and not maybe_web:
                    continue
                https = ("https" in svc or "ssl" in svc or port in ("443", "8443", "9443"))
                scheme = "https" if https else "http"
                if (not https and port == "80") or (https and port == "443"):
                    urls.append(f"{scheme}://{self.target}/")
                else:
                    urls.append(f"{scheme}://{self.target}:{port}/")
        # Also: the moment ANY web command has actually hit the target (curl/whatweb/
        # ffuf/gobuster against an http(s) URL), we KNOW there is a web surface — seed
        # the crawl from it. Executed commands are in-scope by construction (the gate
        # denied anything else), so their URLs are the target's. This is the reliable
        # trigger; nmap service-detection ("open http") is not, and it made the
        # surface-map reflex silently skip SPAs whose port nmap didn't label http.
        for cmd in self.executed_cmds:
            for m in re.finditer(r"https?://[^\s'\";|>]+", cmd):
                sp = urlsplit(m.group(0))
                if sp.scheme and sp.netloc:
                    urls.append(f"{sp.scheme}://{sp.netloc}/")
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def crawl(self, seeds=None, max_pages: int = 20, max_depth: int = 2, observer=None,
              merge: bool = False):
        """Governed breadth-first crawl of the in-scope web surface. Every fetch goes
        through run_web -> the gate -> the cage (scope-locked egress); the HTML that
        comes back is parsed IN-PROCESS (no egress) into an AttackSurface — forms,
        parameters, links. Bounded by max_pages / max_depth and confined to the seed
        host + authorised scope, so it can neither run forever nor wander off-target.
        A gate rate-limit block ends the crawl cleanly with whatever was mapped. The
        resulting map is folded into grounded state so the strategist/exploit agent
        reason over the real site instead of guessing endpoints. Returns the surface."""
        from collections import deque

        from . import webmap
        if self.browser is None:
            return None
        seeds = list(seeds or self.web_urls_from_findings() or [f"http://{self.target}/"])
        surface = webmap.AttackSurface(seed=seeds[0] if seeds else "")
        scope = getattr(self.browser, "_scope", None)
        seed_hosts = {webmap.host_of(u) for u in seeds if webmap.host_of(u)}

        def _in_scope(url: str) -> bool:
            h = webmap.host_of(url)
            if not h:
                return False
            return h in seed_hosts or bool(scope and scope.contains_host(h))

        queue = deque((webmap.normalize_url(u, "") or u, 0)
                      for u in seeds if _in_scope(u) and not _LOGOUT_RE.search(u))
        # Pages a quota pushed aside, crawled only if budget is left over. Deferring
        # rather than dropping keeps the crawl a strict improvement: nothing becomes
        # unreachable, it just stops going first.
        deferred: deque = deque()
        skipped_state: set = set()       # links refused because following them would
                                         # have changed the target rather than read it
        family_count: dict = {}
        non_html = 0
        visited: set = set()
        while (queue or deferred) and len(surface.pages) < max_pages:
            from_queue = bool(queue)
            url, depth = queue.popleft() if from_queue else deferred.popleft()
            if url in visited:
                continue
            # Stylesheets, fonts and images cannot hold a form, a parameter or a route.
            # They cost a request each and taught the crawl nothing; three of twenty
            # pages on the run that motivated this went to font-awesome and jQuery.
            if _ASSET_RE.search(url):
                visited.add(url)
                continue
            if not from_queue:
                pass                             # leftover budget: quotas no longer apply
            else:
                # One deep templated family may not monopolise the budget. DVNA's
                # `/learn/vulnerability/<name>` is ten renderings of one template; the
                # crawl spent twelve of twenty pages there and never reached /products,
                # /admin or /usersearch — the entire application. Three samples are
                # enough to learn what a family looks like.
                fam = _path_family(url)
                if fam:
                    seen_n = family_count.get(fam, 0)
                    if seen_n >= _FAMILY_QUOTA:
                        deferred.append((url, depth))
                        continue
                    family_count[fam] = seen_n + 1
            if non_html >= _MAX_NON_HTML and _looks_non_html(url):
                visited.add(url)
                continue
            visited.add(url)
            if observer is not None:
                try:
                    observer("crawl", url=url, found=len(surface.pages) + 1)
                except Exception:
                    pass
            decision, result, _hl = self.run_web(f"get {url}")
            if decision is not None and getattr(decision, "layer", "").endswith("web-rate"):
                break                              # hit the rate wall — stop, keep the map
            self._rendered.add(url)            # don't let the render reflex re-fetch it
            if result is None:
                continue
            # A 3xx is not a dead end. The web layer deliberately does NOT auto-follow —
            # the destination has to go back through the scope gate rather than being
            # trusted because a target's own Location header said so — and it says as
            # much in its note. Nothing was resubmitting it, so an application whose
            # entry point redirects presented an empty surface: DVNA answers / with a
            # 302 to /login, and a cold run against it crawled one page, found zero
            # links, zero forms, zero routes, and reported nothing at all. Most
            # login-gated applications behave exactly that way.
            if 300 <= (result.status or 0) < 400:
                loc = ((result.headers or {}).get("location")
                       or (result.headers or {}).get("Location") or "")
                if loc and depth <= max_depth:
                    # normalize_url takes (base, href) in that order. Passing them the
                    # other way round resolved the root against the destination and
                    # handed back the root — already visited, so nothing was queued and
                    # the fix looked like it had not worked at all.
                    nxt = webmap.normalize_url(url, loc)
                    if (nxt and nxt not in visited and _in_scope(nxt)
                            and not _LOGOUT_RE.search(nxt)):
                        queue.append((nxt, depth))   # same depth: a hop, not a level
                continue
            server = (result.headers or {}).get("server") or (result.headers or {}).get("Server")
            if server:
                surface.techs.add(str(server).split("/")[0][:24])
            body = result.body or ""
            # Parse as HTML only when the server SAID it was HTML. Feeding a JavaScript
            # bundle to an HTML parser is not harmless: showdown.min.js builds anchors by
            # string concatenation, the parser read `'<a href="'+c+'"'` as a real tag, and
            # the crawl spent four of its twenty pages fetching `/assets/'+c+'` and
            # friends. A bundle is still worth mining for route strings — that is what
            # turns an SPA into a list of endpoints — but it is not a page, so it neither
            # yields links nor costs page budget.
            ctype = str((result.headers or {}).get("content-type")
                        or (result.headers or {}).get("Content-Type") or "").lower()
            is_html = ("html" in ctype) or (not ctype and body.lstrip()[:1] == "<")
            # Path-shaped strings from EVERY body, HTML or bundle. Held as candidates
            # and promoted only under a mount prefix the crawl has proved real — the one
            # honest way to reach an endpoint that nothing links to.
            surface.path_candidates |= webmap.extract_path_candidates(body)
            # THE TWO HALVES OF THE JOIN (GAPs #20, #21). A single-page app keeps its
            # service mounts and its endpoint suffixes in SEPARATE constants and
            # concatenates them at runtime — crAPI ships `ig="workshop/"` and
            # `"api/shop/orders"` — so a miner looking for path-SHAPED strings sees
            # neither. Collected here from every body, confirmed later by request in
            # `discover_mounts` / `resolve_mounted_endpoints`. Nothing is composed until
            # the target has answered for it.
            surface.mount_candidates |= set(webmap.extract_mount_candidates(body))
            surface.api_suffixes |= set(webmap.extract_api_suffixes(body))
            if not is_html:
                surface.add_routes(webmap.extract_api_routes(body))
                self.scan_web_body(url, body)
                non_html += 1
                continue
            links, forms, params = webmap.extract(url, body)
            # Exclude session-destroying links (logout/signout) so an authenticated
            # crawl keeps its session for the whole run.
            # A crawl must be read-only in EFFECT. Logout ends our own session;
            # irreversible paths destroy the target's data; a configuration link
            # reconfigures the application under the assessment that is measuring it.
            # All three are recorded rather than silently dropped, because "Brukal
            # declined to touch this" is information an operator needs.
            in_scope_links = set()
            for l in links:
                if not _in_scope(l):
                    continue
                if _LOGOUT_RE.search(l):
                    continue
                if self._is_irreversible_path(l) or _changes_target_state(l):
                    if l not in skipped_state:
                        skipped_state.add(l)
                    continue
                in_scope_links.add(l)
            surface.add_page(url, in_scope_links, forms, params)
            self.scan_web_body(url, body)      # every crawled page is evidence too
            # Mine API route paths from the body (crucial for SPAs: the endpoints live
            # in the JS bundle, not the near-empty initial HTML). Leads, still gated.
            surface.add_routes(webmap.extract_api_routes(body))
            if depth < max_depth:
                # Rank before queueing. Alphabetical order is not a priority, and here
                # it actively cost findings by putting lazy chunks ahead of the entry
                # bundle that names the API.
                for l in sorted(in_scope_links, key=lambda u: (_bundle_rank(u), u)):
                    if l not in visited:
                        queue.append((l, depth + 1))

        # A templated documentation family is low value to PROBE and high value to
        # READ: on DVNA the only mention of /app/redirect anywhere is inside one
        # `/learn/vulnerability/*` page, and the family quota — added to stop those
        # pages crowding out the application — deferred it past the page budget. The
        # quota was right about probing and wrong about reading, so deferred pages get a
        # small separate allowance, spent purely on mining route strings out of them.
        mined_reads = 0
        # BOTH leftovers: pages a quota pushed aside, and pages the budget simply never
        # reached. The first version drained only the deferred queue and missed the more
        # common case — a frontier page that was next in line when max_pages ran out is
        # just as likely to name an unlinked route.
        leftovers = deque(list(deferred) + list(queue))
        while leftovers and mined_reads < _MINING_READS and not self._rate_limited:
            durl, _d = leftovers.popleft()
            if durl in visited:
                continue
            visited.add(durl)
            mined_reads += 1
            try:
                _dec, dres, _hl = self.run_web(f"get {durl}")
            except Exception:
                break
            if dres is None or not getattr(dres, "body", ""):
                continue
            surface.path_candidates |= webmap.extract_path_candidates(dres.body)
            surface.add_routes(webmap.extract_api_routes(dres.body))

        if skipped_state:
            self.note(f"[crawl] did NOT follow {len(skipped_state)} link(s) that would "
                      f"have changed the target rather than read it: "
                      f"{', '.join(sorted(skipped_state)[:5])}")

        # Promote paths seen only as TEXT but sitting under a prefix this crawl has
        # fetched repeatedly. DVNA's open redirect lives at /app/redirect: the string is
        # in a page the crawl read, nothing links to it, and no keyword miner matches
        # "app". Without this it stayed invisible while the report said the class had
        # been probed nine times.
        try:
            promoted = surface.promote_mounted_routes()
            if promoted:
                self.note(f"[crawl] promoted {len(promoted)} unlinked route(s) under a "
                          f"proven mount prefix: {', '.join(promoted[:6])}")
        except Exception:
            pass

        # Resolve mined FRAGMENTS to paths this application actually answers. Must run
        # after the crawl (it needs paths that answered to align against) and before
        # anything consumes `api_routes` — the signup candidates and the surface the model
        # plans from both read that list.
        try:
            self.resolve_mined_routes()
        except Exception:
            pass

        # Soft-404 detection: probe one path that certainly does not exist. If the app
        # answers 200 (SPA fallback / catch-all route), a "200" from a path scanner does
        # NOT mean the path exists — flag it so the planner stops trusting path-discovery
        # hits (the #1 source of scanner false positives on modern web apps). One
        # governed, in-scope fetch.
        try:
            from urllib.parse import urlsplit
            sp = urlsplit(surface.seed)
            if sp.scheme and sp.netloc:
                probe = f"{sp.scheme}://{sp.netloc}/brukal_nonexistent_9zq7x8k.html"
                _d, pr, _h = self.run_web(f"get {probe}")
                if pr is not None and getattr(pr, "status", None) == 200:
                    surface.soft_404 = True
        except Exception:
            pass

        # An API that ships no HTML and no JS bundle still documents itself. Fetch the
        # well-known OpenAPI/Swagger paths and turn the declared endpoints into routes —
        # without this a pure JSON API (root = a one-line blob, no links) maps to nothing
        # at all. Bounded: stops at the first document that parses.
        try:
            from urllib.parse import urlsplit as _us
            sp = _us(surface.seed)
            if sp.scheme and sp.netloc:
                origin = f"{sp.scheme}://{sp.netloc}"
                for spec in webmap.SPEC_PATHS:
                    _d, sr, _h = self.run_web(f"get {origin}{spec}")
                    if sr is None or getattr(sr, "status", None) != 200:
                        continue
                    spec_routes = webmap.routes_from_openapi(sr.body or "")
                    if spec_routes:
                        surface.add_routes(spec_routes)
                        surface.techs.add("openapi")
                        # The spec also states which operations must be authenticated —
                        # the app's own contract, and free to check against reality.
                        for entry in webmap.protected_operations(sr.body or ""):
                            if entry not in surface.protected_routes:
                                surface.protected_routes.append(entry)
                        # The spec also names WHICH operations mutate a resource
                        # addressed by whose it is, and WHICH body fields a client is
                        # able to set. Both are what the authorization checks would
                        # otherwise have to guess, so take them from the app itself.
                        for entry in webmap.state_changing_operations(sr.body or ""):
                            if entry not in surface.write_operations:
                                surface.write_operations.append(entry)
                        for fname in webmap.writable_privileged_fields(sr.body or ""):
                            if fname not in surface.privileged_fields:
                                surface.privileged_fields.append(fname)
                        self.notes.append(
                            f"[api-spec] {spec} declared {len(spec_routes)} endpoint(s)")
                        break
        except Exception:
            pass

        # A second web surface (another port/vhost found later) ADDS to the map rather
        # than replacing it — otherwise crawling the app on :3000 would erase whatever
        # was learned from :80, and whichever ran last would win.
        if merge and self.surface is not None:
            prev = self.surface
            prev.pages |= surface.pages
            prev.links |= surface.links
            for f in surface.forms:
                if f not in prev.forms:
                    prev.forms.append(f)
            for b, names in surface.params.items():
                prev.params.setdefault(b, set()).update(names)
            prev.techs |= surface.techs
            prev.add_routes(surface.api_routes)
            prev.soft_404 = prev.soft_404 or surface.soft_404
            surface = prev
        self.surface = surface
        # ASK THE TARGET WHAT IT HAS. Runs once, right after the surface is
        # published and before the model is first grounded, so what it sees is
        # what this application actually serves rather than what the last two
        # targets served. Bounded and rate-limited like every other request.
        try:
            if not getattr(self, '_discovered_content', False):
                self._discovered_content = True
                self.discover_content()
        except Exception as exc:
            self.note(f"[discovery] failed and was skipped "
                      f"({type(exc).__name__}: {str(exc)[:90]})")

        # CAPTURED TRAFFIC, folded in the moment a surface EXISTS to receive it.
        # Held at start-up by `capture.hold_for_surface` because `self.surface`
        # is None until this line runs — the first two attempts at this wiring
        # applied it earlier and silently learned nothing, which is the same
        # silent no-op shape as the audit.record and agent=probe bugs before it.
        try:
            from . import capture as _capture
            _n = _capture.drain_onto_surface(self)
            if _n:
                self.note(f"[capture] {_n} route(s) learned from real traffic "
                          f"— methods, parameters and auth shape included")
        except Exception as exc:
            self.note(f"[capture] could not be applied "
                      f"({type(exc).__name__}: {str(exc)[:90]})")
        summ = surface.summary()
        head = summ.splitlines()[0]
        self.highlights.append(("site-map", head))
        self.notes.append(f"[crawl] {summ}")
        self._persist_finding("crawl", f"crawl {surface.seed}", "ALLOW", head,
                              [("site-map", head)])
        return surface

    def discover_params(self, url: str, budget: int = 8) -> list:
        """Query parameters a route actually HONOURS, found by differential.

        This closes a gap that only shows up off the target it was built on. Brukal's
        injection sweep iterates crawled forms and query parameters; a single-page app
        has neither — Juice Shop's crawl returned 0 forms and 0 parameterised endpoints
        beside 60 mined API routes, so SQLi, XSS, LFI, SSTI and command injection never
        ran at all and were absent from the coverage table rather than clean. Brukal's
        own surface note had said "go after the API endpoints below, params, and
        injection", advice it was structurally unable to follow.

        Guessing a parameter name is cheap and wrong most of the time, so a guess is not
        acted on: a candidate counts only when it measurably CHANGES the response
        against a control request. That turns a wordlist into evidence about this
        specific route, and keeps the expensive injection probes for parameters that
        exist."""
        from .web import WebAction
        if self.browser is None or not url or "?" in url:
            return []
        try:
            _d, base = self.browser.run(WebAction("request", url=url, method="GET"))
        except Exception:
            return []
        if base is None or base.status >= 400:
            return []
        baseline = _norm_body((base.body or "")[:4000])
        found: list = []
        for name in self._PARAM_CANDIDATES[:max(1, budget)]:
            # The sweep sets a budget; a standalone call has none. getattr rather than
            # the attribute, so this method is usable outside confirm_surface.
            remaining = getattr(self, "_confirm_budget", None)
            if remaining is not None and remaining <= 0:
                break
            probe = f"{url}{'&' if '?' in url else '?'}{name}=brukalprobe1"
            try:
                _d, r = self.browser.run(WebAction("request", url=probe, method="GET"))
            except Exception:
                continue
            if r is None:
                continue
            # A parameter the app ignores yields the same page; one it uses does not.
            if r.status != base.status or _norm_body((r.body or "")[:4000]) != baseline:
                found.append(name)
        return found

    def discover_content(self, limit: int = 40) -> list:
        """Ask the target what it HAS, with the small list that pays per request.

        GAP #26: nothing in the harness had ever asked. ffuf and friends sat installed in
        the cage for the project's whole life, and recon was a wishlist carried over from
        the last two targets — 19 of 30 URLs on the first cold target were crAPI and Juice
        Shop paths on a PHP app.

        Probed through the GOVERNED BROWSER, not a sweeper: gated, audited, rate-limited
        by the same allowance as everything else, and self-captured, so a discovered path
        becomes a replay candidate instead of a line in tool output nothing reads.

        Measured on DVWA: 22 stack-aware words found 11 paths where 900 requests of a
        generic 4749-word list found one."""
        from . import discovery as _discovery
        from .web import WebAction
        surface = getattr(self, "surface", None)
        if surface is None or self.browser is None:
            return []
        if not _discovery.should_discover(surface):
            self.note("[discovery] SKIPPED: this host answers for paths that do not "
                      "exist, so every candidate would 'succeed' and the surface would "
                      "fill with fiction")
            return []
        base = (getattr(surface, "seed", "") or f"http://{self.target}/").rstrip("/")
        found = []
        for path in _discovery.high_yield_candidates(
                getattr(surface, "techs", None), limit=limit,
                observed=list(getattr(surface, "pages", ()) or ())):
            try:
                _dec, res = self.browser.run(
                    WebAction(kind="get", url=f"{base}{path}"), agent="recon")
            except Exception:
                break
            if res is None:
                break                      # our own gate or limiter — stop, do not
                                           # write the rest off as absent (GAP #8)
            st = getattr(res, "status", None)
            if st and st != 404 and st < 500:
                found.append(path)
                if path not in surface.api_routes:
                    surface.api_routes.append(path)
        if found:
            self.note(f"[discovery] {len(found)} path(s) found by asking the target: "
                      + ", ".join(found[:12]))
        return found

    def shell_captures(self) -> list:
        """Requests the agents made with `curl`, as capture records."""
        return list(getattr(self, "_shell_captures", []) or [])

    def auto_web_action(self) -> str | None:
        """If a web service has been found but not yet rendered, return the WEB
        render action for it — the 'web port open → look at the site with the real
        browser' reflex. Deterministic; still governed when run."""
        if self.browser is None:
            return None
        for url in self.web_urls_from_findings():
            if url not in self._rendered:
                return f"render {url}"
        return None

    def run_web(self, web_text: str):
        """Run a WEB action through the GOVERNED BROWSER (same gate + audit as a
        shell command, but it renders JS and can tamper requests). Records the
        outcome and learns from it exactly like `run`. Returns (decision, result,
        new_highlights)."""
        from .web import parse_web_action
        action = parse_web_action(web_text)
        if action is None or self.browser is None:
            why = "no browser wired" if self.browser is None else "unparseable web action"
            self.notes.append(f"[web] {web_text}\nNOT RUN — {why}")
            return None, None, []
        decision, result = self.browser.run(action, agent="strategist")
        return self._absorb_web(action, decision, result)

    def _absorb_web(self, action, decision, result):
        # THE WEB PLANE'S observation point — same door, same rule. A plane that receives
        # target output and does not pass it here is a plane whose findings cannot be
        # published, which is the defect this whole mechanism exists for.
        try:
            self._observe_record(getattr(action, "url", ""),
                                 getattr(result, "body", "") or "")
            self._observe_answer(getattr(action, "url", ""),
                                 getattr(result, "status", None))
        except Exception:
            pass
        """Fold one WEB outcome into session state (main-thread counterpart to the
        thread-safe browser.run, used by the parallel runner)."""
        if action is not None and action.kind in ("navigate", "get") and action.url:
            self._rendered.add(action.url)     # don't auto-render the same page twice
        new_hl: list[tuple[str, str]] = []
        if result is not None:
            body = (result.body or "").strip()
            new_hl = highlight_findings(body)
            self.highlights.extend(h for h in new_hl if h not in self.highlights)
            head = f"{decision.verdict}: {result.note or ''} status={result.status}".strip()
            self.notes.append(f"[web] {action.describe()}\n{head}\n{body[:600]}")
            # The body goes on the RECORD too, not only into the rolling note window.
            # `PUT /api/BasketItems/1 {"quantity":-100}` answered 200 on a live run and
            # the record kept `status=200 (154B)` — a business-logic hit reduced to a
            # status line, unreadable, un-escalatable, and locked out by the repeat
            # coach three steps later. Notes are in-memory and roll off; this record is
            # what _load_memory reads back and what survives a checkpoint. Bounded,
            # because a digest is not a dump; redaction is applied at the blackboard
            # boundary (write_finding -> redact.data), which covers target-echoed
            # credentials in this text.
            lead = ("; ".join(f"{t}: {l}" for t, l in new_hl[:6])
                    or f"{head} ({len(body)}B)")
            summary = f"{lead}\n{body[:800]}" if body else lead
            self._persist_finding("web", action.describe(), decision.verdict, summary, new_hl)
            self._advance_plan()
        else:
            self.notes.append(f"[web] {action.describe()}\nNOT RUN — {decision.verdict} "
                              f"({decision.layer}: {decision.reason})")
            self._persist_finding("web-blocked", action.describe(), decision.verdict,
                                  f"{decision.layer}: {decision.reason}", [])
        if self.lessons is not None:
            tech = sorted({m.lower() for _t, ln in new_hl for m in _TECH_HINTS.findall(ln)})
            self.lessons.learn_from_outcome(action.describe(), decision, result, tech)
        return decision, result, new_hl

    def run_options_parallel(self, options, max_workers: int = 4):
        """Fan out: run the SAFE (gate-ALLOW) enumeration options CONCURRENTLY —
        the 'main agent dispatches sub-tasks in parallel' idea, inside solve/auto.
        Only actions the gate would ALLOW run in parallel (escalations/denials are
        left for sequential handling, since they need approval / are unproductive).
        Executes in worker threads (thread-safe backends + locked audit), then
        absorbs every outcome on THIS thread, so session state stays single-threaded.
        Returns a list of (label, decision, result, highlights); skipped options are
        reported with decision=None."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from .web import check_web, parse_web_action

        runnable, skipped = [], []
        for o in options:
            if o.command:
                d = self.executor._gate.check(o.command, self.target, "strategist")
                (runnable if d.verdict == "ALLOW" else skipped).append(
                    ("shell", o.command, o.command, d))
            elif o.web and self.browser is not None:
                a = parse_web_action(o.web)
                if a is None:
                    continue
                d = check_web(a, self.browser._scope, self.browser.current_url, "strategist")
                (runnable if d.verdict == "ALLOW" else skipped).append(
                    ("web", o.web, a, d))

        results = []
        if runnable:
            def _exec(kind, payload):
                if kind == "shell":
                    return self.executor.run(payload, self.target, agent="strategist")
                return self.browser.run(payload, agent="strategist")

            raw = {}
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futs = {pool.submit(_exec, kind, payload): (kind, label)
                        for kind, label, payload, _d in runnable}
                for f in as_completed(futs):
                    raw[futs[f]] = f.result()
            # absorb sequentially on the main thread (session state single-threaded)
            for (kind, label), (decision, result) in raw.items():
                if kind == "shell":
                    d, r, hl = self._absorb_shell(label, decision, result)
                else:
                    d, r, hl = self._absorb_web(parse_web_action(label), decision, result)
                results.append((label, d, r, hl))

        for kind, label, _payload, d in skipped:
            results.append((label, d, None, []))    # e.g. ESCALATE/DENY -> handle sequentially
        self.option_list = []
        return results

    def parallel_run(self, commands, max_workers: int = 4):
        """Enumerate INDEPENDENT things (several in-scope hosts/ports) CONCURRENTLY.

        Only gate-ALLOW commands run in parallel; anything the gate would DENY/ESCALATE
        is skipped and reported for sequential handling (approval is single-threaded).
        Execution happens in worker threads over the SAME one door — the audit log's
        append is atomic and the gate's rate window is lock-guarded (see gate.py), so
        concurrent writes can't corrupt the chain or the limiter — and every outcome is
        absorbed back on THIS thread, keeping session state single-threaded. Returns a
        list of (command, decision, result, highlights); skipped commands have result
        None. Never a parallel write to the rate limiter without its lock."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        runnable, skipped = [], []
        for cmd in commands:
            if not (cmd or "").strip():
                continue
            d = self.executor._gate.check(cmd, self.target, "strategist")
            (runnable if d.verdict == "ALLOW" else skipped).append((cmd, d))

        results = []
        if runnable:
            raw = {}
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futs = {pool.submit(self.executor.run, cmd, self.target, "strategist"): cmd
                        for cmd, _d in runnable}
                for f in as_completed(futs):
                    raw[futs[f]] = f.result()
            for cmd, (decision, result) in raw.items():        # absorb on the main thread
                d, r, hl = self._absorb_shell(cmd, decision, result)
                results.append((cmd, d, r, hl))

        for cmd, d in skipped:
            results.append((cmd, d, None, []))                 # ESCALATE/DENY -> sequential
        return results
