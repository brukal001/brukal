"""
assist_planning.py — the _PlanningMixin for AssistSession. Methods extracted verbatim
from assist.py (no logic change); composed back onto AssistSession in assist.py.
"""
from __future__ import annotations

import re
from .assist_util import (
    _TECH_HINTS,
)


class _PlanningMixin:

    # -- objectives --------------------------------------------------------- #

    def add_objective(self, text: str):
        if text.strip():
            self.objectives.append(text.strip())
            self._write_notebook()

    def _objectives_text(self) -> str:
        return "\n".join(f"- {o}" for o in self.objectives)

    def _state(self) -> str:
        return "\n".join(self.notes[-25:]) if self.notes else "(no findings yet)"

    # -- planning (the shortest path, made visible) ------------------------- #

    def _skill_focus(self, extra: str = "") -> str:
        """Build the query used to pull red-team playbooks from the LIVE state, not
        a fixed string. Keys off the current phase + the services/tech we've actually
        discovered (nginx, ssh, http, mysql, …), mined from the highlights and the
        objectives — NOT the raw objective prose, whose generic words ("find", "path")
        spuriously match unrelated playbooks. This is what makes the skill library
        track the engagement and inform each decision instead of returning the same
        irrelevant playbook every turn (or nothing at all for a bare IP)."""
        phase = ""
        if self.last is not None and self.last.phase:
            phase = self.last.phase
        elif self._current_step() is not None:
            phase = self._current_step().phase or ""
        # Mine service/tech terms from what we've seen + the objectives + the ask.
        corpus = " ".join(line for _tag, line in self.highlights[-12:])
        corpus += " " + " ".join(self.objectives) + " " + extra
        tech = sorted({m.lower() for m in _TECH_HINTS.findall(corpus)})
        terms = ([extra] if extra else []) + ([phase] if phase else []) + tech
        if not tech:                        # nothing found yet -> steer to recon packs
            terms += ["reconnaissance", "enumeration", "port", "scan", "service"]
        return " ".join(terms).strip() or self.target

    def set_methodology(self, mode: str | None = None):
        """Pick and store the engagement methodology — OWASP WSTG for a web app, the
        enumeration→foothold→privesc→loot flow for a box. `mode` ('web'/'box') forces
        it; otherwise it's detected from the target (URL/hostname → web, IP → box). The
        checklist then grounds every plan/decision, and its goal becomes the objective
        if none was set. Returns the Methodology."""
        from .methodology import Methodology, detect_kind
        self.methodology = Methodology(detect_kind(self.target, mode))
        if not self.objectives:
            self.add_objective(self.methodology.objective(self.target))
        return self.methodology

    def _reference(self, focus: str) -> str:
        """The guidance block fed to the strategist. Order = priority:
          0. ENGAGEMENT METHODOLOGY — the OWASP-WSTG / box checklist to follow (top).
          1. LEARNED LESSONS  — Brukal's own verified experience (trusted).
          2. LOCAL SKILL PACKS — vendored red-team playbooks (untrusted).
          3. FRESH WEB RESEARCH — on-demand retrieval (untrusted), LAST so local/
             verified knowledge ranks above fresh web. Control-plane egress only;
             degrades to "" on any failure. Everything here is guidance the model may
             use to PROPOSE — the gate still rules on every action."""
        parts = []
        if self.authenticated:
            # Tell the planner it is ALREADY logged in, so it stops wasting turns
            # re-logging-in and instead tests behind the login. Shell web-tools are
            # auto-given the session cookie (see _session_cookie_for); WEB actions
            # carry it natively.
            parts.append(
                "AUTHENTICATED SESSION ACTIVE — you are already logged in as the "
                "operator. Do NOT log in again. Test the pages BEHIND the login "
                "(the crawled site map lists them). Shell web-tools (sqlmap/curl/ffuf/"
                "nikto/…) are automatically given the session cookie; WEB actions carry "
                "it too. Go after the authenticated functionality: injection, access "
                "control, CSRF, file inclusion.")
        if self.cage_tools:
            # Ground the planner in what the cage ACTUALLY has, so a weak model stops
            # burning turns guessing tool/script paths that don't exist (e.g. inventing
            # five `git-dumper.py` locations). A hard constraint, so it leads.
            parts.append(
                "CAGE TOOLS INSTALLED (use ONLY these exact names; anything NOT listed "
                "is NOT installed — never invent a module/script path for it, pick an "
                "installed alternative):\n" + ", ".join(self.cage_tools))
        if self._ad_detected():
            from . import adscan
            parts.append(adscan.METHODOLOGY)
        if self._cloud_detected():
            from . import cloudscan
            parts.append(cloudscan.METHODOLOGY)
        if self._ai_detected():
            from . import aiscan
            parts.append(aiscan.METHODOLOGY)
        if self.methodology is not None:
            parts.append(self.methodology.checklist_text())
        if self.lessons is not None:
            parts.append(self.lessons.context_for(focus))
        if self.skills is not None:
            parts.append(self.skills.context_for(focus))
        if self.research is not None:
            # feed research the highlight text too — it carries service+version/CVE
            # that the distilled skill-focus string drops.
            rq = (self._highlights_text() + " " + focus).strip()
            try:
                parts.append(self.research.context_for(rq))
            except Exception:
                pass                          # research must never break planning
        return "\n\n".join(p for p in parts if p)

    def make_plan(self):
        """Ask the strategist for the shortest-path plan, keep completed steps
        marked, and persist it so a human can watch (and edit) the route."""
        ref = self._reference(self._skill_focus())
        new = self.strategist.plan(self.target, self._state(),
                                   self._objectives_text(), ref)
        # Fall back to the methodology checklist when the model gives a thin/empty plan,
        # so even a weak brain follows the full OWASP-WSTG / box flow rather than a
        # one-line plan.
        if self.methodology is not None:
            if len(new) < 2:
                new = self.methodology.as_plan_steps()
            else:
                # A plan long enough to pass the length check can still be missing the
                # phase the engagement is FOR. The methodology is the floor: a phase the
                # model left out is appended, keeping its own steps and their order.
                new = new + self.methodology.plan_steps_for(
                    self.methodology.missing_phases(new))
        done = self.plan_cursor                    # preserve progress across a re-plan
        self.plan = new
        self.plan_cursor = min(done, len(self.plan))
        for i in range(self.plan_cursor):
            if i < len(self.plan):
                self.plan[i].done = True
        self._persist_plan()
        return self.plan

    def _advance_plan(self):
        """Mark the current plan step done and move to the next."""
        step = self._current_step()
        if step is not None:
            step.done = True
            self.plan_cursor += 1
            self._persist_plan()

    def _plan_text(self) -> str:
        """The plan rendered with a ▶ on the step we're working on."""
        if not self.plan:
            return ""
        lines = []
        for i, st in enumerate(self.plan):
            mark = "x" if st.done else (">" if i == self.plan_cursor else " ")
            ph = f"[{st.phase}] " if st.phase else ""
            lines.append(f"{i + 1}. [{mark}] {ph}{st.text}")
        return "\n".join(lines)

    def _ad_detected(self) -> bool:
        """True if the recon so far shows a Windows/AD host (SMB/LDAP/Kerberos), so the
        planner gets the AD methodology and the AD detector's findings are relevant."""
        blob = " ".join(l for _t, l in self.highlights[-40:]) + " " + " ".join(self.notes[-8:])
        return bool(re.search(
            r"\b(?:445|389|88|636|3268|5985)/tcp\s+open|microsoft-ds|active directory|"
            r"\bkerberos\b|\bldap\b|domain controller|smb signing|netbios-ssn|\bnxc\b|"
            r"netexec|enum4linux", blob, re.I))

    def _cloud_detected(self) -> bool:
        """True if a cloud asset has been seen (a cloud fingerprint, bucket URL, cloud
        CNAME/host, or metadata endpoint), so the planner gets the cloud methodology."""
        blob = " ".join(l for _t, l in self.highlights[-40:]) + " " + " ".join(self.notes[-8:])
        return bool(re.search(
            r"amazonaws\.com|s3\b|blob\.core\.windows|storage\.googleapis|cloudfront|"
            r"\bx-amz-|x-ms-request-id|x-goog-|169\.254\.169\.254|AmazonS3|azurewebsites|"
            r"\bAKIA[0-9A-Z]{16}\b|service_account", blob, re.I))

    def _ai_detected(self) -> bool:
        """True if an LLM-backed feature (chatbot / assistant / copilot / completions API)
        has been seen in the recon, so the planner gets the AI methodology and the AI
        signatures run over tool output. Strict — an ordinary `/messages` page is not an
        AI target."""
        from . import aiscan
        blob = (" ".join(l for _t, l in self.highlights[-40:]) + " "
                + " ".join(self.notes[-8:]) + " " + " ".join(self._ai_endpoints()))
        return aiscan.looks_like_ai_feature(blob)

    def _ai_endpoints(self) -> list[str]:
        """URLs from the crawled surface that look like an LLM-backed endpoint — query
        endpoints, form actions, AND the API routes mined out of the JS bundle. That last
        source is the important one: a chatbot on a SPA ships no form and no query
        parameter, so `/rest/chatbot/respond` only ever appears as a mined route."""
        from urllib.parse import urljoin

        from . import aiscan
        urls: list[str] = []
        if self.surface is None:
            return urls
        for u in list(getattr(self.surface, "params", {}) or {}):
            if aiscan.looks_like_ai_endpoint(u):
                urls.append(u)
        for form in list(getattr(self.surface, "forms", []) or []):
            a = getattr(form, "action", "") or ""
            if a and aiscan.looks_like_ai_endpoint(a):
                urls.append(a)
        base = getattr(self.surface, "seed", "") or f"http://{self.target}"
        for route in list(getattr(self.surface, "api_routes", []) or []):
            if not aiscan.looks_like_ai_endpoint(route):
                continue
            urls.append(route if route.startswith("http") else urljoin(base, route))
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def ad_enum_commands(self) -> list[str]:
        """Read-only Active Directory enumeration the loop fires PROACTIVELY once a
        DC/SMB/LDAP/Kerberos host is detected — the internal-network analogue of the web
        crawl+confirm reflexes, so AD coverage doesn't depend on the model proposing it.

        The proactive set is UNAUTHENTICATED and read-only ONLY: null/guest-session host
        info, share and RID-cycled user enumeration, password policy, LDAP anonymous
        bind. No credential spray (so no account-lockout risk), no dump/relay/roast/
        exploit — those stay with the planner (they ESCALATE, or run under --full-send).
        Every command still passes the gate (scope + allowlist) at run time."""
        if not self._ad_detected():
            return []
        t = self.target
        return [
            f"netexec smb {t}",              # host/domain, SMB signing, SMBv1, null session
            f"netexec smb {t} --shares",     # anonymous / guest share listing
            f"netexec smb {t} --users",      # RID-cycle domain users (read-only)
            f"netexec smb {t} --pass-pol",   # password policy (lockout threshold)
            f"netexec ldap {t}",             # LDAP anonymous bind / naming contexts
            f"enum4linux-ng -A {t}",         # comprehensive read-only enumeration
        ]

    def cloud_enum_commands(self) -> list[str]:
        """Read-only cloud enumeration the loop fires PROACTIVELY once a cloud asset is
        seen — anonymous object-storage listing of any S3 bucket named in the recon so
        far. Read-only ONLY (no writes). Each command is still gated: a cloud host
        OUTSIDE the authorised scope is DENIED — Brukal never touches an asset you did
        not authorise, which is the trust guarantee, not a limitation. So this yields
        autonomous cloud coverage exactly when the operator has scoped the cloud in."""
        if not self._cloud_detected():
            return []
        blob = (" ".join(l for _t, l in self.highlights[-40:]) + " "
                + " ".join(self.notes[-8:]))
        buckets = {b.lower() for b in self._BUCKET_RE.findall(blob)}
        buckets |= {b.lower() for b in self._BUCKET_URI_RE.findall(blob)}
        cmds: list[str] = []
        for b in sorted(buckets)[:3]:
            cmds.append(f"curl -s https://{b}.s3.amazonaws.com/")
            cmds.append(f"aws s3 ls s3://{b} --no-sign-request")
        return cmds

    def _highlights_text(self) -> str:
        base = "\n".join(f"{t}: {l}" for t, l in self.highlights) if self.highlights else ""
        # If the site has been crawled, hand the FULL attack surface (forms, params,
        # endpoints) to the planner/specialists — this is what turns endpoint guessing
        # into reasoning over real targets. Untrusted data; the gate still rules.
        if self.surface is not None and self.surface.pages:
            base = f"{base}\n{self.surface.summary()}" if base else self.surface.summary()
            sugg = self._probe_suggestions_text()
            if sugg:
                base = f"{base}\n{sugg}"
        return base

    def _tried_text(self, limit: int = 15) -> str:
        """The recent commands that actually executed — fed to the planner as
        ALREADY TRIED so it stops re-proposing them. De-duped, most recent last."""
        seen, out = set(), []
        for c in self.executed_cmds:
            if c not in seen:
                seen.add(c); out.append(c)
        return "\n".join(f"- {c}" for c in out[-limit:])

    def advise(self, question: str = ""):
        ref = self._reference(self._skill_focus(question))
        self.last = self.strategist.advise(
            self.target, self._state(), question, ref, self._objectives_text(),
            self._plan_text(), known=self._highlights_text(), tried=self._tried_text())
        return self.last

    def advise_options(self, question: str = "", n: int = 3):
        """Ask for a RANKED list of next moves so the operator can pick one, tweak
        it, or give their own instruction. Falls back to a single-item list."""
        ref = self._reference(self._skill_focus(question))
        opts = self.strategist.options(
            self.target, self._state(), question, ref, self._objectives_text(),
            self._plan_text(), n=n, known=self._highlights_text(), tried=self._tried_text())
        if not opts:                       # never leave the operator with nothing
            opts = [self.advise(question)]
        self.option_list = opts
        self.last = opts[0]
        return opts

    def plan_context(self) -> str:
        """The grounded context handed to a specialist agent (recon/exploit/verify)
        when it generates a command in multi-agent mode. It is deliberately the SAME
        material the strategist reasons over — verified findings (KNOWN), what has
        already been tried (so the specialist doesn't repeat it), and the objective —
        so routing execution to a role never means reasoning on thinner ground. All
        of it is untrusted environment-derived DATA; the gate remains the safeguard."""
        parts: list[str] = []
        known = self._highlights_text()
        if known:
            parts.append(f"KNOWN (verified findings so far):\n{known}")
        tried = self._tried_text()
        if tried:
            parts.append(f"ALREADY TRIED (do NOT repeat these):\n{tried}")
        obj = self._objectives_text()
        if obj:
            parts.append(f"OBJECTIVE:\n{obj}")
        return "\n\n".join(parts)

    def _persist_plan(self):
        if self.blackboard is None:
            return
        body = self._plan_text() or "_(no plan yet)_"
        self.blackboard.write_page(
            "plan.md",
            f"# Plan — {self.target}\n\n"
            f"> Shortest path to the goal. `x` done · `>` current · ` ` pending. "
            f"Edit freely; Brukal re-plans from findings.\n\n{body}\n")
        self._write_notebook()
