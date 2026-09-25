"""
assist_findings.py — the _FindingsMixin for AssistSession. Methods extracted verbatim
from assist.py (no logic change); composed back onto AssistSession in assist.py.
"""
from __future__ import annotations

import re
from .assist_util import (
    _CALIBRATION_MIN_RATE,
    _LOGOUT_RE,
    _PATH_SCANNERS,
    _TECH_HINTS,
    _is_raw_fetch,
    _parse_saved_plan,
    _tool_of,
)


class _FindingsMixin:

    def _current_step(self):
        return self.plan[self.plan_cursor] if self.plan_cursor < len(self.plan) else None

    def record_verified_success(self, verified):
        """A success was CONFIRMED from real gated SHELL output (see verify.py). Promote
        it to the trusted lesson store with provenance, so the brain grows only from
        verified wins, and record it as a CONFIRMED, critical finding in the report.

        Defence in depth: this refuses an UNCONFIRMED (web-sourced) lead — it must never
        write a confirmed critical finding or a trusted lesson from target-controlled
        text. Such leads go through `record_candidate_lead` instead."""
        if not getattr(verified, "confirmed", True):
            return self.record_candidate_lead(verified)
        from .findings import Finding
        self.findings.add(Finding(
            title=str(getattr(verified, "kind", "foothold")).replace("_", " "),
            severity="critical", target=self.target,
            evidence=getattr(verified, "evidence", "")[:200],
            source=getattr(verified, "command", ""), category="access",
            confirmed=True))
        if self.lessons is None:
            return None
        tech = sorted({m.lower() for m in _TECH_HINTS.findall(self._highlights_text())})
        tool = (verified.command.split() or [""])[0].lstrip("`").split("/")[-1].lower()
        service = ", ".join(tech[:3]) or self.target
        tags = [t for t in ([tool] + tech) if t]
        return self.lessons.record_verified_success(
            target=self.target, service=service, command=verified.command,
            outcome=f"{verified.kind}: {verified.evidence[:80]}", tags=tags)

    def record_candidate_lead(self, verified):
        """An UNCONFIRMED success lead (a flag/foothold-like string seen in
        target-controlled WEB output). Record it as a CANDIDATE finding (never
        confirmed) and a CANDIDATE lesson (never retrieved), so the signal is not lost
        but nothing target-controlled can end the run as 'solved', inject a confirmed
        critical finding, or poison the trusted lesson store. Confirm it with a fresh
        gated shell command before believing it."""
        from .findings import Finding
        self.findings.add(Finding(
            title=f"unconfirmed {str(getattr(verified, 'kind', 'foothold')).replace('_', ' ')} "
                  f"(web-sourced, needs shell confirmation)",
            severity="info", target=self.target,
            evidence=getattr(verified, "evidence", "")[:200],
            source=getattr(verified, "command", ""), category="access",
            confirmed=False))
        if self.lessons is not None:
            try:
                self.lessons.add(
                    f"saw a {verified.kind}-like string in web output of "
                    f"`{verified.command}` — confirm with a shell command before trusting.",
                    tags=["candidate-lead", verified.kind], kind="reference",
                    tier="candidate")
            except Exception:
                pass
        return None

    def ask(self, question: str) -> str:
        """Answer the operator's question about the hunt, grounded in real findings.
        A conversational reply — runs nothing, changes no state."""
        ref = self._reference(self._skill_focus(question))
        return self.strategist.answer(
            self.target, question, self._state(), self._highlights_text(),
            plan=self._plan_text(), reference=ref)

    def _record_ad_finding(self, command: str, sev: str, label: str, line: str) -> None:
        """Record one Active Directory attack indicator from real tool output. The target
        is the IP in the command (a DC/host), not the web target. Definitive results
        (a captured hash, Pwn3d!, valid creds, a named CVE) are CONFIRMED."""
        from .findings import Finding
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", command)
        target = m.group(1) if m else self.target
        self.findings.add(Finding(
            title=label, severity=sev, target=target, evidence=line, source=command,
            category="active-directory", confirmed=label in self._CONFIRMED_AD_LABELS))

    def _record_cloud_finding(self, command: str, sev: str, label: str, line: str) -> None:
        """Record one cloud/infra finding. Target = the bucket/host/URL in the command
        if present, else the engagement target. Definitive results (a leaked SA key, a
        listable bucket, IMDS creds, a live ARN) are CONFIRMED."""
        from . import cloudscan
        from .findings import Finding
        m = re.search(r"https?://[^\s\"']+", command)
        target = m.group(0) if m else self.target
        self.findings.add(Finding(
            title=label, severity=sev, target=target, evidence=line, source=command,
            category="cloud", confirmed=label in cloudscan.CONFIRMED_CLOUD_LABELS))

    def _record_ai_finding(self, command: str, sev: str, label: str, line: str) -> None:
        """Record one AI/LLM finding from a real model response. Target = the endpoint URL
        in the command if present. Definitive results (a secret in the output, a leaked
        system prompt, an acknowledged jailbreak) are CONFIRMED — the model emitting what
        it must not IS the proof."""
        from . import aiscan
        from .findings import Finding
        m = re.search(r"https?://[^\s\"']+", command)
        target = m.group(0) if m else self.target
        self.findings.add(Finding(
            title=label, severity=sev, target=target, evidence=line, source=command,
            category="ai", confirmed=label in aiscan.CONFIRMED_AI_LABELS))

    def _record_vuln_finding(self, command: str, sev: str, label: str, line: str) -> None:
        """Turn one vuln SIGNAL from real output into a structured, deduplicated
        finding for the report. Evidence-backed by construction — it only ever runs on
        the stdout of a gate-executed command."""
        from .findings import Finding
        m = re.search(r"https?://[^\s\"']+", command)
        target = m.group(0) if m else self.target
        pm = re.search(r"-p\s+(\S+)", command)
        param = pm.group(1) if pm else ""
        # On a soft-404 host, a PATH-DISCOVERY scanner (nikto / dir-brute) reports a
        # "found" file for every path because everything returns 200 — its high/medium
        # verdicts are false. Downgrade to an info lead (still recorded, no longer
        # misleading). Content-based tools (sqlmap/nuclei) are untouched.
        tool = _tool_of(command)
        if (self.surface is not None and getattr(self.surface, "soft_404", False)
                and tool in _PATH_SCANNERS and sev in ("high", "medium")):
            sev = "info"
            line = f"{line} — UNVERIFIED (host soft-404s: 200 for any path)"
        confirmed = (label in self._CONFIRMED_VULN_LABELS
                     or (label in self._SELF_EVIDENT_EXPOSURES and _is_raw_fetch(command)
                         and not line.endswith("200 for any path)")))
        self.findings.add(Finding(
            title=label, severity=sev, target=target, evidence=line,
            source=command, param=param, category="web", confirmed=confirmed))

    def _record_ownership(self, who: str, source: str, path: str, value) -> None:
        """WHO OWNS WHAT, onto the ledger, with the response that said so.

        `5e7219a` taught the harness each principal's own identifiers and wrote them to
        the PROMPT and to nothing else. Run CM3 then produced the exact event the
        capability milestone exists for — principal A read a basket belonging to the
        second principal — and no artifact could say so: grepped across the whole CM3
        bundle, the disclosure block occurs zero times and no `bid` occurs anywhere in
        the ledger. The ownership map lived in memory and in a model's context window,
        so a reader holding the bundle could not evaluate an ownership claim at all.

        This is the August principal-provenance defect (`2fdbc7f`) in a new form. That
        one recorded which principal ISSUED a request; this records which principal OWNS
        a resource, and for the same reason: without it a sound finding and a
        manufactured one are byte-identical.

        SOURCE is carried, not just the value, because an ownership map with no
        provenance is the 2C2 external-seeding defect wearing a new hat — a reader must
        be able to see WHICH response attributed the id, not take our word for it.

        An audit `kind` rather than a new writer, so it inherits `redact.data` exactly
        like every other record. Nothing here re-implements redaction: a credential that
        arrives under an id-shaped key is masked by the funnel, not by a rule invented
        at this call site."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None:
            return
        audit.append("principal_ownership", {
            "principal": who,
            "name": path.rsplit(".", 1)[-1],
            "value": value,
            "source": source,
            "path": path,
            "target": self.target,
        })

    def _record_candidate(self, target, title, sev, param, evidence, category="web") -> None:
        from .findings import Finding
        self.findings.add(Finding(title=title, severity=sev, target=target, evidence=evidence,
                                  source=f"active probe · param={param}", param=param,
                                  category=category, confirmed=False))
        self.notes.append(f"[lead] {title} on {target} param '{param}' — {evidence}")

    def calibrate(self, max_requests: int = 4):
        """Learn what this application's answers mean, before anything is judged.

        Four gated requests buy every later comparison a baseline drawn from the target
        instead of from a constant somebody wrote against a different application. The
        denial baseline is the valuable one: it is what `a_denied_b_allowed` needed and
        did not have, and its absence meant an app that refuses with a redirect to
        /login could not produce an authorization finding at all.

        Read-only, and it never concludes anything on its own — a profile only makes
        later evidence interpretable."""
        from . import calibrate as _cal
        from .web import WebAction
        profile = _cal.TargetProfile()
        if self.browser is None:
            self.profile = profile
            return profile
        # Calibration is OVERHEAD, and overhead must not starve the work. On a tightly
        # rate-limited engagement the handful of requests it costs are requests not
        # spent probing — measured: on a 30/min scope those few tipped the run over the
        # wall and a confirmed injection finding was lost. Above that, the cost is
        # noise and the accuracy it buys applies to every later comparison, so the
        # trade is worth making explicitly rather than accidentally.
        scope = getattr(self.browser, "_scope", None)
        per_min = getattr(scope, "rate_limit_per_min", None) if scope else None
        if isinstance(per_min, int) and 0 < per_min < _CALIBRATION_MIN_RATE:
            self.profile = profile
            self.note(f"[calibration] skipped: the scope allows only {per_min} "
                      f"request(s)/min, and those are better spent probing. Later "
                      f"comparisons fall back to their built-in rules.")
            return profile
        surface = getattr(self, "surface", None)
        base = (getattr(surface, "seed", "") if surface else "") or f"http://{self.target}/"

        def fetch(url, anonymous=False):
            try:
                if anonymous:
                    with self._separate_identity():
                        return self.browser.run(WebAction("request", url=url,
                                                          method="GET"))[1]
                return self.browser.run(WebAction("request", url=url, method="GET"))[1]
            except Exception:
                return None

        # 1) What a page we are ALLOWED to see looks like.
        profile.learn_ok(fetch(base), base)
        # 2) What "no such thing" looks like. Reuses the soft-404 idea, but keeps the
        #    whole response rather than only the yes/no, because the SHAPE is what later
        #    comparisons need.
        import uuid as _uuid
        from urllib.parse import urljoin as _urljoin
        miss = _urljoin(base, f"/brukal-absent-{_uuid.uuid4().hex[:12]}")
        profile.learn_missing(fetch(miss), miss)
        # 3) What a REFUSAL looks like: a resource we have reached WITH a session, asked
        #    again WITHOUT one. Anything that changes between those two answers is the
        #    application telling us how it says no. Skipped when we hold no session,
        #    since then there is no privileged resource to compare against.
        if self.has_session():
            protected = ""
            for page in sorted(getattr(surface, "pages", set()) or []):
                if page != base and not _LOGOUT_RE.search(page):
                    protected = page
                    break
            if protected:
                anon = fetch(protected, anonymous=True)
                mine = fetch(protected)
                if (anon is not None and mine is not None
                        and not _cal.Sample(anon).resembles(_cal.Sample(mine))):
                    profile.learn_denied(anon, protected)
        self.profile = profile
        if profile.notes:
            self.note(profile.summary())
        return profile

    def learn(self, query: str) -> str:
        """First-class internet learning. Look `query` up from the allowlisted
        CONTROL-PLANE sources (verified + web; NEVER the cage), fold the UNTRUSTED
        result into the notes so the planner sees it, and persist it as a CANDIDATE
        lesson only — recall reads TRUSTED lessons, so a poisoned page can never
        auto-teach a bad habit (a human/verification promotes it). Deduped per query;
        returns the rendered reference, or "" if research is off / nothing found."""
        q = (query or "").strip()
        if not q or self.research is None or q.lower() in self._learned:
            return ""
        self._learned.add(q.lower())
        from . import research as _r
        try:
            snippets = self.research.learn(q)
        except Exception:
            snippets = []
        text = _r.render(snippets)
        if not text:
            self.notes.append(f"[learn] {q}\n(no results from the allowlisted sources)")
            return ""
        self.notes.append(f"[learn] researched '{q}':\n{text[:600]}")
        self.highlights.append(("learned", f"researched '{q}' "
                                            f"({len(snippets)} source hit(s))"))
        if self.lessons is not None:                # candidate tier only — poison-proof
            for s in snippets[:3]:
                try:
                    self.lessons.add(f"[research:{s.source}] {s.query}: {s.text[:200]}",
                                     tags=[s.source, "research"], kind="reference",
                                     tier="candidate")
                except Exception:
                    pass
        return text

    def research_todo(self) -> list[str]:
        """Specific things worth looking up from the live findings (CVE ids, service+
        version pairs) that haven't been researched yet — drives the auto-learn reflex."""
        if self.research is None:
            return []
        from .research import _query_terms
        return [t for t in _query_terms(self._highlights_text())
                if t.lower() not in self._learned]

    def note(self, text: str):
        self.notes.append(f"[note] {text}")
        self._persist_finding("note", "", "", text, [])

    def manual(self, text: str):
        """Record an out-of-cage action the operator performed themselves."""
        self.notes.append(f"[manual] {text}")
        self._persist_finding("manual", "", "", text, [])

    # -- persistence + resume ---------------------------------------------- #

    def _persist_finding(self, kind, command, verdict, summary, highlights):
        if self.blackboard is None:
            return
        self.blackboard.write_finding("strategist", {
            "target": self.target, "task": kind, "command": command,
            "verdict": verdict, "summary": summary,
            "highlights": [list(h) for h in highlights],
        })
        self._write_notebook()

    def _write_notebook(self):
        """A single human-readable engagement page: objectives, plan, what we
        know, and the timeline — the thing you open in Obsidian to see the story."""
        if self.blackboard is None:
            return
        parts = [f"# Engagement — {self.target}\n"]
        if self.objectives:
            parts.append("## Objectives\n" +
                         "\n".join(f"- [ ] {o}" for o in self.objectives) + "\n")
        if self.plan:
            parts.append("## Plan (shortest path)\n" + self._plan_text() + "\n")
        if self.highlights:
            parts.append("## What we know\n" +
                         "\n".join(f"- **{t}** — {l}" for t, l in self.highlights[-20:]) + "\n")
        if self.notes:
            parts.append("## Timeline\n" +
                         "\n".join(f"- {n.splitlines()[0]}" for n in self.notes[-40:]) + "\n")
        self.blackboard.write_page("engagement.md", "\n".join(parts))

    def _load_memory(self):
        """Resume: pull prior findings + plan for this target back into context."""
        prior = self.blackboard.all_findings(self.target)
        for rec in prior:
            summ = rec.get("summary", "")
            self.notes.append(f"[{rec.get('task', 'note')}] {summ}")
            for h in rec.get("highlights", []):
                pair = tuple(h)
                if len(pair) == 2 and pair not in self.highlights:
                    self.highlights.append(pair)
        self.resumed = len(prior)
        self.plan = _parse_saved_plan(self.blackboard.read_page("plan.md"))
        self.plan_cursor = sum(1 for st in self.plan if st.done)
