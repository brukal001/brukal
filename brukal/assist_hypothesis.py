"""
assist_hypothesis.py — the _HypothesisMixin for AssistSession. Methods extracted verbatim
from assist.py (no logic change); composed back onto AssistSession in assist.py.
"""
from __future__ import annotations

from . import redact
import json
import random
import re


class _HypothesisMixin:

    @classmethod
    def _is_destructive_path(cls, url: str) -> bool:
        """True if a path names an operation that CHANGES STATE, whatever method reaches
        it. "Read-only" is a property of the method, not the endpoint: applications
        routinely expose administrative actions behind a plain GET. Brukal learned this
        by wiping its own test target — /createdb was mined as an ordinary route, the
        exposure pass fetched it like any other listing, and the database was
        reinitialised out from under the run."""
        from urllib.parse import urlsplit
        path = urlsplit(url or "").path if "//" in (url or "") else (url or "")
        for segment in path.split("/"):
            if not segment:
                continue
            for token in re.split(r"[-_.]", segment.lower()):
                if token in cls._DESTRUCTIVE_WORDS:
                    return True
        return False

    @classmethod
    def _is_destructive_request(cls, method: str, url: str) -> bool:
        """Judge the REQUEST, not just the path.

        `_is_destructive_path` reads words out of the URL — reset, drop, wipe — and
        crAPI challenge 7 is `DELETE /identity/api/v2/user/videos/9`, which contains no
        such word. While the prompt forbade destructive proposals outright that gap was
        invisible; the moment the prompt is allowed to ask for them, a DELETE on an
        innocuous-looking path would execute having never reached the approver.

        Both rules apply, and neither replaces the other: the URL rule still catches
        /createdb behind a plain GET, which is how Brukal once wiped its own test
        target."""
        if (method or "").upper() in cls._DESTRUCTIVE_METHODS:
            return True
        return cls._is_destructive_path(url)

    def _record_experiment_proposed(self, h) -> None:
        """EVERY proposal, on the ledger, before anything can refuse it.

        Run CM5 exposed why this has to exist. The funnel — proposed / dispatched /
        resolved / judged / confirmed — was computed for five runs by reading
        `[experiment]` lines out of `engagement.md`, and `_write_notebook` renders
        `notes[-40:]`. CM5 ran 70 steps, the window evicted every one of those lines, and
        the file ended up containing the string "experiment" zero times.

        Nothing was lost that mattered — the dispatch records survived — but `proposed`
        was not derivable from the ledger AT ALL: a proposal left no record until it
        dispatched or ran a setup, so a zero-setup proposal refused at reference
        resolution was invisible. A published count that can only be obtained from a
        truncating human note is not a measurement. Third instance in this project of a
        self-report disagreeing with the ledger."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None:
            return
        audit.append("experiment_proposed", {
            "title": getattr(h, "title", ""),
            "comparator": getattr(h, "comparator", ""),
            "setup_steps": len(getattr(h, "setup", []) or []),
            "control_as": (getattr(h, "control", {}) or {}).get("as", "self"),
            "variant_as": (getattr(h, "variant", {}) or {}).get("as", "self"),
            "control_url": (getattr(h, "control", {}) or {}).get("url", ""),
            "variant_url": (getattr(h, "variant", {}) or {}).get("url", ""),
            "target": self.target,
        })

    def _record_experiment_outcome(self, h, outcome: str) -> None:
        """The TERMINAL state of one proposal, whatever it was.

        Written at all eleven exits, including the six that refuse before dispatch, so
        `dispatched`, `resolved` and `judged` stop being inferences. Before this, nothing
        distinguished "reached a comparator and did not hold" from "never judged" —
        except `cross_account_resource`, which writes `ownership_match` either way, which
        is exactly why the cross-account line was the one part of CM5's funnel that WAS
        derivable from the record."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None:
            return
        from . import hypothesis as _hyp
        audit.append("experiment_outcome", {
            "title": getattr(h, "title", ""),
            "comparator": getattr(h, "comparator", ""),
            "outcome": outcome,
            "stage": _hyp.outcome_stage(outcome),
            # WHY this produced no measurement, or that it produced one. Derived from the
            # terminal in one deterministic table so a reader recomputes it, and CR1's
            # "every outcome attributed, none unaccounted" is a number instead of a hope.
            "attribution": _hyp.attribution(outcome),
            "target": self.target,
        })

    def _record_experiment_result(self, role: str, url: str, result) -> None:
        """ONE experiment side's answer, INCLUDING a bounded excerpt of its body.

        Run CM3 dispatched the exact request the capability milestone is about — principal
        A reading `/rest/basket/8`, whose body said `"UserId":27` — and the ledger kept
        `{"status":200,"url":...,"note":"","bytes":154}`. **The field that made it a
        cross-account read was never written down**, so the finding could be derived, felt
        and argued, and not checked.

        The web plane got body capture in August (`_absorb_web`); the experiment plane,
        which is the one that produces findings, did not. A comparator's verdict is only
        as citable as the evidence beside it, and `bytes` is not evidence.

        Recorded for BOTH sides, immediately after each dispatch rather than after the
        judgement, so a pair that never reaches a comparator still leaves its answers
        behind — the refusals above this call site all `continue`, and a record written
        later would be exactly the one missing whenever something went wrong.

        `redact.data` in `audit.append` is the funnel, as everywhere else. That matters
        more here than anywhere: capturing a body verbatim is precisely how a credential
        the TARGET discloses reaches an artifact, which is the open P1 recorded below."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None or result is None:
            return
        from . import hypothesis as _hyp
        raw = getattr(result, "body", "") or ""
        # The other place target output enters the record. Same rule, same funnel: a
        # value this response NAMED a secret is registered before the excerpt is written.
        redact.observe_response(raw)
        excerpt, cut = _hyp.body_excerpt(raw)
        audit.append("experiment_result", {
            "role": role or "unknown",
            "url": url,
            "status": getattr(result, "status", None),
            "bytes": len(raw),
            "body": excerpt,
            "truncated": cut,
            "target": self.target,
        })

    def _record_ownership_match(self, h, vspec, variant_result, variant_as, held) -> None:
        """WHY a cross-account verdict went the way it did, onto the ledger.

        The matched identifier, its path in the response body, whether it was the
        ADDRESSED resource, the recorded owner, and the verdict. Written for refusals as
        well as confirmations, because the refusals are where an integer coincidence gets
        declined — on a target whose id spaces overlap, that is the interesting half.

        A reader can then CHECK the match against the `principal_ownership` records and
        the captured body, instead of taking a HIGH cross-account title on trust, which is
        exactly the failure `1940f09` was written for."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None:
            return
        from . import hypothesis as _hyp
        ev = _hyp.ownership_evidence(vspec, getattr(variant_result, "body", ""),
                                     self.principal_identifiers(), variant_as)
        audit.append("ownership_match", {
            "held": bool(held),
            "variant_as": variant_as,
            "owner": ev["owner"],
            "value": str(ev["value"]),
            "addressed": ev["addressed"],
            "body_path": ev["path"],
            "corroborating": [f"{p}={v} ({o})" for p, v, o in ev["corroborating"]],
            "url": (vspec or {}).get("url", ""),
            "target": self.target,
        })

    def queue_self_capture_experiments(self, max_new: int = 4) -> int:
        """Turn requests BRUKAL ITSELF made into experiments, and queue them.

        The replay consumer has existed since capture.py landed and could only ever be fed
        by an operator handing over a HAR. Every request the governed browser makes is
        already recorded at its own door; each one is an experiment whose CONTROL PROVABLY
        WORKED — we issued it and the target answered. Re-issuing it as `second` or
        `anonymous` is the cross-principal question the comparators were built to judge,
        and a captured WRITE is the `state_changed` shape that no model in either series
        has ever proposed.

        Queued onto `_derived_hypotheses`, which the loop already drains every turn at no
        model cost, so this needs no new scheduling."""
        # ABLATION CONTROL. Arm C of a three-arm measurement: capture-enriched GROUNDING
        # with the harness's derived experiments suppressed, so the model sees the better
        # surface but no worked example of the construction. Without this, "the grounding
        # named the write surface" and "the model copied an experiment it was shown" both
        # predict the same result and neither can be credited.
        import os as _os
        if _os.environ.get("BRUKAL_NO_CAPTURE_REPLAY"):
            return 0
        browser = getattr(self, "browser", None)
        if browser is None or not hasattr(browser, "captured"):
            return 0
        # ALL THREE PRODUCERS: what the browser did, what the shell did, and what the
        # OPERATOR handed over. The last is the only source of writes a human actually
        # performs — the harness makes almost none itself, which is the boundary
        # self-capture cannot cross.
        caps = (browser.captured() + self.shell_captures()
                + list(getattr(self, "_captured_for_replay", []) or []))
        if not caps:
            return 0
        from . import capture as _capture
        # Dedup against EVERYTHING ever queued, not the current queue: the loop drains it
        # every turn, so queue-only dedup forgets what it consumed and re-derives the same
        # experiment next turn. A live run proposed one question 13 times that way.
        ever = getattr(self, "_capture_replay_seen", None)
        if ever is None:
            ever = self._capture_replay_seen = set()
        seen = set(ever) | {(h.comparator, h.control.get("url"))
                            for h in self.derived_hypotheses()}
        queued = 0
        # REUSE EXPERIMENTS FIRST. They come from the relational links — a value the
        # application itself handed back, accepted again — which is the only question here
        # that a structural map cannot pose, and there are never many of them.
        _derived = []
        try:
            _links = list(getattr(getattr(self, "surface", None), "field_links", []) or [])
            if _links:
                _base = (getattr(self.surface, "seed", "")
                         or f"http://{self.target}/").rstrip("/")
                _derived.extend(_capture.reuse_experiments(_links, caps, base=_base))
                # And the question crAPI's own error pointed at: a value issued to ONE
                # principal, submitted by ANOTHER. Both sides run as `second`, so the
                # readiness rule holds these until that principal exists.
                _derived.extend(
                    _capture.foreign_value_experiments(_links, caps, base=_base))
        except Exception as exc:
            self.note(f"[capture] reuse experiments could not be derived "
                      f"({type(exc).__name__}: {str(exc)[:80]})")
        _derived.extend(_capture.hypotheses_from(caps, max_hypotheses=max_new))

        for h in _derived:
            key = (h.comparator, h.control.get("url"))
            if key in seen:
                continue
            seen.add(key)
            ever.add(key)
            self._derived_hypotheses = list(getattr(self, "_derived_hypotheses", []) or [])
            self._derived_hypotheses.append(h)
            queued += 1
        if queued:
            self.note(f"[capture] {queued} experiment(s) derived from Brukal's OWN "
                      f"traffic — each control already answered")
        return queued

    def _partition_by_principal_readiness(self, pending):
        """(runnable now, waiting on a principal).

        An experiment that names a principal which does not exist YET must not be run,
        must not be recorded as a miss, and must not be lost. MEASURED on crAPI: the
        state_changed experiments derived from a recorded human session ran at ledger row
        348 and were written off `second_unavailable`, while the second principal was
        used successfully at row 717. They were not impossible; they were early, and
        `second_unavailable` recorded a SCHEDULE problem as a missing capability.

        Lives here, beside the queue, because BOTH drains use it — the derived-only pass
        and the model round — and guarding one of two drains is not guarding."""
        have = {"second": bool(getattr(self, "_second_identity", None))}
        ready, waiting = [], []
        for h in (pending or []):
            named = {str((h.control or {}).get("as", "")),
                     str((h.variant or {}).get("as", "")),
                     str((h.act or {}).get("as", "")) if h.act else ""}
            if any(not have.get(n, True) for n in named):
                waiting.append(h)
            else:
                ready.append(h)
        return ready, waiting

    def derived_hypotheses(self) -> list:
        """Experiments derived from OBSERVATIONS rather than proposed by the model.

        CR1 run 2 fetched another tenant's complete order through the gate and published
        nothing, because a finding must be comparator-derived and no comparator judged it.
        These are that observation, turned into a question the comparator CAN judge."""
        return list(getattr(self, "_derived_hypotheses", []) or [])

    def _observe_answer(self, url: str, status) -> None:
        """A path that ANSWERED is evidence about where this application mounts things.

        Run 6 confirmed sixteen routes and every one was under `/identity/api`, because
        mount-prefix alignment had exactly one answered path to work from: the login URL
        the operator supplied. crAPI runs three services, so two thirds of the application
        stayed invisible, seeding found no vehicle routes, coverage found no unvisited
        family, and every experiment was asked about a third of the target.

        The agent's own exploration is the missing evidence. The moment anything touches
        `/workshop/api/shop/orders` and gets a reply, `/workshop/api/shop` becomes an
        alignment candidate and the fragments that failed under the old prefix get another
        chance — so a lucky probe stops evaporating and becomes the surface's knowledge.

        Only an ANSWER counts. A 404 means the path is not there, and learning a prefix
        from one would poison every later composition."""
        try:
            if not url or not status or int(status) == 404:
                return
        except Exception:
            return
        seen = getattr(self, "_answered_paths", None)
        if seen is None:
            seen = self._answered_paths = []
        path = url.split("://")[-1]
        path = "/" + path.split("/", 1)[1] if "/" in path else ""
        path = path.split("?", 1)[0]
        if path and path not in seen and len(seen) < 200:
            seen.append(path)

    def _observe_record(self, url: str, body: str) -> None:
        """One plane's output, examined for a record that is not ours. Deterministic and
        cheap; no model, no extra request.

        Called at each plane's own absorption point — the same discipline the redaction
        hook uses, so a third plane added later inherits it instead of silently going
        unhooked."""
        from . import hypothesis as _hyp
        if not url or not body:
            return
        handles = {self.identity or ""}
        handles |= {v for v in (getattr(self, "_principal_handles", None) or {}).values() if v}
        handles |= {(getattr(self, "_second_identity", None) or {}).get("user", "")}
        try:
            made = _hyp.from_foreign_record(url, body, handles) or []
        except Exception:
            return                            # instrumentation never derails a run
        if not made:
            return
        queue = getattr(self, "_derived_hypotheses", None)
        if queue is None:
            queue = self._derived_hypotheses = []
        if any(x.control.get("url") == made[0].control.get("url") for x in queue):
            return                            # the same record, observed again
        if len(queue) >= self._DERIVED_MAX:
            return
        queue.extend(made)
        h = made[0]
        # ON THE LEDGER at the moment of observation, so the lead exists even if the run
        # ends before the experiment is dispatched — which is exactly what happened to
        # CR1's only real finding. The party is MASKED here; the full value is in this
        # plane's own execution/result row, which is the evidence.
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is not None:
            try:
                audit.append("foreign_record", {
                    "url": url, "title": h.title, "comparator": h.comparator,
                    "party": _hyp.mask_party(_hyp.foreign_parties(body, handles)[0]),
                    "target": self.target})
            except Exception:
                pass
        self.note(f"[experiment] derived from an observation: {h.title}")

    def repair_proposals(self, proposals):
        """Rewrite a proposal that names a mined fragment we RESOLVED to the path we proved.

        Run 12's surface was correct — the dashboard confirmed at
        /identity/api/v2/user/dashboard, phantoms gone, methods annotated — and the model
        still proposed `/v2/user/dashboard`, `/v2/user/videos/0`, `/v2/user/pictures/29`.
        Nine of eleven experiment 404s came from the UNVERIFIED fragment list sitting
        beside the confirmed one, whose own label says "prefer the fetched paths above".

        That label has been there since GAP #4 and has never worked once, which is this
        session's most-repeated lesson: a caveat in prose that no code enforces is a
        comment, not a safeguard.

        Repair rather than refusal, because the proposal is not wrong about WHAT to test.
        Deterministic: the mapping is the one resolution recorded by request, no model is
        consulted, the query string and any suffix are preserved, a path we never resolved
        is left exactly as proposed, and every rewrite is recorded — a request that is not
        the one the model wrote must be visible as such.
        """
        rmap = getattr(self, "_resolved_map", None) or {}
        if not rmap:
            return proposals
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        # Longest fragment first: /v2/user/videos must not be rewritten by a shorter
        # fragment that happens to be a prefix of it.
        frags = sorted(rmap, key=len, reverse=True)

        # THE FAMILY RULE. Exact matching alone made repair fire ZERO times in run 14,
        # whose model proposed four unprefixed paths — /orders/9, /orders/31,
        # /v2/user/videos/9, /v2/user/pictures/31 — while resolution had already PROVED,
        # by request, that /v2/user/dashboard lives under /identity/api and
        # /orders/all under /workshop/api/shop. The prefix for both families was in hand
        # and the lookup was too narrow to use it, so every one of those went out
        # unprefixed and 404'd.
        #
        # A family is a resolved fragment's leading segments less its last: /v2/user
        # from /v2/user/dashboard. A prefix proven for one member applies to its
        # siblings. Deterministic, and no less evidenced than the exact rule — the
        # prefix came from a request that answered. A family under which two different
        # prefixes were proved is AMBIGUOUS and repairs nothing: the point is to send
        # what was proven, never to guess between two candidates.
        families: dict = {}
        for _f, _t in rmap.items():
            if not _t.endswith(_f):
                continue
            _pre = _t[:-len(_f)]
            _segs = [x for x in _f.split("/") if x]
            if not _pre or len(_segs) < 2:
                continue
            families.setdefault("/" + "/".join(_segs[:-1]), set()).add(_pre)
        families = {k: v.pop() for k, v in families.items() if len(v) == 1}
        fams = sorted(families, key=len, reverse=True)

        def _fix(spec):
            url = (spec or {}).get("url", "") or ""
            # REPAIR SUPPLIES A MISSING PREFIX — it never rewrites the middle of a path.
            # Run 15's model proposed /identity/api/orders/all: prefixed, and prefixed
            # WRONG (crAPI mounts orders under /workshop/api/shop). Matching the fragment
            # anywhere in the URL would have spliced the proven prefix in at the fragment,
            # giving /identity/api/workshop/api/shop/orders/all — a URL nobody proposed
            # and nothing proved. A path that already carries a prefix is a different
            # claim by the model, and repair has no evidence that claim is wrong.
            try:
                from urllib.parse import urlsplit
                _path = urlsplit(url).path or ""
            except Exception:
                _path = url
            for frag in frags:
                target = rmap[frag]
                if _path.startswith(frag) and target not in url:
                    new_url = url.replace(frag, target, 1)
                    if audit is not None:
                        try:
                            audit.append("proposal_repaired", {
                                "from": url, "to": new_url, "fragment": frag,
                                "target": self.target,
                                "why": "resolution proved this fragment lives here"})
                        except Exception:
                            pass
                    spec["url"] = new_url
                    return
            for fam in fams:
                pre = families[fam]
                if not _path.startswith(fam + "/"):
                    continue                    # not this family, or already prefixed
                new_url = url.replace(fam + "/", pre + fam + "/", 1)
                if audit is not None:
                    try:
                        audit.append("proposal_repaired", {
                            "from": url, "to": new_url, "family": fam,
                            "target": self.target,
                            "why": "resolution proved this family lives under "
                                   f"{pre} by request"})
                    except Exception:
                        pass
                spec["url"] = new_url
                return
        for h in proposals or ():
            _fix(getattr(h, "control", None))
            _fix(getattr(h, "variant", None))
            _fix(getattr(h, "act", None))
            for step in (getattr(h, "setup", None) or ()):
                _fix(step)
        return proposals

    def run_hypotheses(self, max_run: int = 4, derived_only: bool = False) -> int:
        """Ask the model for experiments, execute them through the gate, keep only the
        ones the evidence supports. Returns how many became findings.

        `derived_only` runs the experiments DERIVED FROM OBSERVATIONS and asks the model
        for nothing. Those proposals came out of the target's own responses, so paying for
        imagination we did not need would make the bridge cost a model call per record.
        CR1 run 3 is why it exists: two derived experiments sat unasked because the reflex
        that consumes them fires once, early, and the agent explores afterwards.

        This is the answer to Brukal's narrowest limitation — that it finds only what a
        detector was written for, and so scored fifteen findings on the target its
        detectors were fitted to and two on an unfamiliar one. The model supplies the
        imagination; the comparator supplies the verdict. A proposal the evidence does
        not support is DISCARDED, not recorded as a lead: an unproven guess from a model
        is not a lead, it is noise, and the report's confirmed/candidate distinction only
        means anything while candidates are things a human could actually verify."""
        from . import hypothesis as _hyp
        if self.browser is None or self.surface is None:
            return 0
        if derived_only:
            _pending = self.derived_hypotheses()
            if not _pending:
                return 0
            # AN EXPERIMENT THAT CANNOT RUN YET MUST NOT BE SPENT. The loop drains this
            # queue at the top of every turn; principals are established later, in
            # REFLEX 0b. A cross-principal experiment drained before then was consumed,
            # recorded `second_unavailable`, and never retried — which is HARNESS-LIMIT,
            # true, and useless: the harness limit was the SCHEDULE, and the record made
            # it look like a capability the engagement lacked.
            #
            # MEASURED on crAPI: the three `state_changed` experiments derived from a
            # recorded human session ran at ledger rows 181/190/199 and were written off;
            # the second principal was created at row 322 and used successfully at row
            # 755. They were not impossible. They were early.
            _ready, _waiting = self._partition_by_principal_readiness(_pending)
            self._derived_hypotheses = _waiting
            if _waiting and not _ready:
                return 0                   # nothing runnable this turn; nothing lost
            _pending = _ready
            self.note(f"[experiment] asking {len(_pending)} experiment(s) derived from "
                      f"observed records (no model call)")
            self._record_experiment_round("derived", len(_pending[:max_run]))
            return self._run_one_round(_pending[:max_run], [], [])
        llm = getattr(getattr(self, "strategist", None), "_llm", None)
        if llm is None:
            self._record_experiment_round("model-unavailable", 0)
            return 0
        self._record_experiment_round("model", None)

        # SETTLE THE SURFACE FIRST. Run 9 proposed its first experiment at ledger entry
        # 270 and 57 of the 60 resolution probes happened AFTER it, so the model planned
        # against the unverified, unprefixed fragment list — /v2/user/dashboard,
        # /orders/all — and eight of sixteen experiment requests were 404s while the
        # confirmed /identity/api/... equivalents existed by the end of the run. By report
        # time the surface looked perfect, which is why it stayed invisible for nine runs.
        #
        # This is the moment the surface matters most: it is the model's entire picture of
        # the application. Resolution still yields to the principals (it no-ops until they
        # are established), so the rate budget that the second principal's identity probes
        # depend on is untouched.
        try:
            if getattr(self, "_principals_established", False):
                self.resolve_mined_routes()
        except Exception:
            pass
        grounding = self.surface.summary() if hasattr(self.surface, "summary") else ""
        source_note = ""
        if self.source_leads:
            # Reasoning ABOUT the application, not just pattern-matching it: the model
            # sees what the source implies and proposes a live experiment to test it.
            # The source still proves nothing by itself — it only suggests the question.
            source_note = ("\n\nThe target's source was supplied. Observations from it "
                           "(UNVERIFIED — each still has to be proved against the "
                           "running app):\n"
                           + "\n".join(f"  - {l['kind']}: {l['value'][:60]} "
                                        f"({l['where']})" for l in self.source_leads[:12]))
        # A second real principal, created before we ask. Authorization is a
        # disagreement between principals, so without one the model can only ever ask
        # half of every interesting question, and `a_denied_b_allowed` — the comparator
        # built for exactly this — is unconstructible.
        second_user = ""
        try:
            second_user = self.establish_second_identity()
        except Exception:
            second_user = ""
        second_note = ""
        if second_user:
            second_note = (
                f"\n\nA SECOND real account exists: '{second_user}'. Set "
                f'"as": "second" on a request to issue it as that account, "as": '
                f'"anonymous" to issue it as a stranger with no session, or omit it for '
                f"your own. Objects and identifiers belonging to '{second_user}' are the "
                f"ones worth trying to reach from your own session, and vice versa.")
        # WHAT EACH PRINCIPAL ALREADY OWNS. Until this existed the model was told two
        # email addresses and the sentence "objects and identifiers belonging to <them>
        # are the ones worth trying to reach" — an instruction to reference objects it had
        # no way to name. Its only route was to CREATE one first, and in run CM2 that is
        # where five of seven cross-account proposals died: four on a setup the target
        # answered 500 and one on a reference to it.
        #
        # Every value here was carried by a response this engagement actually received, so
        # the disclosure cannot name something unusable — the same guarantee the setup
        # shape lines give, applied to values. Through `redact.text` because it is built
        # from response bodies, and a body is exactly where a discovered credential lives.
        ids_note = ""
        _ids = {who: vals for who, vals in self.principal_identifiers().items() if vals}
        if _ids:
            _lines = []
            for _who, _vals in _ids.items():
                _label = {"self": "you", "second": f"the second account"}.get(_who, _who)
                _rendered = ", ".join(f"{k.split('.')[-1]}={v}" for k, v in _vals.items())
                _lines.append(f"  - {_who} ({_label}): {_rendered}")
            ids_note = ("\n\n" + _hyp.PRINCIPAL_IDS_HEADER + "\n"
                        + redact.text("\n".join(_lines)))
        # PER-PROGRAM comparator selection: offer the model only the comparators this
        # program enabled (all, unless the scope restricts them), and refuse any other at
        # parse time. Computed once here and reused for the refine round below.
        _active = _hyp.active_comparators(
            getattr(getattr(self, "executor", None), "_gate", None)
            and self.executor._gate.scope)
        prompt = _hyp.experiment_prompt(
            destructive_allowed=self._destructive_authorised(),
            comparators=", ".join(_active))
        try:
            # The BASE URL, not the bare IP. The first live run handed the model
            # "172.20.0.2" while the application was on :3000, so every proposed URL
            # went to port 80, every request missed, and six sound experiments were
            # judged against nothing. A hypothesis aimed at the wrong port is not a
            # failed hypothesis, it is a failed prompt.
            base = (getattr(self.surface, "seed", "") or f"http://{self.target}/").rstrip("/")
            auth = ""
            if self.session_token():
                # The model is NEVER given the credential — not the real one, and not the
                # redacted one either. It used to be handed the real token here, because
                # an earlier version invented `Bearer <userA_token>` and the target
                # rejected it. Once the token was masked at the record boundary the model
                # started copying `Bearer [REDACTED:...]` instead, and because
                # `_apply_cookies` only attaches the session when the request carries no
                # Authorization header, that placeholder SUPPRESSED the real credential:
                # every "authenticated" experiment silently ran logged out.
                #
                # The token was never needed. `_as_identity` already swaps the principal
                # for "as": self/second/anonymous and the governed browser attaches
                # whatever that principal holds — so a model-set header defeats the
                # principal machinery even when the value is real. Same wording as the
                # cookie branch below, because it is the same instruction.
                auth = (f"\n\nYou are already authenticated as '{self.identity}', and the "
                        f"session is attached to every request you propose automatically. "
                        f"Do NOT include a login step and do NOT set a Cookie or "
                        f"Authorization header yourself — use \"as\" to choose the "
                        f"principal instead.")
            elif self.authenticated:
                # A COOKIE session was never mentioned to the model at all — this whole
                # block was gated on holding a JWT. The governed browser attaches the
                # jar to every request automatically, so the experiments really were
                # authenticated; the model just did not know it, and proposed either
                # anonymous probes or a login step it did not need. Half the interesting
                # questions about an application are about what a LOGGED-IN stranger can
                # reach, and it could not ask any of them.
                auth = (f"\n\nYou are already authenticated as '{self.identity}' by a "
                        f"session cookie, which is attached to every request you propose "
                        f"automatically. Do NOT include a login step and do NOT set a "
                        f"Cookie or Authorization header yourself.")
            reply = llm.propose(prompt,
                                f"Authorised target base URL: {base}\n"
                                f"Every url MUST start with exactly that base."
                                f"{auth}\n\n"
                                f"Attack surface:\n{grounding}"
                                f"{second_note}{ids_note}{source_note}",
                                max_tokens=8000)
        except Exception as exc:
            # RECORD, do not widen. What is caught is unchanged — the engagement still
            # continues past a failed proposal — but it may no longer vanish. A live run
            # lost model-proposed experiments entirely to a `ValueError` raised inside
            # the SDK here, and `return 0` erased it: no note, no coverage row, no trace
            # on any surface. REFLEX 0b is gated to fire once, so that single silence
            # cost the whole engagement its most valuable capability, and the report then
            # said the class was never reached — which by the coverage table's own
            # footnote means something different, and untrue.
            _why = f"the proposal call FAILED ({type(exc).__name__}: {str(exc)[:160]})"
            self.note(f"[experiment] {_why} — no experiments were proposed this run")
            self._covered("Model-proposed experiments", probes=0, note=_why)
            return 0

        outcomes: list = []
        # The SHAPE of what each setup request returned, accumulated across the round so
        # the next one can be shown it. Separate from `outcomes` on purpose: that list is
        # windowed to its last 8 entries in the refine prompt, and on a round of nine
        # experiments the shapes — the one thing that would fix the next round — would be
        # the entries pushed out.
        shapes: list = []
        _drops: list = []
        proposals = _hyp.parse(reply, drops=_drops, allowed=_active)
        self._record_proposal_drops(_drops)
        # Record the attempt BEFORE the early return. The first live run asked the model,
        # got a truncated reply, parsed nothing, and left no trace at all — the coverage
        # table simply had no row, which is the exact ambiguity that table exists to
        # remove. "Asked and got nothing usable" is a result and has to be visible.
        if proposals:
            _why = "two gated requests each, judged by a fixed comparator"
        else:
            # Say WHY. An empty reply comes from a refusal, from an allowance spent
            # entirely on thinking, and from a truncation — three causes needing three
            # different responses, and "0 chars" distinguishes none of them.
            _stop = getattr(llm, "last_stop_reason", "") or "unknown"
            _kinds = ",".join(getattr(llm, "last_block_kinds", []) or []) or "none"
            _why = (f"model returned no usable experiment ({len(reply)} chars; "
                    f"stop_reason={_stop}; blocks={_kinds})")
            self.note(f"[experiment] no usable proposal — {_why}")
        self._covered("Model-proposed experiments", probes=len(proposals), note=_why)
        # DERIVED PROPOSALS GO FIRST. They come from something the target already did —
        # an addressed record that came back naming somebody who is not us — so they are
        # the best-evidenced questions in the batch, and CR1 proved they are the ones
        # that get lost. Drained, so an experiment is proposed once; whatever the
        # comparator then says is the published answer.
        proposals = self.repair_proposals(proposals)
        _derived, _defer = self._partition_by_principal_readiness(self.derived_hypotheses())
        if _derived or _defer:
            # The MODEL round drains this queue too. Guarding only the derived-only path
            # meant the deferred experiments were picked up and spent here instead — the
            # readiness rule belongs to the QUEUE, not to one consumer of it.
            self._derived_hypotheses = _defer
        if _derived:
            proposals = _derived + list(proposals)
            self.note(f"[experiment] {len(_derived)} experiment(s) derived from observed "
                      f"records, queued ahead of the model's proposals")
        # COVERAGE FLOOR. Four CR1 runs on the same target proposed 7, 4, 15 and 4
        # experiments and examined wildly different parts of the application; run 4 found
        # another tenant's order at /workshop/api/shop and run 5 never went near it. Depth
        # is the model's job. Making sure no confirmed area of the application is silently
        # skipped is not, so every family nothing asked about gets one read-only question.
        try:
            _cov = _hyp.coverage_proposals(
                list(getattr(self.surface, "confirmed_routes", []) or []),
                proposals,
                base=(getattr(self.surface, "seed", "") or f"http://{self.target}/").rstrip("/"),
                allowed=_active)
        except Exception:
            _cov = []
        if _cov:
            proposals = list(proposals) + _cov
            self.note(f"[experiment] coverage: {len(_cov)} confirmed endpoint "
                      f"family(ies) had no proposal; asking whether each authenticates "
                      f"its callers")
        if not proposals:
            return 0

        confirmed = 0
        rounds = 0
        while proposals and rounds < 2:
            rounds += 1
            confirmed += self._run_one_round(proposals[:max_run], outcomes, shapes)
            if confirmed or rounds >= 2:
                break
            # Nothing held. A refinement is only worth a second model call if the first
            # round actually observed something to reason about — an empty outcome list
            # means every experiment errored before reaching the target, and asking again
            # would produce the same misdirected guesses.
            if not outcomes:
                break
            try:
                # WHAT THE SETUP RETURNED, before the results that depend on it. Run
                # 2C4 lost 9 of 9 experiments to `{{setup.0.id}}` against a body of
                # `{"user": {"id": 25, ...}}`: the reference GRAMMAR is documented to the
                # model and the SCHEMA of the response it references never was, so it was
                # asked to name a field it had never seen while the harness held the
                # answer. Structure only — never values — and it rides the same prompt
                # and the same `redact.text` funnel as everything else here, rather than
                # opening a second boundary that would have to be defended separately.
                shown = shapes[:_hyp.SETUP_SHAPE_MAX_LINES]
                shape_block = ""
                if shown:
                    shape_block = ("\n\n" + _hyp.SETUP_SHAPE_HEADER + "\n"
                                   + "\n".join(f"  - {s}" for s in shown))
                    if len(shapes) > len(shown):
                        shape_block += (f"\n  [TRUNCATED: {len(shown)} of "
                                        f"{len(shapes)} setup responses listed]")
                reply2 = llm.propose(
                    _hyp.refine_prompt(
                        destructive_allowed=self._destructive_authorised(),
                        comparators=", ".join(_active)),
                    f"Authorised target base URL: {base}{auth}\n\n"
                    f"Attack surface:\n{grounding}{shape_block}"
                    f"\n\nResults of your last round:\n"
                    + "\n".join(f"  - {o}" for o in outcomes[-8:]),
                    max_tokens=8000)
            except Exception:
                break
            _drops2: list = []
            proposals = _hyp.parse(reply2, drops=_drops2, allowed=_active)
            self._record_proposal_drops(_drops2, round_name="refine")
            if proposals:
                self._covered("Model-proposed experiments", probes=len(proposals),
                              note="refined round, informed by the first round's results")
        return confirmed

    def _unauth_foreign(self, control_as: str, control_result) -> bool:
        """True when the ANONYMOUS side of an experiment came back with somebody else's
        record — the case `a_denied_b_allowed` correctly refuses and nothing could publish.

        Deterministic and narrow: the request must actually have been issued as
        `anonymous`, it must have answered 2xx, and the body must name a party none of our
        principals authenticated as. Anything less is not this finding."""
        from . import hypothesis as _hyp
        if (control_as or "") != "anonymous":
            return False
        status = getattr(control_result, "status", None)
        if not status or not (200 <= int(status) < 300):
            return False
        handles = {self.identity or ""}
        handles |= {v for v in (getattr(self, "_principal_handles", None) or {}).values() if v}
        handles |= {(getattr(self, "_second_identity", None) or {}).get("user", "")}
        try:
            return bool(_hyp.foreign_parties(getattr(control_result, "body", "") or "",
                                             handles))
        except Exception:
            return False

    def _anon_refused_for(self, control_template, setup_results) -> bool:
        """Whether an UNAUTHENTICATED caller issuing this experiment's own request is
        REFUSED — the load-bearing guard for `shared_private_response`.

        A public endpoint returns the same body to everyone; only when the anonymous
        caller is DENIED is an identical response to two authenticated principals a leak
        rather than a public page. Established the same way as the identity oracle's
        anonymous control: re-resolve the request, dispatch it as `anonymous`, and read
        `_denied`. FAILS CLOSED — if the probe cannot be resolved, is refused by the gate,
        or errors, the answer is False and nothing is confirmed."""
        from . import hypothesis as _hyp
        from .web import WebAction
        try:
            spec = _hyp.resolve_setup_refs(dict(control_template), setup_results)
        except Exception:
            return False
        spec.pop("as", None)
        try:
            with self._as_identity("anonymous", "anon-probe", spec.get("url", "")):
                _decision, result = self.browser.run(WebAction("request", **spec))
        except Exception:
            return False
        if result is None:
            return False
        return bool(_hyp._denied(result, getattr(self, "profile", None)))

    def _keep_reproducible_lead(self, h, a, b, setup_results) -> bool:
        """When a comparator confirmed nothing but the controlled input STABLY changes the
        answer, record an INFO lead instead of discarding the result (Idea #3).

        Deterministic and FAIL-CLOSED: it re-reads the control ONCE to establish a stable
        baseline (endpoints drift on their own) and keeps a lead only when
        `reproducibility.input_dependent` holds. The lead is INFO, `confirmed=False`, and
        carries no comparator (`evidence_class=""`) — a question for a human, never a
        proved impact, and the model is nowhere in the decision. Returns True when a lead
        was kept, so the caller skips the plain not_confirmed record; any error re-reading,
        or an unstable baseline, returns False and the result is recorded not_confirmed as
        before.

        The re-read is skipped unless the two sides already differ — identical answers
        cannot be an input-dependent effect, so the extra request is only spent where it
        could pay."""
        from . import hypothesis as _hyp
        from . import reproducibility as _rep
        from .web import WebAction
        from .findings import Finding
        # Only genuinely UNNAMED signal. Both sides must have SUCCEEDED and returned real
        # content, so the shapes a named comparator already owns — a refusal
        # (`a_denied_b_allowed`), a server error (`b_errors_a_does_not`), a status-class
        # split (`status_differs`) — cannot pose as an unnamed lead. What remains is a
        # reproducible CONTENT difference between two successful reads, which is the case
        # #3 is for.
        profile = getattr(self, "profile", None)
        if not (_hyp._succeeded(a) and _hyp._succeeded(b)):
            return False
        if not (_hyp._substantive(a, profile) and _hyp._substantive(b, profile)):
            return False
        if _rep._fingerprint(a) == _rep._fingerprint(b):
            return False
        try:
            spec = _hyp.resolve_setup_refs(dict(h.control), setup_results)
            with self._as_identity(spec.pop("as", "self"), "control",
                                   spec.get("url", "")):
                _decision, a2 = self.browser.run(WebAction("request", **spec))
        except Exception:
            return False
        keep, reason = _rep.reproducible_lead([a, a2], [b])
        if not keep:
            return False
        self._record_experiment_outcome(h, "reproducible_lead")
        # Structured facts for the OFFLINE miner (Idea #4b): the shape a later run reads to
        # cluster recurring leads into draft comparators. Prose is for a human; this is for
        # the machine, so the report never has to parse a sentence.
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is not None:
            audit.append("reproducible_lead_facts", {
                "endpoint": h.variant.get("url", ""),
                "comparator": h.comparator,
                "status_baseline": getattr(a, "status", None),
                "status_varied": getattr(b, "status", None),
                "size_baseline": len(_rep._fingerprint(a)[1]),
                "size_varied": len(_rep._fingerprint(b)[1]),
            })
        self.note(f"[experiment] REPRODUCIBLE LEAD [{h.comparator}]: {h.title} — {reason}")
        self.findings.add(Finding(
            title=(f"Reproducible input-dependent behaviour at {h.variant['url']} "
                   f"— INFO lead, no comparator"),
            severity=_rep.LEAD_SEVERITY, category="logic", confirmed=False,
            target=h.variant["url"], param="", evidence_class="",
            agent_claim=h.title, agent_severity=(h.severity or ""), evidence=reason))
        return True

    def mined_lead_report(self) -> str:
        """The offline drafts report for THIS engagement's reproducible leads (Idea #4b).

        Reads the leads recorded during the run, mines the recurring shapes into DRAFT
        comparators, and returns a human-review sheet. Pure read + format: it registers
        nothing, runs no predicate, and persists nothing — a maintainer alone turns any
        draft into a real comparator. A run with no audit or no leads yields the report's
        explicit 'nothing to draft' line, never a crash."""
        from . import lead_mining as _lm
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        path = getattr(audit, "path", None)
        if path is None:
            return _lm.format_report([])
        return _lm.format_report(_lm.mine(_lm.leads_from_audit(path)))

    def _destructive_authorised(self) -> bool:
        """What the SCOPE authorised for this engagement — never the model's choice."""
        gate = getattr(getattr(self, "executor", None), "_gate", None)
        return bool(getattr(getattr(gate, "scope", None), "destructive_allowed", False))

    def _record_experiment_round(self, source: str, proposals: int | None) -> None:
        """Say in the LEDGER whether a round of experiments asked the MODEL or not.

        Reading a run's attribution requires knowing how often the imagination was
        actually consulted, and for eighteen runs that was knowable only from a vault
        NOTE — `(no model call)` — which no benchmark parsed. So `crapi_recall.py` scored
        challenges MODEL-LIMIT on runs where the model had been asked exactly once, and
        the label was believed (GAP #16, GAP #18).

        `source` is "model", "derived" (no model call by design) or "model-unavailable".
        A benchmark can now count model rounds instead of inferring them, and an
        attribution computed over too few rounds can say so rather than blame the model."""
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        if audit is None:
            return
        audit.append("experiment_round", {
            "source": source,
            "proposals": proposals,
        })

    def _record_proposal_drops(self, drops: list, round_name: str = "propose") -> None:
        """A proposal the model MADE and validation DISCARDED must reach the ledger.

        Without this, `parse()` skipped a malformed entry with a bare `continue` and the
        raw reply was persisted nowhere, so counting a comparator over the ledger
        measured what SURVIVED validation while being read as what the model PROPOSED.
        Run 18's entire MODEL-LIMIT attribution rested on that reading and its artifacts
        could not tell the two apart (GAP #17).

        The comparator is recorded even when the comparator is what was wrong: the
        question a later run asks is whether the model reached for an evidence class at
        all, and that has to survive the proposal's own rejection."""
        if not drops:
            return
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        by_comparator: dict = {}
        for d in drops:
            by_comparator[d.get("comparator") or "?"] = (
                by_comparator.get(d.get("comparator") or "?", 0) + 1)
        if audit is not None:
            # `append`, NOT `record` — the first version of this called a method the
            # AuditLog does not have, inside a bare `except Exception: pass`, so the
            # whole ledger row was dead code that could never fail visibly. That is the
            # same silent-swallow shape as the experiment reflex's own lost exception,
            # and the test below exists so it cannot come back.
            audit.append("experiment_proposal_dropped", {
                "round": round_name,
                "count": len(drops),
                "by_comparator": by_comparator,
                "drops": drops[:12],
            })
        self.note(f"[experiment] {len(drops)} proposal(s) discarded at validation "
                  f"({round_name}): "
                  + ", ".join(f"{k}x{v}" for k, v in sorted(by_comparator.items())))

    def _approve_destructive_experiment(self, h) -> bool:
        """Put a destructive experiment to the operator, through the SAME approver the
        command path uses. Returns True only if a human (or a pre-authorised auto
        approver) said yes.

        Fail-closed twice over: the scope must have opted in (`destructive_allowed`),
        and the approver must then agree. An engagement that never opted in does not
        consult anyone and does not act — but it now RECORDS an operator refusal instead
        of a silent skip, so a missing result is never mistaken for a clean one."""
        from .gate import Decision
        scope = getattr(getattr(self, "executor", None), "_gate", None)
        allowed = bool(getattr(getattr(scope, "scope", None), "destructive_allowed", False))
        audit = getattr(getattr(self, "executor", None), "_audit", None)
        decision = Decision(
            verdict="ESCALATE",
            action=f"destructive experiment: {h.comparator} {h.variant.get('method','')} "
                   f"{h.variant.get('url','')}",
            target=self.target, agent="experiment",
            reason=(f"the proposal addresses a state-changing path; "
                    f"scope.destructive_allowed={allowed}"),
            layer="soft:destructive-experiment")
        if audit is not None:
            try:
                audit.append("web_decision", decision)
            except Exception:
                pass
        if not allowed:
            return False
        approver = getattr(getattr(self, "executor", None), "_approver", None)
        if approver is None:
            return False
        try:
            return bool(approver(decision))
        except Exception:
            return False                     # an approver that breaks is a refusal

    def _run_one_round(self, proposals, outcomes, shapes=None) -> int:
        """Execute one batch of experiments; returns how many became findings.

        `shapes` collects one line per distinct setup response describing its KEY PATHS,
        for the next round to be shown. Optional so the signature stays compatible; when
        it is None the disclosure is still written to the engagement record."""
        from . import hypothesis as _hyp
        from .findings import Finding
        from .web import WebAction
        confirmed = 0
        for h in proposals:
            # Every experiment leaves a trace, whatever becomes of it. Three separate
            # paths used to discard one silently — a destructive-path skip, a bare
            # `except`, and a pair of unanswered requests — while `outcomes` stayed a
            # local variable that never reached the engagement log. The coverage table
            # then said "6 probes" with no record anywhere of WHAT was tried, so the one
            # component built to generalise beyond hand-written detectors was the only
            # one whose behaviour could not be inspected after a run. A mechanism that
            # finds nothing and explains nothing cannot be improved.
            self._record_experiment_proposed(h)
            self.note(f"[experiment] {h.title} [{h.comparator}] "
                      f"{h.control['method']} {h.control['url']} vs "
                      f"{h.variant['method']} {h.variant['url']}")
            if self._is_destructive_request(h.variant.get("method", ""),
                                            h.variant["url"]) \
                    or self._is_destructive_request(h.control.get("method", ""),
                                                    h.control["url"]) \
                    or any(self._is_destructive_request(s.get("method", ""),
                                                        s.get("url", ""))
                           for s in ((getattr(h, "act", None) and [h.act]) or [])):
                # ASK. This used to be an unconditional skip, and crAPI challenge 3 —
                # "reset the password of a different user" — was proposed by the model and
                # dropped here with nobody consulted, while the COMMAND path escalated
                # eleven destructive actions to the operator in the same engagement. The
                # same action got two different answers depending on which code path
                # reached it. Where Brukal needs authorisation it asks for it; the human
                # decides, and the record shows who answered.
                if not self._approve_destructive_experiment(h):
                    self._record_experiment_outcome(h, "refused_by_operator")
                    self.note(f"[experiment] REFUSED by the operator (destructive): "
                              f"{h.title}")
                    outcomes.append(f"REFUSED BY THE OPERATOR (destructive; experiment NOT "
                                    f"run, this is not a result about the target) {h.title}")
                    continue
                self.note(f"[experiment] destructive experiment AUTHORISED by the "
                          f"operator: {h.title}")
            try:
                # Setup first: it establishes the state the experiment is about, and is
                # never judged. A flaw that only exists partway through a workflow is
                # unreachable without it.
                # What each setup request ANSWERED, so a later request can use it. Setup
                # reaches an interesting state; without its responses the experiment
                # cannot name what was created, and the model reached for a syntax that
                # did not exist — `{{setup.0.BasketId}}` went out with the braces intact
                # and the resulting 401 was filed as a clean negative.
                setup_results: list = []
                for step in h.setup:
                    # Setup exists to CREATE state — adding to a cart, starting an
                    # order — so the ordinary state-changing guard would forbid exactly
                    # what makes a stateful experiment possible. Creation is therefore
                    # allowed, but only under the same authorisation that governs every
                    # other proof that writes; destruction stays refused regardless,
                    # since nothing here can undo it.
                    spec = _hyp.resolve_setup_refs(step, setup_results)
                    if self._is_irreversible_path(spec["url"]):
                        raise ValueError("irreversible setup step")
                    if self._is_destructive_path(spec["url"]) and not self.allow_intrusive:
                        raise ValueError("state-changing setup needs --full-send")
                    with self._as_identity(spec.pop("as", "self"), "setup",
                                           spec.get("url", "")):
                        _ds, rs = self.browser.run(WebAction("request", **spec))
                    setup_results.append(rs)
                    # The response is captured HERE and, until this line, was read once
                    # by the resolver and dropped. Describing it costs nothing and is the
                    # only thing standing between a model that guesses at field names and
                    # one that knows them. `step`, not `spec`: the model's own request
                    # text, so a value substituted into a resolved url by an earlier
                    # reference cannot ride out on this line.
                    _shape = _hyp.describe_setup_shape(
                        len(setup_results) - 1, step, rs)
                    self.note(f"[experiment] setup shape: {_shape}")
                    if shapes is not None and _shape not in shapes:
                        shapes.append(_shape)
                cspec = _hyp.resolve_setup_refs(h.control, setup_results)
                vspec = _hyp.resolve_setup_refs(h.variant, setup_results)
                _oob_token = ""
                if "{{oob}}" in json.dumps(vspec):
                    _lis = self._oob()
                    if _lis is None:
                        raise ValueError(
                            "an out-of-band experiment needs the cage listener, and none "
                            "is available in this environment")
                    _oob_token = "exp" + str(random.randint(10 ** 8, 10 ** 9))
                    vspec = json.loads(json.dumps(vspec).replace(
                        "{{oob}}", _lis.callback_url(_oob_token)))
                # Read before `as` is popped off the spec by the dispatch below.
                _c_as = cspec.get("as", "self")
                _v_as = vspec.get("as", "self")
                with self._as_identity(cspec.pop("as", "self"), "control",
                                       cspec.get("url", "")):
                    _d1, a = self.browser.run(WebAction("request", **cspec))
                self._record_experiment_result("control", cspec.get("url", ""), a)
                # STATE-CHANGE EVIDENCE: read, read again, act, then read once more. The
                # second baseline read is what makes the class sound — endpoints move on
                # their own (timestamps, nonces, counters) and without it every one of
                # them would look like a finding. Same discipline the identity oracle
                # uses when it probes anonymously twice before trusting an answer.
                _stable, _acted = False, False
                if h.act:
                    _spec2 = _hyp.resolve_setup_refs(dict(h.control), setup_results)
                    with self._as_identity(_spec2.pop("as", "self"), "control",
                                           _spec2.get("url", "")):
                        _d1b, _a2 = self.browser.run(WebAction("request", **_spec2))
                    _stable = (a is not None and _a2 is not None
                               and getattr(a, "status", None) == getattr(_a2, "status", None)
                               and (a.body or "") == (_a2.body or ""))
                    aspec = _hyp.resolve_setup_refs(dict(h.act), setup_results)
                    if self._is_irreversible_path(aspec.get("url", "")):
                        raise ValueError("irreversible action in a state-change experiment")
                    with self._as_identity(aspec.pop("as", "self"), "act",
                                           aspec.get("url", "")):
                        _da, _ar = self.browser.run(WebAction("request", **aspec))
                    self._record_experiment_result("act", aspec.get("url", ""), _ar)
                    _acted = _ar is not None and getattr(_ar, "status", None) is not None
                with self._as_identity(vspec.pop("as", "self"), "variant",
                                       vspec.get("url", "")):
                    _d2, b = self.browser.run(WebAction("request", **vspec))
                self._record_experiment_result("variant", vspec.get("url", ""), b)
            except _hyp.PrincipalNotAuthenticated as exc:
                # NOT a negative result, and ahead of the generic handler for the reason
                # the two below it are: the experiment never ran, and a transport-shaped
                # message ("ERRORED before reaching the target") would hide a governance
                # fact behind a plumbing one.
                self._record_experiment_outcome(h, "not_authenticated")
                self.note(f"[experiment] NOT AUTHENTICATED, not run: {h.title} ({exc})")
                outcomes.append(f"NOT AUTHENTICATED (experiment NOT run, this is not a "
                                f"result) {h.title}: {exc}")
                continue
            except _hyp.SecondPrincipalUnavailable as exc:
                # NOT a negative result, and caught ahead of the generic handler for the
                # same reason UnresolvedReference is: the comparator this experiment
                # selected was unconstructible, so any verdict it reached would be a
                # claim about Brukal dressed as a claim about the application. Fed back
                # so the next round proposes something this target can actually answer.
                self._record_experiment_outcome(h, "second_unavailable")
                self.note(f"[experiment] SECOND PRINCIPAL UNAVAILABLE, not run: "
                          f"{h.title} ({exc})")
                outcomes.append(f"SECOND PRINCIPAL UNAVAILABLE (experiment NOT run, "
                                f"this is not a result) {h.title}: {exc}")
                continue
            except _hyp.SetupRequestFailed as exc:
                # Ahead of UnresolvedReference (its parent) so the sentence the next round
                # reasons from names the repair that is actually available. Same shape as
                # the refusals above it: not dispatched, not judged, not a result.
                self._record_experiment_outcome(h, "setup_failed")
                self.note(f"[experiment] SETUP FAILED, not run: {h.title} ({exc})")
                outcomes.append(f"SETUP FAILED (experiment NOT run, this is not a result) "
                                f"{h.title}: {exc}")
                continue
            except _hyp.UnresolvedReference as exc:
                # NOT a negative result. The experiment never ran, and saying so keeps a
                # missing data-flow visible instead of letting it wear a comparator's
                # verdict. Fed back so the next round can reference a field that exists.
                self._record_experiment_outcome(h, "unresolved_reference")
                self.note(f"[experiment] UNRESOLVED REFERENCE, not run: {h.title} "
                          f"({exc})")
                outcomes.append(f"UNRESOLVED REFERENCE (experiment NOT run, this is not "
                                f"a result) {h.title}: {exc}")
                continue
            except Exception as exc:
                self._record_experiment_outcome(h, "errored")
                self.note(f"[experiment] ERRORED before reaching the target: {h.title} "
                          f"({type(exc).__name__}: {str(exc)[:80]})")
                continue
            # THE FLOOR, and it is principled rather than numeric: when BOTH sides are
            # 5xx the application did not behave, it broke, and no comparator can read
            # behaviour out of a crash. The 2C3b pre-flight confirmed `bodies_differ` on
            # two 500s of identical length whose bodies differed only in an echoed id —
            # that is the error handler's output, not the application's. Recorded as
            # not-a-result in the same shape as UNRESOLVED REFERENCE, because "we could
            # not ask" and "we asked and it held" must never look alike.
            # getattr, not attribute access: either side is None when the gate or the
            # rate limiter refused that request, and a blocked pair is handled below.
            _as, _bs = getattr(a, "status", None), getattr(b, "status", None)
            # THE SAME FLOOR, ONE STATUS CLASS OVER. When BOTH sides are 404 the path
            # does not exist, so the comparison is between two absences and says nothing
            # about the application. CR1 run 19 produced the series' first correctly
            # shaped `state_changed` experiment -- control and variant the same read, as
            # the second principal -- and aimed it at `/orders/40` because crAPI's
            # `/workshop/api/shop` mount had not been proven when the proposal was made,
            # so repair had no prefix to apply. Both sides 404'd and it was recorded
            # `not_confirmed / MEASURED`: a fact about crAPI. It was a fact about our aim.
            #
            # Attributed to the HARNESS, not the model: run 19's ledger shows nothing had
            # ever answered under that mount, so the prefix was not learnable at proposal
            # time. The model aimed at the only path it had been shown.
            if (_as or 0) == 404 and (_bs or 0) == 404:
                self._record_experiment_outcome(h, "both_sides_absent")
                self.note(f"[experiment] BOTH SIDES ABSENT (404/404), not judged: "
                          f"{h.title} — the path does not exist on this target, so the "
                          f"comparison is between two absences and measures nothing")
                outcomes.append(f"BOTH SIDES ABSENT (experiment NOT judged, this is not "
                                f"a result) {h.title}: control and variant both HTTP 404 "
                                f"— fix the URL, the mount prefix is probably missing")
                continue
            # THE SAME FLOOR AGAIN, ONE STATUS CLASS OVER (GAP #29). Two 405s mean the
            # URL exists but is not READABLE by the method we asked with, so there is no
            # answer for the comparator to read a change out of. Measured on crAPI: the
            # write `POST /workshop/api/shop/orders/return_order` was paired with a read
            # of the action endpoint itself, both sides answered 405 (40B), and it was
            # recorded `not_confirmed` — indistinguishable in a report from "the write
            # changed nothing". `_read_that_shows` now aims at the collection the session
            # actually read; this floor is what stops a remaining wrong aim from being
            # filed as a judged negative, which is the part that must not be left to the
            # aim being right.
            if (_as or 0) == 405 and (_bs or 0) == 405:
                self._record_experiment_outcome(h, "both_sides_unreadable")
                self.note(f"[experiment] BOTH SIDES UNREADABLE (405/405), not judged: "
                          f"{h.title} — the read is not allowed on this URL, so nothing "
                          f"was observed that a write could have changed")
                outcomes.append(f"BOTH SIDES UNREADABLE (experiment NOT judged, this is "
                                f"not a result) {h.title}: control and variant both HTTP "
                                f"405 — read the COLLECTION the write addresses, not the "
                                f"action endpoint itself")
                continue
            if (_as or 0) >= 500 and (_bs or 0) >= 500:
                self._record_experiment_outcome(h, "both_sides_failed")
                self.note(f"[experiment] BOTH SIDES FAILED ({_as}/{_bs}), not "
                          f"judged: {h.title} — a difference between two server errors "
                          f"is not evidence about the application")
                outcomes.append(f"BOTH SIDES FAILED (experiment NOT judged, this is not "
                                f"a result) {h.title}: control HTTP {_as}, variant "
                                f"HTTP {_bs}")
                continue
            # The ownership map travels to the comparator as CONTEXT. It is the same store
            # `_record_principal_ids` writes to the ledger as `principal_ownership`, in the
            # same call, so the map this judgement reads and the map a reader can
            # reconstruct from the bundle cannot disagree.
            # `vspec` is the RESOLVED variant request — references substituted, `as`
            # already popped — so the comparator sees what was actually addressed rather
            # than the template the model wrote.
            # ISOLATION facts for `shared_private_response`. `_distinct_principals` is
            # cheap and always computed; the anonymous PROBE runs ONLY for that comparator
            # (it costs a real request) and only when the two sides are distinct registered
            # principals, and it fails closed — no probe, or a probe that is not refused,
            # means no confirmation.
            _distinct_principals = bool(
                _c_as in _hyp._REGISTERED_PRINCIPALS
                and _v_as in _hyp._REGISTERED_PRINCIPALS and _c_as != _v_as)
            _anon_refused = bool(
                h.comparator == "shared_private_response" and _distinct_principals
                and self._anon_refused_for(h.control, setup_results))
            _ctx = {"ownership": self.principal_identifiers(), "variant_as": _v_as,
                    "variant_spec": vspec, "profile": getattr(self, "profile", None),
                    # Only a stable baseline and a performed action let `state_changed`
                    # hold; both are facts about what the ENGINE did, not about a body.
                    "baseline_stable": _stable, "acted": _acted,
                    # A fact about the LISTENER, not about either response: both sides of
                    # an SSRF experiment are usually an identical 200.
                    "oob_hit": bool(_oob_token and self._oob() is not None
                                    and self._oob().hit(_oob_token)),
                    # Did a caller with NO credentials retrieve somebody else's record?
                    # Established from the side actually dispatched as `anonymous`, not
                    # from what the proposal said it would do.
                    "unauth_foreign": self._unauth_foreign(_c_as, a),
                    # ISOLATION (shared_private_response): are the two sides distinct
                    # registered principals, and was an UNAUTHENTICATED caller of the same
                    # request refused? Facts about what the ENGINE dispatched, not a body.
                    "distinct_principals": _distinct_principals,
                    "anon_refused": _anon_refused}
            holds, meaning = _hyp.judge(h, a, b, getattr(self, "profile", None), _ctx)
            # SHOW THE MATCH, not just its verdict — and record it whether or not the
            # comparator held. An ownership claim a reader cannot check is the thing this
            # whole line of work exists to stop, and a refusal is as worth seeing as a
            # confirmation: it is where an integer coincidence gets declined.
            if h.comparator == "cross_account_resource":
                self._record_ownership_match(h, vspec, b, _v_as, bool(holds))
            if not holds:
                # Keep what happened — a round that confirms nothing is still the only
                # information the next round has. But only when the target actually
                # ANSWERED: an experiment the gate refused, or one aimed at a host that
                # never replied, observed nothing, and "HTTP None vs HTTP None" is not a
                # result to reason about. Recording it would buy a second model call to
                # refine against noise.
                if getattr(a, "status", None) is None and getattr(b, "status", None) is None:
                    self._record_experiment_outcome(h, "no_answer")
                    self.note(f"[experiment] NO ANSWER from the target: {h.title}")
                    continue
                # KEEP REPRODUCIBLE SIGNAL (Idea #3). The comparator named nothing, but if
                # the controlled input STABLY changes the answer this is a lead, not noise,
                # and discarding it also lets the repeat-suppressor lock this endpoint out
                # of a later round. Costs one extra control read, only when the two sides
                # already differ; fails closed to the plain not_confirmed record below.
                if self._keep_reproducible_lead(h, a, b, setup_results):
                    continue
                self._record_experiment_outcome(h, "not_confirmed")
                self.note(f"[experiment] not confirmed [{h.comparator}]: {h.title} — "
                          f"control HTTP {getattr(a, 'status', None)} "
                          f"({len(getattr(a, 'body', '') or '')}B) vs variant HTTP "
                          f"{getattr(b, 'status', None)} "
                          f"({len(getattr(b, 'body', '') or '')}B)")
                outcomes.append(
                    f"NOT CONFIRMED [{h.comparator}] {h.title}: control -> "
                    f"HTTP {getattr(a, 'status', None)} "
                    f"({len(getattr(a, 'body', '') or '')}B), variant -> "
                    f"HTTP {getattr(b, 'status', None)} "
                    f"({len(getattr(b, 'body', '') or '')}B)")
                continue
            confirmed += 1
            self._record_experiment_outcome(h, "confirmed")
            self.note(f"[experiment] CONFIRMED [{h.comparator}]: {h.title}")
            # The CLAIM is derived, not quoted. `title` and `severity` used to come
            # straight off the model's proposal: on 2026-08-22 that published two HIGH
            # cross-account reads from a single principal, on sound verdicts. The
            # comparator and the two RESOLVED principals decide what may be asserted and
            # how loudly; the model's own words are kept below, marked UNVERIFIED, because
            # they are the most useful sentence in the record and the least trustworthy.
            # WHO the ledger says owns what the variant reached. Recomputed from the same
            # recorded map rather than carried out of the predicate, so the claim and the
            # verdict are derived from one source; `[]` when nothing matched, and
            # `derive_claim` fails closed on a missing owner rather than asserting one.
            _ev = _hyp.ownership_evidence(vspec, getattr(b, "body", ""),
                                          self.principal_identifiers(), _v_as)
            _cl = _hyp.derive_claim(
                h.comparator, _c_as, _v_as,
                control={"url": h.control["url"], "status": a.status,
                         "size": len(a.body or "")},
                variant={"url": h.variant["url"], "status": b.status,
                         "size": len(b.body or ""),
                         "owner": _ev["owner"], "owned_id": _ev["value"]})
            self.findings.add(Finding(
                title=_cl["title"], severity=_hyp.cap_severity(h.severity, _cl["severity_cap"]),
                category="logic",
                # The model's assertion, kept as DATA beside the derived claim and never
                # rendered as the finding. It is here so the gap between what the model
                # claimed and what the evidence supported is countable rather than
                # anecdotal — an overclaim rate is a result worth publishing.
                evidence_class=_cl["evidence_class"],
                agent_claim=h.title, agent_severity=(h.severity or ""),
                target=h.variant["url"], param="", confirmed=True,
                evidence=(f"{meaning}: control {h.control['method']} "
                          f"{h.control['url']} -> HTTP {a.status} ({len(a.body or '')}B); "
                          f"variant {h.variant['method']} {h.variant['url']} -> HTTP "
                          f"{b.status} ({len(b.body or '')}B)"
                          # WHO issued each side, on the finding itself. The audit answers
                          # this for anyone holding the ledger; report.md, report.json
                          # and the SARIF export are generated from HERE, and a reviewer
                          # reading a cross-account claim should not have to correlate
                          # an audit file to learn which principal saw what.
                          + f". Principals: control issued as {_c_as}, "
                            f"variant issued as {_v_as} ({_cl['principals']})"
                          + f". [evidence: {_cl['evidence_class']}] this establishes "
                            f"{_cl['claim']}, and no more"
                          # The model's REASONING is kept and labelled; its TITLE is
                          # not. The rationale is conditional and explains what the agent
                          # was testing, which is the most useful sentence in the record.
                          # The title is a flat assertion — the exact artefact that went
                          # out unearned — and it stays in the note stream, where it reads
                          # as agent chatter rather than as the finding's claim.
                          + (f". UNVERIFIED agent interpretation (NOT part of this "
                             f"finding's claim): {h.rationale}" if h.rationale else "")),
                source=(f"differential [{h.comparator}] between the control and variant "
                        f"requests above"
                        + (f", after {len(h.setup)} setup request(s)" if h.setup else ""))))
        return confirmed
