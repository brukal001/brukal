# Brukal — Threat Model

*Companion to [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) and [`RESEARCH_FINDINGS.md`](RESEARCH_FINDINGS.md).
Written 2026-10-11 against branch `feat/security-audit-suite`.*

## 1. What Brukal promises

An operator can point Brukal at an authorised target and trust two things at once:

1. **It will never do wrong to the target or to anything outside scope** — no matter what the
   model proposes, including a model whose reasoning has been hijacked by hostile target
   content (prompt injection).
2. **What it reports is true** — a finding marked CONFIRMED rests on deterministic evidence,
   and the audit log is a faithful, tamper-evident record of every action.

The design premise: **the model proposes; deterministic code disposes.** Safety never depends
on the model behaving well.

## 2. Trust boundaries

| Component | Trust | Why |
|---|---|---|
| `scope.json` → frozen `Scope` | **trusted** (operator-authored, draft → approve → freeze) | immutable at runtime (invariant 5) |
| `gate.py`, `hostmatch.py`, `scope.py`, `risk.py` | **trusted** | stdlib-only, no LLM (invariant 1), fail-closed (invariant 2) |
| `executor.py` | **trusted** — the ONE door | gates first, logs always (invariant 4) |
| `audit.py` | **trusted** | hash-chained, append-only, anchored against truncation (invariant 5) |
| `capture_confirm.py` provers | **trusted** | deterministic string/set checks over already-captured traffic |
| Kali cage + egress proxy + nftables | **trusted, defence in depth** | contains what the gate allowed; never relied on to excuse a gate gap |
| **Model output** (every agent's proposal, its self-report, its claimed findings) | **UNTRUSTED** | may be wrong, hallucinated, or attacker-steered |
| **Target-controlled data** (HTTP bodies, headers, banners, tool output, files on the box) | **UNTRUSTED** | the attacker writes it; it flows into prompts |
| Skill packs, web research | **UNTRUSTED** | labelled as such in prompts |
| Environment (cage files, DNS, `/etc/hosts`, Docker service names) | **UNTRUSTED** for targeting | a name can resolve anywhere — hence SEC-003 / SEC-008 |

## 3. The attacker we design against

The strongest realistic adversary is **the target itself**, feeding the model content that
steers its proposals (indirect prompt injection). We therefore assume, for every check:

- **the model's output is fully attacker-chosen** — any command string, any `target` field, any
  claimed result; it will use every spelling the parser might miss;
- the attacker **cannot** modify Brukal's code, the frozen scope, or the host filesystem
  outside the cage;
- for audit-log integrity specifically, we also consider an actor **with file-write access to
  the ledger** (keyed vs unkeyed modes, `SECURITY_AUDIT.md` SEC-006).

Under that model a gate gap is exploitable by text alone, which is why SEC-001/002/003/008 were
rated by what a hijacked model could make the gate ALLOW, not by how likely a benign model is to
write it.

## 4. Data flow and the one execution path

```
 target content ──┐  (UNTRUSTED)
 skills / web  ───┤
                  ▼
           ┌─────────────┐   text only (schema-validated Action Request)
           │   AGENTS    │ ───────────────────────────────────────────────┐
           │ (LLM)       │   no kali object, no sockets, no exec          │
           └─────────────┘                                                ▼
                                                    ┌──────────────────────────────┐
                                                    │ GATE  (deterministic, no LLM)│
                                                    │ injection → parse → allowlist│
                                                    │ → declared target in scope   │
                                                    │ → EVERY host in the text     │
                                                    │   (hostmatch: IPs, encodings,│
                                                    │   URLs, CIDR/ranges, paths,  │
                                                    │   dotless in tool positions) │
                                                    │ → no UNSEEN targets (files,  │
                                                    │   stdin, random, variables)  │
                                                    │ → rate → capability          │
                                                    │ → soft RISK (ALLOW/ESCALATE/ │
                                                    │   DENY; can only tighten)    │
                                                    └──────────────┬───────────────┘
                                          DENY ◄───────────────────┤ ESCALATE → human
                                                                   ▼ ALLOW
                                         ┌────────────┐   ┌────────────────────────┐
                                         │ AUDIT LOG  │◄──│ EXECUTOR (the one door)│
                                         │ hash chain │   └───────────┬────────────┘
                                         │ + anchors  │               ▼
                                         └────────────┘   ┌────────────────────────┐
                                                ▲         │ KALI CAGE              │
                                                │         │ egress proxy (per-req  │
                                     CONFIRM ◄──┤         │ scope) + nftables lock │
                                     (provers   │         └───────────┬────────────┘
                                      over the  │                     ▼
                                      captured  └──────── captured traffic / output
                                      traffic)               (UNTRUSTED, back to agents)
```

- **One execution path (I4):** agents are handed `executor.run`, never the cage. Static tests
  enforce no exec/socket outside the door modules.
- **Scope is set before the run (I5):** draft → operator approve → freeze. A session cannot
  widen it; the gate can only DENY.
- **Findings are confirmed by provers, never by the model:** a model's "I found SQLi" is a
  candidate; a CONFIRMED finding needs a correlated deterministic differential (SEC-007).

## 5. What each layer does NOT cover (stated, not assumed away)

| Gap | Where it is held instead |
|---|---|
| A host assembled at run time inside a live shell (`a=10.10.10.1; curl ${a}1`, base64-decoded hosts) | session door: cage egress firewall. (Variables in a host position are denied, SEC-008; arbitrary computation cannot be parsed.) |
| A payload inside a request body that makes the *target* fetch elsewhere (SSRF probes) | the request goes to the in-scope target; what the target then contacts is the target's own behaviour under test. URLs written in the command are still scope-checked. |
| Unkeyed ledger rewritten by a file-writer (edit + re-chain + sidecar) | keyed mode + off-machine anchor (`brukal verify` prints it) |
| Keyed ledger truncated back to a saved old sidecar | off-machine anchor |
| The model being *persuaded* (prompt injection) to propose harmful **in-scope** actions | soft risk layer: writes/attacks ESCALATE to a human, wide+irreversible DENY; nothing the model says lowers risk (SEC-009). Measuring how often injection succeeds is a proposed experiment (`RESEARCH_FINDINGS.md`). |
| Stale evidence from another run in confirmation | NOT-TESTABLE today (no run id on captures) |

## 6. Assumptions this model rests on

- The cage image and host are not compromised; `scope.json` reflects real written authorisation.
- Docker networking and nftables behave as configured (verified live on 2026-09-29/30 for the
  egress proxy; not re-verified in this audit).
- Python's `ipaddress`, `shlex`, `urllib.parse` behave per their documentation.
