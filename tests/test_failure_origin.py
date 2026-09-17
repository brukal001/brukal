"""
test_failure_origin.py — a silence WE caused is not a silence THEY caused.

THE MEASURED PROBLEM (CR1 pre-flight, crAPI, 2026-09-17)
    nmap found 443 open, the crawler followed it to `https://`, and crAPI serves a
    self-signed certificate. Ten consecutive `SSL: CERTIFICATE_VERIFY_FAILED` fetches
    reached `TargetHealth.record(answered=False)`, the loop halted with
    `target-unhealthy`, and the REPORT blamed the target — which was `healthy`, had
    never restarted, and whose own access log shows it answering 404s throughout.
    Measured at the moment of the halt, from inside the cage:

        https, no verification (-k)   -> 200, 1207 bytes
        https, verification on        -> 000, certificate verification failed
        http, same moment             -> 200

    The harness wrote its own limit into the ledger as a target refusal. CR1's
    definition of done requires every outcome attributed to target / harness / model,
    so this defect does not merely stop a run: it mis-attributes by construction.

THE PROPERTY IS ORIGIN, NOT TLS
    `record()`'s own docstring said "a timeout, a refused connection or a torn-down
    socket is not [an answer]". A TLS verification failure is none of those three: the
    socket connected and the server answered — the CLIENT refused the answer. So the
    question health asks is not "did an exception happen" but "did the SILENCE come from
    the target". Only target-origin silence counts toward health; client-origin failure
    is recorded with its cause and surfaces as a HARNESS LIMIT.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, load_scope
from brukal.health import TargetHealth, failure_origin, CLIENT_ORIGIN, TARGET_ORIGIN
from brukal.web import GovernedBrowser, WebAction, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"

# The exact note the CR1 ledger carries, ten times over.
CR1_TLS_NOTE = ("<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify "
                "failed: self signed certificate (_ssl.c:1010)>")


# --------------------------------------------------------------------------- #
# The classifier — every exception path that can reach record()
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("note", [
    CR1_TLS_NOTE,
    "<urlopen error [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure>",
    "certificate verify failed: unable to get local issuer certificate",
    "<urlopen error [Errno -2] Name or service not known>",
    "<urlopen error [Errno -3] Temporary failure in name resolution>",
    "cage web error: Command '['docker', 'exec', ...]' timed out after 30 seconds",
    "'click' needs the live CDP browser (interactive) — not wired live yet",
    "[fake get] get http://t/",
    "interception armed for http://t/",
    "unreachable: [Errno 101] Network is unreachable",
    "unreachable: [Errno 113] No route to host",
])
def test_client_origin_failures_are_ours(note):
    """Each of these is the CLIENT refusing, failing, or never asking — not the target
    declining to answer. The routing pair matters most: our own egress lock produces
    exactly that shape for a host we refused to reach."""
    assert failure_origin(note) == CLIENT_ORIGIN, note


@pytest.mark.parametrize("note", [
    "unreachable: timed out",
    "unreachable: [Errno 110] Connection timed out",
    "unreachable: [Errno 111] Connection refused",
    "unreachable: [Errno 104] Connection reset by peer",
    "<urlopen error [Errno 104] Connection reset by peer>",
    "RemoteDisconnected('Remote end closed connection without response')",
    "unreachable: [Errno 32] Broken pipe",
])
def test_target_origin_failures_are_theirs(note):
    assert failure_origin(note) == TARGET_ORIGIN, note


def test_an_unclassifiable_silence_counts_against_the_target():
    """Fail-closed, invariant 2. The safe default for health is to STOP: an unknown
    silence we cannot explain is treated as the target's, because continuing to hammer
    something that may be dying is the failure this module exists to prevent."""
    assert failure_origin("something nobody has seen before") == TARGET_ORIGIN
    assert failure_origin("") == TARGET_ORIGIN


# --------------------------------------------------------------------------- #
# The CR1 case, at the level that halted
# --------------------------------------------------------------------------- #

def test_ten_TLS_failures_against_an_answering_target_do_not_halt():
    """THE DEFECT. 15 answered then 10 TLS verification failures — CR1's exact counts."""
    h = TargetHealth()
    for _ in range(15):
        h.record(True)
    for _ in range(10):
        h.record(False, note=CR1_TLS_NOTE)
    assert h.state == "healthy", "our own TLS refusal was read as the target dying"
    assert h.should_stop() == "", "the run would halt on a target answering 200s"


def test_a_real_timeout_still_halts():
    """The behaviour the module exists for is untouched."""
    h = TargetHealth()
    for _ in range(15):
        h.record(True)
    for _ in range(10):
        h.record(False, note="unreachable: timed out")
    assert h.state == "dead"
    assert "consecutive" in h.should_stop()


def test_a_404_and_a_500_are_still_answers():
    """BOUNDARY: status-code semantics are unchanged — several of the flaws Brukal looks
    for are found precisely by making an application error."""
    h = TargetHealth()
    for _ in range(12):
        h.record(True)       # a 404/500 arrives here as answered=True
    assert h.state == "healthy"
    assert h.should_stop() == ""


def test_client_origin_failures_do_not_reset_or_mask_a_real_stop():
    """A TLS failure interleaved with real timeouts must neither reset the consecutive
    run nor be counted into it."""
    h = TargetHealth()
    for _ in range(6):
        h.record(True)
    for _ in range(5):
        h.record(False, note="unreachable: timed out")
        h.record(False, note=CR1_TLS_NOTE)
    assert h.consecutive == 5, "client-origin noise changed the target's run length"
    assert h.should_stop() != ""


# --------------------------------------------------------------------------- #
# The record must say which, and the sentence must match it
# --------------------------------------------------------------------------- #

def test_the_operator_sentence_counts_only_what_the_ledger_supports():
    """The stop sentence claims 'N successful one(s)'. That number must be the answered
    requests the ledger shows — client-origin failures are named separately, never
    folded into the target's tally."""
    h = TargetHealth()
    for _ in range(15):
        h.record(True)
    for _ in range(4):
        h.record(False, note=CR1_TLS_NOTE)
    for _ in range(10):
        h.record(False, note="unreachable: timed out")
    msg = h.should_stop()
    assert "10 consecutive" in msg
    assert "after 15 successful" in msg
    assert "client-origin" in msg and "4" in msg, (
        "the four failures we caused are invisible in the sentence the operator reads")


def test_the_summary_does_not_blame_a_target_for_our_failures():
    h = TargetHealth()
    for _ in range(15):
        h.record(True)
    for _ in range(10):
        h.record(False, note=CR1_TLS_NOTE)
    s = h.summary()
    assert not s.startswith("⚠ TARGET HEALTH"), s
    assert "harness" in s.lower() or "client-origin" in s.lower(), s


def test_client_failures_carry_their_cause():
    h = TargetHealth()
    h.record(False, note=CR1_TLS_NOTE)
    h.record(False, note="cage web error: docker exec failed")
    assert h.client_failures == 2
    assert "tls-verification" in h.client_causes
    assert "cage-plumbing" in h.client_causes


# --------------------------------------------------------------------------- #
# The plane: a client-origin failure surfaces as a harness limit in the LEDGER
# --------------------------------------------------------------------------- #

class _TLSRefusingTarget:
    """Answers plain HTTP; every https fetch fails verification. crAPI, exactly."""
    def run(self, action):
        if action.url.startswith("https://"):
            return WebResult(url=action.url, note=CR1_TLS_NOTE)
        return WebResult(status=200, url=action.url, body="ok")


def _browser(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    return GovernedBrowser(load_scope(SCOPE), _TLSRefusingTarget(), audit), audit


def _kinds(audit_path):
    return [json.loads(l) for l in open(audit_path)]


def test_a_client_origin_failure_is_audited_as_a_harness_limit(tmp_path):
    b, audit = _browser(tmp_path)
    b.run(WebAction("get", url=f"https://{TARGET}/openapi.json"))
    rows = [r for r in _kinds(audit.path) if r["kind"] == "harness_limit"]
    assert rows, "a failure we caused left no harness-limit record in the ledger"
    assert rows[0]["data"]["cause"] == "tls-verification"
    assert rows[0]["data"]["plane"] == "web"


def test_the_CR1_sequence_end_to_end_leaves_the_browser_healthy(tmp_path):
    """15 good HTTP fetches, then CR1's ten https fetches. The loop's stop check reads
    `browser.health.should_stop()`; it must stay empty."""
    b, _ = _browser(tmp_path)
    for i in range(15):
        b.run(WebAction("get", url=f"http://{TARGET}/p{i}"))
    for i in range(10):
        b.run(WebAction("get", url=f"https://{TARGET}/s{i}"))
    assert b.health.should_stop() == ""
    assert b.health.state == "healthy"


def test_a_target_origin_failure_is_NOT_audited_as_a_harness_limit(tmp_path):
    """BOUNDARY: the new record must not fire for the target's own silence, or the
    ledger would attribute a target refusal to us — the same defect, mirrored."""
    class _Dead:
        def run(self, action):
            return WebResult(url=action.url, note="unreachable: timed out")
    audit = AuditLog(tmp_path / "a.jsonl")
    b = GovernedBrowser(load_scope(SCOPE), _Dead(), audit)
    b.run(WebAction("get", url=f"http://{TARGET}/x"))
    assert not [r for r in _kinds(audit.path) if r["kind"] == "harness_limit"]
