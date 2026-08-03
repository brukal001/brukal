"""An endpoint that echoes its input must not be able to prove SSRF.

`computeMetadata` appears IN the GCP payload URL
(http://metadata.google.internal/computeMetadata/v1/), so any form that redisplays a
submitted value matched the IMDS marker with the marker it had just been handed. A live
DVNA run reported two CRITICAL "SSRF to GCP metadata" findings against /app/useredit —
on a container that cannot resolve metadata.google.internal at all.

The same echo defect was found and fixed once before, in hypothesis.py's bodies_differ
comparator. The rule never reached the SSRF prover.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
URL = "http://127.0.0.1:5000/app/useredit"


def _sess(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


class _Echoes:
    """Renders whatever it was sent straight back — an ordinary profile form."""

    def run(self, action):
        sent = (action.body or "") + action.url
        return WebResult(status=200, url=action.url, headers={},
                         body=f"<html><input value='{sent}'></html>")


class _ReallyFetches:
    """Actually returns metadata content the request did NOT contain."""

    def run(self, action):
        return WebResult(status=200, url=action.url, headers={},
                         body="ami-id\ninstance-id\niam/security-credentials/role")


def test_an_echoing_form_does_not_prove_ssrf():
    s = _sess(_Echoes())
    assert s.confirm_ssrf(URL, "name", method="POST") is False
    assert not [f for f in s.findings.all() if "SSRF" in f.title], \
        "the payload proved itself by being echoed back"


def test_a_server_that_really_fetches_is_still_confirmed():
    """The fix must not cost the true positive: these markers are NOT in any payload."""
    s = _sess(_ReallyFetches())
    assert s.confirm_ssrf(URL, "name", method="POST") is True
    assert any(f.confirmed and "SSRF" in f.title for f in s.findings.all())


def test_the_payload_is_stripped_in_its_encoded_forms_too():
    strip = AssistSession._without_payload
    p = "http://metadata.google.internal/computeMetadata/v1/"
    assert "computeMetadata" not in strip(f"you sent {p} ok", p)
    assert "computeMetadata" not in strip(
        "sent http%3A%2F%2Fmetadata.google.internal%2FcomputeMetadata%2Fv1%2F", p)


# --- a differential needs a MARGIN, not merely a strict inequality -------------------
class _JitteryPing:
    """A ping handler whose output differs by a couple of bytes between requests, with
    FALSE deterministically one byte further from the baseline than TRUE. That makes
    `st > sf` TRUE while the gap is a ten-thousandth — the exact live shape."""

    def run(self, action):
        from urllib.parse import unquote_plus
        sent = unquote_plus((action.body or "") + action.url)
        filler = "x" * 4000
        tail = ""
        if "AND" in sent:
            tail = "bc" if ("'1'='2" in sent or "1=2" in sent or '"1"="2' in sent) else "b"
        return WebResult(status=200, url=action.url, headers={},
                         body=f"<html>PING {filler}{tail}</html>")


def test_a_ten_thousandth_of_difference_is_not_sql_injection():
    """Live /app/ping produced 0.9985 vs 0.9984 and was reported CRITICAL. Because the
    sweep stops at the first confirmed class per parameter, that false positive MASKED
    the real command injection on the same endpoint."""
    s = _sess(_JitteryPing())
    assert s.confirm_sqli("http://127.0.0.1:5000/app/ping", "address",
                          method="POST") is False
    assert not [f for f in s.findings.all() if "SQL injection" in f.title]


class _RealSqli:
    """TRUE renders the row, FALSE renders an empty result — a genuine divergence."""

    def run(self, action):
        from urllib.parse import unquote_plus
        sent = unquote_plus((action.body or "") + action.url)
        rows = "<tr><td>victim</td></tr>" * 40
        empty = "<tr><td>no results</td></tr>"
        shell = "<html>" + ("y" * 400) + "%s</html>"
        if "'1'='2" in sent or "1=2" in sent or '"1"="2' in sent:
            return WebResult(status=200, url=action.url, headers={}, body=shell % empty)
        return WebResult(status=200, url=action.url, headers={}, body=shell % rows)


def test_a_real_divergence_is_still_confirmed():
    s = _sess(_RealSqli())
    assert s.confirm_sqli("http://127.0.0.1:5000/app/usersearch", "login",
                          method="POST") is True
