"""
test_multipart_delivery.py — a detector that runs, costs requests, and cannot fire.

`test_detectors_wired.py` catches a detector nothing calls. This is the next layer of
the same silence: `confirm_deserialization_rce` IS wired into the confirmation pass and
IS invoked, but every delivery mode `_probe` owned put the payload in a query string or
a urlencoded body — and the sink it was written for takes neither.

Measured against the live DVNA target this file's docstring cites (2026-08-07): the
gadget shape is correct and the endpoint is genuinely vulnerable — delivered as a
multipart part named `products`, the node-serialize IIFE runs and Brukal's in-cage
listener receives the token. Delivered as a urlencoded body, the identical payload
produces nothing, because Express populates `req.files` only from a multipart part
carrying a filename. The detector emitted its "Insecure deserialization" coverage row
throughout.

So the sink is real, the payload is right, and the delivery could not reach it. A file
upload is where deserialization and upload sinks actually live; without a multipart mode
those classes are unreportable by construction.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
SINK = "http://127.0.0.1:5000/app/bulkproductslegacy"

_ND = re.compile(r"_\$\$ND_FUNC\$\$_.*?http://[^/]+/(\w+)", re.S)


class _FakeOOB:
    """Stands in for the in-cage listener. `_oob()` caches into `_oob_listener`, so a
    test can seed it directly."""

    # `confirm_blind_rce` builds raw bash/nc payloads from .ip/.port, so a double
    # without them raises AttributeError — which the confirmation pass used to swallow.
    ip = "10.99.0.1"
    port = 31337

    def __init__(self):
        self.tokens: set[str] = set()

    def callback_url(self, token: str) -> str:
        return f"http://{self.ip}:{self.port}/{token}"

    def hit(self, token: str) -> bool:
        return token in self.tokens


class _NodeSerializeSink:
    """DVNA's `bulkProductsLegacy`, faithfully: it unserialises
    `req.files.products.data` and NOTHING else. A urlencoded body leaves `req.files`
    empty, so the payload is never deserialised however perfect it is."""

    def __init__(self, oob: _FakeOOB):
        self.oob = oob
        self.seen: list[str] = []

    def run(self, action):
        ctype = {k.lower(): v for k, v in (action.headers or {}).items()}.get(
            "content-type", "")
        self.seen.append(ctype.split(";")[0] or "GET")
        body = action.body or ""
        if ctype.startswith("multipart/form-data"):
            # only a part that is a FILE (has a filename) lands in req.files
            part = re.search(r'name="products"; filename="[^"]*"\r\n.*?\r\n\r\n(.*?)\r\n--',
                             body, re.S)
            if part:
                m = _ND.search(part.group(1))
                if m:
                    self.oob.tokens.add(m.group(1))   # the IIFE ran
                    return WebResult(status=500, url=action.url, body="")
        return WebResult(status=500, url=action.url, body="")


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    return AssistSession("127.0.0.1", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()),
        browser=GovernedBrowser(scope, cage, audit))


def test_a_file_upload_deserialization_sink_is_reached(monkeypatch):
    """The regression. Before the multipart mode this returns False against a target
    that is genuinely vulnerable."""
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    oob = _FakeOOB()
    sink = _NodeSerializeSink(oob)
    sess = _session(sink)
    sess._oob_listener = oob

    assert sess.confirm_deserialization_rce(SINK, "products", method="POST") is True
    f = sess.findings.all()[0]
    assert f.severity == "critical" and f.confirmed
    assert "multipart/form-data" in sink.seen


def test_the_payload_rides_a_well_formed_multipart_body(monkeypatch):
    """A malformed boundary would be rejected by a real framework before the sink, which
    would look exactly like 'not vulnerable'."""
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    captured: list = []

    class _Cap:
        def run(self, action):
            captured.append(action)
            return WebResult(status=200, url=action.url, body="")

    sess = _session(_Cap())
    sess._probe(SINK, "products", "PAYLOAD", "MULTIPART")
    act = captured[0]
    ctype = act.headers["Content-Type"]
    boundary = ctype.split("boundary=")[1]
    assert ctype.startswith("multipart/form-data; boundary=")
    assert act.body.startswith(f"--{boundary}\r\n")
    assert act.body.endswith(f"--{boundary}--\r\n")
    assert 'name="products"; filename=' in act.body
    assert "\r\n\r\nPAYLOAD\r\n" in act.body


def test_the_autonomous_pass_actually_reaches_a_file_upload_sink(monkeypatch):
    """The other half of the same silence, and the half a delivery fix alone does not
    close: `confirm_surface` built its probe queue with
    `t.lower() not in ("submit", "hidden", "file")`, so a file input was never enqueued
    at all. Fixing `_probe` while leaving that filter in place would make the detector
    provably capable and still never called with the one parameter that matters.

    Gated on intrusive authorisation, on the same reasoning as mass assignment: an
    upload WRITES to the target."""
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    import brukal.webmap as webmap

    oob = _FakeOOB()
    sink = _NodeSerializeSink(oob)
    sess = _session(sink)
    sess._oob_listener = oob
    sess.allow_intrusive = True
    sess.surface = webmap.AttackSurface(seed="http://127.0.0.1:5000/")
    sess.surface.forms = [webmap.Form(action=SINK, method="POST",
                                      inputs=(("products", "file"),))]

    sess.confirm_surface()
    assert any(f.title.startswith("Insecure deserialization") and f.confirmed
               for f in sess.findings.all()), \
        "the autonomous pass never delivered a multipart probe to the file input"


def test_one_blind_detector_throwing_does_not_cancel_the_others(monkeypatch):
    """How the deserialization class actually stayed silent, and the more general bug.

    The three out-of-band detectors were chained as `a() or b() or c()` inside ONE
    `try/except Exception: pass`. Any throw in `a` or `b` skipped everything after it
    and was never logged — while `_covered(...)` had already recorded both classes as
    probed. A crash in blind RCE therefore presented as 'deserialization: clean'."""
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    import brukal.webmap as webmap
    from brukal.assist import AssistSession

    def _boom(self, *a, **k):
        raise RuntimeError("an unrelated failure inside blind RCE")

    monkeypatch.setattr(AssistSession, "confirm_blind_rce", _boom)

    oob = _FakeOOB()
    sink = _NodeSerializeSink(oob)
    sess = _session(sink)
    sess._oob_listener = oob
    sess.allow_intrusive = True
    sess.surface = webmap.AttackSurface(seed="http://127.0.0.1:5000/")
    sess.surface.forms = [webmap.Form(action=SINK, method="POST",
                                      inputs=(("products", "file"),))]

    sess.confirm_surface()
    assert any(f.title.startswith("Insecure deserialization") and f.confirmed
               for f in sess.findings.all()), \
        "a throw in an earlier OOB detector silently cancelled deserialization"


def test_a_file_input_is_not_uploaded_to_without_authorisation(monkeypatch):
    """Read-only by default: an upload creates state on the target, so it must not
    happen in a non-intrusive run."""
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    import brukal.webmap as webmap

    oob = _FakeOOB()
    sink = _NodeSerializeSink(oob)
    sess = _session(sink)
    sess._oob_listener = oob
    sess.allow_intrusive = False
    sess.surface = webmap.AttackSurface(seed="http://127.0.0.1:5000/")
    sess.surface.forms = [webmap.Form(action=SINK, method="POST",
                                      inputs=(("products", "file"),))]

    sess.confirm_surface()
    assert "multipart/form-data" not in sink.seen


def test_extra_fields_ride_along_as_ordinary_parts(monkeypatch):
    """Upload sinks routinely require a sibling field (a CSRF token, a category id);
    the payload part must not be the only thing in the body."""
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    captured: list = []

    class _Cap:
        def run(self, action):
            captured.append(action)
            return WebResult(status=200, url=action.url, body="")

    sess = _session(_Cap())
    sess._probe(SINK, "products", "P", "MULTIPART",
                {"csrf": "tok123", "_filename": "x.json"})
    body = captured[0].body
    assert 'name="products"; filename="x.json"' in body
    assert 'name="csrf"' in body and "tok123" in body
    assert "_filename" not in body       # a directive, not a field
