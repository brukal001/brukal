"""
test_capture_resp_headers.py — a captured record keeps the response HEADERS too.

`_record` already kept the response BODY (redacted, truncated) because a value the
target handed back and the client later sent is a reference — see capture.py's own
docstring on `CapturedRequest.response`. The headers are the other half of the same
answer (Content-Type, Set-Cookie shape, caching, CORS) and Task 7's live web door will
have both in hand at the same call site, so `_record` must accept and keep both.

Scope is built with the REAL dataclass constructor (see `scope.py` / `tests/test_web.py`
and friends) — there is no `Scope.from_dict`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import capture
from brukal.scope import Scope


def _scope():
    return Scope("t", (), frozenset({"*"}), 60,
                 authorized_hosts=frozenset({"lab.example"}), authorization="test")


def test_record_keeps_response_body_and_headers():
    rec = capture._record("GET", "http://lab.example/x", {}, None, 200, 11, "text/html",
                          _scope(), capture.IngestReport(), "self",
                          response="<html>ok</html>", resp_headers={"Content-Type": "text/html"})
    assert rec is not None
    assert rec.response == "<html>ok</html>"
    assert rec.resp_headers["Content-Type"] == "text/html"


def test_resp_headers_defaults_to_empty_dict_when_omitted():
    """Existing callers (parse_har, parse_curl) don't pass resp_headers — behavior must
    be unchanged: the record still builds, with an empty resp_headers rather than None."""
    rec = capture._record("GET", "http://lab.example/y", {}, None, 200, 4, "text/html",
                          _scope(), capture.IngestReport(), "self")
    assert rec is not None
    assert rec.resp_headers == {}
