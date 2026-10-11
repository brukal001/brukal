"""
test_manual_web_line.py — a typed WEB action at the manual prompt actually runs.

The 2026-10-01 live run typed `via:browser get <url>` at the MANUAL prompt: its first
token is not a tool, so the line was taken as a free-text instruction and never ran.
Also fixed here: in the rich menu, picking a numbered WEB option did nothing (only RUN
and MANUAL were handled), and a web line typed as 'your command' went to the shell gate.

Recognition is conservative: an ordinary sentence ("get the flag") stays an
instruction. A recognised line still goes through the governed browser's gate.
"""
from __future__ import annotations

import io
import sys
import tempfile
from pathlib import Path

import pytest

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.assist_cli import _web_line
from brukal.web import FakeWebCage, GovernedBrowser

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
U = "http://10.10.10.5/filter?category=Gifts"


@pytest.mark.parametrize("line,expected", [
    (f"via:browser get {U}", f"via:browser get {U}"),
    (f"via:raw request POST {U} a=1", f"via:raw request POST {U} a=1"),
    (f"web get {U}", f"get {U}"),
    (f"WEB: navigate {U}", f"navigate {U}"),
    (U, U),
    (f"get {U}", f"get {U}"),
    (f"request POST {U} a=1", f"request POST {U} a=1"),
])
def test_web_lines_are_recognised(line, expected):
    assert _web_line(line) == expected


@pytest.mark.parametrize("line", [
    "get the flag", "navigate to the admin panel", "request a password reset",
    "nmap -sV 10.10.10.5", "focus on the category filter", "what did we find?", "",
    "click the login button",
])
def test_ordinary_lines_are_not_web(line):
    assert _web_line(line) is None


class _SeqLLM:
    last_stop_reason = "end_turn"

    def __init__(self, responses):
        self.responses, self.i = list(responses), 0

    def propose(self, system, user, max_tokens=1024):
        r = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return r


_OPTIONS = ("OPTION: scan services\nPHASE: recon\nGOAL: fingerprint\n"
            "REASONING: start.\nRUN: nmap -sV 10.10.10.5")


def test_typed_via_browser_line_runs_through_the_governed_browser():
    from brukal.assist import _plain_loop
    tmp = tempfile.mkdtemp()
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tmp) / "a.jsonl")
    kali = FakeKali()
    sess = AssistSession("10.10.10.5", Executor(Gate(scope), kali, audit),
                         StrategistAgent(_SeqLLM(["1. [recon] scan", _OPTIONS])),
                         browser=GovernedBrowser(scope, FakeWebCage(), audit))
    old = sys.stdin
    sys.stdin = io.StringIO(f"via:browser get {U}\nquit\n")
    try:
        _plain_loop(sess, audit, "10.10.10.5", "fake")
    finally:
        sys.stdin = old
    web = [line for line in audit.path.read_text().splitlines() if '"web_decision"' in line]
    assert any("/filter" in w for w in web), "the typed web line never reached the browser"
    assert kali.executed == []          # it was NOT sent to the shell
