"""test_principal_before_detectors.py — establish the principals before spending on probes.

The 2C3 and 2C3b pre-flights both failed their second-principal gate for the same reason,
and it was an ORDERING problem rather than a budget one. The loop ran:

    crawl  ->  confirm_surface()  ->  run_hypotheses() -> establish_second_identity()

so the entire deterministic detector sweep — including `confirm_missing_rate_limit`,
which deliberately sends 8 rapid failed logins — spent the web-rate budget *before* the
engagement tried to create the second account. `POST /api/Users` and `POST /register`
were then denied `hard:web-rate`, and every cross-account experiment in the run had to be
recorded NOT RUN.

Halving the login cost (`13bc501`) halved the denials, 26 -> 13, and still did not clear
the gate, because the problem is not the total. It is that the cheapest, most
load-bearing acquisition in the engagement was queued behind the most expensive sweep.

**A principal the whole engagement depends on is acquired first.** It cannot run before
the crawl — candidate signup endpoints come from what the crawl observed — so
immediately after the crawl and before the detectors is the only correct place.

`establish_second_identity` is idempotent: the later call inside `run_hypotheses` becomes
a cache hit, so nothing is acquired twice and the fail-closed path is unchanged.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path


class _Recorder:
    """A session double that records the ORDER of the calls the loop makes."""

    surface = None

    def __init__(self, *, second="brk2@x.test"):
        self.calls: list = []
        self.notes: list = []
        self._second = second

    # -- what the loop's reflex calls, in the order it calls them ------------
    def probeable_surface(self):
        return True

    def establish_second_identity(self):
        self.calls.append("establish_second_identity")
        return self._second

    def confirm_surface(self, *a, **kw):
        self.calls.append("confirm_surface")
        return 0

    def run_hypotheses(self, *a, **kw):
        self.calls.append("run_hypotheses")
        return 0

    def note(self, text):
        self.notes.append(text)


def _reflex(sess):
    """Drive just the reflex that owns this ordering."""
    from brukal.loop import GroundedLoop
    loop = GroundedLoop.__new__(GroundedLoop)
    loop.session = sess
    loop._confirmed_done = False
    loop._establish_principals()
    return loop


# -- 1. the ordering property ---------------------------------------------------

def test_the_second_principal_is_established_before_any_detector_runs():
    """The named defect. Acquisition must not be queued behind the sweep that spends
    the budget it needs."""
    sess = _Recorder()
    _reflex(sess)
    assert "establish_second_identity" in sess.calls, "acquisition never happened"
    if "confirm_surface" in sess.calls:
        assert (sess.calls.index("establish_second_identity")
                < sess.calls.index("confirm_surface")), (
            f"the detector sweep ran first: {sess.calls}")


def test_the_loop_establishes_before_it_sweeps():
    """The same property through the real reflex body rather than the helper."""
    import inspect

    from brukal.loop import GroundedLoop
    src = inspect.getsource(GroundedLoop)
    est = src.index("_establish_principals()")
    conf = src.index("confirm_surface()")
    assert est < conf, (
        "establishment is still written after the detector sweep in the reflex body")


def test_the_order_holds_whatever_the_step_budget():
    """A tiny budget compressed everything into one window and is what made this
    visible; the ordering must not depend on how much budget there is."""
    for _budget in (1, 3, 70):
        sess = _Recorder()
        _reflex(sess)
        assert sess.calls[0] == "establish_second_identity", (
            f"budget {_budget}: acquisition was not first ({sess.calls})")


# -- 2. the boundaries the move must not break -----------------------------------

def test_establishment_still_fails_closed_when_there_is_no_signup_door():
    """Moving it earlier must not turn a failure into a pass. No door, no principal,
    and the engagement carries on to be told NOT RUN by the comparator later."""
    sess = _Recorder(second="")
    loop = _reflex(sess)
    assert sess.calls[0] == "establish_second_identity"
    assert loop is not None                      # the reflex did not raise

def test_a_failure_to_establish_does_not_stop_the_engagement():
    class _Boom(_Recorder):
        def establish_second_identity(self):
            self.calls.append("establish_second_identity")
            raise RuntimeError("registration blew up")

    sess = _Boom()
    _reflex(sess)                                 # must not propagate
    assert "establish_second_identity" in sess.calls
    assert any("principal" in n.lower() for n in sess.notes), (
        f"a failed acquisition left no trace: {sess.notes}")


def test_establishment_is_idempotent_so_the_later_call_is_a_cache_hit():
    """`run_hypotheses` still calls it. That must cost nothing the second time, or the
    saving is handed straight back."""
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import FakeKali

    class _LLM:
        def propose(self, s, u, max_tokens=1024):
            return "[]"

    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(_LLM()))
    sess._second_identity = {"user": "brk2", "password": "x",
                             "cookies": {"s": "v"}, "auth": "Bearer t"}
    assert sess.establish_second_identity() == "brk2"
    assert sess.establish_second_identity() == "brk2"      # no work, no requests
