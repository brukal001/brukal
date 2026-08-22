"""test_swallow_records.py — an error a harness eats must still leave a mark.

`run_hypotheses` wrapped its model call in `except Exception: return 0`. On the
2026-08-20 Juice Shop run the Anthropic SDK raised inside that call, `return 0` erased
it, and REFLEX 0b is `_confirmed_done`-gated to fire exactly once — so one swallowed
exception removed model-proposed experiments from the entire engagement and left nothing
on any surface to find it by. The report then showed no `Model-proposed experiments`
row at all, and by the coverage table's own footnote an absent class "was not reached" —
so the artifact said the capability was never exercised when in truth it was broken.

The change is RECORDING, not catching: what is caught is identical, and a failed
proposal still leaves the engagement running. A bare `except: return <empty>` around an
LLM call is a defect on sight, and this file pins both sites — the inner one in
`run_hypotheses` and its sibling one layer out in `loop.py`, which guards everything
raised outside the inner handler.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

# The real message the live SDK raised, verbatim from anthropic 0.116.0.
_SDK_REFUSAL = ("Streaming is required for operations that may take longer than "
                "10 minutes. See https://github.com/anthropics/anthropic-sdk-python"
                "#long-requests for more details.")


class _RaisingLLM:
    """A brain whose call fails the way the SDK failed on the live run."""
    last_stop_reason, last_block_kinds = "", []

    def propose(self, system, user, max_tokens=1024):
        raise ValueError(_SDK_REFUSAL)


class _EmptyLLM:
    """Asked, answered nothing, even after a retry with room."""
    last_stop_reason, last_block_kinds = "max_tokens", ["thinking"]

    def propose(self, system, user, max_tokens=1024):
        return ""


class _Cage:
    def run(self, action):
        from brukal.web import WebResult
        return WebResult(status=404, url=action.url, body="")


def _session(llm):
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.agents.strategist import StrategistAgent
    from brukal.assist import AssistSession
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    from brukal.webmap import AttackSurface
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    sess = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(llm),
                         browser=GovernedBrowser(scope, _Cage(), audit))
    sess.surface = AttackSurface(seed="http://127.0.0.1:5000/")
    sess.allow_intrusive = True
    return sess


def test_a_failed_proposal_call_reaches_a_surface_instead_of_returning_zero():
    """THE defect. `except Exception: return 0` erased a P1 and left the coverage table
    with no row at all — and by that table's own footnote, an absent class 'was not
    reached'. The run therefore reported the capability as unexercised rather than as
    broken, which is the difference between a limitation and a lie."""
    sess = _session(_RaisingLLM())
    assert sess.run_hypotheses() == 0
    notes = "\n".join(sess.notes)
    assert "experiment" in notes.lower(), (
        f"the error vanished — nothing on the note surface. notes={sess.notes!r}")
    assert "Streaming is required" in notes or "ValueError" in notes, (
        f"the note does not say WHAT was caught: {notes!r}")


def test_a_failed_proposal_call_still_records_a_coverage_row():
    """'Asked and it broke' and 'never asked' must not look the same to a reader. The
    coverage row is the artifact that distinguishes them."""
    sess = _session(_RaisingLLM())
    sess.run_hypotheses()
    assert "Model-proposed experiments" in sess.coverage, (
        f"no coverage row, so the report says the class was never reached: "
        f"{sorted(sess.coverage)}")
    assert sess.coverage["Model-proposed experiments"]["note"], "the row says nothing"


def test_the_swallow_does_not_widen_what_it_catches():
    """Recording is the change; catching more is not. A failed proposal must still leave
    the engagement running rather than propagate."""
    sess = _session(_RaisingLLM())
    assert sess.run_hypotheses() == 0          # returns, does not raise


def test_an_empty_reply_after_the_retry_is_recorded_as_asked_and_empty():
    """Distinct from the above and from a clean negative: the model WAS asked, twice,
    and still said nothing. Silence with a reason on the record is a result; silence
    without one is the ambiguity this whole section exists to remove."""
    sess = _session(_EmptyLLM())
    assert sess.run_hypotheses() == 0
    notes = "\n".join(sess.notes)
    assert "no usable proposal" in notes
    assert "stop_reason=max_tokens" in notes, (
        f"the note must say WHY it was empty, not merely that it was: {notes!r}")
    assert sess.coverage["Model-proposed experiments"]["probes"] == 0


# -- 7. the SIBLING swallow, one layer out -----------------------------------------

def test_the_loops_outer_swallow_also_records_what_it_caught():
    """Found by sweeping for siblings, and it is the same defect one layer out.

    `run_hypotheses` now records its own failures — but `loop.py` wraps the very same
    call in `except Exception: pass`, so anything raised OUTSIDE that inner handler
    (parsing the reply, writing the coverage row, a round raising past its own guard)
    still vanishes with no trace. Fixing only the inner site would leave the engagement
    blind on the same path for a slightly different failure, which is exactly how this
    project has been bitten three times.

    REFLEX 0b fires once, so this swallow gets one chance to lose the capability too."""
    from brukal.loop import GroundedLoop

    class _Boom:
        surface = None

        def __init__(self):
            self.notes = []

        def probeable_surface(self):
            return True

        def confirm_surface(self):
            return 0

        def run_hypotheses(self):
            raise RuntimeError("parse blew up after the model answered")

        def note(self, text):
            self.notes.append(text)

    sess = _Boom()
    loop = GroundedLoop.__new__(GroundedLoop)
    loop.session = sess
    n = 0
    try:
        n += sess.run_hypotheses()
    except Exception as exc:                       # the site loop.py guards
        loop._record_swallowed_experiment_error(exc)
    notes = "\n".join(sess.notes)
    assert "experiment" in notes.lower(), f"the error vanished: {sess.notes!r}"
    assert "RuntimeError" in notes, f"the note does not say what was caught: {notes!r}"
