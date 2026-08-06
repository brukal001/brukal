"""Learn what THIS application's answers mean, instead of assuming.

Eighteen hardcoded status-code comparisons and nineteen hardcoded English phrases
decided whether a response was a refusal, a miss or a success. Each is a sentence about
the two applications Brukal was written against, masquerading as a sentence about the
web — and each is a bug waiting on the next unfamiliar target.
"""
from __future__ import annotations

from types import SimpleNamespace

from brukal import calibrate as cal
from brukal import hypothesis as hyp


def _r(status, body="", location=""):
    return SimpleNamespace(status=status, body=body,
                           headers={"Location": location} if location else {})


# --- the miss that cost a confirmed critical -----------------------------------------

def test_a_login_redirect_is_recognised_as_this_apps_refusal():
    """DVNA refuses a stranger with 302 -> /login. The comparator required 401 or 403,
    so a perfect experiment — anonymous 302 versus a member's 200 with 9,978 bytes of
    the user table — was thrown away."""
    p = cal.TargetProfile()
    p.learn_denied(_r(302, "", "/login"), "http://t/admin")
    assert p.is_denied(_r(302, "", "/login?next=/x")) is True
    assert p.is_denied(_r(200, "y" * 4000)) is False


def test_an_uncalibrated_profile_never_weakens_the_old_rule():
    """Calibration may only ADD certainty. A profile that learned nothing must return
    None — not False — or an uncalibrated run would silently report nothing."""
    p = cal.TargetProfile()
    assert p.is_denied(_r(403)) is None
    assert hyp._denied(_r(403), p) is True          # falls through to the old rule
    assert hyp._denied(_r(302, "", "/login"), p) is True


def test_the_comparator_uses_the_learned_refusal():
    p = cal.TargetProfile()
    p.learn_denied(_r(302, "", "/login"), "http://t/admin")
    p.learn_missing(_r(404, "not found"), "http://t/nope")
    h = hyp.Hypothesis("t", "high", "a_denied_b_allowed",
                       {"url": "http://t/a", "method": "GET"},
                       {"url": "http://t/b", "method": "GET"})
    held, _why = hyp.judge(h, _r(302, "", "/login"), _r(200, "x" * 9978), p)
    assert held is True


# --- "substantive" is measured against the app, not against zero ---------------------

def test_an_empty_shell_page_is_not_substantive():
    """len(body) > 0 is wrong on any app that renders a full template around an empty
    result: its 'nothing here' page is kilobytes."""
    p = cal.TargetProfile()
    p.learn_missing(_r(200, "<html><body><div>No results</div></body></html>"), "http://t/x")
    same_shell = _r(200, "<html><body><div>No results</div></body></html>")
    assert p.is_substantive(same_shell) is False
    real = _r(200, "<html><body>" + "<tr><td>row</td></tr>" * 200 + "</body></html>")
    assert p.is_substantive(real) is True


# --- fingerprinting must survive ordinary page volatility ----------------------------

def test_two_renderings_of_one_page_resemble_each_other():
    """A CSRF token and a timestamp differ on every fetch; the page is the same page."""
    a = cal.Sample(_r(200, '<html><form><input name="csrf" value="a1b2c3d4e5f6a7b8">'
                           '<p>2026-08-06 10:00:00</p></form></html>'))
    b = cal.Sample(_r(200, '<html><form><input name="csrf" value="99887766554433aa">'
                           '<p>2026-08-06 11:30:00</p></form></html>'))
    assert a.resembles(b)


def test_two_different_pages_do_not_resemble_each_other():
    a = cal.Sample(_r(200, "<html><table><tr><td>x</td></tr></table></html>"))
    b = cal.Sample(_r(200, "<html><form><input><select></select></form></html>"))
    assert not a.resembles(b)


def test_a_redirect_is_compared_by_destination_not_by_size():
    """Two refusals of two different resources both redirect to /login, carrying
    different ?next= values. They are the same kind of answer."""
    a = cal.Sample(_r(302, "", "/login?next=/admin"))
    b = cal.Sample(_r(302, "", "/login?next=/billing"))
    assert a.resembles(b)
    c = cal.Sample(_r(302, "", "/dashboard"))
    assert not a.resembles(c)


def test_the_target_never_talks_its_way_into_a_verdict():
    """Invariant 1 reaches here too: a page SAYING 'Access denied' proves nothing. Only
    resemblance to a refusal we actually observed counts."""
    p = cal.TargetProfile()
    p.learn_denied(_r(302, "", "/login"), "http://t/admin")
    liar = _r(200, "<html><h1>403 Forbidden — Access denied</h1></html>")
    assert p.is_denied(liar) is False


# --- the target must never talk its way past a detector ------------------------------

def _live_sess(cage):
    import tempfile
    from pathlib import Path
    from brukal import AuditLog, Executor, Gate, load_scope
    from brukal.assist import AssistSession
    from brukal.agents.strategist import StrategistAgent
    from brukal.kali import FakeKali
    from brukal.web import GovernedBrowser
    scope = load_scope("tests/fixtures/scope_fast.json")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_a_page_claiming_access_denied_does_not_count_as_a_refusal():
    """_AUTHZ_DENY_RE read the target's own words to make a security decision: English
    only, framework specific, and it takes a hostile target at its word — which is what
    invariant 1 forbids. A calibrated profile settles it from observed behaviour."""
    s = _live_sess(type("C", (), {"run": lambda self, a: None})())
    p = cal.TargetProfile()
    p.learn_denied(_r(302, "", "/login"), "http://t/admin")
    s.profile = p
    liar = _r(200, "<html><h1>Access denied</h1>" + "<tr><td>secret</td></tr>" * 50 + "</html>")
    assert s._refused(liar, liar.body) is False, \
        "the target talked its way into a refusal verdict"
    assert s._refused(_r(302, "", "/login"), "") is True


def test_without_calibration_the_phrase_list_still_applies():
    """Some signal beats none on an uncalibrated run — the fallback must survive."""
    s = _live_sess(type("C", (), {"run": lambda self, a: None})())
    s.profile = None
    assert s._refused(_r(403, "Forbidden"), "Forbidden") is True


def test_an_indiscriminate_missing_baseline_is_discarded():
    """A catch-all host answers a nonexistent path exactly as it answers a real one — a
    single-page app serves its shell for everything. The baseline is then not merely
    useless but harmful: every substantive response resembles it and is_substantive
    starts calling real content empty. A live suite run caught exactly that, and an
    injection finding disappeared."""
    p = cal.TargetProfile()
    shell = "<html><body><div id='app'></div></body></html>"
    p.learn_ok(_r(200, shell), "http://t/")
    p.learn_missing(_r(200, shell), "http://t/nope")
    assert p.missing is None, "an unusable baseline must be discarded, not used"
    assert p.is_substantive(_r(200, shell + "<table><tr></tr></table>")) is None


def test_calibration_is_skipped_when_the_rate_budget_is_tight():
    """Overhead must not starve the work. Measured: on a 30/min scope, calibration's few
    requests tipped the run past the wall and a confirmed injection finding was lost."""
    from brukal.assist import _CALIBRATION_MIN_RATE
    assert _CALIBRATION_MIN_RATE >= 30, "the guard must trip before a 30/min scope"
