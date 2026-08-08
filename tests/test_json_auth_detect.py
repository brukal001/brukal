"""
test_json_auth_detect.py — JsonAuth.detect, the one detector with branching logic.

FormAuth.detect and BasicAuth.detect each have two tests already; JsonAuth.detect
had none, despite being the only one of the three with more than a single
condition and a nonzero floor (a bare probe still scores 0.4, not 0.0).
"""
from __future__ import annotations

from brukal.auth import JsonAuth, LoginProbe

LOGIN = "http://127.0.0.1:5000/login"


def test_json_auth_scores_high_on_a_json_content_type_probe():
    probe = LoginProbe(url=LOGIN, status=200,
                       headers={"Content-Type": "application/json; charset=utf-8"})
    assert JsonAuth().detect(probe) == 0.7


def test_json_auth_scores_low_when_html_inputs_are_present():
    """An HTML form on the page means FormAuth is the better fit; JsonAuth still
    reports a nonzero score (an API could still sit behind a token-issuing page
    that also renders a form) but yields to FormAuth's higher one."""
    probe = LoginProbe(url=LOGIN, status=200,
                       inputs=(("username", "text"), ("password", "password")))
    assert JsonAuth().detect(probe) == 0.1


def test_json_auth_has_a_nonzero_floor_on_a_bare_probe():
    """No content-type header and no form inputs at all — nothing rules JSON out,
    so unlike FormAuth and BasicAuth (which floor at 0.0), JsonAuth still reports a
    baseline chance."""
    probe = LoginProbe(url=LOGIN, status=200)
    assert JsonAuth().detect(probe) == 0.4
