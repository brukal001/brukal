"""Horizontal account takeover through a form that names its victim in the BODY.

`confirm_bfla_password_takeover` proves this already — but only where the victim sits
in a templated path and a bearer token carries the session, so on a server-rendered app
it never looked. DVNA's handler is db.User.find({where:{'id': req.body.id}}) followed by
a password write with no ownership check, and a competing tool reported it as a critical
Brukal did not have.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import parse_qs

from brukal import AuditLog, Executor, Gate, load_scope, webmap
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000"
EDIT = f"{ROOT}/app/useredit"


class _Dvna:
    """Accounts get sequential ids; /app/useredit writes to whatever id it is handed."""

    def __init__(self, ownership_check=False):
        self.users = {}                  # login -> [id, password]
        self.next_id = 1
        self.sessions = {}               # sid -> login
        self.ownership_check = ownership_check
        self.sid = 0

    def _who(self, action):
        cookie = (action.headers or {}).get("Cookie", "")
        for sid, login in self.sessions.items():
            if f"sid={sid}" in cookie:
                return login
        return None

    def run(self, action):
        body = parse_qs(action.body or "")
        one = lambda k: (body.get(k) or [""])[0]
        if action.url.endswith("/register"):
            if action.method == "GET":
                return WebResult(status=200, url=action.url,
                                 headers={"content-type": "text/html"},
                                 body='<form method="post" action="/register">'
                                      '<input name="username" type="text">'
                                      '<input name="password" type="password">'
                                      '<input name="cpassword" type="password"></form>')
            login = one("username")
            self.users[login] = [self.next_id, one("password")]
            self.next_id += 1
            self.sid += 1
            self.sessions[str(self.sid)] = login
            return WebResult(status=302, url=action.url, body="",
                             headers={"Location": "/app", "Set-Cookie": f"sid={self.sid}"})
        if action.url.endswith("/login"):
            if action.method == "GET":
                return WebResult(status=200, url=action.url, headers={},
                                 body='<form method="post"><input name="username">'
                                      '<input name="password" type="password"></form>')
            rec = self.users.get(one("username"))
            if rec and rec[1] == one("password"):
                self.sid += 1
                self.sessions[str(self.sid)] = one("username")
                return WebResult(status=302, url=action.url, body="",
                                 headers={"Location": "/app",
                                          "Set-Cookie": f"sid={self.sid}"})
            return WebResult(status=302, url=action.url, body="bad credentials",
                             headers={"Location": "/login"})
        if action.url.endswith("/app/useredit"):
            me = self._who(action)
            if me is None:
                return WebResult(status=302, url=action.url,
                                 headers={"Location": "/login"}, body="")
            if action.method == "GET":
                my_id = self.users[me][0]
                return WebResult(status=200, url=action.url,
                                 headers={"content-type": "text/html"},
                                 body=f'<form method="post">'
                                      f'<input name="id" value="{my_id}">'
                                      f'<input name="password" type="password">'
                                      f'<input name="cpassword" type="password"></form>')
            target = one("id")
            for login, rec in self.users.items():
                if str(rec[0]) == target:
                    # THE FLAW: no check that `target` is the caller's own row.
                    if self.ownership_check and login != me:
                        return WebResult(status=403, url=action.url, body="forbidden",
                                         headers={})
                    if one("password"):
                        rec[1] = one("password")
                    return WebResult(status=200, url=action.url, headers={},
                                     body="Updated successfully")
            return WebResult(status=404, url=action.url, headers={}, body="no such user")
        return WebResult(status=200, url=action.url,
                         headers={"content-type": "text/html"}, body="<html></html>")


def _sess(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    s = AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                      StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                      browser=GovernedBrowser(scope, cage, audit))
    s.allow_intrusive = True
    s.surface = webmap.AttackSurface(seed=ROOT + "/")
    s.surface.forms.append(webmap.Form(
        action=f"{ROOT}/register", method="POST",
        inputs=(("username", "text"), ("password", "password"),
                ("cpassword", "password"))))
    s.surface.forms.append(webmap.Form(
        action=EDIT, method="POST",
        inputs=(("id", "text"), ("password", "password"), ("cpassword", "password"))))
    s.surface.add_routes(["/login"])
    return s


def _target(s):
    got = s.profile_edit_targets()
    assert got, "the profile-edit form was not recognised"
    return got[0]


def test_takeover_is_confirmed_by_logging_in_as_the_victim():
    s = _sess(_Dvna())
    action, fields, idf, pf, cf = _target(s)
    assert s.confirm_horizontal_takeover_via_form(action, fields, idf, pf, cf)
    f = s.findings.all()[0]
    assert f.confirmed and f.severity == "critical"
    assert "did NOT authenticate before" in f.evidence


def test_an_app_that_checks_ownership_yields_nothing():
    s = _sess(_Dvna(ownership_check=True))
    action, fields, idf, pf, cf = _target(s)
    assert s.confirm_horizontal_takeover_via_form(action, fields, idf, pf, cf) is False
    assert not s.findings.all()


def test_it_never_runs_without_intrusive_consent():
    """It moves somebody's credential and cannot put it back."""
    s = _sess(_Dvna())
    action, fields, idf, pf, cf = _target(s)
    s.allow_intrusive = False
    assert s.confirm_horizontal_takeover_via_form(action, fields, idf, pf, cf) is False


def test_a_form_without_an_id_field_is_not_a_target():
    s = _sess(_Dvna())
    s.surface.forms = [webmap.Form(action=EDIT, method="POST",
                                   inputs=(("password", "password"),))]
    assert not s.profile_edit_targets()
