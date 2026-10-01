from brukal.web import WebAction, CompositeWebCage, parse_web_action, check_web
from brukal.scope import Scope


class _Spy:
    def __init__(self, name):
        self.name, self.seen = name, []

    def run(self, action):
        self.seen.append(action.kind)
        return type("R", (), {"status": 200, "url": action.url, "body": "",
                               "headers": {}, "note": self.name})()

    def set_tls_verify(self, v):
        pass


class _CDPDownSpy(_Spy):
    """Render cage that handles navigate/screenshot/get fine but raises
    NotImplementedError on interactive kinds — simulating CDP not being live."""

    def run(self, action):
        if action.kind in ("click", "fill", "eval", "intercept"):
            self.seen.append(action.kind)
            raise NotImplementedError("CDP not available")
        return super().run(action)


def test_via_browser_routes_get_to_render():
    render, request = _Spy("render"), _Spy("request")
    comp = CompositeWebCage(render, request)
    comp.run(WebAction(kind="get", url="http://lab/x", via="browser"))
    assert render.seen == ["get"] and request.seen == []


def test_via_auto_keeps_get_on_request_cage():
    render, request = _Spy("render"), _Spy("request")
    CompositeWebCage(render, request).run(WebAction(kind="get", url="http://lab/x"))
    assert request.seen == ["get"] and render.seen == []


def test_via_raw_keeps_get_on_request_cage():
    render, request = _Spy("render"), _Spy("request")
    CompositeWebCage(render, request).run(WebAction(kind="get", url="http://lab/x", via="raw"))
    assert request.seen == ["get"] and render.seen == []


def test_via_browser_routes_request_to_render():
    render, request = _Spy("render"), _Spy("request")
    CompositeWebCage(render, request).run(
        WebAction(kind="request", url="http://lab/x", via="browser"))
    assert render.seen == ["request"] and request.seen == []


def test_navigate_and_screenshot_always_go_to_render():
    render, request = _Spy("render"), _Spy("request")
    comp = CompositeWebCage(render, request)
    comp.run(WebAction(kind="navigate", url="http://lab/x"))
    comp.run(WebAction(kind="screenshot", url="http://lab/x"))
    assert render.seen == ["navigate", "screenshot"] and request.seen == []


def test_parse_via_prefix():
    a = parse_web_action("via:browser get http://lab/x")
    assert a.kind == "get" and a.via == "browser" and a.url == "http://lab/x"


def test_parse_without_via_defaults_auto():
    a = parse_web_action("get http://lab/x")
    assert a.via == "auto"


def test_parse_via_prefix_on_all_branches():
    cases = [
        "via:browser navigate http://lab/x",
        "via:browser render http://lab/x",
        "via:browser screenshot http://lab/x",
        "via:browser intercept http://lab/*",
        "via:raw eval document.title",
        "via:raw click #sel",
        "via:raw fill #sel payload",
        "via:browser request GET http://lab/x",
        "via:raw http://lab/x",
    ]
    for text in cases:
        a = parse_web_action(text)
        assert a is not None, text
        expected = "browser" if "via:browser" in text else "raw"
        assert a.via == expected, (text, a.via)


def test_via_browser_interactive_cdp_down_returns_note_not_crash():
    """Named Review Focus risk: via=browser + interactive kind + CDP-down render
    cage must fail closed to the explanatory note, never crash and never
    silently fall back to the raw request cage."""
    render, request = _CDPDownSpy("render"), _Spy("request")
    comp = CompositeWebCage(render, request)
    result = comp.run(WebAction(kind="eval", expression="1+1", via="browser"))
    assert render.seen == ["eval"]
    assert request.seen == []
    assert "CDP" in result.note or "not available" in result.note.lower()


def test_via_does_not_reach_the_gate():
    # gate re-reads the URL; an out-of-scope host is DENY regardless of via
    scope = Scope("t", (), frozenset(), 30, authorized_hosts=frozenset({"lab.example"}),
                  authorization="t")
    d = check_web(WebAction(kind="get", url="http://evil.example/x", via="browser"), scope)
    assert d.verdict == "DENY"


def test_via_raw_also_denied_out_of_scope():
    scope = Scope("t", (), frozenset(), 30, authorized_hosts=frozenset({"lab.example"}),
                  authorization="t")
    d = check_web(WebAction(kind="get", url="http://evil.example/x", via="raw"), scope)
    assert d.verdict == "DENY"
