"""The crawl's page budget must be spent on things that can answer a question.

Every case here is taken from one live authenticated run on DVNA that mapped twenty
pages: twelve renderings of one documentation template, four URLs invented by parsing
showdown.min.js as HTML, three static assets — and none of /products, /admin or
/usersearch, which is the entire application.
"""
import re

from brukal.assist import (_ASSET_RE, _FAMILY_QUOTA, _looks_non_html, _path_family)


def test_templated_siblings_share_one_family():
    a = _path_family("http://t:9090/learn/vulnerability/a1_injection")
    b = _path_family("http://t:9090/learn/vulnerability/a7_xss")
    assert a and a == b


def test_shallow_paths_are_not_capped():
    # The top-level routes are the ones worth reaching; a quota here would be a
    # regression, not a fix.
    assert _path_family("http://t:9090/products") == ""
    assert _path_family("http://t:9090/admin/users") == ""


def test_family_quota_leaves_room_for_the_rest():
    assert 0 < _FAMILY_QUOTA < 12      # 12 was what one family actually consumed


def test_static_assets_are_skipped():
    for u in ("http://t/assets/fa/css/font-awesome.min.css",
              "http://t/img/logo.png", "http://t/f.woff2", "http://t/x.map?v=2"):
        assert _ASSET_RE.search(u), u


def test_js_is_not_an_asset_because_bundles_carry_routes():
    assert not _ASSET_RE.search("http://t/assets/jquery-3.2.1.min.js")
    assert _looks_non_html("http://t/assets/jquery-3.2.1.min.js")


# --- end-to-end, against a fixture shaped like the target that exposed this ----------
import tempfile
from pathlib import Path

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.assist import AssistSession
from brukal.agents.strategist import StrategistAgent
from brukal.kali import FakeKali
from brukal.web import GovernedBrowser, WebResult

SCOPE = "tests/fixtures/scope_fast.json"
ROOT = "http://127.0.0.1:5000/"
_DOCS = ["a1_injection", "a2_broken_auth", "a3_sensitive_data", "a4_xxe",
         "a5_broken_access_control", "a6_sec_misconf", "a7_xss", "a8_ides",
         "a9_vuln_component", "a10_logging", "ax_csrf", "ax_redirect"]
# The application. None of these was reached on the live run.
_APP = ["/products", "/admin", "/usersearch", "/calc", "/ping"]


class _DvnaLike:
    """A landing page linking twelve renderings of one doc template, three static
    assets and a JS bundle — plus the actual application, listed last."""

    def __init__(self):
        self.seen = []

    def run(self, action):
        self.seen.append(action.url)
        path = action.url.split("5000", 1)[-1]
        if path.endswith(".js"):
            # A real minified bundle builds anchors by concatenation. Fed to an HTML
            # parser this yields links to paths that do not exist.
            return WebResult(status=200, url=action.url,
                             headers={"content-type": "application/javascript"},
                             body="""var x='<a href="'+c+'">'+g+'</a>';""")
        if path.endswith(".css"):
            return WebResult(status=200, url=action.url,
                             headers={"content-type": "text/css"}, body="a{}")
        if path in ("/", "/learn"):
            links = "".join(f'<a href="/learn/vulnerability/{d}">d</a>' for d in _DOCS)
            links += '<a href="/assets/fa.css">c</a><a href="/assets/j.js">j</a>'
            links += "".join(f'<a href="{p}">p</a>' for p in _APP)
            return WebResult(status=200, url=action.url,
                             headers={"content-type": "text/html"},
                             body=f"<html>{links}</html>")
        return WebResult(status=200, url=action.url,
                         headers={"content-type": "text/html"},
                         body='<html><form action="%s" method="post">'
                              '<input name="q"></form></html>' % path)


def _sess(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession("127.0.0.1", Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_the_application_is_reached_instead_of_one_doc_template():
    cage = _DvnaLike()
    _sess(cage).crawl(seeds=[ROOT], max_pages=12)
    fetched = [u.split("5000", 1)[-1] for u in cage.seen]
    reached = [p for p in _APP if p in fetched]
    assert len(reached) >= 4, f"application unreached; crawl spent budget on {fetched}"


def test_one_doc_family_goes_last_not_first():
    """The quota DEFERS, it does not drop: with budget to spare the whole family is
    still crawled, which is why this asserts order rather than a count. What broke the
    live run was the family going FIRST and exhausting the budget before the
    application was touched."""
    cage = _DvnaLike()
    _sess(cage).crawl(seeds=[ROOT], max_pages=12)
    order = [u.split("5000", 1)[-1] for u in cage.seen]
    docs = [i for i, u in enumerate(order) if "/learn/vulnerability/" in u]
    app = [i for i, u in enumerate(order) if u in _APP]
    assert app, f"application never reached: {order}"
    # No more than the quota may be crawled before the application is reached at all.
    assert len([i for i in docs if i < max(app)]) <= _FAMILY_QUOTA, order


def test_a_js_bundle_does_not_invent_links():
    cage = _DvnaLike()
    _sess(cage).crawl(seeds=[ROOT], max_pages=12)
    assert not [u for u in cage.seen if "'+" in u], \
        f"phantom URLs parsed out of JavaScript: {[u for u in cage.seen if chr(39)+'+' in u]}"


def test_static_assets_cost_no_requests():
    cage = _DvnaLike()
    _sess(cage).crawl(seeds=[ROOT], max_pages=12)
    assert not [u for u in cage.seen if u.endswith(".css")]


# --- links the server ships as markdown ---------------------------------------------
def test_markdown_links_are_found():
    """DVNA's only route from the crawlable surface to the application is
    `](/app/usersearch)` inside a page showdown.js renders in the browser. An
    HTML-parsing crawl mapped thirteen pages of documentation and never reached the app."""
    from brukal import webmap
    body = ("<html><body><div id='doc'>See [User Search](/app/usersearch) and "
            "[Ping](/app/ping) for examples.</div></body></html>")
    links, _f, _p = webmap.extract("http://127.0.0.1:5000/learn/vulnerability/a1", body)
    assert any(u.endswith("/app/usersearch") for u in links), links
    assert any(u.endswith("/app/ping") for u in links), links


def test_prose_brackets_do_not_become_links():
    from brukal import webmap
    body = "<p>an array[0](not a link) and [see below](#anchor) and [x](mailto:a@b.c)</p>"
    links, _f, _p = webmap.extract("http://127.0.0.1:5000/", body)
    assert not links, links


# --- the confirmation budget must not be decided by loop order ----------------------
class _ManyEndpoints:
    """Fifteen endpoints; only the LAST one is injectable. Depth-first probing spends
    its whole budget on the first few and never reaches it — which is what happened on
    DVNA: two runs against an identical surface produced two criticals and none,
    differing only in which loop got there first."""

    def __init__(self):
        self.seen = []

    def run(self, action):
        self.seen.append(action.url)
        body = "<html>ok</html>"
        if "/app/ping" in action.url and ";id" in (action.body or "") + action.url:
            body = "uid=0(root) gid=0(root) groups=0(root)"
        return WebResult(status=200, url=action.url,
                         headers={"content-type": "text/html"}, body=body)


def test_the_highest_severity_classes_reach_every_endpoint():
    """Command injection and SQL injection are tried against ALL collected endpoints
    before any endpoint gets the exhaustive treatment. Without that, an endpoint late in
    the list is never touched by ANY class, and the coverage table's promise that a
    listed class was 'exercised' becomes false for it."""
    from brukal import webmap
    cage = _ManyEndpoints()
    s = _sess(cage)
    s.surface = webmap.AttackSurface(seed="http://127.0.0.1:5000/")
    for i in range(14):
        s.surface.params[f"http://127.0.0.1:5000/p{i}"] = {"q"}
    s.surface.forms.append(webmap.Form(
        action="http://127.0.0.1:5000/app/ping", method="POST",
        inputs=(("address", "text"),)))
    s.confirm_surface(max_params=40)
    assert any("/app/ping" in u for u in cage.seen), \
        "the last endpoint was never probed at all"




def test_the_summary_separates_fetched_pages_from_mined_guesses():
    """The model was shown mined route fragments and nothing else, so it aimed its admin
    experiments at /admin/users — which 404s, because the app mounts it at
    /app/admin/users and the miner strips the prefix. Three experiments in a row proved
    only that a nonexistent path 404s for everybody."""
    from brukal import webmap
    surface = webmap.AttackSurface(seed="http://t:9090/")
    surface.add_page("http://t:9090/app/admin/users", set(), [], {})
    surface.add_routes(["/admin/users"])
    text = surface.summary()
    assert "/app/admin/users" in text.split("mined")[0], \
        "the verified path is not listed ahead of the mined guesses"
    assert "UNVERIFIED" in text
