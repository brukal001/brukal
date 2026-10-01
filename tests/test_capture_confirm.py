from brukal import capture_confirm as cc
from brukal.capture import CapturedRequest as CR


def _cr(url, body, status=200, q=""):
    return CR(method="GET", url=url + (("?" + q) if q else ""), status=status, response=body)


def test_is_solved_banner():
    assert cc.is_solved_banner("<div class='is-solved'>Solved</div>")
    assert cc.is_solved_banner("Congratulations, you solved the lab")
    assert not cc.is_solved_banner("<p>not yet</p>")


def test_boolean_sqli_differential_confirms_on_divergent_bodies():
    caps = [
        _cr("http://lab/filter", "A B C D E rows", q="category=Gifts"),                 # baseline
        _cr("http://lab/filter", "A B C D E rows", q="category=Gifts' AND '1'='1"),     # truthy ~ baseline
        _cr("http://lab/filter", "", q="category=Gifts' AND '1'='2"),                    # falsy diverges
    ]
    found = cc.boolean_sqli_differential(caps)
    assert found and found[0]["title"].lower().startswith("sql")


def test_reflected_executed_records_only_unescaped():
    unescaped = [_cr("http://lab/s", "<b>zqx941</b> hello", q="q=zqx941")]
    escaped = [_cr("http://lab/s", "&lt;b&gt;zqx941&lt;/b&gt;", q="q=zqx941")]
    assert cc.reflected_executed(unescaped)
    assert cc.reflected_executed(escaped) == []


def test_positive_control_law_no_baseline_no_finding():
    # only a single injected request, no benign 200 control → nothing to prove against
    caps = [_cr("http://lab/filter", "", q="category=x' AND '1'='2")]
    assert cc.boolean_sqli_differential(caps) == []


def test_reflected_unescaped_not_fooled_by_unrelated_raw_tags():
    # the MARKER's own reflection is escaped (&lt;b&gt;...&lt;/b&gt;); the real <p>/</p>
    # tags around it are unrelated page chrome and must not trigger a false positive.
    caps = [_cr("http://lab/s", "<p>Your search: &lt;b&gt;zqx941&lt;/b&gt;</p>", q="q=zqx941")]
    assert cc.reflected_executed(caps) == []


def test_reflected_unescaped_checks_every_occurrence():
    # first occurrence is escaped, second is genuinely raw/executable — the second
    # occurrence must still be caught even though find() would stop at the first.
    body = "echo1: &lt;b&gt;zqx941&lt;/b&gt;" + "x" * 40 + "<script>zqx941</script>"
    caps = [_cr("http://lab/s", body, q="q=zqx941")]
    assert cc.reflected_executed(caps)


def test_reflected_unescaped_not_fooled_by_distant_unrelated_tag():
    # marker reflected as plain text; a long run of whitespace separates it from a
    # wholly unrelated tag far down the page — that tag is not the marker's neighbor.
    body = "Reflected: zqx941" + "\n" * 200 + "<footer>site footer</footer>"
    caps = [_cr("http://lab/s", body, q="q=zqx941")]
    assert cc.reflected_executed(caps) == []
