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
