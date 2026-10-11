# tests/security/conftest.py
#
# The `result` of every recorded row comes from the TEST'S OWN pytest outcome, not
# from comparing the `expected` and `actual` strings. Those strings are descriptive
# ("not ALLOW", "no widening", "0") and the old `expected == actual` comparison
# recorded every correct DENY/ERROR against "not ALLOW" as a FAIL — 82 false FAILs
# in security_results.json. The assertion is the real check, so it decides:
#
#   passed   -> PASS
#   xfailed  -> FAIL, with `finding` set to the xfail reason's id (SEC-NNN or
#               DESIGN-LIMIT) — a documented, still-open bypass
#   failed   -> FAIL (an undocumented regression), `finding` = None
#
# Granularity is per test: a test that records several rows marks them all with its
# outcome.
import json, pathlib, re
import pytest

_RESULTS: list[dict] = []
_FINDING_RE = re.compile(r"(SEC-\d+|DESIGN-LIMIT)")


@pytest.fixture
def record(request):
    nodeid = request.node.nodeid

    def _record(test_id, category, invariant, input_repr, expected, actual, severity):
        _RESULTS.append({
            "test_id": test_id, "attack_category": category, "security_invariant": invariant,
            "input": input_repr, "expected_result": expected, "actual_result": actual,
            "severity": severity, "result": None, "finding": None,
            "reproducible": True, "_nodeid": nodeid,
        })
    return _record


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call":
        return
    finding = None
    if hasattr(rep, "wasxfail"):
        result = "FAIL"
        m = _FINDING_RE.search(rep.wasxfail or "")
        finding = m.group(1) if m else "XFAIL"
    else:
        result = "PASS" if rep.passed else "FAIL"
    for r in _RESULTS:
        if r["_nodeid"] == item.nodeid and r["result"] is None:
            r["result"], r["finding"] = result, finding


def pytest_sessionfinish(session, exitstatus):
    out = pathlib.Path(__file__).resolve().parents[2] / "security_results.json"
    rows = [{k: v for k, v in r.items() if k != "_nodeid"} for r in _RESULTS]
    for r in rows:                     # a row whose test never reached the call phase
        if r["result"] is None:
            r["result"] = "FAIL"
    try:
        out.write_text(json.dumps({"records": rows, "total": len(rows),
                                   "failed": sum(1 for r in rows if r["result"] == "FAIL")},
                                  indent=2), encoding="utf-8")
    except OSError:
        pass
