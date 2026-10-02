# tests/security/conftest.py
import json, pathlib
import pytest

_RESULTS: list[dict] = []

@pytest.fixture
def record():
    def _record(test_id, category, invariant, input_repr, expected, actual, severity):
        _RESULTS.append({
            "test_id": test_id, "attack_category": category, "security_invariant": invariant,
            "input": input_repr, "expected_result": expected, "actual_result": actual,
            "severity": severity, "result": "PASS" if expected == actual else "FAIL",
            "reproducible": True,
        })
        return actual == expected
    return _record

def pytest_sessionfinish(session, exitstatus):
    out = pathlib.Path(__file__).resolve().parents[2] / "security_results.json"
    try:
        out.write_text(json.dumps({"records": _RESULTS, "total": len(_RESULTS),
                                   "failed": sum(1 for r in _RESULTS if r["result"] == "FAIL")},
                                  indent=2), encoding="utf-8")
    except OSError:
        pass
