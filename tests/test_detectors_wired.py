"""Every detector must be reachable from the autonomous path.

A detector the product never calls is worth nothing, and this codebase has done it
three times. `confirm_default_credentials` was written BECAUSE a comparative benchmark
found a critical default login Brukal walked past — and was then never invoked, so the
gap it existed to close stayed open. `confirm_blind_ssrf` and `confirm_blind_rce` were
the same. The mass-assignment prover had already been caught this way once, with the
note "the harness invoked it directly, so the coverage number looked right while the
autonomous path had never once found the flaw".

Reading the source is the only way to catch this: every one of them passes its own unit
tests in isolation, which is exactly why the suite stayed green while they did nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path("brukal/assist.py").read_text(encoding="utf-8")

# Detectors deliberately reachable only through an explicit operator action, with the
# reason. Anything else must be called from the autonomous confirmation pass.
_BY_HAND = {
    "confirm_surface": "the confirmation pass itself; driven from loop.py",
}


def _defined():
    return set(re.findall(r"def (confirm_[a-z0-9_]+)\(", SRC))


def test_every_detector_is_invoked_somewhere():
    unwired = sorted(
        name for name in _defined()
        if name not in _BY_HAND and not re.search(r"self\.%s\b" % name, SRC))
    assert not unwired, (
        "these detectors are defined and never invoked — they cannot find anything: "
        + ", ".join(unwired))


def test_the_confirmation_pass_reaches_the_high_value_ones():
    """Named explicitly, because 'referenced somewhere' is a weaker property than
    'runs during a real engagement'."""
    pass_src = SRC.split("def confirm_surface(")[1]
    for name in ("confirm_default_credentials", "confirm_predictable_reset_token",
                 "confirm_privileged_route_via_signup",
                 "confirm_horizontal_takeover_via_form", "confirm_blind_ssrf"):
        assert re.search(r"self\.%s\b" % name, pass_src), \
            f"{name} is never reached from confirm_surface()"
