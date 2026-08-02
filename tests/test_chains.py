"""
test_chains.py — composing findings into an assessment, without inventing any.

A competing white-box tool read as far more serious on the same target while finding
barely more, because it said what its findings ADDED UP TO. Brukal found the same JWT
forgery, mass assignment and credential leak and never said any one of them alone hands
over the whole application.

The risk in closing that gap is a report that sounds worse than the evidence supports,
so the tests below are mostly about what the composer must REFUSE to say.
"""
from __future__ import annotations

from brukal import chains
from brukal.findings import Finding


def _f(title, confirmed=True):
    return Finding(title=title, severity="critical", category="api",
                   target="http://t/x", param="", evidence="e", confirmed=confirmed)


def test_a_single_unauthenticated_flaw_reaching_admin_is_its_own_chain():
    cs = chains.compose([_f("Authentication bypass via forged JWT")])
    assert len(cs) == 1 and len(cs[0]) == 1
    assert "administrator takeover" in chains.summarise(cs)


def test_two_step_chain_requires_the_second_step_to_need_the_first():
    """The regression. Any unauthenticated foothold paired with any unauthenticated
    terminal produced sentences like 'credential exposure enables JWT forgery' — two
    independent findings concatenated and presented as a path the attacker walked."""
    cs = chains.compose([_f("Unauthenticated exposure of credentials"),
                         _f("Authentication bypass via forged JWT")])
    # both are one-step chains; neither is a premise for the other
    assert all(len(c) == 1 for c in cs)
    assert len(cs) == 1          # only the forgery reaches a terminal capability


def test_a_genuine_two_step_chain_is_composed():
    """BOLA needs an account; a credential leak provides one. That is a real path."""
    cs = chains.compose([_f("Unauthenticated exposure of credentials"),
                         _f("Broken object-level authorization (BOLA/IDOR)")])
    assert any(len(c) == 2 for c in cs)
    steps = [s.title for s, _ in next(c for c in cs if len(c) == 2)]
    assert steps[0].startswith("Unauthenticated exposure")
    assert "object-level" in steps[1]


def test_unconfirmed_findings_never_enter_a_chain():
    """A chain built partly from a lead would read as proven. That blur is the one
    thing the whole report exists to avoid."""
    cs = chains.compose([_f("Authentication bypass via forged JWT", confirmed=False)])
    assert cs == []


def test_findings_that_are_not_rungs_are_left_out_rather_than_padded():
    assert chains.classify(_f("Missing security header: x-frame-options")) is None
    cs = chains.compose([_f("Missing security header: x-frame-options"),
                         _f("Missing security header: content-security-policy")])
    assert cs == []


def test_nothing_is_claimed_when_there_is_nothing_to_claim():
    assert chains.compose([]) == []
    assert chains.summarise([]) == "" and chains.render([]) == ""


def test_independence_is_counted_not_permutations():
    """Five separate routes in is a different sentence from one route with five steps,
    and the same entry point reaching the same outcome twice is not two chains."""
    cs = chains.compose([_f("Unauthenticated exposure of credentials"),
                         _f("Broken object-level authorization (BOLA/IDOR)"),
                         _f("Unauthenticated exposure of personal data")])
    keys = {(c[0][0].title, c[-1][1]) for c in cs}
    assert len(keys) == len(cs)


def test_render_names_the_proving_finding_at_every_step():
    cs = chains.compose([_f("Unauthenticated exposure of credentials"),
                         _f("Broken object-level authorization (BOLA/IDOR)")])
    md = chains.render(cs)
    assert "Unauthenticated exposure of credentials" in md
    assert "nothing here is inferred" in md
