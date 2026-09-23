"""
test_lead_mining.py — recurring reproducible leads become DRAFT comparators (Idea #4).

Two properties, and the second is the one that matters most:
  - USEFUL: leads of the same family+shape that recur are clustered and drafted, with a
    predicate that is a valid closed-grammar tree — a real starting point, not a placeholder.
  - CONTAINED: mining only ever produces DATA. It never registers a comparator, never
    mutates the closed set, never runs a predicate. Every draft is a proposal a human gates.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import lead_mining as lm
from brukal import predicate_grammar as pg
from brukal import hypothesis as hyp


def _lead(endpoint, sb=200, sv=200, zb=100, zv=500, comparator="status_differs"):
    return lm.Lead(endpoint=endpoint, status_baseline=sb, status_varied=sv,
                   size_baseline=zb, size_varied=zv, comparator=comparator)


# --------------------------------------------------------------------------- #
# USEFUL — recurrence is clustered and drafted
# --------------------------------------------------------------------------- #

def test_two_leads_of_the_same_family_and_shape_cluster():
    leads = [_lead("http://t/api/orders/1"), _lead("http://t/api/orders/2")]
    clusters = lm.cluster(leads)
    assert len(clusters) == 1
    c = clusters[0]
    assert c.family == "/api/orders"
    assert c.support == 2
    assert c.shape == "2xx->2xx:varied_larger"


def test_a_single_lead_is_not_a_pattern():
    assert lm.cluster([_lead("http://t/api/orders/1")]) == []


def test_different_shapes_do_not_cluster_together():
    leads = [_lead("http://t/api/orders/1", zb=100, zv=500),   # varied_larger
             _lead("http://t/api/orders/2", zb=500, zv=100)]   # varied_smaller
    assert lm.cluster(leads) == []                              # neither shape reaches 2


def test_a_draft_carries_a_valid_grammar_predicate():
    leads = [_lead("http://t/api/orders/1"), _lead("http://t/api/orders/2")]
    drafts = lm.mine(leads)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "low"
    assert d.support == 2
    assert d.name.startswith("draft_")
    # The predicate is a real, VALID closed-grammar tree...
    assert pg.compile_predicate(d.predicate) >= 1
    # ...and it actually discriminates: it holds on the shape it was drafted from.
    class _R:
        def __init__(self, status, body):
            self.status, self.body = status, body
    assert pg.evaluate(d.predicate, _R(200, "x" * 100), _R(200, "y" * 500)) is True
    assert pg.evaluate(d.predicate, _R(200, "x" * 500), _R(200, "y" * 100)) is False


def test_same_size_but_differing_content_drafts_a_bodies_differ_shape():
    leads = [_lead("http://t/api/x/1", zb=300, zv=300), _lead("http://t/api/x/2", zb=300, zv=300)]
    drafts = lm.mine(leads)
    assert len(drafts) == 1
    class _R:
        def __init__(self, status, body):
            self.status, self.body = status, body
    # same length, different bytes -> holds; identical -> does not
    assert pg.evaluate(drafts[0].predicate, _R(200, "aaa"), _R(200, "bbb")) is True
    assert pg.evaluate(drafts[0].predicate, _R(200, "aaa"), _R(200, "aaa")) is False


def test_the_draft_has_a_rationale_and_a_red_first_test_stub():
    d = lm.mine([_lead("http://t/api/orders/1"), _lead("http://t/api/orders/2")])[0]
    assert "reproducible" in d.rationale.lower()
    assert str(d.support) in d.rationale
    assert "RED-FIRST" in d.test_stub


# --------------------------------------------------------------------------- #
# CONTAINED — mining changes nothing, registers nothing, runs nothing
# --------------------------------------------------------------------------- #

def test_mining_never_registers_a_comparator_or_mutates_the_closed_set():
    before = dict(hyp._COMPARATORS)
    before_ev = dict(hyp._EVIDENCE_CLASS)
    drafts = lm.mine([_lead("http://t/api/orders/1"), _lead("http://t/api/orders/2")])
    assert drafts                                   # it did produce a proposal
    # ...but the closed set is byte-for-byte unchanged: a draft is not a registration.
    assert hyp._COMPARATORS == before
    assert hyp._EVIDENCE_CLASS == before_ev
    assert drafts[0].name not in hyp._COMPARATORS


def test_a_shape_outside_what_we_draft_yields_no_draft():
    # A refusal/error/status split is already owned by a named comparator; never drafted.
    leads = [_lead("http://t/api/x/1", sb=200, sv=500),
             _lead("http://t/api/x/2", sb=200, sv=500)]
    assert lm.mine(leads) == []


def test_empty_input_is_handled():
    assert lm.mine([]) == []
    assert lm.cluster([]) == []


def test_clustering_is_deterministic_and_order_stable():
    a = [_lead("http://t/api/orders/1"), _lead("http://t/api/users/9"),
         _lead("http://t/api/orders/2"), _lead("http://t/api/users/8")]
    names1 = [d.name for d in lm.mine(a)]
    names2 = [d.name for d in lm.mine(list(reversed(a)))]
    assert names1 == names2 and names1 == sorted(names1)
