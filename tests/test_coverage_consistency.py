"""The coverage table must never contradict the finding list.

A class is probed by `_covered("X")` and reported as found when a finding title matches
a word under `_COVERAGE_WORDS["X"]`. When the two drift, the report says a class found
nothing while a CRITICAL from that class sits above it in the same document — which
destroys the one property the table exists to provide.

This has now happened five times: model-proposed experiments, both cookie-session authz
checks, credential storage, and signup abuse. Every instance was invisible to the suite
because each detector's own test passed. These two assertions make the whole family
impossible rather than something to rediscover.
"""
from __future__ import annotations

import re
from pathlib import Path

from brukal.assist import _COVERAGE_WORDS

SRC = Path("brukal/assist.py").read_text(encoding="utf-8")


def test_every_probed_class_can_report_a_finding():
    probed = set(re.findall(r'_covered\(\s*"([^"]+)"', SRC))
    orphans = sorted(probed - set(_COVERAGE_WORDS))
    assert not orphans, (
        "these classes are probed but have no words in _COVERAGE_WORDS, so the table "
        "will say 'none found' however much they find: " + ", ".join(orphans))


def test_every_finding_title_maps_to_a_class():
    """Titles are read out of the source rather than a fixture: a fixture would only
    contain the titles somebody remembered to add to it, which is precisely the failure
    being guarded against."""
    titles = set(re.findall(r'title="([A-Z][^"]{6,80})"', SRC))
    titles |= set(re.findall(r'_record_confirmed\(\s*[a-z_]+,\s*f?"([A-Z][^"]{6,80})"', SRC))
    titles |= set(re.findall(r'_record_candidate\(\s*[a-z_]+,\s*f?"([A-Z][^"]{6,80})"', SRC))
    words = [(k, w) for k, ws in _COVERAGE_WORDS.items() for w in ws]
    unmapped = sorted(t for t in titles
                      if not any(w in t.lower() for _k, w in words))
    assert not unmapped, (
        "these finding titles match no coverage class, so producing one makes the "
        "report contradict itself: " + "; ".join(unmapped))
