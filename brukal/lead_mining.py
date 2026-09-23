"""
lead_mining.py — turn recurring reproducible leads into DRAFT comparators for a human.

Brukal's coverage has always grown one hand-written comparator at a time. Idea #3 keeps the
reproducible signal no comparator names; this closes the loop by reading those leads OFFLINE
and, where the same shape recurs across an endpoint family, drafting a CANDIDATE comparator
for a maintainer to review and merge.

The safety line is absolute and structural: this module only produces DATA — a draft's name,
a predicate expressed in the closed `predicate_grammar`, a suggested (low) bound, a rationale
and a red-first test stub. It NEVER registers a comparator, never mutates `_COMPARATORS`,
never runs a predicate against a target. A draft is a proposal a human accepts, edits or
throws away; nothing it contains takes effect until a maintainer writes it into the closed
set by hand — the same gate every comparator has always passed through. So the loop that
lifts the linear-effort ceiling never becomes the model (or a pile of leads) declaring a new
truth on its own.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import predicate_grammar as _pg


# A drafted comparator suggests a bound but never above LOW: a pattern mined from
# unconfirmed leads is a hypothesis about the target, and a maintainer decides what it may
# claim once it is a real comparator with a real bound.
DRAFT_SEVERITY = "low"

# How many leads of the same family+shape make a pattern worth drafting. Two is the floor:
# a single lead is an anecdote, not a recurrence.
MIN_SUPPORT = 2


@dataclass
class Lead:
    """One reproducible, unconfirmed lead — the structured facts #3 kept, not its prose.

    `status_*` and `size_*` are the baseline (control) and varied (variant) readings the
    reproducibility gate compared. `comparator` is the one that did NOT confirm, kept only
    as context for the draft's rationale."""
    endpoint: str
    status_baseline: int
    status_varied: int
    size_baseline: int
    size_varied: int
    comparator: str = ""


@dataclass
class Cluster:
    family: str
    shape: str
    members: list = field(default_factory=list)

    @property
    def support(self) -> int:
        return len(self.members)


@dataclass
class DraftComparator:
    """A PROPOSAL, never a registration. `predicate` is a validated `predicate_grammar`
    AST; `severity` is a suggestion a human overrides; `test_stub` is red-first skeleton
    text for the maintainer to fill."""
    name: str
    predicate: dict
    severity: str
    family: str
    shape: str
    support: int
    rationale: str
    test_stub: str


def _family(endpoint: str) -> str:
    """The endpoint FAMILY: the path with its last segment dropped, so `/api/orders/1` and
    `/api/orders/2` cluster together. The same 'one question per area' grouping the
    coverage sweep uses — an application authorises an area, not a leaf."""
    path = urlsplit(endpoint or "").path or (endpoint or "/")
    segs = [s for s in path.split("/") if s]
    if len(segs) <= 1:
        return "/" + "/".join(segs)
    return "/" + "/".join(segs[:-1])


def _size_relation(lead: Lead) -> str:
    if lead.size_varied > lead.size_baseline:
        return "varied_larger"
    if lead.size_varied < lead.size_baseline:
        return "varied_smaller"
    return "same_size"


def _shape(lead: Lead) -> str:
    """A canonical shape signature: the status CLASS of each side plus the size relation.
    Two leads with the same shape are the same candidate rule."""
    return (f"{(lead.status_baseline or 0) // 100}xx->"
            f"{(lead.status_varied or 0) // 100}xx:{_size_relation(lead)}")


def cluster(leads, min_support: int = MIN_SUPPORT) -> list:
    """Group leads by (family, shape) and keep the groups that RECUR (>= min_support).

    Deterministic and order-stable: groups come out sorted by (family, shape) so two runs
    over the same leads draft the same candidates in the same order."""
    groups: dict = {}
    for lead in leads or []:
        groups.setdefault((_family(lead.endpoint), _shape(lead)), []).append(lead)
    out = [Cluster(family, shape, members)
           for (family, shape), members in groups.items() if len(members) >= min_support]
    out.sort(key=lambda c: (c.family, c.shape))
    return out


def _predicate_for(shape: str) -> dict | None:
    """The closed-grammar AST that captures a shape, or None if the shape is not one we
    draft. Built from the same observables a maintainer would reach for, so the draft is a
    real starting point rather than a placeholder. `a` is the baseline (control), `b` the
    varied (variant) side, matching the Lead fields.

    Only both-2xx shapes are drafted: those are exactly the reproducible CONTENT
    differences #3 keeps (a refusal, an error or a status split is already owned by a named
    comparator, so a draft there would duplicate one)."""
    if not shape.startswith("2xx->2xx:"):
        return None
    both_ok = [{"obs": "succeeded", "of": "a"}, {"obs": "succeeded", "of": "b"}]
    relation = shape.split(":", 1)[1]
    if relation == "varied_larger":
        diff = {"op": "gt", "args": [{"obs": "body_len", "of": "b"},
                                     {"obs": "body_len", "of": "a"}]}
    elif relation == "varied_smaller":
        diff = {"op": "gt", "args": [{"obs": "body_len", "of": "a"},
                                     {"obs": "body_len", "of": "b"}]}
    else:  # same_size but the content differs — the input changed the bytes, not the length
        diff = {"op": "and", "args": [
            {"op": "eq", "args": [{"obs": "body_len", "of": "a"},
                                  {"obs": "body_len", "of": "b"}]},
            {"op": "not", "args": [{"obs": "bodies_equal"}]}]}
    return {"op": "and", "args": both_ok + [diff]}


def _slug(family: str, shape: str) -> str:
    body = (family + "_" + shape).lower()
    keep = [c if (c.isalnum()) else "_" for c in body]
    slug = "".join(keep)
    while "__" in slug:
        slug = slug.replace("__", "_")
    return "draft_" + slug.strip("_")


def _test_stub(name: str, family: str, support: int) -> str:
    return (f"# RED-FIRST test for the drafted comparator {name!r}.\n"
            f"# {support} reproducible leads at {family} share this shape.\n"
            f"# 1. Assert the predicate HOLDS on a response pair matching the shape.\n"
            f"# 2. Assert it does NOT hold on a pair that does not.\n"
            f"# 3. Add the bound to _EVIDENCE_CLASS in the SAME edit, and confirm the\n"
            f"#    positive case fails before the comparator is registered.\n")


def draft_comparator(clstr: Cluster) -> DraftComparator | None:
    """A DRAFT from one cluster, or None when the shape is not one we draft or the AST does
    not validate. The predicate is always run through `compile_predicate`, so a draft can
    never carry a tree outside the closed grammar — even a drafted proposal is fail-closed."""
    ast = _predicate_for(clstr.shape)
    if ast is None:
        return None
    try:
        _pg.compile_predicate(ast)
    except Exception:
        return None
    name = _slug(clstr.family, clstr.shape)
    rationale = (
        f"{clstr.support} reproducible, unconfirmed leads at the endpoint family "
        f"{clstr.family} share the shape {clstr.shape} — both sides succeeded and the "
        f"controlled input reproducibly changed the response. No comparator names this; a "
        f"maintainer decides whether it is a real class and what it may claim. Suggested "
        f"bound: {DRAFT_SEVERITY} (a mined pattern is a hypothesis, not a proved impact).")
    return DraftComparator(
        name=name, predicate=ast, severity=DRAFT_SEVERITY, family=clstr.family,
        shape=clstr.shape, support=clstr.support, rationale=rationale,
        test_stub=_test_stub(name, clstr.family, clstr.support))


def mine(leads, min_support: int = MIN_SUPPORT) -> list:
    """Recurring reproducible leads -> draft comparators, for HUMAN review.

    Pure and side-effect-free: it reads leads and returns drafts. It does not touch the
    closed comparator set, does not run a predicate, and does not persist anything — the
    caller decides what to do with the proposals, and a maintainer alone turns any of them
    into a real comparator."""
    drafts = [draft_comparator(c) for c in cluster(leads, min_support)]
    return [d for d in drafts if d is not None]
