"""One machine-readable coverage ledger for the whole research stack.

The engine already reports coverage in several places: the attack-class model
registry, the capability matrix, the taxonomy, and the assurance portfolio. Each
is correct on its own; read separately, an operator can mistake a modelled class
for a tested target or a capability for an execution.

This module joins them without inventing a new verdict. It answers three
questions in one payload:

* what the engine can *model* (attack-class coverage);
* what it can *do* (capability matrix, including partial/no);
* what the wider taxonomy says is missing (classes with no objective link).

A gap is reported as a gap. Nothing here upgrades a lead to a finding, and a
modelled class is still a representative, never exhaustive coverage.
"""

from __future__ import annotations

from .capability import CAPABILITIES, as_dict as capability_dict
from .coverage_engine import Taxonomy
from .invariants.coverage import coverage_report, coverage_summary


def unified_coverage() -> dict:
    """Return the joined coverage ledger, with every gap named."""
    model = coverage_summary()
    capability = capability_dict()
    tax = Taxonomy()
    taxonomy = dict(tax.summary())
    partial = [c.name for c in CAPABILITIES if c.status != "yes"]
    unmodelled = list(model["unmodelled_categories"])
    prose_only = list(model.get("prose_only_categories") or [])
    unlinked = [c.key for c in tax if not c.objective_category]
    taxonomy["unlinked_categories"] = unlinked
    reasons = []
    if unmodelled:
        reasons.append(f"{len(unmodelled)} objective categories have no executable model")
    if prose_only:
        reasons.append(f"{len(prose_only)} objective categories are prose-only")
    if unlinked:
        reasons.append(f"{len(unlinked)} taxonomy classes have no objective link")
    if partial:
        reasons.append(f"{len(partial)} capabilities are partial or absent")
    status = "COMPLETE" if not reasons else "INCOMPLETE"
    return {
        "status": status,
        "model_coverage": model,
        "taxonomy": taxonomy,
        "capability": {
            "can_find_payable_bug_unaided": capability[
                "can_find_payable_bug_unaided"],
            "yes": sum(1 for c in CAPABILITIES if c.status == "yes"),
            "partial": sum(1 for c in CAPABILITIES if c.status == "partial"),
            "no": sum(1 for c in CAPABILITIES if c.status == "no"),
            "partial_or_no": partial,
        },
        "status_reasons": reasons,
        "gaps": {
            "unmodelled_objective_categories": unmodelled,
            "prose_only_objective_categories": prose_only,
            "taxonomy_classes_without_objective_link": unlinked,
        },
        "categories": [c.to_dict() for c in coverage_report()],
        "note": (
            "A modelled category has at least one executable vulnerable/guarded "
            "pair -- a representative, not exhaustive coverage. A partial or no "
            "capability is a named limitation, not a finding. This ledger does "
            "not upgrade a lead."
        ),
    }
