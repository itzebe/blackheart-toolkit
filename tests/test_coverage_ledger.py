"""The unified ledger must join the real ledgers, never invent coverage."""

from blackheart.coverage_ledger import unified_coverage


def test_unified_ledger_joins_model_capability_and_taxonomy():
    payload = unified_coverage()
    assert payload["model_coverage"]["categories"] == 30
    assert payload["model_coverage"]["modelled"] == 27
    assert payload["model_coverage"]["unmodelled_categories"] == []
    assert payload["capability"]["can_find_payable_bug_unaided"] is False
    assert payload["capability"]["partial"] > 0
    assert "taxonomy" in payload
    assert payload["gaps"]["taxonomy_classes_without_objective_link"]
    assert payload["gaps"]["prose_only_objective_categories"] == [
        "mcp-consent-bypass", "mcp-cross-tenant-disclosure", "mcp-scope-overreach"]
    assert payload["status_reasons"]
    assert "not exhaustive" in payload["note"]


def test_a_partial_capability_is_named_not_hidden():
    payload = unified_coverage()
    assert "whole-program-taint" in payload["capability"]["partial_or_no"]
    assert payload["status"] == "INCOMPLETE"
