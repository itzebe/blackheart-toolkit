"""Acceptance bar for the property pipeline.

A written property becomes a real ``InvariantSpec`` that evaluates true/false on
a state dict, and a missing/raising predicate is *unevaluable* (``None``) -- never
a silent pass. The generated Foundry/Chimera test carries each Solidity assertion.
"""

from __future__ import annotations

import pytest

from blackheart.fuzz.properties import (
    PropertyError,
    PropertySpec,
    load_specs,
    parse_properties,
    render_invariant_test,
    to_invariant_specs,
)

SPEC = """
# a couple of properties for a vault
[total_supply_equals_sum]
title = totalSupply equals sum of balances
solidity = totalSupply() == sumBalances()
python = s["total"] == sum(s["balances"])
severity = high

[balance_covers_deposits]
title = contract balance covers deposits
solidity = address(this).balance >= totalDeposits()
"""


def test_parse_properties():
    props = parse_properties(SPEC)
    assert [p.inv_id for p in props] == ["total_supply_equals_sum", "balance_covers_deposits"]
    assert props[0].python == 's["total"] == sum(s["balances"])'
    assert props[1].python == ""
    assert props[0].severity == "high"


def test_invariant_spec_evaluates_true_and_false():
    props, specs = load_specs(SPEC)
    spec = specs[0]
    assert spec.evaluate({"total": 3, "balances": [1, 2]}) is True
    assert spec.evaluate({"total": 5, "balances": [1, 2]}) is False


def test_missing_python_predicate_is_unevaluable_not_true():
    props = parse_properties(SPEC)
    specs = to_invariant_specs(props)
    # second property has no python expression -> raises -> evaluate() is None
    assert specs[1].evaluate({"anything": 1}) is None


def test_raising_predicate_is_unevaluable():
    spec = to_invariant_specs([PropertySpec(
        inv_id="boom", solidity="true", python='s["missing"] == 1'
    )])[0]
    assert spec.evaluate({"present": 1}) is None


def test_render_invariant_test_contains_assertions():
    props = parse_properties(SPEC)
    text = render_invariant_test(props, contract_name="VaultInvariants",
                                 target_type="IVault", target_ctor="address(0xBEEF)")
    assert "function invariant_total_supply_equals_sum() public" in text
    assert "assert(totalSupply() == sumBalances());" in text
    assert "function invariant_balance_covers_deposits() public" in text
    assert 'import {Test} from "forge-std/Test.sol";' in text
    assert "VaultInvariants is Test" in text


def test_property_without_solidity_is_an_error():
    with pytest.raises(PropertyError):
        parse_properties("[bad]\ntitle = no expression here\n")


def test_empty_spec_is_an_error():
    with pytest.raises(PropertyError):
        parse_properties("# nothing\n")
