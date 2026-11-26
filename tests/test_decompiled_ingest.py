"""A decompiled surface is recovered, and its effects stay honestly unknown."""

from __future__ import annotations

from blackheart.ingest.decompiled import parse_decompiled
from blackheart.ingest.verified import build_decompiled_model

TEXT = """
function transfer(address,uint256) external returns (bool)
function 0x70a08231 balanceOf(address) external view returns (uint256)
function approve(address spender, uint256 amount) public
"""


def test_the_surface_is_recovered_with_selectors_and_visibility():
    surface = parse_decompiled(TEXT)
    names = [f.name for f in surface.functions]
    assert names == ["transfer", "balanceOf", "approve"]
    by_name = {f.name: f for f in surface.functions}
    assert by_name["balanceOf"].mutability == "view"
    assert by_name["approve"].visibility == "public"
    assert by_name["transfer"].params == ("address", "uint256")


def test_the_model_is_unmodelled_not_a_silent_no_op():
    result = build_decompiled_model(TEXT)
    assert result.status == "UNMODELLED"
    assert result.binding["source"] == "decompiled"
    assert result.binding["functions"] == 3
    assert set(result.report.unmodelled_ops) == {"transfer", "balanceOf", "approve"}
    assert result.report.modelled_ops == ()
    assert any("bodies are unmodelled" in reason for reason in result.reasons)


def test_an_empty_decompilation_is_reported_not_clean():
    result = build_decompiled_model("no functions here")
    assert result.status == "UNMODELLED"
    assert result.report is None
    assert any("no function surface" in reason for reason in result.reasons)


def test_a_selector_without_a_name_is_still_recovered():
    surface = parse_decompiled("function 0xdeadbeef (uint256)")
    assert surface.functions
    assert surface.functions[0].name.startswith("selector_")
