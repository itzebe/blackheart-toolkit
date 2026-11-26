"""Acceptance bar for the forge-std-free Halmos harness path.

Two things are pinned here:

* ``blackheart.symbolic.harness`` emits a harness that Halmos can actually
  explore -- plain Solidity, builtin ``assert``, no cheatcodes -- and refuses to
  emit one that smuggles a cheatcode back in.
* The Halmos adapter stops calling a cheatcode failure a generic ``FAILED``. A
  run that could not explore the harness is ``UNSUPPORTED`` with the remedy, so
  it can never be read as a clean scan.
"""

from __future__ import annotations

import pytest

from blackheart.engines import get_adapter
from blackheart.engines.contract import EngineState, ExecutionMetadata, ExecutionResult
from blackheart.symbolic.harness import (
    CHEATCODE_MARKERS,
    HarnessError,
    SymbolicHarnessSpec,
    detect_cheatcodes,
    harness_from_dict,
    render_harness,
)


def _spec(**kw) -> SymbolicHarnessSpec:
    base = dict(
        contract_name="VaultSymbolic",
        imports=["src/Vault.sol"],
        target_decl="interface IVault { function totalAssets() external view returns (uint256); }",
        setup=["IVault vault = IVault(address(0xBEEF));"],
        checks=[("assets_never_exceed_cap", "vault.totalAssets() <= 10 ether")],
    )
    base.update(kw)
    return SymbolicHarnessSpec(**base)


def test_render_harness_is_forge_std_free():
    text = render_harness(_spec())
    lowered = text.lower()
    for marker in CHEATCODE_MARKERS:
        assert marker.lower() not in lowered, f"generated harness contains {marker!r}"
    assert "assert(vault.totalAssets() <= 10 ether);" in text
    assert "function check_assets_never_exceed_cap() public" in text
    assert "contract VaultSymbolic {" in text


def test_render_harness_rejects_smuggled_cheatcode():
    with pytest.raises(HarnessError):
        render_harness(_spec(setup=["vm.prank(address(0x1));"]))
    with pytest.raises(HarnessError):
        render_harness(_spec(checks=[("x", "vm.deployCode('A.sol') == 0")]))


def test_render_harness_requires_a_check():
    with pytest.raises(HarnessError):
        render_harness(_spec(checks=[]))


def test_detect_cheatcodes():
    assert detect_cheatcodes("import 'forge-std/Test.sol';") != []
    assert detect_cheatcodes("assert(x > 0);") == []


def test_harness_from_dict_roundtrip():
    d = _spec().to_dict()
    spec = harness_from_dict(d)
    assert spec.contract_name == "VaultSymbolic"
    assert spec.checks == [("assets_never_exceed_cap", "vault.totalAssets() <= 10 ether")]
    # The re-rendered harness is still forge-std-free.
    render_harness(spec)


def _result(state: EngineState, *, stderr: str = "", stdout: str = "") -> ExecutionResult:
    return ExecutionResult(
        metadata=ExecutionMetadata(
            engine="halmos", version="0.1", argv=["halmos"], cwd="/tmp",
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            exit_code=1, target="/tmp/target", state=state,
        ),
        raw_stdout=stdout,
        raw_stderr=stderr,
        artifacts={},
        raw_records=[],
    )


def test_adapter_reclassifies_cheatcode_failure_as_unsupported():
    adapter = get_adapter("halmos", "/tmp")
    result = adapter._explain_unrunnable(
        _result(EngineState.FAILED, stderr="Error: cheatcode 'deployCode' is not supported")
    )
    assert result.metadata.state is EngineState.UNSUPPORTED
    assert "BLOCKED on the harness" in result.metadata.note
    assert "blackheart.symbolic.harness" in result.metadata.note


def test_adapter_leaves_unrelated_failure_alone():
    adapter = get_adapter("halmos", "/tmp")
    result = adapter._explain_unrunnable(_result(EngineState.FAILED, stderr="segfault"))
    assert result.metadata.state is EngineState.FAILED


def test_adapter_leaves_completed_run_alone():
    adapter = get_adapter("halmos", "/tmp")
    result = adapter._explain_unrunnable(
        _result(EngineState.COMPLETED, stderr="forge-std")
    )
    assert result.metadata.state is EngineState.COMPLETED
