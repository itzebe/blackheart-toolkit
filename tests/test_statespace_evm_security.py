"""Security and trust-boundary regression tests for the external EVM adapter.

Mission 04 Phase 4/6. These assert the properties a reviewer would attack, so a
future change that weakens a control fails here rather than silently shipping:

  * execution is **local only** -- the adapter cannot be pointed at a remote RPC
    (no ``url``/``host`` parameter), and the node it spawns is bound to loopback;
  * scope and authorization **fail closed** -- an unset decision, a missing
    reference, a non-loopback host or a cloud-metadata address is refused;
  * malformed / hostile operation input is recorded as evidence, never a crash;
  * an unsupported ABI type fails explicitly rather than being silently
    mis-encoded;
  * a constructed target's ``anvil`` process is terminated on every path.

The scope and encoder checks need no node; the node-backed checks skip when the
harness is not built (a skip is not a pass).
"""

from __future__ import annotations

import inspect
import subprocess

import pytest

from blackheart.statespace.runtime import evm as evm_mod
from blackheart.statespace.runtime.authz import (
    LocalScope,
    is_forbidden_address,
    is_loopback_host,
)
from blackheart.statespace.runtime.evm import (
    _enc_dynamic,
    _enc_static,
    encode_params,
)
from blackheart.statespace.runtime.interface import ScopeError


def _no_foundry() -> bool:
    from blackheart.statespace.runtime.evm import _foundry_bin

    return _foundry_bin("anvil") is None or _foundry_bin("cast") is None


def _live_anvil() -> int:
    out = subprocess.run(
        ["bash", "-c",
         "ps -eo stat,comm | awk '$2==\"anvil\" && $1 !~ /Z/ {n++} END{print n+0}'"],
        capture_output=True, text=True, check=False).stdout.strip()
    return int(out or 0)


# --------------------------------------------------------------------------- #
# Local-only: no remote endpoint can be supplied
# --------------------------------------------------------------------------- #

def test_anvil_node_cannot_be_pointed_at_a_remote_endpoint():
    params = inspect.signature(evm_mod.AnvilNode.__init__).parameters
    assert "url" not in params and "host" not in params, (
        "AnvilNode must self-choose a loopback port; a caller-supplied url/host "
        "would allow a remote RPC")
    src = inspect.getsource(evm_mod.AnvilNode.start)
    assert "--host" in src and "127.0.0.1" in src


def test_evm_adapter_has_no_rpc_injection_point():
    params = inspect.signature(evm_mod.EvmExecutionAdapter.__init__).parameters
    assert "url" not in params and "rpc" not in params and "endpoint" not in params


# --------------------------------------------------------------------------- #
# Scope fails closed
# --------------------------------------------------------------------------- #

def test_scope_fails_closed_without_authorization():
    with pytest.raises(ScopeError):
        LocalScope(asset="x").check(host="127.0.0.1")


def test_scope_requires_a_named_reference():
    with pytest.raises(ScopeError):
        LocalScope(asset="x", authorized=True).check(host="127.0.0.1")


@pytest.mark.parametrize("host", ["evil.example.com", "10.0.0.1", "8.8.8.8"])
def test_scope_refuses_non_loopback(host):
    with pytest.raises(ScopeError):
        LocalScope(asset="x", authorized=True, reference="r").check(host=host)


@pytest.mark.parametrize("host", ["169.254.169.254", "100.100.100.200", "fe80::1"])
def test_scope_refuses_metadata_and_link_local(host):
    assert is_forbidden_address(host)
    with pytest.raises(ScopeError):
        LocalScope(asset="x", authorized=True, reference="r").check(host=host)


def test_loopback_classifier_is_exact():
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("::1")
    assert not is_loopback_host("evil.example.com")
    assert not is_loopback_host("127.0.0.1.evil.example.com")


# --------------------------------------------------------------------------- #
# Malformed / hostile input fails explicitly, never silently
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("t", ["fixed128x18", "function", "tuple"])
def test_unsupported_static_abi_type_fails_explicitly(t):
    with pytest.raises(ValueError):
        _enc_static(t, 1)


def test_unsupported_dynamic_abi_type_fails_explicitly():
    with pytest.raises(ValueError):
        _enc_dynamic("tuple[]", [1])


def test_arity_mismatch_is_rejected():
    with pytest.raises(ValueError):
        encode_params(["uint256"], [])


def test_out_of_range_value_raises_not_truncates():
    # an out-of-range integer must not be silently truncated to 256 bits
    with pytest.raises(OverflowError):
        _enc_static("uint256", 1 << 300)


# --------------------------------------------------------------------------- #
# Node-backed: cleanup on every path, revert handling
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_malformed_value_is_evidence_not_a_crash(dvdf_ready):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    from blackheart.statespace.runtime.evm_run import build_evm_target

    before = _live_anvil()
    adapter, target = build_evm_target("dvdf-unstoppable")
    try:
        target.reset()
        rec = adapter.execute("transfer_in", "attacker", {"amount": 1 << 300})
        assert rec.status == "error" and rec.accepted is False
        assert "OverflowError" in rec.error
    finally:
        adapter.close()
    assert _live_anvil() == before, "anvil process leaked after close()"


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_constructed_target_is_closed_even_on_reset_failure(dvdf_ready):
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    from blackheart.statespace.runtime.evm_run import build_evm_target

    before = _live_anvil()
    adapter, _ = build_evm_target("dvdf-unstoppable")
    try:
        adapter.load()
        raise RuntimeError("simulated mid-run failure")
    except RuntimeError:
        pass
    finally:
        adapter.close()
    assert _live_anvil() == before


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_redundant_load_does_not_spawn_a_second_node(dvdf_ready):
    """load() must be idempotent: a second call cannot orphan a running node."""
    if not dvdf_ready:
        pytest.skip("dvdf-external harness not built")
    from blackheart.statespace.runtime.evm_run import build_evm_target

    before = _live_anvil()
    adapter, _ = build_evm_target("dvdf-unstoppable")
    try:
        assert _live_anvil() == before + 1
        adapter.load()  # redundant
        assert _live_anvil() == before + 1, "redundant load() spawned a second node"
    finally:
        adapter.close()
    assert _live_anvil() == before, "close() did not release the node"


@pytest.mark.skipif(_no_foundry(), reason="foundry (anvil/cast) not installed")
def test_raw_address_actor_is_re_impersonated_after_reload(ethernaut_ready):
    """Impersonation is node-scoped: close()+load() must re-impersonate on the new node."""
    if not ethernaut_ready:
        pytest.skip("ethernaut-external harness not built")
    from dataclasses import replace

    from blackheart.statespace.runtime.evm import EvmExecutionAdapter
    from blackheart.statespace.runtime.evm_cases_ethernaut import token_case
    from blackheart.statespace.runtime.evm_run import _evm_scope

    raw = "0x00000000000000000000000000000000000A11CE"
    case = replace(token_case(), actors={"attacker": raw})
    adapter = EvmExecutionAdapter(case, _evm_scope(case.name))
    try:
        adapter.load()
        assert adapter.execute("transfer", "attacker", {"amount": 101}).status == "ok"
        adapter.close()
        adapter.load()  # fresh node: the old impersonation is gone
        rec = adapter.execute("transfer", "attacker", {"amount": 101})
        assert rec.status == "ok", f"not re-impersonated: {rec.error}"
    finally:
        adapter.close()


# --------------------------------------------------------------------------- #
# Harness fetch scripts enforce the exact pinned revision (fail closed)
# --------------------------------------------------------------------------- #

def _fetch_script(harness: str):
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    return (root / "harnesses" / harness / "fetch.sh").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "harness,repo,pin",
    [
        ("dvdf-external", "https://github.com/tinchoabbate/damn-vulnerable-defi.git",
         "64fddf9f96de2782f8868898d68673acb295119c"),
        ("ethernaut-external", "https://github.com/OpenZeppelin/ethernaut.git",
         "d05643a40aa98c45d66247c69ffceab8f44dd8cb"),
    ],
)
def test_fetch_script_pins_and_enforces_the_exact_revision(harness, repo, pin):
    """The fetch script must clone the pinned repo AND verify HEAD == the pin,
    so a drifted checkout is corrected (or the script fails closed) rather than
    silently changing the bytecode the cases were validated against."""
    src = _fetch_script(harness)
    assert repo in src, f"{harness}/fetch.sh must clone {repo}"
    assert pin in src, f"{harness}/fetch.sh must name the pin {pin}"
    # an unconditional checkout of the pin (not gated on first clone only)
    assert "--force" in src, f"{harness}/fetch.sh must force the checkout to the pin"
    # and an explicit equality check that exits non-zero on mismatch
    assert "rev-parse HEAD" in src, f"{harness}/fetch.sh must read HEAD to verify it"
    assert "exit 1" in src, f"{harness}/fetch.sh must fail closed on a pin mismatch"
