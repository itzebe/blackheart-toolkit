"""Acceptance bar for Go / Cosmos attack-surface ingestion.

The QoreChain run failed at the first step: 669 Go files were reported as
"0 functions" because no scanner existed, and the Solidity interface files were
the only thing read. These tests pin the scanner, the rules, the build-flavor
split and the fail-closed coverage gate.
"""

from __future__ import annotations

from pathlib import Path

from blackheart.ingest import (
    CoverageError,
    assess_coverage,
    assert_coverage,
    detect_language,
    evaluate_go,
    ingest_go,
    unread_sources,
)
from blackheart.cosmos import model_from_go


MSG_SERVER = '''package amm

import (
    "context"
    "time"
)

type msgServer struct{ k Keeper }

func (s msgServer) CreatePool(ctx context.Context, msg *types.MsgCreatePool) (*types.MsgCreatePoolResponse, error) {
    amount := int64(msg.Amount)
    _ = s.k.bankKeeper.SendCoins(ctx, msg.Creator, msg.Authority, amount)
    for _, pool := range s.k.GetAllPools(ctx) {
        _ = pool
    }
    _ = time.Now()
    panic("bad input")
}

func (s msgServer) PausePool(ctx context.Context, msg *types.MsgPausePool) (*types.MsgPausePoolResponse, error) {
    if msg.Authority != s.k.GetAuthority() {
        return nil, ErrUnauthorized
    }
    s.k.Set(ctx, msg.PoolId, false)
    return nil, nil
}
'''

STUB = '''//go:build !full

package pqc

func (k *Keeper) VerifySignature(ctx context.Context, sig []byte) error {
    return ErrNotImplemented
}
'''

FULL = '''//go:build full

package pqc

func (k *Keeper) VerifySignature(ctx context.Context, sig []byte) error {
    if len(sig) == 0 {
        return ErrInvalidSignature
    }
    return k.verify(ctx, sig)
}
'''

CGO = '''package svm

/*
#include <stdint.h>
*/
import "C"

func Run(input []byte) int {
    return int(C.run(input))
}
'''


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module example.com/chain\n\ngo 1.23\n", encoding="utf-8")
    for rel, text in {
        "x/amm/msg_server.go": MSG_SERVER,
        "x/pqc/keeper_stub.go": STUB,
        "x/pqc/keeper_full.go": FULL,
        "x/svm/cgo.go": CGO,
    }.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_go_scanner_recovers_message_handlers_and_build_flavors(tmp_path):
    root = _tree(tmp_path)
    report = ingest_go(root)
    assert len(report.files) == 4
    assert len(report.handlers) >= 2
    assert len(report.stubs) >= 1
    assert dict(report.build_flavors)["community"] == 1
    assert dict(report.build_flavors)["full"] == 1
    assert report.full_files
    assert report.stub_files
    assert report.boundaries and report.boundaries[0].kind == "cgo"

    names = {(f.receiver, f.name) for f in report.handlers}
    assert ("msgServer", "CreatePool") in names
    assert ("msgServer", "PausePool") in names


def test_go_rules_fire_on_reachable_code_and_never_on_stubs(tmp_path):
    report = ingest_go(_tree(tmp_path))
    flags = evaluate_go(report)
    rules = {f.rule for f in flags}
    assert "go-panic-on-input" in rules
    assert "go-unchecked-value-result" in rules
    assert "go-unchecked-cast" in rules
    assert "go-unbounded-state-iteration" in rules
    assert "go-wall-clock-in-consensus" in rules
    # The `!full` stub is reported as a stub, not judged as implementation.
    assert all("keeper_stub.go" not in f.path for f in flags)


def test_go_surface_is_recovered_for_cosmos_messages(tmp_path):
    report = ingest_go(_tree(tmp_path))
    surface = model_from_go(report)
    by_name = {h.name: h for h in surface.handlers}
    assert by_name["CreatePool"].message == "MsgCreatePool"
    assert by_name["CreatePool"].guarded is False
    assert by_name["PausePool"].guarded is True
    assert surface.stubs >= 1
    assert surface.unmodelled


def test_go_is_detected_and_covered_by_its_own_scanner(tmp_path):
    root = _tree(tmp_path)
    assert detect_language(str(root)) == "go"
    coverage = assess_coverage(root, "go")
    assert coverage.status == "FULL"
    assert coverage.covered == ("Go",)
    assert not coverage.blocked


def test_mixed_tree_fails_closed_until_the_other_language_is_allowed(tmp_path):
    root = _tree(tmp_path)
    (root / "contracts").mkdir()
    (root / "contracts" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault { function a() external {} }",
        encoding="utf-8",
    )
    coverage = assess_coverage(root, "go")
    assert coverage.blocked
    assert "Solidity" in coverage.unscanned
    assert any("Solidity" in reason for reason in coverage.reasons)
    try:
        assert_coverage(root, "go")
    except CoverageError as exc:
        assert "BLOCKED" in str(exc)
    else:  # pragma: no cover - the gate must fail closed
        raise AssertionError("coverage gate did not refuse a mixed tree")

    allowed = assess_coverage(root, "go", allow_unscanned=("Solidity",))
    assert not allowed.blocked
    assert allowed.status == "PARTIAL"
    assert any("explicitly allowed" in r for r in allowed.reasons)


def test_unread_sources_names_go(tmp_path):
    root = _tree(tmp_path)
    (root / "contracts").mkdir()
    (root / "contracts" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8"
    )
    notes = unread_sources(root, "go")
    assert any("solidity" in note.lower() for note in notes)


def test_go_scanner_uses_the_nearest_module_for_import_paths(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/root\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "go.mod").write_text("module example.com/nested\n", encoding="utf-8")
    (nested / "keeper.go").write_text(
        "package nested\n\nfunc ExportGenesis() {}\n", encoding="utf-8")
    report = ingest_go(tmp_path)
    packages = {p.name: p for p in report.packages}
    assert packages["nested"].import_path == "example.com/nested"
