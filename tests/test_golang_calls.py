"""The Go call graph follows a handler into the keeper that writes state."""

from __future__ import annotations

from pathlib import Path

from blackheart.cosmos import model_from_go
from blackheart.ingest import evaluate_go, ingest_go
from blackheart.ingest.golang_calls import GoCallGraph

DELEGATED = '''package amm

import "context"

type msgServer struct{ keeper Keeper }

type Keeper struct{ store Store }

type Store struct{}

func (s Store) Set(_ context.Context, _ string, _ int) {}

func (k Keeper) Grant(ctx context.Context, msg *types.MsgGrant) error {
    k.store.Set(ctx, msg.Grantee, msg.Amount)
    return nil
}

func (s msgServer) Grant(ctx context.Context, msg *types.MsgGrant) (*types.MsgGrantResponse, error) {
    return nil, s.keeper.Grant(ctx, msg)
}
'''

GUARDED = '''package amm

import "context"

type msgServer struct{ keeper Keeper }

type Keeper struct{ store Store }

type Store struct{}

func (s Store) Set(_ context.Context, _ string, _ int) {}

func (k Keeper) Grant(ctx context.Context, msg *types.MsgGrant) error {
    k.store.Set(ctx, msg.Grantee, msg.Amount)
    return nil
}

func (s msgServer) Grant(ctx context.Context, msg *types.MsgGrant) (*types.MsgGrantResponse, error) {
    if msg.Authority != s.keeper.GetAuthority() {
        return nil, ErrUnauthorized
    }
    return nil, s.keeper.Grant(ctx, msg)
}
'''

INTERFACE_STUB = '''//go:build !full

package license

import "context"

type LicenseKeeper interface {
    Grant(ctx context.Context, msg *types.MsgGrant) error
}

type StubKeeper struct{}

func (k *StubKeeper) Grant(_ context.Context, _ *types.MsgGrant) error {
    return nil
}

type msgServer struct{ keeper LicenseKeeper }

func (s msgServer) Grant(ctx context.Context, msg *types.MsgGrant) (*types.MsgGrantResponse, error) {
    return nil, s.keeper.Grant(ctx, msg)
}
'''


def _ingest(tmp_path: Path, source: str):
    (tmp_path / "go.mod").write_text("module example.com/chain\n\ngo 1.23\n", encoding="utf-8")
    path = tmp_path / "x" / "amm" / "msg_server.go"
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    return ingest_go(tmp_path)


def test_handler_to_keeper_write_is_resolved_and_flagged(tmp_path):
    report = _ingest(tmp_path, DELEGATED)
    graph = GoCallGraph(report)
    handler = next(f for f in report.functions if f.name == "Grant" and f.receiver == "msgServer")
    callees = graph.delegated_writes(handler)
    assert [(c.receiver, c.name) for c in callees] == [("Keeper", "Grant")]

    flags = evaluate_go(report)
    assert any(f.rule == "go-delegated-write-without-guard" and f.function == "Grant"
               for f in flags)


def test_guard_in_the_handler_suppresses_the_delegated_write_flag(tmp_path):
    report = _ingest(tmp_path, GUARDED)
    flags = evaluate_go(report)
    assert not any(f.rule == "go-delegated-write-without-guard" for f in flags)


def test_interface_dispatch_to_a_public_stub_is_not_a_write(tmp_path):
    report = _ingest(tmp_path, INTERFACE_STUB)
    graph = GoCallGraph(report)
    handler = next(f for f in report.functions if f.name == "Grant" and f.receiver == "msgServer")
    edges = [e for e in graph.edges(handler) if e.expression.endswith(".Grant")]
    assert edges and edges[0].kind == "interface"
    assert edges[0].callee is not None and edges[0].callee.stub
    assert graph.delegated_writes(handler) == ()
    assert not any(f.rule == "go-delegated-write-without-guard" for f in evaluate_go(report))


def test_unresolved_dispatch_is_reported_not_guessed(tmp_path):
    source = '''package amm

import "context"

type msgServer struct{ keeper UnknownKeeper }

func (s msgServer) Grant(ctx context.Context, msg *types.MsgGrant) (*types.MsgGrantResponse, error) {
    return nil, s.keeper.Grant(ctx, msg)
}
'''
    report = _ingest(tmp_path, source)
    summary = GoCallGraph(report).summary()
    assert summary.unresolved >= 1
    assert any("s.keeper.Grant" in expression for _, expression in summary.unresolved_dispatches)


def test_cosmos_surface_marks_a_delegated_write_and_its_guard(tmp_path):
    surface = model_from_go(_ingest(tmp_path, DELEGATED))
    grant = next(h for h in surface.handlers if h.name == "Grant")
    assert grant.writes_state is True
    assert grant.guarded is False
    assert "Keeper.Grant" in grant.reason
    assert "Keeper.Grant" in grant.delegated_to

    guarded_root = tmp_path / "guarded"
    guarded_root.mkdir()
    guarded = model_from_go(_ingest(guarded_root, GUARDED))
    grant = next(h for h in guarded.handlers if h.name == "Grant")
    assert grant.writes_state is True
    assert grant.guarded is True


FALSE_GUARD = '''package amm

import "context"

type msgServer struct{ keeper Keeper }

type Keeper struct{ store Store }

type Store struct{}

func (s Store) Set(_ context.Context, _ string, _ int) {}

func (k Keeper) Grant(ctx context.Context, msg *types.MsgGrant) error {
    k.store.Set(ctx, msg.Grantee, msg.Amount)
    return nil
}

func (s msgServer) Grant(ctx context.Context, msg *types.MsgGrant) (*types.MsgGrantResponse, error) {
    if err := s.keeper.Grant(ctx, msg); err != nil {
        return nil, err
    }
    return nil, nil
}
'''


def test_an_error_check_that_passes_authority_is_not_a_guard(tmp_path):
    surface = model_from_go(_ingest(tmp_path, FALSE_GUARD))
    grant = next(h for h in surface.handlers if h.name == "Grant")
    assert grant.guarded is False
    assert "delegates to Keeper.Grant" in grant.reason


CROSS_PACKAGE = '''package amm

import (
    "context"

    "example.com/chain/x/amm/keeper"
)

type msgServer struct{ keeper keeper.Keeper }

func (s msgServer) Grant(ctx context.Context, msg *types.MsgGrant) (*types.MsgGrantResponse, error) {
    if err := keeper.CheckAuthority(ctx, msg.Authority); err != nil {
        return nil, err
    }
    return nil, s.keeper.Grant(ctx, msg)
}
'''

CROSS_KEEPER = '''package keeper

import "context"

type Store struct{}

func (s Store) Set(_ context.Context, _ string, _ int) {}

type Keeper struct{ store Store }

func (k Keeper) Grant(ctx context.Context, msg *types.MsgGrant) error {
    k.store.Set(ctx, msg.Grantee, msg.Amount)
    return nil
}

func CheckAuthority(_ context.Context, _ string) error { return nil }
'''


def test_cross_package_keeper_write_is_resolved(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/chain\n\ngo 1.23\n", encoding="utf-8")
    msg = tmp_path / "x" / "amm" / "msg_server.go"
    msg.parent.mkdir(parents=True)
    msg.write_text(CROSS_PACKAGE, encoding="utf-8")
    keeper = tmp_path / "x" / "amm" / "keeper" / "keeper.go"
    keeper.parent.mkdir(parents=True)
    keeper.write_text(CROSS_KEEPER, encoding="utf-8")

    report = ingest_go(tmp_path)
    graph = GoCallGraph(report)
    handler = next(f for f in report.functions
                   if f.name == "Grant" and f.receiver == "msgServer")
    callees = graph.delegated_writes(handler)
    assert [(c.package, c.receiver, c.name) for c in callees] == [
        ("keeper", "Keeper", "Grant")
    ]

    package_call = next(e for e in graph.edges(handler)
                        if e.expression == "keeper.CheckAuthority")
    assert package_call.kind == "package"
    assert package_call.callee is not None
    assert package_call.callee.package == "keeper"

    flags = evaluate_go(report)
    # The cross-package CheckAuthority call is a real guard, so the delegated
    # write is resolved but not flagged.
    assert not any(f.rule == "go-delegated-write-without-guard" for f in flags)


def test_cross_package_method_ambiguity_is_not_guessed(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/chain\n\ngo 1.23\n", encoding="utf-8")
    msg = tmp_path / "x" / "amm" / "msg_server.go"
    msg.parent.mkdir(parents=True)
    msg.write_text(CROSS_PACKAGE.replace(
        'type msgServer struct{ keeper keeper.Keeper }',
        'type msgServer struct{ keeper Keeper }',
    ).replace('"example.com/chain/x/amm/keeper"', '"example.com/chain/x/amm/keeper"'), encoding="utf-8")
    for name in ("a", "b"):
        other = tmp_path / "x" / name / "keeper.go"
        other.parent.mkdir(parents=True)
        other.write_text(
            'package %s\n\nimport "context"\n\n'
            'type Keeper struct{}\n\n'
            'func (k Keeper) Grant(_ context.Context, _ *types.MsgGrant) error { return nil }\n'
            % name, encoding="utf-8")
    report = ingest_go(tmp_path)
    graph = GoCallGraph(report)
    handler = next(f for f in report.functions
                   if f.name == "Grant" and f.receiver == "msgServer")
    edge = next(e for e in graph.edges(handler) if e.expression == "s.keeper.Grant")
    assert edge.callee is None
    assert "candidates across packages" in edge.detail



def test_module_path_resolves_an_otherwise_ambiguous_import(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/chain\n\ngo 1.23\n", encoding="utf-8")
    msg = tmp_path / "x" / "amm" / "msg_server.go"
    msg.parent.mkdir(parents=True)
    msg.write_text(CROSS_PACKAGE.replace(
        '"example.com/chain/x/amm/keeper"', '"example.com/chain/x/b/keeper"',
    ), encoding="utf-8")
    for name in ("a", "b"):
        keeper = tmp_path / "x" / name / "keeper" / "keeper.go"
        keeper.parent.mkdir(parents=True)
        keeper.write_text(CROSS_KEEPER, encoding="utf-8")
    report = ingest_go(tmp_path)
    graph = GoCallGraph(report)
    assert graph.imports[("amm", "keeper")] == "x/b/keeper"
    handler = next(f for f in report.functions
                   if f.name == "Grant" and f.receiver == "msgServer")
    edge = next(e for e in graph.edges(handler) if e.expression == "s.keeper.Grant")
    assert edge.callee is not None
    assert edge.callee.path.startswith("x/b/keeper/")
