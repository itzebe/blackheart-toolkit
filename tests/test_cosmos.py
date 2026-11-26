"""Acceptance bar for the Cosmos SDK reference model.

The invariant engine is target-agnostic, but a Cosmos chain had no target. These
tests pin the model's accounting invariants, the vulnerable/guarded contrast and
the Go message-surface recovery that connects real source to it.
"""

from __future__ import annotations

from pathlib import Path

from blackheart.assurance import CertifyConfig, certify
from blackheart.cosmos import CosmosTarget, model_from_go
from blackheart.ingest.golang import ingest_go


def _cert(target: CosmosTarget):
    return certify(target, CertifyConfig(max_depth=3, max_sequences=20_000,
                                         price_findings=False))


def test_guarded_cosmos_model_holds_its_accounting_invariants():
    cert = _cert(CosmosTarget())
    assert cert.violations == []
    assert cert.unevaluable == []
    assert cert.alphabet_size > 0


def test_vulnerable_cosmos_model_breaks_supply_conservation():
    cert = _cert(CosmosTarget(vulnerable=True))
    broken = {v["invariant_id"] for v in cert.violations}
    assert "cosmos:supply-conservation" in broken
    witness = next(v["minimal_sequence"] for v in cert.violations
                   if v["invariant_id"] == "cosmos:supply-conservation")
    actions = {s["action"] for s in witness}
    assert "delegate" in actions or "deposit" in actions or "lock" in actions


def test_cosmos_surface_recovers_messages_and_guards(tmp_path: Path):
    source = '''package amm

type msgServer struct{ k Keeper }

func (s msgServer) CreatePool(ctx context.Context, msg *types.MsgCreatePool) (*types.MsgCreatePoolResponse, error) {
    s.k.Set(ctx, msg.PoolId, msg.Amount)
    return nil, nil
}

func (s msgServer) PausePool(ctx context.Context, msg *types.MsgPausePool) (*types.MsgPausePoolResponse, error) {
    if msg.Authority != s.k.GetAuthority() {
        return nil, ErrUnauthorized
    }
    s.k.Set(ctx, msg.PoolId, false)
    return nil, nil
}
'''
    (tmp_path / "go.mod").write_text("module example.com/chain\n\ngo 1.23\n", encoding="utf-8")
    path = tmp_path / "x" / "amm" / "msg_server.go"
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    surface = model_from_go(ingest_go(tmp_path))
    by_name = {h.name: h for h in surface.handlers}
    assert by_name["CreatePool"].message == "MsgCreatePool"
    assert by_name["CreatePool"].guarded is False
    assert "writes state" in by_name["CreatePool"].reason
    assert by_name["PausePool"].guarded is True
