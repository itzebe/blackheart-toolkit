"""Economic-invariant analysis and capital accounting (mission 3.E).

A sequence that breaks an invariant is not yet an *economic* finding. This module
turns a violating sequence into an attacker profit-and-loss account, so a
theoretical inconsistency can be told apart from an exploitable one.

The accounting itself now lives in :mod:`blackheart.value` -- the universal,
target-agnostic value and profitability engine -- because the same question ("did
the attacker profit, how much, and from whom?") is asked by the discovery
benchmark, the state-space search, the campaign loop, and the CLI. This module is
the discovery-facing facade over that engine: it re-exports the account type and
the analyser, and keeps the economic-invariant catalogue the discovery pipeline
reasons about.

Keeping the accounting in one place is deliberate: a per-engine re-derivation of
"what counts as value" is exactly how one engine reports profit and another
silently reports zero. See :mod:`blackheart.value` for the honesty rules (a
permission is not capital, an obligation is subtracted, a reverted step is not
profit, a wraparound is not spendable value, a state change with no value movement
is not a financial impact).
"""

from __future__ import annotations

from ..value import ValueAccount, ValueModel, analyse

#: Backwards-compatible alias: discovery's account is the universal value account.
EconomicAccount = ValueAccount

__all__ = ["EconomicAccount", "ValueAccount", "ValueModel", "analyse",
           "ECONOMIC_INVARIANTS", "invariant_for_root_cause"]


# --------------------------------------------------------------------------- #
# Economic invariant catalogue -- the properties the analyser reasons about.
# --------------------------------------------------------------------------- #

ECONOMIC_INVARIANTS: dict[str, str] = {
    "asset-conservation": "total assets are conserved across a transfer",
    "liability-accounting": "recorded liabilities never exceed backing assets",
    "supply-consistency": "token supply changes only through mint/burn",
    "collateralization": "debt never exceeds the collateral's true value",
    "withdrawal-solvency": "withdrawals never exceed available reserves",
    "fee-extraction": "fees charged never exceed the notional they apply to",
    "rounding-accumulation": "rounding never accumulates in the user's favour",
    "liquidation-incentive": "liquidation never seizes a healthy position",
    "unbacked-minting": "no value is created without a matching deposit",
    "double-settlement": "a single obligation is settled at most once",
    "cross-contract-accounting": "two components agree on a shared balance",
    "repeated-small-extraction": "a small extraction cannot be repeated to drain value",
}


def invariant_for_root_cause(root_cause: str) -> list[str]:
    """Map a corpus root cause to the economic invariants it can violate."""
    table = {
        "reentrancy": ["withdrawal-solvency", "asset-conservation"],
        "access-control": ["unbacked-minting"],
        "oracle-manipulation": ["collateralization"],
        "accounting-rounding": ["rounding-accumulation", "asset-conservation"],
        "signature-replay": ["double-settlement"],
        "initialization": ["unbacked-minting"],
        "logic-error": ["asset-conservation"],
        "price-manipulation": ["collateralization", "asset-conservation"],
        "insolvency": ["withdrawal-solvency"],
        "liquidation": ["liquidation-incentive"],
        "fee-accounting": ["fee-extraction"],
        "share-inflation": ["unbacked-minting", "asset-conservation"],
        "donation-attack": ["unbacked-minting"],
        "cross-contract-trust": ["cross-contract-accounting"],
        "arithmetic": ["supply-consistency", "unbacked-minting"],
        "state-staleness": ["withdrawal-solvency"],
    }
    return table.get(root_cause, ["asset-conservation"])
