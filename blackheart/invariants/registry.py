"""Registry of executable invariant-engine targets.

Central place that maps a target name to its implementing class and groups the
*vulnerable* / *guarded* variants into differential pairs. Keeping the registry in
one module means the CLI, the tests, and any future campaign all agree on what is
executable, and adding a target is a single edit here.

Target kinds:
  * ``erc4626``  -- share accounting (``reference_targets``)
  * ``wrapper``  -- wrapper-share over a rebasing aToken (``wrapper_targets``)
  * ``oracle``   -- lending priced by a manipulable spot oracle (``attack_targets``)
  * ``permit``   -- single-use signed authorization (``attack_targets``)
  * ``proxy``    -- upgradeable initializer (``attack_targets``)

Each pair is (vulnerable, guarded): the engine must find an attacker-reachable
invariant violation in the first and none in the second. That contrast is the
non-vacuity control; ``differential`` runs it in one shot.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attack_targets import (
    GuardedLendingPool,
    GuardedProxyVault,
    LendingPool,
    PermitToken,
    ProxyVault,
    SafePermitToken,
)
from .class_targets import (
    AccessRegistry,
    CallbackVault,
    GuardedAccessRegistry,
    GuardedCallbackVault,
)
from .logic_targets import (
    ExpiringOffer,
    GuardedExpiringOffer,
    GuardedObjectStore,
    GuardedRoundingVault,
    ObjectStore,
    RoundingVault,
)
from .hyperliquid_targets import (
    GuardedOutcomeMarket,
    GuardedPortfolioMarginLiquidation,
    GuardedPortfolioMarginSupply,
    GuardedQuestionMarket,
    OutcomeMarket,
    PortfolioMarginLiquidation,
    PortfolioMarginSupply,
    QuestionMarket,
)
from .reference_targets import SafeVault, VulnerableVault
from .wrapper_targets import GuardedWrapper, WrapperTarget
from .defi_targets import (
    CrossDomainBridge,
    DecimalVault,
    Governor,
    GuardedCrossDomainBridge,
    GuardedDecimalVault,
    GuardedGovernor,
    GuardedLiquidator,
    GuardedProxyStorage,
    GuardedRewardPool,
    GuardedSilentFailBridge,
    GuardedSlippageAmm,
    Liquidator,
    ProxyStorage,
    RewardPool,
    SilentFailBridge,
    SlippageAmm,
)
from .mev_targets import GuardedSandwichPool, SandwichPool
from .multicontract_targets import (
    GuardedStrategyVault,
    GuardedTrustingMarket,
    StrategyVault,
    TrustingMarket,
)
from .mcp_targets import (
    AudienceConfusedVerifier,
    CorsResource,
    GuardedAudienceVerifier,
    GuardedCorsResource,
)


@dataclass(frozen=True)
class TargetSpec:
    name: str
    kind: str
    cls: type
    guarded: bool = False


# Ordered so a differential pair's two members are adjacent.
TARGET_SPECS: list[TargetSpec] = [
    TargetSpec("vulnerable", "erc4626", VulnerableVault),
    TargetSpec("safe", "erc4626", SafeVault, guarded=True),
    TargetSpec("wrapper", "wrapper", WrapperTarget),
    TargetSpec("wrapper-guarded", "wrapper", GuardedWrapper, guarded=True),
    TargetSpec("lending-oracle", "oracle", LendingPool),
    TargetSpec("lending-oracle-guarded", "oracle", GuardedLendingPool, guarded=True),
    TargetSpec("permit-replay", "permit", PermitToken),
    TargetSpec("permit-guarded", "permit", SafePermitToken, guarded=True),
    TargetSpec("proxy-initializer", "proxy", ProxyVault),
    TargetSpec("proxy-guarded", "proxy", GuardedProxyVault, guarded=True),
    TargetSpec("callback-reentrancy", "reentrancy", CallbackVault),
    TargetSpec("callback-guarded", "reentrancy", GuardedCallbackVault, guarded=True),
    TargetSpec("cross-contract-oracle", "cross-contract", TrustingMarket),
    TargetSpec("cross-contract-oracle-guarded", "cross-contract",
               GuardedTrustingMarket, guarded=True),
    TargetSpec("cross-protocol-strategy", "cross-protocol", StrategyVault),
    TargetSpec("cross-protocol-strategy-guarded", "cross-protocol",
               GuardedStrategyVault, guarded=True),
    TargetSpec("access-control", "access-control", AccessRegistry),
    TargetSpec("access-guarded", "access-control", GuardedAccessRegistry, guarded=True),
    TargetSpec("rounding-precision", "rounding", RoundingVault),
    TargetSpec("rounding-guarded", "rounding", GuardedRoundingVault, guarded=True),
    TargetSpec("timing-expiry", "timing", ExpiringOffer),
    TargetSpec("timing-guarded", "timing", GuardedExpiringOffer, guarded=True),
    TargetSpec("info-disclosure", "info", ObjectStore),
    TargetSpec("info-guarded", "info", GuardedObjectStore, guarded=True),
    TargetSpec("hl-pm-supply", "portfolio-margin", PortfolioMarginSupply),
    TargetSpec("hl-pm-supply-guarded", "portfolio-margin",
               GuardedPortfolioMarginSupply, guarded=True),
    TargetSpec("hl-pm-liquidation", "portfolio-margin", PortfolioMarginLiquidation),
    TargetSpec("hl-pm-liquidation-guarded", "portfolio-margin",
               GuardedPortfolioMarginLiquidation, guarded=True),
    TargetSpec("hl-outcome", "outcome", OutcomeMarket),
    TargetSpec("hl-outcome-guarded", "outcome", GuardedOutcomeMarket, guarded=True),
    TargetSpec("hl-question", "outcome", QuestionMarket),
    TargetSpec("hl-question-guarded", "outcome", GuardedQuestionMarket, guarded=True),
    TargetSpec("cross-chain-replay", "cross-chain", CrossDomainBridge),
    TargetSpec("cross-chain-guarded", "cross-chain", GuardedCrossDomainBridge, guarded=True),
    TargetSpec("amm-slippage", "amm", SlippageAmm),
    TargetSpec("amm-guarded", "amm", GuardedSlippageAmm, guarded=True),
    TargetSpec("silent-transfer-failure", "silent-transfer", SilentFailBridge),
    TargetSpec("silent-transfer-guarded", "silent-transfer", GuardedSilentFailBridge, guarded=True),
    TargetSpec("flashloan-governance", "governance", Governor),
    TargetSpec("flashloan-governance-guarded", "governance", GuardedGovernor, guarded=True),
    TargetSpec("griefing-dos", "griefing", Liquidator),
    TargetSpec("griefing-guarded", "griefing", GuardedLiquidator, guarded=True),
    TargetSpec("reward-manipulation", "reward", RewardPool),
    TargetSpec("reward-guarded", "reward", GuardedRewardPool, guarded=True),
    TargetSpec("storage-collision", "storage-collision", ProxyStorage),
    TargetSpec("storage-guarded", "storage-collision", GuardedProxyStorage, guarded=True),
    TargetSpec("decimals-mismatch", "decimals", DecimalVault),
    TargetSpec("decimals-guarded", "decimals", GuardedDecimalVault, guarded=True),
    TargetSpec("sandwich-slippage", "ordering", SandwichPool),
    TargetSpec("sandwich-guarded", "ordering", GuardedSandwichPool, guarded=True),
    TargetSpec("mcp-cors", "mcp-cors", CorsResource),
    TargetSpec("mcp-cors-guarded", "mcp-cors", GuardedCorsResource, guarded=True),
    TargetSpec("mcp-audience", "mcp-audience", AudienceConfusedVerifier),
    TargetSpec("mcp-audience-guarded", "mcp-audience", GuardedAudienceVerifier,
               guarded=True),
]

# (vulnerable, guarded, hypothesis) -- what each pair is meant to demonstrate.
DIFFERENTIAL_PAIRS: list[tuple[str, str, str]] = [
    ("vulnerable", "safe",
     "ERC4626 share inflation: first-depositor donation steals a later deposit"),
    ("wrapper", "wrapper-guarded",
     "wrapper-share / aToken accounting divergence under rebase and donation"),
    ("lending-oracle", "lending-oracle-guarded",
     "borrow against a manipulable spot-price oracle"),
    ("permit-replay", "permit-guarded",
     "replay of a signed authorization with no single-use binding"),
    ("proxy-initializer", "proxy-guarded",
     "re-callable initializer hands the owner role to an attacker"),
    ("callback-reentrancy", "callback-guarded",
     "reentrant withdrawal drains the vault before state is updated"),
    ("cross-contract-oracle", "cross-contract-oracle-guarded",
     "a market trusts an external oracle contract's report, so an attacker who "
     "controls that contract borrows far beyond their collateral's true value"),
    ("cross-protocol-strategy", "cross-protocol-strategy-guarded",
     "a vault prices redemptions off a strategy contract's self-reported assets, "
     "so an attacker who controls the strategy redeems more than it holds"),
    ("access-control", "access-guarded",
     "ungated privileged setter lets a non-owner overwrite protected state"),
    ("rounding-precision", "rounding-guarded",
     "deposit mints shares with a ceiling, so a dust deposit buys a whole share and "
     "redeems for far more (rounding-direction bug)"),
    ("timing-expiry", "timing-guarded",
     "an offer is accepted after its deadline because the clock is never checked "
     "(ordering/timing bug)"),
    ("info-disclosure", "info-guarded",
     "object read is gated on authentication, not ownership, so any caller reads "
     "another principal's record (IDOR / object-level authorization)"),
    ("hl-pm-supply", "hl-pm-supply-guarded",
     "portfolio-margin supplier withdraws lent-out funds, leaving debt unbacked"),
    ("hl-pm-liquidation", "hl-pm-liquidation-guarded",
     "liquidation uses the borrow LTV instead of 0.5 + 0.5*LTV, seizing healthy positions"),
    ("hl-outcome", "hl-outcome-guarded",
     "HIP-4 outcome merge refunds quote for unmatched Yes/No shares, minting value"),
    ("hl-question", "hl-question-guarded",
     "HIP-4 question merge pays n quote for a full No set instead of n-1, minting value"),
    ("cross-chain-replay", "cross-chain-guarded",
     "a cross-domain message is replayed, or executed on the wrong chain, because it "
     "carries no executed-marker and no destination binding"),
    ("amm-slippage", "amm-guarded",
     "a swap output divides by the reserve instead of the reserve plus the input, so "
     "the pool invariant k = rx*ry decreases and the trader drains value"),
    ("silent-transfer-failure", "silent-transfer-guarded",
     "a bridge credits a deposit even when the token transfer silently moved nothing "
     "(unchecked return / non-standard token)"),
    ("flashloan-governance", "flashloan-governance-guarded",
     "governance counts a voter's current balance instead of a proposal snapshot, so a "
     "flash loan passes a proposal the attacker never held power for"),
    ("griefing-dos", "griefing-guarded",
     "one frozen position blocks the entire liquidation path, so an attacker griefs the "
     "protocol into permanent bad debt"),
    ("reward-manipulation", "reward-guarded",
     "a stake fails to checkpoint the staker's reward debt, so an attacker stakes after a "
     "distribution and claims rewards they never accrued"),
    ("storage-collision", "storage-guarded",
     "unprivileged implementation logic can write the proxy's reserved admin slot and "
     "take ownership"),
    ("decimals-mismatch", "decimals-guarded",
     "the vault assumes every token has 6 decimals, so an 18-decimal deposit is credited "
     "1e12x its real value"),
    ("sandwich-slippage", "sandwich-guarded",
     "a front-run / victim-swap / back-run sandwich extracts the victim's price impact "
     "because the victim's slippage limit is not enforced (ordering / MEV)"),
    ("mcp-cors", "mcp-cors-guarded",
     "an MCP protected resource reflects any Origin (including 'null') while allowing "
     "credentials, so an attacker page reads the user's authenticated cross-origin response"),
    ("mcp-audience", "mcp-audience-guarded",
     "an MCP token verifier checks signature and expiry but not audience or tenant, so a "
     "token minted for one resource or site is accepted by another (cross-tenant read)"),
]

_BY_NAME = {spec.name: spec for spec in TARGET_SPECS}


def available_targets() -> list[str]:
    return [spec.name for spec in TARGET_SPECS]


def get_spec(name: str) -> TargetSpec:
    if name not in _BY_NAME:
        raise KeyError(f"unknown target: {name} (known: {', '.join(available_targets())})")
    return _BY_NAME[name]


def make_target(name: str):
    """Instantiate a target by name."""
    return get_spec(name).cls()
