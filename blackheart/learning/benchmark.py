"""Historical + negative benchmark for the hypothesis-ranking strategy.

A strategy improvement is worthless if it is only *asserted*. This module holds a
labelled corpus of ranking scenarios and measures the engine's top-1 accuracy and
mean reciprocal rank (MRR) against them, before and after a change.

Two corpora, deliberately kept apart (mission Phase 6, 10):

  * ``historical`` -- scenarios drawn from how real engagements actually resolved.
    Here the strategy is *supposed* to improve.
  * ``negative``   -- mutation / misleading cases: superficially similar targets
    where the "obvious" learned rule is wrong. A change that raises the historical
    score by memorising it will usually fall over here. This is the anti-overfitting
    gate.

Each scenario names the vulnerability class that a competent analyst would
investigate next, given the target's *actual* surface. The benchmark never invents
a vulnerability; it only checks whether the engine ranks the right class first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..objectives import TargetProfile


@dataclass
class Scenario:
    name: str
    profile: TargetProfile
    acceptable: tuple[str, ...]
    note: str = ""

    @property
    def expected_class(self) -> str:
        """The single best class, for display only (the metric uses the set)."""
        return self.acceptable[0]


def _prof(name: str, **kw) -> TargetProfile:
    base = dict(kind="smart-contract", assets=[], entry_points=[],
                trust_boundaries=[], roles=[], external_deps=[], notes="")
    base.update(kw)
    return TargetProfile(name=name, **base)


# --------------------------------------------------------------------------- #
# Historical corpus -- targets whose real surface rules classes in or out.
# `acceptable` is the set a competent analyst would consider defensible; the
# metric credits any of them at top-1.
# --------------------------------------------------------------------------- #

HISTORICAL: list[Scenario] = [
    Scenario(
        "oracle-free-vault",
        _prof(
            "VaultNoOracle",
            assets=["shares", "funds"],
            entry_points=["deposit(uint256)", "withdraw(uint256)", "redeem(uint256)"],
            trust_boundaries=["user <-> vault"],
            roles=["depositor"],
            external_deps=[],
            notes="ERC4626 vault with no external price dependency",
        ),
        ("rounding-precision", "accounting-manipulation"),
        note="No oracle -> oracle-manipulation must not win; share math is the real surface.",
    ),
    Scenario(
        "no-signature-surface",
        _prof(
            "PlainPool",
            assets=["funds"],
            entry_points=["deposit(uint256)", "withdraw(uint256)", "swap(uint256)"],
            trust_boundaries=["user <-> pool"],
            roles=["liquidity-provider"],
            external_deps=[],
            notes="AMM pool; no permit, no EIP-712, no signatures",
        ),
        ("accounting-manipulation", "rounding-precision"),
        note="No signature surface -> replay/signature classes must be damped.",
    ),
    Scenario(
        "no-proxy-surface",
        _prof(
            "ImmutableToken",
            assets=["tokens"],
            entry_points=["transfer(address,uint256)", "approve(address,uint256)"],
            trust_boundaries=["holder <-> token"],
            roles=["holder", "spender"],
            external_deps=[],
            notes="Immutable (non-upgradeable) ERC20; no initialize()",
        ),
        ("state-inconsistency", "accounting-manipulation"),
        note="No proxy/initializer -> proxy-initializer must be damped.",
    ),
    Scenario(
        "signature-bridge",
        _prof(
            "SignedBridge",
            assets=["funds"],
            entry_points=["settle(bytes,bytes)", "deposit(uint256)"],
            trust_boundaries=["relayer <-> bridge"],
            roles=["relayer", "user"],
            external_deps=["signature-verifier"],
            notes="EIP-712 signed settlement messages; nonce present",
        ),
        ("replay-forgery", "signature-bypass"),
        note="Signature surface present -> replay is the right next class.",
    ),
]

# --------------------------------------------------------------------------- #
# Negative corpus -- the misleading twins. The learned rule must NOT break here.
# --------------------------------------------------------------------------- #

NEGATIVE: list[Scenario] = [
    Scenario(
        "oracle-present-via-notes",
        _prof(
            "LendingWithOracle",
            assets=["collateral", "funds"],
            entry_points=["borrow(uint256)", "liquidate(address)"],
            trust_boundaries=["market <-> price feed"],
            roles=["borrower", "liquidator"],
            external_deps=["chainlink-price-feed"],
            notes="collateral is valued by an external price feed",
        ),
        ("oracle-manipulation", "liquidation-bypass"),
        note="Oracle IS present -> a naive 'never rank oracle' rule would fail here.",
    ),
    Scenario(
        "signature-present-via-entrypoint",
        _prof(
            "PermitToken",
            assets=["tokens"],
            entry_points=["permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                          "transferFrom(address,address,uint256)"],
            trust_boundaries=["signer <-> spender"],
            roles=["holder", "spender"],
            external_deps=["ecrecover"],
            notes="ERC2612 permit token",
        ),
        ("replay-forgery", "signature-bypass"),
        note="Signature surface present -> replay must stay rankable.",
    ),
    Scenario(
        "proxy-present",
        _prof(
            "UpgradeableVault",
            assets=["funds"],
            entry_points=["initialize(address)", "deposit(uint256)"],
            trust_boundaries=["admin <-> proxy"],
            roles=["admin", "user"],
            external_deps=["proxy"],
            notes="UUPS upgradeable; initialize() present",
        ),
        ("privilege-escalation", "proxy-initializer", "access-control"),
        note="Proxy surface present -> proxy class must stay rankable.",
    ),
    Scenario(
        "callback-present",
        _prof(
            "HookVault",
            assets=["funds"],
            entry_points=["deposit(uint256)", "onFlashLoan(address,uint256)"],
            trust_boundaries=["vault <-> callback"],
            roles=["user", "callback"],
            external_deps=["flashloan-provider"],
            notes="external callback / hook present",
        ),
        ("callback-reentrancy", "state-inconsistency"),
        note="Callback surface present -> reentrancy must stay rankable.",
    ),
]


@dataclass
class RankingMetrics:
    corpus: str
    cases: int
    top1: int
    mrr: float
    suppress_ok: int
    suppress_total: int
    seconds: float = 0.0

    @property
    def top1_accuracy(self) -> float:
        return self.top1 / self.cases if self.cases else 0.0

    @property
    def suppression_accuracy(self) -> float:
        return self.suppress_ok / self.suppress_total if self.suppress_total else 1.0

    def to_dict(self) -> dict:
        return {
            "corpus": self.corpus,
            "cases": self.cases,
            "top1": self.top1,
            "top1_accuracy": round(self.top1_accuracy, 4),
            "mrr": round(self.mrr, 4),
            "suppression_accuracy": round(self.suppression_accuracy, 4),
            "suppressed": f"{self.suppress_ok}/{self.suppress_total}",
            "seconds": round(self.seconds, 4),
        }


class RankingBenchmark:
    """Evaluate a ranking strategy (a HypothesisEngine factory) on the corpora."""

    def __init__(
        self,
        historical: Optional[list[Scenario]] = None,
        negative: Optional[list[Scenario]] = None,
    ) -> None:
        self.historical = historical if historical is not None else HISTORICAL
        self.negative = negative if negative is not None else NEGATIVE

    @staticmethod
    def _class_ranking(scenario: Scenario, engine_factory) -> list[str]:
        engine = engine_factory(scenario.profile, None)
        hyps = [h for h in engine.generate() if not h.skipped_disproven]
        best: dict[str, float] = {}
        for h in hyps:
            best[h.category] = max(best.get(h.category, 0.0), h.score)
        return [c for c, _ in sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))]

    def evaluate(
        self, engine_factory, *, corpus: str = "historical"
    ) -> RankingMetrics:
        import time

        from ..hypothesis.surface import applicability, detect_surface

        scenarios = self.historical if corpus == "historical" else self.negative
        t0 = time.perf_counter()
        top1 = 0
        rr = 0.0
        suppress_ok = 0
        suppress_total = 0
        for sc in scenarios:
            ranking = self._class_ranking(sc, engine_factory)
            best_rank = min(
                (ranking.index(c) for c in sc.acceptable if c in ranking),
                default=None,
            )
            if best_rank is not None:
                if best_rank == 0:
                    top1 += 1
                rr += 1.0 / (best_rank + 1)
            # Suppression: classes whose required surface is ABSENT must rank below
            # the best acceptable class. This is the generalizable property the
            # surface model provides, and the negative corpus keeps it honest.
            surface = detect_surface(sc.profile)
            if best_rank is not None:
                for cat in ranking:
                    app = applicability(cat, surface)
                    if app.multiplier < 1.0:  # surface absent -> should be suppressed
                        suppress_total += 1
                        if ranking.index(cat) > best_rank:
                            suppress_ok += 1
        seconds = time.perf_counter() - t0
        return RankingMetrics(
            corpus, len(scenarios), top1,
            rr / len(scenarios) if scenarios else 0.0,
            suppress_ok, suppress_total, seconds,
        )

    def evaluate_all(self, engine_factory) -> dict:
        return {
            "historical": self.evaluate(engine_factory, corpus="historical").to_dict(),
            "negative": self.evaluate(engine_factory, corpus="negative").to_dict(),
        }
