"""Executable models of the *documented* Hyperliquid mechanics, for the stateful
invariant engine.

Why models and not the real thing: the Hyperliquid bounty scope covers bugs that
cause an outage or logical error on nodes/API servers (HyperCore), and explicitly
prohibits testing mainnet code ("all testing should be done on testnet or local
forks"). Portfolio margin and HIP-4 outcomes live inside the proprietary HyperCore
node -- there is no public source for either (``github.com/hyperliquid-dex`` ships
only an SDK, a node Dockerfile stub, and a 2023 Rust contracts stub). The live
implementations therefore cannot be executed locally, and the mission's rule set
forbids pointing an unaudited model at mainnet.

So these are **spec-derived executable models** of the accounting the official
docs describe, with the documented parameters baked in:

  * Portfolio margin (https://hyperliquid.gitbook.io/hyperliquid-docs/trading/portfolio-margin)
    - HYPE LTV 0.65, BTC LTV 0.50
    - liquidation threshold ``0.5 + 0.5 * LTV``
    - borrow capacity ``token_balance * borrow_oracle_price * ltv``
    - "if all existing supply is lent out, suppliers cannot withdraw" (FAQ)
  * HIP-4 outcomes (https://hyperliquid.gitbook.io/hyperliquid-docs/hyperliquid-improvement-proposals-hips/hip-4-outcome-markets)
    - split X quote -> X Yes + X No; merge X Yes + X No -> X quote
    - settlement pays ``settleFraction`` per Yes and ``1 - settleFraction`` per No

Each class ships a **vulnerable** variant (a plausible implementation defect of
the documented mechanic, so the fuzzer finds a genuine invariant violation) and a
**guarded** variant that implements the documentation correctly (the same
invariants hold -- the non-vacuity control the engine already relies on).

These are fixtures that let the engine *attack the class*. A counterexample here
is a **hypothesis about the specification**, never a claim that the live protocol
is vulnerable. Turning a hypothesis into a finding requires the authorization
gate plus reachability against the real, in-scope implementation -- which, for
HyperCore, means the testnet feature the program has announced. See
``research/private/hyperliquid/`` for the dated scope capture and the ledger.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, Target

SCALE = 10 ** 6                       # USDC and prices are 6-decimal fixed point
LTV_BPS = {"HYPE": 6500, "BTC": 5000}  # HYPE 0.65, BTC 0.50
HYPE_PRICE = 40 * SCALE
BTC_PRICE = 80_000 * SCALE


def _value(amount: int, price: int) -> int:
    """USDC value (6dp) of ``amount`` units (6dp) at ``price`` (6dp)."""
    return amount * price // SCALE


def _liq_threshold_bps(ltv_bps: int) -> int:
    """Documented liquidation threshold ``0.5 + 0.5 * LTV`` in basis points."""
    return 5000 + ltv_bps // 2


# --------------------------------------------------------------------------- #
# 1. Portfolio-margin supply / borrow / withdraw solvency
# --------------------------------------------------------------------------- #

@dataclass
class PMSupplyState:
    collateral: dict[str, dict[str, int]] = field(default_factory=dict)
    supplied: dict[str, int] = field(default_factory=dict)      # USDC per actor
    borrowed: dict[str, int] = field(default_factory=dict)      # USDC per actor
    price: dict[str, int] = field(default_factory=dict)
    total_supplied: int = 0
    total_borrowed: int = 0
    external_in: dict[str, int] = field(default_factory=dict)
    external_out: dict[str, int] = field(default_factory=dict)


class PortfolioMarginSupply(Target):
    """A portfolio-margin account where suppliers may withdraw funds that are lent out.

    The documented rule (FAQ, "Advanced technical details"): *"If all existing
    supply is lent out, users who have supplied assets will not be able to
    withdraw their collateral until more supply is added or borrows are repaid."*
    This model omits that rule, so a supplier can withdraw their full claim while
    the balance is on loan -- leaving outstanding debt unbacked and the pool
    insolvent (the first-withdrawer advantage of a bank run).
    """

    name = "hl-pm-supply"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]

    def reset(self) -> PMSupplyState:
        st = PMSupplyState()
        st.price = {"HYPE": HYPE_PRICE, "BTC": BTC_PRICE}
        st.collateral = {
            self.ATTACKER: {"HYPE": 100 * SCALE, "BTC": 0},
            self.VICTIM: {"HYPE": 0, "BTC": 1 * SCALE},
        }
        st.supplied = {self.ATTACKER: 0, self.VICTIM: 100 * SCALE}
        st.borrowed = {self.ATTACKER: 0, self.VICTIM: 0}
        st.total_supplied = 100 * SCALE
        st.total_borrowed = 0
        st.external_in = {self.ATTACKER: 0, self.VICTIM: 100 * SCALE}
        st.external_out = {self.ATTACKER: 0, self.VICTIM: 0}
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("supply", self.ACTORS, {"amount": [10 * SCALE, 100 * SCALE, 1000 * SCALE]},
                   weight=3, description="supply USDC to earn yield"),
            OpSpec("borrow", self.ACTORS, {"amount": [10 * SCALE, 100 * SCALE, 1000 * SCALE]},
                   weight=4, description="borrow USDC against eligible collateral up to LTV"),
            OpSpec("repay", self.ACTORS, {"amount": [10 * SCALE, 100 * SCALE]},
                   weight=1, description="repay outstanding USDC borrow"),
            OpSpec("withdraw_supply", self.ACTORS,
                   {"amount": [10 * SCALE, 100 * SCALE, 1000 * SCALE]},
                   weight=4, description="withdraw supplied USDC"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "pm-pool-solvent",
                "total supplied USDC always covers total borrowed USDC "
                "(idle supply never goes negative), so no debt is left unbacked",
                self._solvent,
                severity_if_broken="critical",
            ),
        ]

    def _solvent(self, st: PMSupplyState) -> bool:
        return st.total_supplied >= st.total_borrowed

    def _borrow_limit(self, st: PMSupplyState, actor: str) -> int:
        limit = 0
        for asset, bal in st.collateral.get(actor, {}).items():
            limit += _value(bal, st.price[asset]) * LTV_BPS[asset] // 10_000
        return limit

    def step(self, st: PMSupplyState, op: str, actor: str, params: dict[str, Any]) -> None:
        amt = int(params.get("amount", 0))
        if amt <= 0:
            return
        if op == "supply":
            st.supplied[actor] = st.supplied.get(actor, 0) + amt
            st.total_supplied += amt
            st.external_in[actor] = st.external_in.get(actor, 0) + amt
        elif op == "borrow":
            if amt > self._borrow_limit(st, actor):
                return
            if amt > st.total_supplied - st.total_borrowed:
                return
            st.borrowed[actor] = st.borrowed.get(actor, 0) + amt
            st.total_borrowed += amt
            st.external_out[actor] = st.external_out.get(actor, 0) + amt
        elif op == "repay":
            pay = min(amt, st.borrowed.get(actor, 0))
            if pay <= 0:
                return
            st.borrowed[actor] -= pay
            st.total_borrowed -= pay
        elif op == "withdraw_supply":
            self._withdraw(st, actor, amt)

    def _withdraw(self, st: PMSupplyState, actor: str, amt: int) -> None:
        # Vulnerable: only the supplier's own claim is checked -- not whether the
        # funds are currently lent out.
        pay = min(amt, st.supplied.get(actor, 0))
        if pay <= 0:
            return
        st.supplied[actor] -= pay
        st.total_supplied -= pay
        st.external_out[actor] = st.external_out.get(actor, 0) + pay

    def snapshot(self, st: PMSupplyState) -> dict[str, Any]:
        return {
            "supplied": dict(st.supplied),
            "borrowed": dict(st.borrowed),
            "total_supplied": st.total_supplied,
            "total_borrowed": st.total_borrowed,
            "idle": st.total_supplied - st.total_borrowed,
        }


class GuardedPortfolioMarginSupply(PortfolioMarginSupply):
    """Same model, but a withdrawal may not take lent-out funds (idle floor)."""

    name = "hl-pm-supply-guarded"

    def _withdraw(self, st: PMSupplyState, actor: str, amt: int) -> None:
        idle = st.total_supplied - st.total_borrowed
        pay = min(amt, st.supplied.get(actor, 0), idle)
        if pay <= 0:
            return
        st.supplied[actor] -= pay
        st.total_supplied -= pay
        st.external_out[actor] = st.external_out.get(actor, 0) + pay


# --------------------------------------------------------------------------- #
# 2. Portfolio-margin liquidation threshold
# --------------------------------------------------------------------------- #

@dataclass
class PMLiquidationState:
    collateral: dict[str, dict[str, int]] = field(default_factory=dict)
    borrowed: dict[str, int] = field(default_factory=dict)
    price: dict[str, int] = field(default_factory=dict)
    improper_liquidations: int = 0
    liquidations: int = 0


class PortfolioMarginLiquidation(Target):
    """Liquidation gated on the wrong threshold.

    The docs distinguish the borrow LTV (0.65 HYPE / 0.50 BTC) from the
    liquidation threshold ``0.5 + 0.5 * LTV`` (0.825 / 0.75). This model treats a
    position as liquidatable as soon as the debt exceeds the *borrow* LTV, i.e.
    it seizes positions that are healthy under the documented threshold.
    """

    name = "hl-pm-liquidation"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]

    def reset(self) -> PMLiquidationState:
        st = PMLiquidationState()
        st.price = {"HYPE": HYPE_PRICE, "BTC": BTC_PRICE}
        st.collateral = {
            self.ATTACKER: {"HYPE": 100 * SCALE, "BTC": 0},
            self.VICTIM: {"HYPE": 0, "BTC": 1 * SCALE},
        }
        st.borrowed = {self.ATTACKER: 0, self.VICTIM: 0}
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("borrow", self.ACTORS, {"amount": [10 * SCALE, 500 * SCALE, 1000 * SCALE]},
                   weight=4, description="borrow against collateral up to LTV"),
            OpSpec("price_move", [self.ATTACKER, self.VICTIM], {"pct": [90, 95, 99, 105]},
                   weight=4, description="the collateral mark price moves by pct%"),
            OpSpec("liquidate", self.ACTORS, {},
                   weight=4, description="backstop liquidates an account it deems unhealthy"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "pm-liquidation-only-past-threshold",
                "an account is only liquidated once its debt exceeds the documented "
                "liquidation threshold 0.5 + 0.5 * LTV; healthy positions are never seized",
                self._only_past_threshold,
                severity_if_broken="high",
            ),
        ]

    def _only_past_threshold(self, st: PMLiquidationState) -> bool:
        return st.improper_liquidations == 0

    def _collateral_value(self, st: PMLiquidationState, actor: str) -> int:
        return sum(_value(bal, st.price[asset])
                   for asset, bal in st.collateral.get(actor, {}).items())

    def _liq_threshold_value(self, st: PMLiquidationState, actor: str) -> int:
        total = 0
        for asset, bal in st.collateral.get(actor, {}).items():
            total += _value(bal, st.price[asset]) * _liq_threshold_bps(LTV_BPS[asset]) // 10_000
        return total

    def _borrow_limit(self, st: PMLiquidationState, actor: str) -> int:
        total = 0
        for asset, bal in st.collateral.get(actor, {}).items():
            total += _value(bal, st.price[asset]) * LTV_BPS[asset] // 10_000
        return total

    def step(self, st: PMLiquidationState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op == "borrow":
            amt = int(params["amount"])
            if amt <= 0 or amt > self._borrow_limit(st, actor):
                return
            st.borrowed[actor] = st.borrowed.get(actor, 0) + amt
        elif op == "price_move":
            pct = int(params["pct"])
            for asset in st.price:
                st.price[asset] = st.price[asset] * pct // 100
        elif op == "liquidate":
            self._liquidate(st, actor)

    def _liquidatable(self, st: PMLiquidationState, actor: str) -> bool:
        # Vulnerable: the borrow LTV is used as the liquidation bar.
        return st.borrowed.get(actor, 0) > self._borrow_limit(st, actor)

    def _liquidate(self, st: PMLiquidationState, actor: str) -> None:
        if st.borrowed.get(actor, 0) <= 0:
            return
        if not self._liquidatable(st, actor):
            return
        # Record whether this seizure was actually past the documented threshold.
        if st.borrowed[actor] <= self._liq_threshold_value(st, actor):
            st.improper_liquidations += 1
        st.liquidations += 1
        st.borrowed[actor] = 0
        for asset in st.collateral.get(actor, {}):
            st.collateral[actor][asset] = 0

    def snapshot(self, st: PMLiquidationState) -> dict[str, Any]:
        return {
            "borrowed": dict(st.borrowed),
            "collateral": {a: dict(c) for a, c in st.collateral.items()},
            "price": dict(st.price),
            "liquidations": st.liquidations,
            "improper_liquidations": st.improper_liquidations,
        }


class GuardedPortfolioMarginLiquidation(PortfolioMarginLiquidation):
    """Same model, but liquidation uses the documented ``0.5 + 0.5 * LTV`` bar."""

    name = "hl-pm-liquidation-guarded"

    def _liquidatable(self, st: PMLiquidationState, actor: str) -> bool:
        return st.borrowed.get(actor, 0) > self._liq_threshold_value(st, actor)


# --------------------------------------------------------------------------- #
# 3. HIP-4 binary outcome split / merge / settle
# --------------------------------------------------------------------------- #

@dataclass
class OutcomeState:
    yes: dict[str, int] = field(default_factory=dict)
    no: dict[str, int] = field(default_factory=dict)
    quote: dict[str, int] = field(default_factory=dict)
    locked: int = 0
    collateral_in: int = 0
    collateral_out: int = 0
    settled: bool = False
    settle_fraction_bps: int = 0


class OutcomeMarket(Target):
    """A binary outcome market whose ``merge`` burns Yes and No independently.

    Documented mechanic: ``split`` turns X quote into X Yes + X No; ``merge``
    turns X Yes + X No back into X quote. This model burns ``min(amt, yes)`` Yes
    and ``min(amt, no)`` No independently while refunding ``min(amt, yes)`` quote,
    so an actor holding only Yes (having transferred the No away) can merge and
    mint quote it never locked -- value extracted from the collateral pool.
    """

    name = "hl-outcome"
    ATTACKER, ATTACKER2, VICTIM = "attacker", "attacker2", "victim"
    ACTORS = [ATTACKER, ATTACKER2, VICTIM]

    def reset(self) -> OutcomeState:
        st = OutcomeState()
        st.quote = {self.ATTACKER: 500 * SCALE, self.ATTACKER2: 500 * SCALE,
                    self.VICTIM: 500 * SCALE}
        st.yes = {a: 0 for a in self.ACTORS}
        st.no = {a: 0 for a in self.ACTORS}
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("split", self.ACTORS, {"amount": [10 * SCALE, 100 * SCALE]},
                   weight=4, description="split quote into equal Yes and No shares"),
            OpSpec("merge", self.ACTORS, {"amount": [10 * SCALE, 100 * SCALE]},
                   weight=5, description="merge Yes and No shares back into quote"),
            OpSpec("transfer", self.ACTORS,
                   {"amount": [10 * SCALE, 100 * SCALE],
                    "to": [self.ATTACKER, self.ATTACKER2, self.VICTIM],
                    "side": ["yes", "no"]},
                   weight=3, description="transfer one side of the outcome to another account"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "outcome-shares-collateralized",
                "locked quote equals the outstanding Yes supply and equals the "
                "outstanding No supply, so every share is fully collateralized",
                self._collateralized,
                severity_if_broken="critical",
            ),
        ]

    def _collateralized(self, st: OutcomeState) -> bool:
        if st.settled:
            return True
        total_yes = sum(st.yes.values())
        total_no = sum(st.no.values())
        return st.locked == total_yes and total_yes == total_no

    def step(self, st: OutcomeState, op: str, actor: str, params: dict[str, Any]) -> None:
        if st.settled:
            return
        amt = int(params.get("amount", 0))
        if amt <= 0:
            return
        if op == "split":
            pay = min(amt, st.quote.get(actor, 0))
            if pay <= 0:
                return
            st.quote[actor] -= pay
            st.yes[actor] = st.yes.get(actor, 0) + pay
            st.no[actor] = st.no.get(actor, 0) + pay
            st.locked += pay
            st.collateral_in += pay
        elif op == "merge":
            self._merge(st, actor, amt)
        elif op == "transfer":
            self._transfer(st, actor, params["to"], params.get("side", "yes"), amt)

    def _merge(self, st: OutcomeState, actor: str, amt: int) -> None:
        # Vulnerable: Yes and No are clamped independently.
        burn_yes = min(amt, st.yes.get(actor, 0))
        if burn_yes <= 0:
            return
        burn_no = min(amt, st.no.get(actor, 0))
        st.yes[actor] -= burn_yes
        st.no[actor] -= burn_no
        st.quote[actor] = st.quote.get(actor, 0) + burn_yes
        st.locked -= burn_yes
        st.collateral_out += burn_yes

    def _transfer(self, st: OutcomeState, actor: str, to: str, side_name: str, amt: int) -> None:
        # Move `amt` of the named side to a counterparty (transfer of one leg).
        if to == actor:
            return
        side = st.yes if side_name == "yes" else st.no
        move = min(amt, side.get(actor, 0))
        if move <= 0:
            return
        side[actor] -= move
        side[to] = side.get(to, 0) + move

    def snapshot(self, st: OutcomeState) -> dict[str, Any]:
        return {
            "yes": dict(st.yes),
            "no": dict(st.no),
            "quote": dict(st.quote),
            "locked": st.locked,
            "collateral_in": st.collateral_in,
            "collateral_out": st.collateral_out,
        }


class GuardedOutcomeMarket(OutcomeMarket):
    """Same model, but ``merge`` burns ``min(amt, yes, no)`` on both sides."""

    name = "hl-outcome-guarded"

    def _merge(self, st: OutcomeState, actor: str, amt: int) -> None:
        burn = min(amt, st.yes.get(actor, 0), st.no.get(actor, 0))
        if burn <= 0:
            return
        st.yes[actor] -= burn
        st.no[actor] -= burn
        st.quote[actor] = st.quote.get(actor, 0) + burn
        st.locked -= burn
        st.collateral_out += burn


# --------------------------------------------------------------------------- #
# 4. HIP-4 question: negate/merge must conserve a full No set
# --------------------------------------------------------------------------- #

@dataclass
class QuestionState:
    # quote[actor][q] = quote on question q; no[actor][q][outcome] = No shares held.
    # ``redeemed[q]`` counts the total No-set quote paid out by the protocol on
    # question q; ``fair[q]`` is what the documented (n-1) payout would have been.
    # The protocol only ever locks quote via ``split``, so at settlement the
    # question must have paid out at most what it locked.
    quote: dict[str, dict[int, int]] = field(default_factory=dict)
    yes: dict[str, dict[int, dict[int, int]]] = field(default_factory=dict)
    no: dict[str, dict[int, dict[int, int]]] = field(default_factory=dict)
    locked: dict[int, int] = field(default_factory=dict)
    redeemed: dict[int, int] = field(default_factory=dict)
    fair: dict[int, int] = field(default_factory=dict)
    questions: int = 2
    outcomes_per_q: int = 3
    q_quote_in: int = 0
    q_quote_out: int = 0


class QuestionMarket(Target):
    """A question of ``n`` outcomes whose ``merge`` refunds a No set as ``n`` quote.

    HIP-4: "users with No shares on different outcomes of the same question can
    redeem quote tokens before the underlying outcomes settle", and exactly one
    outcome settles Yes, so a full No set is worth exactly ``n - 1`` quote. This
    model pays ``n`` quote for a full No set (one too many), minting quote the
    protocol never locked -- value extracted from the collateral pool. The
    guarded model pays ``n - 1``.
    """

    name = "hl-question"
    ATTACKER, VICTIM = "attacker", "victim"
    ACTORS = [ATTACKER, VICTIM]
    QUESTIONS = 2
    OUTCOMES = 3

    def reset(self) -> QuestionState:
        st = QuestionState(questions=self.QUESTIONS, outcomes_per_q=self.OUTCOMES)
        st.quote = {a: {q: 500 * SCALE for q in range(st.questions)} for a in self.ACTORS}
        st.yes = {a: {q: {i: 0 for i in range(st.outcomes_per_q)}
                      for q in range(st.questions)} for a in self.ACTORS}
        st.no = {a: {q: {i: 0 for i in range(st.outcomes_per_q)}
                     for q in range(st.questions)} for a in self.ACTORS}
        st.locked = {q: 0 for q in range(st.questions)}
        st.redeemed = {q: 0 for q in range(st.questions)}
        st.fair = {q: 0 for q in range(st.questions)}
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("split", self.ACTORS,
                   {"q": list(range(self.QUESTIONS)),
                    "outcome": list(range(self.OUTCOMES)),
                    "amount": [10 * SCALE, 100 * SCALE]},
                   weight=3, description="split quote into Yes+No on one outcome"),
            OpSpec("merge_no_set", self.ACTORS,
                   {"q": list(range(self.QUESTIONS)),
                    "amount": [10 * SCALE, 100 * SCALE]},
                   weight=5, description="merge a full No set across a question's outcomes"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "question-no-set-conserves",
                "a full No set across a question's n outcomes redeems exactly n-1 "
                "quote tokens, so the question's locked collateral always covers "
                "every redemption",
                self._conserves,
                severity_if_broken="critical",
            ),
        ]

    def _conserves(self, st: QuestionState) -> bool:
        # Documented payout for a full No set is n-1 quote per set. If the protocol
        # paid more than that (redeemed > fair), it minted quote it never locked.
        return all(st.redeemed[q] <= st.fair[q] for q in st.redeemed)

    def step(self, st: QuestionState, op: str, actor: str, params: dict[str, Any]) -> None:
        amt = int(params.get("amount", 0))
        if amt <= 0:
            return
        if op == "split":
            q = int(params["q"])
            i = int(params["outcome"])
            pay = min(amt, st.quote[actor][q])
            if pay <= 0:
                return
            st.quote[actor][q] -= pay
            st.yes[actor][q][i] += pay
            st.no[actor][q][i] += pay
            st.locked[q] += pay
            st.q_quote_in += pay
        elif op == "merge_no_set":
            self._merge_no_set(st, actor, int(params["q"]), amt)

    def _merge_no_set(self, st: QuestionState, actor: str, q: int, amt: int) -> None:
        # Vulnerable: pays `n` quote for a full No set (should be `n - 1`).
        burn = min(amt, *(st.no[actor][q][i] for i in range(st.outcomes_per_q)))
        if burn <= 0:
            return
        for i in range(st.outcomes_per_q):
            st.no[actor][q][i] -= burn
        payout = burn * self.OUTCOMES          # <-- the defect: n, not n-1
        st.quote[actor][q] += payout
        st.locked[q] -= payout
        st.redeemed[q] += payout
        st.fair[q] += burn * (self.OUTCOMES - 1)
        st.q_quote_out += payout


class GuardedQuestionMarket(QuestionMarket):
    """Same model, but a full No set redeems ``n - 1`` quote (documented value)."""

    name = "hl-question-guarded"

    def _merge_no_set(self, st: QuestionState, actor: str, q: int, amt: int) -> None:
        burn = min(amt, *(st.no[actor][q][i] for i in range(st.outcomes_per_q)))
        if burn <= 0:
            return
        for i in range(st.outcomes_per_q):
            st.no[actor][q][i] -= burn
        payout = burn * (self.OUTCOMES - 1)     # n - 1, the documented value
        st.quote[actor][q] += payout
        st.locked[q] -= payout
        st.redeemed[q] += payout
        st.fair[q] += payout
        st.q_quote_out += payout
