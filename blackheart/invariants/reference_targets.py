"""Reference targets for testing the invariant engine end-to-end.

These are deliberately small, local, self-contained models used to prove the
engine can (a) find a genuine invariant violation in a *vulnerable* reference and
(b) report *no* violation in a *safe* reference. They are the engine's own test
fixtures, not bounty targets -- no network, no real funds.

The vulnerable vault reproduces the classic ERC4626 share-inflation flaw: an
attacker deposits 1 wei, donates underlying directly to inflate the share price,
and a later depositor's shares round down to zero -- their deposit is captured by
the attacker. The safe vault defends with virtual shares/offset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .engine import InvariantSpec, OpSpec, Target

DECIMALS = 10 ** 18


@dataclass
class VaultState:
    total_shares: int = 0
    total_assets: int = 0
    balances: dict[str, int] = field(default_factory=dict)     # shares per actor
    underlying: dict[str, int] = field(default_factory=dict)   # wallet underlying per actor
    donation_assets: int = 0                                   # unsolicited underlying
    deposited: dict[str, int] = field(default_factory=dict)    # cumulative deposits
    withdrawn: dict[str, int] = field(default_factory=dict)    # cumulative withdrawals
    donated: dict[str, int] = field(default_factory=dict)      # voluntary donations
    initial: dict[str, int] = field(default_factory=dict)      # starting underlying
    last_deposit_amount: int = 0
    last_deposit_shares: int = 0

    def assets_backing(self) -> int:
        return self.total_assets + self.donation_assets

    def redeemable(self, who: str) -> int:
        if self.total_shares == 0:
            return 0
        return (self.balances.get(who, 0) * self.assets_backing()) // self.total_shares


class VulnerableVault(Target):
    """ERC4626-style vault with no virtual-share defence (vulnerable)."""

    name = "vulnerable-vault"
    ACTORS = ["attacker", "victim"]

    def reset(self) -> VaultState:
        st = VaultState()
        st.underlying = {"attacker": 10000 * DECIMALS, "victim": 100 * DECIMALS}
        st.initial = dict(st.underlying)
        st.balances = {a: 0 for a in self.ACTORS}
        st.deposited = {a: 0 for a in self.ACTORS}
        st.withdrawn = {a: 0 for a in self.ACTORS}
        st.donated = {a: 0 for a in self.ACTORS}
        return st

    def ops(self) -> list[OpSpec]:
        return [
            OpSpec("deposit", ["attacker", "victim"],
                   {"amount": [1, 2, 5, 10, 50, 100 * DECIMALS]},
                   weight=5, description="deposit underlying, receive shares"),
            OpSpec("withdraw", ["attacker", "victim"],
                   {"shares": [1, 2, 5, 10, 50 * DECIMALS]},
                   weight=3, description="redeem shares for underlying"),
            OpSpec("donate", ["attacker"],
                   {"amount": [1, 2, 10, 1000 * DECIMALS]},
                   weight=2, description="transfer underlying directly to the vault"),
        ]

    def invariants(self) -> list[InvariantSpec]:
        return [
            InvariantSpec(
                "no-material-attacker-profit",
                "the attacker's net value never exceeds their starting value by more "
                "than 0.1% (dust-level rounding is ignored; real extraction is not)",
                self._no_material_attacker_profit,
                severity_if_broken="high",
            ),
            InvariantSpec(
                "no-material-victim-loss",
                "no actor who never donated loses more than 1% of their starting value",
                self._no_material_victim_loss,
                severity_if_broken="high",
            ),
        ]

    ATTACKER_MATERIAL_BPS = 10    # 0.1% of attacker capital counts as profit
    VICTIM_MATERIAL_BPS = 100     # 1% of victim capital counts as loss
    BPS_DENOM = 10_000

    def _no_material_attacker_profit(self, st: VaultState) -> bool:
        a = "attacker"
        net = st.underlying.get(a, 0) + st.redeemable(a)
        gain = net - st.initial[a]
        threshold = (st.initial[a] * self.ATTACKER_MATERIAL_BPS) // self.BPS_DENOM
        return gain <= threshold

    def _no_material_victim_loss(self, st: VaultState) -> bool:
        for a in st.initial:
            if st.donated.get(a, 0) > 0:
                continue  # voluntary donations are not a security loss
            net = st.underlying.get(a, 0) + st.redeemable(a)
            loss = st.initial[a] - net
            threshold = (st.initial[a] * self.VICTIM_MATERIAL_BPS) // self.BPS_DENOM
            if loss > threshold:
                return False
        return True

    def step(self, st: VaultState, op: str, actor: str, params: dict[str, Any]) -> None:
        st.last_deposit_amount = 0
        st.last_deposit_shares = 0
        if op == "deposit":
            amount = min(int(params["amount"]), st.underlying.get(actor, 0))
            if amount <= 0:
                return
            backing = st.assets_backing()
            shares = amount if st.total_shares == 0 else (amount * st.total_shares) // backing
            st.underlying[actor] -= amount
            st.total_assets += amount
            st.total_shares += shares
            st.balances[actor] = st.balances.get(actor, 0) + shares
            st.deposited[actor] = st.deposited.get(actor, 0) + amount
            st.last_deposit_amount = amount
            st.last_deposit_shares = shares
        elif op == "withdraw":
            shares = min(int(params["shares"]), st.balances.get(actor, 0))
            if shares <= 0 or st.total_shares == 0:
                return
            assets = (shares * st.assets_backing()) // st.total_shares
            st.balances[actor] -= shares
            st.total_shares -= shares
            st.underlying[actor] = st.underlying.get(actor, 0) + assets
            st.withdrawn[actor] = st.withdrawn.get(actor, 0) + assets
            # assets leave the vault; draw down donations first, then deposits
            take = min(assets, st.donation_assets)
            st.donation_assets -= take
            st.total_assets = max(0, st.total_assets - (assets - take))
        elif op == "donate":
            amount = min(int(params["amount"]), st.underlying.get(actor, 0))
            if amount <= 0:
                return
            st.underlying[actor] -= amount
            st.donation_assets += amount
            st.donated[actor] = st.donated.get(actor, 0) + amount

    def snapshot(self, st: VaultState) -> dict[str, Any]:
        return {
            "total_shares": st.total_shares,
            "total_assets": st.total_assets,
            "donation_assets": st.donation_assets,
            "balances": dict(st.balances),
            "redeemable": {a: st.redeemable(a) for a in st.initial},
            "underlying": dict(st.underlying),
        }


class SafeVault(VulnerableVault):
    """Same vault with a virtual-shares/offset defence."""

    name = "safe-vault"
    VIRTUAL_SHARES = DECIMALS
    VIRTUAL_ASSETS = 1

    def step(self, st: VaultState, op: str, actor: str, params: dict[str, Any]) -> None:
        if op != "deposit":
            super().step(st, op, actor, params)
            return
        st.last_deposit_amount = 0
        st.last_deposit_shares = 0
        amount = min(int(params["amount"]), st.underlying.get(actor, 0))
        if amount <= 0:
            return
        backing = st.assets_backing() + self.VIRTUAL_ASSETS
        shares = (amount * (st.total_shares + self.VIRTUAL_SHARES)) // backing
        st.underlying[actor] -= amount
        st.total_assets += amount
        st.total_shares += shares
        st.balances[actor] = st.balances.get(actor, 0) + shares
        st.deposited[actor] = st.deposited.get(actor, 0) + amount
        st.last_deposit_amount = amount
        st.last_deposit_shares = shares
