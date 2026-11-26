"""Executable attack-chain database (mission sections 2B, 10, 11).

:mod:`blackheart.chains` *describes* multi-operation attack chains as hypotheses
(parameterised templates with placeholders such as ``"A"``). Those hypotheses
cannot be executed -- the placeholders are not values.

This module is the executable counterpart: a curated database of **concrete**
attack sequences, each bound to a registered invariant-engine target and to the
invariant it is meant to violate. A chain can therefore be *run*, and the run
reports whether the targeted invariant actually broke, on which actor, and
whether the failure is attacker-reachable -- the same honest machinery the fuzzer
uses.

Every chain also names its **guarded counterpart**. Running a chain against the
guarded target is the non-vacuity control: a chain that breaks the vulnerable
model but not the guarded one is a real class demonstration, not a tautology.

Nothing here is a claim that any live system is vulnerable. These are executable
hypotheses against local models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .invariants.engine import run_sequence
from .invariants.registry import make_target
from .models import AttackStep


@dataclass(frozen=True)
class ChainStep:
    actor: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_attack_step(self, index: int, target: str) -> AttackStep:
        return AttackStep(
            index=index, actor=self.actor, action=self.action,
            params=dict(self.params), target_contract=target,
        )


@dataclass(frozen=True)
class AttackChainSpec:
    """A concrete, executable attack sequence bound to a target and invariant."""

    chain_id: str
    title: str
    category: str
    target: str                    # vulnerable target name (see `blackheart targets`)
    guarded_target: str            # its guarded counterpart (non-vacuity control)
    invariant: str                 # invariant this chain is meant to violate
    steps: tuple[ChainStep, ...]
    hypothesis: str = ""
    severity_if_broken: str = "high"

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "category": self.category,
            "target": self.target,
            "guarded_target": self.guarded_target,
            "invariant": self.invariant,
            "hypothesis": self.hypothesis,
            "severity_if_broken": self.severity_if_broken,
            "steps": [
                {"actor": s.actor, "action": s.action, "params": s.params}
                for s in self.steps
            ],
        }


# --------------------------------------------------------------------------- #
# The database
# --------------------------------------------------------------------------- #

_CHAINS: list[AttackChainSpec] = [
    AttackChainSpec(
        chain_id="erc4626-first-depositor-inflation",
        title="Donate to inflate share price, then capture a later depositor's funds",
        category="rounding-precision",
        target="vulnerable",
        guarded_target="safe",
        invariant="no-material-victim-loss",
        hypothesis=(
            "With no virtual-share offset, a 1-wei deposit mints the only share; a "
            "direct donation inflates the asset base so a later depositor's shares "
            "round to zero and the attacker redeems the whole balance."
        ),
        steps=(
            ChainStep("attacker", "deposit", {"amount": 1}),
            ChainStep("attacker", "donate", {"amount": 1000 * 10**18}),
            ChainStep("victim", "deposit", {"amount": 100 * 10**18}),
            ChainStep("attacker", "withdraw", {"shares": 1}),
        ),
    ),
    AttackChainSpec(
        chain_id="oracle-pump-then-borrow",
        title="Pump a manipulable spot price, then borrow past the true LTV",
        category="oracle-manipulation",
        target="lending-oracle",
        guarded_target="lending-oracle-guarded",
        invariant="no-actor-over-borrows",
        hypothesis=(
            "Collateral is valued at a spot price the attacker can move, so a "
            "price pump lets the attacker borrow far beyond the debt the true "
            "reference price would allow."
        ),
        severity_if_broken="critical",
        steps=(
            ChainStep("attacker", "pump_price", {"factor": 10}),
            ChainStep("attacker", "borrow", {"amount": 50_000}),
        ),
    ),
    AttackChainSpec(
        chain_id="permit-sign-once-spend-twice",
        title="Replay a single permit signature to spend more than was authorized",
        category="replay-forgery",
        target="permit-replay",
        guarded_target="permit-guarded",
        invariant="authorization-used-once",
        hypothesis=(
            "A permit with no single-use binding re-arms the allowance each time it "
            "is submitted, so one signature can draw value repeatedly."
        ),
        steps=(
            ChainStep("victim", "victim_sign", {"value": 100}),
            ChainStep("attacker", "replay_permit", {}),
            ChainStep("attacker", "transfer_from", {"amount": 100}),
            ChainStep("attacker", "replay_permit", {}),
            ChainStep("attacker", "transfer_from", {"amount": 100}),
        ),
    ),
    AttackChainSpec(
        chain_id="proxy-reinit-takeover",
        title="Re-call an initializer to seize the owner role, then sweep funds",
        category="privilege-escalation",
        target="proxy-initializer",
        guarded_target="proxy-guarded",
        invariant="no-material-attacker-profit",
        hypothesis=(
            "An initializer that can be called again lets an attacker overwrite the "
            "owner and exercise owner-only functionality."
        ),
        severity_if_broken="critical",
        steps=(
            ChainStep("owner", "initialize", {}),
            ChainStep("attacker", "initialize", {}),
            ChainStep("attacker", "sweep", {"amount": 1000}),
        ),
    ),
    AttackChainSpec(
        chain_id="reentrant-withdraw-drain",
        title="Re-enter withdraw to drain the vault before state is updated",
        category="cross-contract",
        target="callback-reentrancy",
        guarded_target="callback-guarded",
        invariant="no-material-attacker-profit",
        hypothesis=(
            "A withdraw that credits the caller before decrementing its balance "
            "lets a re-entrant call read a stale balance and pay out twice for one "
            "withdrawal, extracting value the attacker never deposited."
        ),
        severity_if_broken="critical",
        steps=(
            ChainStep("attacker", "deposit", {"amount": 50}),
            ChainStep("attacker", "withdraw_reentrant", {"amount": 50}),
        ),
    ),
    AttackChainSpec(
        chain_id="access-control-fee-overwrite",
        title="Overwrite privileged state because the setter is not role-gated",
        category="auth-bypass",
        target="access-control",
        guarded_target="access-guarded",
        invariant="privileged-state-only-by-owner",
        hypothesis=(
            "A privileged setter that never checks the caller's role lets a "
            "non-owner change protected state."
        ),
        steps=(
            ChainStep("owner", "set_fee", {"value": 1}),
            ChainStep("attacker", "set_fee", {"value": 9999}),
        ),
    ),
    AttackChainSpec(
        chain_id="hl-pm-withdraw-lent-supply",
        title="Borrow against collateral, then let a supplier withdraw the lent-out USDC",
        category="accounting-settlement",
        target="hl-pm-supply",
        guarded_target="hl-pm-supply-guarded",
        invariant="pm-pool-solvent",
        hypothesis=(
            "Portfolio margin lets a supplier withdraw funds that are currently lent "
            "out (the FAQ says they must not be able to), leaving outstanding borrows "
            "unbacked -- the first-withdrawer advantage of a bank run."
        ),
        severity_if_broken="critical",
        steps=(
            ChainStep("attacker", "borrow", {"amount": 100 * 10**6}),
            ChainStep("victim", "withdraw_supply", {"amount": 100 * 10**6}),
        ),
    ),
    AttackChainSpec(
        chain_id="hl-pm-liquidate-healthy-position",
        title="Liquidate a position that is healthy under the documented 0.5 + 0.5*LTV bar",
        category="liquidation-risk",
        target="hl-pm-liquidation",
        guarded_target="hl-pm-liquidation-guarded",
        invariant="pm-liquidation-only-past-threshold",
        hypothesis=(
            "Gating liquidation on the borrow LTV (0.65/0.50) instead of the "
            "documented threshold 0.5 + 0.5*LTV seizes collateral while the position "
            "is still solvent, harming a user who never crossed the liquidation bar."
        ),
        severity_if_broken="high",
        steps=(
            ChainStep("attacker", "borrow", {"amount": 2500 * 10**6}),
            ChainStep("attacker", "price_move", {"pct": 95}),
            ChainStep("attacker", "liquidate", {}),
        ),
    ),
    AttackChainSpec(
        chain_id="hl-outcome-merge-unmatched-shares",
        title="Merge unmatched Yes/No shares to mint quote that was never locked",
        category="rounding-precision",
        target="hl-outcome",
        guarded_target="hl-outcome-guarded",
        invariant="outcome-shares-collateralized",
        hypothesis=(
            "An outcome merge that clamps Yes and No independently refunds quote for "
            "shares the actor does not hold, breaking the 1:1 collateral backing of "
            "the Yes and No supplies and extracting value from the pool."
        ),
        severity_if_broken="critical",
        steps=(
            ChainStep("attacker", "split", {"amount": 100 * 10**6}),
            ChainStep("attacker", "transfer",
                      {"amount": 100 * 10**6, "to": "attacker2", "side": "yes"}),
            ChainStep("attacker", "merge", {"amount": 100 * 10**6}),
            ChainStep("attacker2", "merge", {"amount": 100 * 10**6}),
        ),
    ),
    AttackChainSpec(
        chain_id="hl-question-merge-no-set-overpay",
        title="Redeem a full No set for n quote when only n-1 is backed",
        category="accounting-manipulation",
        target="hl-question",
        guarded_target="hl-question-guarded",
        invariant="question-no-set-conserves",
        hypothesis=(
            "A question of n outcomes settles with exactly one Yes, so a full No set "
            "is worth n-1 quote. A negate/merge that pays n quote per No set mints "
            "quote the question never locked, extracting value from its collateral."
        ),
        severity_if_broken="critical",
        steps=(
            ChainStep("attacker", "split", {"q": 0, "outcome": 0, "amount": 100 * 10**6}),
            ChainStep("attacker", "split", {"q": 0, "outcome": 1, "amount": 100 * 10**6}),
            ChainStep("attacker", "split", {"q": 0, "outcome": 2, "amount": 100 * 10**6}),
            ChainStep("attacker", "merge_no_set", {"q": 0, "amount": 100 * 10**6}),
        ),
    ),
]

_BY_ID = {c.chain_id: c for c in _CHAINS}


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

@dataclass
class ChainRunResult:
    chain_id: str
    target: str
    broke: bool
    broken_invariants: list[str]
    targeted_invariant_broke: bool
    attacker_reachable: bool
    steps_executed: int
    observed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "broke": self.broke,
            "broken_invariants": self.broken_invariants,
            "targeted_invariant_broke": self.targeted_invariant_broke,
            "attacker_reachable": self.attacker_reachable,
            "steps_executed": self.steps_executed,
            "observed": self.observed,
        }


def _run_spec_on(spec: AttackChainSpec, target_name: str) -> ChainRunResult:
    target = make_target(target_name)
    steps = [s.to_attack_step(i, target_name) for i, s in enumerate(spec.steps)]
    result = run_sequence(target, steps)
    return ChainRunResult(
        chain_id=spec.chain_id,
        target=target_name,
        broke=bool(result.violated),
        broken_invariants=result.violated,
        targeted_invariant_broke=spec.invariant in result.violated,
        attacker_reachable=any(s.actor == "attacker" for s in steps),
        steps_executed=len(steps),
        observed=target.snapshot(result.state),
    )


def run_chain(chain_id: str) -> ChainRunResult:
    """Execute one chain against its vulnerable target and report the outcome."""
    spec = get_chain(chain_id)
    return _run_spec_on(spec, spec.target)


def run_chain_control(chain_id: str) -> ChainRunResult:
    """Execute the same chain against its guarded counterpart (non-vacuity control)."""
    spec = get_chain(chain_id)
    return _run_spec_on(spec, spec.guarded_target)


def verify_chain(chain_id: str) -> dict:
    """Run a chain and its control, and report whether the contrast holds.

    A chain is ``verified`` when it breaks the targeted invariant on the
    vulnerable model and does **not** break it on the guarded model.
    """
    spec = get_chain(chain_id)
    vulnerable = _run_spec_on(spec, spec.target)
    guarded = _run_spec_on(spec, spec.guarded_target)
    verified = vulnerable.targeted_invariant_broke and not guarded.broke
    return {
        "chain_id": chain_id,
        "hypothesis": spec.hypothesis,
        "invariant": spec.invariant,
        "vulnerable": vulnerable.to_dict(),
        "guarded": guarded.to_dict(),
        "verified": verified,
    }


def verify_all_chains() -> dict:
    results = [verify_chain(c.chain_id) for c in _CHAINS]
    passed = sum(1 for r in results if r["verified"])
    return {"chains": results, "passed": passed, "total": len(results)}


def get_chain(chain_id: str) -> AttackChainSpec:
    if chain_id not in _BY_ID:
        raise KeyError(
            f"unknown chain: {chain_id} (known: {', '.join(sorted(_BY_ID))})"
        )
    return _BY_ID[chain_id]


def all_chains() -> list[AttackChainSpec]:
    return list(_CHAINS)


def chains_for_target(target: str) -> list[AttackChainSpec]:
    return [c for c in _CHAINS if c.target == target or c.guarded_target == target]
