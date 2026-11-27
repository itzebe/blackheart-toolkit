"""Who is attacking: the capability set that decides which campaigns exist.

A profile is deliberately small. It records only the things that change what an
attacker can attempt -- what it can afford, whether it can hold a position, what
it can reach outside the protocol, and how long it will wait -- so a plan can be
derived from it instead of asserted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Tier(str, Enum):
    """How much of a campaign the actor can sustain."""

    OPPORTUNIST = "opportunist"     # one transaction, flash capital, no role
    ORGANIZED = "organized"         # funded across blocks, weeks of dwell
    STATE_GRADE = "state-grade"     # months of dwell, infrastructure, non-market reach


class Capability(str, Enum):
    """A concrete thing the actor can do. Each one unlocks stages, and only those."""

    FLASH_CAPITAL = "flash-capital"            # atomic borrow, repaid in the same tx
    SUSTAINED_CAPITAL = "sustained-capital"    # held across blocks, days or epochs
    PRIVILEGED_ROLE = "privileged-role"        # admin, owner, operator, guardian
    INSIDER_ACCESS = "insider-access"          # off-chain knowledge or credentials
    VALIDATOR_CONTROL = "validator-control"    # reorder, censor, or time a block
    SUPPLY_CHAIN = "supply-chain"              # a dependency, build, or deployment
    LONG_DWELL = "long-dwell"                  # stay in position for months
    SOCIAL_ENGINEERING = "social-engineering"  # a human, not a contract


#: Capabilities no local engine may exercise, whatever the profile holds. They are
#: modelled (so a plan can reason about them) and never executed.
MODEL_ONLY_CAPABILITIES: frozenset[Capability] = frozenset({
    Capability.INSIDER_ACCESS,
    Capability.VALIDATOR_CONTROL,
    Capability.SUPPLY_CHAIN,
    Capability.SOCIAL_ENGINEERING,
})


@dataclass(frozen=True)
class AdversaryProfile:
    """A named capability set, its budget, and its patience."""

    name: str
    tier: Tier
    capabilities: frozenset[Capability]
    dwell_days: int
    capital_units: int
    opsec: str
    summary: str

    def can(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "tier": self.tier.value,
            "capabilities": sorted(c.value for c in self.capabilities),
            "dwell_days": self.dwell_days,
            "capital_units": self.capital_units,
            "opsec": self.opsec,
            "summary": self.summary,
        }


#: The unprivileged attacker the mindset asks the question from: one transaction,
#: borrowed capital, no role, no waiting.
OPPORTUNIST = AdversaryProfile(
    name="opportunist",
    tier=Tier.OPPORTUNIST,
    capabilities=frozenset({Capability.FLASH_CAPITAL}),
    dwell_days=0,
    capital_units=0,
    opsec="low",
    summary="unprivileged, one transaction, flash capital, cannot wait or hold a role",
)

#: A funded actor: it can lock capital across blocks, wait for a favourable state,
#: and repeat an extraction that works.
ORGANIZED = AdversaryProfile(
    name="organized",
    tier=Tier.ORGANIZED,
    capabilities=frozenset({
        Capability.FLASH_CAPITAL,
        Capability.SUSTAINED_CAPITAL,
    }),
    dwell_days=30,
    capital_units=10_000_000,
    opsec="medium",
    summary="funded, can hold a position for weeks, repeatable extraction",
)

#: The well-resourced actor: everything above, plus months of dwell and reach
#: outside the market (infrastructure, dependencies, people, block ordering).
STATE_GRADE = AdversaryProfile(
    name="state-grade",
    tier=Tier.STATE_GRADE,
    capabilities=frozenset({
        Capability.FLASH_CAPITAL,
        Capability.SUSTAINED_CAPITAL,
        Capability.LONG_DWELL,
        Capability.INSIDER_ACCESS,
        Capability.VALIDATOR_CONTROL,
        Capability.SUPPLY_CHAIN,
        Capability.SOCIAL_ENGINEERING,
    }),
    dwell_days=180,
    capital_units=1_000_000_000,
    opsec="high",
    summary="months of dwell, non-market reach, accepts a loss to reach a larger one",
)

PROFILES: dict[str, AdversaryProfile] = {
    p.name: p for p in (OPPORTUNIST, ORGANIZED, STATE_GRADE)
}


def profile(name: str) -> AdversaryProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(
            f"unknown adversary profile '{name}'; choose one of "
            f"{', '.join(sorted(PROFILES))}"
        ) from exc
