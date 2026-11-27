"""Adversary emulation: capability, capital, patience and objective.

The engine's searches answer *what is reachable*. They do not answer *who would
bother, what would it cost them, how long would they wait, and what do they take
first*. A stateless scanner cannot answer that either, because every answer
depends on an adversary, and an adversary is a set of constraints.

What changes a campaign is not nationality. It is **capability** (what the actor
can bring to bear), **capital** (what it can afford to lose or lock up),
**patience** (how long it can hold a position) and **objective** (what it is
actually trying to take). Those four variables separate the unprivileged attacker
:data:`blackheart.mindset.ATTACKER_QUESTION` is asked from -- one transaction, no
role, no waiting -- from a well-resourced actor that can fund a position for
months, run infrastructure, and accept a loss to reach a larger one.

Two rules keep this honest:

* **Modelling a capability is not authorising it.** A stage that needs a
  capability no local engine may exercise (validator control, supply-chain reach,
  insider access, social engineering) is ``MODEL_ONLY``: it is described so the
  operator can reason about it, and it is never executed.
* **Thinking is free; execution is gated.** A plan can always be produced. A
  stage is ``executable`` only when the asset passes the authorization gate, so
  an unauthorised plan is a hypothesis about an adversary, not a licence.
"""

from .campaign import (
    STAGE_ORDER,
    CampaignPlan,
    Stage,
    plan_campaign,
    scanner_contrast,
)
from .profiles import (
    PROFILES,
    AdversaryProfile,
    Capability,
    Tier,
    profile,
)

__all__ = [
    "PROFILES",
    "STAGE_ORDER",
    "AdversaryProfile",
    "CampaignPlan",
    "Capability",
    "Stage",
    "Tier",
    "plan_campaign",
    "profile",
    "scanner_contrast",
]
