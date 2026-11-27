"""Bounty-program eligibility registry and gate (mission sections 5 and 7).

Selecting the *next* target is a decision, not a guess. This module turns the
mission's eligibility questions into an explicit, data-driven record so the same
evidence produces the same verdict every time, and so an unverifiable claim can
never be silently upgraded into "authorized".

It is deliberately separate from :mod:`blackheart.authz`:

  * ``authz``/``scope`` decide whether *active testing of one asset* may run.
  * ``eligibility`` decides whether a *whole program* is worth entering at all,
    and ranks the known candidates.

The two meet at :func:`to_authorization_record`, which refuses to emit a
``verified`` record unless the program was checked against captured scope text.

Nothing here fetches the network: the operator records what they actually read
(a brief URL, its SHA-256, the verbatim scope). A fact that could not be
established is stored as ``"unknown"`` and blocks viability -- it is never
assumed.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from .models import AuthorizationRecord

# A criterion fact may be True, False, or "unknown". Only True satisfies the gate.
Fact = Any  # bool | "unknown"

# The program-level questions that must be answered affirmatively before a
# program is eligible. Mirrors mission section 5 steps 2-9.
REQUIRED_FACTS = (
    "program_active",      # program is currently running
    "scope_verified",      # official scope captured verbatim, with a hash
    "safe_harbor",         # research is authorized / legal protection
    "zero_cost",           # participation needs no spend
    "nigerian_eligible",   # a Nigerian individual may participate
    "payout_feasible",     # a Nigerian individual can practically be paid
)

# Facts that are asserted True must cite at least one dated evidence item.
# `payout_feasible` is the case that matters: no bounty brief publishes a
# supported-countries list, so "a Nigerian individual can actually be paid" can
# only ever be established by a dated operator/support record -- never inferred
# from the brief. Requiring evidence stops this one entry-gating fact from being
# flipped to True on an assumption.
EVIDENCE_BACKED_FACTS = ("payout_feasible",)

# Ranks "how much can this plausibly be worth", for prioritising between two
# otherwise-eligible programs. Ordered by the advertised top reward.
_REWARD_ORDER = ["0", "<$1k", "$1k-$10k", "$10k-$100k", ">$100k"]


@dataclass
class ProgramEligibility:
    """Everything the mission's authorization gate needs about one program.

    ``nigerian_eligible`` / ``payout_feasible`` are tri-state on purpose
    (True / False / "unknown"): the honest answer is often "not documented", and
    that must read as *blocked*, not as *allowed*.
    """

    program: str
    platform: str
    brief_url: str
    scope_url: str = ""
    # Provenance of the brief the facts were read from.
    brief_retrieved_at: str = ""
    brief_sha256: str = ""
    scope_sha256: str = ""
    # Verbatim scope text as read from the official brief (auditable).
    scope_text: str = ""
    # Facts.
    program_active: Fact = "unknown"
    safe_harbor: Fact = "unknown"
    zero_cost: Fact = "unknown"
    nigerian_eligible: Fact = "unknown"
    payout_feasible: Fact = "unknown"
    poc_required: Fact = "unknown"
    idv_required: Fact = "unknown"
    # Free-form supporting detail (never a substitute for the facts above).
    eligibility_basis: str = ""
    payout_channels: list[str] = field(default_factory=list)
    max_reward: str = ""
    reward_tiers: dict[str, str] = field(default_factory=dict)
    exclusions: list[str] = field(default_factory=list)
    notes: str = ""
    # Asset -> AssetStatus value; the assets a campaign could actually attack.
    assets: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)

    def fact(self, name: str) -> Fact:
        if name == "scope_verified":
            return bool(self.scope_sha256 and self.scope_url and self.scope_text.strip())
        return getattr(self, name, "unknown")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ProgramEligibility":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class EligibilityVerdict:
    """The gate's answer for one program, with the reasoning attached."""

    program: str
    viable: bool
    checks: dict[str, bool]
    blockers: list[str] = field(default_factory=list)
    authorized_assets: list[str] = field(default_factory=list)
    rank: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(program: ProgramEligibility) -> EligibilityVerdict:
    """Apply the mission's eligibility gate. Fails closed on any non-True fact."""
    checks: dict[str, bool] = {}
    blockers: list[str] = []
    for name in REQUIRED_FACTS:
        value = program.fact(name)
        ok = value is True
        if ok and name in EVIDENCE_BACKED_FACTS and not program.evidence:
            # An asserted-True fact with no evidence is treated as unproven.
            # Fail closed rather than trust the claim.
            ok = False
            blockers.append(f"{name}=True requires dated evidence (mission rule 10)")
        checks[name] = ok
        if not ok and value is not True:
            blockers.append(f"{name}={value!r} (must be True)")

    authorized = [
        asset for asset, status in program.assets.items() if status == "AUTHORIZED"
    ]
    if not authorized:
        blockers.append("no asset is classified AUTHORIZED")

    return EligibilityVerdict(
        program=program.program,
        viable=not blockers,
        checks=checks,
        blockers=blockers,
        authorized_assets=sorted(authorized),
        rank=_reward_rank(program.max_reward),
    )


def _reward_rank(max_reward: str) -> int:
    return _REWARD_ORDER.index(max_reward) if max_reward in _REWARD_ORDER else 0


def rank_programs(programs: list[ProgramEligibility]) -> list[EligibilityVerdict]:
    """Evaluate every program and return them best-first.

    Viable programs come first; among equals, a higher advertised top reward
    wins. A non-viable program is never ranked above a viable one, however large
    its reward chart.
    """
    verdicts = [evaluate(p) for p in programs]
    return sorted(verdicts, key=lambda v: (v.viable, v.rank), reverse=True)


def to_authorization_record(program: ProgramEligibility) -> AuthorizationRecord:
    """Bridge an eligible program into the active-testing authorization gate.

    Refuses (via :class:`ScopeError` in ``scope.record_authorization``) unless the
    scope was captured verbatim -- this function does not weaken that rule, it
    only supplies the structured record. Callers still pass the result through
    :func:`blackheart.scope.record_authorization`.
    """
    verdict = evaluate(program)
    rec = AuthorizationRecord(
        program=program.program,
        platform=program.platform,
        target_url=program.brief_url,
        scope_url=program.scope_url or program.brief_url,
        program_active=_as_bool(program.program_active),
        safe_harbor=_as_bool(program.safe_harbor),
        poc_required=_as_bool(program.poc_required),
        nigerian_eligible=_as_bool(program.nigerian_eligible),
        payout_feasible=_as_bool(program.payout_feasible),
        zero_cost=_as_bool(program.zero_cost),
        asset_classes=dict(program.assets),
        retrieved_scope={
            "source_url": program.scope_url or program.brief_url,
            "retrieved_at": program.brief_retrieved_at,
            "sha256": program.scope_sha256 or program.brief_sha256,
            "text": program.scope_text,
        },
        evidence=list(program.evidence),
        notes=program.notes,
        verified=verdict.viable,
    )
    return rec


def _as_bool(value: Fact) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def load_program(path: str | Path) -> ProgramEligibility:
    return ProgramEligibility.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def load_programs(path: str | Path) -> list[ProgramEligibility]:
    """Load a registry file: either one program object or ``{"programs": [...]}``."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data["programs"] if isinstance(data, dict) and "programs" in data else data
    if isinstance(items, dict):
        items = [items]
    return [ProgramEligibility.from_dict(d) for d in items]
