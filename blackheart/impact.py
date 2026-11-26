"""Pre-surface impact triage: is this even a security issue before anyone reviews it?

A lead is not a finding, and a *difference* is not a vulnerability. This gate sits
in front of promotion and surfacing and refuses the false-positive classes that
have no attacker outcome:

* an **unexecutable surface** (off-chain API, HTTP response, config, docs) is a
  lead, never a finding -- the engine can only prove what it can run;
* a **name collision** (``marginTable`` vs ``notionalMarginTable``) is two
  different identifiers, not a contradiction;
* an **impact claim** that names no unprivileged-attacker outcome (receive more /
  bypass a restriction / absorb a loss), or shows no value movement or restriction
  bypass, is informational.

It fails closed: anything it cannot show qualifies is ``INFORMATIONAL`` or
``LEAD_ONLY``, never ``SURFACE``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .mindset import OUTCOMES

EXECUTABLE_SURFACES = frozenset({
    "contract", "smart-contract", "smartcontract", "on-chain", "onchain", "evm",
    "state-machine", "statemachine", "solidity", "bytecode", "runtime", "chain",
})

NON_EXECUTABLE_SURFACES = frozenset({
    "off-chain", "offchain", "api", "http", "https", "endpoint", "response", "json",
    "frontend", "backend", "ui", "rpc", "rpc-response", "rest", "graphql",
    "documentation", "docs", "config", "reference", "table",
})

_DIFFERENCE_MARKERS = ("differ", "mismatch", "inconsisten", "does not match",
                       "doesn't match", "not match", "contradict", " vs ", " versus ",
                       "!=", "discrepan")

_VALUE_MOVEMENT = (
    "transfer", "balance", "funds", "withdraw", "deposit", "mint", "burn", "steal",
    "drain", "inflate", "double-count", "double count", "more assets",
    "more than entitled", "payout", "reward", "fee", "liquidat", "collateral",
    "reserve", "supply", "share", "token", "asset", "price", "profit", "gain",
)
_RESTRICTION_BYPASS = (
    "bypass", "restriction", "require", "access control", "access-control",
    "authorization", "authoriz", "onlyowner", "only owner", "role", "permission",
    "allowance", "whitelist", "blacklist", "freeze", "pause", "lock", "guard", "admin",
)
_OUTCOME_RECEIVE = ("receive more", "more assets", "more than entitled", "steal",
                    "drain", "inflate", "double-count", "withdraw more", "over-mint",
                    "mint more", "profit", "gain assets")
_OUTCOME_BYPASS = ("bypass", "circumvent", "evade", "access control",
                   "authorization", "restriction", "onlyowner")
_OUTCOME_ABSORB = ("absorb", "another user", "another's", "socializ", "shift loss",
                   "victim", "other users")

_CAMEL = re.compile(r"[a-z]+(?:[A-Z][a-z0-9]+)+|[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+")


@dataclass
class TriageResult:
    disposition: str            # SURFACE | INFORMATIONAL | LEAD_ONLY
    outcome: str = ""
    reasons: list[str] = field(default_factory=list)

    @property
    def qualifies(self) -> bool:
        return self.disposition == "SURFACE"

    def as_dict(self) -> dict:
        return {"disposition": self.disposition, "outcome": self.outcome,
                "qualifies": self.qualifies, "reasons": list(self.reasons),
                "note": "SURFACE means the claim names an attacker outcome and an "
                        "executable surface; it is still not a finding"}


def _normalize_surface(surface: str) -> str:
    return (surface or "").strip().lower().replace("_", "-").replace(" ", "-")


def _outcome_of(text: str) -> str:
    low = (text or "").lower()
    if any(k in low for k in _OUTCOME_BYPASS):
        return OUTCOMES[1]
    if any(k in low for k in _OUTCOME_ABSORB):
        return OUTCOMES[2]
    if any(k in low for k in _OUTCOME_RECEIVE):
        return OUTCOMES[0]
    return ""


def outcome_for_invariant(invariants) -> str:
    """Map derived invariants to an attacker outcome (authorization -> bypass, etc.)."""
    names = [str(i) for i in (invariants or [])]
    if any(n.startswith("authorization:") for n in names):
        return OUTCOMES[1]
    if any(n.startswith("conservation:") for n in names):
        return OUTCOMES[0]
    return ""


def _identifiers_in_text(text: str) -> list[str]:
    return list(dict.fromkeys(_CAMEL.findall(text or "")))


def _is_name_collision(a: str, b: str) -> bool:
    la, lb = a.lower(), b.lower()
    if la == lb or len(la) < 4 or len(lb) < 4:
        return False
    shorter, longer = (la, lb) if len(la) <= len(lb) else (lb, la)
    return longer.endswith(shorter)


def _find_name_collision(identifiers, text: str) -> tuple[str, str] | None:
    ids = list(identifiers or [])
    explicit = bool(ids)
    if not ids:
        ids = _identifiers_in_text(text)
    if len(ids) < 2:
        return None
    if not explicit and not any(m in (text or "").lower() for m in _DIFFERENCE_MARKERS):
        return None
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            if _is_name_collision(ids[i], ids[j]):
                return ids[i], ids[j]
    return None


def _has_value_movement(text: str) -> bool:
    low = (text or "").lower()
    return any(k in low for k in _VALUE_MOVEMENT)


def _has_restriction_bypass(text: str) -> bool:
    low = (text or "").lower()
    return any(k in low for k in _RESTRICTION_BYPASS)


def triage(*, impact: str = "", surface: str = "contract", identifiers=(),
           outcome: str = "", value_movement: bool | None = None,
           restriction_bypass: bool | None = None,
           require_value_movement: bool = True) -> TriageResult:
    """Decide whether a claim may be surfaced, or is informational / a lead only."""
    norm = _normalize_surface(surface)
    if norm not in EXECUTABLE_SURFACES:
        return TriageResult("LEAD_ONLY", outcome, [
            f"surface {surface!r} has no executable model; a lead, not a finding"])
    collision = _find_name_collision(identifiers, impact)
    if collision:
        return TriageResult("INFORMATIONAL", outcome, [
            f"{collision[0]!r} and {collision[1]!r} denote different things "
            "(name collision), not a contradiction"])
    resolved = outcome or _outcome_of(impact)
    if not resolved:
        return TriageResult("INFORMATIONAL", "", [
            "no unprivileged-attacker outcome (receive more / bypass a restriction "
            "/ absorb a loss)"])
    if require_value_movement:
        has_value = value_movement is True or _has_value_movement(impact)
        has_bypass = (restriction_bypass is True or _has_restriction_bypass(impact)
                      or resolved == OUTCOMES[1])
        if not (has_value or has_bypass):
            return TriageResult("INFORMATIONAL", resolved, [
                "no value movement or restriction bypass; the outcome is asserted, "
                "not shown"])
    return TriageResult("SURFACE", resolved, [])


__all__ = ["TriageResult", "triage", "outcome_for_invariant",
           "EXECUTABLE_SURFACES", "NON_EXECUTABLE_SURFACES"]
