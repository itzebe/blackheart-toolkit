"""Turn external-tool leads into grounded hypotheses -- a lead, never a finding.

A scanner result (SARIF/JSON/text from ``blackheart external``) is a *candidate*,
exactly like a lexer flag or an LLM proposal. This module promotes a lead to a
``Hypothesis``-shaped dict only when it clears three honest gates:

1. **It answers the question.** The rule/message must map to one of the three
   attacker outcomes (``mindset.OUTCOMES``) via a lever from ``mindset.LEVERS``.
   A lead that names no unprivileged-attacker outcome is refused with its reason.
2. **It is grounded.** The component must be declared (``--component``) or the
   file stem, and -- when a ``ThreatModel`` is supplied -- must appear in its
   ``architecture``. An ungrounded component is refused.
3. **It is not a finding.** The promoted dict carries ``status: HYPOTHESIS`` and
   ``is_finding: False``. Certification and independent verification remain the
   only path to a finding.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from ..impact import triage
from ..mindset import LEVERS, OUTCOMES

#: (keywords, category, outcome, levers). Order matters: the first match wins.
_RULES: tuple[tuple[tuple[str, ...], str, str, tuple[str, ...]], ...] = (
    (("access-control", "authorization", "authorize", "onlyowner", "unprotected",
      "missing-auth", "privilege", "unrestricted"), "authorization", OUTCOMES[1],
     (LEVERS[1], LEVERS[3])),
    (("reentran", "re-entran", "external-call", "cross-function"), "reentrancy",
     OUTCOMES[0], (LEVERS[0],)),
    (("overflow", "underflow", "arithmetic", "rounding", "precision"), "arithmetic",
     OUTCOMES[0], (LEVERS[1],)),
    (("oracle", "price-manipulation", "slippage", "spot-price"), "oracle-manipulation",
     OUTCOMES[0], (LEVERS[4],)),
    (("unchecked", "low-level", "return-value", "ignored-return", "unchecked-call"),
     "unchecked-return", OUTCOMES[0], (LEVERS[1],)),
    (("delegatecall", "selfdestruct", "arbitrary-call"), "dangerous-delegatecall",
     OUTCOMES[1], (LEVERS[1],)),
    (("randomness", "timestamp", "block-number", "weak-random", "predictable"),
     "weak-randomness", OUTCOMES[0], (LEVERS[2],)),
    (("denial", "dos", "gas-limit", "unbounded-loop", "grief"), "denial-of-service",
     OUTCOMES[2], (LEVERS[1],)),
)


@dataclass(frozen=True)
class LeadPromotion:
    """Promoted hypotheses and the reason each refused lead stayed a lead."""

    promoted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    tool: str = ""

    @property
    def promoted_count(self) -> int:
        return len(self.promoted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "promoted": list(self.promoted),
            "promoted_count": self.promoted_count,
            "rejected": list(self.rejected),
            "rejected_count": self.rejected_count,
            "note": "promoted entries are hypotheses (candidates), not findings",
        }


def classify_lead(lead: dict) -> Optional[tuple[str, str, tuple[str, ...]]]:
    """Map a lead's rule+message to (category, outcome, levers), or None."""
    text = f"{lead.get('rule', '')} {lead.get('message', '')}".lower()
    for keys, category, outcome, levers in _RULES:
        if any(key in text for key in keys):
            return category, outcome, tuple(levers)
    return None


def _stem(path: str) -> str:
    """The contract/component name a file path implies (``a/b/C.sol`` -> ``C``)."""
    base = str(path or "").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0] if "." in base else base


def _ground(component: str, threat_model: Any) -> tuple[bool, str]:
    if not component:
        return False, "no component to ground the lead to (pass --component or give a path)"
    if threat_model is None:
        return True, "grounded by declaration"
    architecture = [a for a in getattr(threat_model, "architecture", []) or [] if a]
    if not architecture:
        return True, "grounded by declaration (the threat model declares no architecture)"
    low = component.lower()
    if any(a.lower() in low or low in a.lower() for a in architecture):
        return True, "grounded in the threat model's architecture"
    return False, (f"ungrounded: component {component!r} is not in the threat "
                   f"model's architecture")


_OFFCHAIN = re.compile(
    r"\b(api|http|https|endpoint|json|rpc|graphql|off-?chain|response|frontend|"
    r"backend|documentation|config)\b|/info\b")


def _lead_surface(lead: dict) -> str:
    """A lead about an off-chain surface (API/HTTP/config) is a lead, never a finding."""
    text = f"{lead.get('rule', '')} {lead.get('message', '')} {lead.get('path', '')}".lower()
    return "off-chain" if _OFFCHAIN.search(text) else "contract"


def lead_to_hypothesis(lead: dict, *, tool: str = "", component: str = "",
                       threat_model: Any = None) -> tuple[Optional[dict], str]:
    """Promote one lead to a hypothesis dict, or return (None, reason)."""
    if not isinstance(lead, dict):
        return None, "lead is not a mapping"
    classified = classify_lead(lead)
    if classified is None:
        return None, "no unprivileged-attacker outcome in the lead (not one of ours)"
    category, outcome, levers = classified
    verdict = triage(impact=f"{lead.get('rule', '')} {lead.get('message', '')}",
                     surface=_lead_surface(lead), outcome=outcome,
                     require_value_movement=False)
    if not verdict.qualifies:
        return None, f"refused by impact triage: {verdict.reasons[0]}"
    comp = component or _stem(lead.get("path", ""))
    grounded, why = _ground(comp, threat_model)
    if not grounded:
        return None, why
    rule = str(lead.get("rule", ""))
    path = str(lead.get("path", ""))
    line = lead.get("line", 0)
    message = str(lead.get("message", ""))
    hyp_id = "ext-" + hashlib.sha256(
        f"{tool}|{rule}|{path}|{line}".encode()).hexdigest()[:12]
    title = f"[{tool or 'external'}] {rule or category} at {path}:{line}".strip()
    return {
        "hyp_id": hyp_id,
        "objective_id": f"external:{category}",
        "title": title,
        "category": category,
        "hypothesis": f"{outcome} via {', '.join(levers)} -- {message}".strip(),
        "invariant": message,
        "attacker_outcome": outcome,
        "attacker_levers": list(levers),
        "component": comp,
        "entry_point": "",
        "expected_impact": outcome,
        "rationale": ("promoted from a scanner lead (" + why +
                      "); still needs certification and independent verification"),
        "recommended_tools": [tool] if tool else [],
        "source": {"tool": tool, "rule": rule, "path": path, "line": line},
        "status": "HYPOTHESIS",
        "is_finding": False,
    }, "promoted"


def leads_to_hypotheses(source: Any, *, component: str = "",
                        threat_model: Any = None) -> LeadPromotion:
    """Promote every lead in an ``ExternalOutcome`` (or a plain list) to a hypothesis."""
    if hasattr(source, "leads"):
        leads = list(getattr(source, "leads", []) or [])
        tool = getattr(source, "tool", "") or ""
    else:
        leads = list(source or [])
        tool = ""
    promoted: list[dict] = []
    rejected: list[dict] = []
    seen: set[str] = set()
    for lead in leads:
        hyp, reason = lead_to_hypothesis(lead, tool=tool, component=component,
                                         threat_model=threat_model)
        if hyp is None:
            rejected.append({"lead": lead, "reason": reason})
            continue
        if hyp["hyp_id"] in seen:
            rejected.append({"lead": lead, "reason": "duplicate hypothesis"})
            continue
        seen.add(hyp["hyp_id"])
        promoted.append(hyp)
    return LeadPromotion(promoted=promoted, rejected=rejected, tool=tool)


__all__ = [
    "LeadPromotion", "classify_lead", "lead_to_hypothesis",
    "leads_to_hypotheses",
]
