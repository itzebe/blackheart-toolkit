"""Independent analytical roles for the multi-model layer (mission B2).

The mission is explicit: do **not** ask several models the same question and treat
agreement as proof. Each role below asks a *different* question and has a
*different* system prompt, so the roles can genuinely disagree. A
:class:`RoleResult` preserves that disagreement verbatim.

The seven roles, in pipeline order:

  1. ``planner``          -- turns a target/threat model into a research plan.
  2. ``hypothesis``       -- proposes falsifiable technical hypotheses.
  3. ``code_analyst``     -- independently analyses the code path for/against a
                             hypothesis.
  4. ``adversarial``      -- tries to *disprove* the hypothesis.
  5. ``exploit_dev``      -- proposes a minimal reproduction / PoC.
  6. ``reproduction``     -- independently judges whether a reproduction proves
                             the claim.
  7. ``report_quality``   -- judges whether the evidence supports the report.

Consensus is recorded, never obeyed: :func:`summarise` reports agreement and
disagreement, and states plainly that agreement is **not** confirmation. Only a
deterministic reproduction (the P3 engine + verifier) can confirm a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..doctrine import doctrine_prompt_block
from ..mindset import prompt_block
from .adapters import ModelResponse


@dataclass(frozen=True)
class Role:
    name: str
    title: str
    system: str
    schema: dict
    purpose: str


_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "category": {"type": "string"},
                    "component": {"type": "string"},
                    "invariant": {"type": "string"},
                    "attack_strategy": {"type": "string"},
                    "expected_impact": {"type": "string"},
                    "falsification_criteria": {"type": "string"},
                    "confidence": {"type": "string",
                                   "enum": ["low", "medium", "high"]},
                },
                "required": ["title", "invariant", "falsification_criteria"],
            },
        }
    },
    "required": ["hypotheses"],
}

_JUDGEMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["supports", "disputes", "inconclusive"]},
        "reasoning": {"type": "string"},
        "evidence_required": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["verdict", "reasoning"],
}


ROLES: dict[str, Role] = {
    "planner": Role(
        name="planner",
        title="Research planner",
        purpose="Turn a target and threat model into a bounded, ordered research plan.",
        system=(
            "You are a security research planner. Given a target and a threat "
            "model, produce a short, ordered plan of research steps. Name the "
            "trust boundaries and the assets worth attacking. Do not propose "
            "active testing; propose reading, modelling, and local reproduction "
            "only. Be concrete and falsifiable. Return JSON."
        ),
        schema={"type": "object", "properties": {
            "steps": {"type": "array", "items": {"type": "string"}},
            "trust_boundaries": {"type": "array", "items": {"type": "string"}},
            "priority_assets": {"type": "array", "items": {"type": "string"}},
        }, "required": ["steps"]},
    ),
    "hypothesis": Role(
        name="hypothesis",
        title="Technical hypothesis generator",
        purpose="Propose specific, falsifiable vulnerability hypotheses.",
        system=(
            "You are a vulnerability hypothesis generator. Propose specific, "
            "falsifiable technical hypotheses about the given code or design. "
            "Each hypothesis must name the security invariant it would violate "
            "and the observation that would falsify it. Prefer a small number of "
            "sharp hypotheses over a long list. Do not assert a vulnerability "
            "exists; propose what to test. Return JSON."
        ),
        schema=_HYPOTHESIS_SCHEMA,
    ),
    "code_analyst": Role(
        name="code_analyst",
        title="Independent code analyst",
        purpose="Independently analyse the code path for or against a hypothesis.",
        system=(
            "You are an independent code analyst. Given a hypothesis and a code "
            "path, analyse the code strictly on its own terms. State whether the "
            "code supports the hypothesis, disputes it, or is inconclusive, and "
            "quote the specific functions/conditions that decide it. Do not "
            "assume the hypothesis is true. Return JSON."
        ),
        schema=_JUDGEMENT_SCHEMA,
    ),
    "adversarial": Role(
        name="adversarial",
        title="Adversarial reviewer",
        purpose="Attempt to disprove the hypothesis or show it is not exploitable.",
        system=(
            "You are an adversarial reviewer whose job is to DISPROVE the claim. "
            "Find the precondition that fails, the guard that blocks it, the "
            "reason the impact does not follow, or the benign explanation. If you "
            "cannot disprove it, say what evidence would still be required. "
            "Return JSON."
        ),
        schema=_JUDGEMENT_SCHEMA,
    ),
    "exploit_dev": Role(
        name="exploit_dev",
        title="Exploit-development assistant",
        purpose="Propose a minimal, deterministic reproduction (local only).",
        system=(
            "You are an exploit-development assistant. Propose the MINIMAL "
            "deterministic reproduction for a hypothesis: the exact setup, the "
            "single operation that triggers it, and the observable result. It "
            "must run locally and must not target a live system. State the "
            "preconditions explicitly. Return JSON."
        ),
        schema={"type": "object", "properties": {
            "repro_steps": {"type": "array", "items": {"type": "string"}},
            "preconditions": {"type": "array", "items": {"type": "string"}},
            "expected_observation": {"type": "string"},
            "minimal_poc_sketch": {"type": "string"},
        }, "required": ["repro_steps", "expected_observation"]},
    ),
    "reproduction": Role(
        name="reproduction",
        title="Independent reproduction reviewer",
        purpose="Judge whether a reproduction actually proves the claim.",
        system=(
            "You are an independent reproduction reviewer. Given a claim and the "
            "raw output of a reproduction attempt, judge whether the output "
            "actually demonstrates the claimed behaviour. Distinguish a genuine "
            "violation from a crash, an environmental error, a self-DoS, or a "
            "coincidence. Be strict. Return JSON."
        ),
        schema=_JUDGEMENT_SCHEMA,
    ),
    "report_quality": Role(
        name="report_quality",
        title="Evidence and report-quality reviewer",
        purpose="Judge whether the evidence supports a submission-quality report.",
        system=(
            "You are an evidence and report-quality reviewer. Given a finding and "
            "its evidence, judge whether the evidence is complete and supports the "
            "claimed impact, or what is missing. Check: exact affected asset, "
            "root cause, deterministic reproduction, demonstrated impact, and "
            "novelty. Return JSON."
        ),
        schema={"type": "object", "properties": {
            "verdict": {"type": "string",
                        "enum": ["ready", "needs_more_evidence", "reject"]},
            "missing": {"type": "array", "items": {"type": "string"}},
            "reasoning": {"type": "string"},
        }, "required": ["verdict", "reasoning"]},
    ),
}


# Every role holds the attacker question (BLACKHEART's mindset) and the
# operational doctrine. Both are prepended to each role's own instructions so
# they are never restated -- and cannot drift -- across the pipeline. The prompts
# stay distinct because each role appends a different question of its own. The
# guard makes this idempotent, so re-importing the module cannot prepend the
# block twice. The persona still leads, so a role prompt always starts with it.
_LENS = prompt_block() + " " + doctrine_prompt_block()
for _role in ROLES.values():
    if not _role.system.startswith(_LENS):
        object.__setattr__(_role, "system", _LENS + " " + _role.system)


@dataclass
class RoleResult:
    """One role's answer, with provenance and honest success state."""

    role: str
    provider: str
    model: str
    ok: bool
    data_class: str
    text: str = ""
    structured: Optional[dict] = None
    error: str = ""
    simulated: bool = False
    latency_ms: float = 0.0
    redacted: bool = False

    def to_dict(self) -> dict:
        return {
            "role": self.role, "provider": self.provider, "model": self.model,
            "ok": self.ok, "data_class": self.data_class, "text": self.text,
            "structured": self.structured, "error": self.error,
            "simulated": self.simulated, "latency_ms": round(self.latency_ms, 1),
            "redacted": self.redacted,
        }

    @classmethod
    def from_response(cls, role: str, resp: ModelResponse, data_class: str,
                      redacted: bool = False) -> "RoleResult":
        return cls(role=role, provider=resp.provider, model=resp.model, ok=resp.ok,
                   data_class=data_class, text=resp.text,
                   structured=resp.structured, error=resp.error,
                   simulated=resp.simulated, latency_ms=resp.latency_ms,
                   redacted=redacted)


def summarise(results: list[RoleResult]) -> dict:
    """Aggregate role results WITHOUT treating agreement as confirmation.

    Returns the verdicts by role, the agreement/disagreement, and an explicit
    reminder that this is advisory. ``disagreements`` is non-empty whenever the
    judgement roles (code_analyst, adversarial, reproduction) do not agree -- and
    that disagreement is preserved, not averaged away.
    """
    judgements = [r for r in results
                  if r.role in ("code_analyst", "adversarial", "reproduction")]
    verdicts = {}
    for r in judgements:
        if r.ok and isinstance(r.structured, dict):
            verdicts[r.role] = r.structured.get("verdict", "unknown")
        else:
            verdicts[r.role] = "unavailable"
    distinct = {v for v in verdicts.values() if v not in ("unknown", "unavailable")}
    disagreements = []
    if "supports" in distinct and "disputes" in distinct:
        disagreements.append(
            "at least one role supports the claim while another disputes it; the "
            "disagreement is preserved and neither is privileged"
        )
    any_simulated = any(r.simulated for r in results)
    return {
        "role_verdicts": verdicts,
        "disagreements": disagreements,
        "any_simulated": any_simulated,
        "advisory_only": True,
        "note": (
            "AI role outputs are advisory. Agreement between roles is NOT "
            "confirmation of a vulnerability; only deterministic reproduction, "
            "verified impact, and applicable authorization can confirm a finding."
        ),
    }
