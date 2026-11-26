"""The ranked capability upgrades, implemented as composable, tested steps.

Each entry in :data:`IMPROVEMENTS` maps one item from the ranked roadmap to code
that exists in this repository. ``installed`` means the capability was already
present and is now named with its acceptance command; ``added`` means this
package adds the missing composition. Nothing here claims a full solution: a
``partial`` entry carries the exact limitation it still has.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Improvement:
    key: str
    title: str
    status: str
    implemented_by: tuple[str, ...]
    limitation: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "status": self.status,
            "implemented_by": list(self.implemented_by),
            "limitation": self.limitation,
        }


IMPROVEMENTS: tuple[Improvement, ...] = (
    Improvement(
        "compiler-execution", "Compiler-grade execution layer", "added",
        ("blackheart/improve/execution.py", "blackheart/ingest/compile.py",
         "blackheart/pocgen.py"),
        "Compiles and models a project; a witness still needs a renderable "
        "invariant and a Foundry-compatible source tree.",
    ),
    Improvement(
        "model-coverage", "Full-language model synthesis", "partial",
        ("blackheart/improve/model_coverage.py", "blackheart/ingest/synthesize.py"),
        "Reports every statement the interpreter cannot model; it does not "
        "silently guess the missing semantics.",
    ),
    Improvement(
        "closed-source", "Closed-source analysis path", "added",
        ("blackheart/improve/closed.py", "blackheart/ingest/decompiled.py",
         "blackheart/bytecode.py"),
        "Recovers a decompiled surface and replays a concrete witness; a closed "
        "body's source semantics remain unavailable.",
    ),
    Improvement(
        "invariant-discovery", "Invariant discovery", "added",
        ("blackheart/improve/invariants.py", "blackheart/solidity/extract.py"),
        "Candidates are heuristics with provenance and confidence, never claims.",
    ),
    Improvement(
        "market-simulation", "Live adversarial market simulation", "added",
        ("blackheart/improve/competition.py", "blackheart/value/orderflow.py"),
        "Latency and declared competitors are modelled; builder policy, private "
        "order flow and bundle merging are not.",
    ),
    Improvement(
        "crosschain-oracle", "Cross-chain and oracle modelling", "added",
        ("blackheart/improve/crosschain.py",),
        "Deterministic replay/authentication and staleness/deviation models; it "
        "does not read live bridge or oracle state.",
    ),
    Improvement(
        "policy-payout", "Policy-to-payout automation", "added",
        ("blackheart/improve/bounty_package.py", "blackheart/bounty",
         "blackheart/program_intel"),
        "Builds a submission package and cites the policy; it never submits.",
    ),
    Improvement(
        "independent-review", "Stronger independent review", "added",
        ("blackheart/improve/review_gate.py", "blackheart/providers/router.py"),
        "Fails closed when the reviewer is configured but unverified, or serves "
        "the same model.",
    ),
    Improvement(
        "scale-triage", "Scale and triage", "added",
        ("blackheart/improve/scale.py", "blackheart/parallel.py"),
        "Parallel ingestion and deterministic ranking; large repositories still "
        "need memory and a depth budget.",
    ),
    Improvement(
        "continuous-operation", "Continuous operation", "added",
        ("blackheart/improve/continuous.py", "blackheart/watch",
         "blackheart/triggers", "blackheart/scheduler"),
        "Composes a watch cycle with an explicit enqueue callback; it does not "
        "invent an engine verdict for a lead.",
    ),
)


def status() -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in IMPROVEMENTS:
        counts[item.status] = counts.get(item.status, 0) + 1
    return {
        "improvements": [item.to_dict() for item in IMPROVEMENTS],
        "counts": counts,
        "note": "status is evidence-based: installed means the module and its "
                "acceptance test exist, added means this package supplies the "
                "composition, partial names the remaining gap.",
    }


def render() -> str:
    lines = ["# Capability upgrades", ""]
    for item in IMPROVEMENTS:
        lines.append(f"- {item.key} [{item.status}] {item.title}")
        lines.append(f"  implemented by: {', '.join(item.implemented_by)}")
        lines.append(f"  limit: {item.limitation}")
    return "\n".join(lines)


__all__ = ["Improvement", "IMPROVEMENTS", "status", "render"]
