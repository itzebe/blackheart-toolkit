"""Mempool ordering simulation -- front-run, back-run and sandwich as search.

Every other engine in BLACKHEART searches over sequences a *single* party can
submit. A large family of real extractions is not that: it is an **interleaving**.
A sandwich is a victim's swap with the attacker's swap placed before it and the
reverse swap placed after it; a liquidation snatch is a keeper's call inserted
ahead of a victim's; a governance race is a vote inserted just before the window
closes. The attacker here is not choosing their own operations alone -- they are
choosing *where in someone else's flow* to land, and the protocol's ordering rule
is what makes it profitable.

This module makes that a first-class search over the existing machinery:

  * A :class:`MempoolScenario` is a **victim flow** (the benign transactions a
    real user submits, in order) plus the attacker's allowed operations and the
    invariants that must hold.
  * :func:`search_ordering` enumerates the interleavings of attacker operations
    into the victim flow -- a bounded, deterministic search over (which operation,
    which actor, which parameters, and *which gap* in the victim flow) -- executes
    each on the target, and prices it with the universal value engine.
  * The result names the best interleaving by attacker profit and by invariant
    violation, and reports the honest bound it searched.

It is a *simulation of the ordering rule*, not a connection to a real mempool:
the scenario declares the victim flow and the attacker's reachable operations, and
the search decides the ordering. That is the honest form -- a real mempool is
unpredictable, but whether an ordering *exists* that extracts value is a property
of the protocol, and that is exactly what this measures. It never asserts a
vulnerability: a profitable interleaving is a lead, subject to the same
certification and patched-control gates as everything else.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import AttackStep
from ..value import analyse
from .model import SequenceTarget

#: How many attacker steps a sandwich may use by default. A sandwich is three
#: (front-run, victim, back-run); a little more lets a two-leg or a follow-on
#: extraction be expressed, and the bound is reported.
DEFAULT_MAX_ATTACKER_STEPS = 3


@dataclass
class MempoolScenario:
    """A victim flow plus the attacker's reachable operations, on a live target.

    ``victim_flow`` is the ordered list of steps the honest user submits -- the
    transactions the attacker is trying to get in front of, behind, or between.
    ``attacker_ops`` names the operations the attacker may use (a subset of the
    target's, so a scenario is explicit about what the attacker can reach);
    empty means every operation the target exposes.
    """

    name: str
    target: SequenceTarget
    victim_flow: list[AttackStep]
    attacker_ops: list[str] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Ordering:
    """One candidate interleaving, with what it achieved."""

    sequence: list[AttackStep]
    #: Gap index in the victim flow each attacker step was inserted at (0 = before
    #: the first victim tx, len(flow) = after the last).
    insertions: list[int] = field(default_factory=list)
    violated: list[str] = field(default_factory=list)
    attacker_profit: int = 0
    victim_loss: int = 0
    revert: bool = False

    def to_dict(self) -> dict:
        return {
            "sequence": [s.to_dict() for s in self.sequence],
            "insertions": list(self.insertions),
            "violated": list(self.violated),
            "attacker_profit": self.attacker_profit,
            "victim_loss": self.victim_loss,
            "revert": self.revert,
        }


@dataclass
class OrderingReport:
    scenario: str
    target: str
    bound: dict
    orderings_tried: int = 0
    steps_executed: int = 0
    #: The interleaving that violated the most invariants (ties broken by profit).
    violating: Optional[Ordering] = None
    #: The interleaving that earned the attacker the most (even if no invariant
    #: broke) -- the ordering-level loss that a plain single-actor search misses.
    most_profitable: Optional[Ordering] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scenario": self.scenario,
            "target": self.target,
            "bound": dict(self.bound),
            "orderings_tried": self.orderings_tried,
            "steps_executed": self.steps_executed,
            "violating": self.violating.to_dict() if self.violating else None,
            "most_profitable": self.most_profitable.to_dict() if self.most_profitable else None,
            "notes": list(self.notes),
        }


def _op_specs(target: Any) -> dict[str, Any]:
    return {op.name: op for op in target.ops()}


def _boundary_assignments(op: Any, *, cap: int = 4) -> list[dict[str, Any]]:
    """Parameter assignments worth trying for one operation, boundaries first."""
    domain = getattr(op, "param_domain", {}) or {}
    if not domain:
        return [{}]
    keys = list(domain)
    options: list[list[Any]] = []
    for k in keys:
        vals = list(domain[k])
        nums = sorted(v for v in vals if isinstance(v, int) and not isinstance(v, bool))
        picked: list[Any] = []
        if nums:
            picked.append(nums[0])            # the smallest -- where rounding lives
            if nums[-1] != nums[0]:
                picked.append(nums[-1])
            mid = nums[len(nums) // 2]
            if mid not in picked:
                picked.append(mid)
        for v in vals:
            if v not in picked:
                picked.append(v)
        options.append(picked[:cap])
    return [dict(zip(keys, combo)) for combo in itertools.product(*options)]


def _attacker_steps(scenario: MempoolScenario, target: Any) -> list[AttackStep]:
    """The single attacker steps the ordering search may place into the flow."""
    specs = _op_specs(target)
    names = scenario.attacker_ops or list(specs)
    steps: list[AttackStep] = []
    for name in names:
        op = specs.get(name)
        if op is None:
            continue
        actors = list(getattr(op, "actors", ()) or ()) or ["attacker"]
        actor = actors[0]
        for params in _boundary_assignments(op):
            steps.append(AttackStep(index=0, actor=actor, action=name, params=params,
                                    target_contract=getattr(target, "name", "target"),
                                    expected_effect=getattr(op, "description", "")))
    return steps


def _interleave(flow: list[AttackStep], inserts: list[AttackStep],
                gaps: tuple[int, ...]) -> tuple[list[AttackStep], list[int]]:
    """Weave ``inserts`` into ``flow`` at the given gap indices (order preserved)."""
    buckets: dict[int, list[AttackStep]] = {g: [] for g in range(len(flow) + 1)}
    for gap, step in zip(gaps, inserts):
        buckets[gap].append(step)
    out: list[AttackStep] = []
    insertions: list[int] = []
    for gap in range(len(flow) + 1):
        for step in buckets[gap]:
            insertions.append(gap)
            out.append(step)
        if gap < len(flow):
            out.append(flow[gap])
    return out, insertions


def _execute(target: Any, seq: list[AttackStep]) -> tuple[list[str], bool, dict]:
    """Run a sequence; return (violated invariants, reverted, final snapshot)."""
    state = target.reset()
    violated: list[str] = []
    reverted = False
    for step in seq:
        try:
            target.step(state, step.action, step.actor, dict(step.params))
        except Exception:  # noqa: BLE001 -- a reverted tx is feedback, not a crash
            reverted = True
            continue
        for inv in target.invariants():
            if not inv.holds(state):
                violated.append(inv.inv_id)
    try:
        snap = target.snapshot(state)
    except Exception:  # noqa: BLE001
        snap = {}
    return sorted(set(violated)), reverted, snap


def _price(target: Any, seq: list[AttackStep]) -> tuple[int, int]:
    """Attacker profit and victim loss for a sequence, via the value engine."""
    try:
        acct = analyse(target, seq)
    except Exception:  # noqa: BLE001 -- pricing is best-effort, never fatal
        return 0, 0
    return int(getattr(acct, "attacker_profit", 0) or 0), int(getattr(acct, "victim_loss", 0) or 0)


def search_ordering(scenario: MempoolScenario, *,
                    max_attacker_steps: int = DEFAULT_MAX_ATTACKER_STEPS,
                    max_orderings: int = 4000) -> OrderingReport:
    """Search the interleavings of attacker steps into the victim flow.

    Bounded and deterministic: at most ``max_attacker_steps`` attacker operations,
    inserted into the ``len(flow)+1`` gaps, with the operation's boundary
    parameters. The bound is reported; the search never claims completeness.
    """
    target = scenario.target
    flow = scenario.victim_flow
    attacker_steps = _attacker_steps(scenario, target)
    gaps = range(len(flow) + 1)

    report = OrderingReport(
        scenario=scenario.name, target=getattr(target, "name", "target"),
        bound={"max_attacker_steps": max_attacker_steps, "max_orderings": max_orderings,
               "victim_flow_len": len(flow), "attacker_steps_available": len(attacker_steps)},
    )
    if not attacker_steps:
        report.notes.append("no attacker-reachable operations; nothing to order")
        return report

    best_violating: Optional[Ordering] = None
    best_profit: Optional[Ordering] = None

    # Try k attacker steps for k = 1..max, at every ordered choice of gaps. The
    # gap tuple is non-decreasing so the attacker's own step order is preserved
    # while every relative placement against the victim flow is explored.
    for k in range(1, max_attacker_steps + 1):
        if report.orderings_tried >= max_orderings:
            report.notes.append(f"ordering budget reached at k={k}")
            break
        for chosen in itertools.product(attacker_steps, repeat=k):
            for gap_tuple in itertools.combinations_with_replacement(gaps, k):
                if report.orderings_tried >= max_orderings:
                    break
                seq, insertions = _interleave(flow, list(chosen), tuple(gap_tuple))
                violated, reverted, _snap = _execute(target, seq)
                report.orderings_tried += 1
                report.steps_executed += len(seq)
                profit, loss = _price(target, seq)
                ordering = Ordering(sequence=seq, insertions=insertions, violated=violated,
                                    attacker_profit=profit, victim_loss=loss, revert=reverted)
                if violated:
                    if (best_violating is None
                            or len(violated) > len(best_violating.violated)
                            or (len(violated) == len(best_violating.violated)
                                and profit > best_violating.attacker_profit)):
                        best_violating = ordering
                if profit > 0 and (best_profit is None
                                   or profit > best_profit.attacker_profit):
                    best_profit = ordering
            if report.orderings_tried >= max_orderings:
                break

    report.violating = best_violating
    report.most_profitable = best_profit
    if best_profit is not None and best_violating is None:
        report.notes.append(
            "a profitable ordering exists but broke no stated invariant -- "
            "the ordering is a loss with no invariant to catch it")
    return report


# --------------------------------------------------------------------------- #
# Named scenarios -- the ordering analogue of the target registry
# --------------------------------------------------------------------------- #

def _sandwich_scenario(guarded: bool) -> MempoolScenario:
    from ..invariants.registry import make_target

    target = make_target("sandwich-guarded" if guarded else "sandwich-slippage")
    flow = [AttackStep(index=0, actor="victim", action="victim_swap",
                       params={"amount": 100, "min_out": 90},
                       target_contract=getattr(target, "name", "target"),
                       expected_effect="the victim's slippage-protected swap")]
    return MempoolScenario(
        name="sandwich", target=target, victim_flow=flow,
        attacker_ops=["swap_a_for_b", "swap_b_for_a"],
        description="front-run / victim-swap / back-run around an unenforced "
                    "slippage limit (the classic sandwich)")


#: Named ordering scenarios, so the harness is drivable without a bespoke script.
SCENARIOS: dict[str, Any] = {
    "sandwich": lambda: _sandwich_scenario(guarded=False),
    "sandwich-guarded": lambda: _sandwich_scenario(guarded=True),
}


def scenario_names() -> list[str]:
    return list(SCENARIOS)


def make_scenario(name: str) -> MempoolScenario:
    if name not in SCENARIOS:
        raise KeyError(f"unknown scenario: {name} (known: {', '.join(scenario_names())})")
    return SCENARIOS[name]()
