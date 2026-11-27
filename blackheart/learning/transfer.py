"""Cross-target attack memory -- transfer a proven attack to a new target.

A hunter who has broken a first-depositor ERC4626 vault does not re-derive the
idea from nothing on the next vault. The engine should not either. This module is
the durable memory that lets a *proven* attack sequence found on one target become
a *seed* for the search on another -- the property that makes the engine stronger
the more it runs, and the one an exhaustive, per-target search lacks.

The design is deliberately conservative, because a memory that misleads is worse
than no memory:

  * Only **certified** findings are recorded (a sequence whose violation was
    reproduced and distinguished from the patched control). A lead that was never
    proved is never transferred.
  * A stored entry holds the attack's *shape* -- the ordered operation roles, the
    actor roles, and the parameter pattern (which parameter of which operation was
    a boundary value, not the value itself) -- plus its root-cause class. It is a
    shape, not a payload, so it can be projected onto a different target.
  * Transfer is a *proposal generator*: it projects a stored shape onto the new
    target's operations by role, and returns candidate sequences to run. It never
    asserts a vulnerability. Every transferred seed is executed and verified by the
    same pipeline as any other candidate; a transferred sequence that fires is a
    lead, and the same certification gate decides whether it is real.

Similarity is structural, not lexical alone: two targets are close when they share
operation-role tokens, invariant ids, and root-cause class. The score is
transparent (Jaccard over token sets with explicit weights) so a surprising
transfer can be explained, and the threshold is a knob, not a hidden heuristic.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from ..models import AttackStep

#: Characters that split an operation/entry-point name into role tokens.
_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return {t for t in _SPLIT.split((text or "").lower()) if t}


# --------------------------------------------------------------------------- #
# Target signature
# --------------------------------------------------------------------------- #

@dataclass
class TargetSignature:
    """A structural fingerprint of a target, used to find transferable attacks.

    Built from the *model* (operations, actor roles, invariant ids), never from a
    target-specific hard-coded name, so two different protocols that expose the
    same surface fingerprint as close.
    """

    target: str
    op_tokens: set[str] = field(default_factory=set)
    op_names: set[str] = field(default_factory=set)
    actor_roles: set[str] = field(default_factory=set)
    invariant_ids: set[str] = field(default_factory=set)
    root_cause: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "op_tokens": sorted(self.op_tokens),
            "op_names": sorted(self.op_names),
            "actor_roles": sorted(self.actor_roles),
            "invariant_ids": sorted(self.invariant_ids),
            "root_cause": self.root_cause,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TargetSignature":
        return cls(
            target=d.get("target", ""),
            op_tokens=set(d.get("op_tokens", [])),
            op_names=set(d.get("op_names", [])),
            actor_roles=set(d.get("actor_roles", [])),
            invariant_ids=set(d.get("invariant_ids", [])),
            root_cause=d.get("root_cause", ""),
        )


def signature_of(target: Any, *, root_cause: str = "") -> TargetSignature:
    """Derive a signature from any target exposing ``ops``/``invariants``/``name``.

    Operation *tokens* (not just names) are collected so ``deposit``/``depositFor``
    and ``withdraw``/``redeem`` share signal, and actor roles and invariant ids add
    the two strongest structural cues for "is this the same class of target?".
    """
    op_names: set[str] = set()
    op_tokens: set[str] = set()
    actor_roles: set[str] = set()
    for op in target.ops():
        name = getattr(op, "name", "")
        if not name:
            continue
        op_names.add(name)
        op_tokens |= _tokens(name)
        for a in getattr(op, "actors", ()) or ():
            actor_roles.add(str(a))
    invariant_ids = {inv.inv_id for inv in target.invariants()}
    return TargetSignature(
        target=getattr(target, "name", "target"),
        op_tokens=op_tokens, op_names=op_names,
        actor_roles=actor_roles, invariant_ids=invariant_ids,
        root_cause=root_cause,
    )


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


#: Relative weight of each structural cue in the similarity score. Operation
#: tokens dominate (the surface is what an attack drives); invariant id is the
#: strongest single signal when it matches; root-cause class confirms the family.
_W_TOKENS = 0.45
_W_INVARIANTS = 0.30
_W_ACTORS = 0.10
_W_ROOT_CAUSE = 0.15


def similarity(a: TargetSignature, b: TargetSignature) -> float:
    """Transparent, weighted structural similarity in ``[0, 1]``."""
    score = (
        _W_TOKENS * _jaccard(a.op_tokens, b.op_tokens)
        + _W_INVARIANTS * _jaccard(a.invariant_ids, b.invariant_ids)
        + _W_ACTORS * _jaccard(a.actor_roles, b.actor_roles)
    )
    if a.root_cause and a.root_cause == b.root_cause:
        score += _W_ROOT_CAUSE
    return round(score, 4)


# --------------------------------------------------------------------------- #
# Memory entries
# --------------------------------------------------------------------------- #

@dataclass
class StepShape:
    """One step of a stored attack, reduced to a transferable shape.

    The *operation* is kept as a role token set so it can be matched to a new
    target's operation of the same role (``withdraw`` on target A ~= ``redeem`` on
    target B if their tokens overlap); the actor is kept as a role; a parameter is
    recorded by name and by whether its value was a boundary (min/max) rather than
    the literal number, so the transfer re-derives a boundary on the new target.
    """

    op: str
    op_tokens: set[str] = field(default_factory=set)
    actor: str = "attacker"
    params: dict[str, Any] = field(default_factory=dict)
    param_is_boundary: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"op": self.op, "op_tokens": sorted(self.op_tokens), "actor": self.actor,
                "params": dict(self.params), "param_is_boundary": dict(self.param_is_boundary)}

    @classmethod
    def from_dict(cls, d: dict) -> "StepShape":
        return cls(op=d.get("op", ""), op_tokens=set(d.get("op_tokens", [])),
                   actor=d.get("actor", "attacker"), params=dict(d.get("params", {})),
                   param_is_boundary=dict(d.get("param_is_boundary", {})))


@dataclass
class MemoryEntry:
    """A proven attack, stored as a transferable shape."""

    entry_id: str
    source_target: str
    root_cause: str
    invariant_id: str
    signature: TargetSignature
    steps: list[StepShape] = field(default_factory=list)
    outcome: str = ""            # the attacker outcome the attack achieved
    evidence: str = ""           # pointer to the certificate / evidence id
    created_at: str = ""
    #: What the source attack assumed about its target. A transfer is refused
    #: when the new target cannot satisfy them, instead of silently keeping a
    #: truncated prefix that no longer means what the certificate proved.
    assumptions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "source_target": self.source_target,
            "root_cause": self.root_cause,
            "invariant_id": self.invariant_id,
            "signature": self.signature.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "outcome": self.outcome,
            "evidence": self.evidence,
            "created_at": self.created_at,
            "assumptions": dict(self.assumptions),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryEntry":
        return cls(
            entry_id=d.get("entry_id", ""),
            source_target=d.get("source_target", ""),
            root_cause=d.get("root_cause", ""),
            invariant_id=d.get("invariant_id", ""),
            signature=TargetSignature.from_dict(d.get("signature", {})),
            steps=[StepShape.from_dict(s) for s in d.get("steps", [])],
            outcome=d.get("outcome", ""),
            evidence=d.get("evidence", ""),
            created_at=d.get("created_at", ""),
            assumptions=dict(d.get("assumptions", {})),
        )


def assumptions_from_sequence(seq: list[AttackStep]) -> dict:
    """The capabilities a proven sequence relied on, reduced to checkable facts."""
    return {
        "required_ops": list(dict.fromkeys(s.action for s in seq)),
        "min_actors": len({s.actor for s in seq}),
    }


def _assumptions_hold(entry: MemoryEntry, ops: list[Any]) -> tuple[bool, str]:
    """Check a stored entry's assumptions against a target's exposed operations."""
    assumptions = entry.assumptions or {}
    for name in assumptions.get("required_ops", []):
        if _best_op(StepShape(op=name, op_tokens=_tokens(name)), ops) is None:
            return False, f"missing operation {name!r}"
    min_actors = int(assumptions.get("min_actors", 0) or 0)
    available = {a for op in ops for a in (getattr(op, "actors", ()) or ())}
    if min_actors > len(available):
        return False, (f"needs {min_actors} distinct actor role(s), "
                       f"the target exposes {len(available)}")
    return True, "assumptions hold"


def _is_boundary(value: Any, domain: Iterable[Any]) -> bool:
    nums = sorted(v for v in domain if isinstance(v, int) and not isinstance(v, bool))
    if not nums or not isinstance(value, int) or isinstance(value, bool):
        return False
    return value in (nums[0], nums[-1])


def shape_from_sequence(seq: list[AttackStep], ops_by_name: dict[str, Any]) -> list[StepShape]:
    """Reduce a concrete attack sequence to transferable step shapes."""
    shapes: list[StepShape] = []
    for s in seq:
        op = ops_by_name.get(s.action)
        domain = (getattr(op, "param_domain", {}) or {}) if op is not None else {}
        shapes.append(StepShape(
            op=s.action,
            op_tokens=_tokens(s.action),
            actor=s.actor,
            params=dict(s.params),
            param_is_boundary={k: _is_boundary(v, domain.get(k, []))
                               for k, v in (s.params or {}).items()},
        ))
    return shapes


# --------------------------------------------------------------------------- #
# The memory store
# --------------------------------------------------------------------------- #

class AttackMemory:
    """A persistent, append-only store of proven attack shapes (JSONL).

    Append-only, like the findings log: a recorded proof is never silently
    rewritten. The file is plain JSONL so it is diffable and reviewable.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> list[MemoryEntry]:
        if not self.path.exists():
            return []
        out: list[MemoryEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(MemoryEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, TypeError):
                continue
        return out

    def entries(self) -> list[MemoryEntry]:
        return self._load()

    def record(self, entry: MemoryEntry) -> MemoryEntry:
        """Append a proven attack. Only certified findings should reach here."""
        from ..models import utcnow

        if not entry.created_at:
            entry.created_at = utcnow()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
        return entry

    def record_from_certificate(
        self, *, target: Any, sequence: list[AttackStep], root_cause: str,
        invariant_id: str, certificate: dict, outcome: str = "", evidence: str = "",
    ) -> Optional[MemoryEntry]:
        """Record a *certified* finding as a transferable shape.

        Returns ``None`` (and records nothing) when the certificate is not
        ``proven`` -- an unproven lead is never promoted into the memory, which is
        the rule that keeps a bad idea from propagating to every later target.
        """
        if not certificate or not certificate.get("proven"):
            return None
        ops_by_name = {op.name: op for op in target.ops()}
        sig = signature_of(target, root_cause=root_cause)
        entry = MemoryEntry(
            entry_id=f"{sig.target}:{invariant_id}:{len(self._load())}",
            source_target=sig.target,
            root_cause=root_cause,
            invariant_id=invariant_id,
            signature=sig,
            steps=shape_from_sequence(sequence, ops_by_name),
            outcome=outcome,
            evidence=evidence or str(certificate.get("witness") is not None),
            assumptions=assumptions_from_sequence(sequence),
        )
        return self.record(entry)

    # -- retrieval -------------------------------------------------------- #

    def nearest(self, signature: TargetSignature, *, limit: int = 5,
                min_score: float = 0.0) -> list[tuple[float, MemoryEntry]]:
        scored = [(similarity(signature, e.signature), e) for e in self._load()]
        scored = [(s, e) for s, e in scored if s >= min_score]
        # Deterministic: by score desc, then entry id, so equal scores are stable.
        scored.sort(key=lambda t: (-t[0], t[1].entry_id))
        return scored[:limit]

    def seeds_for(self, target: Any, *, limit: int = 5, min_score: float = 0.35,
                  root_cause: str = "") -> list[list[AttackStep]]:
        """Project the nearest proven attacks onto ``target`` as candidate seeds.

        Projection is by *role*: a stored step's operation is matched to the new
        target's operation with the highest token overlap (falling back to an exact
        name match), and the actor is mapped to a role the new target's operation
        actually permits. A step whose operation cannot be projected onto anything
        breaks the sequence there -- the prefix that *does* project is kept, because
        a partial transfer is still a useful seed, and the pipeline verifies it.
        """
        sig = signature_of(target, root_cause=root_cause)
        ops = list(target.ops())
        seeds: list[list[AttackStep]] = []
        for score, entry in self.nearest(sig, limit=limit, min_score=min_score):
            holds, _ = _assumptions_hold(entry, ops)
            if not holds:
                continue
            seq = _project(entry, ops, target)
            if seq:
                seeds.append(seq)
        return seeds

    def transfer_decisions(self, target: Any, *, limit: int = 5,
                           min_score: float = 0.0, root_cause: str = "") -> list[dict]:
        """Why each nearby entry was accepted or refused for ``target``.

        This is the audit trail the plain ``seeds_for`` cannot show: a refused
        transfer names the assumption the new target does not satisfy, so a
        "no seed" result is explainable rather than silent.
        """
        sig = signature_of(target, root_cause=root_cause)
        ops = list(target.ops())
        out: list[dict] = []
        for score, entry in self.nearest(sig, limit=limit, min_score=min_score):
            holds, reason = _assumptions_hold(entry, ops)
            out.append({
                "entry_id": entry.entry_id,
                "score": round(score, 4),
                "accepted": holds,
                "reason": reason,
                "assumptions": dict(entry.assumptions),
            })
        return out

    def summary(self) -> dict:
        entries = self._load()
        by_root: dict[str, int] = {}
        by_target: dict[str, int] = {}
        for e in entries:
            by_root[e.root_cause] = by_root.get(e.root_cause, 0) + 1
            by_target[e.source_target] = by_target.get(e.source_target, 0) + 1
        return {
            "entries": len(entries),
            "by_root_cause": dict(sorted(by_root.items())),
            "by_source_target": dict(sorted(by_target.items())),
            "path": str(self.path),
        }


def _best_op(shape: StepShape, ops: list[Any]) -> Optional[Any]:
    """Match a stored step's operation to the new target's closest operation."""
    by_name = {op.name: op for op in ops}
    if shape.op in by_name:
        return by_name[shape.op]
    best: Optional[Any] = None
    best_score = 0.0
    for op in ops:
        s = _jaccard(shape.op_tokens, _tokens(getattr(op, "name", "")))
        if s > best_score:
            best_score, best = s, op
    return best if best_score >= 0.5 else None


def _project(entry: MemoryEntry, ops: list[Any], target: Any) -> list[AttackStep]:
    seq: list[AttackStep] = []
    for i, shape in enumerate(entry.steps):
        op = _best_op(shape, ops)
        if op is None:
            break                      # keep the projectable prefix only
        actors = list(getattr(op, "actors", ()) or ())
        actor = shape.actor if (not actors or shape.actor in actors) else \
            (actors[0] if actors else "attacker")
        params: dict[str, Any] = {}
        domain = getattr(op, "param_domain", {}) or {}
        for key, val in shape.params.items():
            if key in domain and domain[key]:
                # Re-derive the boundary on the *new* target rather than copying a
                # value that may be meaningless there.
                d = list(domain[key])
                if shape.param_is_boundary.get(key):
                    nums = sorted(v for v in d if isinstance(v, int) and not isinstance(v, bool))
                    params[key] = nums[0] if nums else val
                elif val in d:
                    params[key] = val
                else:
                    params[key] = d[0]
        seq.append(AttackStep(index=i, actor=actor, action=op.name, params=params,
                              target_contract=getattr(target, "name", "target"),
                              expected_effect=getattr(op, "description", "")))
    return seq
