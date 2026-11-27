"""Propose a :class:`SystemModel` from Solidity source -- then validate it.

This is the capability the state-space engine was missing for on-chain targets.
Given one or more ``.sol`` files it reads the contracts, their state variables,
their externally-callable functions and the guards on them, and emits a
:class:`~blackheart.statespace.model.SystemModel`: actors, operations (with
visibility, mutability, and role-bearing modifiers), transitions for the guarded
functions, and a first-pass set of invariants derived from the asset-accounting
functions it saw. Every element carries ``provenance`` (``file:line``).

Two hard rules, both inherited from the Python extractor because they are the
difference between a research tool and a bug generator:

  1. **A proposal is not a claim.** The result is a *proposal*. It becomes the
     model the engine runs against only after it is cross-checked against the
     running system (``validate_against_operations`` / the runtime adapter). Where
     source and runtime disagree, the runtime wins and the discrepancy is
     reported.

  2. **Never invent an architecture.** An operation whose role the source does not
     reveal is recorded with an *empty* role, not a guessed one; an invariant the
     extractor is unsure of is emitted as a *candidate* with its provenance and a
     confidence, so the operator can accept or discard it. The extractor reports
     what it could not read (unvendored imports, assembly, unresolved inheritance)
     as explicit ``limitations`` rather than silently omitting them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..statespace.model import Actor, ModelInvariant, Operation, SystemModel, TransitionRule
from .parser import ContractDecl, FunctionDecl, ParsedSource, parse_source
from .taxonomy import (
    infer_asset,
    infer_category,
    infer_guard_roles,
    is_sensitive,
)


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

@dataclass
class CandidateInvariant:
    """An invariant the extractor *proposes* from the accounting it observed.

    ``confidence`` is low by default: the extractor can see that a pair of
    functions move an asset, but it cannot read the intended semantics of a
    bespoke protocol, so it proposes the invariant as a candidate and says so.
    """

    inv_id: str
    statement: str
    applies_to: tuple[str, ...]
    provenance: str
    confidence: str = "low"      # low | medium | high

    def to_dict(self) -> dict:
        return {
            "inv_id": self.inv_id,
            "statement": self.statement,
            "applies_to": list(self.applies_to),
            "provenance": self.provenance,
            "confidence": self.confidence,
        }


@dataclass
class SolidityProposal:
    """The proposal: a SystemModel plus the provenance and honesty record."""

    model: SystemModel
    candidates: list[CandidateInvariant] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    contracts_read: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model": self.model.to_dict(),
            "candidates": [c.to_dict() for c in self.candidates],
            "limitations": list(self.limitations),
            "contracts_read": list(self.contracts_read),
        }


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

_ACTOR_ATTACKER = "attacker"

# Names that are never operations an attacker invokes: internal plumbing.
_SKIP_NAMES = frozenset({
    "receive", "fallback", "constructor",
})


def _is_external_entry(fn: FunctionDecl) -> bool:
    """A function an external actor can call: public/external, or a fallback/
    receive/constructor. Interface functions are all external by definition."""
    if fn.is_constructor or fn.name in ("fallback", "receive"):
        return True
    if fn.is_interface:
        return True
    return fn.visibility in ("public", "external")


def _is_public_getter(fn: FunctionDecl, contract: ContractDecl) -> bool:
    """A Solidity-generated public state-variable getter: no body, no params,
    matches a public state variable name."""
    if fn.body_present or fn.params:
        return False
    return any(v.name == fn.name and v.visibility == "public"
               for v in contract.state_variables)


def propose_model(
    path: str | Path,
    *,
    text: Optional[str] = None,
    target_name: Optional[str] = None,
) -> SolidityProposal:
    """Propose a SystemModel from a single Solidity file."""
    p = Path(path)
    src_text = text if text is not None else p.read_text(encoding="utf-8")
    parsed = parse_source(str(p), src_text)
    return _propose_from_parsed([parsed], target_name=target_name or p.stem)


def propose_model_from_files(
    paths: Iterable[str | Path],
    *,
    target_name: str = "solidity-target",
) -> SolidityProposal:
    """Propose a SystemModel from several Solidity files (a whole project)."""
    parsed_list: list[ParsedSource] = []
    for path in paths:
        p = Path(path)
        try:
            parsed_list.append(parse_source(str(p), p.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError) as exc:
            parsed_list.append(ParsedSource(path=str(p), errors=[str(exc)]))
    return _propose_from_parsed(parsed_list, target_name=target_name)


def _propose_from_parsed(parsed_list: list[ParsedSource], *, target_name: str) -> SolidityProposal:
    model = SystemModel(target=target_name)
    proposal = SolidityProposal(model=model)

    actors: dict[str, Actor] = {}

    def actor(name: str, *, roles: tuple[str, ...] = (), unprivileged: bool = True,
              note: str = "") -> None:
        if name not in actors:
            actors[name] = Actor(name=name, roles=roles, unprivileged=unprivileged, note=note)

    # The attacker is always the weakest actor. A privileged actor is added only
    # if some operation is actually guarded by a role.
    actor(_ACTOR_ATTACKER, unprivileged=True,
          note="the weakest actor: an ordinary unprivileged caller")

    op_names: set[str] = set()
    op_from_interface: dict[str, bool] = {}
    role_actors: dict[str, set[str]] = {}

    for parsed in parsed_list:
        proposal.contracts_read.append(parsed.path)
        if parsed.errors:
            proposal.limitations.extend(f"{parsed.path}: {e}" for e in parsed.errors)
        for cdecl in parsed.contracts:
            _extract_contract(cdecl, parsed, model, proposal, op_names,
                              op_from_interface, role_actors)

    for role in sorted(role_actors):
        actor(role, roles=(role,), unprivileged=False,
              note=f"holds the {role!r} role (privileged; not the attacker)")

    model.actors = list(actors.values())

    # Promote the candidates into the model's invariant list. They stay *labelled*
    # as candidates (low/medium confidence, with provenance) -- but the engine
    # needs a stated invariant to have anything to attack, and a proposal with no
    # invariant is a model the engine refuses to run against (fail-closed).
    for cand in proposal.candidates:
        model.invariants.append(ModelInvariant(
            inv_id=cand.inv_id,
            statement=cand.statement,
            applies_to=cand.applies_to,
            expression=cand.inv_id,
            severity_if_broken="high" if cand.confidence == "medium" else "medium",
        ))

    if not op_names:
        proposal.limitations.append(
            "no externally-callable operations were extracted; the source may be an "
            "interface-only file, use a pattern the parser does not recognise, or "
            "rely on unvendored inheritance -- an explicit adapter declaration is "
            "still required rather than an invented model")

    model.assets = _assets_from(model)
    model.summary = (
        f"{target_name}: {len(model.operations)} operations across "
        f"{len(proposal.contracts_read)} file(s), {len(proposal.candidates)} candidate "
        f"invariant(s). PROPOSAL from source -- validate against the running system "
        f"before treating any element as fact."
    )
    model.revision = "solidity-extract"
    return proposal


def _extract_contract(
    cdecl: ContractDecl,
    parsed: ParsedSource,
    model: SystemModel,
    proposal: SolidityProposal,
    op_names: set[str],
    op_from_interface: dict[str, bool],
    role_actors: dict[str, set[str]],
) -> None:
    is_interface = cdecl.kind == "interface"
    for fn in cdecl.functions:
        if not _is_external_entry(fn):
            continue
        if _is_public_getter(fn, cdecl):
            continue
        if fn.name.lower() in _SKIP_NAMES and fn.name not in ("fallback", "receive"):
            continue

        prov = f"{parsed.path}:{fn.line}"
        category, _hint = infer_category(fn.name)
        roles = infer_guard_roles(fn.role_modifiers, cdecl.name)
        _has_role_mod = bool(fn.role_modifiers)
        sensitive = is_sensitive(fn.name, mutating=fn.mutating, category=category)
        asset = infer_asset(fn.name)

        # A public operation with no source-visible guard: any actor may call it.
        actor_roles: tuple[str, ...] = () if is_interface else (roles or ())

        op = Operation(
            name=fn.name,
            actor_roles=actor_roles,
            asset=asset,
            sensitive=sensitive,
            precondition="",
            effect=_effect(fn),
            entry_point=f"{cdecl.name}.{fn.name}({_param_sig(fn)})",
            guard=(", ".join(fn.role_modifiers) if fn.role_modifiers else
                   ("role" if roles else "")),
            guard_roles=roles,
            requires=(),
            source=prov,
        )
        # Only add each operation name once (a name can appear in several
        # contracts, e.g. an interface and its implementation). A concrete
        # implementation always wins over an interface declaration, because the
        # implementation is where the real body -- and its sensitivity -- lives.
        already = fn.name in op_names
        replace = already and op_from_interface.get(fn.name, False) and not is_interface
        if not already or replace:
            if replace:
                model.operations = [o for o in model.operations if o.name != fn.name]
            model.operations.append(op)
            op_names.add(fn.name)
            op_from_interface[fn.name] = is_interface

        if roles:
            for r in roles:
                role_actors.setdefault(r, set())
            model.transitions.append(TransitionRule(
                name=f"guard:{fn.name}",
                guard=", ".join(fn.role_modifiers),
                guard_roles=roles,
                operation=fn.name,
                description=f"{fn.name} is guarded by {', '.join(fn.role_modifiers)}",
            ))

        if sensitive and asset:
            proposal.candidates.append(CandidateInvariant(
                inv_id=f"inv:{asset}-conserved:{fn.name}",
                statement=(
                    f"{fn.name} moves {asset!r}; the protocol's accounting of {asset!r} "
                    f"must be conserved across any sequence (no operation may create or "
                    f"destroy {asset!r} without a matching counter-entry)"),
                applies_to=(asset,),
                provenance=prov,
                confidence="medium" if category else "low",
            ))

    if cdecl.uses_reentrancy_guard:
        model.trust_boundaries.append(
            f"{cdecl.name}: uses a reentrancy guard (nonReentrant) on at least one function")


def _effect(fn: FunctionDecl) -> str:
    parts = []
    if fn.mutability == "payable":
        parts.append("payable")
    if fn.mutability == "view":
        parts.append("read-only")
    if fn.mutating and not fn.is_interface:
        parts.append("state-changing")
    return "; ".join(parts)


def _param_sig(fn: FunctionDecl) -> str:
    return ", ".join(t for t, _ in fn.params)


def _assets_from(model: SystemModel) -> list[str]:
    assets: list[str] = []
    for op in model.operations:
        if op.asset and op.asset not in assets:
            assets.append(op.asset)
    return assets


# --------------------------------------------------------------------------- #
# Validation against a running system
# --------------------------------------------------------------------------- #

@dataclass
class ValidationResult:
    validated: bool
    matched: list[str] = field(default_factory=list)
    missing_at_runtime: list[str] = field(default_factory=list)
    undeclared_at_source: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "validated": self.validated,
            "matched": list(self.matched),
            "missing_at_runtime": list(self.missing_at_runtime),
            "undeclared_at_source": list(self.undeclared_at_source),
            "notes": list(self.notes),
        }


def validate_against_operations(
    proposal: SolidityProposal,
    runtime_operations: Iterable[str],
) -> ValidationResult:
    """Cross-check a source proposal against the operations a running system exposes.

    ``runtime_operations`` is the set of operation names a live adapter (an anvil
    deployment, an HTTP app) actually dispatches. Static analysis is not proof, so
    a proposal is only ``validated`` when every proposed operation is executable;
    a running system that exposes more is reported, and the runtime model -- not
    the source proposal -- is the one the engine should run.
    """
    runtime = set(runtime_operations)
    proposed = {op.name for op in proposal.model.operations}
    res = ValidationResult(validated=False)
    res.matched = sorted(proposed & runtime)
    res.missing_at_runtime = sorted(proposed - runtime)
    res.undeclared_at_source = sorted(runtime - proposed)
    if res.missing_at_runtime:
        res.notes.append(
            "proposed operations are not executable at runtime; the source model is "
            "not a valid runtime model")
    if res.undeclared_at_source:
        res.notes.append(
            "the running system exposes operations the source scan did not reveal; "
            "rely on the executable model, not the source proposal")
    res.validated = not res.missing_at_runtime and bool(proposed)
    return res
