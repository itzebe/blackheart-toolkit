"""The execution boundary: where the compatibility gate is enforced, not described.

The policy, the prompts, the agents, the skills and the CLI all say a tool may
not run before its stack is identified and its compatibility is verified. A
caller that imports :mod:`blackheart.statespace` reads none of that. Enforcement
therefore has to live where a target is actually acted upon, and it has to be
the *only* such place:

* :class:`ExecutionTarget` -- what is about to run: its name, and the repository
  and commit it was read from when those are known.
* :func:`bind` -- :func:`blackheart.toolchain.admit` plus identity. A record that
  is complete, official and smoke-tested still cannot authorise a *different*
  target: a record for protocol A at commit X must not run protocol B at commit Y.
* :func:`require_compatibility` -- the validator an engine entry point calls. It
  raises :class:`CompatibilityError`, which carries the decision, the reasons and
  the remediation.
* :func:`guarded` / :func:`authorized_execution` -- validate once, then install
  the authority for the duration of the run so internal primitives inherit it.
* :func:`require_execution_authorized` -- the chokepoint. It refuses to act on a
  target with no authority installed, or with an authority for another target.
  It is called by the primitives every engine funnels through, so an engine that
  forgets to ask its caller for a record still cannot run.

No policy is defined here. The gate fields, the statuses, the languages and the
registry come from :mod:`blackheart.doctrine` through :mod:`blackheart.toolchain`;
this module only decides *when* they are consulted and *what* they bind to.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Union

from . import CompatibilityRecord, GateDecision, admit

#: The record a mission supplies: an object, a dict, a path, or raw JSON text.
RecordSource = Union[CompatibilityRecord, dict, str, Path, None]

#: The shortest commit a record may name and still be matched by prefix.
MIN_COMMIT_PREFIX = 7

#: Installed only by :func:`authorized_execution`, and only after a record has
#: been validated against the target. A ``ContextVar`` rather than a module
#: global so a run cannot authorise another thread's or another task's execution.
_AUTHORITY: ContextVar[Optional["Authority"]] = ContextVar(
    "blackheart_execution_authority", default=None
)


@dataclass(frozen=True)
class ExecutionTarget:
    """The identity of what an engine is about to act upon.

    ``repository`` and ``commit`` are empty when the caller genuinely has no
    checkout to bind to (an in-memory model, a fixture). An empty identity is
    not a wildcard: the record's ``target_component`` must still name this
    target, so a record written for one target cannot authorise another.
    """

    name: str
    repository: str = ""
    commit: str = ""
    #: Other names that denote the *same* component -- a registry alias for a
    #: model's canonical name. Declared by the caller that resolved them, so this
    #: module never has to know the registry. A record naming any of them binds.
    aliases: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "name": self.name, "repository": self.repository,
            "commit": self.commit, "aliases": list(self.aliases),
        }


@dataclass(frozen=True)
class Authority:
    """A validated record, the target it was validated for, and the decision."""

    record: CompatibilityRecord
    decision: GateDecision
    target: ExecutionTarget
    #: Every name the record's components resolve to, declared by the entry point
    #: that installed the authority (a registry alias and its canonical name are
    #: one component). Derived strictly from ``target_component`` and
    #: ``control_component``, so it can never name a third component.
    grants: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "target": self.target.to_dict(),
            "decision": self.decision.to_dict(),
            "record": self.record.to_dict(),
            "grants": list(self.grants),
        }


class CompatibilityError(RuntimeError):
    """An engine was asked to run without a compatibility record that admits it.

    Carries the machine-readable decision so a caller (or a test) can assert on
    the *reason* an execution was denied, not only on the message.
    """

    def __init__(self, decision: GateDecision, target: ExecutionTarget, where: str = ""):
        self.decision = decision
        self.target = target
        self.where = where
        location = f" at {where}" if where else ""
        reasons = "\n".join(f"  - {r}" for r in decision.reasons) or "  - (no reason given)"
        super().__init__(
            f"compatibility gate BLOCKED execution of '{target.name}'{location}:\n"
            f"{reasons}\n"
            f"  remedy: write a record with `blackheart compat template --out record.json`, "
            f"fill every field with official evidence, run its smoke test, then pass it "
            f"with --compatibility record.json (or compatibility=... in the Python API)."
        )

    def to_dict(self) -> dict:
        return {
            "where": self.where,
            "target": self.target.to_dict(),
            "decision": self.decision.to_dict(),
        }


# --------------------------------------------------------------------------- #
# Identity binding
# --------------------------------------------------------------------------- #

def _names_match(a: str, b: str) -> bool:
    """True when two target names denote the same component.

    Equal after case-folding and whitespace-trimming, or equal basenames, so a
    record naming ``Vault.sol`` binds to a target named ``contracts/Vault.sol``
    but not to ``Other.sol``.
    """
    left, right = a.strip().casefold(), b.strip().casefold()
    if not left or not right:
        return False
    if left == right:
        return True
    return Path(left).name == Path(right).name


def _commit_matches(recorded: str, actual: str) -> bool:
    """Exact match, or a full-length prefix (a 7+ character short SHA)."""
    recorded, actual = recorded.strip().casefold(), actual.strip().casefold()
    if not recorded or not actual:
        return False
    if recorded == actual:
        return True
    return len(recorded) >= MIN_COMMIT_PREFIX and actual.startswith(recorded)


def _component_covered(granted: str, target: ExecutionTarget,
                       aliases: tuple[str, ...] = ()) -> bool:
    """True when ``granted`` names this component (canonical name or declared alias).

    ``aliases`` is passed separately because it is only meaningful for the
    component the caller resolved it for: an alias must never authorise a
    *different* target that happens to share a basename.
    """
    if _names_match(granted, target.name):
        return True
    return any(_names_match(granted, alias) for alias in aliases)


def bind(record: CompatibilityRecord, target: ExecutionTarget) -> GateDecision:
    """Admit the record *and* bind it to this exact target.

    Fails closed. Every unmet requirement is a blocker, and any blocker is BLOCK.
    A wildcard component (``*``) is accepted only for a record that is bound to a
    repository, so a wildcard can never authorise an unbounded set of targets.
    """
    decision = admit(record)
    blockers = list(decision.reasons)

    component = record.target_component.strip()
    if component == "*":
        if not record.repository.strip():
            blockers.append(
                "a wildcard target component ('*') is only accepted for a record bound "
                "to a repository; name the component instead"
            )
        elif not target.repository.strip():
            blockers.append(
                "a wildcard target component ('*') authorises only targets that declare "
                "their repository; this execution declares none, so name the component"
            )
        elif not _names_match(record.repository, target.repository):
            blockers.append(
                f"record is bound to repository '{record.repository}', "
                f"not '{target.repository}'"
            )
    elif not _component_covered(component, target, target.aliases):
        blockers.append(
            f"record is for target component '{component}', not '{target.name}'; a "
            f"record does not authorise a different target"
        )

    if target.repository:
        if not record.repository.strip():
            blockers.append(
                f"record names no repository but the execution target is "
                f"'{target.repository}'; the record must name what it was verified against"
            )
        elif not _names_match(record.repository, target.repository):
            blockers.append(
                f"record is bound to repository '{record.repository}', "
                f"not '{target.repository}'"
            )

    if target.commit:
        if not record.commit.strip():
            blockers.append(
                f"record names no commit but the execution target is at "
                f"'{target.commit}'; bind the record to the commit it was verified against"
            )
        elif not _commit_matches(record.commit, target.commit):
            blockers.append(
                f"record is bound to commit '{record.commit}', not '{target.commit}'"
            )

    return GateDecision(
        decision="BLOCK" if blockers else "ADMIT",
        reasons=tuple(blockers),
        language=record.language,
        tool=record.tool,
    )


# --------------------------------------------------------------------------- #
# Loading a record
# --------------------------------------------------------------------------- #

def load_record(source: RecordSource) -> CompatibilityRecord:
    """Coerce a record source into a :class:`CompatibilityRecord`.

    Accepts an object, a dict, a path to a JSON file, or raw JSON text. Anything
    else is an error -- never a permissive default.
    """
    if isinstance(source, CompatibilityRecord):
        return source
    if isinstance(source, dict):
        return CompatibilityRecord.from_dict(source)
    if isinstance(source, (str, Path)):
        text = str(source)
        path = Path(text)
        if path.is_file():
            return CompatibilityRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
        stripped = text.strip()
        if stripped.startswith("{"):
            return CompatibilityRecord.from_dict(json.loads(stripped))
        raise FileNotFoundError(
            f"compatibility record '{text}' is neither a readable JSON file nor JSON text"
        )
    raise TypeError(
        f"a compatibility record must be a CompatibilityRecord, dict, path or JSON "
        f"text, not {type(source).__name__}"
    )


# --------------------------------------------------------------------------- #
# The gate an entry point calls
# --------------------------------------------------------------------------- #

def require_compatibility(
    source: RecordSource,
    target: ExecutionTarget,
    where: str = "",
) -> tuple[CompatibilityRecord, GateDecision]:
    """Validate a record for a target, or raise :class:`CompatibilityError`.

    This is the one validator every engine entry point calls. It never returns a
    permissive default: a missing record, an incomplete record, an unverified
    tool, non-official evidence, a failed smoke test or a mismatched identity all
    raise.
    """
    if source is None:
        raise CompatibilityError(_no_record_decision(where, target), target, where)
    record = load_record(source)
    decision = bind(record, target)
    if not decision.admitted:
        raise CompatibilityError(decision, target, where)
    return record, decision


def _no_record_decision(where: str, target: ExecutionTarget) -> GateDecision:
    location = where or "an engine execution boundary"
    return GateDecision(
        decision="BLOCK",
        reasons=(
            f"no compatibility record was supplied to {location}: identify the stack "
            f"and verify the tool's compatibility before the engine runs "
            f"(docs/SECURITY_TOOL_COMPATIBILITY.md, section E)",
        ),
        language="",
        tool="",
    )


def check_scope(authority: Authority, target: ExecutionTarget) -> None:
    """Raise unless ``authority`` covers ``target``.

    A record covers exactly two components: the one it was verified against
    (``target_component``) and, when it declares one, the guarded twin it is
    compared against (``control_component``). That is a comparison, not an open
    set -- a control cannot be promoted into a grant for a third component.

    Aliases the entry caller resolved (``ExecutionTarget.aliases``) are honoured
    for the *primary* component only, so a record naming ``vulnerable`` still
    covers the canonical ``vulnerable-vault`` it was written for.
    """
    record = authority.record
    component = record.target_component.strip()
    if component == "*" and record.repository.strip():
        return
    if any(g and _names_match(target.name, g) for g in authority.grants):
        return
    aliases = (
        authority.target.aliases
        if _names_match(authority.target.name, target.name) else ()
    )
    for granted in (component, record.control_component.strip()):
        if granted and granted != "*" and _component_covered(granted, target, aliases):
            return
    granted_desc = ", ".join(
        f"'{g}'" for g in (component, record.control_component.strip()) if g
    ) or "(none)"
    decision = GateDecision(
        decision="BLOCK",
        reasons=(
            f"the active compatibility authority is for {granted_desc}, not "
            f"'{target.name}'; one record authorises the target and its declared "
            f"control, nothing else",
        ),
        language=record.language,
        tool=record.tool,
    )
    raise CompatibilityError(decision, target, "nested engine execution")


# --------------------------------------------------------------------------- #
# Installing and requiring the authority
# --------------------------------------------------------------------------- #

@contextmanager
def authorized_execution(
    source: RecordSource,
    target: ExecutionTarget,
    where: str = "",
    grants: tuple[str, ...] = (),
) -> Iterator[Authority]:
    """Validate the record, then authorise execution of ``target`` for the block.

    Nested engine calls inherit the authority; they do not re-read the record and
    they cannot widen it -- :func:`require_execution_authorized` re-checks the
    target name on every call. ``grants`` lets the entry point declare the names
    its two authorised components resolve to (see :class:`Authority`); it is
    additive to the record, never a replacement for it.
    """
    record, decision = require_compatibility(source, target, where)
    authority = Authority(record=record, decision=decision, target=target,
                          grants=tuple(grants))
    token = _AUTHORITY.set(authority)
    try:
        yield authority
    finally:
        _AUTHORITY.reset(token)


@contextmanager
def guarded(
    source: RecordSource,
    target: ExecutionTarget,
    where: str = "",
    grants: tuple[str, ...] = (),
) -> Iterator[Authority]:
    """An entry point's guard: inherit a matching authority, or validate a record.

    ``source`` is ``None`` for a nested call, which then requires an authority
    already installed by the outer entry point *and* that the outer authority
    covers this target. There is no path from ``None`` to unrestricted execution.
    """
    if source is None:
        authority = _AUTHORITY.get()
        if authority is None:
            raise CompatibilityError(_no_record_decision(where, target), target, where)
        check_scope(authority, target)
        yield authority
        return
    with authorized_execution(source, target, where, grants=grants) as authority:
        yield authority


def execution_authority() -> Optional[Authority]:
    """The authority installed for the current execution, if any."""
    return _AUTHORITY.get()


@contextmanager
def no_authority() -> Iterator[None]:
    """Suspend any installed authority for the block.

    Used by the enforcement tests to prove denial in a process that is otherwise
    running under an authority, and by any command that must not inherit one. It
    can only *remove* permission, never grant it.
    """
    token = _AUTHORITY.set(None)
    try:
        yield
    finally:
        _AUTHORITY.reset(token)


def require_execution_authorized(name: str, where: str = "") -> Authority:
    """The chokepoint: refuse to act on ``name`` without an authority that covers it.

    Called by the primitives every engine funnels through. It has no default and
    no bypass: an execution started without a validated record raises here even
    if the engine itself never asks for one.
    """
    authority = _AUTHORITY.get()
    target = ExecutionTarget(name=name)
    if authority is None:
        raise CompatibilityError(_no_record_decision(where, target), target, where)
    check_scope(authority, target)
    return authority


# --------------------------------------------------------------------------- #
# The repository's own fixtures
# --------------------------------------------------------------------------- #

def self_test_record() -> CompatibilityRecord:
    """The record BLACKHEART's own fixture engines run under.

    This is not an exemption from the gate: it passes :func:`bind` like any other
    record, and it is bound to this repository. It exists because the repository's
    self-tests (the vulnerable/guarded fixture pairs, the corpus, the benchmarks)
    are *also* engine executions and must declare their stack like any other.

    Its component is ``*`` -- a wildcard -- which :func:`bind` accepts only for a
    repository-bound record, so it can never authorise a third-party target.
    """
    return CompatibilityRecord(
        target_component="*",
        language="Python",
        language_version=">=3.11",
        framework="blackheart invariant engine (fixture Target models)",
        runtime="CPython, in-process",
        tool="pytest",
        compatibility_evidence="https://docs.python.org/3/library/unittest.html",
        selection_reason=(
            "the repository's fixture engines are Python models exercised by the "
            "in-process engine, so the native harness is pytest over those models"
        ),
        expected_coverage=(
            "the declared fixture models only; this record authorises no other target"
        ),
        known_limitations=(
            "a fixture model is a representative, not exhaustive, model of the class"
        ),
        smoke_test="passed",
        repository="blackheart",
        commit="",
    )


@contextmanager
def self_test_authority(name: str) -> Iterator[Authority]:
    """Run a repository self-test engine against one of its own fixtures."""
    with authorized_execution(
        self_test_record(),
        ExecutionTarget(name=name, repository="blackheart"),
        where="repository self-test",
    ) as authority:
        yield authority


__all__ = [
    "MIN_COMMIT_PREFIX",
    "ExecutionTarget", "Authority", "CompatibilityError",
    "bind", "load_record", "require_compatibility", "check_scope",
    "authorized_execution", "guarded", "execution_authority", "no_authority",
    "require_execution_authorized",
    "self_test_record", "self_test_authority",
]
