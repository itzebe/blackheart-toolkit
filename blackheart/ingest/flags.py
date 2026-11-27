"""Candidate-weakness rules over an ingested surface.

A rule here emits a :class:`CandidateFlag` -- a *lead* with its evidence, never
a finding. The distinction is the whole point: the doctrine forbids dressing a
guess as a finding, so every flag carries the exact source line that raised it
and the attacker question it would have to answer to become real.

Every flag is mapped to a category in ``blackheart.objectives._OBJECTIVE_CATALOG``.
The mapping is validated at import: a rule pointing at a category that does not
exist is a programming error, not a runtime surprise, so the taxonomy and this
module cannot drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..objectives import _OBJECTIVE_CATALOG
from .solidity import ContractSurface, FunctionSurface, SurfaceReport

SEVERITIES = ("info", "low", "medium")


@dataclass(frozen=True)
class CandidateFlag:
    rule: str
    category: str
    severity_hint: str
    contract: str
    function: str
    path: str
    line: int
    evidence: str
    rationale: str
    question: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "category": self.category,
            "severity_hint": self.severity_hint,
            "contract": self.contract,
            "function": self.function,
            "location": f"{self.path}:{self.line}",
            "evidence": self.evidence,
            "rationale": self.rationale,
            "question": self.question,
        }


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    severity: str
    rationale: str
    question: str
    test: Callable[[ContractSurface, FunctionSurface], Optional[str]]


def _snippet(func: FunctionSurface, pattern: str, width: int = 90) -> Optional[str]:
    m = re.search(pattern, func.body)
    if not m:
        return None
    start = max(0, m.start() - 20)
    text = func.body[start:start + width]
    return " ".join(text.split())


_ONE_SHOT_GUARDS = frozenset({"initializer", "reinitializer"})


def _guarded(func: FunctionSurface) -> bool:
    if any(mod.startswith("only") for mod in func.modifiers):
        return True
    # OZ's one-shot initializer modifiers are access control: the function runs once.
    if any(mod in _ONE_SHOT_GUARDS for mod in func.modifiers):
        return True
    return bool(re.search(r"\bmsg\.sender\b|\b_msgSender\(\)", func.body))


def _unchecked_low_level_call(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if ".call(" not in f.body and ".call{" not in f.body:
        return None
    for stmt in re.split(r"[;\n]", f.body):
        if ".call(" in stmt or ".call{" in stmt:
            if "bool" not in stmt and "require(" not in stmt and "success" not in stmt:
                return " ".join(stmt.split())[:120]
    return None


def _delegatecall(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if c.kind == "library":
        return None
    return _snippet(f, r"\.delegatecall\(")


def _tx_origin(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    return _snippet(f, r"\btx\.origin\b")


def _unguarded_state_changer(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if not (f.externally_callable and f.state_changing):
        return None
    if not c.has_access_control:
        return None
    if _guarded(f):
        return None
    if not f.body.strip():
        return None  # an empty body cannot change state
    return f"{f.visibility} {f.mutability} {f.signature} with no only* modifier and no msg.sender check"


def _unguarded_initializer(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    name = f.name.lower()
    if not (name.startswith("initialize") or name == "init"):
        return None
    if not f.externally_callable:
        return None
    if any(mod in ("initializer", "reinitializer") for mod in f.modifiers):
        return None
    if "initialized" in f.body or "_initialized" in f.body:
        return None
    return f"public {f.signature} has no initializer modifier and no initialized guard"


def _selfdestruct(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    return _snippet(f, r"\b(selfdestruct|suicide)\(")


def _unbounded_loop(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if not re.search(r"\b(for|while)\s*\(", f.body):
        return None
    if not any("[]" in p for p in f.params):
        return None
    if ".length" not in f.body:
        return None
    return _snippet(f, r"\b(for|while)\s*\(")


def _ecrecover_unchecked(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if "ecrecover(" not in f.body:
        return None
    if "address(0)" in f.body:
        return None
    return _snippet(f, r"ecrecover\(")


def _timestamp_comparison(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if "block.timestamp" not in f.body:
        return None
    if not re.search(r"block\.timestamp\s*(<=|>=|<|>)|(<=|>=|<|>)\s*[^;\n]*block\.timestamp", f.body):
        return None
    return _snippet(f, r"block\.timestamp")


def _oracle_staleness(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if "latestRoundData(" not in f.body:
        return None
    if "updatedAt" in f.body or "answeredInRound" in f.body:
        return None
    return _snippet(f, r"latestRoundData\(")


def _self_balance_pricing(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if not re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", f.body):
        return None
    return _snippet(f, r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")


def _mint_without_transfer(c: ContractSurface, f: FunctionSurface) -> Optional[str]:
    if c.kind in ("interface", "library"):
        return None
    if not f.state_changing:
        return None
    if not re.search(r"[._]mint\s*\(", f.body):
        return None
    if re.search(r"(safe)?[Tt]ransferFrom\s*\(|\.wrap\s*\(|\.deposit\s*\(", f.body):
        return None
    return _snippet(f, r"[._]mint\s*\(")


RULES: tuple[Rule, ...] = (
    Rule(
        "unchecked-low-level-call", "silent-transfer-failure", "medium",
        "A low-level call whose success flag is not observed can fail silently.",
        "Can I make this call fail while the caller still believes it succeeded?",
        _unchecked_low_level_call,
    ),
    Rule(
        "delegatecall-present", "storage-collision", "medium",
        "delegatecall executes foreign code against this contract's storage.",
        "Can I influence the delegatecall target or calldata so the code writes my slot?",
        _delegatecall,
    ),
    Rule(
        "tx-origin-used", "auth-bypass", "medium",
        "tx.origin is the whole call chain's origin, not the immediate caller.",
        "Can I route a call through a contract I control so tx.origin passes the check?",
        _tx_origin,
    ),
    Rule(
        "unguarded-state-changer", "access-control", "medium",
        "An externally callable state changer in a contract that has guards, without a guard.",
        "Can I call this directly and change state the protocol assumes only an operator changes?",
        _unguarded_state_changer,
    ),
    Rule(
        "unguarded-initializer", "privilege-escalation", "medium",
        "A public initializer with no initializer modifier can be front-run or re-run.",
        "Can I initialize the proxy first and become its admin?",
        _unguarded_initializer,
    ),
    Rule(
        "selfdestruct-present", "denial-of-service", "medium",
        "selfdestruct removes code and forwards balance.",
        "Can I reach this path and destroy a contract others depend on?",
        _selfdestruct,
    ),
    Rule(
        "unbounded-loop-over-param", "denial-of-service", "low",
        "A loop over a caller-supplied array can exceed the block gas limit.",
        "Can I pass a large enough array to make this function unexecutable?",
        _unbounded_loop,
    ),
    Rule(
        "ecrecover-unchecked", "signature-bypass", "low",
        "ecrecover returns address(0) on failure; unchecked, that is a valid 'signer'.",
        "Can I supply a signature that recovers to address(0) and pass the check?",
        _ecrecover_unchecked,
    ),
    Rule(
        "timestamp-comparison", "ordering-timing", "info",
        "A block.timestamp comparison is miner-influenceable within a small window.",
        "Can I shift the outcome by a few seconds of timestamp control?",
        _timestamp_comparison,
    ),
    Rule(
        "oracle-staleness-unchecked", "oracle-manipulation", "low",
        "latestRoundData without a staleness or round check accepts an old price.",
        "Can I trade against a stale price during an oracle outage?",
        _oracle_staleness,
    ),
    Rule(
        "self-balance-pricing", "accounting-manipulation", "low",
        "Pricing off the contract's own token balance invites donation/inflation attacks.",
        "Can I donate tokens to skew this balance and change the price?",
        _self_balance_pricing,
    ),
    Rule(
        "mint-without-transfer", "unbacked-debt", "info",
        "A mint in a path with no visible collateral intake; verify the backing.",
        "Can I mint more than I paid in, or mint against someone else's collateral?",
        _mint_without_transfer,
    ),
)

# Linkage invariant: every rule's category must exist in the objective catalog.
_UNKNOWN = sorted({r.category for r in RULES} - set(_OBJECTIVE_CATALOG))
if _UNKNOWN:  # pragma: no cover - import-time contract violation
    raise RuntimeError(f"ingest rules reference unknown objective categories: {_UNKNOWN}")


def evaluate(report: SurfaceReport) -> tuple[CandidateFlag, ...]:
    """Run every rule over every function and return the flags, most severe first."""
    flags: list[CandidateFlag] = []
    for contract in report.contracts:
        for func in contract.functions:
            for rule in RULES:
                evidence = rule.test(contract, func)
                if evidence is None:
                    continue
                flags.append(
                    CandidateFlag(
                        rule=rule.name,
                        category=rule.category,
                        severity_hint=rule.severity,
                        contract=contract.name,
                        function=func.name,
                        path=contract.path,
                        line=func.line,
                        evidence=evidence,
                        rationale=rule.rationale,
                        question=rule.question,
                    )
                )
    order = {s: i for i, s in enumerate(("medium", "low", "info"))}
    flags.sort(key=lambda f: (order[f.severity_hint], f.path, f.line, f.rule))
    return tuple(flags)
