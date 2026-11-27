"""Category-linked rules over a Go / Cosmos SDK surface.

The rules ask the same question as the Solidity and Rust rules, in the Cosmos
environment: what can an ordinary signed account do here that it should not?
Only reachable code is judged -- a message server, an ante handler, a consensus
entry point, or an exported keeper method -- because a private helper that no
message can reach is not an unprivileged attacker's surface.

A flag is a lead, never a finding. Stub functions are excluded: a public-build
stub that returns ``ErrNotImplemented`` is evidence of a missing implementation,
not of a weakness in the implementation it replaces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..objectives import _OBJECTIVE_CATALOG
from .flags import CandidateFlag
from .golang import GoFunction, GoSurfaceReport
from .golang_calls import (
    AUTHORITY_GUARD_PATTERN,
    STATE_WRITE_PATTERN,
    GoCallGraph,
)


@dataclass(frozen=True)
class GoRule:
    name: str
    category: str
    severity: str
    rationale: str
    question: str
    test: Callable[..., Optional[str]]
    needs_graph: bool = False


def _snippet(func: GoFunction, pattern: str, width: int = 140) -> Optional[str]:
    m = re.search(pattern, func.body)
    if not m:
        return None
    start = max(0, m.start() - 40)
    return " ".join(func.body[start:start + width].split())


def _has(func: GoFunction, pattern: str) -> bool:
    return re.search(pattern, func.body) is not None


def _is_message_handler(func: GoFunction) -> bool:
    if func.stub or func.is_consensus:
        return False
    return func.is_handler


def _reachable(func: GoFunction) -> bool:
    return not func.stub and (func.is_handler or func.is_consensus)


def _panic_on_input(func: GoFunction) -> Optional[str]:
    if not _is_message_handler(func):
        return None
    return _snippet(func, r"\bpanic\(|\bMust[A-Z]\w*\(|\blog\.Fatal")


def _wall_clock_in_consensus(func: GoFunction) -> Optional[str]:
    if not (func.is_handler or func.is_consensus) or func.stub:
        return None
    return _snippet(func, r"\btime\.(?:Now|Since|Until)\(")


def _map_iteration_in_consensus(func: GoFunction) -> Optional[str]:
    if not func.is_consensus or func.stub:
        return None
    # A range over a slice is deterministic. Only flag a range whose expression
    # is a map, a map-valued field, or a conventionally map-named collection.
    m = re.search(r"for\s+[^;{\n]*range\s+([^\s{]+)\s*\{", func.body)
    if not m:
        return None
    expr = m.group(1)
    if not ("map[" in func.body or
            re.search(r"map|Map|entries|signers|scores|validators|votes", expr)):
        return None
    return _snippet(func, r"for\s+[^;{\n]*range\s+[^\s{]+\s*\{")


def _unchecked_value_result(func: GoFunction) -> Optional[str]:
    if not _is_message_handler(func):
        return None
    pattern = (
        r"(?:_\s*=\s*|[A-Za-z_]\w*\s*,\s*_\s*:?=\s*)"
        r"[^\n;]*(?:SendCoins|MintCoins|BurnCoins|Delegate|Undelegate|"
        r"Redelegate|Transfer|SendFromModuleToAccount)\("
    )
    return _snippet(func, pattern)


def _unchecked_cast(func: GoFunction) -> Optional[str]:
    if func.stub or ".pb.go" in func.path or not _is_message_handler(func):
        return None
    if not _has(func, r"amount|balance|coin|supply|share|stake|locked|escrow"):
        return None
    # A length cast is a wire-format prefix, not a value conversion.
    return _snippet(func, r"\b(?:int64|uint64|int|uint|int32|uint32)\s*\(\s*(?!len\()")


def _missing_authority_check(func: GoFunction) -> Optional[str]:
    if not _is_message_handler(func):
        return None
    if not _has(func, STATE_WRITE_PATTERN):
        return None
    if _has(func, AUTHORITY_GUARD_PATTERN):
        return None
    return "message handler writes state without an authority or signer check"


def _delegated_write_without_guard(func: GoFunction,
                                   graph: GoCallGraph) -> Optional[str]:
    """A handler that only delegates still owns the authorization decision."""
    if not _is_message_handler(func) or _has(func, AUTHORITY_GUARD_PATTERN):
        return None
    callees = graph.delegated_writes(func)
    if not callees:
        return None
    callee = callees[0]
    return (f"handler has no signer/authority check and delegates to "
            f"{callee.receiver}.{callee.name} ({callee.path}:{callee.line}) "
            f"which writes state")


def _ethereum_tx_outside_evm(func: GoFunction) -> Optional[str]:
    if not _is_message_handler(func):
        return None
    if re.search(r"^(?:reject|check|guard|validate|is|encode|decode|new)", func.name, re.I):
        return None
    if not _has(func, r"MsgEthereumTx|EthereumTx"):
        return None
    if "evm" in func.receiver.lower() or "evm" in func.package.lower():
        return None
    if _has(func, r"EVMLaneAnteRan|WithEVMLaneAnte"):
        return None
    return _snippet(func, r"MsgEthereumTx|EthereumTx")


def _unbounded_state_iteration(func: GoFunction) -> Optional[str]:
    if not (func.is_handler or func.is_consensus) or func.stub:
        return None
    return _snippet(func, r"for\s+[^;{\n]*range\s+[^\n{]*"
                           r"(?:GetAll|Iterate|Iterator|Walk|PrefixIterator)")


def _block_time_window(func: GoFunction) -> Optional[str]:
    if not (func.is_handler or func.is_consensus) or func.stub:
        return None
    return _snippet(func, r"(?:BlockTime|blockTime|ctx\.BlockTime\(\))[^\n;]{0,80}"
                           r"(?:<|>|<=|>=|\+|-)")


GO_RULES: tuple[GoRule, ...] = (
    GoRule(
        "go-panic-on-input", "denial-of-service", "medium",
        "A panic in a message or consensus path aborts the caller's work and, if "
        "the input is attacker-chosen, can be repeated cheaply.",
        "Can I make this function panic with an input any signed account can supply?",
        _panic_on_input,
    ),
    GoRule(
        "go-wall-clock-in-consensus", "ordering-timing", "medium",
        "Wall-clock time is not consensus time. Two validators can disagree on a "
        "boundary and produce different block results.",
        "Can I land a transaction at a wall-clock boundary where validators disagree?",
        _wall_clock_in_consensus,
    ),
    GoRule(
        "go-map-iteration-in-consensus", "state-inconsistency", "medium",
        "Iterating a map in consensus code has no deterministic order, so two "
        "validators can apply the same block differently.",
        "Does this loop depend on map order that differs between validators?",
        _map_iteration_in_consensus,
    ),
    GoRule(
        "go-unchecked-value-result", "silent-transfer-failure", "medium",
        "Discarding a bank or staking result records success for an operation that "
        "may have failed.",
        "If this transfer returns an error, does the state still record it as done?",
        _unchecked_value_result,
    ),
    GoRule(
        "go-unchecked-cast", "accounting-manipulation", "medium",
        "A narrowing integer cast truncates. In a value path the caller can choose "
        "an amount whose narrowed value is not the value that moved.",
        "Can I choose an amount whose cast wraps, and does the wrapped value move funds?",
        _unchecked_cast,
    ),
    GoRule(
        "go-missing-authority-check", "access-control", "medium",
        "A message handler that writes state without checking the signer or an "
        "authority field may be callable by any account.",
        "What stops any signed account from reaching this write?",
        _missing_authority_check,
    ),
    GoRule(
        "go-delegated-write-without-guard", "access-control", "medium",
        "A handler that delegates a state write to a keeper still owns the "
        "authorization decision; a keeper method is not a signer check.",
        "Does the handler or the delegated keeper verify that the caller may "
        "perform this write?",
        _delegated_write_without_guard,
        needs_graph=True,
    ),
    GoRule(
        "go-ethereum-tx-outside-evm", "access-control", "high",
        "The MsgEthereumTx handler skips the EVM ante checks when it is reached "
        "through another dispatcher (authz, group, governance, a contract).",
        "Can I dispatch MsgEthereumTx around the EVM lane's ante handler?",
        _ethereum_tx_outside_evm,
    ),
    GoRule(
        "go-unbounded-state-iteration", "denial-of-service", "medium",
        "Iterating a store collection makes the cost depend on state an attacker "
        "may be able to grow.",
        "Can I grow this collection until the handler exceeds its declared cost?",
        _unbounded_state_iteration,
    ),
    GoRule(
        "go-block-time-window", "ordering-timing", "low",
        "A block-time window decides eligibility, and the caller chooses when to "
        "land the transaction.",
        "Can I choose the block at which this window opens or closes?",
        _block_time_window,
    ),
)

_UNKNOWN = sorted({r.category for r in GO_RULES} - set(_OBJECTIVE_CATALOG))
if _UNKNOWN:  # pragma: no cover - import-time contract violation
    raise RuntimeError(f"Go ingest rules reference unknown objective categories: {_UNKNOWN}")


def evaluate_go(report: GoSurfaceReport) -> tuple[CandidateFlag, ...]:
    """Run every rule over every reachable Go function, most severe first."""
    flags: list[CandidateFlag] = []
    graph = GoCallGraph(report)
    for func in report.functions:
        if func.stub or func.path.endswith(".pb.go"):
            continue
        for rule in GO_RULES:
            evidence = (rule.test(func, graph) if rule.needs_graph
                        else rule.test(func))
            if evidence is None:
                continue
            flags.append(CandidateFlag(
                rule=rule.name,
                category=rule.category,
                severity_hint=rule.severity,
                contract=func.receiver or func.package,
                function=func.name,
                path=func.path,
                line=func.line,
                evidence=evidence,
                rationale=rule.rationale,
                question=rule.question,
            ))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    flags.sort(key=lambda f: (order.get(f.severity_hint, 9), f.path, f.line, f.rule))
    return tuple(flags)

