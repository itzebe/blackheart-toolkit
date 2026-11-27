"""Real EVM execution coverage -- program-counter/opcode feedback from the node.

The universal coverage signal (:mod:`blackheart.fuzz.coverage`) is *behavioural*:
it is derived from what a target exposes (which operations ran, which states were
reached). That works on every target without instrumentation, but for a target
that runs on a real EVM it leaves the strongest signal on the table -- the actual
instruction stream the contract executed. AFL, Echidna and Medusa all rely on
that signal, and an EVM node can hand it over: ``debug_traceTransaction`` returns
the struct logs (the ``pc``/``op``/``depth`` of every step the transaction took).

This module turns those struct logs into the same bitmap features the rest of the
engine already consumes, so a sequence that drives the contract down a *new code
path* -- a branch no earlier sequence reached -- is retained and mutated, even
when it reaches a state the behavioural signal already saw. That is exactly the
signal a coverage-guided hunter needs and a behavioural-only signal cannot give.

It is honest about its limits:

  * it needs a node that implements ``debug_traceTransaction`` (anvil does);
  * if tracing fails or returns an unexpected shape, it yields **no** features and
    records a note -- it never invents coverage;
  * it is pure parsing plus one RPC call per executed transaction, so it is
    deterministic for a deterministic transaction stream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TraceCoverage:
    """Features extracted from one transaction's struct logs."""

    features: list[tuple] = field(default_factory=list)
    steps: int = 0
    note: str = ""


def _struct_logs(trace: Any) -> list[dict]:
    """Extract the struct-log list from a ``debug_traceTransaction`` result.

    Handles the two shapes nodes return: the default struct-log tracer
    (``{"structLogs": [...]}``) and a raw list of logs. Anything else is empty --
    the caller records that tracing produced nothing rather than guessing.
    """
    if isinstance(trace, dict):
        logs = trace.get("structLogs")
        return logs if isinstance(logs, list) else []
    if isinstance(trace, list):
        return trace
    return []


def features_from_struct_logs(trace: Any, *, label: str = "") -> TraceCoverage:
    """Turn a transaction trace into coverage features.

    Three families of feature, mirroring the behavioural map so they fold into the
    same bitmap:

      * ``("evm_op", label, op)`` -- which opcodes executed;
      * ``("evm_pc", label, depth, pc)`` -- which program counters, per call depth
        (a ``pc`` reached at a deeper call is a different code location);
      * ``("evm_edge", label, prev_pc, pc)`` -- the *transitions* between program
        counters, which is the real branch signal: the same two ``pc`` values in a
        new order is a new path.
    """
    logs = _struct_logs(trace)
    if not logs:
        return TraceCoverage(note="trace contained no struct logs")
    out: list[tuple] = []
    prev_pc: Optional[int] = None
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        pc = entry.get("pc")
        op = entry.get("op")
        depth = entry.get("depth", 0)
        if pc is None or op is None:
            continue
        out.append(("evm_op", label, str(op)))
        out.append(("evm_pc", label, int(depth), int(pc)))
        if prev_pc is not None:
            out.append(("evm_edge", label, prev_pc, int(pc)))
        prev_pc = int(pc)
    return TraceCoverage(features=out, steps=len(logs))


@dataclass
class EvmCoverageOracle:
    """Accumulates EVM coverage across the transactions of one run.

    A node-backed oracle: it is handed the ``EthRpc`` client and a transaction
    hash after each executed step, traces the transaction, and folds the resulting
    features into a run-scoped buffer. ``begin_run`` clears the buffer, so the
    features the caller reads always describe the run just executed.
    """

    rpc: Any
    #: Nodes disagree on the tracer argument; the default struct-log tracer is the
    #: one that yields ``pc``/``op``. Kept explicit so the dependency is visible.
    tracer: Optional[str] = None
    enabled: bool = True
    _features: list[tuple] = field(default_factory=list)
    _traced: int = 0
    _notes: list[str] = field(default_factory=list)

    def begin_run(self) -> None:
        self._features = []
        self._traced = 0
        self._notes = []

    def collect(self, tx_hash: Optional[str], *, label: str = "") -> None:
        """Trace one transaction and accumulate its coverage features.

        A missing hash, a disabled oracle, or a tracing error is recorded as a note
        and contributes nothing -- tracing never fabricates coverage and never
        aborts the run.
        """
        if not self.enabled or not tx_hash:
            return
        params: list[Any] = [tx_hash]
        if self.tracer:
            params.append({"tracer": self.tracer})
        try:
            trace = self.rpc.call("debug_traceTransaction", params)
        except Exception as exc:  # noqa: BLE001 -- tracing is best-effort feedback
            self._notes.append(f"trace {tx_hash[:10]} failed: {exc}")
            return
        tc = features_from_struct_logs(trace, label=label)
        if tc.note:
            self._notes.append(f"trace {tx_hash[:10]}: {tc.note}")
        self._features.extend(tc.features)
        self._traced += 1

    def features(self) -> list[tuple]:
        return list(self._features)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "transactions_traced": self._traced,
            "feature_count": len(self._features),
            "notes": list(self._notes),
        }
