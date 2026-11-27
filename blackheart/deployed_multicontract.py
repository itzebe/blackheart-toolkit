"""Execute a candidate path across *real, related* deployed contracts.

A single contract is rarely where a bug lives. The interesting paths cross a
boundary: a pair calls its tokens, a vault calls its oracle, a proxy delegates to
an implementation. This module builds the evidence for that boundary and then
runs a sequence across it on the pinned local fork.

Two things it refuses to do:

  * it does not infer a relationship. ``token0()`` returning an address is only a
    relationship once the *other* contract is fetched and shown to answer as a
    token; a guess about wiring is not a graph edge;
  * it does not call a difference a vulnerability. Every sequence is run beside a
    guarded control, and the comparison is against a *stated property*. If the
    property holds on both paths, the honest verdict is "no violation".

All writes are executed with ``eth_sendTransaction`` on the local anvil fork.
Nothing is broadcast: the node has no route to a validator, and the caller is a
public anvil test account, never a real key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .deployed import ChainClient
from .toolchain.enforce import ExecutionTarget, guarded

__all__ = [
    "ContractNode",
    "ContractEdge",
    "ContractGraph",
    "StateObservation",
    "SequenceStep",
    "SequenceResult",
    "build_graph",
    "run_sequence",
]

#: Getters that reveal a dependency, with the relationship they establish. The
#: value returned is treated as an address only when the target it names answers
#: as a contract -- that is what turns a return value into an edge.
RELATION_GETTERS: dict[str, str] = {
    "0x0dfe1681": "token0",       # token0()
    "0xd21220a7": "token1",       # token1()
    "0x06fdde03": "name",         # name()  -- used to confirm a token, not an edge
    "0x95d89b41": "symbol",       # symbol()
    "0x313ce567": "decimals",     # decimals()
    "0x18160ddd": "totalSupply",  # totalSupply()
    "0x3644e515": "DOMAIN_SEPARATOR",  # marker of a real EIP-2612 token
}

_ADDRESS_GETTERS = frozenset({"token0", "token1"})


def _addr_from_word(word: str) -> str:
    return "0x" + word[-40:]


@dataclass
class ContractNode:
    """A real contract in the graph, with the bytecode hash it was read at."""

    label: str
    address: str
    code_size: int
    code_sha256: str
    is_proxy: bool = False
    logic_address: str = ""
    facts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "address": self.address,
            "code_size": self.code_size,
            "code_sha256": self.code_sha256,
            "is_proxy": self.is_proxy,
            "logic_address": self.logic_address or self.address,
            "facts": self.facts,
        }


@dataclass
class ContractEdge:
    """A relationship that was *proven* by a call, not assumed."""

    source: str
    target: str
    kind: str
    evidence: str

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "kind": self.kind, "evidence": self.evidence}


@dataclass
class ContractGraph:
    chain_id: int
    block_number: int
    block_hash: str
    nodes: list[ContractNode] = field(default_factory=list)
    edges: list[ContractEdge] = field(default_factory=list)
    unproven: list[str] = field(default_factory=list)

    def node(self, address: str) -> Optional[ContractNode]:
        return next((n for n in self.nodes if n.address.lower() == address.lower()), None)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "unproven": self.unproven,
        }


def _fetch_code(client: ChainClient, address: str, tag: str) -> bytes:
    code = client.call("eth_getCode", [address, tag])
    return bytes.fromhex(code[2:] if code and code.startswith("0x") else (code or ""))


def _call(client: ChainClient, to: str, data: str, tag: str) -> Optional[str]:
    """``eth_call`` returning the raw word, or None when the call reverts."""
    try:
        return client.call("eth_call", [{"to": to, "data": data}, tag])
    except Exception:  # noqa: BLE001 -- a revert is information, not an error
        return None


def _probe_facts(client: ChainClient, address: str, tag: str) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for selector, name in RELATION_GETTERS.items():
        raw = _call(client, address, selector, tag)
        # A revert yields None; an empty ``0x`` return means the call landed on a
        # fallback that returns nothing. Neither is a fact, so neither is recorded.
        if raw is None or len(raw) <= 2:
            continue
        if name in _ADDRESS_GETTERS:
            facts[name] = _addr_from_word(raw)
        elif name in ("name", "symbol"):
            # ABI-encoded string: offset word, length word, then the bytes.
            try:
                body = raw[2:]
                length = int(body[64:128], 16)
                facts[name] = bytes.fromhex(body[128:128 + length * 2]).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                facts[name] = "<undecodable>"
            continue
        else:
            facts[name] = int(raw, 16)
    return facts


def build_graph(
    roots: list[tuple[str, str]],
    *,
    client: ChainClient,
    block_number: int,
    max_depth: int = 2,
) -> ContractGraph:
    """Walk outward from ``roots`` (label, address) and prove each edge by call."""
    import hashlib

    block = client.call("eth_getBlockByNumber", [hex(block_number), False])
    tag = hex(block_number)
    graph = ContractGraph(
        chain_id=int(client.call("eth_chainId", []), 16),
        block_number=block_number,
        block_hash=block["hash"],
    )

    seen: set[str] = set()
    frontier = [(label, addr) for label, addr in roots]
    for _ in range(max_depth):
        nxt: list[tuple[str, str]] = []
        for label, addr in frontier:
            key = addr.lower()
            if key in seen:
                continue
            seen.add(key)
            code = _fetch_code(client, addr, tag)
            if not code:
                graph.unproven.append(f"{label} {addr}: no code at block {block_number}")
                continue
            facts = _probe_facts(client, addr, tag)
            node = ContractNode(
                label=label, address=addr, code_size=len(code),
                code_sha256=hashlib.sha256(code).hexdigest(),
                facts=facts,
            )
            # A token0/token1 address becomes an edge only because we then fetch
            # that contract and confirm it answers as a token (name/symbol).
            for getter, name in (("token0", "token0"), ("token1", "token1")):
                child = facts.get(getter)
                if not isinstance(child, str):
                    continue
                child_facts = _probe_facts(client, child, tag)
                child_code = _fetch_code(client, child, tag)
                if child_code and child_facts.get("symbol") is not None:
                    graph.edges.append(ContractEdge(
                        source=addr, target=child, kind=name,
                        evidence=(
                            f"{addr}.{name}() returned {child}; that address holds "
                            f"{len(child_code)} bytes and answers symbol()="
                            f"{child_facts.get('symbol')!r}"
                        ),
                    ))
                    nxt.append((f"{label}.{name}", child))
                else:
                    graph.unproven.append(
                        f"{addr}.{name}() returned {child} but it does not answer as a token"
                    )
            graph.nodes.append(node)
        frontier = nxt
        if not frontier:
            break
    return graph


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

@dataclass
class StateObservation:
    label: str
    values: dict[str, Any]

    def to_dict(self) -> dict:
        return {"label": self.label, "values": self.values}


@dataclass
class SequenceStep:
    """One transaction in a sequence, executed on the local fork."""

    label: str
    to: str
    data: str
    sender: str
    value: int = 0

    def to_dict(self) -> dict:
        return {"label": self.label, "to": self.to, "data": self.data,
                "sender": self.sender, "value": self.value}


@dataclass
class SequenceResult:
    """What actually happened, including whether it reverted."""

    steps: list[dict] = field(default_factory=list)
    observations: list[StateObservation] = field(default_factory=list)
    reverted_at: Optional[str] = None
    #: True only when every step was mined without revert.
    completed: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "steps": self.steps,
            "observations": [o.to_dict() for o in self.observations],
            "reverted_at": self.reverted_at,
            "completed": self.completed,
            "notes": self.notes,
        }


def _node_name(node) -> str:
    for attr in ("address", "name", "target"):
        value = getattr(node, attr, None)
        if isinstance(value, str) and value:
            return value
    return type(node).__name__


def run_sequence(
    node,
    steps: list[SequenceStep],
    *,
    observe: Optional[list[tuple[str, str, str]]] = None,
    compatibility: object = None,
) -> SequenceResult:
    """Execute ``steps`` on the fork, recording the receipt and observations.

    ``observe`` is a list of ``(label, address, calldata)`` reads taken after the
    whole sequence. A revert is recorded and stops the sequence -- a partial run
    is never reported as a completed one.
    """
    with guarded(compatibility, ExecutionTarget(name=_node_name(node)),
                 "deployed_multicontract.run_sequence"):
        return _run_sequence(node, steps, observe=observe)


def _run_sequence(node, steps: list[SequenceStep], *,
                  observe: Optional[list[tuple[str, str, str]]] = None) -> SequenceResult:
    result = SequenceResult()
    for step in steps:
        tx = {"from": step.sender, "to": step.to, "data": step.data}
        if step.value:
            tx["value"] = hex(step.value)
        try:
            tx_hash = node.rpc.call("eth_sendTransaction", [tx])
            receipt = node.rpc.call("eth_getTransactionReceipt", [tx_hash])
        except Exception as exc:  # noqa: BLE001
            result.reverted_at = step.label
            result.notes.append(f"{step.label} could not be sent: {exc}")
            break
        status = int(receipt.get("status", "0x0"), 16) if receipt else 0
        result.steps.append({
            "label": step.label,
            "tx_hash": tx_hash,
            "status": "success" if status == 1 else "reverted",
            "gas_used": int(receipt.get("gasUsed", "0x0"), 16) if receipt else 0,
            "logs": len(receipt.get("logs", [])) if receipt else 0,
        })
        if status != 1:
            result.reverted_at = step.label
            break
    else:
        result.completed = True

    for label, address, data in (observe or []):
        raw = _call(node.rpc, address, data, "latest")
        result.observations.append(StateObservation(label=label, values={"raw": raw}))
    return result
