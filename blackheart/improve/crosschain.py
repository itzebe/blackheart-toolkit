"""Deterministic bridge-replay and oracle-freshness models.

A bridge is a replay machine with an authentication boundary. An oracle is a
freshness and deviation machine. Both are small enough to model honestly: the
bridge records source chain, destination chain, sender, nonce and payload hash;
the oracle records the last update, a heartbeat and a reference price. The
models answer only the question they are given, and every refusal names its
cause.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass(frozen=True)
class BridgeMessage:
    source_chain: int
    dest_chain: int
    sender: str
    nonce: str
    payload_hash: str

    def to_dict(self) -> dict:
        return {
            "source_chain": self.source_chain, "dest_chain": self.dest_chain,
            "sender": self.sender, "nonce": self.nonce,
            "payload_hash": self.payload_hash,
        }


@dataclass
class BridgeResult:
    status: str  # ACCEPTED | REPLAYED | REJECTED_SOURCE | REJECTED_CHAIN | REJECTED_AUTH
    reason: str

    @property
    def accepted(self) -> bool:
        return self.status == "ACCEPTED"

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason}


@dataclass
class BridgeReplayModel:
    dest_chain: int
    allowed_source_chains: frozenset[int]
    allowed_senders: frozenset[str] = field(default_factory=frozenset)
    seen_nonces: set[str] = field(default_factory=set)

    def process(self, message: BridgeMessage, *, authenticated: bool = True) -> BridgeResult:
        """Apply the bridge's checks in the order that matters for replay safety."""
        if message.dest_chain != self.dest_chain:
            return BridgeResult("REJECTED_CHAIN", (
                f"message targets chain {message.dest_chain}, this bridge is "
                f"chain {self.dest_chain}"))
        if message.source_chain not in self.allowed_source_chains:
            return BridgeResult("REJECTED_SOURCE", (
                f"source chain {message.source_chain} is not allowlisted"))
        if self.allowed_senders and message.sender not in self.allowed_senders:
            return BridgeResult("REJECTED_AUTH", (
                f"sender {message.sender} is not allowlisted"))
        if not authenticated:
            return BridgeResult("REJECTED_AUTH", "message authentication failed")
        key = f"{message.source_chain}:{message.sender}:{message.nonce}"
        if key in self.seen_nonces:
            return BridgeResult("REPLAYED", f"nonce {key} was already consumed")
        self.seen_nonces.add(key)
        return BridgeResult("ACCEPTED", "message is authentic, in scope and new")


@dataclass(frozen=True)
class OracleReading:
    price: int
    updated_at: int
    source: str = ""

    def to_dict(self) -> dict:
        return {"price": self.price, "updated_at": self.updated_at,
                "source": self.source}


@dataclass
class OracleStatus:
    status: str  # FRESH | STALE | DEVIATED | NO_REFERENCE
    age_seconds: int = 0
    deviation_bps: int = 0
    reason: str = ""

    def to_dict(self) -> dict:
        return {"status": self.status, "age_seconds": self.age_seconds,
                "deviation_bps": self.deviation_bps, "reason": self.reason}


def oracle_status(
    reading: OracleReading,
    *,
    now: int,
    heartbeat: int,
    reference_price: Optional[int] = None,
    max_deviation_bps: int = 500,
) -> OracleStatus:
    """Report staleness first, then deviation from a declared reference."""
    if heartbeat <= 0:
        raise ValueError("heartbeat must be positive")
    age = max(0, int(now) - int(reading.updated_at))
    if age > heartbeat:
        return OracleStatus("STALE", age, 0,
                            f"last update is {age}s old; heartbeat is {heartbeat}s")
    if reference_price is None or reference_price <= 0:
        return OracleStatus("NO_REFERENCE", age, 0,
                            "no reference price was supplied; deviation is unverified")
    deviation = abs(reading.price - reference_price) * 10_000 // reference_price
    if deviation > max_deviation_bps:
        return OracleStatus("DEVIATED", age, deviation, (
            f"price deviates {deviation} bps from reference; limit is "
            f"{max_deviation_bps} bps"))
    return OracleStatus("FRESH", age, deviation, "fresh and inside the deviation limit")


def bridge_replay_sequence(
    model: BridgeReplayModel,
    messages: Iterable[BridgeMessage],
    *,
    authenticated: bool = True,
) -> list[BridgeResult]:
    """Process a declared sequence; a second delivery of one nonce is REPLAYED."""
    return [model.process(m, authenticated=authenticated) for m in messages]


__all__ = [
    "BridgeMessage", "BridgeResult", "BridgeReplayModel",
    "OracleReading", "OracleStatus", "oracle_status", "bridge_replay_sequence",
]
