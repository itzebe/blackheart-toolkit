"""Differential fuzzing of two compiled runtime bytecodes.

The vulnerable and guarded contracts are the same protocol at two revisions. This
module deploys each runtime code into the concrete EVM world, runs the same
calldata against both, and reports where they disagree -- an outcome difference
(revert vs success), a storage difference, or a return-data difference.

It is a *differential* tool: a divergence is a lead that one revision behaves
differently, not proof that either is wrong. The guarded twin is the control, so a
divergence is only interesting when the guarded side is the one that refuses.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .evmworld import Account, TxResult, World, execute_message

DEFAULT_ADDRESS = 0xC0DE
DEFAULT_CALLER = 0xA11CE
MASK = (1 << 256) - 1


@dataclass
class Divergence:
    calldata: str
    kind: str  # outcome | state | return
    vulnerable: dict
    guarded: dict

    def to_dict(self) -> dict:
        return {"calldata": self.calldata, "kind": self.kind,
                "vulnerable": dict(self.vulnerable), "guarded": dict(self.guarded)}


@dataclass
class BytecodeDiff:
    checked: int = 0
    identical: int = 0
    divergences: list[Divergence] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.divergences)

    def to_dict(self) -> dict:
        return {"checked": self.checked, "identical": self.identical,
                "divergences": [d.to_dict() for d in self.divergences]}


def calldata_words(values: Iterable[int]) -> list[bytes]:
    """Encode each integer as one 32-byte ABI word."""
    return [int(v).to_bytes(32, "big") for v in values]


def run_bytecode(
    code: bytes,
    calldata: bytes = b"",
    *,
    address: int = DEFAULT_ADDRESS,
    caller: int = DEFAULT_CALLER,
    value: int = 0,
    storage: Optional[dict[int, int]] = None,
    env: Optional[dict[str, int]] = None,
    collect_pcs: bool = False,
) -> TxResult:
    """Deploy ``code`` at ``address`` and run one top-level message."""
    world = World({address: Account(code=bytes(code), storage=dict(storage or {}))})
    return execute_message(world, caller=caller, to=address, calldata=calldata,
                           value=value, env=env, collect_pcs=collect_pcs)


def _summary(result: TxResult) -> dict:
    return {
        "succeeded": result.succeeded,
        "halt": str(result.halt),
        "return_data": "0x" + result.return_data.hex(),
        "state_diff": result.state_diff,
    }


def _same(left: dict, right: dict) -> bool:
    return (left["succeeded"] == right["succeeded"]
            and left["state_diff"] == right["state_diff"]
            and left["return_data"] == right["return_data"])


def differential_fuzz(
    vulnerable: bytes,
    guarded: bytes,
    calldatas: Iterable[bytes],
    *,
    storage: Optional[dict[int, int]] = None,
    env: Optional[dict[str, int]] = None,
) -> BytecodeDiff:
    """Run every calldata against both revisions and report disagreements."""
    report = BytecodeDiff()
    for calldata in calldatas:
        left = _summary(run_bytecode(vulnerable, calldata, storage=storage, env=env))
        right = _summary(run_bytecode(guarded, calldata, storage=storage, env=env))
        report.checked += 1
        if _same(left, right):
            report.identical += 1
            continue
        if left["succeeded"] != right["succeeded"]:
            kind = "outcome"
        elif left["state_diff"] != right["state_diff"]:
            kind = "state"
        else:
            kind = "return"
        report.divergences.append(Divergence("0x" + calldata.hex(), kind, left, right))
    return report


@dataclass
class CoverageReport:
    iterations: int = 0
    corpus_size: int = 0
    covered: list[int] = field(default_factory=list)
    new_paths: int = 0
    reverting: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "iterations": self.iterations,
            "corpus_size": self.corpus_size,
            "covered": list(self.covered),
            "new_paths": self.new_paths,
            "reverting": list(self.reverting),
        }


def _words(calldata: bytes) -> list[int]:
    return ([int.from_bytes(calldata[i:i + 32].ljust(32, b"\x00"), "big")
             for i in range(0, len(calldata), 32)] or [0])


def _encode(words: Iterable[int]) -> bytes:
    return b"".join((int(word) & MASK).to_bytes(32, "big") for word in words)


def coverage_fuzz(
    code: bytes,
    seeds: Iterable[bytes] = (),
    *,
    iterations: int = 500,
    max_corpus: int = 64,
    seed: int = 0,
    storage: Optional[dict[int, int]] = None,
    env: Optional[dict[str, int]] = None,
) -> CoverageReport:
    """Keep calldata that reaches new bytecode, then mutate it further.

    The corpus is the inputs that taught the run something. A mutation is kept
    only when it executes a program counter no earlier input executed, so the
    budget goes to new behaviour rather than to repetition. Determinism comes
    from ``seed``: the same seed and inputs give the same corpus.
    """
    rng = random.Random(seed)
    corpus: list[bytes] = []
    covered: set[int] = set()
    reverting: list[str] = []
    report = CoverageReport(iterations=iterations)

    def observe(data: bytes) -> bool:
        result = run_bytecode(code, data, storage=storage, env=env, collect_pcs=True)
        pcs = set(result.frame.pcs)
        new = pcs - covered
        covered.update(pcs)
        if not result.succeeded:
            encoded = "0x" + data.hex()
            if encoded not in reverting and len(reverting) < 32:
                reverting.append(encoded)
        return bool(new)

    for data in seeds:
        data = bytes(data)
        if data not in corpus:
            corpus.append(data)
    for data in list(corpus):
        observe(data)

    for _ in range(iterations):
        base = rng.choice(corpus) if corpus else b""
        words = _words(base)
        index = rng.randrange(len(words))
        choice = rng.randrange(6)
        if choice == 0:
            words[index] ^= 1 << rng.randrange(256)
        elif choice == 1:
            words[index] = (words[index] + rng.choice([-2, -1, 1, 2])) & MASK
        elif choice == 2:
            words[index] = rng.choice([0, 1, 2, (1 << 255), MASK])
        elif choice == 3:
            words.append(rng.randrange(1 << 64))
        elif choice == 4:
            words[index] = rng.randrange(1 << 256)
        elif len(words) > 1:
            del words[index]
        data = _encode(words)
        if observe(data) and data not in corpus:
            report.new_paths += 1
            corpus.append(data)
            if len(corpus) > max_corpus:
                corpus.pop(1)

    report.corpus_size = len(corpus)
    report.covered = sorted(covered)
    report.reverting = reverting
    return report
