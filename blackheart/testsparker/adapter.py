"""The TestSparker adapter contract: generate, execute, classify, never overclaim.

An adapter is a *plugin that produces executable tests*. It does not decide what a
test means -- that lives in one place (:data:`DISPOSITIONS`) so every adapter's
output is read the same way by the evaluator and by a human.

Design constraints that are not negotiable:

* ``generate()`` must be **pure and deterministic** given its seed. It returns
  tests without running anything, so a test corpus can be inspected and replayed.
* ``execute()`` must record the *real* result. If it cannot run a test it says so
  (:data:`DISPOSITION_INCONCLUSIVE`); it never assumes a pass.
* ``validate()`` rejects a malformed test before execution. An adapter that
  silently accepts garbage input and "passes" it is a false-negative factory.

Scope and authorization are **not** the adapter's job. An adapter declares what
kind of execution it needs (``requires_live_target``); the evaluator enforces the
authorization gate before calling ``execute()`` on anything that is not a local
fixture. That separation means a new adapter cannot accidentally bypass the gate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

__all__ = [
    "GeneratedTest",
    "TestOutcome",
    "SparkerAdapter",
    "DISPOSITION_CONFIRMED_DEFECT",
    "DISPOSITION_NO_SIGNAL",
    "DISPOSITION_INCONCLUSIVE",
    "DISPOSITION_REGRESSION",
    "DISPOSITIONS",
    "fingerprint",
]

#: The code under test did something that contradicts a *declared expectation*.
#: This is a candidate defect signal -- still not a confirmed vulnerability.
DISPOSITION_CONFIRMED_DEFECT = "CONFIRMED_DEFECT"
#: The test ran and behaved as expected: it exercised code without exposing a
#: difference. Exercising code is not discovery.
DISPOSITION_NO_SIGNAL = "NO_SIGNAL"
#: The test could not be run, or its result cannot be interpreted. Never a pass.
DISPOSITION_INCONCLUSIVE = "INCONCLUSIVE"
#: The test reproduces a previously-recorded defect. Distinct from a fresh signal
#: so the evaluator can count regressions without conflating them with new leads.
DISPOSITION_REGRESSION = "REGRESSION"

DISPOSITIONS = (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_NO_SIGNAL,
    DISPOSITION_INCONCLUSIVE,
    DISPOSITION_REGRESSION,
)


def fingerprint(*parts: Any) -> str:
    """A stable short hash over the given parts, for provenance and dedupe."""
    payload = json.dumps(parts, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


@dataclass
class GeneratedTest:
    """One executable test and everything needed to reproduce it.

    ``expectation`` is what the test *asserts*. It is data, not a closure, so a
    stored test can be re-run later without importing the generator.
    """

    test_id: str
    adapter: str
    #: What is being exercised, in a form the adapter can dispatch on.
    kind: str
    #: The exact input the test feeds the code under test.
    input: dict = field(default_factory=dict)
    #: What the adapter asserts should happen. Free-form per ``kind``.
    expectation: dict = field(default_factory=dict)
    #: The bytecode (hex, no 0x) under test, when the test targets raw code.
    code: str = ""
    #: Why this test exists -- the untested path or boundary it targets.
    rationale: str = ""
    #: Generator configuration that produced it, for reproducibility.
    generation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "adapter": self.adapter,
            "kind": self.kind,
            "input": self.input,
            "expectation": self.expectation,
            "code": self.code,
            "rationale": self.rationale,
            "generation": self.generation,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GeneratedTest":
        return cls(
            test_id=d["test_id"],
            adapter=d["adapter"],
            kind=d["kind"],
            input=d.get("input", {}),
            expectation=d.get("expectation", {}),
            code=d.get("code", ""),
            rationale=d.get("rationale", ""),
            generation=d.get("generation", {}),
        )


@dataclass
class TestOutcome:
    """What actually happened, and what it means -- kept strictly separate.

    ``observed`` is the raw result; ``disposition`` is the classification. A
    consumer that reads only ``disposition`` still cannot mistake "the test ran"
    for "a defect was found", because the two are different fields.
    """

    test_id: str
    disposition: str
    #: The raw execution result, so the classification can be audited.
    observed: dict = field(default_factory=dict)
    #: Human-readable reason for the disposition.
    detail: str = ""
    #: True only when the code under test contradicted a declared expectation.
    defect_signal: bool = False

    __test__ = False  # not a pytest test class despite the Test prefix

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "disposition": self.disposition,
            "observed": self.observed,
            "detail": self.detail,
            "defect_signal": self.defect_signal,
        }


@runtime_checkable
class SparkerAdapter(Protocol):
    """The contract every TestSparker adapter satisfies."""

    #: Stable adapter name, used on the CLI and in reports.
    name: str
    #: True when ``execute`` may touch a live target. The evaluator refuses to call
    #: such an adapter unless the authorization gate passed for the target.
    requires_live_target: bool

    def generate(self, *, seed: int = 0, corpus: Optional[list[dict]] = None,
                 limit: Optional[int] = None) -> list[GeneratedTest]:
        """Produce tests deterministically. Must not execute anything."""
        ...

    def validate(self, test: GeneratedTest) -> Optional[str]:
        """Return a reason the test is malformed, or ``None`` if it is runnable."""
        ...

    def execute(self, test: GeneratedTest) -> TestOutcome:
        """Run the test and return the real outcome. Never assume a pass."""
        ...
