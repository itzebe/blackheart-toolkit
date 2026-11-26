"""TestSparker: generate executable tests, then run them, and report honestly.

The temptation with a "test generator" is to equate *generation* with *discovery*:
emit a test, watch it fail, and call the failure a vulnerability. That is the single
most common way an automated tool manufactures false findings, and this package is
built to make it impossible.

The rules encoded here:

1. **A generated test is a question, not an answer.** It is only meaningful after
   it runs. ``TestOutcome`` records the real execution result.
2. **A failing test is not a vulnerability.** ``Disposition`` separates "the code
   under test behaved differently from the model" from "a defect was confirmed".
   Only an outcome that matches a *declared expectation* is a defect signal, and
   even then it is a candidate, not a finding.
3. **Every test carries provenance**: the generator, its configuration, the seed,
   the input, and the exact bytes under test. Two runs with the same seed must
   produce the same tests.
4. **Inconclusive is a first-class result.** A test the adapter could not run, or
   whose result it cannot interpret, is ``INCONCLUSIVE`` -- never a pass and never
   a finding.

Adapters implement :class:`SparkerAdapter`. The first one,
:class:`~blackheart.testsparker.dispatch.DispatchSparker`, targets the dispatcher
analysis: it generates calls against real and synthesised bytecode, executes them
in the deterministic interpreter, and checks the *analysis* against the
*execution*. A disagreement is a real defect in the analyser -- which is exactly
how the via-IR gap was found, made continuous and automatic.
"""

from __future__ import annotations

from .adapter import (
    DISPOSITION_CONFIRMED_DEFECT,
    DISPOSITION_INCONCLUSIVE,
    DISPOSITION_NO_SIGNAL,
    DISPOSITION_REGRESSION,
    GeneratedTest,
    SparkerAdapter,
    TestOutcome,
)
from .dispatch import DispatchSparker
from .registry import adapter_names, get_adapter

__all__ = [
    "GeneratedTest",
    "TestOutcome",
    "SparkerAdapter",
    "DispatchSparker",
    "get_adapter",
    "adapter_names",
    "DISPOSITION_CONFIRMED_DEFECT",
    "DISPOSITION_NO_SIGNAL",
    "DISPOSITION_INCONCLUSIVE",
    "DISPOSITION_REGRESSION",
]
