"""Execution-grade evidence for an ``ingest --synthesize`` witness.

The certifier reasons over a *model*; this module turns its best witness into a
source-level Foundry test (reusing :mod:`blackheart.pocgen`) and runs it behind
the compatibility gate (reusing :func:`blackheart.pocgen.execute_source_poc`,
which is fail-closed: no record, or no ``forge``, means nothing runs).

The model verdict is never changed here. This records an *additional*,
separately-honest execution outcome — ``PASS`` is a reproduction, not a priced
finding — so a caller can attach execution-grade evidence to a lead without the
engine ever upgrading a model result on its own.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from ..models import AttackStep
from ..pocgen import execute_source_poc, render_source_poc


def read_solidity_sources(root: str | Path) -> dict[str, str]:
    """Read every ``.sol`` file under ``root`` as ``{relative_path: text}``."""
    base = Path(root)
    if base.is_file():
        return {base.name: base.read_text(encoding="utf-8", errors="replace")}
    files: dict[str, str] = {}
    for path in sorted(base.rglob("*.sol")):
        files[path.relative_to(base).as_posix()] = path.read_text(
            encoding="utf-8", errors="replace")
    return files


def contract_path_for(contract_path: str, root: str | Path) -> str:
    """Return ``contract_path`` relative to ``root`` so it matches the source keys.

    A source-level PoC imports the contract by its path under ``src/``; the key
    the renderer derives must line up with the keys :func:`read_solidity_sources`
    produces, or the generated test imports the wrong file.
    """
    base = Path(root)
    if base.is_file():
        return base.name
    try:
        return Path(contract_path).resolve().relative_to(base.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(contract_path).name


def _best_witness(cert: Any) -> tuple[dict, list[AttackStep]]:
    """Pick one certified witness deterministically: authorization first, then shortest."""
    best: Optional[tuple[tuple[int, int], dict, list[AttackStep]]] = None
    for violation in getattr(cert, "violations", []) or []:
        steps = [AttackStep(**step) for step in violation.get("minimal_sequence", [])]
        if not steps:
            continue
        score = (
            1 if str(violation.get("invariant_id", "")).startswith("authorization:") else 0,
            -len(steps),
        )
        if best is None or score > best[0]:
            best = (score, violation, steps)
    if best is None:
        return {}, []
    return best[1], best[2]


def execute_witness(
    cert: Any,
    *,
    contract: str,
    contract_path: str,
    files: dict[str, str],
    compatibility: Any,
    repository: str,
    commit: str = "",
    timeout: int = 600,
    runner: Any = None,
    constructor_args: Optional[list[Any]] = None,
) -> dict:
    """Render the best certified witness and run it; return an honest outcome dict.

    ``status`` is one of ``PASS`` / ``BLOCKED`` / ``INCOMPLETE`` / ``UNSUPPORTED``
    / ``SKIPPED``. A ``PASS`` proves the rendered sequence reproduced under
    ``forge``; it is not a priced finding and it does not change the model verdict.
    """
    violation, steps = _best_witness(cert)
    if not steps:
        return {"status": "SKIPPED", "detail": "no certifier witness to execute",
                "invariant_id": ""}
    invariant_id = str(violation.get("invariant_id", ""))
    candidate = render_source_poc(
        files, contract, contract_path, steps, invariant_id,
        constructor_args=list(constructor_args or []),
    )
    if not candidate.rendered:
        return {"status": candidate.status or "UNSUPPORTED",
                "detail": candidate.reason or "the witness could not be rendered",
                "invariant_id": invariant_id}
    outcome = execute_source_poc(
        candidate, compatibility=compatibility,
        target_component=f"ingest:{contract}", repository=repository,
        commit=commit, timeout=timeout, runner=runner,
    )
    payload = outcome.as_dict()
    payload.setdefault("invariant_id", invariant_id)
    payload["test_source"] = candidate.solidity
    return payload
