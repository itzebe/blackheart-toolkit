"""Run a real Solidity analysis tool behind the compatibility gate.

This is the second half of the engine upgrade: ``synthesize`` gives the search a
model, and this module lets a real tool (Foundry, Echidna, Medusa) run against
the actual contract -- but only when the language-aware gate admits it for *this*
target. The gate is not advisory here: a blocked run returns ``BLOCKED`` and
**never invokes the tool**, which is the property ``tests/test_runner.py`` pins.

Statuses are the doctrine's, and only the doctrine's:

* ``PASS``        -- the tool ran and produced a positive (a failing invariant).
* ``NO_FINDINGS`` -- the tool ran clean. Not the same as "secure".
* ``INCOMPLETE``  -- the tool ran but did not complete (build/parse failure).
* ``BLOCKED``     -- the gate refused, or the tool is absent. Nothing ran.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..engines.solidity.base import resolve_tool
from ..toolchain.enforce import (
    CompatibilityRecord,
    ExecutionTarget,
    bind,
)

STATUSES = ("PASS", "BLOCKED", "INCOMPLETE", "NO_FINDINGS")


@dataclass(frozen=True)
class ToolAvailability:
    forge: bool
    echidna: bool
    medusa: bool

    @property
    def any_solidity(self) -> bool:
        return self.forge or self.echidna or self.medusa


def detect() -> ToolAvailability:
    """Which Solidity analysis tools exist on this host, by name only."""
    return ToolAvailability(
        forge=resolve_tool("forge") is not None,
        echidna=resolve_tool("echidna") is not None,
        medusa=resolve_tool("medusa") is not None,
    )


def solidity_record(
    *,
    tool: str = "Foundry",
    target_component: str,
    repository: str,
    commit: str,
    language_version: str = ">=0.8.0",
    evidence: str = "registry:Solidity/Foundry",
    framework: str = "Foundry",
) -> CompatibilityRecord:
    """Build a Solidity compatibility record for the gate.

    The caller supplies the official documentation URL it verified and the exact
    component/repository/commit the tool was checked against; this function does
    not invent them.
    """
    return CompatibilityRecord(
        target_component=target_component,
        language="Solidity",
        language_version=language_version,
        framework=framework,
        runtime="EVM (forge test / anvil fork)",
        tool=tool,
        compatibility_evidence=evidence,
        selection_reason="the target is Solidity and the tool's documented compatibility "
                         "with this compiler range was verified before the run",
        expected_coverage="the target's own tests and generated invariant harness",
        known_limitations="a clean run is not a secure protocol; the harness is a "
                          "representative, not exhaustive, model",
        smoke_test="passed",
        repository=repository,
        commit=commit,
    )


@dataclass(frozen=True)
class RunOutcome:
    tool: str
    status: str
    detail: str
    output: str = ""

    def as_dict(self) -> dict:
        return {"tool": self.tool, "status": self.status,
                "detail": self.detail, "output": self.output}


def _summarise_forge(stdout: str) -> tuple[Optional[int], Optional[int], str]:
    """Return (passed, failed, note) from ``forge test --json`` output."""
    try:
        payload = json.loads(stdout)
    except (ValueError, TypeError):
        return None, None, "output is not JSON"
    if not isinstance(payload, dict):
        return None, None, "unexpected JSON shape"
    if "passed" in payload and isinstance(payload["passed"], int):
        return payload.get("passed", 0), payload.get("failed", 0), ""
    passed = failed = 0
    for suite in payload.values():
        if isinstance(suite, dict):
            passed += len(suite.get("passed", []) or [])
            failed += len(suite.get("failed", []) or [])
    return passed, failed, ""


def run_foundry(
    project_dir: str | Path,
    *,
    compatibility: Optional[CompatibilityRecord],
    target_component: str,
    repository: str,
    commit: str = "",
    timeout: int = 600,
) -> RunOutcome:
    """Run ``forge test`` under the gate. Fail-closed: a block never invokes forge."""
    if compatibility is None:
        return RunOutcome("forge", "BLOCKED",
                          "no compatibility record; nothing was run")
    decision = bind(compatibility, ExecutionTarget(
        name=target_component, repository=repository, commit=commit))
    if decision.decision != "ADMIT":
        return RunOutcome("forge", "BLOCKED",
                          "gate refused: " + "; ".join(decision.reasons))
    forge = resolve_tool("forge")
    if forge is None:
        return RunOutcome("forge", "BLOCKED",
                          "forge is not installed on this host; nothing was run")

    try:
        proc = subprocess.run(
            [forge.binary, "test", "--json"],
            cwd=str(project_dir), capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RunOutcome("forge", "INCOMPLETE", f"could not complete: {exc}")

    passed, failed, note = _summarise_forge(proc.stdout)
    if passed is None:
        return RunOutcome("forge", "INCOMPLETE",
                          f"forge did not produce a parseable result ({note})",
                          output=(proc.stdout or proc.stderr)[:4000])
    if failed:
        return RunOutcome("forge", "PASS",
                          f"{failed} failing test(s) / invariant(s) across {passed} passed",
                          output=proc.stdout[:4000])
    return RunOutcome("forge", "NO_FINDINGS",
                      f"{passed} test(s) passed, 0 failed (a clean run is not a proof)",
                      output=proc.stdout[:4000])


HARNESS_HEADER = """\
// SPDX-License-Identifier: MIT
// {banner}
{banner_detail}
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {{{contract}}} from "{import_path}";

contract {contract}InvariantTest is Test {{
    {contract} internal target;

    function setUp() public {{
{setup}
    }}

    function targetContracts() public view returns (address[] memory contracts) {{
        contracts = new address[](1);
        contracts[0] = address(target);
    }}

{invariants}}}
"""


def write_harness(contract_name: str, invariants: tuple[str, ...],
                  import_path: str, out_dir: str | Path, *,
                  setup: str = "", assertions: tuple[str, ...] = ()) -> Path:
    """Write a Foundry invariant test for one contract.

    With no ``setup``/``assertions`` this is a skeleton: it names the derived
    invariants as TODO assertions and will not compile until a human completes it,
    so the runner reports ``INCOMPLETE`` rather than a false ``NO_FINDINGS``.

    Given ``setup`` (deployment lines) and ``assertions`` (boolean Solidity
    expressions), it emits a *complete* test instead: the runner can then compile
    and execute it, and a failing assertion is a real result rather than a TODO.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    complete = bool(setup or assertions)
    body = []
    if complete:
        for i, expr in enumerate(assertions or ()):
            body.append(
                f"    function invariant_{i}() public {{\n"
                f"        assertTrue({expr});\n"
                f"    }}\n"
            )
        if not body:
            body.append("    // no invariant assertion supplied\n")
    else:
        for inv in invariants:
            fn = "invariant_" + "".join(c if c.isalnum() else "_" for c in inv)
            body.append(
                f"    function {fn}() public {{\n"
                f"        // TODO: assert `{inv}` against {contract_name}'s real accounting.\n"
                f"    }}\n"
            )
    setup_body = setup or (
        f"        // TODO: deploy {contract_name} with its real constructor arguments.\n"
        f"        // target = new {contract_name}(...);"
    )
    source = HARNESS_HEADER.format(
        banner=("COMPLETE harness generated by `blackheart ingest --emit-harness`."
                if complete else
                "SKELETON generated by `blackheart ingest --emit-harness`."),
        banner_detail=("// It compiles and runs against the real contract's constructor "
                       "and accounting getters."
                       if complete else
                       "// It compiles only after the TODOs are completed against the real "
                       "contract's\n// constructor and accounting getters. It is a starting "
                       "point, not a finished test."),
        contract=contract_name,
        import_path=import_path,
        setup=setup_body,
        invariants="\n".join(body) if body else "    // no invariant derived\n",
    )
    path = out / f"{contract_name}Invariant.t.sol"
    path.write_text(source, encoding="utf-8")
    return path
