"""Halmos -- symbolic execution.

Halmos symbolically executes Foundry-compatible test functions and asks an SMT
solver whether an assertion can fail. The result is a *counterexample*: concrete
argument values that break the assertion, which is much stronger evidence than a
static pattern match and still weaker than a reproduced exploit.

Three honesty requirements shape this adapter:

  * **Symbolic exploration is not reproduction.** A counterexample proves the
    assertion is violable under the modelled semantics; it does not prove the
    attack is profitable, reachable in a deployed system, or unprivileged. The
    finding is normalised with ``reproduction_status="symbolic-counterexample"``
    so no consumer can mistake it for a reproduced exploit.
  * **Bounded, not complete.** Halmos bounds loops and path depth. "No
    counterexample" therefore means "none within the bound", never "proven
    safe". The bound is recorded in the finding rather than dropped.
  * **Exit 1 means counterexample found.** A run that finds one is a *successful
    scan*, not a tool failure. Only other non-zero codes are failures.

Halmos needs a Foundry project (``foundry.toml``) because it reads the compiled
artifacts; a bare directory is a configuration error, not an empty result.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from ..contract import EngineState, ExecutionMetadata, ExecutionResult
from ..schema import NormalizedFinding, normalize_severity
from ...models import utcnow
from .base import SolidityEngineAdapter


class HalmosAdapter(SolidityEngineAdapter):
    name = "halmos"
    upstream_url = "https://github.com/a16z/halmos"
    license_id = "AGPL-3.0"
    description = "Symbolic execution of Foundry test assertions (SMT counterexamples)"
    CLEAN_EXIT_CODES = frozenset({0})
    #: Halmos exits 1 when at least one assertion has a counterexample.
    FINDING_EXIT_CODES = frozenset({1})
    DEFAULT_TIMEOUT_S = 1800.0

    def analysis_methods(self) -> tuple[str, ...]:
        return ("symbolic-execution",)

    def _is_foundry_project(self, root: Path) -> bool:
        return (root / "foundry.toml").is_file()

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        root = self._project_root(target)
        if not self._is_foundry_project(root):
            meta = ExecutionMetadata(
                engine=self.name, version=self.inspect_version(), argv=[],
                cwd=str(root), started_at=utcnow(), target=str(root),
                state=EngineState.CONFIGURATION_ERROR,
                note="halmos requires a Foundry project (no foundry.toml in target)",
            )
            return ExecutionResult(metadata=meta)
        result = super().execute_scan(target, **options)
        return self._explain_unrunnable(result)

    #: Markers that a Halmos run hit an unmodelled cheatcode. Such a run could not
    #: explore the harness, so it is BLOCKED on the harness -- never a clean scan
    #: and never a generic tool crash.
    _UNSUPPORTED_MARKERS = (
        "deploycode", "vm.etch", "vm.store", "vm.mockcall", "vm.prank",
        "cheatcode", "forge-std",
    )

    def _explain_unrunnable(self, result: ExecutionResult) -> ExecutionResult:
        """Reclassify a cheatcode failure as UNSUPPORTED with the remedy.

        Halmos exits non-zero and writes no report when the harness uses a
        cheatcode it does not model, which the base adapter would record as a
        generic ``FAILED``. That reads like the tool broke; in truth the harness
        is outside what Halmos can explore. Naming the cause and the remedy keeps
        a blocked run from being mistaken for a negative result.
        """
        if result.metadata.state is not EngineState.FAILED:
            return result
        blob = f"{result.raw_stdout}\n{result.raw_stderr}".lower()
        hit = next((m for m in self._UNSUPPORTED_MARKERS if m in blob), "")
        if not hit:
            return result
        result.metadata.state = EngineState.UNSUPPORTED
        result.metadata.note = (
            f"halmos could not symbolically execute this harness: it uses the "
            f"unmodelled cheatcode/import '{hit}'. This is BLOCKED on the harness, "
            f"not a clean scan. Remedy: emit a forge-std-free harness with "
            f"`blackheart.symbolic.harness` (plain `assert`, no vm.*) and re-run."
        )
        return result

    def _build_argv(self, root: Path, options: dict) -> list[str]:
        paths = self.paths()
        binary = paths.binary if paths else "halmos"
        # The report goes to the adapter's scratch directory, never into the
        # analysed project: writing there mutated a tracked fixture and let two
        # concurrent runs overwrite each other's results.
        json_out = Path(options.get("json_out") or (self._scratch_dir() / "halmos_results.json"))
        argv = [binary, "--root", str(root), "--json-output", str(json_out)]
        if options.get("match_contract"):
            argv += ["--match-contract", str(options["match_contract"])]
        if options.get("match_test"):
            argv += ["--match-test", str(options["match_test"])]
        if options.get("loop"):
            argv += ["--loop", str(int(options["loop"]))]
        if options.get("depth"):
            argv += ["--depth", str(int(options["depth"]))]
        if options.get("solver"):
            argv += ["--solver", str(options["solver"])]
        return argv

    def _collect(self, root: Path,
                 stdout: str = "", stderr: str = "") -> tuple[dict[str, str], Optional[list[dict]]]:
        path = self._scratch_dir() / "halmos_results.json"
        if not path.is_file():
            return {}, None
        data = self._read_json(path)
        if not isinstance(data, dict):
            return {"halmos_results.json": str(path)}, None
        results = data.get("test_results")
        if not isinstance(results, dict):
            return {"halmos_results.json": str(path)}, None
        records: list[dict] = []
        for contract, tests in results.items():
            if not isinstance(tests, list):
                continue
            for test in tests:
                if isinstance(test, dict):
                    records.append({**test, "contract": contract})
        return {"halmos_results.json": str(path)}, records

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for record in result.raw_records:
            # Only a non-zero per-test exit code means a counterexample was found.
            try:
                code = int(record.get("exitcode") or 0)
            except (TypeError, ValueError):
                code = 0
            if code == 0:
                continue
            finding = self._normalize_one(record, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, record: dict,
                       result: ExecutionResult) -> Optional[NormalizedFinding]:
        name = str(record.get("name") or "").strip()
        if not name:
            return None
        models = record.get("models") or []
        counterexample = _render_models(models)
        paths = record.get("num_paths") or []
        explored = paths[0] if isinstance(paths, list) and paths else ""
        bounded = record.get("num_bounded_loops")
        bound_note = (f"symbolic exploration bounded at {bounded} loop iteration(s); "
                      f"'no counterexample' means 'none within the bound'"
                      if bounded else "symbolic exploration, unbounded loops may be truncated")

        return NormalizedFinding(
            source_engine=self.name,
            engine_version=result.metadata.version,
            target_id=result.metadata.target,
            raw_artifact=result.artifacts.get("halmos_results.json", ""),
            category="assertion-violation",
            title=f"symbolic counterexample: {name}",
            description=(f"Halmos found a satisfying assignment that violates the assertion "
                         f"in {name}. {bound_note}."),
            severity=normalize_severity("high"),
            cwe="CWE-617",
            confidence="symbolic",
            component=str(record.get("contract") or ""),
            source_location=str(record.get("contract") or ""),
            attack_vector="symbolic argument assignment",
            exploit_steps=[counterexample] if counterexample else [],
            reproduction=counterexample,
            evidence_refs=[str(result.artifacts.get("halmos_results.json", ""))]
            if result.artifacts.get("halmos_results.json") else [],
            execution_environment=(f"halmos {result.metadata.version} "
                                   f"({explored} paths explored)"),
            # Deliberately NOT "reproduced": a symbolic model is not a concrete
            # execution against real state.
            reproduction_status="symbolic-counterexample",
            raw=record,
        ).finalize()


def _render_models(models: Any) -> str:
    if not isinstance(models, list) or not models:
        return ""
    lines: list[str] = []
    for entry in models[:1]:
        if not isinstance(entry, dict):
            continue
        model = entry.get("model") or {}
        if not isinstance(model, dict):
            continue
        for _, var in model.items():
            if not isinstance(var, dict):
                continue
            lines.append(f"{var.get('variable_name')} ({var.get('solidity_type')}) = "
                         f"{var.get('value')}")
    return "\n".join(lines)
