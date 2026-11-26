"""Slither -- static analysis.

Slither walks the Solidity AST/IR and runs ~100 detectors. Its output is a
*static observation*: it can prove a pattern exists, never that the pattern is
exploitable. Every finding here is therefore normalised with
``reproduction_status="not_attempted"`` and a disposition the orchestrator resets
to ``NEEDS_MORE_EVIDENCE`` regardless of what Slither claims.

Mapping notes that matter for correctness:

  * Slither's ``impact`` is its own severity scale; ``confidence`` is a separate
    axis and is preserved verbatim in ``confidence`` rather than folded into
    severity (a High-impact/Low-confidence detector is not a High finding).
  * The first ``elements`` entry with a source mapping gives the location; the
    enclosing contract gives ``component``. Reading only the description text
    would lose the structured location and break fingerprint deduplication.
  * ``--json`` writes a file; Slither also prints the same report to stdout.
    The file is the artifact, so a truncated stdout cannot lose the findings.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ..contract import ExecutionResult
from ..schema import NormalizedFinding, normalize_severity
from .base import SolidityEngineAdapter, solidity_files

#: Slither detector -> CWE. Only the detectors where the mapping is defensible;
#: an absent entry means "no CWE asserted", never a guessed one.
_DETECTOR_CWE = {
    "reentrancy-eth": "CWE-841",
    "reentrancy-no-eth": "CWE-841",
    "reentrancy-benign": "CWE-841",
    "reentrancy-events": "CWE-841",
    "unchecked-transfer": "CWE-252",
    "unchecked-lowlevel": "CWE-252",
    "unchecked-send": "CWE-252",
    "arbitrary-send-eth": "CWE-284",
    "arbitrary-send-erc20": "CWE-284",
    "controlled-delegatecall": "CWE-829",
    "delegatecall-loop": "CWE-829",
    "suicidal": "CWE-284",
    "tx-origin": "CWE-287",
    "weak-randomness": "CWE-330",
    "divide-before-multiply": "CWE-682",
    "incorrect-equality": "CWE-697",
    "locked-ether": "CWE-667",
    "msg-value-loop": "CWE-834",
    "shadowing-state": "CWE-710",
    "uninitialized-state": "CWE-457",
    "uninitialized-storage": "CWE-457",
    "uninitialized-local": "CWE-457",
    "write-after-write": "CWE-670",
    "boolean-equal": "CWE-697",
}

#: Slither detector -> BLACKHEART attack category, so the orchestrator's
#: chain-correlation edges can fire on Slither output like any other engine's.
_DETECTOR_CATEGORY = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "controlled-delegatecall": "access-control",
    "arbitrary-send-eth": "access-control",
    "arbitrary-send-erc20": "access-control",
    "suicidal": "access-control",
    "tx-origin": "access-control",
    "unchecked-transfer": "silent-transfer-failure",
    "unchecked-lowlevel": "silent-transfer-failure",
    "divide-before-multiply": "rounding-precision",
    "incorrect-equality": "logic-error",
    "weak-randomness": "randomness",
    "locked-ether": "denial-of-service",
}


class SlitherAdapter(SolidityEngineAdapter):
    name = "slither"
    upstream_url = "https://github.com/crytic/slither"
    license_id = "AGPL-3.0"
    description = "Static analysis of Solidity (AST/IR detectors)"
    #: Slither exits 0 on a clean analysis and 255 when detectors fire -- and
    #: also 255 on an internal error. The exit code alone is therefore ambiguous;
    #: the base adapter resolves it from the JSON artifact (a real analysis writes
    #: ``success: true`` with a detectors list, an error writes ``success: false``).
    CLEAN_EXIT_CODES = frozenset({0})
    FINDING_EXIT_CODES = frozenset({255})
    DEFAULT_TIMEOUT_S = 900.0

    def analysis_methods(self) -> tuple[str, ...]:
        return ("static-analysis",)

    def _build_argv(self, root: Path, options: dict) -> list[str]:
        paths = self.paths()
        binary = paths.binary if paths else "slither"
        # Written to the adapter's scratch directory, never into the analysed
        # project, so a run cannot mutate a tracked fixture or collide with
        # another sandbox analysing the same target.
        out = Path(options.get("json_out") or (self._scratch_dir() / "slither_results.json"))
        # Slither refuses to overwrite an existing report ("the overwrite is
        # prevented") and then exits 255 with a stale artifact in place, which
        # reads as a failed scan. Removing it first makes a re-run behave exactly
        # like a first run -- the difference between a reproducible scan and a
        # confusing one.
        try:
            out.unlink(missing_ok=True)
        except OSError:
            pass
        argv = [binary, *self._target_args(root), "--json", str(out)]
        # Vendored dependencies and test scaffolding are not the target's code;
        # reporting them inflates the finding count with third-party noise.
        filter_paths = options.get("filter_paths", "lib,node_modules,test,script")
        if filter_paths:
            argv += ["--filter-paths", str(filter_paths)]
        for detector in options.get("detectors") or []:
            argv += ["--detect", str(detector)]
        for excluded in options.get("exclude") or []:
            argv += ["--exclude", str(excluded)]
        if options.get("exclude_informational"):
            argv.append("--exclude-informational")
        if options.get("exclude_low"):
            argv.append("--exclude-low")
        if options.get("compile_force_framework"):
            argv += ["--compile-force-framework", str(options["compile_force_framework"])]
        if paths and paths.solc:
            argv += ["--solc", paths.solc]
        return argv

    #: crytic-compile can only resolve a bare directory when a compilation
    #: framework declares how to build it. Without one it does not fail: it
    #: analyses *zero* contracts and exits 0, which Slither reports as
    #: ``success: true`` with an empty detector list -- a silent "clean" scan of
    #: nothing. These files are the frameworks it detects.
    _FRAMEWORK_FILES = (
        "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
        "truffle-config.js", "truffle.js", "brownie-config.yaml",
        "ape-config.yaml", "brownie-config.yml",
    )

    def _target_args(self, root: Path) -> list[str]:
        """The path argument(s) that make crytic-compile analyse real code."""
        if any((root / f).is_file() for f in self._FRAMEWORK_FILES):
            return ["."]
        # No framework: hand crytic-compile the source directory it can walk
        # directly, preferring the conventional layout over the project root
        # (which would also pull in node_modules/lib).
        for name in ("contracts", "src"):
            candidate = root / name
            if candidate.is_dir() and solidity_files(candidate):
                return [name]
        files = solidity_files(root)
        if files:
            return [str(p.relative_to(root)) for p in files]
        return ["."]

    #: ``". analyzed (0 contracts with 100 detectors), 0 result(s) found"`` --
    #: the message a framework-less project produces. Also covers the wording
    #: older Slither releases use ("No contract was analyzed").
    _NOTHING_ANALYSED = re.compile(
        r"analy[sz]ed\s*\(\s*0\s+contracts?\b|No contract was analy[sz]ed",
        re.IGNORECASE,
    )

    @classmethod
    def _analysed_nothing(cls, stdout: str) -> bool:
        return bool(stdout and cls._NOTHING_ANALYSED.search(stdout))

    def _collect(self, root: Path,
                 stdout: str = "", stderr: str = "") -> tuple[dict[str, str], Optional[list[dict]]]:
        candidates = [self._scratch_dir() / "slither_results.json"]
        if self.config.get("json_out"):
            candidates.insert(0, Path(str(self.config["json_out"])))
        artifacts: dict[str, str] = {}
        for path in candidates:
            if not path.is_file():
                continue
            artifacts["slither_results.json"] = str(path)
            data = self._read_json(path)
            if not isinstance(data, dict):
                return artifacts, None
            # `success: false` means Slither could not analyse at all (compile
            # error, unsupported construct). That is not a clean scan and not a
            # findings report -- it is unparseable, and the base adapter turns it
            # into PARTIAL/FAILED rather than "no findings".
            if data.get("success") is False:
                return artifacts, None
            results = data.get("results")
            if not isinstance(results, dict):
                return artifacts, None
            # A genuinely clean scan and a scan of *nothing* produce the same
            # JSON (``success: true``, ``results: {}``), so the report alone
            # cannot tell them apart. Slither prints the contract count only on
            # stdout; a zero-contract run is an unanalysed target, never "clean".
            if self._analysed_nothing(stdout) or self._analysed_nothing(stderr):
                return artifacts, None
            detectors = results.get("detectors")
            if detectors is None:
                detectors = []
            if not isinstance(detectors, list):
                return artifacts, None
            return artifacts, [d for d in detectors if isinstance(d, dict)]
        return artifacts, None

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        version = result.metadata.version
        for record in result.raw_records:
            finding = self._normalize_one(record, version, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, record: dict, version: str,
                       result: ExecutionResult) -> Optional[NormalizedFinding]:
        detector = str(record.get("check") or "").strip()
        if not detector:
            return None
        description = str(record.get("description") or "").strip()
        elements = record.get("elements") or []
        component, location = _element_location(elements)
        impact = str(record.get("impact") or "")
        confidence = str(record.get("confidence") or "")

        return NormalizedFinding(
            source_engine=self.name,
            engine_version=version,
            target_id=result.metadata.target,
            raw_artifact=result.artifacts.get("slither_results.json", ""),
            category=_DETECTOR_CATEGORY.get(detector, "static-analysis"),
            title=f"{detector} ({impact}/{confidence})" if impact else detector,
            description=description,
            severity=normalize_severity(impact),
            cwe=_DETECTOR_CWE.get(detector, ""),
            confidence=confidence,
            component=component,
            source_location=location,
            # A static detector does not execute anything, so there is no
            # attack vector or exploit step to report -- claiming one would be
            # inventing evidence. The orchestrator's gate is the only route up.
            attack_vector="",
            preconditions=[],
            exploit_steps=[],
            reproduction="",
            evidence_refs=[str(result.artifacts.get("slither_results.json", ""))]
            if result.artifacts.get("slither_results.json") else [],
            execution_environment=f"slither {version}",
            impact="",
            remediation="",
            raw=record,
        ).finalize()


def _element_location(elements: Any) -> tuple[str, str]:
    """Extract ``(contract, "file:line")`` from Slither's element tree."""
    if not isinstance(elements, list):
        return "", ""
    for element in elements:
        if not isinstance(element, dict):
            continue
        mapping = element.get("source_mapping") or {}
        if not isinstance(mapping, dict):
            continue
        filename = str(mapping.get("filename_relative") or mapping.get("filename_short") or "")
        if not filename:
            continue
        lines = mapping.get("lines") or []
        line = str(lines[0]) if isinstance(lines, list) and lines else ""
        location = f"{filename}:{line}" if line else filename
        type_fields = element.get("type_specific_fields") or {}
        parent = type_fields.get("parent") if isinstance(type_fields, dict) else None
        contract = ""
        if isinstance(parent, dict):
            contract = str(parent.get("name") or "")
        if not contract:
            contract = str(element.get("name") or "")
        return contract, location
    return "", ""
