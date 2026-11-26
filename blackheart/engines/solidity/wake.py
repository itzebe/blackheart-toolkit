"""Wake -- independent static analysis.

Wake (Ackee Blockchain) implements its own Solidity compiler front end and its
own detector set, so its output is *independent* of Slither's rather than a
re-skin. That independence is the whole reason to run both: when Slither and Wake
report the same defect, the orchestrator marks the cluster corroborated, and when
only one does, that difference is real information.

Wake writes ``.wake/detections.json`` when asked for JSON export. It exits 0 on a
clean run, 1 when detectors fire, and higher codes for a compile/tool failure --
so the "found something" code is declared explicitly rather than guessed.

Wake's detector names overlap Slither's semantically but not lexically. The
category map below is what lets the orchestrator collapse
``reentrancy`` (Wake) and ``reentrancy-eth`` (Slither) into one root cause
instead of counting the same bug twice.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..contract import ExecutionResult
from ..schema import NormalizedFinding, normalize_severity
from .base import SolidityEngineAdapter

_DETECTOR_CWE = {
    "reentrancy": "CWE-841",
    "tx-origin": "CWE-287",
    "unprotected-selfdestruct": "CWE-284",
    "unsafe-delegatecall": "CWE-829",
    "unchecked-return-value": "CWE-252",
    "unsafe-erc20-call": "CWE-252",
    "msg-value-nonpayable-function": "CWE-670",
    "balance-relied-on": "CWE-697",
    "missing-return": "CWE-394",
}

_DETECTOR_CATEGORY = {
    "reentrancy": "reentrancy",
    "tx-origin": "access-control",
    "unprotected-selfdestruct": "access-control",
    "unsafe-delegatecall": "access-control",
    "unchecked-return-value": "silent-transfer-failure",
    "unsafe-erc20-call": "silent-transfer-failure",
    "balance-relied-on": "logic-error",
    "incorrect-interface": "logic-error",
}


class WakeAdapter(SolidityEngineAdapter):
    name = "wake"
    upstream_url = "https://github.com/Ackee-Blockchain/wake"
    license_id = "ISC"
    description = "Independent static analysis of Solidity (own compiler front end)"
    CLEAN_EXIT_CODES = frozenset({0})
    #: Wake exits non-zero when at least one detector fired. Both 2 and 3 are
    #: observed across versions for that same outcome (4.22.2 exits 2 with 35
    #: detections and 0 on a clean control contract), so the exit code alone
    #: cannot separate "found something" from "failed". The detections artifact is
    #: the real discriminator: a finding exit code with no parseable artifact is
    #: reported FAILED, never COMPLETED.
    FINDING_EXIT_CODES = frozenset({2, 3})
    DEFAULT_TIMEOUT_S = 900.0

    def analysis_methods(self) -> tuple[str, ...]:
        return ("static-analysis", "property-fuzzing")

    def _build_argv(self, root: Path, options: dict) -> list[str]:
        paths = self.paths()
        binary = paths.binary if paths else "wake"
        # `--export` must precede the subcommand: it is an option of the `detect`
        # group, not of `all`.
        argv = [binary, "detect", "--export", "json"]
        if options.get("only"):
            argv += ["--only", str(options["only"])]
        for excluded in options.get("exclude") or []:
            argv += ["--exclude", str(excluded)]
        if options.get("ignore_errors"):
            argv.append("--ignore-errors")
        argv.append("all")
        return argv

    def _collect(self, root: Path,
                 stdout: str = "", stderr: str = "") -> tuple[dict[str, str], Optional[list[dict]]]:
        path = root / ".wake" / "detections.json"
        if not path.is_file():
            return {}, None
        data = self._read_json(path)
        if not isinstance(data, list):
            return {".wake/detections.json": str(path)}, None
        return {".wake/detections.json": str(path)}, [d for d in data if isinstance(d, dict)]

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for record in result.raw_records:
            finding = self._normalize_one(record, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, record: dict,
                       result: ExecutionResult) -> Optional[NormalizedFinding]:
        detector = str(record.get("detector_name") or "").strip()
        if not detector:
            return None
        detection = record.get("detection") or {}
        if not isinstance(detection, dict):
            detection = {}
        message = str(detection.get("message") or "").strip()
        location = detection.get("location") or {}
        if not isinstance(location, dict):
            location = {}
        relative = str(location.get("relative_path") or location.get("path") or "")
        line = location.get("start_line")
        source_location = f"{relative}:{line}" if relative and line else relative
        contract = str(location.get("contract") or "")

        return NormalizedFinding(
            source_engine=self.name,
            engine_version=result.metadata.version,
            target_id=result.metadata.target,
            raw_artifact=result.artifacts.get(".wake/detections.json", ""),
            category=_DETECTOR_CATEGORY.get(detector, "static-analysis"),
            title=f"{detector} ({record.get('impact', '')}/{record.get('confidence', '')})",
            description=message,
            severity=normalize_severity(record.get("impact")),
            cwe=_DETECTOR_CWE.get(detector, ""),
            confidence=str(record.get("confidence") or ""),
            component=contract,
            source_location=source_location,
            evidence_refs=[str(record.get("uri"))] if record.get("uri") else [],
            execution_environment=f"wake {result.metadata.version}",
            raw=record,
        ).finalize()
