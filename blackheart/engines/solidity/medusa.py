"""Medusa -- coverage-guided sequence fuzzing.

Medusa explores *transaction sequences* rather than single calls, so it reaches
bugs that need ordered state (a deposit, then a manipulation, then a borrow) that
a stateless fuzzer and a bounded symbolic search both miss. Its corpus and
shrunk call sequences are the reproducibility artifact: a finding that carries a
replayable sequence can be verified by a human, one that carries a stack trace
cannot.

Operational facts encoded here, each learned from a real run rather than assumed:

  * **A target contract must be named.** With ``targetContracts: []`` and more
    than one compiled contract, Medusa aborts with "specify target contract(s)".
    The adapter therefore derives the target from the config or the source, and
    refuses with a configuration error when it cannot.
  * **Property predicates must be configured.** Medusa does not enable
    ``property_*`` detection by default in the shape this repo ships; the
    ``testing.propertyTesting`` block must be present or it aborts with "no
    assertion, property, optimization, or custom tests were found".
  * **Exit 7 means a test failed.** That is a successful scan with findings. Exit
    0 means everything passed. Anything else is a real tool failure.

The adapter writes a per-run ``medusa.json`` under the run's own directory so two
sandboxes never share a corpus or overwrite each other's config.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ...models import utcnow
from ..contract import EngineState, ExecutionMetadata, ExecutionResult
from ..schema import NormalizedFinding, normalize_severity
from .base import SolidityEngineAdapter, solidity_files


class MedusaAdapter(SolidityEngineAdapter):
    name = "medusa"
    upstream_url = "https://github.com/crytic/medusa"
    license_id = "AGPL-3.0"
    description = "Coverage-guided stateful transaction-sequence fuzzing"
    CLEAN_EXIT_CODES = frozenset({0})
    #: Medusa exits 7 when at least one test failed.
    FINDING_EXIT_CODES = frozenset({7})
    DEFAULT_TIMEOUT_S = 1800.0

    def analysis_methods(self) -> tuple[str, ...]:
        return ("sequence-fuzzing",)

    # -- target discovery -------------------------------------------------- #
    def _target_contracts(self, root: Path, options: dict) -> list[str]:
        explicit = options.get("target_contracts") or self.config.get("target_contracts")
        if explicit:
            return [str(c) for c in explicit] if isinstance(explicit, (list, tuple)) else [str(explicit)]
        # Prefer a contract that declares a fuzzable predicate, then any contract.
        names: list[str] = []
        predicate: list[str] = []
        for path in solidity_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in re.finditer(r"\b(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)", text):
                name = match.group(1)
                if name not in names:
                    names.append(name)
            if "property_" in text or "echidna_" in text:
                for match in re.finditer(r"\b(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)", text):
                    if match.group(1) not in predicate:
                        predicate.append(match.group(1))
        return predicate or names

    def _harness(self, root: Path, options: dict) -> Optional[Path]:
        """The harness source that declares the fuzzable predicates."""
        explicit = options.get("harness") or self.config.get("harness")
        if explicit:
            p = Path(str(explicit))
            if not p.is_absolute():
                p = root / p
            return p if p.is_file() else None
        for path in solidity_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "function property_" in text or "function echidna_" in text:
                return path
        return None

    def _contracts_in(self, path: Path) -> list[str]:
        """The concrete contracts declared in one source file."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return re.findall(r"^\s*contract\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.MULTILINE)

    def _compile_args(self, root: Path, options: dict) -> list[str]:
        """crytic-compile flags that make a Foundry-layout harness compile.

        crytic-compile's Foundry platform shells out to ``forge build``, whose
        build-info references generated ``foundry-pp/DeployHelper*.sol`` sources
        that crytic-compile cannot resolve -- the run dies with "Unknown file".
        Forcing the solc framework compiles the harness file directly instead.
        solc then refuses imports outside the target's own directory, so the
        project root is added to the allowed paths. Both are required; either
        alone still fails.
        """
        explicit = options.get("compile_args")
        if explicit is not None:
            return [str(a) for a in explicit]
        args = ["--compile-force-framework", "solc"]
        remaps = options.get("solc_remaps")
        if remaps:
            args += ["--solc-remaps", str(remaps)]
        else:
            forge_std = root / "lib" / "forge-std" / "src"
            if forge_std.is_dir():
                args += ["--solc-remaps", f"forge-std/={forge_std}/"]
        solc_args = options.get("solc_args") or f"--allow-paths {root}"
        args += ["--solc-args", str(solc_args)]
        return args

    def _write_config(self, root: Path, options: dict, targets: list[str]) -> Path:
        """Write a deterministic per-run Medusa config into the project root."""
        # crytic-compile's Foundry platform skips `test/**`, so a harness in
        # `test/` is never compiled and Medusa aborts with "target contract not
        # found in artifacts". Compiling the harness file directly with solc is
        # what makes a Foundry-layout project fuzzable at all.
        harness = self._harness(root, options)
        # An absolute target keeps the config location-independent: the file
        # lives in the adapter's scratch directory, not in the analysed project.
        compile_target = options.get("compile_target") or (
            str(harness.resolve()) if harness else str(root))
        corpus = Path(options.get("corpus_dir")
                      or (self._scratch_dir() / "medusa-corpus"))
        config = {
            "fuzzing": {
                "workers": int(options.get("workers", 2)),
                "testLimit": int(options.get("test_limit", 30000)),
                "shrinkLimit": int(options.get("shrink_limit", 2000)),
                "seed": str(options.get("seed", "0x1")),
                "callSequenceLength": int(options.get("call_sequence_length", 50)),
                "corpusDirectory": str(corpus),
                "coverageEnabled": True,
                "targetContracts": targets,
                "deployerAddress": "0x30000",
                "senderAddresses": ["0x10000", "0x20000", "0x30000"],
                "blockNumberDelayMax": 60480,
                "blockTimestampDelayMax": 604800,
                "assertionChecking": True,
                "testing": {
                    "assertionTesting": {"enabled": True},
                    "propertyTesting": {
                        "enabled": True,
                        "testPrefixes": list(options.get("test_prefixes")
                                             or ["property_", "echidna_", "invariant_"]),
                    },
                },
            },
            "compilation": {
                "platform": "crytic-compile",
                "platformConfig": {
                    "target": str(options.get("compile_target") or compile_target),
                    "args": self._compile_args(root, options),
                },
            },
            "logging": {"level": "info"},
        }
        # Written to the adapter's own scratch directory: the analysed project is
        # read-only to an engine, and two sandboxes fuzzing the same target must
        # not overwrite each other's config or corpus.
        path = self._scratch_dir() / "medusa.json"
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return path

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        root = self._project_root(target)
        targets = self._target_contracts(root, options)
        harness = self._harness(root, options)
        if harness is not None and not (options.get("target_contracts")
                                        or self.config.get("target_contracts")):
            harness_contracts = self._contracts_in(harness)
            if harness_contracts:
                targets = harness_contracts
        if not targets:
            meta = ExecutionMetadata(
                engine=self.name, version=self.inspect_version(), argv=[],
                cwd=str(root), started_at=utcnow(), target=str(root),
                state=EngineState.CONFIGURATION_ERROR,
                note="medusa needs a target contract: pass target_contracts or a .sol with a contract",
            )
            return ExecutionResult(metadata=meta)
        options = dict(options)
        options.setdefault("target_contracts", targets)
        options["config"] = str(self._write_config(root, options, targets))
        return super().execute_scan(target, **options)

    def _build_argv(self, root: Path, options: dict) -> list[str]:
        paths = self.paths()
        binary = paths.binary if paths else "medusa"
        config = Path(options.get("config") or (root / "medusa.json"))
        return [binary, "fuzz", "--config", str(config)]

    def _collect(self, root: Path,
                 stdout: str = "", stderr: str = "") -> tuple[dict[str, str], Optional[list[dict]]]:
        artifacts: dict[str, str] = {}
        records: list[dict] = []

        corpus = self._scratch_dir() / "medusa-corpus"
        if corpus.is_dir():
            artifacts["medusa-corpus"] = str(corpus)
            results_dir = corpus / "test_results"
            if results_dir.is_dir():
                for path in sorted(results_dir.glob("*.json")):
                    data = self._read_json(path)
                    if isinstance(data, list):
                        records.append({"kind": "failing_sequence",
                                        "sequence_file": str(path),
                                        "sequence": data})
        coverage = corpus / "coverage"
        if coverage.is_dir():
            artifacts["medusa-coverage"] = str(coverage)

        if records:
            violated = _violated_properties(stdout)
            for index, record in enumerate(records):
                # The per-sequence JSON names no property; the console log does.
                # Attach only an unambiguous match, never a guess.
                if len(violated) == 1:
                    record["property"] = violated[0]
                elif index < len(violated):
                    record["property"] = violated[index]
            return artifacts, records
        # A run that produced no corpus at all is unparseable -- it may have
        # aborted before fuzzing. Do not report that as a clean scan.
        if _looks_like_clean_run(stdout):
            return artifacts, []
        return artifacts, None

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        # Medusa writes one corpus file per distinct failing sequence, and a
        # corpus carried over from an earlier run is re-reported. Every sequence
        # falsifying the same property is the same defect, so those collapse to
        # the first (shortest) sequence; without a resolved property name the
        # sequence itself is the identity. Counting corpus files as findings
        # would inflate the count several-fold.
        seen: set[tuple[str, ...]] = set()
        ordered = sorted(
            (r for r in result.raw_records if r.get("kind") == "failing_sequence"),
            key=lambda r: len(r.get("sequence") or []),
        )
        for record in ordered:
            property_name = str(record.get("property") or "").strip()
            signature = (("property", property_name) if property_name
                         else _sequence_signature(record.get("sequence") or []))
            if signature in seen:
                continue
            seen.add(signature)
            finding = self._normalize_one(record, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, record: dict,
                       result: ExecutionResult) -> Optional[NormalizedFinding]:
        sequence = record.get("sequence") or []
        property_name = str(record.get("property") or "").strip()
        steps = [_render_call(call) for call in sequence if isinstance(call, dict)]
        if not steps:
            return None
        return NormalizedFinding(
            source_engine=self.name,
            engine_version=result.metadata.version,
            target_id=result.metadata.target,
            raw_artifact=str(record.get("sequence_file") or ""),
            category="sequence-violation",
            title=(f"falsified property: {property_name} ({len(steps)} call(s))"
                   if property_name else
                   f"failing transaction sequence ({len(steps)} call(s))"),
            description=("Medusa found a call sequence that breaks an assertion or "
                         "property. The sequence is preserved for replay."),
            severity=normalize_severity("high"),
            cwe="",
            confidence="fuzzed",
            component="",
            source_location="",
            attack_vector="fuzzed transaction sequence",
            exploit_steps=steps,
            reproduction="\n".join(steps),
            evidence_refs=[str(record.get("sequence_file"))]
            if record.get("sequence_file") else [],
            execution_environment=f"medusa {result.metadata.version}",
            reproduction_status="observed",
            raw=record,
        ).finalize()


def _render_call(call: dict) -> str:
    inner = call.get("call") if isinstance(call.get("call"), dict) else call
    values = inner.get("dataAbiValues") or {}
    signature = str(values.get("methodSignature") or inner.get("data") or "?")
    args = values.get("inputValues") or []
    rendered = ", ".join(str(a) for a in args)
    sender = inner.get("from") or ""
    target = inner.get("to") or ""
    return f"{sender} -> {target}.{signature}({rendered})"


def _looks_like_clean_run(stdout: str) -> bool:
    """True only when the log shows a completed fuzzing campaign with no failures."""
    text = stdout or ""
    if "Test summary:" not in text:
        return False
    if "test(s) failed" not in text:
        return False
    match = re.search(r"Test summary:\s*(\d+)\s*test\(s\) passed,\s*(\d+)\s*test\(s\) failed", text)
    if match is None:
        return False
    return int(match.group(2)) == 0


def _violated_properties(stdout: str) -> list[str]:
    """Property/assertion identifiers Medusa reported as failing, in order.

    Medusa prints ``[FAILED] Property Test: Contract.func()``; the contract
    qualifier is dropped so the name matches what the harness declares.
    """
    pattern = re.compile(
        r"\[FAILED\]\s*(?:Property|Assertion|Optimization)\s+Test\s*:\s*"
        r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        re.IGNORECASE,
    )
    return pattern.findall(_strip_ansi(stdout or ""))


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Medusa colourises its log; the escape sequences break line matching."""
    return _ANSI.sub("", text)


def _sequence_signature(sequence: list) -> tuple[str, ...]:
    """A stable identity for a call sequence, for de-duplication."""
    steps = []
    for call in sequence:
        inner = call.get("call") if isinstance(call, dict) and isinstance(
            call.get("call"), dict) else call
        if not isinstance(inner, dict):
            steps.append(str(inner))
            continue
        values = inner.get("dataAbiValues") or {}
        steps.append("|".join((
            str(inner.get("to") or ""),
            str(values.get("methodSignature") or inner.get("data") or ""),
            ",".join(str(a) for a in (values.get("inputValues") or [])),
        )))
    return tuple(steps)
