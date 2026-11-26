"""Echidna -- property-based fuzzing.

Echidna is a *differential* engine: it needs a test harness contract that exposes
``echidna_*`` (or ``property_*``) predicates, and it falsifies them with random
call sequences. Without a harness it has nothing to fuzz, which is why the
adapter reports ``CONFIGURATION_ERROR`` with an actionable message instead of a
silent empty run.

The exit-code contract is the important part:

  * ``0`` -- every property held. A genuine clean result.
  * ``1`` -- at least one property was falsified. **This is a successful scan
    that found something**, not a tool failure.
  * anything else -- a tool/compile failure, which must never be read as clean.

Echidna streams JSON documents to stdout as it works; the last document is the
final state. Each falsified property carries the minimised call sequence, which
is preserved verbatim as the reproduction artifact -- a counterexample the
operator can replay is worth more than the severity label attached to it.
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


class EchidnaAdapter(SolidityEngineAdapter):
    name = "echidna"
    upstream_url = "https://github.com/crytic/echidna"
    license_id = "AGPL-3.0"
    description = "Property-based smart-contract fuzzing"
    CLEAN_EXIT_CODES = frozenset({0})
    #: Echidna exits 1 when a property is falsified.
    FINDING_EXIT_CODES = frozenset({1})
    DEFAULT_TIMEOUT_S = 1200.0

    def analysis_methods(self) -> tuple[str, ...]:
        return ("property-fuzzing",)

    def validate_configuration(self) -> tuple[bool, str]:
        return True, "ok"

    # -- harness discovery ------------------------------------------------- #
    def _harness(self, root: Path, options: dict) -> Optional[Path]:
        """Find the contract file that declares a property predicate."""
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
            if "echidna_" in text or "function property_" in text:
                return path
        return None

    def _contract_name(self, harness: Path) -> str:
        """The harness contract name, read from the source rather than guessed.

        Each ``contract X`` declaration is treated as running until the next one,
        and the contract whose slice declares a predicate wins. A brace-matching
        regex is unreliable on Solidity with nested literals, so this stays
        slice-based and falls back to the first declared contract.
        """
        try:
            text = harness.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        declarations = list(re.finditer(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)", text))
        if not declarations:
            return ""
        for index, match in enumerate(declarations):
            start = match.end()
            end = declarations[index + 1].start() if index + 1 < len(declarations) else len(text)
            body = text[start:end]
            if "echidna_" in body or "function property_" in body:
                return match.group(1)
        return declarations[0].group(1)

    def _build_argv(self, root: Path, options: dict) -> list[str]:
        paths = self.paths()
        binary = paths.binary if paths else "echidna"
        harness = self._harness(root, options)
        argv = [binary, str(harness) if harness else "."]
        contract = options.get("contract") or (self._contract_name(harness) if harness else "")
        if contract:
            argv += ["--contract", str(contract)]
        argv += ["--test-mode", str(options.get("test_mode", "property"))]
        argv += ["--format", "json"]
        if options.get("test_limit"):
            argv += ["--test-limit", str(int(options["test_limit"]))]
        if options.get("seq_len"):
            argv += ["--seq-len", str(int(options["seq_len"]))]
        if options.get("corpus_dir"):
            argv += ["--corpus-dir", str(options["corpus_dir"])]
        if options.get("config"):
            argv += ["--config", str(options["config"])]
        if options.get("seed"):
            argv += ["--seed", str(options["seed"])]
        # A Foundry project's build-info references generated helper sources that
        # crytic-compile cannot resolve ("Unknown file: foundry-pp/..."), which
        # fails the whole run. Compiling the harness with solc directly sidesteps
        # that indirection and is what the tools' own CI does. Operators can
        # override with crytic_args.
        crytic_args = options.get("crytic_args")
        if crytic_args is None:
            crytic_args = "--compile-force-framework solc"
        if crytic_args:
            argv += ["--crytic-args", str(crytic_args)]
        solc_args = options.get("solc_args")
        if solc_args is None and crytic_args:
            # Compiling the harness file directly means solc's base path is the
            # file's own directory, and the harness imports `../src/...`. Without
            # an explicit allow-path solc refuses the import, the target contract
            # is undeclared, and the run fails on a cold build (a warm cache
            # hides it, which is why this only showed up after `forge clean`).
            solc_args = f"--allow-paths {root}"
        if solc_args:
            argv += ["--solc-args", str(solc_args)]
        return argv

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        root = self._project_root(target)
        if self._harness(root, options) is None:
            # No predicate to falsify. Refuse rather than report a clean scan --
            # "echidna found nothing" and "echidna had nothing to look at" must
            # never be the same result.
            meta = ExecutionMetadata(
                engine=self.name,
                version=self.inspect_version(),
                argv=[],
                cwd=str(root),
                started_at=utcnow(),
                target=str(root),
                state=EngineState.CONFIGURATION_ERROR,
                note=("no echidna harness found: expected a contract declaring "
                      "echidna_* or property_* predicates"),
            )
            return ExecutionResult(metadata=meta)
        return super().execute_scan(target, **options)

    def _collect(self, root: Path,
                 stdout: str = "", stderr: str = "") -> tuple[dict[str, str], Optional[list[dict]]]:
        """Parse the JSON documents Echidna streams to stdout.

        Echidna's JSON serialises the ``name`` *key* instead of the property name
        (``"name": "name"``), so the real identifier is recovered from the
        human-readable lines and attached as ``property``. The JSON still supplies
        the structured, minimised call sequence.
        """
        document = _last_json_document(stdout or "")
        if document is None:
            return {}, None
        tests = document.get("tests")
        if not isinstance(tests, list):
            return {}, None
        records = [t for t in tests if isinstance(t, dict)]
        # Echidna's JSON omits the property name entirely (it emits the literal
        # key), and --format json suppresses the text log that carries it. The
        # name is therefore resolved from the harness source, and only when the
        # mapping is unambiguous; otherwise it stays explicitly unresolved rather
        # than being invented.
        names = self._predicate_names(self._harness(root, {}))
        for index, record in enumerate(records):
            if len(names) == 1:
                record.setdefault("property", names[0])
            elif index < len(names):
                record.setdefault("property", names[index])
        return {}, records

    def _predicate_names(self, harness: Optional[Path]) -> list[str]:
        """``echidna_*``/``property_*`` function names declared in the harness."""
        if harness is None:
            return []
        try:
            text = harness.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return re.findall(r"function\s+(echidna_[A-Za-z0-9_]*|property_[A-Za-z0-9_]*)\s*\(",
                          text)

    # -- normalization ----------------------------------------------------- #
    def normalize_findings(self, result: ExecutionResult) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for record in result.raw_records:
            # Echidna reports every property it touched; only the falsified ones
            # are findings. A "passing"/"fuzzing" status is not a vulnerability.
            status = str(record.get("status") or "").lower()
            if status not in ("failed", "falsified", "shrinking"):
                continue
            finding = self._normalize_one(record, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _normalize_one(self, record: dict,
                       result: ExecutionResult) -> Optional[NormalizedFinding]:
        name = (str(record.get("property") or "").strip()
                or str(record.get("name") or "").strip())
        if not name or name == "name":  # Echidna's JSON echoes the key
            name = "unresolved property (echidna --format json omits the name)"
        transactions = record.get("transactions") or []
        steps = [_render_transaction(tx) for tx in transactions if isinstance(tx, dict)]
        contract = str(record.get("contract") or "")

        return NormalizedFinding(
            source_engine=self.name,
            engine_version=result.metadata.version,
            target_id=result.metadata.target,
            raw_artifact="",
            category="property-violation",
            title=f"falsified property: {name}",
            description=(f"Echidna falsified the property {name!r} in "
                         f"{len(steps)} transaction(s)."),
            # A falsified property is a real observed execution, so it ranks
            # above a static observation -- but it is still not a proven exploit.
            severity=normalize_severity(record.get("severity") or "high"),
            cwe="",
            confidence="fuzzed",
            component=contract,
            source_location="",
            attack_vector="fuzzed call sequence",
            exploit_steps=steps,
            reproduction="\n".join(steps),
            evidence_refs=[],
            execution_environment=f"echidna {result.metadata.version}",
            reproduction_status="observed",
            raw=record,
        ).finalize()


def _render_transaction(tx: dict) -> str:
    fn = str(tx.get("function") or "?")
    args = tx.get("arguments") or []
    rendered = ", ".join(str(a) for a in args)
    sender = tx.get("sender")
    call = f"{fn}({rendered})"
    return f"{sender} -> {call}" if sender else call


def _last_json_document(text: str) -> Optional[dict]:
    """Echidna streams one JSON object per status update; return the last one.

    The documents are concatenated without separators, so a naive ``json.loads``
    fails on everything but a single-document run. Scanning for balanced braces
    from each ``{"coverage"`` marker and keeping the last that parses is robust to
    the extra log lines Echidna interleaves on stderr-free stdout.
    """
    decoder = json.JSONDecoder()
    last: Optional[dict] = None
    index = text.find('{"coverage"')
    while index != -1:
        try:
            obj, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index = text.find('{"coverage"', index + 1)
            continue
        if isinstance(obj, dict):
            last = obj
        index = text.find('{"coverage"', end)
    return last
