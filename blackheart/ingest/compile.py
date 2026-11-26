"""Compile a Solidity project into artifacts, behind the compatibility gate.

This is the front of the source-to-execution loop: a real compiler turns source
into an ABI and bytecode the EVM adapters can deploy, instead of a lexer guessing
a surface. It is fail-closed in the same way as :mod:`blackheart.ingest.runner`:
a blocked run returns ``BLOCKED`` and **never invokes the compiler**, and a
compiler that is absent is reported as blocked, not as a clean build.

Statuses are the doctrine's: ``OK`` (artifacts produced), ``BLOCKED`` (the gate
refused or no compiler is installed; nothing ran), ``INCOMPLETE`` (the compiler
ran but produced nothing parseable).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

from ..toolchain.enforce import CompatibilityRecord, ExecutionTarget, bind

STATUSES = ("OK", "BLOCKED", "INCOMPLETE")


@dataclass(frozen=True)
class CompiledArtifact:
    contract: str
    abi: list[dict]
    bytecode: str = ""
    path: str = ""
    runtime_bytecode: str = ""
    storage_layout: dict = field(default_factory=dict)
    ast: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "path": self.path,
            "abi": list(self.abi),
            "bytecode_len": len(self.bytecode),
            "runtime_bytecode_len": len(self.runtime_bytecode),
            "storage_slots": len((self.storage_layout or {}).get("storage") or []),
            "has_ast": bool(self.ast),
        }


@dataclass
class CompileOutcome:
    tool: str
    status: str
    artifacts: dict[str, CompiledArtifact] = field(default_factory=dict)
    reason: str = ""
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "OK"

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status,
            "reason": self.reason,
            "artifacts": {k: v.to_dict() for k, v in self.artifacts.items()},
        }


# --------------------------------------------------------------------------- #
# Tool discovery
# --------------------------------------------------------------------------- #

def find_compiler() -> Optional[tuple[str, str]]:
    """Return ``(tool, path)`` for an installed compiler, or ``None``.

    Uses the toolchain resolver, which searches the isolated install directories
    and ``PATH`` explicitly -- a compiler found only by luck of the shell is not
    found at all in the next process.
    """
    from ..engines.solidity.base import resolve_tool

    for tool in ("forge", "solc"):
        found = resolve_tool(tool)
        if found is not None:
            return tool, found.binary
    return None


# --------------------------------------------------------------------------- #
# Pure parsers (testable without a compiler)
# --------------------------------------------------------------------------- #

def _loads(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _forge_source_asts(payload: Any) -> dict[str, dict]:
    """Recover source-unit ASTs from Forge's standard-JSON output.

    Foundry 1.10 emits ``sources[path]`` as a list of compiler outputs, with the
    AST under ``source_file.ast``. Older releases emitted a flat artifact map
    and put ``ast`` on the contract. Both are read; an unrecognised shape yields
    no AST rather than a guessed one.
    """
    if not isinstance(payload, dict):
        return {}
    out: dict[str, dict] = {}
    sources = payload.get("sources")
    if not isinstance(sources, dict):
        return out
    for path, value in sources.items():
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            source_file = entry.get("source_file") or entry.get("sourceFile")
            ast = (source_file.get("ast") if isinstance(source_file, dict) else None)
            ast = ast or entry.get("ast") or entry.get("AST")
            if isinstance(ast, dict) and ast:
                out[str(path)] = ast
    return out


def parse_forge_artifacts(payload: Any) -> dict[str, CompiledArtifact]:
    """Parse ``forge build --json`` output into artifacts, defensively.

    Foundry has emitted this as a flat mapping, as a mapping of source path to
    contract name to a list of entries, and as a list. A recursive walk finds
    every object carrying an ``abi``, so a shape change cannot silently produce
    an empty build. An object without an ``abi`` is not a contract.
    """
    out: dict[str, CompiledArtifact] = {}
    source_asts = _forge_source_asts(payload)

    def walk(node: Any, hint: str = "", path: str = "") -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, hint, path)
            return
        if not isinstance(node, dict):
            return
        if "abi" in node:
            abi = node.get("abi")
            if abi is None:
                return
            bytecode = node.get("bytecode")
            if isinstance(bytecode, dict):
                bytecode = bytecode.get("object", "")
            deployed = node.get("deployedBytecode")
            if isinstance(deployed, dict):
                deployed = deployed.get("object", "")
            raw_name = node.get("contractName") or hint or path
            name = str(raw_name).split(":")[-1] if raw_name else "contract"
            out[name] = CompiledArtifact(
                contract=name, abi=list(abi), bytecode=str(bytecode or ""),
                path=path or hint, runtime_bytecode=str(deployed or ""),
                storage_layout=dict(node.get("storageLayout") or {}),
                ast=dict(node.get("ast") or {}),
            )
            return
        for key, value in node.items():
            text = str(key)
            child_hint = hint if text in ("contract", "contracts") else text.split(":")[-1]
            if text.endswith(".sol") or (not path and isinstance(value, (dict, list))):
                child_path = text
            else:
                child_path = path
            walk(value, child_hint, child_path)

    walk(payload)
    for name, artifact in list(out.items()):
        if artifact.ast:
            continue
        path = str(artifact.path)
        ast = (source_asts.get(path)
               or source_asts.get(path.split(":", 1)[0])
               or next((ast for source, ast in source_asts.items()
                        if source.endswith("/" + path) or source.endswith(path)),
                       {}))
        if ast:
            out[name] = replace(artifact, ast=ast)
    return out


def parse_solc_combined_json(payload: Any) -> dict[str, CompiledArtifact]:
    """Parse ``solc --combined-json abi,bin`` output into artifacts."""
    out: dict[str, CompiledArtifact] = {}
    if not isinstance(payload, dict):
        return out
    contracts = payload.get("contracts") or {}
    if not isinstance(contracts, dict):
        return out
    sources = payload.get("sources") or {}
    for key, art in contracts.items():
        if not isinstance(art, dict):
            continue
        abi = art.get("abi")
        if isinstance(abi, str):
            abi = _loads(abi)
        if not isinstance(abi, list):
            continue
        name = key.split(":")[-1]
        source_name = key.split(":", 1)[0]
        source = sources.get(source_name) if isinstance(sources, dict) else None
        ast = source.get("AST") if isinstance(source, dict) else None
        out[name] = CompiledArtifact(
            contract=name, abi=abi, bytecode=str(art.get("bin", "")),
            path=str(key), runtime_bytecode=str(art.get("bin-runtime", "")),
            storage_layout=dict(art.get("storage-layout") or {}),
            ast=dict(ast or {}),
        )
    return out


# --------------------------------------------------------------------------- #
# Compile
# --------------------------------------------------------------------------- #

def compile_project(
    root: str | Path,
    *,
    compatibility: Optional[CompatibilityRecord],
    target_component: str,
    repository: str,
    commit: str = "",
    timeout: int = 600,
) -> CompileOutcome:
    """Compile ``root`` under the gate. Fail-closed: a block never invokes a tool."""
    if compatibility is None:
        return CompileOutcome("", "BLOCKED",
                              reason="no compatibility record; nothing was compiled")
    decision = bind(compatibility, ExecutionTarget(
        name=target_component, repository=repository, commit=commit))
    if decision.decision != "ADMIT":
        return CompileOutcome("", "BLOCKED",
                              reason="gate refused: " + "; ".join(decision.reasons))

    compiler = find_compiler()
    if compiler is None:
        return CompileOutcome("", "BLOCKED",
                              reason="no Solidity compiler (forge/solc) is installed on "
                                     "this host; nothing was compiled")
    tool, path = compiler
    root = Path(root)

    try:
        if tool == "forge":
            # ``forge build --json`` prints an empty contracts map when the
            # cache is warm. A one-shot compile must ask for the artifacts, so
            # force a rebuild rather than reporting a cached success as empty.
            proc = subprocess.run([path, "build", "--force", "--json"],
                                  cwd=str(root),
                                  capture_output=True, text=True, timeout=timeout)
            artifacts = parse_forge_artifacts(_loads(proc.stdout or ""))
        else:
            files = sorted(str(p) for p in root.rglob("*.sol"))
            if not files:
                return CompileOutcome(tool, "INCOMPLETE", reason="no .sol files under root")
            proc = subprocess.run([path, "--combined-json",
                                   "abi,bin,bin-runtime,storage-layout,ast", *files],
                                  cwd=str(root), capture_output=True, text=True,
                                  timeout=timeout)
            artifacts = parse_solc_combined_json(_loads(proc.stdout or ""))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CompileOutcome(tool, "INCOMPLETE", reason=f"could not complete: {exc}")

    if not artifacts:
        detail = (proc.stdout or proc.stderr or "")[:2000]
        return CompileOutcome(tool, "INCOMPLETE",
                              reason="the compiler produced no parseable artifacts "
                                     "(a build failure is not a clean build)",
                              output=detail)
    return CompileOutcome(tool, "OK", artifacts=artifacts,
                          reason=f"compiled {len(artifacts)} contract(s) with {tool}")


def models_from_compiled(outcome: CompileOutcome) -> dict[str, Any]:
    """A :class:`SystemModel` per compiled contract, read from its ABI."""
    from ..solidity.abi import propose_model_from_abi

    return {
        name: propose_model_from_abi(art.abi, target_name=name)
        for name, art in outcome.artifacts.items()
    }
