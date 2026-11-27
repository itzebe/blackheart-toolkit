"""Shared machinery for the Solidity engine adapters.

Everything here exists because the same three problems recur for every engine:

1. **Finding the binary.** These engines live in isolated virtualenvs (Slither
   ships a top-level ``tests`` package that shadows this repository's own
   ``tests/`` directory, so a global install breaks the test suite). Resolution
   is therefore: explicit config, then ``$BLACKHEART_<TOOL>``, then the
   ``~/.blackheart/venvs/<tool>/bin`` venv the bootstrap creates, then ``PATH``.
   A tool that resolves nowhere is ``MISSING`` -- never assumed present.

2. **Deciding what an exit code means.** Echidna/Medusa/Halmos exit non-zero
   when they find a counterexample. That is a *successful scan with a finding*.
   Each subclass declares ``FINDING_EXIT_CODES``; the base treats only those as
   success, so a crash (a real tool failure) can never be read as "no bugs".

3. **Not lying about a run.** A run that produced no parseable artifact is
   ``PARTIAL``, never ``COMPLETED``. ``COMPLETED`` is reserved for "the tool ran
   to a decision and we could read the decision".
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..contract import (
    Capability,
    EngineAdapter,
    EngineState,
    EngineUnavailable,
    ExecutionMetadata,
    ExecutionResult,
    Health,
    redact_secrets,
    run_bounded,
)
from ...models import utcnow


@dataclass
class ToolPaths:
    """Where an engine's executables and its compiler live on this host."""

    binary: str
    bin_dir: str = ""
    solc: str = ""
    source: str = ""          # "config" | "env" | "venv" | "path"

    def to_dict(self) -> dict:
        return {"binary": self.binary, "bin_dir": self.bin_dir,
                "solc": self.solc, "source": self.source}


#: Extra directories the bootstrap populates. Order matters: an isolated venv
#: wins over a stray global install, because the global one is what breaks tests.
def _home_root() -> Path:
    """The install root, honouring ``$BLACKHEART_HOME`` like the bootstrap does.

    If the adapter looked only under ``~/.blackheart`` while bootstrap installed
    elsewhere, doctor would report a tool the adapter cannot find -- or worse,
    the adapter would run the host's copy and call an isolated sandbox verified.
    """
    override = os.environ.get("BLACKHEART_HOME", "").strip()
    return Path(override).expanduser() if override else Path.home() / ".blackheart"


_VENV_ROOT = _home_root() / "venvs"
_BIN_ROOT = _home_root() / "bin"


#: Tools whose venv name differs from the binary name. Mythril installs the
#: `myth` binary into `venvs/mythril` (the name `install.sh` and the tool
#: registry both use), so resolving `myth` must look there.
_VENV_ALIASES = {"myth": "mythril"}

#: Install roots a bootstrap, a language installer or a package manager writes to
#: and that are commonly *not* on the PATH of a non-login shell. Resolving through
#: them keeps "installed" meaning the same thing everywhere; a tool found only by
#: luck of the PATH is a tool that disappears when the next process starts.
_EXTRA_BIN_DIRS: tuple[Path, ...] = (
    Path.home() / ".foundry" / "bin",   # forge, cast, anvil, chisel
    Path.home() / "go" / "bin",         # nuclei, httpx, subfinder, ffuf, ...
    Path.home() / ".cargo" / "bin",     # rustc, cargo, cargo-fuzz, cargo-audit
    Path.home() / ".local" / "bin",     # pipx / pip --user
    Path("/usr/local/go/bin"),          # go toolchain
)


def _candidate_dirs(tool: str) -> list[tuple[Path, str]]:
    return [
        (_VENV_ROOT / _VENV_ALIASES.get(tool, tool) / "bin", "venv"),
        (_BIN_ROOT, "venv"),
        *((d, "toolchain") for d in _EXTRA_BIN_DIRS),
    ]


#: Directories holding the Solidity *toolchain* an engine shells out to. Slither
#: and Medusa compile through crytic-compile, which runs ``forge config``/``forge
#: build`` for a Foundry project; without ``forge`` on PATH the compile raises
#: ``FileNotFoundError`` and the engine exits non-zero, which would otherwise look
#: like a scan that found nothing. These are resolved the same deterministic way
#: as the engines themselves, never assumed to be on PATH.
_TOOLCHAIN_DIRS: tuple[Path, ...] = (
    Path.home() / ".foundry" / "bin",
    _BIN_ROOT,
)


def toolchain_bin_dirs() -> list[str]:
    """Existing directories to prepend to PATH so engines can compile a target.

    ``crytic-compile`` (and the ``solc-select`` shim it drives) is installed into
    Slither's venv and is used by Slither, Echidna and Medusa alike. Adding it
    once here keeps every engine that shells out to it working, instead of each
    adapter remembering to do it.
    """
    dirs = [str(d) for d in _TOOLCHAIN_DIRS if d.is_dir()]
    crytic = _VENV_ROOT / "slither" / "bin"
    if crytic.is_dir():
        dirs.append(str(crytic))
    return dirs


def resolve_tool(
    tool: str,
    *,
    config: Optional[dict] = None,
    extra_bin: Optional[str] = None,
) -> Optional[ToolPaths]:
    """Resolve ``tool`` to an executable, or ``None`` if it is not installed.

    Never returns a path that does not exist and is not executable, so a caller
    can trust ``None`` to mean "not available here".
    """
    config = config or {}

    # 1. Explicit configuration (an operator overriding the venv layout).
    configured = config.get("binary") or config.get(f"{tool}_binary")
    if configured:
        p = Path(str(configured)).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return ToolPaths(str(p), str(p.parent), source="config")

    # 2. Environment override, e.g. $BLACKHEART_SLITHER.
    env_val = os.environ.get(f"BLACKHEART_{tool.upper()}")
    if env_val:
        p = Path(env_val).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return ToolPaths(str(p), str(p.parent), source="env")

    # 3. The bootstrap's isolated venv / bin directory.
    if extra_bin:
        p = Path(extra_bin).expanduser() / tool
        if p.is_file() and os.access(p, os.X_OK):
            return ToolPaths(str(p), str(p.parent), source="venv")
    for directory, origin in _candidate_dirs(tool):
        p = directory / tool
        if p.is_file() and os.access(p, os.X_OK):
            return ToolPaths(str(p), str(directory), source=origin)

    # 4. Whatever is on PATH.
    found = shutil.which(tool)
    if found:
        return ToolPaths(found, str(Path(found).parent), source="path")
    return None


class SolidityEngineAdapter(EngineAdapter):
    """Base adapter for a local Solidity analysis engine.

    Subclasses set the identity fields, ``FINDING_EXIT_CODES``, and implement
    ``_build_argv``, ``_artifact_paths`` and ``_parse_artifacts``.
    """

    #: Exit codes that mean "the scan completed and found something".
    FINDING_EXIT_CODES: frozenset[int] = frozenset()
    #: Exit codes that mean "the scan completed and found nothing".
    CLEAN_EXIT_CODES: frozenset[int] = frozenset({0})
    #: Default wall-clock budget. A subclass may widen it for fuzzers.
    DEFAULT_TIMEOUT_S: float = 900.0

    def __init__(self, workspace: str | Path, *, config: Optional[dict] = None):
        super().__init__(workspace, config=config)
        self._paths: Optional[ToolPaths] = None
        self._resolved = False

    # -- discovery --------------------------------------------------------- #
    def paths(self) -> Optional[ToolPaths]:
        if not self._resolved:
            self._paths = resolve_tool(self.name, config=self.config)
            if self._paths is not None:
                solc = resolve_tool("solc", config=self.config)
                if solc is not None:
                    self._paths.solc = solc.binary
            self._resolved = True
        return self._paths

    def detect_installation(self) -> bool:
        return self.paths() is not None

    def inspect_version(self) -> str:
        paths = self.paths()
        if paths is None:
            return ""
        # A version probe must not depend on the workdir existing: `blackheart
        # engines list` runs before any engagement directory is created, and a
        # missing cwd would make every engine read as CONFIGURATION_ERROR.
        cwd = self.workspace if self.workspace.is_dir() else Path.home()
        try:
            out = run_bounded([paths.binary, "--version"], cwd=cwd,
                              timeout_s=30.0, max_output_bytes=64 * 1024)
        except OSError:
            return ""
        text = (out.stdout or "") + (out.stderr or "")
        return _first_version(text)

    def verify_health(self) -> Health:
        paths = self.paths()
        if paths is None:
            return Health(
                state=EngineState.MISSING,
                detail=(f"{self.name} not found (looked in $BLACKHEART_{self.name.upper()}, "
                        f"{_VENV_ROOT / self.name / 'bin'}, and PATH); "
                        f"run `blackheart engines bootstrap`"),
            )
        version = self.inspect_version()
        if not version:
            return Health(state=EngineState.CONFIGURATION_ERROR,
                          detail=f"{self.name} present at {paths.binary} but --version failed")
        ok, reason = self.validate_configuration()
        if not ok:
            return Health(state=EngineState.CONFIGURATION_ERROR, version=version, detail=reason)
        return Health(state=EngineState.INSTALLED, version=version,
                      detail=f"{self.name} {version} at {paths.binary} ({paths.source})")

    def inspect_capabilities(self) -> list[Capability]:
        installed = self.detect_installation()
        return [
            Capability(key=method, label=method.replace("-", " ").title(),
                       available=installed,
                       detail="" if installed else f"{self.name} is not installed")
            for method in self.analysis_methods()
        ]

    def analysis_methods(self) -> tuple[str, ...]:
        """The analysis methods this engine provides (overridden per engine)."""
        return ()

    def target_types(self) -> tuple[str, ...]:
        return ("solidity-project",)

    def validate_configuration(self) -> tuple[bool, str]:
        return True, "ok"

    # -- execution --------------------------------------------------------- #
    def prepare_execution(self, target: str, **options: Any) -> ExecutionMetadata:
        root = self._project_root(target)
        return ExecutionMetadata(
            engine=self.name,
            version=self.inspect_version(),
            argv=self._build_argv(root, options),
            cwd=str(root),
            started_at=utcnow(),
            target=str(root),
        )

    def _scratch_dir(self) -> Path:
        """Per-adapter scratch under the run workspace, never inside the target.

        An engine must not write into the project it analyses: that mutates a
        possibly-tracked file, and two sandboxes fuzzing the same target would
        overwrite each other's config and corpus.
        """
        scratch = self.workspace / f".{self.name}-scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        return scratch

    def _project_root(self, target: str) -> Path:
        """Resolve the project directory to analyse, refusing an absent one."""
        p = Path(target).expanduser()
        if not p.is_absolute():
            # A relative target means "relative to where the operator typed it",
            # as a shell would resolve it. The workdir is only a fallback, so
            # `--workdir` cannot silently change which directory is analysed.
            from_cwd = p.resolve()
            p = from_cwd if from_cwd.exists() else (self.workspace / p).resolve()
        p = p.resolve()
        if not p.exists():
            raise EngineUnavailable(f"target does not exist: {target}")
        if p.is_file():
            # A single .sol file is analysed via its containing directory, which
            # is what every one of these tools expects.
            return p.parent
        return p

    def execute_scan(self, target: str, **options: Any) -> ExecutionResult:
        health = self.verify_health()
        if health.state in (EngineState.MISSING, EngineState.UNSUPPORTED):
            raise EngineUnavailable(health.detail)
        if health.state == EngineState.CONFIGURATION_ERROR:
            raise EngineUnavailable(health.detail)

        meta = self.prepare_execution(target, **options)
        timeout_s = float(options.get("timeout_s") or self.config.get("timeout_s")
                          or self.DEFAULT_TIMEOUT_S)
        env = self._build_env(Path(meta.cwd))

        try:
            out = run_bounded(meta.argv, cwd=meta.cwd, env=env, timeout_s=timeout_s,
                              cancel_event=options.get("cancel_event"))
        except OSError as e:
            meta.state = EngineState.FAILED
            meta.note = f"could not execute {self.name}: {e}"
            meta.finished_at = utcnow()
            return ExecutionResult(metadata=meta, raw_stdout="", raw_stderr=str(e))

        meta.finished_at = utcnow()
        meta.exit_code = out.returncode
        meta.output_sha256 = out.output_sha256
        meta.timed_out = out.timed_out
        meta.cancelled = out.cancelled

        # The artifact is read *before* the exit code is judged, because several
        # of these engines use one non-zero code for both "found something" and
        # "internal error" (Slither exits 255 for both). Only a parseable report
        # distinguishes the two, so the artifact has to be in hand first.
        artifacts, records = self._collect(Path(meta.cwd), out.stdout, out.stderr)
        meta.state, meta.note = self._classify_exit(
            out.returncode, out.timed_out, out.cancelled, parsed=records is not None)

        return ExecutionResult(
            metadata=meta,
            raw_stdout=redact_secrets(out.stdout),
            raw_stderr=redact_secrets(out.stderr),
            artifacts=artifacts,
            raw_records=records or [],
        )

    def _classify_exit(self, code: Optional[int], timed_out: bool, cancelled: bool,
                       *, parsed: bool) -> tuple[EngineState, str]:
        """Decide what an exit code means, given whether a report was readable.

        ``parsed`` is the only thing that can tell "the tool reported findings"
        from "the tool crashed", because Slither uses exit 255 for both. A run
        with no readable report is never COMPLETED.
        """
        if cancelled:
            return EngineState.CANCELLED, "cancelled"
        if timed_out:
            return EngineState.FAILED, "timeout"
        if code is None:
            return EngineState.FAILED, "no exit status"
        if not parsed:
            # Nothing to read: a crash, a compile failure, or a truncated run.
            if code in self.CLEAN_EXIT_CODES:
                return EngineState.PARTIAL, "no parseable artifact produced"
            return EngineState.FAILED, f"exit {code} (no parseable artifact)"
        if code in self.CLEAN_EXIT_CODES:
            return EngineState.COMPLETED, "clean"
        if code in self.FINDING_EXIT_CODES:
            return EngineState.COMPLETED, f"exit {code} (findings reported)"
        return EngineState.FAILED, f"exit {code}"

    def _build_env(self, root: Optional[Path] = None) -> dict[str, str]:
        env = dict(os.environ)
        env.setdefault("NO_COLOR", "1")
        paths = self.paths()
        prefix = list(toolchain_bin_dirs())
        if paths is not None and paths.bin_dir:
            prefix.append(paths.bin_dir)
        if prefix:
            env["PATH"] = os.pathsep.join(prefix + [env.get("PATH", "")])
        if paths is not None and paths.solc:
            # solc-select keeps its shim in a directory; pointing every engine at
            # one compiler keeps a run reproducible across sandboxes.
            env.setdefault("SOLC_BINARY", paths.solc)
        self._pin_foundry_evm_version(env, root)
        return env

    #: The newest EVM target the pinned solc (0.8.26) can emit for. Foundry's
    #: default moved ahead of it (``osaka``), and crytic-compile forwards forge's
    #: default to solc, which then rejects it with "Invalid option for
    #: --evm-version" -- so every Foundry target fails to compile with an error
    #: that has nothing to do with the target's code. Pinning the compiler's own
    #: ceiling keeps the run faithful to the code being analysed.
    _PINNED_SOLC_EVM_CEILING = "cancun"

    def _pin_foundry_evm_version(self, env: dict[str, str],
                                 root: Optional[Path]) -> None:
        """Set ``FOUNDRY_EVM_VERSION`` only when the target does not set its own.

        An explicit ``evm_version`` in the target's ``foundry.toml`` is the
        author's choice and is left untouched; the pin exists only to keep
        forge's *default* from exceeding what the pinned solc supports.
        """
        if env.get("FOUNDRY_EVM_VERSION"):
            return
        if root is not None:
            foundry_toml = Path(root) / "foundry.toml"
            if foundry_toml.is_file():
                try:
                    text = foundry_toml.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                if "evm_version" in text:
                    return
        env["FOUNDRY_EVM_VERSION"] = self._PINNED_SOLC_EVM_CEILING

    def _build_argv(self, root: Path, options: dict) -> list[str]:
        raise NotImplementedError

    def _collect(self, root: Path,
                 stdout: str = "", stderr: str = "") -> tuple[dict[str, str], Optional[list[dict]]]:
        """Return ``(artifacts, records)``; ``records is None`` means unparseable.

        ``stdout`` is passed because some engines (Echidna) stream their result to
        stdout instead of writing a file.
        """
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------- #
    def _read_json(self, path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return None


_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def _first_version(text: str) -> str:
    m = _VERSION_RE.search(text or "")
    return m.group(1) if m else ""


def solidity_files(root: Path, *, limit: int = 2000) -> list[Path]:
    """Every Solidity source under ``root``, excluding vendored dependencies."""
    # `corpus` and `crytic-export` are fuzzer output, not project sources:
    # Echidna writes its saved test cases there as Foundry-format `.sol` files,
    # and one of those declares a `property_` function, so a harness search that
    # walked them would pick a corpus artefact as the harness and compile it.
    skip = {"lib", "node_modules", "out", "cache", ".git", "vendor", "artifacts",
            "corpus", "crytic-export"}
    found: list[Path] = []
    for path in sorted(root.rglob("*.sol")):
        if any(part in skip for part in path.relative_to(root).parts[:-1]):
            continue
        found.append(path)
        if len(found) >= limit:
            break
    return found
