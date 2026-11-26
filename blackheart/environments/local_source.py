"""A real local backend: a source repository and its local test environment.

This is the first of the two materially different execution backends that prove
the research core is not coupled to one sandbox. It works entirely offline:

  * **inspect / enumerate** walk a local source tree and report its real layout,
    file types, and executable entry points -- read from disk, not assumed.
  * **execute** runs a *declared* command list (never a shell string) inside the
    repository, with a timeout and no shell interpolation, and captures the real
    stdout/stderr and exit status.

Deliberately, this backend cannot transact, cannot roll state back, and has no
network. It declares those absences as limitations rather than pretending. A
research probe that needs a transaction is routed to a backend that declares one,
or is reported as blocked -- never silently simulated here.

Safety: only an allowlisted command shape runs. The adapter refuses a request whose
command is not in the repo's own declared allowlist, so a hostile hypothesis or a
poisoned file cannot turn this into an arbitrary-command executor.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..models import utcnow
from .adapter import (
    AdapterState,
    Capabilities,
    ExecutionAdapter,
    Observation,
    ProbeRequest,
    ProbeResult,
)

#: Source extensions this backend recognises when enumerating a tree.
_SOURCE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".rb",
    ".sol", ".vy", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".php", ".swift",
    ".sh",
}

#: Directories never descended into while enumerating (build output, vendored
#: deps, VCS metadata) -- they are not the target's authored surface.
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "dist",
    "build", "target", ".mypy_cache", ".pytest_cache", ".ruff_cache", "lib",
}

#: The command shapes this backend will run. Anything else is refused. Each entry
#: is the argv prefix; a request must match one exactly at its head.
DEFAULT_COMMAND_ALLOWLIST: tuple[tuple[str, ...], ...] = (
    ("python3", "-m", "pytest"),
    ("python", "-m", "pytest"),
    ("pytest",),
    ("python3", "-m", "unittest"),
    ("npm", "test"),
    ("go", "test"),
    ("go", "vet"),
    ("go", "build"),
    ("go", "list"),
    ("go", "env"),
    ("govulncheck",),
    ("cargo", "test"),
    ("cargo", "clippy"),
    ("cargo", "audit"),
    ("forge", "test"),
)

#: Flags that let a bare interpreter run arbitrary code. A prefix match alone is
#: not enough: ``("python3",)`` would allow ``python3 -c <anything>``, turning the
#: allowlist into an arbitrary-command executor. These are refused anywhere in argv.
_CODE_INJECTION_FLAGS = frozenset({"-c", "--eval", "-e", "--exec", "--command"})

#: The only environment variables a probe subprocess inherits. Everything else --
#: API keys, tokens, cloud credentials -- is withheld: a probe must not be able to
#: read the operator's secrets out of the environment.
_ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TEMP", "TMP",
    "PYTHONPATH", "PYTHONHASHSEED", "VIRTUAL_ENV", "SYSTEMROOT", "TERM",
    # Go build/test cache and module paths. These are build inputs, not secrets.
    "GOCACHE", "GOPATH", "GOMODCACHE", "GOFLAGS", "GOTOOLCHAIN", "GOROOT",
    "CGO_ENABLED", "CC", "CXX", "PKG_CONFIG_PATH", "LD_LIBRARY_PATH",
    # Cargo build inputs.
    "CARGO_HOME", "RUSTUP_HOME",
})


#: Tool directories a non-interactive process does not inherit from a login
#: shell. Resolving them explicitly is what stops a host with every tool
#: installed from reporting "not found" in the next process.
_TOOL_DIRS: tuple[Path, ...] = (
    Path.home() / ".foundry" / "bin",
    Path.home() / "go" / "bin",
    Path.home() / ".cargo" / "bin",
    Path.home() / ".local" / "bin",
    Path("/usr/local/go/bin"),
    Path("/workspace/.tools/go/bin"),
)


def _which(tool: str) -> str:
    found = shutil.which(tool)
    if found:
        return found
    for directory in _TOOL_DIRS:
        candidate = directory / tool
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return ""


def _tool_path_env() -> str:
    parts = [os.environ.get("PATH", "")]
    parts.extend(str(d) for d in _TOOL_DIRS if d.is_dir())
    return os.pathsep.join(p for p in parts if p)


def _tree_digest(root: Path, limit: int = 5000) -> tuple[str, int]:
    """A stable digest of a source tree's *authored* files (skips build output)."""
    h = hashlib.sha256()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fname in sorted(filenames):
            if count >= limit:
                break
            p = Path(dirpath) / fname
            try:
                h.update(str(p.relative_to(root)).encode("utf-8"))
                h.update(p.read_bytes())
            except OSError:
                continue
            count += 1
    return h.hexdigest(), count


class LocalSourceAdapter(ExecutionAdapter):
    """Inspect and run tests against a local source repository, offline."""

    name = "local-source"

    declared = Capabilities(
        target_types=("source-repository", "test-environment", "protocol-implementation"),
        operations=("inspect", "enumerate", "execute", "capture"),
        network=False,
        state_control=False,
        transactions=False,
        snapshot_rollback=False,
        evidence_capture=True,
        evidence_tier="real-execution",
        limitations=[
            "no network access: cannot reach a remote or deployed target",
            "cannot submit transactions (no chain or live service)",
            "cannot roll state back: each execute runs against the working tree as-is",
            "runs only a declared command allowlist, never an arbitrary shell string",
        ],
        required_permissions=["read access to the repository path"],
        safety_constraints=[
            "command must match the allowlist; no shell interpolation",
            "runs with a hard timeout; output is capped",
        ],
    )

    MAX_OUTPUT_BYTES = 200_000

    def __init__(self, root: str, *, command_allowlist: tuple[tuple[str, ...], ...] = ()):
        self._root = Path(root).expanduser()
        self._allow = command_allowlist or DEFAULT_COMMAND_ALLOWLIST
        super().__init__()

    # -- probe --------------------------------------------------------- #

    def _probe(self) -> ProbeResult:
        if not self._root.exists() or not self._root.is_dir():
            return ProbeResult(
                state=AdapterState.MISSING,
                detail=f"repository path does not exist or is not a directory: {self._root}",
            )
        # Probe every tool the allowlist can invoke. A missing tool narrows what
        # `execute` can do; it is reported, never hidden behind a blanket READY.
        tools = {
            "pytest": bool(_which("pytest")) or self._python_has_pytest(),
            "go": bool(_which("go")),
            "govulncheck": bool(_which("govulncheck")),
            "cargo": bool(_which("cargo")),
            "forge": bool(_which("forge")),
        }
        confirmed = Capabilities(
            target_types=self.declared.target_types,
            operations=self.declared.operations,
            tools=tools,
            network=False,
            state_control=False,
            transactions=False,
            snapshot_rollback=False,
            evidence_capture=True,
            evidence_tier="real-execution",
            limitations=list(self.declared.limitations),
            required_permissions=list(self.declared.required_permissions),
            safety_constraints=list(self.declared.safety_constraints),
        )
        # If a tool is absent, `execute` is still usable for the other allowlisted
        # commands, but the narrowed capability is recorded instead of hidden.
        for tool, present in tools.items():
            if not present:
                confirmed.limitations.append(f"{tool} not found on PATH")
        return ProbeResult(state=AdapterState.READY, detail="local repository readable",
                           confirmed=confirmed)

    @staticmethod
    def _python_has_pytest() -> bool:
        try:
            import importlib.util

            return importlib.util.find_spec("pytest") is not None
        except Exception:
            return False

    # -- execute ------------------------------------------------------- #

    def _command_allowed(self, argv: list[str]) -> bool:
        if any(a in _CODE_INJECTION_FLAGS for a in argv):
            return False
        for prefix in self._allow:
            if tuple(argv[: len(prefix)]) == prefix:
                return True
        return False

    def _execute(self, request: ProbeRequest, caps: Capabilities) -> Observation:
        if request.operation in ("inspect", "enumerate", "capture"):
            return self._inspect(request)
        if request.operation == "execute":
            return self._run(request)
        # execute() already gate-checked the operation, so this is unreachable for
        # the declared set -- be explicit rather than silently returning ok.
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=False, evidence_tier=caps.evidence_tier,
            error=f"operation '{request.operation}' is not implemented by {self.name}",
        )

    def _inspect(self, request: ProbeRequest) -> Observation:
        digest, n = _tree_digest(self._root)
        by_ext: dict[str, int] = {}
        entries: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for fname in sorted(filenames):
                ext = Path(fname).suffix.lower()
                if ext in _SOURCE_EXTS:
                    by_ext[ext] = by_ext.get(ext, 0) + 1
                    if len(entries) < 200:
                        rel = (Path(dirpath) / fname).relative_to(self._root)
                        entries.append(str(rel))
        facts: dict[str, Any] = {
            "root": str(self._root),
            "tree_sha256": digest,
            "files_hashed": n,
            "source_files_by_ext": dict(sorted(by_ext.items())),
            "entry_points": entries[:200],
            "inspected_at": utcnow(),
        }
        return Observation(
            adapter=self.name, target=request.target, operation=request.operation,
            ok=True, evidence_tier="real-execution", facts=facts,
            raw=f"{n} files hashed; languages: {', '.join(sorted(by_ext)) or 'none'}",
        )

    def _run(self, request: ProbeRequest) -> Observation:
        argv = request.params.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            return Observation(
                adapter=self.name, target=request.target, operation="execute", ok=False,
                evidence_tier="real-execution",
                error="execute requires params.argv: a list of strings (no shell string)",
            )
        if not self._command_allowed(argv):
            return Observation(
                adapter=self.name, target=request.target, operation="execute", ok=False,
                evidence_tier="real-execution",
                error=(f"command {argv[:2]} is not permitted by this backend: it must "
                       f"match the allowlist and carry no code-injection flag"),
            )
        # Inherit only the variables a build/test needs. Passing the whole
        # environment would hand every secret the operator holds to the target's
        # own code, which the target runs.
        env = {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}
        env["PATH"] = _tool_path_env()
        try:
            proc = subprocess.run(
                argv, cwd=str(self._root), capture_output=True,
                timeout=request.timeout_s, env=env, shell=False,
            )
        except subprocess.TimeoutExpired:
            return Observation(
                adapter=self.name, target=request.target, operation="execute", ok=False,
                evidence_tier="real-execution",
                error=f"command exceeded {request.timeout_s}s timeout",
                limitation="execution timed out",
            )
        except FileNotFoundError as exc:
            return Observation(
                adapter=self.name, target=request.target, operation="execute", ok=False,
                evidence_tier="real-execution", error=f"command not found: {exc}",
            )
        out = proc.stdout.decode("utf-8", "replace")[: self.MAX_OUTPUT_BYTES]
        err = proc.stderr.decode("utf-8", "replace")[: self.MAX_OUTPUT_BYTES]
        return Observation(
            adapter=self.name, target=request.target, operation="execute",
            ok=proc.returncode == 0, evidence_tier="real-execution",
            raw=out, facts={
                "argv": argv, "cwd": str(self._root), "exit_code": proc.returncode,
                "stdout_sha256": hashlib.sha256(proc.stdout).hexdigest(),
                "stderr_tail": err[-2000:],
            },
            error="" if proc.returncode == 0 else f"exit code {proc.returncode}",
        )
