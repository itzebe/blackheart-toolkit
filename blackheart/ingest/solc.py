"""Compile verified source into runtime bytecode, or say why it could not.

This is the compiler half of source binding. It takes the files Sourcify
returned, writes them into a temporary Foundry/solc project, invokes the
installed compiler, and returns the *runtime* bytecode -- the artifact the
chain actually executes. A missing compiler is a named gap, never a clean
build; a compiler that runs but produces nothing is ``INCOMPLETE``.

The default recompiler is deliberately conservative: it compiles every contract
in the bundle and picks the runtime that matches the deployed code (metadata
stripped). When none matches it returns the largest runtime, so
:func:`blackheart.ingest.verified.bind_runtime` reports a real mismatch instead
of hiding it.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - the package requires 3.11
    tomllib = None  # type: ignore[assignment]

from .compile import (
    CompiledArtifact,
    find_compiler,
    parse_forge_artifacts,
    parse_solc_combined_json,
)

STATUSES = ("OK", "NO_COMPILER", "INCOMPLETE")


@dataclass
class SourceCompile:
    status: str
    tool: str = ""
    artifacts: dict[str, CompiledArtifact] = field(default_factory=dict)
    reason: str = ""
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "OK" and bool(self.artifacts)

    def runtimes(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for name, artifact in self.artifacts.items():
            raw = artifact.runtime_bytecode or artifact.bytecode
            text = raw[2:] if raw.startswith(("0x", "0X")) else raw
            if text:
                try:
                    out[name] = bytes.fromhex(text)
                except ValueError:
                    continue
        return out

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "tool": self.tool,
            "reason": self.reason,
            "artifacts": {k: v.to_dict() for k, v in self.artifacts.items()},
            "runtimes": {k: len(v) for k, v in self.runtimes().items()},
        }


def _clean_key(path: str) -> str:
    clean = path.replace("\\", "/").lstrip("/")
    if ".." in clean.split("/"):
        clean = Path(clean).name
    return clean


def _write_project(
    files: dict[str, str],
    root: Path,
    *,
    subset: Iterable[str] = (),
    remappings: Iterable[str] = (),
    libs: Iterable[str] = (),
) -> Path:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    chosen = set(subset) or set(files)
    for path in sorted(chosen):
        if path not in files:
            continue
        clean = _clean_key(path)
        target = src / clean
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(files[path], encoding="utf-8")
    lines = [
        "[profile.default]",
        'src = "src"',
        'test = "test"',
        'out = "out"',
        "ast = true",
        "build_info = true",
    ]
    if libs:
        lines.append("libs = [" + ", ".join(json.dumps(str(p)) for p in libs) + "]")
    else:
        lines.append("libs = []")
    if remappings:
        lines.append("remappings = [" +
                     ", ".join(json.dumps(str(r)) for r in remappings) + "]")
    (root / "foundry.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return src


def _strip_metadata(code: bytes) -> bytes:
    if len(code) < 4:
        return code
    length = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - length
    if 0 < start < len(code) - 2 and code[start] in (0xA1, 0xA2, 0xA3, 0xA4):
        return code[:start]
    return code


def _matches(candidate: bytes, deployed: bytes) -> bool:
    return _strip_metadata(candidate) == _strip_metadata(deployed)


_IMPORT_RE = re.compile(
    r"""import\s+(?:[^;"']*?\s+from\s+)?["']([^"']+)["']""")


def _solc_dirs() -> list[Path]:
    home = Path.home()
    return [
        home / ".local" / "bin",
        home / ".foundry" / "bin",
        home / ".blackheart" / "bin",
        Path("/usr/local/bin"),
    ]


def _solc_version(path: Path) -> tuple[int, int, int]:
    match = re.search(r"solc-v?(\d+)\.(\d+)\.(\d+)", path.name)
    if not match:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _versioned_solc(version: str = "") -> Optional[str]:
    """Return an installed versioned solc, newest first unless one is named."""
    wanted = version.lstrip("v").split("+")[0]
    candidates: list[Path] = []
    for directory in _solc_dirs():
        if not directory.is_dir():
            continue
        for path in directory.glob("solc-*"):
            if not path.is_file() or not os.access(path, os.X_OK):
                continue
            if wanted and _solc_version(path) != tuple(
                    int(part) for part in wanted.split(".")[:3]):
                continue
            candidates.append(path)
    if not candidates:
        return None
    return str(max(candidates, key=_solc_version))


def find_solc() -> Optional[str]:
    """Resolve a standalone solc, including ``~/.local/bin/solc-<version>``."""
    from ..engines.solidity.base import resolve_tool

    found = resolve_tool("solc")
    if found is not None:
        return found.binary
    return _versioned_solc()


def _resolve_compiler(requested: str, entry_files: Iterable[str]) -> Optional[tuple[str, str]]:
    requested = requested.strip()
    if requested:
        is_version = bool(requested) and (
            requested[0].isdigit()
            or (requested.startswith("v") and len(requested) > 1 and requested[1].isdigit())
            or "+commit" in requested)
        if is_version:
            versioned = _versioned_solc(requested)
            if versioned:
                return "solc", versioned
            return find_compiler()
        candidate = Path(requested).expanduser()
        if candidate.exists():
            tool = "forge" if candidate.name == "forge" else "solc"
            return tool, str(candidate)
        if requested == "solc":
            found = find_solc()
            return ("solc", found) if found else None
        from ..engines.solidity.base import resolve_tool
        resolved = resolve_tool(requested)
        if resolved is None:
            return None
        return requested, resolved.binary
    if tuple(entry_files):
        found = find_solc()
        if found:
            return "solc", found
    return find_compiler()


def discover_compile_inputs(root: str | Path) -> tuple[list[str], list[str], list[str]]:
    """Find include paths, remappings and libs a real project already declares.

    Foundry's ``foundry.toml`` and ``remappings.txt`` are read when present;
    Hardhat and Foundry both use ``node_modules``, so ancestor directories are
    searched too. Only existing directories are returned. Nothing is guessed:
    a missing dependency directory is absent from the result and the compiler's
    own diagnostic names the import that could not be resolved.
    """
    base = Path(root).expanduser().resolve()
    include: list[str] = []
    remappings: list[str] = []
    libs: list[str] = []

    def add_include(path: str | Path) -> None:
        candidate = Path(path).expanduser()
        if candidate.is_dir():
            text = str(candidate.resolve())
            if text not in include:
                include.append(text)

    def add_remapping(prefix: str, target: str, origin: Path) -> None:
        target_path = Path(target).expanduser()
        trailing = target.endswith(("/", "\\"))
        if not target_path.is_absolute():
            target_path = (origin / target_path).resolve()
        text = f"{prefix}={target_path}" + ("/" if trailing else "")
        if text not in remappings:
            remappings.append(text)

    config_bases = [base, *list(base.parents)[:3]]
    for origin in config_bases:
        config = origin / "foundry.toml"
        if not config.is_file() or tomllib is None:
            continue
        try:
            data = tomllib.loads(config.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        profile = (data.get("profile") or {}).get("default")
        if not isinstance(profile, dict):
            profile = data
        for lib in profile.get("libs") or []:
            candidate = Path(str(lib)).expanduser()
            if not candidate.is_absolute():
                candidate = (origin / candidate).resolve()
            if candidate.is_dir():
                add_include(candidate)
                libs.append(str(candidate))
        for path in profile.get("allow_paths") or []:
            candidate = Path(str(path)).expanduser()
            if not candidate.is_absolute():
                candidate = (origin / candidate).resolve()
            add_include(candidate)
        for remap in profile.get("remappings") or []:
            if isinstance(remap, str) and "=" in remap:
                prefix, target = remap.split("=", 1)
                add_remapping(prefix, target, origin)
        break

    for origin in config_bases:
        remap_file = origin / "remappings.txt"
        if not remap_file.is_file():
            continue
        for line in remap_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                prefix, target = line.split("=", 1)
                add_remapping(prefix.strip(), target.strip(), origin)
        break

    for origin in [base, *base.parents]:
        add_include(origin / "node_modules")
        add_include(origin / "lib")
    return include, remappings, libs


def _dependency_closure(
    files: dict[str, str],
    entry_files: Iterable[str],
    remappings: Iterable[str],
    project_root: Optional[Path],
    include_paths: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    """Return the entry files' internal import closure and unresolved imports."""
    entries = [_clean_key(path) for path in entry_files]
    normalised: list[str] = []
    for entry in entries:
        if entry in files:
            normalised.append(entry)
            continue
        match = next((key for key in files
                      if key == entry or key.endswith("/" + entry)), None)
        if match:
            normalised.append(match)
    if not normalised:
        return [], []

    remap_pairs: list[tuple[str, str]] = []
    for remap in remappings:
        if "=" not in remap:
            continue
        prefix, target = remap.split("=", 1)
        target = target.replace("\\", "/")
        if project_root is not None:
            try:
                target = Path(target).resolve().relative_to(
                    project_root.resolve()).as_posix()
            except (OSError, ValueError):
                pass
        remap_pairs.append((prefix, target))

    def resolve(spec: str, current: str) -> Optional[str]:
        if spec.startswith("."):
            candidate = posixpath.normpath(
                posixpath.join(posixpath.dirname(current), spec))
        else:
            candidate = spec
            for prefix, target in remap_pairs:
                if spec.startswith(prefix):
                    candidate = target + spec[len(prefix):]
                    break
        candidate = candidate.replace("\\", "/").lstrip("/")
        if candidate in files:
            return candidate
        for key in files:
            if key == candidate or key.endswith("/" + candidate):
                return key
        return None

    seen: set[str] = set()
    queue = list(normalised)
    unresolved: list[str] = []
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        for spec in _IMPORT_RE.findall(files.get(current, "")):
            found = resolve(spec, current)
            if found is not None:
                if found not in seen:
                    queue.append(found)
            elif not _external_import_exists(spec, remap_pairs, include_paths):
                if spec not in unresolved:
                    unresolved.append(spec)
    return sorted(seen), unresolved


def _external_import_exists(
    spec: str,
    remappings: Iterable[tuple[str, str]],
    include_paths: Iterable[str],
) -> bool:
    candidate = spec
    for prefix, target in remappings:
        if spec.startswith(prefix):
            candidate = target + spec[len(prefix):]
            break
    path = Path(candidate).expanduser()
    if path.is_file():
        return True
    for include in include_paths:
        if (Path(include) / candidate).is_file():
            return True
    return False


def _compiler_diagnostic(payload: object, output: str) -> str:
    if isinstance(payload, dict):
        for error in payload.get("errors") or []:
            if isinstance(error, dict) and error.get("severity") == "error":
                text = str(error.get("formattedMessage") or error.get("message") or "")
                if text:
                    return text.strip().splitlines()[0][:500]
    for line in (output or "").splitlines():
        if line.startswith("Error:") or "not found" in line.lower():
            return line.strip()[:500]
    return ""


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _exact_pragma(files: dict[str, str], subset: Iterable[str]) -> str:
    """Return the one exact solc version a target's closure requires, if any."""
    exact: set[str] = set()
    for path in subset:
        for constraint in _PRAGMA_RE.findall(files.get(path, "")):
            for token in constraint.replace("||", " ").split():
                token = token.strip()
                if token.startswith("="):
                    token = token[1:]
                if re.fullmatch(r"\d+\.\d+\.\d+", token):
                    exact.add(token)
    return exact.pop() if len(exact) == 1 else ""


def _covered_by_include(prefix: str, include_paths: Iterable[str]) -> bool:
    for include in include_paths:
        if (Path(include) / prefix.rstrip("/")).exists():
            return True
    return False


def _solc_remappings(
    remappings: Iterable[str],
    project_root: Optional[Path],
    include_paths: Iterable[str],
) -> list[str]:
    """Keep only remappings the compiler still needs and can resolve.

    A dependency already reachable through an include path is left to that path;
    an absolute remapping target outside the temporary project is not portable.
    An internal target is rewritten into the temporary project's ``src`` tree.
    """
    out: list[str] = []
    for remap in remappings:
        if "=" not in remap:
            continue
        prefix, target = remap.split("=", 1)
        if _covered_by_include(prefix, include_paths):
            continue
        trailing = target.endswith("/")
        path = Path(target).expanduser()
        if project_root is not None and path.is_absolute():
            try:
                rel = path.resolve().relative_to(project_root.resolve())
                target = "src/" + rel.as_posix()
            except (OSError, ValueError):
                if not path.exists():
                    continue
        out.append(f"{prefix}={target}" + ("/" if trailing and not target.endswith("/") else ""))
    return out


def compile_sources(
    files: dict[str, str],
    *,
    compiler: str = "",
    timeout: int = 180,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    entry_files: Iterable[str] = (),
    include_paths: Iterable[str] = (),
    remappings: Iterable[str] = (),
    project_root: str | Path | None = None,
) -> SourceCompile:
    """Compile ``files`` and return runtime bytecode per contract.

    ``entry_files`` narrows a large repository to the target's import closure,
    so an unrelated broken contract cannot fail the build. ``project_root``
    discovers Foundry/Hardhat include paths and remappings from the tree the
    operator already has. A missing import is named from the compiler's own
    diagnostic; a failed build is never reported as clean.
    """
    if not files:
        return SourceCompile("INCOMPLETE", reason="no Solidity files to compile")

    project = Path(project_root).expanduser().resolve() if project_root else None
    discovered_include, discovered_remaps, discovered_libs = (
        discover_compile_inputs(project) if project else ([], [], []))

    def normalise_paths(paths: Iterable[str]) -> list[str]:
        out: list[str] = []
        for raw in paths:
            candidate = Path(str(raw)).expanduser()
            if not candidate.is_absolute() and project is not None:
                candidate = project / candidate
            if candidate.exists():
                text = str(candidate.resolve())
                if text not in out:
                    out.append(text)
        return out

    includes = normalise_paths([*include_paths, *discovered_include])

    def normalise_remaps(items: Iterable[str]) -> list[str]:
        out: list[str] = []
        for raw in items:
            if "=" not in str(raw):
                continue
            prefix, target = str(raw).split("=", 1)
            candidate = Path(target).expanduser()
            trailing = target.endswith(("/", "\\"))
            if not candidate.is_absolute():
                candidate = (project or Path.cwd()) / candidate
            text = f"{prefix}={candidate.resolve()}" + ("/" if trailing else "")
            if text not in out:
                out.append(text)
        return out

    remaps = normalise_remaps([*remappings, *discovered_remaps])
    subset, unresolved = _dependency_closure(
        files, entry_files, remaps, project, includes)

    requested = compiler.strip()
    if not requested and subset:
        exact = _exact_pragma(files, subset)
        if exact:
            versioned = _versioned_solc(exact)
            if versioned is not None:
                resolved = ("solc", versioned)
            else:
                resolved = find_compiler()
                if resolved is None:
                    return SourceCompile(
                        "NO_COMPILER",
                        reason=f"the source requires solc {exact}, which is not installed")
        else:
            resolved = _resolve_compiler("", entry_files)
    else:
        resolved = _resolve_compiler(requested, entry_files)
    if resolved is None:
        return SourceCompile("NO_COMPILER", reason=(
            f"the requested compiler {compiler!r} could not be resolved"
            if compiler else "no Solidity compiler (forge/solc) is installed"))
    tool, path = resolved

    root = Path(tempfile.mkdtemp(prefix="blackheart-solc-"))
    try:
        src = _write_project(files, root, subset=subset,
                             remappings=remaps, libs=discovered_libs)
        invoke = runner or subprocess.run
        if tool == "forge":
            # Foundry 1.10 no longer includes the AST unless asked; without
            # --ast the source binding silently falls back to the lexer.
            cmd = [path, "build", "--json", "--ast"]
        else:
            sol_files = sorted(str(p.relative_to(root))
                               for p in src.rglob("*.sol"))
            if not sol_files:
                return SourceCompile("INCOMPLETE", tool=tool,
                                     reason="the selected entry has no Solidity files")
            cmd = [path, "--base-path", str(root), "--combined-json",
                   "abi,bin,bin-runtime,storage-layout,ast"]
            for include in includes:
                cmd += ["--include-path", include]
            solc_remaps = _solc_remappings(remaps, project, includes)
            allowed = [str(root), *includes]
            for include in includes:
                real = os.path.realpath(include)
                if real not in allowed:
                    allowed.append(real)
            for remap in [*remaps, *solc_remaps]:
                target = remap.split("=", 1)[1].rstrip("/")
                for candidate in (target, os.path.realpath(target)):
                    if candidate and candidate not in allowed:
                        allowed.append(candidate)
            cmd += ["--allow-paths", ",".join(allowed)]
            cmd += solc_remaps
            cmd += sol_files
        try:
            proc = invoke(cmd, cwd=str(root), capture_output=True, text=True,
                          timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return SourceCompile("INCOMPLETE", tool=tool,
                                 reason=f"compiler failed: {exc}")
        payload = None
        try:
            payload = json.loads(proc.stdout or "")
        except (ValueError, TypeError):
            pass
        artifacts = (parse_forge_artifacts(payload) if tool == "forge"
                     else parse_solc_combined_json(payload))
        diagnostic = _compiler_diagnostic(payload, (proc.stdout or proc.stderr or ""))
        if not artifacts or getattr(proc, "returncode", 0) != 0:
            reason = ("the compiler produced no parseable artifacts "
                      "(a build failure is not a clean build)")
            if diagnostic:
                reason += f": {diagnostic}"
            if unresolved:
                reason += "; unresolved imports: " + ", ".join(unresolved[:5])
            return SourceCompile(
                "INCOMPLETE", tool=tool, reason=reason,
                output=(proc.stdout or proc.stderr or "")[:2000],
            )
        return SourceCompile("OK", tool=tool, artifacts=artifacts,
                             reason=f"compiled {len(artifacts)} contract(s) with {tool}")
    finally:
        shutil.rmtree(root, ignore_errors=True)

def recompile_runtime(
    files: dict[str, str],
    compiler: str,
    deployed_runtime: bytes,
    *,
    timeout: int = 180,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> bytes:
    """Compile and return the runtime that best matches ``deployed_runtime``.

    Raises ``RuntimeError`` with the compiler's own reason when no artifact was
    produced. A mismatch is returned (the largest runtime) so the caller's
    comparison can report it rather than treating the build as clean.
    """
    outcome = compile_sources(files, compiler=compiler, timeout=timeout, runner=runner)
    if not outcome.ok:
        raise RuntimeError(outcome.reason or outcome.status)
    runtimes = outcome.runtimes()
    if not runtimes:
        raise RuntimeError("the compiler produced no runtime bytecode")
    for code in runtimes.values():
        if _matches(code, deployed_runtime):
            return code
    return max(runtimes.values(), key=len)


def default_recompiler(
    deployed_runtime: bytes,
    *,
    timeout: int = 180,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> Callable[[dict[str, str], str], bytes]:
    """A recompiler callable suitable for ``build_verified_model``."""
    def _recompile(files: dict[str, str], compiler: str) -> bytes:
        return recompile_runtime(files, compiler, deployed_runtime,
                                 timeout=timeout, runner=runner)
    return _recompile
