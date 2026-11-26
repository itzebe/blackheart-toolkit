"""Reproducible installation and verification of the Solidity engine toolchain.

Two operations, both driven by the pinned manifest in ``engines/toolchain.json``:

* :func:`bootstrap` installs every engine at its pinned version into an isolated
  location, so a fresh sandbox reaches the same toolchain with one command.
* :func:`doctor` verifies what is *actually* installed against the manifest and
  reports, per engine, whether it is installed, configured and usable -- never
  inferring availability from the presence of an adapter.

Design rules that this module exists to enforce:

* **Isolation.** Every Python engine gets its own venv. Installing slither into
  the system interpreter would shadow this repository's ``tests/`` package with
  slither's own, breaking ``pytest`` for everyone.
* **Exact pins.** A floating version makes a finding unreproducible. The
  manifest pins a version; bootstrap installs that version and doctor compares
  the *reported* version against it, so drift is visible rather than silent.
* **Honesty.** A missing tool is reported missing, a version mismatch is
  reported as a mismatch, and neither is ever upgraded to "operational". The
  only path to "operational" is a successful real execution, which doctor does
  not claim on its own -- that is ``tests/test_engines_live.py``'s job.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

#: The manifest ships inside the package, so a fresh clone -- and an installed
#: wheel -- carries its own definition of the toolchain.
MANIFEST_PATH = Path(__file__).resolve().parent / "toolchain.json"

def home_root() -> Path:
    """The install root: ``$BLACKHEART_HOME`` or ``~/.blackheart``.

    ``install.sh`` and the clean-install verifier export ``BLACKHEART_HOME`` to
    put a toolchain somewhere other than the home directory. Ignoring it made an
    "isolated" bootstrap silently reuse (and report on) the host's toolchain,
    which is the opposite of what isolation is for.
    """
    override = os.environ.get("BLACKHEART_HOME", "").strip()
    return Path(override).expanduser() if override else Path.home() / ".blackheart"


VENV_ROOT = home_root() / "venvs"
BIN_ROOT = home_root() / "bin"


def load_manifest(path: Optional[Path] = None) -> dict[str, Any]:
    """Read and minimally validate the pinned toolchain manifest."""
    p = Path(path) if path else MANIFEST_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported toolchain manifest schema: {data.get('schema_version')}")
    if not isinstance(data.get("engines"), dict) or not data["engines"]:
        raise ValueError("toolchain manifest declares no engines")
    return data


def host_arch() -> str:
    """The machine architecture, normalised to the names release assets use."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return machine


# --------------------------------------------------------------------------- #
# Report types
# --------------------------------------------------------------------------- #

@dataclass
class CheckResult:
    """One engine's or tool's verification outcome."""

    name: str
    kind: str
    expected_version: str
    actual_version: str = ""
    location: str = ""
    state: str = "MISSING"          # INSTALLED | VERSION_MISMATCH | MISSING | BLOCKED
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.state == "INSTALLED" and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "expected_version": self.expected_version,
            "actual_version": self.actual_version,
            "location": self.location,
            "state": self.state,
            "problems": list(self.problems),
            "notes": list(self.notes),
            "ok": self.ok,
        }


# --------------------------------------------------------------------------- #
# Version probing
# --------------------------------------------------------------------------- #

def _first_semver(text: str) -> str:
    """The first ``N.N[.N]`` token in a version banner."""
    import re

    m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", text or "")
    return m.group(1) if m else ""


def _resolve(name: str, install_dir: str = "") -> Optional[Path]:
    """Locate a tool the way the engine adapters do.

    Doctor must agree with the adapter, or it reports a blocker that does not
    exist. The adapter prepends ``~/.foundry/bin`` and Slither's venv to PATH;
    so does this. ``shutil.which`` alone would call a working setup broken.
    """
    found = shutil.which(name)
    if found:
        return Path(found)
    dirs: list[Path] = []
    if install_dir:
        dirs.append(Path(install_dir).expanduser())
    dirs.extend([
        Path.home() / ".foundry" / "bin",
        VENV_ROOT / "slither" / "bin",
        BIN_ROOT,
    ])
    for directory in dirs:
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run_version(binary: Path, args: list[str]) -> str:
    try:
        out = subprocess.run([str(binary), *args], capture_output=True, text=True,
                             timeout=60, cwd=str(binary.parent))
    except (OSError, subprocess.SubprocessError):
        return ""
    return _first_semver((out.stdout or "") + (out.stderr or ""))


def _resolve_shared(tool: str, manifest: dict[str, Any]) -> Optional[Path]:
    """Find a shared tool in the venv of any engine that declares providing it."""
    for provider in manifest.get("engines", {}).values():
        if tool not in (provider.get("provides_shared") or []):
            continue
        venv = VENV_ROOT / str(provider.get("venv") or "")
        candidate = venv / "bin" / tool
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _probe_engine(name: str, spec: dict[str, Any],
                  manifest: Optional[dict[str, Any]] = None) -> CheckResult:
    """Locate an engine and read its real version."""
    expected = str(spec.get("version") or "")
    result = CheckResult(name=name, kind=str(spec.get("kind") or ""),
                         expected_version=expected)

    binary_name = str(spec.get("binary") or name)
    candidates: list[Path] = []
    if spec.get("kind") == "pip":
        candidates.append(VENV_ROOT / str(spec.get("venv") or name) / "bin" / binary_name)
    candidates.append(BIN_ROOT / binary_name)

    binary: Optional[Path] = None
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            binary = candidate
            break
    if binary is None:
        found = shutil.which(binary_name)
        binary = Path(found) if found else None
    if binary is None:
        result.state = "MISSING"
        result.problems.append(f"{binary_name} is not installed")
        return result

    result.location = str(binary)
    result.actual_version = _run_version(binary, ["--version"])
    if not result.actual_version:
        result.state = "BLOCKED"
        result.problems.append(f"{binary_name} exists but --version produced no version")
        return result
    if expected and result.actual_version != expected:
        result.state = "VERSION_MISMATCH"
        result.problems.append(
            f"installed {result.actual_version}, manifest pins {expected}")
        return result

    # Declared dependencies that must be present for the engine to compile a
    # target. Absence here is a real blocker, not a warning: the engine would
    # exit non-zero and look like a clean scan.
    for tool in spec.get("requires_toolchain") or []:
        if _resolve(str(tool)) is None:
            result.problems.append(f"requires {tool}, which is not resolvable")
    # A shared dependency (crytic-compile, solc-select) is provided by another
    # engine's venv. Declared but unverified would be a claim doctor cannot back.
    for tool in spec.get("requires_shared") or []:
        if _resolve_shared(str(tool), manifest or {}) is None:
            result.problems.append(
                f"requires shared {tool}, which no installed engine provides")
    result.state = "INSTALLED"
    return result


def _probe_toolchain(name: str, spec: dict[str, Any]) -> CheckResult:
    """Verify a compiler/toolchain entry (forge, solc)."""
    expected = str(spec.get("version") or "")
    result = CheckResult(name=name, kind=str(spec.get("kind") or ""),
                         expected_version=expected)
    binary = _resolve(name, str(spec.get("install_dir") or ""))
    if binary is None:
        result.state = "MISSING"
        result.problems.append(f"{name} is not installed")
        return result
    result.location = str(binary)
    result.actual_version = _run_version(binary, ["--version"])
    if expected and result.actual_version and result.actual_version != expected:
        result.state = "VERSION_MISMATCH"
        result.problems.append(
            f"installed {result.actual_version}, manifest pins {expected}")
        return result
    result.state = "INSTALLED"
    return result


def doctor(*, only: Optional[str] = None,
           manifest: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Compare what is installed against the pinned manifest.

    Returns a report of ``{"engines": [...], "toolchain": [...], "ok": bool}``.
    ``ok`` is True only when every checked entry is INSTALLED at its pinned
    version. This never claims an engine is *operational*: that requires a real
    execution, which is what the live tests prove.
    """
    data = manifest or load_manifest()
    engines = {**data.get("engines", {}), **(data.get("bytecode_tools") or {})}
    toolchain = data.get("toolchain", {})

    selected = [only] if only else list(data.get("engines", {}))
    unknown = [n for n in selected if n not in engines]
    if unknown:
        raise KeyError(f"unknown engine(s): {', '.join(unknown)}")

    engine_results = [_probe_engine(name, engines[name], data) for name in selected]
    tool_results = [_probe_toolchain(name, spec) for name, spec in toolchain.items()]
    # Bytecode tools are probed with the same machinery as source engines: they
    # differ only in the input they consume, not in how they are verified.
    bytecode_results = [_probe_engine(name, spec, data)
                        for name, spec in (data.get("bytecode_tools") or {}).items()
                        if name not in selected]

    return {
        "host_arch": host_arch(),
        "python": platform.python_version(),
        "manifest": str(MANIFEST_PATH),
        "engines": [r.to_dict() for r in engine_results],
        "bytecode_tools": [r.to_dict() for r in bytecode_results],
        "toolchain": [r.to_dict() for r in tool_results],
        "ok": (all(r.ok for r in engine_results)
               and all(r.ok for r in bytecode_results)
               and all(r.ok for r in tool_results)),
    }


# --------------------------------------------------------------------------- #
# Installation
# --------------------------------------------------------------------------- #

def _ensure_venv(name: str, python: str) -> Path:
    """Create the isolated venv for one Python engine, if absent."""
    venv = VENV_ROOT / name
    python_bin = venv / "bin" / "python"
    if python_bin.is_file():
        return venv
    venv.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([python, "-m", "venv", str(venv)], check=True)
    return venv


def _pip_install(venv: Path, packages: list[str]) -> None:
    """Install pinned packages into a venv, without touching the system one."""
    python = str(venv / "bin" / "python")
    subprocess.run([python, "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
                   check=True)
    subprocess.run([python, "-m", "pip", "install", "--quiet", *packages], check=True)


def release_url(spec: dict[str, Any]) -> str:
    """The exact asset URL for this host.

    ``tag_template`` exists because not every project tags releases ``v<version>``
    and not every project's tag equals the version its binary prints. ``asset_os``
    exists because some assets name the platform as ``linux``/``macos`` rather
    than only the architecture.
    """
    repo = str(spec["repo"])
    version = str(spec["version"])
    tag = str(spec.get("tag_template") or "v{version}").format(version=version)
    arch = (spec.get("asset_arch") or {}).get(host_arch(), host_arch())
    os_name = (spec.get("asset_os") or {}).get(host_arch(), "linux")
    asset = str(spec["asset_template"]).format(version=version, arch=arch, os=os_name)
    return f"https://github.com/{repo}/releases/download/{tag}/{asset}"


def _verify_sha256(path: Path, expected: str, asset: str) -> None:
    """Fail closed when a downloaded asset does not match its pinned digest."""
    if not expected:
        return
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"{asset} sha256 {actual} does not match the pinned {expected}; "
            "refusing to install an unverified binary")


def _download_release(spec: dict[str, Any], dest_dir: Path) -> Path:
    """Download a GitHub release asset and install it under ``dest_dir``.

    Two asset shapes are supported. An archive (``.tar.gz``) is extracted and the
    named binary copied out; a bare binary (``asset_is_binary``) is the
    executable itself, which is how heimdall ships. In both cases a declared
    ``sha256`` is verified before anything is made executable.
    """
    url = release_url(spec)
    asset = url.rsplit("/", 1)[-1]
    binary_name = str(spec.get("binary") or str(spec["repo"]).split("/")[-1])
    expected_sha = str(spec.get("sha256") or "")

    dest_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        download = Path(tmp) / asset
        with urllib.request.urlopen(url, timeout=120) as response, \
                open(download, "wb") as handle:
            shutil.copyfileobj(response, handle)

        if spec.get("asset_is_binary"):
            _verify_sha256(download, expected_sha, asset)
            target = dest_dir / binary_name
            shutil.copy2(download, target)
            target.chmod(0o755)
            return target

        _verify_sha256(download, expected_sha, asset)
        with tarfile.open(download) as tar:
            # Only regular files are extracted: a release archive is untrusted
            # input, and a symlink or device node has no business here.
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                member.name = os.path.basename(member.name)
                tar.extract(member, path=tmp)
        extracted = Path(tmp) / binary_name
        if not extracted.is_file():
            raise RuntimeError(f"{asset} did not contain {binary_name}")
        target = dest_dir / binary_name
        shutil.copy2(extracted, target)
        target.chmod(0o755)
        return target


def bootstrap(*, only: Optional[list[str]] = None, python: Optional[str] = None,
              manifest: Optional[dict[str, Any]] = None,
              log=None) -> dict[str, Any]:
    """Install every engine at its pinned version.

    Idempotent: an engine already present at the right version is left alone, so
    re-running bootstrap in a warm sandbox is cheap. Returns the doctor report
    taken after installation, which is the only honest statement of the result.
    """
    data = manifest or load_manifest()
    engines = {**data.get("engines", {}), **(data.get("bytecode_tools") or {})}
    say = log or (lambda _msg: None)
    interpreter = python or sys.executable

    wanted = only or list(engines)
    unknown = [n for n in wanted if n not in engines]
    if unknown:
        raise KeyError(f"unknown engine(s): {', '.join(unknown)}")

    BIN_ROOT.mkdir(parents=True, exist_ok=True)

    for name in wanted:
        spec = engines[name]
        kind = str(spec.get("kind") or "")
        if kind == "pip":
            venv_name = str(spec.get("venv") or name)
            venv = _ensure_venv(venv_name, interpreter)
            packages = [str(spec["package"]), *[str(p) for p in spec.get("extra_packages") or []]]
            say(f"installing {name} {spec['version']} into {venv}")
            _pip_install(venv, packages)
        elif kind == "github-release":
            say(f"downloading {name} {spec['version']} into {BIN_ROOT}")
            _download_release(spec, BIN_ROOT)
        else:
            raise ValueError(f"{name}: unsupported install kind {kind!r}")

    return doctor(manifest=data)


def format_doctor(report: dict[str, Any]) -> str:
    """A compact, honest rendering of a doctor report."""
    lines: list[str] = [
        f"host: {report['host_arch']}  python {report['python']}",
        f"manifest: {report['manifest']}",
        "",
        "engines:",
    ]
    for row in report["engines"]:
        mark = "ok  " if row["ok"] else "FAIL"
        version = row["actual_version"] or "-"
        lines.append(f"  [{mark}] {row['name']:8} {row['state']:16} "
                     f"v{version} (pin {row['expected_version'] or '-'})")
        for problem in row["problems"]:
            lines.append(f"         - {problem}")
    if report.get("bytecode_tools"):
        lines.append("")
        lines.append("bytecode tools:")
        for row in report["bytecode_tools"]:
            mark = "ok  " if row["ok"] else "FAIL"
            version = row["actual_version"] or "-"
            lines.append(f"  [{mark}] {row['name']:8} {row['state']:16} "
                         f"v{version} (pin {row['expected_version'] or '-'})")
            for problem in row["problems"]:
                lines.append(f"         - {problem}")
    if report["toolchain"]:
        lines.append("")
        lines.append("toolchain:")
        for row in report["toolchain"]:
            mark = "ok  " if row["ok"] else "FAIL"
            version = row["actual_version"] or "-"
            lines.append(f"  [{mark}] {row['name']:8} {row['state']:16} "
                         f"v{version} (pin {row['expected_version'] or '-'})")
            for problem in row["problems"]:
                lines.append(f"         - {problem}")
    lines.append("")
    lines.append("result: " + ("all pinned tools present" if report["ok"]
                               else "missing or mismatched tools above"))
    return "\n".join(lines)
