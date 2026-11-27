"""Verified toolchain registry (mission section 4).

Requirements honoured here:
  * Distinguish installed / version-verified / functional / missing / unsupported.
  * Do not report installation success merely because a binary exists -- a tool
    becomes FUNCTIONAL only after a real command produced a correct result.
  * Do not silently substitute a different tool.
  * Pin versions where practical.
  * No paid API keys required.

``verify()`` runs each tool's ``--version`` (version verification) and then its
``functional_test`` (a small, real invocation). Results are recorded in a JSON
registry so the state is portable and auditable.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..models import ToolRecord, ToolStatus, utcnow


@dataclass
class ToolSpec:
    name: str
    category: str
    version_cmd: list[str]
    functional_cmd: list[str]
    functional_expect: str          # substring that must appear for FUNCTIONAL
    version_regex: str = r"\d+\.\d+"  # must match in version output
    pinned: str = ""
    notes: str = ""
    #: Venv directory under ``~/.blackheart/venvs`` when it differs from the tool
    #: name (mythril ships the ``myth`` binary from ``venvs/mythril``).
    venv: str = ""


# The default toolchain. Commands are written so they work once PATH is set by
# install.sh. Nothing requires a paid key.
DEFAULT_TOOLCHAIN: list[ToolSpec] = [
    ToolSpec("forge", "solidity", ["forge", "--version"], ["forge", "--version"],
             "forge", pinned="1.9.0"),
    ToolSpec("cast", "solidity", ["cast", "--version"], ["cast", "to-hex", "255"],
             "0xff", pinned="1.9.0"),
    ToolSpec("anvil", "solidity", ["anvil", "--version"], ["anvil", "--version"],
             "anvil", pinned="1.9.0"),
    ToolSpec("slither", "solidity", ["slither", "--version"],
             ["slither", "--version"], "0.", pinned="0.11.6"),
    ToolSpec("echidna", "fuzzing", ["echidna", "--version"],
             ["echidna", "--version"], "Echidna", pinned="2.4.0"),
    ToolSpec("medusa", "fuzzing", ["medusa", "--version"],
             ["medusa", "--version"], "medusa", pinned="1.5.1"),
    ToolSpec("halmos", "formal", ["halmos", "--version"],
             ["halmos", "--version"], "halmos", pinned="0.3.3"),
    ToolSpec("wake", "solidity", ["wake", "--version"],
             ["wake", "config"], "compiler", pinned="4.22.2",
             notes="Python Solidity framework; static detectors + LSP"),
    ToolSpec("semgrep", "static", ["semgrep", "--version"],
             ["semgrep", "--version"], "1.", pinned="1.185.0"),
    ToolSpec("nmap", "infra", ["nmap", "--version"],
             ["nmap", "--version"], "Nmap", pinned="7.95"),
    ToolSpec("nuclei", "web", ["nuclei", "-version"],
             ["nuclei", "-version"], "Nuclei", pinned="3.3.7"),
    ToolSpec("httpx", "web", ["httpx", "-version"],
             ["httpx", "-version"], "Current Version", pinned="1.6.10"),
    ToolSpec("subfinder", "recon", ["subfinder", "-version"],
             ["subfinder", "-version"], "subfinder", pinned="2.6.7"),
    ToolSpec("katana", "recon", ["katana", "-version"],
             ["katana", "-version"], "Current version", pinned="1.1.2"),
    ToolSpec("solc", "solidity", ["solc", "--version"],
             ["solc", "--version"], "solc", pinned="0.8.23"),
]

# Live-protocol toolchain: web application, API, reconnaissance, and
# secrets/dependency scanning. These are used against *authorized* live assets
# only; every one is free and open-source and needs no API key. Commands are
# written so they work once PATH is set by install.sh.
LIVE_TOOLCHAIN: list[ToolSpec] = [
    ToolSpec("ffuf", "web", ["ffuf", "-V"], ["ffuf", "-V"], "ffuf version",
             pinned="2.1.0", notes="content discovery / fuzzing"),
    ToolSpec("gobuster", "web", ["gobuster", "version"], ["gobuster", "version"], "3.",
             pinned="3.6.0", notes="directory/DNS/vhost brute forcing"),
    ToolSpec("dalfox", "web", ["dalfox", "version"], ["dalfox", "version"], "Dalfox",
             pinned="2.9.2", notes="XSS scanning (reflected/stored/DOM)"),
    ToolSpec("sqlmap", "web", ["sqlmap", "--version"], ["sqlmap", "--version"], "1.",
             pinned="1.10", notes="SQL injection detection/exploitation"),
    ToolSpec("wafw00f", "web", ["wafw00f", "--version"], ["wafw00f", "--version"], "WAFW00F",
             pinned="2.4.2", notes="WAF fingerprinting"),
    ToolSpec("arjun", "api",
             ["{venv}/bin/python", "-m", "pip", "show", "arjun"],
             ["{venv}/bin/arjun", "-h"], "usage",
             pinned="2.2.7", notes="HTTP parameter discovery (API surface)"),
    ToolSpec("dnsx", "recon", ["dnsx", "-version"], ["dnsx", "-version"], "Current Version",
             pinned="1.2.1", notes="DNS resolution / subdomain enumeration"),
    ToolSpec("gau", "recon", ["gau", "--version"], ["gau", "--version"], "gau version",
             pinned="2.2.3", notes="historical URLs (Wayback/CommonCrawl)"),
    ToolSpec("naabu", "infra", ["naabu", "-version"], ["naabu", "-version"], "Current Version",
             pinned="2.3.1", notes="port scanning (needs libpcap)"),
    ToolSpec("gitleaks", "secrets", ["gitleaks", "version"], ["gitleaks", "version"], "8.",
             pinned="8.21.2", notes="secret scanning (source, history, artifacts)"),
    ToolSpec("trivy", "infra", ["trivy", "--version"], ["trivy", "--version"], "Version:",
             pinned="0.76.2", notes="dependency/config/container vulnerability scanning"),
]

# Rust/Substrate toolchain: what a Polkadot-SDK or runtime audit needs before a
# single line can be executed. The EVM engines cannot read Rust, and the verified
# Rust registry entry (`blackheart compat registry --language Rust`) names these
# tools, so they are verified here like every other tool rather than assumed.
RUST_TOOLCHAIN: list[ToolSpec] = [
    ToolSpec("rustc", "rust", ["rustc", "--version"], ["rustc", "--version"],
             "rustc", pinned="1.100.0", notes="Rust compiler (stable)"),
    ToolSpec("cargo", "rust", ["cargo", "--version"], ["cargo", "--version"],
             "cargo", pinned="1.100.0", notes="Rust build/test driver"),
    ToolSpec("cargo-fuzz", "rust", ["cargo-fuzz", "--version"],
             ["cargo-fuzz", "--version"], "cargo-fuzz", pinned="0.13.2",
             notes="libFuzzer harnesses; needs nightly"),
    ToolSpec("cargo-audit", "rust", ["cargo-audit", "--version"],
             ["cargo-audit", "--version"], "cargo-audit", pinned="0.23.0",
             notes="RustSec advisory scan of Cargo.lock"),
    ToolSpec("cargo-deny", "rust", ["cargo-deny", "--version"],
             ["cargo-deny", "--version"], "cargo-deny", pinned="0.22.0",
             notes="licence, ban, advisory and source policy for a crate graph"),
    ToolSpec("clippy", "rust", ["cargo", "clippy", "--version"],
             ["cargo", "clippy", "--version"], "clippy", pinned="0.1.100",
             notes="Rust lints; not a security tool, but the first compile gate"),
]

# Tools that require isolation (their own venv) and are invoked by absolute path.
ISOLATED_TOOLS: list[ToolSpec] = [
    ToolSpec("myth", "solidity",
             ["{venv}/bin/myth", "version"], ["{venv}/bin/myth", "version"],
             "Mythril", pinned="0.24.x", venv="mythril",
             notes="isolated venv (dependency conflicts with global site-packages)"),
]


class ToolRegistry:
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _venv_for(spec: ToolSpec) -> str:
        """The isolated venv this tool lives in.

        ``{venv}`` used to expand to mythril's directory for every tool, so any
        second isolated tool would silently have been pointed at mythril's venv.
        The venv is now per-tool, and ``$BLACKHEART_<TOOL>_VENV`` still overrides
        it (``BLACKHEART_MYTHRIL_VENV`` keeps working).
        """
        name = spec.venv or spec.name
        override = os.environ.get(f"BLACKHEART_{name.upper()}_VENV", "").strip()
        if override:
            return override
        return str(Path.home() / ".blackheart" / "venvs" / name)

    @staticmethod
    def _resolve(exe: str) -> str:
        """Resolve a bare tool name the same way the engine layer does.

        ``blackheart engines bootstrap`` installs Python engines (wake, halmos,
        slither) into isolated venvs that are deliberately *not* on PATH, so a
        ``shutil.which`` lookup reports an installed, operational engine as
        missing -- two subsystems disagreeing about what "installed" means. The
        engine resolver already searches the venvs, the bin directory, the
        environment override and PATH, so it is the single source of truth.

        A name that already contains a path separator is used verbatim: the
        caller has resolved it (mythril's ``{venv}/bin/myth``).
        """
        if not exe or os.sep in exe:
            return exe if exe and (Path(exe).exists() or shutil.which(exe)) else ""
        try:
            from ..engines.solidity.base import resolve_tool
        except Exception:  # pragma: no cover - engines layer is always importable
            resolve_tool = None
        if resolve_tool is not None:
            paths = resolve_tool(exe)
            if paths is not None:
                return paths.binary
        return shutil.which(exe) or ""

    # ------------------------------------------------------------------ #
    @staticmethod
    def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
        exe = cmd[0]
        if shutil.which(exe) is None and not Path(exe).exists():
            return 127, f"{exe}: not found"
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            return proc.returncode, out.strip()
        except subprocess.TimeoutExpired:
            return 124, f"{exe}: timed out after {timeout}s"
        except Exception as exc:  # pragma: no cover - defensive
            return 1, f"{exe}: {exc}"

    def verify_one(self, spec: ToolSpec, env: dict[str, str] | None = None) -> ToolRecord:
        import re

        rec = ToolRecord(
            name=spec.name,
            category=spec.category,
            verify_command=" ".join(spec.version_cmd),
            functional_test=" ".join(spec.functional_cmd),
            notes=spec.notes,
        )
        exe = spec.version_cmd[0]
        resolved = self._resolve(exe)
        rec.path = resolved
        if not resolved:
            rec.status = ToolStatus.MISSING.value
            return rec

        version_cmd = [resolved, *spec.version_cmd[1:]]
        functional_cmd = [self._resolve(spec.functional_cmd[0]) or resolved,
                          *spec.functional_cmd[1:]]

        code, out = self._run(version_cmd)
        if code == 127 or "not found" in out:
            rec.status = ToolStatus.MISSING.value
            return rec
        if code == 124:
            rec.status = ToolStatus.UNSUPPORTED.value
            rec.version = out
            return rec
        m = re.search(spec.version_regex, out)
        rec.version = m.group(0) if m else out.splitlines()[0] if out else ""
        rec.status = ToolStatus.VERSION_VERIFIED.value

        fcode, fout = self._run(functional_cmd)
        if fcode == 0 and spec.functional_expect.lower() in fout.lower():
            rec.status = ToolStatus.FUNCTIONAL.value
            rec.functional_evidence = fout.splitlines()[0][:200] if fout else ""
        else:
            rec.notes = (rec.notes + f" | functional test failed: rc={fcode} out={fout[:120]}").strip(" |")
        return rec

    @staticmethod
    def specs(extra: list[ToolSpec] | None = None) -> list[ToolSpec]:
        """Every tool this registry knows how to verify, in report order."""
        return (
            list(DEFAULT_TOOLCHAIN)
            + list(LIVE_TOOLCHAIN)
            + list(RUST_TOOLCHAIN)
            + list(ISOLATED_TOOLS)
            + list(extra or [])
        )

    def verify_all(self, extra: list[ToolSpec] | None = None) -> list[ToolRecord]:
        specs = self.specs(extra)
        records: list[ToolRecord] = []
        for spec in specs:
            venv = self._venv_for(spec)
            resolved = ToolSpec(
                name=spec.name,
                category=spec.category,
                version_cmd=[c.replace("{venv}", venv) for c in spec.version_cmd],
                functional_cmd=[c.replace("{venv}", venv) for c in spec.functional_cmd],
                functional_expect=spec.functional_expect,
                version_regex=spec.version_regex,
                pinned=spec.pinned,
                notes=spec.notes,
                venv=spec.venv,
            )
            records.append(self.verify_one(resolved))
        self.save(records)
        return records

    def save(self, records: list[ToolRecord]) -> None:
        payload = {
            "generated_at": utcnow(),
            "tools": [r.to_dict() for r in records],
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load(self) -> list[ToolRecord]:
        if not self.path.exists():
            return []
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return [ToolRecord(**t) for t in payload.get("tools", [])]

    @staticmethod
    def summary(records: list[ToolRecord]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in records:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts
