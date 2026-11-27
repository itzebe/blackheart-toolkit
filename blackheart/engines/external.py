"""Fail-closed integration of external security tools.

This is the honest way to "add a tool": register it with real provenance, run it
only when it is installed and the compatibility gate admits the target, and
record what it produced. It never invents a result.

Design rules (mirroring the engine adapters and the compatibility gate):

* **Nothing runs ungated.** A run without a compatibility record bound to the
  target is ``BLOCKED`` before the binary is touched.
* **A missing tool is missing.** ``NOT_INSTALLED`` names the install hint; it is
  never read as "clean".
* **A lead is not a finding.** Parsed output is a list of *leads* (rule, level,
  location). No ``disposition``/``confirmed`` is ever set here; BLACKHEART's own
  verification gate is the only thing that can raise a lead to a finding.
* **No fake invocation.** A tool whose CLI shape is not verified here is
  registered as ``MANUAL`` with its docs and install hint, never given a
  guessed command line.
* **A clean run is not proof of safety.** ``COMPLETED`` with zero leads says so
  in its detail.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any

from ..toolchain.enforce import ExecutionTarget, bind
from .solidity.base import resolve_tool

#: Bounded raw output kept on an outcome (never the whole report).
_MAX_OUTPUT = 8000
#: A text parser keeps at most this many non-empty lines as leads.
_MAX_TEXT_LEADS = 200


@dataclass(frozen=True)
class ExternalTool:
    """One external tool and the gap it closes. Metadata is real, not decorative."""

    name: str
    kind: str            # scanner | fuzzer | symbolic | formal | reverse | intel | corpus | supply | debug | llm
    license: str
    docs: str
    gap: str
    install: str = ""
    #: Arguments after the binary; ``{target}`` is substituted. Empty = MANUAL.
    command: tuple[str, ...] = ()
    #: How to parse stdout: sarif | json | text | "" (raw artifact only).
    format: str = ""

    @property
    def runnable(self) -> bool:
        return bool(self.command) and not self.manual

    @property
    def manual(self) -> bool:
        return not self.command

    def to_dict(self) -> dict:
        return {
            "name": self.name, "kind": self.kind, "license": self.license,
            "docs": self.docs, "gap": self.gap, "install": self.install,
            "command": list(self.command), "format": self.format,
            "runnable": self.runnable,
        }


#: The registered tools. Runnable entries have a verified CLI shape; the rest are
#: documented for manual use so no command line is fabricated.
EXTERNAL_TOOLS: dict[str, ExternalTool] = {
    # --- runnable scanners (SARIF / JSON / text) -------------------------------
    "semgrep": ExternalTool(
        "semgrep", "scanner", "LGPL-2.1", "https://semgrep.dev/docs/",
        "cheap multi-language breadth (custom rules in minutes)",
        install="pipx install semgrep  # or: brew install semgrep",
        command=("--sarif", "--config", "auto", "--quiet", "{target}"), format="sarif"),
    "gosec": ExternalTool(
        "gosec", "scanner", "Apache-2.0", "https://github.com/securego/gosec",
        "Go client static security (BSC/op-geth are Go)",
        install="go install github.com/securego/gosec/v2/cmd/gosec@latest",
        command=("-fmt=json", "-quiet", "{target}"), format="json"),
    "govulncheck": ExternalTool(
        "govulncheck", "scanner", "BSD-3-Clause", "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
        "Go vulnerability database matching",
        install="go install golang.org/x/vuln/cmd/govulncheck@latest",
        command=("-json", "{target}"), format="json"),
    "staticcheck": ExternalTool(
        "staticcheck", "scanner", "MIT", "https://staticcheck.dev/",
        "Go static analysis beyond the compiler",
        install="go install honnef.co/go/tools/cmd/staticcheck@latest",
        command=("-f", "json", "{target}"), format="json"),
    "osv-scanner": ExternalTool(
        "osv-scanner", "supply", "Apache-2.0", "https://google.github.io/osv-scanner/",
        "dependency supply-chain matching (OSV database)",
        install="go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        command=("--format", "json", "-r", "{target}"), format="json"),
    "grype": ExternalTool(
        "grype", "supply", "Apache-2.0", "https://github.com/anchore/grype",
        "image/filesystem vulnerability matching",
        install="brew install grype  # or: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh",
        command=("{target}", "-o", "json", "-q"), format="json"),
    "syft": ExternalTool(
        "syft", "supply", "Apache-2.0", "https://github.com/anchore/syft",
        "SBOM generation feeding grype/osv",
        install="brew install syft  # or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh",
        command=("{target}", "-o", "json", "-q"), format="json"),
    "trivy": ExternalTool(
        "trivy", "supply", "Apache-2.0", "https://trivy.dev/",
        "filesystem/image SBOM + vulnerability scan",
        install="brew install trivy  # or: apt-get install trivy",
        command=("fs", "--format", "json", "--quiet", "{target}"), format="json"),
    # --- registered for manual use (documented, no guessed CLI) ----------------
    "ityfuzz": ExternalTool(
        "ityfuzz", "fuzzer", "Apache-2.0", "https://github.com/fuzzland/ityfuzz",
        "real-EVM offensive coverage-guided fuzzing (closes the #1 fidelity gap)",
        install="cargo install --git https://github.com/fuzzland/ityfuzz ityfuzz"),
    "hevm": ExternalTool(
        "hevm", "symbolic", "AGPL-3.0", "https://github.com/ethereum/hevm",
        "bytecode symbolic execution + equivalence",
        install="see docs; builds with cabal/nix"),
    "evmole": ExternalTool(
        "evmole", "reverse", "MIT", "https://github.com/cdump/evmole",
        "fast bytecode ABI/selector/arg recovery (turns Heimdall structure into an ABI)",
        install="pip install evmole"),
    "whatsabi": ExternalTool(
        "whatsabi", "reverse", "MIT", "https://github.com/shazow/whatsabi",
        "bytecode ABI recovery (JS)",
        install="npm install -g whatsabi"),
    "ghidra": ExternalTool(
        "ghidra", "reverse", "Apache-2.0", "https://ghidra-sre.org/",
        "deep binary reverse engineering (headless analyser) for Go/Rust clients",
        install="download from ghidra-sre.org"),
    "goresym": ExternalTool(
        "goresym", "reverse", "Apache-2.0", "https://github.com/mandiant/GoReSym",
        "recover symbols/strings from a stripped Go binary (BSC client)",
        install="go install github.com/mandiant/GoReSym@latest"),
    "redress": ExternalTool(
        "redress", "reverse", "BSD-3-Clause", "https://github.com/goretk/redress",
        "Go binary analysis (packages, types, call graph)",
        install="go install github.com/goretk/redress@latest"),
    "solodit": ExternalTool(
        "solodit", "intel", "commercial-API", "https://solodit.cyfrin.io/",
        "known-issue / duplicate intel across audit contests (eligibility)",
        install="API: https://solodit.cyfrin.io/api"),
    "defihacklabs": ExternalTool(
        "defihacklabs", "corpus", "MIT", "https://github.com/SunWeb3Sec/DeFiHackLabs",
        "reproduced real DeFi exploit PoCs (recall corpus)",
        install="git clone https://github.com/SunWeb3Sec/DeFiHackLabs"),
    "smartbugs": ExternalTool(
        "smartbugs", "corpus", "Apache-2.0", "https://github.com/smartbugs/smartbugs-curated",
        "curated vulnerable-contract dataset + tool harness",
        install="git clone https://github.com/smartbugs/smartbugs-curated"),
    "4byte": ExternalTool(
        "4byte", "intel", "public", "https://www.4byte.directory/",
        "function-selector lookup",
        install="API: https://www.4byte.directory/api/v1/"),
    "kontrol": ExternalTool(
        "kontrol", "formal", "BSD-3-Clause", "https://github.com/runtimeverification/kontrol",
        "KEVM symbolic execution (formal proofs)",
        install="see docs; K framework toolchain"),
    "certora": ExternalTool(
        "certora", "formal", "commercial", "https://docs.certora.com/",
        "CVL formal verification (SaaS; optional, never a hard dependency)",
        install="pip install certora-cli (needs an API key)"),
    "propertygpt": ExternalTool(
        "propertygpt", "llm", "research", "https://github.com/SphereEx/PropertyGPT",
        "LLM-assisted invariant generation (hypothesis seeds, noisy)",
        install="see repo"),
    "delphi": ExternalTool(
        "delphi", "debug", "AGPL-3.0", "https://github.com/trailofbits/delphi",
        "interactive EVM step debugger",
        install="pip install delphi-evm"),
}


@dataclass
class ExternalOutcome:
    """What an external run produced -- leads and provenance, never a finding."""

    tool: str
    status: str                     # COMPLETED | PARTIAL | INCOMPLETE | BLOCKED | NOT_INSTALLED | MANUAL | UNKNOWN_TOOL
    detail: str
    leads: list[dict] = field(default_factory=list)
    output: str = ""
    command: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool, "status": self.status, "detail": self.detail,
            "leads": list(self.leads), "lead_count": len(self.leads),
            "output": self.output, "command": list(self.command),
            "note": "leads are candidates; only BLACKHEART's verification gate can "
                    "raise one to a finding",
        }


def parse_sarif(document: dict) -> list[dict]:
    """Extract ``runs[].results[]`` from a generic SARIF 2.1.0 document as leads."""
    leads: list[dict] = []
    for run in (document or {}).get("runs", []) or []:
        for result in run.get("results", []) or []:
            loc = ((result.get("locations") or [{}])[0]
                   .get("physicalLocation", {}) or {})
            region = loc.get("region", {}) or {}
            leads.append({
                "rule": result.get("ruleId", ""),
                "level": result.get("level", "warning"),
                "message": (result.get("message") or {}).get("text", ""),
                "path": (loc.get("artifactLocation") or {}).get("uri", ""),
                "line": region.get("startLine", 0),
            })
    return leads


def parse_json(document: Any) -> list[dict]:
    """Best-effort lead extraction from a tool's JSON output (shape-agnostic)."""
    if isinstance(document, dict):
        for key in ("findings", "results", "vulnerabilities", "matches", "Issues"):
            if isinstance(document.get(key), list):
                return [d for d in document[key] if isinstance(d, dict)]
        # govulncheck style: {"finding": {...}}
        if isinstance(document.get("finding"), dict):
            return [document["finding"]]
        return []
    if isinstance(document, list):
        return [d for d in document if isinstance(d, dict)]
    return []


def parse_text(text: str, limit: int = _MAX_TEXT_LEADS) -> list[dict]:
    """One lead per non-empty line, bounded. A line is a lead, never a finding."""
    leads: list[dict] = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        leads.append({"line": stripped})
        if len(leads) >= limit:
            break
    return leads


def _parse(fmt: str, stdout: str) -> tuple[list[dict], bool]:
    """Return (leads, parsed_ok). An unparseable body is not a clean result."""
    if fmt in ("sarif", "json"):
        try:
            document = json.loads(stdout)
        except (ValueError, TypeError):
            return [], False
        return (parse_sarif(document) if fmt == "sarif" else parse_json(document)), True
    if fmt == "text":
        return parse_text(stdout), True
    return [], True


def run_external(
    name: str,
    target: str,
    *,
    compatibility: Any,
    repository: str = "",
    commit: str = "",
    timeout: int = 300,
    runner: Any = None,
) -> ExternalOutcome:
    """Run one registered external tool behind the gate; return an honest outcome."""
    spec = EXTERNAL_TOOLS.get(name)
    if spec is None:
        return ExternalOutcome(name, "UNKNOWN_TOOL",
                               f"{name!r} is not a registered external tool")
    if spec.manual:
        return ExternalOutcome(
            name, "MANUAL",
            f"{name} is registered for manual use ({spec.docs}); install: {spec.install}")
    if compatibility is None:
        return ExternalOutcome(name, "BLOCKED", "no compatibility record; nothing was run")
    paths = resolve_tool(spec.name)
    if paths is None:
        return ExternalOutcome(
            name, "NOT_INSTALLED",
            f"{name} is not installed on this host; install: {spec.install or 'see ' + spec.docs}")
    decision = bind(compatibility, ExecutionTarget(
        name=target, repository=repository, commit=commit))
    if decision.decision != "ADMIT":
        return ExternalOutcome(name, "BLOCKED",
                               "gate refused: " + "; ".join(decision.reasons))
    command = [paths.binary] + [part.replace("{target}", target) for part in spec.command]
    invoke = runner or (lambda cmd, cwd, t: subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=t))
    try:
        proc = invoke(command, ".", timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ExternalOutcome(name, "INCOMPLETE", f"could not complete: {exc}", command=command)
    stdout = getattr(proc, "stdout", "") or ""
    output = stdout[: _MAX_OUTPUT]
    leads, parsed = _parse(spec.format, stdout)
    if leads:
        return ExternalOutcome(name, "COMPLETED", f"{len(leads)} lead(s)", leads, output, command)
    if getattr(proc, "returncode", 0) == 0 and parsed:
        return ExternalOutcome(
            name, "COMPLETED",
            "ran; no leads (not a proof of safety)", [], output, command)
    return ExternalOutcome(
        name, "INCOMPLETE",
        f"exit {getattr(proc, 'returncode', '?')}; output not parseable into leads",
        [], output, command)


def doctor() -> list[dict]:
    """Per registered tool: installed / missing / manual, resolved honestly."""
    rows: list[dict] = []
    for name, spec in sorted(EXTERNAL_TOOLS.items()):
        if spec.manual:
            state = "manual"
        else:
            state = "installed" if resolve_tool(spec.name) is not None else "missing"
        rows.append({"name": name, "kind": spec.kind, "state": state,
                     "license": spec.license, "gap": spec.gap})
    return rows


__all__ = [
    "ExternalTool", "EXTERNAL_TOOLS", "ExternalOutcome",
    "parse_sarif", "parse_json", "parse_text", "run_external", "doctor",
]
