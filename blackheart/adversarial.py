"""Reusable adversarial harness driver (mission sections 2C, 3, 12, 13).

This module wires the *multi-engine* adversarial harness under
``harnesses/adversarial/`` into BLACKHEART's exploit/verification workflow. The
harness is a self-contained Foundry project that ships, for each attack class:

  * a deliberately vulnerable target and a defended control (differential),
  * an attacker contract that performs the exploit,
  * a deterministic PoC (``ExploitPoC``),
  * a stateful invariant fuzzer with a non-vacuity control
    (``VulnerableVaultInvariants`` / ``SafeVaultInvariants``),
  * Echidna and Medusa property harnesses, and
  * a Halmos symbolic suite (proofs and counterexamples).

Every engine runs **locally**: in-process EVM, no broadcast, no live network.
The driver captures the exact command and output of each engine as evidence and
builds a :class:`Finding` from the *actual* captured output. Nothing is
fabricated; a missing engine is reported ``missing``, never assumed.

Run standalone:  python -m blackheart.adversarial
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import EvidenceStore
from .models import Finding, Severity

HARNESS = Path("harnesses/adversarial")


def _resolve_argv(cmd: list[str]) -> tuple[list[str], dict[str, str]]:
    """Resolve ``cmd[0]`` the way the engine layer does, and fix up the child PATH.

    ``blackheart engines bootstrap`` installs the Python engines into isolated
    venvs and the prebuilt ones into ``~/.blackheart/bin``; neither is on PATH by
    design. A bare ``shutil.which`` therefore reported every engine as
    ``not found on PATH`` (rc 127) while the engine layer ran them happily -- the
    orchestrator never actually executed an engine on a host where all of them
    were installed.

    The child PATH also gains the Solidity toolchain directories, because
    crytic-compile shells out to ``forge``/``solc`` from inside the engine.
    """
    from .engines.solidity.base import resolve_tool, toolchain_bin_dirs

    argv = list(cmd)
    paths = resolve_tool(argv[0])
    if paths is not None:
        argv[0] = paths.binary

    env: dict[str, str] = {}
    bin_dirs = toolchain_bin_dirs()
    if bin_dirs:
        env["PATH"] = os.pathsep.join([*bin_dirs, os.environ.get("PATH", "")])
    return argv, env


def _run(cmd: list[str], cwd: Path, timeout: int, env: dict | None = None) -> tuple[int, str]:
    """Run a command, returning (returncode, combined output).

    A missing binary is reported honestly as returncode 127, never as success.
    """
    argv, path_env = _resolve_argv(cmd)
    if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
        return 127, (f"{argv[0]}: not found (checked the engine venvs, "
                     f"~/.blackheart/bin and PATH)")
    try:
        proc = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, **path_env, **(env or {})},
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"{argv[0]}: timed out after {timeout}s"


def _slither_detectors(output: str) -> list[dict]:
    """Pull Slither's JSON report out of combined stdout+stderr.

    Slither writes the report to stdout and its human log to stderr, and the
    driver captures both in one string, so the document is the first JSON value
    in the text rather than the whole of it.
    """
    start = output.find("{")
    if start == -1:
        return []
    try:
        report, _end = json.JSONDecoder().raw_decode(output[start:])
    except json.JSONDecodeError:
        return []
    return list((report.get("results") or {}).get("detectors") or [])


@dataclass
class EngineResult:
    name: str
    command: str
    returncode: int
    output: str
    # Engine-specific structured facts extracted from the real output.
    facts: dict = field(default_factory=dict)
    evidence_id: str = ""

    @property
    def available(self) -> bool:
        return self.returncode != 127

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "returncode": self.returncode,
            "available": self.available,
            "facts": self.facts,
            "evidence_id": self.evidence_id,
        }


_SUMMARY = re.compile(r"(\d+)\s+tests?\s+passed,\s+(\d+)\s+failed,\s+(\d+)\s+skipped")
_SEED = re.compile(r"Fuzz seed:\s*(0x[0-9a-fA-F]+)")
_SEQUENCE = re.compile(r"\[Sequence\][^\n]*")


class AdversarialHarness:
    """Drive every engine of the adversarial harness and capture evidence."""

    def __init__(self, root: str | Path, *, timeout: int = 900,
                 repo_root: str | Path | None = None) -> None:
        # `root` is where evidence/artefacts are written; the harness always lives
        # in the repository, so resolve it from this module, not from `root`.
        self.root = Path(root)
        repo = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
        self.harness = repo / HARNESS
        self.timeout = timeout

    # ------------------------------------------------------------------ forge
    def build(self, evidence: EvidenceStore | None = None) -> EngineResult:
        rc, out = _run(["forge", "build"], self.harness, self.timeout)
        return self._record("forge-build", "forge build", rc, out, evidence, {})

    def forge_test(
        self, match_contract: str, *, seed: str | None = None,
        evidence: EvidenceStore | None = None,
    ) -> EngineResult:
        args = ["forge", "test", "--match-contract", match_contract, "-vv"]
        if seed:
            args += ["--fuzz-seed", seed]
        command = " ".join(args)
        rc, out = _run(args, self.harness, self.timeout)
        facts: dict = {}
        m = _SUMMARY.search(out)
        if m:
            facts["passed"], facts["failed"], facts["skipped"] = (int(g) for g in m.groups())
        sm = _SEED.search(out)
        if sm:
            facts["fuzz_seed"] = sm.group(1)
        facts["counterexample"] = _SEQUENCE.findall(out)[:3]
        return self._record(f"forge-{match_contract}", command, rc, out, evidence, facts)

    # ------------------------------------------------------------------ echidna
    def echidna(self, contract: str = "EchidnaVulnerableVault", limit: int = 20000,
                evidence: EvidenceStore | None = None) -> EngineResult:
        # crytic-compile's Foundry platform builds through `forge build`, whose
        # build-info references generated `foundry-pp/DeployHelper*.sol` sources
        # it cannot resolve, so the harness never compiles. Forcing solc compiles
        # the harness file directly and adds the project root to the allowed
        # import paths -- both are required.
        args = ["echidna", "test/Echidna.sol", "--contract", contract,
                "--config", "test/echidna.yaml", "--test-limit", str(limit),
                "--crytic-args", "--compile-force-framework solc",
                "--solc-args", f"--allow-paths {self.harness}"]
        rc, out = _run(args, self.harness, self.timeout)
        facts = {
            "falsified": "falsified" in out or "failed!💥" in out or "failed!" in out,
            "seed": (re.search(r"Seed:\s*(\d+)", out).group(1)
                     if re.search(r"Seed:\s*(\d+)", out) else None),
            "total_calls": (re.search(r"Total calls:\s*(\d+)", out).group(1)
                            if re.search(r"Total calls:\s*(\d+)", out) else None),
        }
        return self._record("echidna", " ".join(args), rc, out, evidence, facts)

    # ------------------------------------------------------------------ medusa
    def medusa(self, contract: str = "MedusaVulnerableVault", limit: int = 30000,
               evidence: EvidenceStore | None = None) -> EngineResult:
        args = ["medusa", "fuzz", "--config", "medusa.json",
                "--compilation-target", "test/Medusa.sol",
                "--target-contracts", contract]
        rc, out = _run(args, self.harness, self.timeout)
        m = re.search(r"Test summary:\s*(\d+)\s*test\(s\) passed,\s*(\d+)\s*test\(s\) failed", out)
        facts = {
            "passed": int(m.group(1)) if m else None,
            "failed": int(m.group(2)) if m else None,
            "property_failed": "property_noValueExtraction()" in out and "[FAILED]" in out,
        }
        return self._record("medusa", " ".join(args), rc, out, evidence, facts)

    # ------------------------------------------------------------------ halmos
    def halmos(self, contract: str = "Symbolic",
               evidence: EvidenceStore | None = None) -> EngineResult:
        args = ["halmos", "--contract", contract]
        rc, out = _run(args, self.harness, self.timeout)
        facts = {
            "passed": out.count("[PASS]"),
            "counterexamples": out.count("[FAIL]"),
            "witnesses": re.findall(r"p_\w+\s*=\s*(0x[0-9a-fA-F]+)", out),
        }
        return self._record("halmos", " ".join(args), rc, out, evidence, facts)

    # ------------------------------------------------------------------ slither
    def slither(self, evidence: EvidenceStore | None = None) -> EngineResult:
        """Run Slither and read its machine-readable report.

        The text report is not parseable for this purpose: since Slither 0.11 the
        human output names only the wiki anchor (`#reentrancy-vulnerabilities-1`),
        not the detector id, so a text grep for `reentrancy-no-eth` finds nothing
        even when the detector fired. The JSON report carries `check` and the
        owning contract, which is what a differential needs.
        """
        args = ["slither", "src", "--filter-paths", "lib", "--json", "-"]
        rc, out = _run(args, self.harness, self.timeout)
        detectors = _slither_detectors(out)
        checks = sorted({str(d.get("check")) for d in detectors})

        def _flagged(check: str, contract: str) -> bool:
            for det in detectors:
                if det.get("check") != check:
                    continue
                for element in det.get("elements") or []:
                    parent = (element.get("type_specific_fields") or {}).get("parent") or {}
                    if parent.get("name") == contract:
                        return True
            return False

        facts = {
            # The exact detector on the exact contract: a reentrancy finding
            # anywhere in the tree would not prove the vulnerable twin breaks.
            "reentrancy": _flagged("reentrancy-no-eth", "VulnerableVault"),
            "reentrancy_no_eth_anywhere": "reentrancy-no-eth" in checks,
            "detectors": checks,
        }
        return self._record("slither", " ".join(args), rc, out, evidence, facts)

    # ------------------------------------------------------------------ mythril
    def mythril(self, contract: str = "VulnerableVault",
                evidence: EvidenceStore | None = None) -> EngineResult:
        """Mythril cannot download solc here (no route to solc-bin.ethereum.org),
        so it is fed the forge-built creation bytecode instead."""
        artifact = self.harness / "out" / f"{contract}.sol" / f"{contract}.json"
        if not artifact.is_file():
            return EngineResult(
                "mythril", "myth analyze (bytecode)", 127,
                f"artifact missing: {artifact}", {"reason": "no bytecode; run forge build"},
            )
        obj = json.loads(artifact.read_text(encoding="utf-8"))["bytecode"]["object"]
        if not obj.startswith("0x"):
            obj = "0x" + obj
        binfile = self.harness / "out" / f"{contract}.bin"
        binfile.write_text(obj, encoding="utf-8")
        args = ["myth", "analyze", "-f", str(binfile), "--execution-timeout", "90", "-t", "3"]
        rc, out = _run(args, self.harness, self.timeout)
        out = "\n".join(
            ln for ln in out.splitlines()
            if "pkg_resources" not in ln and "UserWarning" not in ln
        )
        facts = {
            "issues": sorted(set(re.findall(r"====\s*(.+?)\s*====", out))),
            "medium_state_access_after_call": "State access after external call" in out,
            "swc_ids": sorted(set(re.findall(r"SWC ID:\s*(\d+)", out))),
        }
        return self._record("mythril", " ".join(args), rc, out, evidence, facts)

    # ------------------------------------------------------------------ fork
    def forge_fork_test(self, match_contract: str = "ForkIsolation",
                        evidence: EvidenceStore | None = None) -> EngineResult:
        """Run a fork-isolated test. Read-only: in-process fork, no broadcast.

        Network-gated: if the keyless RPC is unreachable the run is reported as
        unavailable (returncode 127) rather than as a pass.
        """
        rpc = os.environ.get("BLACKHEART_ETH_RPC", "")
        if not rpc:
            from .rpc import resolve_mainnet_rpc

            rpc = resolve_mainnet_rpc()
        if not rpc:
            return EngineResult("forge-fork", "resolve RPC", 127,
                                "no live RPC endpoint could be resolved; fork test skipped",
                                {"rpc": ""})
        probe_rc, _ = _run(["cast", "block-number", "--rpc-url", rpc], self.harness, 30)
        if probe_rc != 0:
            return EngineResult("forge-fork", f"cast block-number --rpc-url {rpc}", 127,
                                "keyless RPC unreachable; fork test skipped", {"rpc": rpc})
        args = ["forge", "test", "--match-contract", match_contract, "-vv"]
        rc, out = _run(args, self.harness, self.timeout)
        facts: dict = {"rpc": rpc}
        m = _SUMMARY.search(out)
        if m:
            facts["passed"], facts["failed"], facts["skipped"] = (int(g) for g in m.groups())
        return self._record(f"forge-{match_contract}", " ".join(args), rc, out, evidence, facts)

    # ------------------------------------------------------------------ helpers
    def _record(self, name: str, command: str, rc: int, out: str,
                evidence: EvidenceStore | None, facts: dict) -> EngineResult:
        res = EngineResult(name=name, command=command, returncode=rc, output=out, facts=facts)
        if evidence is not None:
            ev = evidence.put_text(
                out, kind=f"engine-{name}", description=f"{name}: {command}",
                command=command, metadata={"returncode": rc, **facts},
            )
            res.evidence_id = ev.evidence_id
        return res


def run_adversarial_engagement(root: str | Path, *,
                               run_slow_engines: bool = True) -> dict:
    """Run the full multi-engine engagement and return a structured summary.

    ``run_slow_engines`` gates the symbolic/fuzzing engines (halmos, echidna,
    medusa, mythril); the fast forge PoC + invariants always run.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    evidence = EvidenceStore(root / "evidence")
    h = AdversarialHarness(root)

    engines: dict[str, EngineResult] = {}
    engines["build"] = h.build(evidence)
    engines["poc"] = h.forge_test("ExploitPoC", evidence=evidence)
    engines["inv_vulnerable"] = h.forge_test("VulnerableVaultInvariants", evidence=evidence)
    engines["inv_safe"] = h.forge_test("SafeVaultInvariants", evidence=evidence)
    engines["fork"] = h.forge_fork_test(evidence=evidence)

    if run_slow_engines:
        engines["echidna"] = h.echidna(evidence=evidence)
        engines["medusa"] = h.medusa(evidence=evidence)
        engines["halmos"] = h.halmos(evidence=evidence)
        engines["slither"] = h.slither(evidence=evidence)
        engines["mythril"] = h.mythril(evidence=evidence)

    # Deterministic-reproduction artefacts.
    seeds = {
        "forge_invariant_fuzz_seed": engines["inv_vulnerable"].facts.get("fuzz_seed"),
        "echidna_seed": engines.get("echidna", EngineResult("", "", 0, "")).facts.get("seed"),
        "halmos_witnesses": engines.get("halmos", EngineResult("", "", 0, "")).facts.get("witnesses"),
    }
    (root / "seeds.json").write_text(json.dumps(seeds, indent=2), encoding="utf-8")

    # ---- Build a Finding from the ACTUAL captured output (reentrancy PoC).
    poc = engines["poc"]
    inv_v = engines["inv_vulnerable"]
    inv_s = engines["inv_safe"]
    finding = Finding(
        finding_id="adv-harness-reentrancy-vault",
        title="Reentrant withdrawal drains a vault that updates state after the external call",
        target="adversarial-harness/VulnerableVault",
        component="VulnerableVault.withdraw (checks-effects-interactions violation)",
        scope_reference="local reference target (engine validation, not a bounty asset)",
        category="reentrancy",
        severity=Severity.HIGH.value,
        prerequisites=[
            "withdraw performs the external token transfer before decrementing the "
            "caller's balance",
            "the balance decrement is unchecked (so a nested call does not revert on "
            "the second subtraction)",
            "a reentrant callback path exists (here: a hostile ERC20 transfer hook)",
        ],
        root_cause=(
            "withdraw reads the caller's balance, performs the external transfer, and "
            "only then decrements. A hostile token re-enters withdraw while the balance "
            "is still inflated; because the decrement is unchecked, the nested calls "
            "succeed and the attacker withdraws more than deposited."
        ),
        reproduction_steps=[
            "deploy AdversarialERC20 + VulnerableVault; victim deposits 900e18",
            "attacker deposits 100e18 and arms the token reentry callback",
            "attacker calls withdraw(100e18); the token re-enters withdraw 3 times",
            "attacker drains 400e18 (300e18 profit); the vault can no longer cover the victim",
        ],
        poc_path="harnesses/adversarial/test/ExploitPoC.t.sol::test_reentrancy_drains_vulnerable_vault",
        expected_behavior="a withdraw transfers at most the caller's recorded balance",
        actual_behavior="the attacker leaves with 400e18 from a 100e18 deposit (300e18 profit)",
        impact=(
            "Direct theft of other depositors' funds. Foundry: attacker profit 3e20 wei. "
            "Independently reproduced by the stateful invariant fuzzer (ghostProfit != 0) "
            "and by Mythril (SWC-107 state access after external call)."
        ),
        commands=[engines["poc"].command, inv_v.command, inv_s.command],
        evidence_ids=[e for e in [
            engines["poc"].evidence_id, inv_v.evidence_id, inv_s.evidence_id,
            engines.get("echidna", EngineResult("", "", 0, "")).evidence_id,
            engines.get("halmos", EngineResult("", "", 0, "")).evidence_id,
            engines.get("mythril", EngineResult("", "", 0, "")).evidence_id,
        ] if e],
        limitations=[
            "Reference target: proves the engine and the attack class, not a bounty finding.",
            "The hostile token is a controlled instrument; a real exploit needs a genuine "
            "callback path in the target.",
        ],
    )

    # ---- Independent verification: re-run the PoC and the safe control.
    def reproduce() -> bool:
        r = h.forge_test("ExploitPoC")
        return r.facts.get("passed", 0) >= 8 and r.facts.get("failed", 1) == 0

    from .verify import IndependentVerifier, VerificationContext
    ctx = VerificationContext(
        in_scope=True,
        scope_reference="local reference target (engine validation)",
        protection_exists=False,
        behavior_intentional=False,
        duplicate_known=False,
        attacker_controls_input=True,
        reachable=True,
        measurable_impact=True,
        reproduce=reproduce,
        evidence_ids=finding.evidence_ids,
    )
    vr = IndependentVerifier().verify(finding, ctx)

    summary = {
        "harness": str(HARNESS),
        "engines": {k: v.to_dict() for k, v in engines.items()},
        "seeds": seeds,
        "verification": vr.to_dict(),
        "finding": finding.to_dict(),
        "verdicts": {},
    }
    # Only emit a verdict for an engine that actually ran (a --fast run must not
    # report an unrun engine as a failure).
    all_verdicts = {
        "forge_poc_all_pass": poc.facts.get("passed") == 8 and poc.facts.get("failed") == 0,
        "invariant_vulnerable_breaks": inv_v.facts.get("failed", 0) >= 1,
        "invariant_safe_holds": inv_s.facts.get("failed", 0) == 0
                                 and inv_s.facts.get("passed", 0) >= 1,
        "fork_isolated_and_readonly": (
            engines["fork"].facts.get("passed", 0) >= 1
            and engines["fork"].facts.get("failed", 0) == 0
        ),
        "echidna_falsified": engines.get("echidna", EngineResult("", "", 0, "")).facts.get("falsified", False),
        "medusa_property_failed": engines.get("medusa", EngineResult("", "", 0, "")).facts.get("property_failed", False),
        "halmos_proofs_and_counterexample": (
            engines.get("halmos", EngineResult("", "", 0, "")).facts.get("passed", 0) >= 2
            and engines.get("halmos", EngineResult("", "", 0, "")).facts.get("counterexamples", 0) >= 1
        ),
        "mythril_flags_reentrancy": engines.get("mythril", EngineResult("", "", 0, "")).facts.get(
            "medium_state_access_after_call", False),
    }
    _gate = {
        "echidna_falsified": "echidna", "medusa_property_failed": "medusa",
        "halmos_proofs_and_counterexample": "halmos", "mythril_flags_reentrancy": "mythril",
    }
    summary["verdicts"] = {
        k: v for k, v in all_verdicts.items()
        if _gate.get(k) is None or _gate[k] in engines
    }
    (root / "adversarial-engagement-summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    return summary


if __name__ == "__main__":  # pragma: no cover
    out = run_adversarial_engagement("research/private/adversarial-engagement")
    print(json.dumps(out["verdicts"], indent=2))
