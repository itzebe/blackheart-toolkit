"""Product-surface helpers: onboarding, an offline demo, and grouped help.

These functions deliberately add no research engine. ``scaffold`` writes a
workspace whose authorization record is valid but **fails closed** (unverified,
no evidence), ``run_demo`` exercises the existing fuzzer, findings repository,
SARIF writer and baseline on the repository's own reference targets, and
``COMMAND_GROUPS`` is the curated map behind ``blackheart guide``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .baseline import compare, create, dumps as baseline_dumps
from .evidence import EvidenceStore
from .findings import FindingRecord, FindingRepository
from .findings.sarif import dumps as sarif_dumps, to_sarif, validate as validate_sarif
from .invariants import FuzzConfig, StatefulFuzzer
from .invariants.reference_targets import SafeVault, VulnerableVault
from .models import AuthorizationRecord, ReviewIndependence

SCAFFOLD_DIRS = ("findings", "evidence", "reports", "work", "targets")
GITIGNORE_LINES = (
    "findings/",
    "evidence/",
    "reports/",
    "work/",
    "authorization.json",
    "baseline.json",
)


def _authorization_template() -> str:
    record = AuthorizationRecord(
        program="",
        platform="",
        target_url="",
        scope_url="",
        checked_at="",
        program_active=None,
        safe_harbor=None,
        poc_required=None,
        nigerian_eligible=None,
        payout_feasible=None,
        zero_cost=None,
        assets={},
        asset_classes={},
        scope_patterns=[],
        scope_exclusions=[],
        retrieved_scope={},
        evidence=[],
        notes=(
            "TEMPLATE -- not authorization. Fill every field from the program's "
            "official policy, record dated evidence, and set verified=true only "
            "after the scope has been checked. Until then every gate fails closed."
        ),
        verified=False,
    )
    return json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n"


def _workspace_readme(root: Path) -> str:
    return f"""# BLACKHEART workspace

Created by `blackheart init` at `{root}`.

## Before any active testing

`authorization.json` is a **template that fails closed**. Fill it from the
program's official policy, record dated evidence, and set `verified: true` only
after you have checked the scope. A public repository or a deployed contract is
not authorization.

## Layout

- `findings/` -- the hash-chained findings repository (git-ignored)
- `evidence/` -- content-addressed evidence (git-ignored)
- `reports/` -- rendered reports and SARIF (git-ignored)
- `work/` -- engine workspaces (git-ignored)
- `targets/` -- target profiles you author
- `baseline.json` -- created by `blackheart baseline create` (git-ignored)

## Next steps

```bash
blackheart doctor
blackheart demo --dir .            # offline pipeline proof, no network
blackheart ingest <path> --synthesize --symbolic
blackheart findings --dir findings summary
blackheart findings --dir findings sarif --out reports/findings.sarif
blackheart baseline --findings findings create --out baseline.json
```

A finding is only `CONFIRMED` when it carries evidence, an independent
verification result and a named reviewer. Anything else is labelled by its
verdict.
"""


def scaffold(root: str | Path, *, force: bool = False) -> dict:
    """Create the workspace files. Existing files are kept unless ``force``."""
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    kept: list[str] = []

    for name in SCAFFOLD_DIRS:
        path = root / name
        if not path.exists():
            path.mkdir(parents=True)
            created.append(name + "/")

    files = {
        "authorization.json": _authorization_template(),
        "README.md": _workspace_readme(root),
    }
    for name, text in files.items():
        path = root / name
        if path.exists() and not force:
            kept.append(name)
            continue
        path.write_text(text, encoding="utf-8")
        created.append(name)

    ignore = root / ".gitignore"
    existing = ignore.read_text(encoding="utf-8").splitlines() if ignore.exists() else []
    missing = [line for line in GITIGNORE_LINES if line not in existing]
    if missing:
        with ignore.open("a", encoding="utf-8") as fh:
            if existing and existing[-1].strip():
                fh.write("\n")
            fh.write("\n".join(missing) + "\n")
        created.append(".gitignore")

    return {
        "root": str(root),
        "created": created,
        "kept": kept,
        "next": [
            "fill authorization.json from the official policy (it fails closed)",
            "blackheart doctor",
            "blackheart demo --dir .",
            "blackheart ingest <path> --synthesize --symbolic",
        ],
    }


def _sequence(failure: Any) -> list[str]:
    steps = failure.minimal_sequence or failure.sequence
    return [f"{s.actor}: {s.action}({json.dumps(s.params, sort_keys=True)})" for s in steps]


def run_demo(root: str | Path, *, runs: int = 300, steps: int = 10) -> dict:
    """Prove the pipeline on the repository's own vulnerable/guarded pair.

    No network, no Foundry, no provider key. The vulnerable model must break and
    the guarded twin must stay clean; otherwise the demo reports ``ok: False``
    rather than presenting a vacuous success.
    """
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    vulnerable = StatefulFuzzer(
        VulnerableVault(), FuzzConfig(runs=runs, steps_per_run=steps, seed=0)
    ).run()
    guarded = StatefulFuzzer(
        SafeVault(), FuzzConfig(runs=runs, steps_per_run=steps, seed=0)
    ).run()
    if not vulnerable.failures:
        return {"ok": False, "reason": "the vulnerable reference target did not break",
                "runs": runs, "steps": steps}
    if guarded.failures:
        return {"ok": False, "reason": "the guarded reference target also broke; the demo is vacuous",
                "runs": runs, "steps": steps,
                "guarded_failures": len(guarded.failures)}

    failure = vulnerable.failures[0]
    sequence = _sequence(failure)
    evidence = EvidenceStore(root / "evidence").put_json(
        {"vulnerable": vulnerable.to_dict(), "guarded": guarded.to_dict()},
        kind="demo-counterexample",
        description="reference vault counterexample + guarded control",
        command=f"StatefulFuzzer(runs={runs}, steps_per_run={steps}, seed=0)",
    )

    record = FindingRecord(
        finding_id="demo-erc4626-share-inflation",
        title="ERC4626 share inflation: donation before the first deposit steals a later depositor's funds",
        target="reference-erc4626-vault",
        component="VulnerableVault.deposit",
        affected_version="reference fixture",
        category="asset-theft",
        severity="high",
        root_cause_file="blackheart/invariants/reference_targets.py",
        root_cause_location="VulnerableVault.deposit",
        design_mistake="share price is manipulable by donating before the first deposit",
        hypothesis="An attacker donates to inflate the share price, then a victim deposits and the attacker redeems the victim's assets.",
        attack_sequence=sequence,
        consequences="The victim's deposit is absorbed by the attacker's shares.",
        repro_environment="pure-Python reference target; no network, no Foundry",
        repro_commands=["blackheart demo --dir ."],
        expected_behavior="The guarded vault holds share accounting under the same sequence.",
        observed_behavior=f"Vulnerable model produced {len(vulnerable.failures)} failure(s); guarded produced 0.",
        execution_result="PASS",
        evidence_ids=[evidence.evidence_id],
        verification_result=(
            "Deterministic control: the vulnerable target failed and the guarded "
            "twin produced 0 failures under the same seed and budget."
        ),
        reviewer="deterministic-verifier",
        review_independence=ReviewIndependence.UNRECORDED.value,
        remaining_uncertainty="This is a reference fixture, not a third-party deployment.",
        recommended_fix="Use virtual shares/assets (or a minimum-liquidity offset) so the first deposit cannot be diluted.",
        retest_result="guarded twin clean",
    )
    if not record.confirm():
        return {"ok": False, "reason": "the finding did not satisfy the evidence gate"}

    repo = FindingRepository(root / "findings")
    repo.add(record)

    document = to_sarif([record])
    errors = validate_sarif(document)
    if errors:
        return {"ok": False, "reason": "the generated SARIF is invalid", "errors": errors}
    (root / "reports").mkdir(parents=True, exist_ok=True)
    sarif_path = root / "reports" / "demo.sarif"
    sarif_path.write_text(sarif_dumps(document), encoding="utf-8")

    baseline_path = root / "baseline.json"
    baseline_path.write_text(baseline_dumps(create(repo.all())), encoding="utf-8")
    diff = compare(json.loads(baseline_path.read_text(encoding="utf-8")), repo.all())

    return {
        "ok": True,
        "root": str(root),
        "finding_id": record.finding_id,
        "verdict": record.status,
        "evidence_id": evidence.evidence_id,
        "sequence": sequence,
        "guarded_failures": len(guarded.failures),
        "sarif": str(sarif_path),
        "baseline": str(baseline_path),
        "diff": diff.to_dict()["counts"],
    }


# --------------------------------------------------------------------------- #
# Grouped help
# --------------------------------------------------------------------------- #

COMMAND_GROUPS: dict[str, tuple[str, ...]] = {
    "Start here": (
        "version", "info", "init", "demo", "guide", "doctor", "capability",
        "mindset", "doctrine",
    ),
    "Research": (
        "objectives", "chains", "chain", "hypothesize", "hypothesis", "threatmodel",
        "investigate", "adversary", "campaign", "hunt", "autohunt", "agent", "ton",
        "statespace", "discovery",
        "fuzz", "fuzz-bench", "reproduce", "assure", "differential", "coverage",
        "coverage-engine", "graph", "targets", "value", "interrogate", "explore",
        "evaluate", "evmbench", "symbolic-harness", "differential-fuzz", "properties",
    ),
    "Ingest & model": (
        "ingest", "dossier", "dataflow", "verified-model", "pipeline", "mission", "cosmos", "closure",
        "deployed", "deployment",
        "symbolic-evm", "evm-diff", "evm-fuzz", "evm-exec", "debug", "probe", "poc", "layout", "dvdf",
        "forge-gen",
    ),
    "Evidence & findings": (
        "findings", "baseline", "retest", "audit", "report", "verify", "triage",
        "impact", "novelty",
        "integrity", "engagement", "demonstrate",
    ),
    "Bounty & intelligence": (
        "bounty", "watch", "monitor", "intel", "program", "mail", "eligibility",
        "scope", "ingress", "threatintel",
    ),
    "Engines & tools": (
        "tools", "engines", "external", "compat", "fork", "gha-analyze", "gha-bench",
        "cloud", "chrome", "testsparker",
    ),
    "Operations": (
        "queue", "schedule", "trigger", "research", "learn", "continuous",
        "improve", "provision", "agents", "agents-verify", "models", "environment",
        "conformance", "regress", "adversarial",
    ),
}


def grouped_names() -> list[str]:
    return [name for names in COMMAND_GROUPS.values() for name in names]


def render_guide(helps: dict[str, str] | None = None) -> str:
    lines = ["BLACKHEART commands", ""]
    for group, names in COMMAND_GROUPS.items():
        lines.append(f"{group}")
        for name in names:
            detail = (helps or {}).get(name, "")
            lines.append(f"  {name:20} {detail}")
        lines.append("")
    lines.append("Every command takes --help; the doctrine and mindset explain the method.")
    return "\n".join(lines)
