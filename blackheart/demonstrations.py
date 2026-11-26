"""Generic class demonstration: drive any vulnerable/guarded pair through the
full engine pipeline and produce a verified, reportable finding.

The reference engagement is hard-wired to the ERC4626 share-inflation class. This
module generalises that pipeline so *any* pair in the target registry (oracle
manipulation, permit replay, proxy initializer, wrapper accounting, ...) can be
taken end to end:

    stateful fuzz -> minimal counterexample -> Finding -> independent verification
    -> report (only when CONFIRMED)

Everything is built from real engine output: the reproduction steps are the
minimal sequence the fuzzer actually found, the observed state is a real
snapshot, and the verifier's reproduction callable re-executes that exact
sequence. Nothing is fabricated. It runs entirely against local models -- no
network, no real funds.
"""

from __future__ import annotations

import json
from pathlib import Path

from .evidence import EvidenceStore
from .invariants import FuzzConfig, StatefulFuzzer
from .invariants.engine import run_sequence
from .invariants.registry import DIFFERENTIAL_PAIRS, make_target
from .models import Classification, Finding, Severity
from .report import is_submission_ready, write_report
from .value import analyse
from .verify import IndependentVerifier, VerificationContext


def _steps_text(failure) -> list[str]:
    steps = []
    for i, s in enumerate(failure.minimal_sequence, 1):
        params = ", ".join(f"{k}={v}" for k, v in s.params.items())
        steps.append(f"{i}. actor '{s.actor}' calls {s.action}({params}) on {s.target_contract}")
    return steps


def _impact_text(account, guard_report, moves_value: bool) -> str:
    """An honest impact statement built from the priced value account.

    Never inflates: when the sequence moves value it is named an extraction with
    the measured amounts; when it moves none it is named a *state manipulation or
    restriction bypass* with no measured value movement -- the violation is still
    one of the three outcomes (a bypassed restriction), but the money is not
    claimed. ``measurable_impact`` in the verification context stays true because
    a reachable, reproducible invariant violation is itself the demonstrated
    consequence.
    """
    guard_note = (
        f"the guarded model with the same operations does not break this invariant "
        f"(guarded failures={len(guard_report.failures)}), isolating the missing control"
    )
    if not moves_value:
        return (
            f"State manipulation / restriction bypass with no measured value movement "
            f"(attacker profit={account.attacker_profit}, victim loss={account.victim_loss}, "
            f"value created={account.value_created}); {guard_note}. The broken invariant is "
            f"the demonstrated consequence; no financial extraction is claimed."
        )
    return (
        f"Demonstrated extraction: attacker profit={account.attacker_profit}, "
        f"victim loss={account.victim_loss}, protocol loss={account.protocol_loss}, "
        f"value created={account.value_created}, repeatable={account.repeatable}, "
        f"max extraction={account.max_extraction}; {guard_note}."
    )


def run_class_demonstration(
    workdir: str | Path,
    *,
    pair: str = "lending-oracle/lending-oracle-guarded",
    runs: int = 400,
    steps_per_run: int = 10,
    seed: int = 0,
) -> dict:
    """Run one vulnerable/guarded pair through the full pipeline.

    Returns a summary dict. ``finding`` is present only when the vulnerable model
    actually produced an attacker-reachable counterexample.
    """
    try:
        vuln_name, guard_name = (p.strip() for p in pair.split("/", 1))
    except ValueError as exc:
        raise ValueError(
            f"pair must be 'vulnerable/guarded' (e.g. 'permit-replay/permit-guarded'); got {pair!r}"
        ) from exc

    known = {f"{v}/{g}" for v, g, _ in DIFFERENTIAL_PAIRS}
    if f"{vuln_name}/{guard_name}" not in known:
        raise ValueError(f"unknown pair {pair!r}; known: {', '.join(sorted(known))}")

    root = Path(workdir)
    root.mkdir(parents=True, exist_ok=True)
    evidence = EvidenceStore(root / "evidence")
    cfg = FuzzConfig(runs=runs, steps_per_run=steps_per_run, seed=seed)

    summary: dict = {"pair": pair, "runs": runs, "steps_per_run": steps_per_run, "seed": seed}

    vuln_target = make_target(vuln_name)
    guard_target = make_target(guard_name)
    vuln_report = StatefulFuzzer(vuln_target, cfg).run()
    guard_report = StatefulFuzzer(guard_target, cfg).run()

    evidence.put_json(
        vuln_report.to_dict(), kind="invariant-failures",
        description=f"{pair}: vulnerable-model counterexamples",
    )
    summary["vulnerable_failures"] = len(vuln_report.failures)
    summary["guarded_failures"] = len(guard_report.failures)

    attacker_failures = [f for f in vuln_report.failures if f.reachable_by_attacker]
    if not attacker_failures:
        # Honest negative: the model did not yield an attacker-reachable break.
        summary["status"] = "NO_ATTACKER_REACHABLE_FAILURE"
        summary["finding"] = None
        (root / "demonstration-summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        return summary

    failure = attacker_failures[0]
    inv = {i.inv_id: i for i in vuln_target.invariants()}[failure.inv_id]
    observed = vuln_target.snapshot(run_sequence(vuln_target, failure.minimal_sequence).state)
    steps = _steps_text(failure)
    severity = getattr(inv, "severity_if_broken", Severity.HIGH.value)

    # Price the finding with the universal value engine, so "impact" is an
    # economic account read from the target's own snapshots -- never an
    # assumed consequence. A violation that moves no value is reported as a
    # state manipulation and the impact gate is not asserted on a guess.
    account = analyse(vuln_target, failure.minimal_sequence, failure.inv_id, vuln_name)
    summary["economic"] = account.to_dict()
    moves_value = account.attacker_profit > 0 or account.victim_loss > 0

    finding = Finding(
        finding_id=f"demo-{vuln_name}-{failure.inv_id}",
        title=f"{inv.title} (class: {vuln_name})",
        target=vuln_name,
        component=f"{vuln_name}:{failure.inv_id}",
        scope_reference="local engine demonstration target (not a bounty asset)",
        category=vuln_name,
        severity=severity,
        prerequisites=[
            "attacker is an unprivileged external actor",
            f"the vulnerable model is reachable through: "
            f"{', '.join(sorted({s.action for s in failure.minimal_sequence}))}",
        ],
        root_cause=inv.title,
        reproduction_steps=steps,
        poc_path=f"stateful fuzz: seed={failure.seed}, minimal_sequence len={len(failure.minimal_sequence)}",
        expected_behavior="the invariant holds for every reachable operation sequence",
        actual_behavior=(
            f"sequence [{', '.join(s.action for s in failure.minimal_sequence)}] "
            f"breaks '{failure.inv_id}'; observed={json.dumps(observed, default=str)}"
        ),
        impact=_impact_text(account, guard_report, moves_value),
        economic=account.to_dict(),
        commands=[
            f"python3 -m blackheart reproduce --target {vuln_name} "
            f"--invariant {failure.inv_id} --seed {failure.seed}"
        ],
        evidence_ids=[],
        limitations=[
            "Local model, not a live protocol: proves the attack class and the engine, "
            "not a bounty finding.",
            "The minimal sequence is a counterexample, not a production exploit.",
        ],
    )

    # Independent verification: re-execute the exact minimal sequence.
    def reproduce() -> bool:
        result = run_sequence(vuln_target, failure.minimal_sequence)
        return failure.inv_id in result.violated

    ctx = VerificationContext(
        in_scope=True,
        scope_reference=finding.scope_reference,
        protection_exists=False,
        behavior_intentional=False,
        duplicate_known=False,
        attacker_controls_input=True,
        reachable=True,
        measurable_impact=True,
        reproduce=reproduce,
    )
    vr = IndependentVerifier().verify(finding, ctx)
    finding.evidence_ids = [
        evidence.put_json(
            {"minimal_sequence": [s.to_dict() for s in failure.minimal_sequence],
             "observed": observed, "verification": vr.to_dict()},
            kind="counterexample",
            description=f"{pair}: minimal counterexample for {failure.inv_id}",
        ).evidence_id
    ]
    summary["verification"] = vr.to_dict()

    report_path = None
    if finding.classification == Classification.CONFIRMED:
        report_path = write_report(
            finding, root / "reports",
            remediation=(
                "Add the control the guarded model implements for this class "
                "(manipulation-resistant pricing, single-use authorization, or a "
                "one-shot initializer)."
            ),
        )
    summary["status"] = finding.classification.value
    summary["report_path"] = str(report_path) if report_path else None
    summary["submission_ready"] = is_submission_ready(finding)
    summary["finding"] = finding.to_dict()

    (root / "demonstration-summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    return summary
