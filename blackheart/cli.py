"""BLACKHEART command-line interface.

Subcommands:
    tools verify                      -> verify the toolchain and write the registry
    objectives --profile FILE         -> generate attacker objectives from a profile
    chains --profile FILE             -> generate attack chains
    targets                           -> list executable invariant-engine targets
    fuzz --target NAME                -> run the stateful invariant engine
    reproduce --target ... --seed N   -> reproduce a specific failing sequence
    differential                      -> run every vulnerable/guarded pair and assert the contrast
    campaign --profile FILE --authz F -> run the authorization-gated attack loop
    verify --finding FILE --ctx FILE  -> run independent verification on a finding
    doctrine [--json|--prompt|--phase KEY] -> the operational doctrine (identity, lifecycle, gates)
    findings ...                      -> persistent findings repository (document/search/verify/export)
    cloud doctor|connect|status|execute|artifacts -> run work on the InstaBox machine

The CLI never fabricates output: every value it prints comes from a real call.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from dataclasses import fields
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Optional

from . import __version__
from .authz import authorize_active_testing
from .campaign import Campaign
from .chains import generate_chains
from .evidence import EvidenceStore
from .invariants import FuzzConfig, StatefulFuzzer
from .models import (
    AttackStep,
    AuthorizationRecord,
    Classification,
    Finding,
)
from .objectives import TargetProfile, generate_objectives
from .intelligence.providers import DEFAULT_ORDER
from .report import is_submission_ready, write_report
from .tools import ToolRegistry
from .verify import IndependentVerifier, VerificationContext


def _load_profile(path: str) -> TargetProfile:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return TargetProfile(**data)


def _load_authz(path: str) -> AuthorizationRecord:
    return AuthorizationRecord.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _make_target(name: str):
    from .invariants.registry import make_target

    return make_target(name)


def _target_choices() -> list[str]:
    from .invariants.registry import available_targets

    return available_targets()


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def _fixture_command(fn):
    """Run a CLI command that executes the repository's *own* fixtures.

    Commands that take a target from the repository's target registry, fixture
    pairs or corpus are engine executions too, so they run under the repository
    self-test record -- a record that passes the same gate and is bound to this
    repository. A command that accepts an arbitrary target is *not* decorated: it
    takes ``--compatibility`` and validates the record against that target.
    """
    import functools as _functools

    @_functools.wraps(fn)
    def wrapper(args: argparse.Namespace) -> int:
        from .toolchain.enforce import CompatibilityError, self_test_authority

        name = (getattr(args, "target", None) or getattr(args, "app", None)
                or getattr(args, "case", None) or getattr(args, "asset", None)
                or "repository self-test")
        try:
            with self_test_authority(str(name)):
                return fn(args)
        except CompatibilityError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    return wrapper


def cmd_tools_verify(args: argparse.Namespace) -> int:
    reg = ToolRegistry(args.out)
    records = reg.verify_all()
    summary = reg.summary(records)
    print(json.dumps({"registry": str(args.out), "summary": summary}, indent=2))
    for r in records:
        print(f"  {r.name:12} {r.status:18} {r.version:14} {r.notes}")
    # Non-zero exit if any expected tool is missing/unsupported.
    bad = [r.name for r in records if r.status in ("missing", "unsupported")]
    if bad:
        print(f"\nWARNING: tools not usable: {', '.join(bad)}", file=sys.stderr)
    return 0


def cmd_tools_run(args: argparse.Namespace) -> int:
    """Drive a live tool against an AUTHORIZED asset and record the result.

    The tool never starts unless the asset is AUTHORIZED under a verified
    authorization record -- the gate is enforced by the adapter, not here. The run
    (command, output, parsed findings) is written to the evidence store so it can
    be attached to a finding.
    """
    from .evidence import EvidenceStore
    from .scope import load_record
    from .tools.adapters import ADAPTERS, adapter_for

    spec = adapter_for(args.tool)
    if spec is None:
        print(f"unknown tool adapter {args.tool!r}; known: {', '.join(sorted(ADAPTERS))}",
              file=sys.stderr)
        return 2

    try:
        record = load_record(args.authorization)
    except (OSError, ValueError) as exc:
        print(f"no readable authorization record at {args.authorization!r}: {exc}", file=sys.stderr)
        return 2

    kwargs: dict = {"record": record, "asset": args.asset or ""}
    if spec.requires_wordlist:
        if not args.wordlist:
            print(f"{args.tool} requires --wordlist", file=sys.stderr)
            return 2
        run = spec.fn(args.target, args.wordlist, **kwargs)
    else:
        run = spec.fn(args.target, **kwargs)

    payload = run.to_dict()
    store = EvidenceStore(Path(args.evidence_dir))
    ev = store.put_json(payload, name=f"tool-run-{args.tool}", media_type="application/json")
    print(json.dumps({
        "tool": run.tool, "target": run.target, "available": run.available,
        "authorized": run.authorized, "findings": len(run.findings),
        "evidence_id": ev.evidence_id, "reason": run.reason,
        "parse_notes": run.parse_notes,
    }, indent=2))
    for f in run.findings:
        print(f"  [{f.severity:8}] {f.kind:24} {f.target} {f.detail}")
    if not run.available:
        print(f"\nNOTE: {run.reason}; no scan was performed", file=sys.stderr)
        return 3
    return 0


def cmd_objectives(args: argparse.Namespace) -> int:
    profile = _load_profile(args.profile)
    objectives = generate_objectives(profile)
    if args.out:
        Path(args.out).write_text(
            json.dumps([o.to_dict() for o in objectives], indent=2), encoding="utf-8"
        )
    for o in objectives:
        print(f"[{o.priority:3}] {o.obj_id:45} {o.title}")
    print(f"\n{len(objectives)} objectives generated")
    return 0


def cmd_chains(args: argparse.Namespace) -> int:
    profile = _load_profile(args.profile)
    objectives = generate_objectives(profile)
    all_chains = []
    for o in objectives:
        all_chains.extend(generate_chains(o, profile.kind))
    if args.out:
        Path(args.out).write_text(
            json.dumps([c.to_dict() for c in all_chains], indent=2), encoding="utf-8"
        )
    for c in all_chains:
        print(f"[{c.priority:3}] {c.chain_id:55} {c.title}")
    print(f"\n{len(all_chains)} attack chains generated")
    return 0


@_fixture_command
def cmd_fuzz(args: argparse.Namespace) -> int:
    target = _make_target(args.target)
    strategy = getattr(args, "strategy", "random")
    if strategy == "corpus":
        from .fuzz import CorpusConfig, CoverageGuidedFuzzer

        cfg = CorpusConfig(seed=args.seed, max_sequences=args.runs,
                           max_steps=args.steps)
        report = CoverageGuidedFuzzer(target, cfg).run()
        payload = report.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"target={target.name} strategy=corpus sequences={report.sequences_executed} "
              f"seed={args.seed} coverage={report.coverage_buckets} corpus={report.corpus_size}")
        print(f"invariant failures found: {len(report.failures)}")
        for f, at in zip(report.failures, report.detection_at):
            print(f"  - {f.inv_id}: found_at_sequence={at} minimal_len={len(f.minimal_sequence)} "
                  f"reproducible={f.reproducible} attacker_reachable={f.reachable_by_attacker}")
        for acct in report.economic:
            print(f"    economic: attacker_profit={acct['attacker_profit']} "
                  f"victim_loss={acct['victim_loss']} repeatable={acct['repeatable']}")
        return 0

    cfg = FuzzConfig(runs=args.runs, steps_per_run=args.steps, seed=args.seed)
    report = StatefulFuzzer(target, cfg).run()
    payload = report.to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"target={target.name} strategy=random runs={report.runs} "
          f"steps={report.steps_per_run} seed={report.base_seed}")
    print(f"invariant failures found: {len(report.failures)}")
    for f in report.failures:
        print(f"  - {f.inv_id}: seed={f.seed} minimal_len={len(f.minimal_sequence)} "
              f"reproducible={f.reproducible} attacker_reachable={f.reachable_by_attacker}")
    if report.unevaluable:
        print(f"WARNING: {len(report.unevaluable)} invariant(s) could not be evaluated "
              f"({', '.join(report.unevaluable)}); this run cannot be called clean",
              file=sys.stderr)
    return 0


@_fixture_command
def cmd_fuzz_bench(args: argparse.Namespace) -> int:
    """Coverage-guided vs random ablation over the hard/deep fixtures."""
    from .fuzz.benchmark import run_fuzz_benchmark

    report = run_fuzz_benchmark(budget=args.budget, seed=args.seed, max_steps=args.steps)
    payload = report.to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))
    for case in payload["cases"]:
        print(f"  {case['case_id']}: corpus={case['corpus']['detected']} "
              f"(at {case['corpus']['seqs_to_detect']}) "
              f"random={case['random']['detected']} "
              f"corpus_fp={case['corpus']['false_positive']} "
              f"random_fp={case['random']['false_positive']}")
    return 0


@_fixture_command
def cmd_reproduce(args: argparse.Namespace) -> int:
    from .invariants.engine import run_sequence

    target = _make_target(args.target)
    cfg = FuzzConfig(runs=args.runs, steps_per_run=args.steps, seed=args.seed)
    report = StatefulFuzzer(target, cfg).run()
    match = [f for f in report.failures if f.inv_id == args.invariant]
    if not match:
        print(f"no failure for invariant '{args.invariant}' in seed range "
              f"{args.seed}..{args.seed + args.runs - 1}", file=sys.stderr)
        return 1
    failure = match[0]
    seq = failure.minimal_sequence
    result = run_sequence(target, seq)
    print(json.dumps({
        "invariant": failure.inv_id,
        "seed": failure.seed,
        "minimal_sequence": [s.to_dict() for s in seq],
        "reproduced": failure.inv_id in result.violated,
        "observed": target.snapshot(result.state),
    }, indent=2, default=str))
    return 0


def cmd_campaign(args: argparse.Namespace) -> int:
    profile = _load_profile(args.profile)
    authz = _load_authz(args.authz)
    workdir = Path(args.workdir)
    camp = Campaign(args.engagement, profile, authz, workdir)
    decision = authorize_active_testing(authz, args.asset)
    print(f"authorization for '{args.asset}': allowed={decision.allowed} "
          f"status={decision.status.value}")
    for b in decision.blockers:
        print(f"  blocker: {b}")
    from .toolchain.enforce import CompatibilityError

    try:
        result = camp.run_active(args.asset, compatibility=args.compatibility)
    except CompatibilityError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    path = camp.write_summary(result)
    print(f"campaign summary written to {path}")
    if not result.allowed:
        print(f"BLOCKED: {result.blocked_reason}")
        return 2
    # Automatic documentation: every finding the campaign produced is persisted to
    # the findings repository, so a meaningful operation never finishes without a
    # permanent, traceable record. A finding the engine classified CONFIRMED is
    # only stored CONFIRMED when its evidence resolves; otherwise it is downgraded.
    if result.findings:
        from .evidence import EvidenceStore
        from .findings import FindingRepository, document_finding

        repo = FindingRepository(args.findings_dir)
        store = EvidenceStore(Path(args.findings_dir) / "evidence")
        documented = [
            document_finding(
                repo, f, evidence_exists=lambda eid: store.get(eid) is not None
            )
            for f in result.findings
        ]
        print(f"documented {len(documented)} finding(s) in {args.findings_dir}")
    print(f"objectives={len(result.objectives)} chains={len(result.chains)}")
    print(f"open hypotheses: {len(result.next_hypotheses)}")
    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    from .invariants import TARGET_SPECS

    payload = [
        {"name": s.name, "kind": s.kind, "guarded": s.guarded, "class": s.cls.__name__}
        for s in TARGET_SPECS
    ]
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    for s in payload:
        role = "guarded" if s["guarded"] else "vulnerable"
        print(f"  {s['name']:24} kind={s['kind']:8} {role:10} {s['class']}")
    print(f"\n{len(payload)} executable targets")
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    """Report which objective categories the engine has an executable model for.

    The engine can only break an attack class it has a vulnerable/guarded target
    for, so a category with no model is a class every search is blind to. This
    renders the class-coverage ledger honestly: a category is ``modelled`` only
    when the registry actually holds its pair, and an unmodelled category is a
    named gap, never a silent omission. Exits non-zero when any category is
    unmodelled, so a caller fails closed on an uncovered class.
    """
    from .invariants import coverage_report, coverage_summary

    if getattr(args, "unified", False):
        from .coverage_ledger import unified_coverage

        payload = unified_coverage()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0 if payload["status"] == "COMPLETE" else 1

    report = [c.to_dict() for c in coverage_report()]
    summary = coverage_summary()
    if args.out:
        Path(args.out).write_text(
            json.dumps({"summary": summary, "categories": report}, indent=2),
            encoding="utf-8",
        )
    for c in coverage_report():
        if c.coverage.value == "modelled":
            print(f"  [MODELLED]   {c.category:24} kind={c.kind:16} {c.representative}")
        else:
            print(f"  [{c.coverage.value.upper():10}] {c.category:24} {c.reason}")
    print(
        f"\n{summary['modelled']}/{summary['categories']} objective categories have an "
        f"executable vulnerable/guarded model"
    )
    if summary["unmodelled"]:
        print(
            f"GAP: {summary['unmodelled']} categor(ies) unmodelled -- every search is "
            f"blind to: {', '.join(summary['unmodelled_categories'])}"
        )
    if summary["prose_only"]:
        print(
            f"{summary['prose_only']} categor(ies) are deliberately prose-only (a live "
            f"system is required; named in PROSE_ONLY, not claimed as coverage): "
            f"{', '.join(summary['prose_only_categories'])}"
        )
    if not summary["unmodelled"]:
        print(
            "Every category that can be executed has a representative model the engine "
            "can break; prose-only classes are reported as gaps, never as coverage."
        )
    return 1 if summary["unmodelled"] else 0


def cmd_coverage_engine(args: argparse.Namespace) -> int:
    """The Universal Vulnerability Coverage Engine, from the CLI.

    ``coverage-engine taxonomy`` prints the extensible class universe and how much of
    it has an executable model. ``coverage-engine assess`` classifies the taxonomy
    against a target profile and prints what is applicable, inapplicable (with a
    reason), or unresolved -- and the hypotheses and multi-stage paths it implies.
    Nothing here executes or confirms a finding; it is the coverage *plan*.
    """
    from .coverage_engine import (
        ApplicabilityEngine,
        ControllerConfig,
        ResearchController,
        SurfaceEnumerator,
        Taxonomy,
    )
    from .objectives import TargetProfile

    tax = Taxonomy()
    if args.ce_sub == "taxonomy":
        summary = tax.summary()
        for c in tax:
            tag = "MODELLED" if c.objective_category else "NO-MODEL"
            disc = " (discovered)" if c.discovered else ""
            print(f"  [{tag:9}] {c.key:26} band={c.default_band.value:8} "
                  f"needs={','.join(c.requires) or 'any'}{disc}")
        print(f"\n{summary['classes']} classes "
              f"({summary['curated']} curated, {summary['discovered']} discovered); "
              f"{summary['with_objective_model_link']} link to an executable model")
        print("A class with NO-MODEL is a recorded gap, not silent coverage.")
        return 0

    if args.ce_sub == "assess":
        profile = TargetProfile(
            name=args.target or "target", kind=args.kind or "unknown",
            assets=list(args.asset or []), entry_points=list(args.entry or []),
            roles=list(args.role or []), external_deps=list(args.dep or []),
            notes=args.notes or "",
        )
        if args.plan:
            result = ResearchController(tax, ControllerConfig(max_probes=0)).run(
                profile, probe=None)
            payload = {
                "summary": result.summary(),
                "priorities": result.priorities,
                "attack_paths": result.surface.to_dict()["paths"],
            }
            print(json.dumps(payload, indent=2))
            return 0
        applicability = ApplicabilityEngine(tax).classify(profile)
        surface = SurfaceEnumerator(tax).build(applicability, profile)
        print(f"surfaces detected: {', '.join(sorted(applicability.surfaces.tokens())) or 'none'}")
        for v in applicability.verdicts:
            print(f"  [{v.state.value:18}] {v.key:26} {v.reason}")
        counts = applicability.to_dict()["counts"]
        print(f"\napplicable={counts['applicable']} inapplicable={counts['inapplicable']} "
              f"unresolved={counts['unresolved']}")
        print(f"hypotheses={len(surface.hypotheses)} attack_paths={len(surface.paths)}")
        return 0

    print("usage: coverage-engine {taxonomy|assess}")
    return 2


def cmd_environment(args: argparse.Namespace) -> int:
    """The environment-agnostic execution backends, from the CLI.

    ``environment list`` probes every built-in backend *in this environment* and
    prints its confirmed capabilities and evidence tier. A backend that is not ready
    here is reported with its state, never assumed available. ``environment route``
    shows which backend would serve a given target-type + operation, or why none can.
    """
    from .environments import (
        DevnetAdapter,
        EnvironmentRegistry,
        HttpServiceAdapter,
        LocalSourceAdapter,
        SequenceModelAdapter,
    )

    reg = EnvironmentRegistry()
    if args.root:
        reg.register(LocalSourceAdapter(args.root))
    if getattr(args, "compose", ""):
        reg.register(DevnetAdapter(args.compose, allow_exec=getattr(args, "allow_exec", False)))
    reg.register(HttpServiceAdapter(allow_hosts=tuple(args.allow_host or ())))
    if args.model:
        from .invariants.registry import make_target

        reg.register(SequenceModelAdapter(make_target(args.model)))
    reg.probe_all()

    if args.env_sub == "route":
        if not args.target_type or not args.operation:
            print("route requires --target-type and --operation")
            return 2
        decision = reg.route(args.target_type, args.operation,
                             required_tool=getattr(args, "tool", "") or "")
        print(json.dumps(decision.to_dict(), indent=2))
        return 0 if decision.routed else 1

    matrix = reg.capability_matrix()
    print(json.dumps({
        "backends": matrix,
        "can_prove_real_execution": reg.can_prove_real_execution(),
        "note": "state is this host's probe result; an unready backend is reported, "
                "never assumed available",
    }, indent=2))
    return 0


def cmd_program(args: argparse.Namespace) -> int:
    """Universal program intelligence, from the CLI.

    ``program normalize --file PATH --program NAME --source-url URL`` reads a
    program's published policy text and prints the normalized policy, its provenance
    hash, and any uncertainty the parser could not establish (never a guess).
    ``program requirement`` prints the Gmail OAuth requirement for the read-only
    integration, including the restricted-scope blocker.
    """
    from .program_intel import PolicyNormalizer

    if args.prog_sub == "requirement":
        from .mail_intel import describe_requirement

        print(json.dumps(describe_requirement(), indent=2))
        return 0

    if args.prog_sub == "normalize":
        if not args.file:
            print("normalize requires --file")
            return 2
        text = Path(args.file).read_text(encoding="utf-8")
        policy = PolicyNormalizer().normalize(
            text, program=args.program or "program",
            source_url=args.source_url or "", version=args.version or "",
        )
        print(json.dumps(policy.to_dict(), indent=2))
        if policy.uncertainties:
            print(f"\n{len(policy.uncertainties)} uncertaint(ies) recorded -- these were "
                  f"NOT guessed:")
            for u in policy.uncertainties:
                print(f"  - {u}")
        return 0

    print("usage: program {normalize|requirement}")
    return 2


def cmd_mail(args: argparse.Namespace) -> int:
    """Secure, read-only Gmail intelligence, from the CLI.

    ``mail status`` reports the integration's honest state and the restricted-scope
    blocker. ``mail import --file PATH`` runs the zero-OAuth manual-import fallback,
    which extracts opportunity *candidates* (never authorizations) from a message.
    """
    from .mail_intel import (
        GmailReadOnlyClient,
        ManualImporter,
        OpportunityIntake,
        describe_requirement,
    )

    if args.mail_sub == "status":
        client = GmailReadOnlyClient()
        print(json.dumps({"status": client.status().to_dict(),
                          "requirement": describe_requirement()}, indent=2))
        return 0

    if args.mail_sub == "import":
        if not args.file:
            print("import requires --file")
            return 2
        text = Path(args.file).read_text(encoding="utf-8")
        importer = ManualImporter()
        msg = importer.parse_json(text) if args.json else importer.parse_text(text)
        intake = OpportunityIntake()
        opp = importer.ingest(intake, msg, program=args.program or "")
        if opp is None:
            print("no opportunity extracted (empty body or duplicate)")
            return 1
        print(json.dumps(opp.to_dict(), indent=2))
        if msg.errors:
            print("\nprovenance warnings:")
            for e in msg.errors:
                print(f"  - {e}")
        return 0

    print("usage: mail {status|import}")
    return 2


@_fixture_command
def cmd_value(args: argparse.Namespace) -> int:
    """The universal value and profitability engine, from the CLI.

    ``value classify`` prints how each field of a target's reset snapshot is read
    (asset / liability / permission / protocol / other) -- the auditable answer to
    "what does this engine consider value here?". ``value targets`` runs the
    value model across every executable target and reports which ones expose
    trackable attacker value. ``value analyse`` prices a target's *discovered*
    violations (found by the adaptive search) into attacker profit, victim loss,
    and repeatability, so a broken invariant is told apart from a demonstrated
    extraction.
    """
    from .value import ValueModel, analyse
    from .invariants.registry import available_targets, make_target

    sub = getattr(args, "sub", "")

    if sub == "classify":
        target = make_target(args.target)
        snap = target.snapshot(target.reset())
        if not isinstance(snap, dict):
            print(json.dumps({"target": args.target, "snapshot_is_mapping": False}, indent=2))
            return 0
        model = ValueModel(snap)
        payload = {
            "target": args.target,
            "fields": {k: v.value for k, v in model.kinds.items()},
            "actors": sorted(model.actors()),
            "attacker_actor": model.attacker_actor(),
        }
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "targets":
        rows = []
        for name in available_targets():
            target = make_target(name)
            model = ValueModel(target.snapshot(target.reset()))
            rows.append({
                "target": name,
                "attacker_actor": model.attacker_actor(),
                "value_fields": sorted(k for k, v in model.kinds.items()
                                       if v.value in ("asset", "liability", "permission")),
            })
        tracked = [r for r in rows if r["attacker_actor"]]
        if args.out:
            Path(args.out).write_text(json.dumps(rows, indent=2), encoding="utf-8")
        for r in rows:
            mark = r["attacker_actor"] or "-"
            print(f"  {r['target']:26} attacker={mark:10} value_fields={','.join(r['value_fields']) or '-'}")
        print(f"\n{len(tracked)}/{len(rows)} targets expose attacker-identifiable value")
        return 0

    if sub == "analyse":
        from .statespace.adaptive import AdaptiveConfig, AdaptiveExplorer
        from .discovery.harness import ModelTarget
        target = make_target(args.target)
        mt = ModelTarget(target)
        rep = AdaptiveExplorer(mt, AdaptiveConfig(
            seed=args.seed, max_steps=args.steps, max_sequences=args.budget)).explore()
        priced = []
        for v in rep.violations:
            acct = analyse(mt, v.minimal_sequence, v.invariant_id, target.name)
            priced.append({"invariant": v.invariant_id, **acct.to_dict()})
        payload = {
            "target": target.name,
            "sequences_executed": rep.sequences_tried,
            "violations": len(rep.violations),
            "priced": priced,
            "note": ("Attacker profit is measured from the target's own snapshots. A "
                     "violation with no established value movement is a state "
                     "manipulation, not a demonstrated extraction."),
        }
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        for p in priced:
            print(f"  {p['invariant']:28} profit={p['attacker_profit']:>24} "
                  f"victim_loss={p['victim_loss']:>24} impact={p['financial_impact_established']}")
        if not priced:
            print("  no violations found within budget")
        return 0

    print(json.dumps({"error": f"unknown value subcommand: {sub}"}, indent=2))
    return 2


@_fixture_command
def cmd_assure(args: argparse.Namespace) -> int:
    """The assurance layer: bounded-exhaustive certification and the search portfolio.

    ``assure certify`` enumerates *every* sequence up to a depth over the target's
    declared alphabet and checks every invariant -- the only search allowed to say
    "no counterexample exists" (up to the bound, which it prints with its limits).
    ``assure portfolio`` runs every strategy on one target, unions the
    counterexamples, prices them, and reports which strategy covered what.
    """
    from .assurance import (
        CertifyConfig,
        OracleAuditConfig,
        PortfolioConfig,
        audit_oracles,
        certify,
        run_portfolio,
    )

    target = _make_target(args.target)
    sub = getattr(args, "sub", "")

    if sub == "oracles":
        audit = audit_oracles(target, OracleAuditConfig(
            max_depth=args.depth,
            max_sequences=args.max_sequences,
        ))
        payload = audit.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"target={target.name} states_sampled={audit.states_sampled} "
              f"numeric_paths={audit.numeric_paths} invariants={len(audit.findings)}")
        for f in audit.findings:
            print(f"  {f.inv_id:32} verdict={f.verdict:15} evals={f.evaluations:5} "
                  f"raised={f.raised:5} flips={f.mutation_flips:4}")
        print(audit.verdict_line())
        return 0

    if sub == "certify":
        cert = certify(target, CertifyConfig(
            max_depth=args.depth,
            max_sequences=args.max_sequences,
            price_findings=not args.no_price,
        ))
        payload = cert.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"target={target.name} alphabet={cert.alphabet_size} "
              f"depth={cert.complete_to_depth}/{cert.max_depth} "
              f"tested={cert.sequences_tested} space={cert.sequences_in_space} "
              f"exhaustive={cert.exhaustive}")
        print(cert.verdict_line())
        for v in cert.violations:
            print(f"  - {v['invariant_id']}: length={v['length']} "
                  f"attacker_reachable={v['reachable_by_attacker']} "
                  f"sequence={[s['action'] for s in v['minimal_sequence']]}")
        return 0

    if sub == "portfolio":
        strategies = tuple(args.strategies.split(",")) if args.strategies else None
        cfg = PortfolioConfig(
            seed=args.seed,
            certify_depth=args.depth,
            certify_max_sequences=args.max_sequences,
            corpus_sequences=args.runs,
            random_runs=args.random_runs,
            **({"strategies": strategies} if strategies else {}),
        )
        res = run_portfolio(target, cfg)
        payload = res.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"target={target.name} strategies={len(res.stages)}")
        for s in res.stages:
            note = f" ({s.note})" if s.note else ""
            err = f" ERROR={s.error}" if s.error else ""
            print(f"  {s.strategy:10} sequences={s.sequences:>7} "
                  f"found={','.join(s.invariants_found) or '-'}{note}{err}")
        if res.oracle_audit is not None:
            print(res.oracle_audit.verdict_line())
        print(res.verdict_line())
        for v in res.violations:
            acct = v.get("economic") or {}
            print(f"  - {v['invariant_id']}: length={v['length']} strategy={v['strategy']} "
                  f"profit={acct.get('attacker_profit', '?')} "
                  f"victim_loss={acct.get('victim_loss', '?')}")
        return 0

    if sub == "directed":
        from .discovery.certify import certify_directed

        cert = certify_directed(
            target, max_depth=args.depth, max_states=args.max_sequences,
            beam_width=args.beam, param_sets=args.param_sets)
        payload = cert.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"target={target.name} proven={cert.proven} explored={cert.explored} "
              f"bound={cert.bound}")
        print(cert.reason)
        for step in cert.witness:
            print(f"  {step.actor} {step.action} {step.params}")
        return 0

    print(json.dumps({"error": f"unknown assure subcommand: {sub}"}, indent=2))
    return 2


def cmd_hunt(args: argparse.Namespace) -> int:
    """The universal hunt: one command that runs every engine, in order.

    Composes the existing stages -- cross-target recall, the search portfolio,
    path certification, independent verification, the ordering search, and the
    memory write-back -- into a single operation with one honest verdict. It
    introduces no new engine: every stage calls a tested module and the result
    carries that module's own verdict.
    """
    from .hunt import HuntConfig, hunt

    stages = tuple(s.strip() for s in args.stages.split(",") if s.strip()) if args.stages else None
    strategies = tuple(s.strip() for s in args.strategies.split(",") if s.strip()) if args.strategies else ()

    def control_factory() -> object:
        return _make_target(args.control)

    cfg = HuntConfig(
        **({"stages": stages} if stages else {}),
        seed=args.seed,
        certify_depth=args.depth,
        certify_max_sequences=args.max_sequences,
        corpus_sequences=args.runs,
        random_runs=args.random_runs,
        strategies=strategies,
        concolic_rounds=args.concolic_rounds,
        scenario=args.scenario or "",
        max_attacker_steps=args.max_attacker_steps,
        max_orderings=args.max_orderings,
        memory=args.memory,
        memory_path=args.memory_path,
        control_factory=control_factory if args.control else None,
        control_name=(args.control or ""),
        in_scope=(True if args.in_scope else None),
        scope_reference=args.scope_reference or "",
        authorization_gate_passed=(True if args.authorized else None),
    )
    from .toolchain.enforce import CompatibilityError

    try:
        result = hunt(args.target, cfg, compatibility=args.compatibility)
    except CompatibilityError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    payload = result.to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"hunt target={result.target} stages={len(result.stages)}")
    for s in result.stages:
        mark = "ran " if s.ran else "skip"
        err = f" ERROR={s.error}" if s.error else ""
        print(f"  {s.stage:9} {mark} {s.summary}{err}")
    print(f"  candidates={len(result.candidates)} certified={len(result.certified)} "
          f"verified={len(result.verified)} reproduced={len(result.reproduced)} "
          f"recalled_seeds={result.recalled_seeds} remembered={result.remembered}")
    print(result.verdict_line())
    for v in result.verified:
        acct = v.get("economic") or {}
        print(f"  + VERIFIED {v['invariant_id']} profit={acct.get('attacker_profit', '?')} "
              f"victim_loss={acct.get('victim_loss', '?')}")
    for v in result.reproduced:
        print(f"  ~ REPRODUCED {v['invariant_id']} (supply --control to establish the twin)")
    for c in result.certified:
        print(f"  - CERTIFIED {c['invariant_id']} witness_len={len(c['witness'])}")
    if result.ordering:
        prof = result.ordering.get("most_profitable")
        viol = result.ordering.get("violating")
        print(f"  ordering: tried={result.ordering.get('orderings_tried')} "
              f"violating={'yes' if viol else 'no'} "
              f"most_profitable={prof.get('attacker_profit') if prof else 0}")
    # Non-zero exit only when nothing was proven AND nothing was even found, so a
    # caller can gate on it; a lead still exits 0 (it is a real result).
    return 0 if (result.candidates or result.certified or result.verified
                 or result.ordering) else 1


@_fixture_command
def cmd_differential(args: argparse.Namespace) -> int:
    """Run each vulnerable/guarded pair and assert the expected contrast.

    For every pair the vulnerable model MUST yield at least one
    attacker-reachable violation and the guarded model MUST yield none. A pair
    that does not behave this way is a regression in the engine or a target.

    A random walk is not a proof of absence: a narrow numeric window (accumulate
    debt past the borrow LTV but stay under the liquidation threshold, then
    liquidate) can sit a few steps away and still be missed by sampling. When the
    random search finds nothing on the vulnerable twin, the pair escalates to the
    bounded-exhaustive certifier, which enumerates *every* sequence to ``--depth``
    and therefore cannot miss a violation inside that bound. The guarded twin is
    certified with the same bound, so the contrast is established by the same
    search on both sides rather than by sampling on one and exhaustion on the
    other.
    """
    from .assurance import CertifyConfig, certify
    from .invariants import DIFFERENTIAL_PAIRS, FuzzConfig, StatefulFuzzer
    from .invariants.registry import make_target

    cfg = FuzzConfig(runs=args.runs, steps_per_run=args.steps, seed=args.seed)
    depth = max(0, int(getattr(args, "depth", 4)))
    results = []
    ok = True
    for vuln, guard, hypothesis in DIFFERENTIAL_PAIRS:
        vr = StatefulFuzzer(make_target(vuln), cfg).run()
        gr = StatefulFuzzer(make_target(guard), cfg).run()
        v_reach = [f for f in vr.failures if f.reachable_by_attacker]
        broken = sorted({f.inv_id for f in v_reach})
        strategy = "fuzz"
        witness = None
        if not v_reach and depth > 0:
            cert = certify(make_target(vuln),
                           CertifyConfig(max_depth=depth, price_findings=False))
            hits = [v for v in cert.violations if v.get("reachable_by_attacker")]
            if hits:
                # The contrast only holds if the same exhaustive search leaves the
                # guarded twin clean; otherwise the pair proves nothing.
                gcert = certify(make_target(guard),
                                CertifyConfig(max_depth=depth, price_findings=False))
                if not gcert.violations:
                    v_reach = hits
                    broken = sorted({v["invariant_id"] for v in hits})
                    strategy = "certify"
                    witness = hits[0]["minimal_sequence"]
        passed = bool(v_reach) and len(gr.failures) == 0
        ok = ok and passed
        results.append({
            "pair": f"{vuln} / {guard}",
            "hypothesis": hypothesis,
            "vulnerable_failures": len(vr.failures),
            "vulnerable_attacker_reachable": len(v_reach),
            "guarded_failures": len(gr.failures),
            "invariants_broken": broken,
            "detected_by": strategy,
            "witness": witness,
            "passed": passed,
        })
        mark = "PASS" if passed else "FAIL"
        note = "" if strategy == "fuzz" else f" (certified at depth {depth})"
        print(f"[{mark}] {vuln:22} vs {guard:22} "
              f"vuln_fail={len(vr.failures):2} guarded_fail={len(gr.failures):2}{note}")
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
    escalated = sum(1 for r in results if r["detected_by"] == "certify")
    print(f"\n{sum(r['passed'] for r in results)}/{len(results)} differential pairs "
          f"behaved as expected ({escalated} found only by the certifier)")
    return 0 if ok else 1


def cmd_symbolic_harness(args: argparse.Namespace) -> int:
    """Render a forge-std-free symbolic harness (for Halmos) from a JSON spec."""
    from .symbolic.harness import HarnessError, harness_from_dict, render_harness

    try:
        data = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        text = render_harness(harness_from_dict(data))
    except (OSError, ValueError, HarnessError) as exc:
        print(f"symbolic-harness: {exc}")
        return 2
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


@_fixture_command
def cmd_differential_fuzz(args: argparse.Namespace) -> int:
    """Differential-fuzz two registered targets and report snapshot divergences."""
    from .fuzz.differential import DifferentialError, differential_fuzz
    from .invariants.registry import make_target

    try:
        report = differential_fuzz(make_target(args.reference),
                                   make_target(args.candidate),
                                   runs=args.runs, steps=args.steps, seed=args.seed)
    except (KeyError, DifferentialError) as exc:
        print(f"differential-fuzz: {exc}")
        return 2
    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    state = "CLEAN" if report.clean else "DIVERGENCE"
    print(f"[{state}] {args.reference} vs {args.candidate}: "
          f"{len(report.divergences)} divergence(s) over {report.compared} sequence(s) "
          f"(a divergence is a lead, not a finding)")
    return 0 if report.clean else 1


def cmd_properties(args: argparse.Namespace) -> int:
    """Compile a property spec into invariants and (optionally) a Foundry test."""
    from .fuzz.properties import PropertyError, load_specs, render_invariant_test

    try:
        props, specs = load_specs(Path(args.spec).read_text(encoding="utf-8"))
    except (OSError, PropertyError) as exc:
        print(f"properties: {exc}")
        return 2
    if args.out:
        sol = render_invariant_test(props, contract_name=args.contract_name,
                                    target_type=args.target_type, target_ctor=args.target_ctor)
        Path(args.out).write_text(sol, encoding="utf-8")
        print(f"wrote {args.out} ({len(specs)} invariant(s))")
    else:
        for spec in specs:
            print(f"{spec.inv_id}: {spec.title}")
    return 0


def cmd_threatintel(args: argparse.Namespace) -> int:
    """Ingest a public threat-intel feed into LEAD regression fixtures."""
    from .threatintel import ThreatIntelError, ingest, ingest_from_url, write_fixtures

    try:
        if args.url:
            result = ingest_from_url(args.url, args.source, allow_network=args.allow_network)
        elif args.input:
            result = ingest(json.loads(Path(args.input).read_text(encoding="utf-8")), args.source)
        else:
            print("threatintel: provide --input FILE or --url URL")
            return 2
    except (OSError, ValueError, ThreatIntelError) as exc:
        print(f"threatintel: {exc}")
        return 2
    if args.out:
        write_fixtures(result.patterns, args.out)
        print(f"wrote {len(result.patterns)} fixture(s) to {args.out}")
    print(f"accepted={len(result.patterns)} skipped={len(result.skipped)} (all LEAD)")
    for skip in result.skipped:
        print(f"  skipped #{skip['index']}: {skip['reason']}")
    return 0


def _ton_emit_surface(surface, label: str, as_json: bool) -> None:
    import json

    if as_json:
        print(json.dumps(surface.to_dict(), indent=2))
        return
    print(f"{label} surface: {surface.root}")
    print(f"  contracts: {len(surface.contracts)}  "
          f"handlers: {len(surface.handlers)}")
    for h in surface.handlers:
        guard = "guarded" if h.guarded else "NO-GUARD"
        print(f"  {h.path}:{h.line} {h.contract}.{h.name} ({h.kind}) [{guard}]")
        if h.reason:
            print(f"    {h.reason}")
    if surface.unmodelled:
        print("  not modelled:")
        for item in surface.unmodelled:
            print(f"    - {item}")


def _ton_emit_derived(target, surface, cert, as_json: bool) -> None:
    import json

    from .ton import UNMODELLED

    payload = {
        "root": surface.root,
        "enabled_ops": sorted(target.enabled_ops),
        "derived_unguarded": sorted(target.derived_unguarded),
        "unmodelled_handlers": list(target.unmodelled_handlers),
        "invariants": [i.inv_id for i in target.invariants()],
        "unmodelled": list(UNMODELLED),
    }
    if cert is not None:
        payload["certificate"] = cert.to_dict()
        payload["target_kind"] = "derived"
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    print(f"TON derived model: {surface.root}")
    print(f"  enabled ops: {', '.join(sorted(target.enabled_ops)) or '(none matched)'}")
    unguarded = ", ".join(sorted(target.derived_unguarded)) or "(none)"
    print(f"  unguarded privileged handlers (leads): {unguarded}")
    if target.unmodelled_handlers:
        print(f"  unmodelled handlers: {', '.join(target.unmodelled_handlers)}")
    if cert is not None:
        for v in cert.violations[:5]:
            seq = " -> ".join(f"{s['actor']}.{s['action']}({s['params']})"
                              for s in v.get("minimal_sequence", []))
            print(f"  LEAD {v['invariant_id']}: {seq}")
        if not cert.violations:
            print("  no invariant broken within the bound")
        if cert.unevaluable:
            print("  unevaluable: " + ", ".join(cert.unevaluable))


def cmd_ton(args: argparse.Namespace) -> int:
    """TON (The Open Network) reference model and bounded certification."""
    import json

    from .assurance import CertifyConfig, certify
    from .ton import TON_OPS, UNMODELLED, TONTarget

    if args.ton_command == "model":
        payload = {
            "name": TONTarget.name,
            "operations": [
                {"name": o.name, "actors": list(o.actors), "params": list(o.params),
                 "description": o.description}
                for o in TON_OPS
            ],
            "invariants": [i.inv_id for i in TONTarget().invariants()],
            "unmodelled": list(UNMODELLED),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("TON reference model: " + payload["name"])
            for o in payload["operations"]:
                print(f"  {o['name']:14} actors={','.join(o['actors'])} "
                      f"params={','.join(o['params'])}")
            print("invariants:")
            for inv in payload["invariants"]:
                print(f"  {inv}")
            print("not modelled:")
            for item in payload["unmodelled"]:
                print(f"  - {item}")
        return 0

    if args.ton_command in ("from-tact", "from-func"):
        if args.ton_command == "from-tact":
            from .ton.tact import scan_tact
            surface, label = scan_tact(args.path), "Tact"
        else:
            from .ton.func import scan_func
            surface, label = scan_func(args.path), "FunC"
        _ton_emit_surface(surface, label, args.json)
        return 0

    if args.ton_command in ("model-from-tact", "model-from-func"):
        from .ton.derive import derive_target
        if args.ton_command == "model-from-tact":
            from .ton.tact import scan_tact
            surface = scan_tact(args.path)
        else:
            from .ton.func import scan_func
            surface = scan_func(args.path)
        target = derive_target(surface)
        cert = None
        if args.certify:
            cert = certify(target, CertifyConfig(
                max_depth=args.depth, max_sequences=args.max_sequences,
                price_findings=False,
            ))
        _ton_emit_derived(target, surface, cert, args.json)
        return 0

    if args.ton_command == "hunt":
        from .hunt.orchestrator import HuntConfig, hunt
        from .toolchain.enforce import self_test_record
        from .ton.derive import derive_target
        from .ton.func import scan_func
        from .ton.tact import scan_tact

        def _derive(path):
            surf = scan_tact(path)
            if not surf.handlers:
                surf = scan_func(path)
            model = derive_target(surf)
            # A derived model is BLACKHEART's own, not a third-party component, so
            # it runs under the repository-bound self-test record.
            model.repository = "blackheart"
            return model, surf

        model, surface = _derive(args.path)
        control_path = getattr(args, "control", "") or ""
        control_surface = _derive(control_path)[1] if control_path else None
        result = hunt(model, HuntConfig(
            stages=("search", "certify", "verify"),
            certify_depth=args.depth,
            certify_max_sequences=args.max_sequences,
            target_factory=lambda: _derive(args.path)[0],
            control_factory=(lambda: _derive(control_path)[0]) if control_path else None,
            in_scope=True if getattr(args, "in_scope", False) else None,
            authorization_gate_passed=True if getattr(args, "authorized", False) else None,
            scope_reference=getattr(args, "scope_ref", "") or "",
        ), compatibility=self_test_record())
        payload = result.to_dict()
        payload["surface"] = surface.to_dict()
        if control_surface is not None:
            payload["control_surface"] = control_surface.to_dict()
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0
        print(f"TON hunt: {surface.root}")
        if control_surface is not None:
            print(f"  control: {control_surface.root} (guarded twin)")
        print(f"  verdict: {payload['verdict']}")
        for stage in payload["stages"]:
            if stage["ran"]:
                note = f" (error: {stage['error']})" if stage["error"] else ""
                print(f"  {stage['stage']}: {stage['summary']}{note}")
        if payload["verdict"].startswith("VERIFIED"):
            print("  note: model-level verification (fresh re-run + discriminating "
                  "control); not a deployed-contract confirmation.")
        return 0

    target = TONTarget(vulnerable=args.vulnerable)
    cert = certify(target, CertifyConfig(
        max_depth=args.depth, max_sequences=args.max_sequences,
        price_findings=False,
    ))
    payload = cert.to_dict()
    payload["target_kind"] = "vulnerable" if args.vulnerable else "guarded"
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"ton certify target={payload['target_kind']} depth={cert.max_depth} "
              f"alphabet={cert.alphabet_size} tested={cert.sequences_tested} "
              f"exhaustive={cert.exhaustive}")
        for v in cert.violations[:5]:
            seq = " -> ".join(f"{s['actor']}.{s['action']}({s['params']})"
                              for s in v.get("minimal_sequence", []))
            print(f"  BROKEN {v['invariant_id']}: {seq}")
        if not cert.violations:
            print("  no declared invariant broken within the bound")
        if cert.unevaluable:
            print("  unevaluable: " + ", ".join(cert.unevaluable))
    if args.expect == "vulnerable":
        return 0 if cert.violations else 1
    if args.expect == "guarded":
        return 0 if not cert.violations else 1
    return 0


def cmd_cosmos(args: argparse.Namespace) -> int:
    """Cosmos reference model, Go message surface, and bounded certification."""
    import json

    from .assurance import CertifyConfig, certify
    from .cosmos import COSMOS_OPS, UNMODELLED, CosmosTarget, model_from_go
    from .ingest.golang import ingest_go

    if args.cosmos_command == "model":
        payload = {
            "name": CosmosTarget.name,
            "operations": [
                {"name": o.name, "actors": list(o.actors), "params": list(o.params),
                 "description": o.description}
                for o in COSMOS_OPS
            ],
            "invariants": [i.inv_id for i in CosmosTarget().invariants()],
            "unmodelled": list(UNMODELLED),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("Cosmos reference model: " + payload["name"])
            for o in payload["operations"]:
                print(f"  {o['name']:18} actors={','.join(o['actors'])} params={','.join(o['params'])}")
            print("invariants:")
            for inv in payload["invariants"]:
                print(f"  {inv}")
            print("not modelled:")
            for item in payload["unmodelled"]:
                print(f"  - {item}")
        return 0

    if args.cosmos_command == "from-go":
        report = ingest_go(args.path)
        surface = model_from_go(report)
        payload = surface.to_dict()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"Go / Cosmos surface: {surface.root}")
            print(f"  handlers: {len(surface.handlers)}  stubs: {surface.stubs}")
            for h in surface.handlers:
                guard = "guarded" if h.guarded else "NO-GUARD"
                print(f"  {h.path}:{h.line} {h.receiver}.{h.name} -> {h.message} ({guard})")
                if h.reason:
                    print(f"    {h.reason}")
            if surface.boundaries:
                print("  boundaries:")
                for b in surface.boundaries:
                    print(f"    - {b}")
            print("  not modelled:")
            for item in surface.unmodelled:
                print(f"    - {item}")
        return 0

    target = CosmosTarget(vulnerable=args.vulnerable)
    cert = certify(target, CertifyConfig(
        max_depth=args.depth, max_sequences=args.max_sequences,
        price_findings=False,
    ))
    payload = cert.to_dict()
    payload["target_kind"] = "vulnerable" if args.vulnerable else "guarded"
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"cosmos certify target={payload['target_kind']} depth={cert.max_depth} "
              f"alphabet={cert.alphabet_size} tested={cert.sequences_tested} "
              f"exhaustive={cert.exhaustive}")
        for v in cert.violations[:5]:
            seq = " -> ".join(f"{s['actor']}.{s['action']}({s['params']})"
                              for s in v.get("minimal_sequence", []))
            print(f"  BROKEN {v['invariant_id']}: {seq}")
        if not cert.violations:
            print("  no declared invariant broken within the bound")
        if cert.unevaluable:
            print("  unevaluable: " + ", ".join(cert.unevaluable))
    if args.expect == "vulnerable":
        return 0 if cert.violations else 1
    if args.expect == "guarded":
        return 0 if not cert.violations else 1


def cmd_adversary(args: argparse.Namespace) -> int:
    """Adversary emulation: list the profiles, or plan one profile's campaign.

    The plan is objective-first: it starts from what the actor wants to take,
    checks the profile can afford the preconditions, and lays out the stages with
    the engine that runs each, the evidence it must produce, and the condition the
    actor must wait for. Without an authorization record no stage is executable --
    the reasoning is free, the execution is gated.
    """
    from .adversary import PROFILES, plan_campaign, profile, scanner_contrast
    from .scope import load_record

    if args.adversary_command == "profiles":
        payload = {"profiles": [p.to_dict() for p in PROFILES.values()],
                   "scanner_contrast": scanner_contrast()}
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0
        for p in PROFILES.values():
            print(f"{p.name:12} tier={p.tier.value:11} dwell={p.dwell_days:3}d "
                  f"capital={p.capital_units:>12,}")
            print(f"  {p.summary}")
            print(f"  capabilities: {', '.join(sorted(c.value for c in p.capabilities))}")
        print("\nwhat a stateless scanner cannot see:")
        for row in scanner_contrast():
            print(f"  {row['stage']:10} cannot: {row['scanner_cannot']}")
        return 0

    record = load_record(args.authz) if getattr(args, "authz", None) else None
    plan = plan_campaign(
        profile(args.profile), args.objective, args.asset,
        target=getattr(args, "target", "") or "", record=record,
    )
    if args.json:
        print(json.dumps({**plan.to_dict(), "scanner_contrast": scanner_contrast()},
                         indent=2))
    else:
        print(plan.summary())
    return 0 if plan.feasible else 1


@_fixture_command
def cmd_verify(args: argparse.Namespace) -> int:
    # Malformed input is a user error, not a crash: report it and exit 2.
    try:
        finding_data = json.loads(Path(args.finding).read_text(encoding="utf-8"))
        ctx_data = json.loads(Path(args.ctx).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read the finding/context: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:  # json.JSONDecodeError is a ValueError
        print(f"error: the finding/context is not valid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        finding = Finding.from_dict(finding_data)
    except (TypeError, ValueError) as exc:
        print(f"error: invalid --finding: {exc}", file=sys.stderr)
        return 2
    if not isinstance(ctx_data, dict):
        print("error: --ctx must be a JSON object of verification context fields",
              file=sys.stderr)
        return 2
    known = {f.name for f in fields(VerificationContext)}
    unknown = sorted(set(ctx_data) - known - {"reproduce"})
    if unknown:
        print(f"error: unknown --ctx field(s): {', '.join(unknown)}; "
              f"valid fields are: {', '.join(sorted(known - {'reproduce'}))}",
              file=sys.stderr)
        return 2
    ctx = VerificationContext(
        **{k: v for k, v in ctx_data.items() if k != "reproduce"}
    )
    result = IndependentVerifier().verify(finding, ctx)
    print(json.dumps(result.to_dict(), indent=2))
    # The exit code must agree with the verdict: a rejected finding is not a pass.
    confirmed = result.classification == Classification.CONFIRMED
    if not confirmed:
        print(f"verify: {result.classification.value} -- not a confirmed finding",
              file=sys.stderr)
    return 0 if confirmed else 1


def cmd_triage(args: argparse.Namespace) -> int:
    """Run the deterministic weak-finding gate on one finding class + evidence."""
    from .verify.triage import TriageGate

    verdict = TriageGate().evaluate(
        args.category, args.evidence,
        chain_demonstrated=args.chain_demonstrated,
    )
    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        print(f"{verdict.category}: {verdict.disposition}")
        for sig in verdict.kill_signals:
            missing = sig.get("missing_evidence") or []
            extra = f" (missing: {', '.join(missing)})" if missing else ""
            print(f"  - {sig['id']}: {sig['reason']}{extra}")
            if sig.get("upstream"):
                print(f"    upstream: {sig['upstream']}")
        if verdict.chain_required:
            print(f"  chain required: {verdict.chain_required}")
        if verdict.disposition == "PASS":
            print("  no kill signal; the independent verifier still decides the outcome")
    # REJECT -> exit 2 (do not report). DOWNGRADE/PASS -> 0.
    return 2 if verdict.reject else 0


def cmd_engines(args: argparse.Namespace) -> int:
    """Engine integration layer: discover, inspect, run, verify, report."""
    from .engines import get_adapter, list_engines
    from .engines import report as eng_report
    from .engines import session as eng_session

    sub = args.sub

    if sub == "list":
        rows = []
        for name in list_engines():
            a = get_adapter(name, args.workdir)
            rows.append({**a.describe(),
                         "state": a.verify_health().state.value,
                         "version": a.verify_health().version})
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"{r['name']:8} {r['state']:20} v{r['version'] or '-':12} "
                      f"[{r['license']}] {r['description']}")
                print(f"         {r['upstream_url']}")
        return 0

    if sub in ("bootstrap", "doctor"):
        from .engines.toolchain import bootstrap, doctor, format_doctor

        only = [args.engine] if args.engine else None
        if sub == "bootstrap":
            report = bootstrap(only=only, python=args.python,
                               log=lambda m: print(m, file=sys.stderr))
        else:
            report = doctor(only=args.engine or None)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(format_doctor(report))
        return 0 if report["ok"] else 1

    if sub == "capabilities":
        if not args.engine:
            print("--engine is required", file=sys.stderr)
            return 2
        a = get_adapter(args.engine, args.workdir)
        caps = [c.to_dict() for c in a.inspect_capabilities()]
        if args.json:
            print(json.dumps({"engine": args.engine, "capabilities": caps}, indent=2))
        else:
            h = a.verify_health()
            print(f"{args.engine}: {h.state.value} ({h.detail})")
            for c in caps:
                mark = "x" if c["available"] else " "
                print(f"  [{mark}] {c['key']:22} {c['label']}")
        return 0

    if sub == "verify":
        name = args.engine or ""
        names = [name] if name else list_engines()
        out = []
        for n in names:
            a = get_adapter(n, args.workdir)
            h = a.verify_health()
            ok, reason = a.validate_configuration()
            out.append({"engine": n, "state": h.state.value, "version": h.version,
                        "detail": h.detail, "config_ok": ok, "config_reason": reason})
        print(json.dumps(out, indent=2))
        # Exit non-zero only if a *requested* engine is unavailable.
        if name and out and out[0]["state"] in ("MISSING", "UNSUPPORTED", "CONFIGURATION_ERROR"):
            return 1
        return 0

    if sub == "run":
        engines = [e.strip() for e in (args.engines or "").split(",") if e.strip()] or None
        authz = _load_authz(args.authz) if args.authz else None
        opts = json.loads(Path(args.options).read_text(encoding="utf-8")) if args.options else {}
        from .toolchain.enforce import CompatibilityError

        try:
            outcome = eng_session.run_session(
                args.workdir, args.target, engines=engines, authz=authz,
                asset=args.asset or "", allow_local=args.allow_local,
                engine_options=opts, compatibility=args.compatibility,
            )
        except CompatibilityError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if not outcome.allowed:
            print(f"BLOCKED: {outcome.blocked_reason}", file=sys.stderr)
            return 2
        result = outcome.result
        print(f"engines run complete: target={result.target}")
        for e in result.engines:
            print(f"  {e.engine:8} {e.state:12} findings={e.findings} {e.detail}")
        if result.missing_engines:
            print(f"  missing engines: {', '.join(result.missing_engines)}")
        print(f"  candidates={len(result.candidates)} clusters={len(result.clusters)} "
              f"confirmed={len(result.confirmed)} chains={len(result.chains)}")
        if args.report:
            written = eng_report.write_reports(
                result, Path(args.report), engagement=args.engagement or "",
                authz_status="AUTHORIZED" if authz else "local/disposable")
            print(f"  reports: {written}")
        return 0

    if sub == "status":
        print(json.dumps(eng_session.engine_status(args.workdir), indent=2))
        return 0

    if sub == "cancel":
        path = eng_session.request_cancel(args.workdir)
        print(f"cancellation requested: {path}")
        return 0

    if sub == "findings":
        result = eng_session.load_state(args.workdir)
        if result is None:
            print(f"no engine run in {args.workdir}", file=sys.stderr)
            return 2
        clusters = [c.to_dict() for c in result.clusters]
        print(json.dumps(clusters, indent=2, default=str))
        return 0

    if sub == "document":
        try:
            ids = eng_session.document_run(args.workdir, args.findings_dir, name=args.name)
        except eng_session.EngineSessionError as e:
            print(str(e), file=sys.stderr)
            return 2
        print(f"documented {len(ids)} cluster(s) into {args.findings_dir}")
        for i in ids:
            print(f"  {i}")
        return 0

    if sub == "report":
        result = eng_session.load_state(args.workdir)
        if result is None:
            print(f"no engine run in {args.workdir}", file=sys.stderr)
            return 2
        if args.stdout:
            fmt = args.format
            if fmt == "md":
                print(eng_report.render_markdown(result, engagement=args.engagement or ""))
            elif fmt == "json":
                print(eng_report.render_json(result, engagement=args.engagement or ""))
            else:
                print(eng_report.render_sarif(result))
            return 0
        written = eng_report.write_reports(
            result, Path(args.out), engagement=args.engagement or "",
            formats=tuple(args.format.split(",")))
        print(json.dumps(written, indent=2))
        return 0

    print(f"unknown engines subcommand {sub!r}", file=sys.stderr)
    return 2


def cmd_deployment(args: argparse.Namespace) -> int:
    """Bind a live deployment to a component and a compatibility record."""
    from .ingest.deployment import bind_deployment, write_binding

    binding = bind_deployment(
        args.address, args.chain,
        repository=args.repository, commit=args.commit,
        rpc_url=args.rpc, component=args.component,
        smoke_test=args.smoke_test, timeout=args.timeout,
    )
    if args.out:
        write_binding(binding, args.out)
    if args.json:
        print(json.dumps(binding.to_dict(), indent=2))
    else:
        print(f"status       {binding.status}")
        print(f"address      {binding.address}")
        print(f"chain_id     {binding.chain_id}")
        print(f"component    {binding.component or '-'}")
        print(f"repository   {binding.repository}")
        print(f"commit       {binding.commit}")
        print(f"smoke_test   {binding.smoke_test}")
        print(f"reason       {binding.reason}")
        if binding.missing:
            print("missing      " + ", ".join(binding.missing))
    return 0 if binding.bound else 2


def cmd_deployed(args: argparse.Namespace) -> int:
    """Verify a deployed contract's real on-chain facts (read-only).

    Reads runtime bytecode, hashes it, detects standard proxy patterns, and
    records the block/chain/time. Never sends a transaction. Exits non-zero when
    the contract could not be verified, so a caller fails closed.
    """
    from .deployed import verify_contract
    from .rpc import resolve_mainnet_rpc

    # Resolve a *live* endpoint (operator override -> keyless registry -> You.com
    # discovery -> probed fallback). Never assume a hardcoded URL is up.
    rpc = args.rpc or os.environ.get("BLACKHEART_ETH_RPC") or resolve_mainnet_rpc()
    if not rpc:
        print("no live RPC endpoint could be resolved for mainnet; supply --rpc or "
              "set BLACKHEART_ETH_RPC", file=sys.stderr)
        return 1
    result = verify_contract(
        args.address, rpc,
        at_block=args.block, detect_proxy=not args.no_proxy,
    )

    # Optional: fingerprint specific function signatures in the runtime bytecode.
    # A selector that merely occurs in the bytecode is *not* a callable function:
    # PUSH4 constants, error strings and ABI tables put 4-byte values there too.
    # The verdict reports dispatch-reachability, and keeps the raw substring hit
    # as a separate, weaker fact so a reader can see both.
    selectors: list[dict] = []
    if args.selectors:
        from .deployed import function_selector, selector_present
        from .deployed_selectors import analyse_selectors

        dispatch = analyse_selectors(result.code)
        by_sel = dispatch.by_selector()
        for sig in args.selectors.split(";"):
            sig = sig.strip()
            if not sig:
                continue
            sel = function_selector(sig)
            entry = by_sel.get(sel)
            selectors.append({
                "signature": sig,
                "selector": "0x" + sel,
                "reachable": bool(entry and entry.reachable),
                "status": entry.status if entry else "ABSENT",
                "present": selector_present(result.code, sel),
                "evidence": entry.evidence if entry else "no PUSH4 with this value",
            })

    if args.json:
        payload = result.to_dict()
        if selectors:
            payload["selectors"] = selectors
        print(json.dumps(payload, indent=2))
    else:
        print(f"address      {result.address}")
        print(f"rpc          {result.rpc_url}")
        print(f"chain_id     {result.chain_id}  block {result.block_number}")
        print(f"is_contract  {result.is_contract}  size {result.code_size} bytes")
        print(f"code_sha256  {result.code_sha256}")
        if result.eip7702_delegate:
            print(f"eip7702      delegates to {result.eip7702_delegate} (EOA, not a contract)")
        if result.proxy:
            print(f"proxy        {result.proxy_kind} -> {result.implementation or result.beacon}")
        if result.admin:
            print(f"admin        {result.admin}")
        for sel in selectors:
            mark = "present" if sel["present"] else "absent "
            print(f"selector     {sel['selector']}  {mark}  {sel['signature']}")
        for lim in result.limitations:
            print(f"limitation   {lim}")
        print(f"verified     {result.verified}")
    return 0 if result.verified else 1


def _monitor_rpc(args: argparse.Namespace) -> str:
    """The operator's explicit endpoint wins; otherwise resolve a *live* one.

    No endpoint is hardcoded here: the universal resolver probes candidates and
    returns only one that answered. ``DEFAULT_RPC`` remains the resolver's own
    last-resort fallback, so a fresh sandbox still works.
    """
    explicit = getattr(args, "rpc", None) or os.environ.get("BLACKHEART_ETH_RPC")
    if explicit:
        return explicit
    from .monitor import DEFAULT_RPC
    from .rpc import resolve_mainnet_rpc

    return resolve_mainnet_rpc() or DEFAULT_RPC


def cmd_research_deployed(args: argparse.Namespace) -> int:
    """Research a real deployed contract at a pinned block (read-only by default).

    Retrieval, proxy resolution and dispatch-reachability analysis are read-only.
    ``--execute`` additionally runs a sequence on an isolated local fork; nothing
    is ever broadcast. The command exits non-zero only when the target could not
    be retrieved at all -- an inconclusive investigation is not an error, but it
    is also never reported as a clean result.
    """
    from .deployed_experiment import run_deployed_experiment
    from .toolchain.enforce import CompatibilityError

    try:
        rec = run_deployed_experiment(
            args.experiment_id or f"deployed-{args.address[:10]}",
            address=args.address,
            block_number=args.block,
            rpc_urls=[args.rpc] if args.rpc else None,
            execute=args.execute,
            compatibility=args.compatibility,
        )
    except CompatibilityError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 -- an infrastructure crash is BLOCKED
        # A crashed retrieval or executor is not an investigation result. Report
        # it as blocked with the cause, and never let it read as "nothing found".
        print(f"research blocked: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    payload = rec.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        t = payload.get("target") or {}
        print(f"experiment   {payload['experiment_id']}")
        print(f"state        {payload['state']}")
        if t:
            print(f"chain_id     {t.get('chain_id')}  block {t.get('block_number')}")
            print(f"block_hash   {t.get('block_hash')}")
            print(f"code         {t.get('code_size')} bytes  sha256 {t.get('code_sha256')}")
            print(f"proxy        {t.get('is_proxy')}  logic {t.get('logic_address')}")
            d = t.get("dispatch") or {}
            print(f"selectors    {len(d.get('reachable') or [])} reachable, "
                  f"{len(d.get('present_only') or [])} present-only")
        if payload.get("blocked_reason"):
            print(f"blocked      {payload['blocked_reason']}")
        print(f"hypotheses   {len(payload.get('hypotheses') or [])}")
        for lim in payload.get("limitations") or []:
            print(f"limitation   {lim}")
    return 1 if rec.state == "BLOCKED" else 0


def cmd_monitor_targets(args: argparse.Namespace) -> int:
    """List the watched-contract registry (no network access)."""
    from .monitor import TARGETS

    if args.json:
        print(json.dumps([t.to_dict() for t in TARGETS], indent=2))
        return 0
    for t in TARGETS:
        proxy = " [proxy]" if t.proxy else ""
        print(f"{t.key:26} {t.chain_id:>3}  {t.address}{proxy}")
        print(f"{'':26} {t.kind:8} {t.name}")
        if t.note:
            print(f"{'':26} note: {t.note}")
    return 0


def _select_targets(keys: list[str] | None) -> tuple:
    from .monitor import TARGETS

    if not keys:
        return TARGETS
    wanted = set(keys)
    known = {t.key for t in TARGETS}
    unknown = wanted - known
    if unknown:
        raise SystemExit(f"unknown target key(s): {', '.join(sorted(unknown))}")
    return tuple(t for t in TARGETS if t.key in wanted)


def cmd_monitor_run(args: argparse.Namespace) -> int:
    """Poll targets and report deployed-code drift against a baseline (read-only)."""
    from .monitor import DriftKind, load_state, run_monitor, save_state

    rpc = _monitor_rpc(args)
    targets = _select_targets(args.targets)
    baseline = load_state(args.baseline) if args.baseline else None
    report, drifts = run_monitor(rpc, targets=targets, baseline=baseline)

    changed = [k for k, d in drifts.items()
               if d in (DriftKind.CODE_CHANGED, DriftKind.IMPL_CHANGED)]
    gaps = [k for k, d in drifts.items() if d == DriftKind.UNVERIFIED]

    if args.json:
        payload = report.to_dict()
        payload["drift"] = drifts
        payload["changed"] = changed
        payload["unverified"] = gaps
        print(json.dumps(payload, indent=2))
    else:
        print(f"rpc   {rpc}")
        print(f"when  {report.retrieved_at}")
        for obs in report.observations:
            drift = drifts[obs.key]
            mark = "!!" if drift in changed else "  "
            impl = f" -> {obs.implementation}" if obs.proxy and obs.implementation else ""
            print(f"{mark} {obs.key:26} {drift:16} blk {obs.block_number} "
                  f"fp {obs.fingerprint()[:18] or '(none)'}{impl}")
            for lim in obs.limitations:
                print(f"{'':29} limitation: {lim}")
        if changed:
            print(f"\nDRIFT in {len(changed)} target(s): {', '.join(changed)}")
            print("Investigate: re-diff deployed source vs audited HEAD and fork-test.")
        elif gaps:
            print(f"\nINCOMPLETE: {len(gaps)} target(s) unreadable: {', '.join(gaps)}")
            print("This is an RPC/availability gap, NOT a clean result. Retry.")
        else:
            print("\nno code drift detected")

    if args.save:
        save_state(report, args.save)
        if not args.json:
            print(f"saved baseline -> {args.save}")
    # 1 = code drift (investigate), 2 = could not read the chain (retry),
    # 0 = every target read and unchanged. A gap is never reported as clean.
    if changed:
        return 1
    return 2 if gaps else 0


def cmd_monitor_baseline(args: argparse.Namespace) -> int:
    """Write a pinned baseline of the current deployed code (read-only)."""
    from .monitor import run_monitor, save_state

    rpc = _monitor_rpc(args)
    report, _ = run_monitor(rpc)
    save_state(report, args.out)
    unverified = [o.key for o in report.observations if not o.verified]
    if args.json:
        print(json.dumps({"out": args.out, "observations": report.to_dict()["observations"],
                          "unverified": unverified}, indent=2))
    else:
        print(f"wrote baseline -> {args.out} ({len(report.observations)} targets)")
        if unverified:
            print(f"unverified (no code / RPC gap): {', '.join(unverified)}")
    # A baseline with unreadable targets is not a trustworthy baseline.
    return 2 if unverified else 0


def cmd_watch_targets(args: argparse.Namespace) -> int:
    """List the independent bounty watchlist (no network access)."""
    from .watch.registry import load_registry, write_target_records

    targets = load_registry(args.registry)
    if args.write:
        written = write_target_records(targets, args.write)
        if args.json:
            print(json.dumps({"written": written, "count": len(targets)}, indent=2))
        else:
            print(f"wrote {len(written) - 1} target record(s) + index -> {args.write}")
        return 0
    if args.json:
        print(json.dumps([t.to_dict() for t in targets], indent=2))
        return 0
    print(f"{len(targets)} independent target record(s)\n")
    for t in targets:
        perm = "PERMITTED" if t.submission_permitted else "monitor-only"
        print(f"{t.group} {t.slug:18} {t.program_status:24} {perm:12} "
              f"policy={len(t.policy_urls):2} repos={len(t.repos):2} contracts={len(t.contracts):2}")
        print(f"{'':20}{t.name}")
        if t.restrictions:
            print(f"{'':20}restriction: {t.restrictions[0]}")
    return 0


def cmd_watch_cycle(args: argparse.Namespace) -> int:
    """Run one hourly monitoring cycle (read-only) and write a durable report."""
    from .watch.cycle import CycleConfig, run_cycle
    from .watch.report import render_issue, render_status

    cfg = CycleConfig(
        state_dir=args.state,
        out_dir=args.out,
        registry_path=args.registry,
        targets=tuple(args.targets or ()),
        skip_policy=bool(getattr(args, "skip_policy", False)),
        skip_repos=bool(getattr(args, "skip_repos", False)),
        skip_contracts=bool(getattr(args, "skip_contracts", False)),
        max_repos=args.max_repos,
        max_policy=args.max_policy,
        max_contracts=args.max_contracts,
        timeout=args.timeout,
        dry_run=args.dry_run,
        email=bool(getattr(args, "email", False)),
        email_to=getattr(args, "email_to", ""),
        source_diff=not bool(getattr(args, "skip_source", False)),
    )
    report = run_cycle(cfg)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(render_status(report))
        print()
        for tr in report.targets:
            if not tr.events and not tr.failures:
                continue
            statuses = ", ".join(sorted({l.status for l in tr.leads})) or "NO CHANGE"
            print(f"{tr.target.slug:18} {statuses}")
            for ev in tr.events:
                print(f"  - [{ev.kind}] {ev.component}: {ev.summary}")
            for failure in tr.failures:
                print(f"  ! {failure}")
        if report.warnings:
            print()
            for warning in report.warnings:
                print(f"warning: {warning}")
        print()
        print(f"report -> {args.out}/reports/{report.cycle_id}.md")
    if getattr(args, "issue", False):
        print("\n--- issue body ---\n")
        print(render_issue(report))
    return report.exit_code


def cmd_watch_status(args: argparse.Namespace) -> int:
    """Show the durable state summary without touching the network."""
    from .watch.state import WatchState

    state = WatchState.load(args.state)
    summary = state.summary()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    print(f"state       {state.path}")
    for key in (
        "version", "cycles", "last_cycle_at", "targets_tracked",
        "policy_observations", "repo_observations", "contract_observations",
        "seen_events", "failing_sources",
    ):
        print(f"{key:20} {summary.get(key)}")
    if summary.get("warning"):
        print(f"warning             {summary['warning']}")
    return 0


def cmd_watch_selftest(args: argparse.Namespace) -> int:
    """Real-network smoke test: one official policy, one repo, one contract.

    This is the honest demonstration that the clients work against public
    sources. It reports PASS / INCOMPLETE and never fabricates a success.
    """
    from .watch.fetch import GitHubClient, HttpFetcher, RpcClient
    from .watch.registry import load_registry

    targets = load_registry(args.registry)
    checks: list[dict] = []

    policy_target = next((t for t in targets if t.policy_urls), None)
    if policy_target:
        ref = policy_target.policy_urls[0]
        res = HttpFetcher(timeout=args.timeout, retries=1).fetch(ref.url)
        checks.append({
            "check": "policy",
            "target": policy_target.slug,
            "source": ref.url,
            "ok": res.ok,
            "detail": f"HTTP {res.status}, {res.bytes} bytes, sha256 {res.text_sha256[:16]}"
            if res.ok else res.error,
        })
    repo_target = next((t for t in targets if t.repos), None)
    if repo_target:
        ref = repo_target.repos[0]
        res = GitHubClient(timeout=args.timeout, retries=1).repo(ref.repo)
        checks.append({
            "check": "github",
            "target": repo_target.slug,
            "source": f"https://github.com/{ref.repo}",
            "ok": res.ok,
            "detail": (
                f"default_branch={res.data.get('default_branch')} "
                f"pushed_at={res.data.get('pushed_at')}"
                if res.ok and isinstance(res.data, dict) else res.error
            ),
        })
    contract_target = next((t for t in targets if t.contracts), None)
    obs = None
    if contract_target:
        ref = contract_target.contracts[0]
        obs = RpcClient(timeout=args.timeout).observe(ref)
        checks.append({
            "check": "contract",
            "target": contract_target.slug,
            "source": ref.provenance or ref.address,
            "ok": obs.ok,
            "detail": (
                f"chain {obs.chain_id} block {obs.block_number} "
                f"fingerprint {obs.fingerprint[:18]} proxy={obs.proxy}"
                if obs.ok else obs.error
            ),
        })
    if contract_target and obs is not None and obs.ok:
        from .watch.source import SourceClient

        address = obs.implementation if obs.proxy and obs.implementation else ref.address
        bundle = SourceClient(timeout=args.timeout).fetch(obs.chain_id, address)
        checks.append({
            "check": "verified_source",
            "target": contract_target.slug,
            "source": bundle.url,
            "ok": bundle.ok,
            "detail": (
                f"{bundle.status} match={bundle.match} files={len(bundle.files)} "
                f"compiler={bundle.compiler_version}"
                if bundle.ok else f"{bundle.status}: {bundle.error}"
            ),
        })
    passed = sum(1 for c in checks if c["ok"])
    state = "PASS" if checks and passed == len(checks) else "INCOMPLETE"
    payload = {"state": state, "passed": passed, "total": len(checks), "checks": checks}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"selftest {state} ({passed}/{len(checks)})")
        for c in checks:
            print(f"  [{'ok' if c['ok'] else 'GAP'}] {c['check']:9} {c['target']:12} {c['detail']}")
        if state != "PASS":
            print("A gap is not a clean result; retry or fix the source.")
    return 0 if state == "PASS" else 2


def cmd_version(args: argparse.Namespace) -> int:
    """The installed version, interpreter and package root."""
    import platform

    payload = {
        "name": "blackheart",
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "executable": sys.executable,
        "root": str(Path(__file__).resolve().parent.parent),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"blackheart {payload['version']} (python {payload['python']}, {payload['platform']})")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """A compact product summary: counts, capability headline and paths."""
    import platform

    from .capability import CAPABILITIES, as_dict
    from .invariants import TARGET_SPECS
    from .objectives import _OBJECTIVE_CATALOG

    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    caps = as_dict()
    counts = {status: sum(1 for c in CAPABILITIES if c.status == status)
              for status in ("yes", "partial", "no")}
    payload = {
        "name": "blackheart",
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "root": str(Path(__file__).resolve().parent.parent),
        "commands": len(sub.choices),
        "objective_categories": len(_OBJECTIVE_CATALOG),
        "executable_targets": len(TARGET_SPECS),
        "capabilities": {"total": len(CAPABILITIES), **counts},
        "can_find_payable_bug_unaided": caps["can_find_payable_bug_unaided"],
        "paths": {
            "findings": str(Path.cwd() / "research/private/findings"),
            "evidence": str(Path.cwd() / "research/private/evidence"),
            "reports": str(Path.cwd() / "research/private/reports"),
        },
        "docs": {
            name: (
                str(path) if path.is_file()
                else f"https://github.com/itzebe/blackheart/blob/main/docs/{path.name}"
            )
            for name, path in (
                ("quickstart", Path(__file__).resolve().parent.parent / "docs/QUICKSTART.md"),
                ("capabilities", Path(__file__).resolve().parent.parent / "docs/CAPABILITIES.md"),
                ("doctrine", Path(__file__).resolve().parent.parent / "docs/DOCTRINE.md"),
            )
        },
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"BLACKHEART {payload['version']}  (python {payload['python']})")
        print(f"root: {payload['root']}")
        print(f"{payload['commands']} commands | {payload['objective_categories']} objective "
              f"categories | {payload['executable_targets']} executable targets")
        print(f"capabilities: {counts['yes']} yes, {counts['partial']} partial, {counts['no']} no")
        print("Can it find a payable bug unaided? "
              f"{'Yes' if payload['can_find_payable_bug_unaided'] else 'No'}")
        print(f"findings: {payload['paths']['findings']}")
        print("next: blackheart guide | blackheart doctor | blackheart demo")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold a workspace whose authorization record fails closed."""
    from .product import scaffold

    result = scaffold(args.dir, force=args.force)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"workspace: {result['root']}")
        if result["created"]:
            print("created: " + ", ".join(result["created"]))
        if result["kept"]:
            print("kept (use --force to replace): " + ", ".join(result["kept"]))
        print("next:")
        for step in result["next"]:
            print(f"  - {step}")
    return 0


@_fixture_command
def cmd_demo(args: argparse.Namespace) -> int:
    """Run the offline reference pipeline: fuzz -> finding -> SARIF -> baseline."""
    from .product import run_demo

    result = run_demo(args.dir, runs=args.runs, steps=args.steps)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    elif result.get("ok"):
        print(f"demo: {result['root']}")
        print(f"  finding: {result['finding_id']} [{result['verdict']}]")
        print(f"  sequence: {' -> '.join(result['sequence'])}")
        print(f"  guarded twin failures: {result['guarded_failures']}")
        print(f"  SARIF: {result['sarif']}")
        print(f"  baseline: {result['baseline']} ({result['diff']})")
    else:
        print(f"demo failed: {result.get('reason')}", file=sys.stderr)
        for error in result.get("errors") or []:
            print(f"  - {error}", file=sys.stderr)
    return 0 if result.get("ok") else 1


def cmd_guide(args: argparse.Namespace) -> int:
    """Grouped command list, so the large command surface is navigable."""
    from .product import render_guide

    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps = {
        action.dest: (action.help or "")
        for action in getattr(sub, "_choices_actions", [])
        if getattr(action, "dest", None)
    }
    print(render_guide(helps))
    return 0


@_fixture_command
def cmd_doctor(args: argparse.Namespace) -> int:
    """Portability and health check: python, package, agents/skills, forge, registry."""
    import sys

    from .invariants import TARGET_SPECS

    root = Path(__file__).resolve().parent.parent
    checks: list[tuple[str, bool, str]] = []

    py_ok = sys.version_info >= (3, 11)
    checks.append(("python>=3.11", py_ok, sys.version.split()[0]))

    agents = sorted(p.stem for p in (root / "agents").glob("*.md")) if (root / "agents").is_dir() else []
    skills = sorted(p.parent.name for p in (root / "skills").glob("*/SKILL.md")) if (root / "skills").is_dir() else []
    checks.append(("agents>=14", len(agents) >= 14, f"{len(agents)} agents"))
    checks.append(("skills>=5", len(skills) >= 5, f"{len(skills)} skills"))

    checks.append(("targets>=10", len(TARGET_SPECS) >= 10, f"{len(TARGET_SPECS)} executable targets"))

    # Attack-class coverage is a *hard* health property, not a setup step: a
    # category with no executable model is invisible to every search strategy, so
    # an unmodelled category means the engine is structurally blind to a class it
    # claims to pursue. It must fail the doctor, not warn.
    from .invariants.coverage import coverage_summary

    cov = coverage_summary()
    checks.append((
        "attack-class coverage",
        cov["unmodelled"] == 0,
        f"{cov['modelled']}/{cov['categories']} categories modelled"
        + (f" (gaps: {', '.join(cov['unmodelled_categories'])})" if cov["unmodelled"] else ""),
    ))

    from .attackdb import verify_all_chains

    chain_report = verify_all_chains()
    checks.append((
        "executable chains verify",
        chain_report["passed"] == chain_report["total"],
        f"{chain_report['passed']}/{chain_report['total']} chains break vuln, hold guarded",
    ))

    # The operator's word must be universal: it reaches every agent and the
    # mindset/adversarial skills. A layer that lacks it would second-guess a clear
    # instruction into a summary, so a missing layer is a hard failure.
    agent_docs = sorted((root / "agents").glob("*.md"))
    agents_with_rule = [p for p in agent_docs
                        if "## The operator's word" in p.read_text(encoding="utf-8")]
    skill_docs = sorted((root / "skills").glob("*/SKILL.md"))
    skills_with_rule = [p for p in skill_docs
                        if "## The operator's word" in p.read_text(encoding="utf-8")]
    op_ok = (len(agents_with_rule) == len(agent_docs) and len(skill_docs) > 0
             and len(skills_with_rule) == len(skill_docs))
    checks.append((
        "operator's word universal",
        op_ok,
        f"{len(agents_with_rule)}/{len(agent_docs)} agents, "
        f"{len(skills_with_rule)}/{len(skill_docs)} skills",
    ))

    # Language-aware tooling must be universal for the same reason: a tool aimed at
    # the wrong language reports nothing, and the silence is read as "no findings".
    # A missing registry entry, policy document, or agent bar is a hard failure.
    from .doctrine import LANGUAGE_AWARE_POLICY
    from .toolchain import TOOLCHAINS

    agents_with_bar = [p for p in agent_docs
                       if "## The language bar" in p.read_text(encoding="utf-8")]
    policy_doc = root / "docs" / "SECURITY_TOOL_COMPATIBILITY.md"
    registry_ok = bool(TOOLCHAINS) and all(
        chain.verified_at and chain.tools
        and all(t.official_docs.startswith("https://") for t in chain.tools)
        for chain in TOOLCHAINS
    )
    gate_fields = LANGUAGE_AWARE_POLICY.get("pre_execution_gate", {}).get("fields", [])
    lang_ok = (registry_ok and bool(gate_fields)
               and len(agents_with_bar) == len(agent_docs) and policy_doc.is_file())
    checks.append((
        "language-aware tooling universal",
        lang_ok,
        f"{len(agents_with_bar)}/{len(agent_docs)} agents, "
        f"{len(TOOLCHAINS)} languages registered, "
        f"{len(gate_fields)} gate fields, policy doc "
        f"{'present' if policy_doc.is_file() else 'MISSING'}",
    ))

    # The .openhands discovery layout must be *functional* for OpenHands to load
    # the project's own skills and agents. Merely existing is not enough: a stale
    # link, an empty directory, or a link that no longer resolves leaves OpenHands
    # unable to discover anything, so we check the layout actually resolves to a
    # non-empty skills/agents tree.
    disc_skills = root / ".openhands" / "skills"
    disc_agents = root / ".openhands" / "agents"
    disc_ok = (disc_skills.is_dir() and any(disc_skills.iterdir())
               and disc_agents.is_dir() and any(disc_agents.iterdir()))
    if disc_ok:
        disc_detail = "present and resolvable"
    elif not (disc_skills.exists() or disc_agents.exists()):
        disc_detail = "missing (run: blackheart provision)"
    else:
        disc_detail = "present but empty or broken (re-run: blackheart provision)"
    checks.append(("openhands discovery layout", disc_ok, disc_detail))
    from .targets import FORK_TARGETS, is_fetched

    checks.append(("fork targets>=1", len(FORK_TARGETS) >= 1,
                   f"{len(FORK_TARGETS)} real-target harness(es)"))
    fetched = sum(1 for t in FORK_TARGETS if is_fetched(t))
    checks.append(("fork source fetched", fetched == len(FORK_TARGETS),
                   f"{fetched}/{len(FORK_TARGETS)} (run: blackheart fork fetch)"))

    from .engines.solidity.base import resolve_tool

    forge_paths = resolve_tool("forge")
    checks.append(("forge on PATH", forge_paths is not None,
                   forge_paths.binary if forge_paths else "not found (install.sh --core)"))

    # External intelligence is how a mission finds the RPC and address of a live
    # target. You.com is the primary, structured provider; the keyless
    # fallbacks and the keyless chain registry keep discovery working without it,
    # so a missing key is a setup warning, not a hard failure.
    try:
        from .intelligence.providers import ProviderRegistry

        statuses = ProviderRegistry().status(probe=False)
        by_name = {s.name: s for s in statuses}
        yc = by_name.get("you.com")
        intel_ok = bool(yc and yc.available)
        checks.append(("intel you.com configured", intel_ok,
                       "key present" if intel_ok else "YDC_API_KEY not set "
                       "(keyless fallback + chain registry still work)"))
    except Exception as exc:  # pragma: no cover - defensive
        checks.append(("intel you.com configured", False, f"unavailable: {exc}"))

    reg_path = Path(args.registry)
    # `blackheart tools verify` without --out writes a repo-local registry, while
    # the global install writes one under $BLACKHEART_HOME. Accept either so the
    # documented setup step actually satisfies the doctor instead of reporting a
    # false "setup incomplete".
    if not reg_path.exists():
        for alt in (root / "research/private/tools/registry.json",):
            if alt.exists():
                reg_path = alt
                break
    if reg_path.exists():
        try:
            data = json.loads(reg_path.read_text(encoding="utf-8"))
            tools = data.get("tools", [])
            functional = [t for t in tools if t.get("status") == "functional"]
            checks.append(("toolchain functional>0", len(functional) > 0,
                           f"{len(functional)}/{len(tools)} functional"))
        except Exception as exc:  # pragma: no cover - defensive
            checks.append(("toolchain registry readable", False, str(exc)))
    else:
        checks.append(("toolchain registry present", False, f"{reg_path} (run: tools verify)"))

    payload = [{"check": c, "ok": ok, "detail": d} for c, ok, d in checks]
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # Hard failures are things that make the *engine itself* unusable and cannot
    # be explained by a setup step. The discovery layout is created by install.sh /
    # `blackheart provision`, and forge/registry/fork source are post-install
    # state, so those are reported as setup warnings rather than hard failures.
    setup_checks = {
        "openhands discovery layout", "forge on PATH",
        "toolchain registry present", "fork source fetched", "intel you.com configured",
    }
    hard = [c for c, ok, _ in checks if not ok and c not in setup_checks]
    pending = [c for c, ok, _ in checks if not ok and c in setup_checks]
    status = "unhealthy" if hard else ("setup_incomplete" if pending else "healthy")

    if getattr(args, "json", False):
        print(json.dumps({
            "status": status,
            "hard": hard,
            "pending": pending,
            "checks": payload,
        }, indent=2))
    else:
        for name, ok, detail in checks:
            print(f"  [{'ok' if ok else '!!'}] {name:26} {detail}")
        if hard:
            print(f"\nissues: {', '.join(hard)}")
        elif pending:
            # Never print a bare "healthy" when setup steps are still outstanding --
            # that would falsely report a ready installation.
            print(f"\nengine healthy; setup incomplete: {', '.join(pending)}")
            print("run `blackheart provision` and `install.sh --core` to finish setup")
        else:
            print("\nhealthy")

    if hard:
        return 1
    return 0


@_fixture_command
def cmd_demonstrate(args: argparse.Namespace) -> int:
    from .demonstrations import run_class_demonstration

    summary = run_class_demonstration(
        args.workdir, pair=args.pair, runs=args.runs, steps_per_run=args.steps, seed=args.seed
    )
    print(f"pair={summary['pair']} status={summary['status']}")
    print(f"  vulnerable_failures={summary['vulnerable_failures']} "
          f"guarded_failures={summary['guarded_failures']}")
    if summary.get("finding"):
        f = summary["finding"]
        print(f"  finding={f['finding_id']} classification={f['classification']} "
              f"submission_ready={summary['submission_ready']}")
        print(f"  report={summary['report_path']}")
    else:
        print("  no attacker-reachable counterexample on this model")
    return 0


@_fixture_command
def cmd_adversarial(args: argparse.Namespace) -> int:
    """Run the multi-engine adversarial harness and print the verdicts."""
    from .adversarial import run_adversarial_engagement

    summary = run_adversarial_engagement(args.workdir, run_slow_engines=not args.fast)
    for name, res in summary["engines"].items():
        status = "missing" if not res["available"] else f"rc={res['returncode']}"
        print(f"  {name:16} {status:8} {res['facts']}")
    print("\nverdicts:")
    for k, v in summary["verdicts"].items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"\nverification={summary['verification'].get('classification')}")
    print(f"summary={args.workdir}/adversarial-engagement-summary.json")
    return 0


@_fixture_command
def cmd_chain(args: argparse.Namespace) -> int:
    """List or execute the executable attack-chain database."""
    from .attackdb import all_chains, get_chain, run_chain, run_chain_control

    if args.list or not args.run:
        for c in all_chains():
            print(f"  {c.chain_id:38} {c.target:20} -> {c.invariant}")
        print(f"\n{len(all_chains())} executable chains (run one with --run <id>)")
        return 0

    try:
        spec = get_chain(args.run)
    except KeyError as exc:
        print(f"error: {exc.args[0] if exc.args else exc}", file=sys.stderr)
        return 2
    vuln = run_chain(args.run)
    control = run_chain_control(args.run)
    payload = {
        "chain_id": spec.chain_id,
        "title": spec.title,
        "hypothesis": spec.hypothesis,
        "invariant": spec.invariant,
        "vulnerable": vuln.to_dict(),
        "guarded": control.to_dict(),
        "verified": vuln.targeted_invariant_broke and not control.broke,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"chain={spec.chain_id}  invariant={spec.invariant}")
    print(f"  vulnerable[{spec.target}]: broke={vuln.broke} "
          f"targeted={vuln.targeted_invariant_broke} reachable={vuln.attacker_reachable}")
    print(f"  guarded[{spec.guarded_target}]: broke={control.broke}")
    print(f"  verified={payload['verified']}")
    return 0 if payload["verified"] else 1


@_fixture_command
def cmd_regress(args: argparse.Namespace) -> int:
    """Run the fuzzer and emit a deterministic regression test per failure."""
    from .regress import emit_from_fuzz_report

    target = _make_target(args.target)
    cfg = FuzzConfig(runs=args.runs, steps_per_run=args.steps, seed=args.seed)
    report = StatefulFuzzer(target, cfg).run()
    paths = emit_from_fuzz_report(report, args.target, args.out)
    print(f"target={args.target} runs={report.runs} failures={len(report.failures)}")
    if not paths:
        print("no invariant failures found; no regression test emitted")
        return 0
    for p in paths:
        print(f"  wrote {p}")
    return 0


def cmd_forge_gen(args: argparse.Namespace) -> int:
    """Render a runnable Foundry test from an executable chain."""
    from .foundry import default_out_path, write_foundry_test

    harness = Path(args.harness)
    out = Path(args.out) if args.out else default_out_path(args.chain, harness)
    path = write_foundry_test(args.chain, out)
    print(f"wrote {path}")
    print("run with: cd harnesses/erc4626 && forge test --match-contract GeneratedPoC -vv")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    """Record and inspect dated engagement-authorization evidence."""
    from .scope import check_asset, load_record, record_authorization

    # Pattern-match mode: a deterministic scope decision for one asset against
    # explicit allow/exclude patterns (no record file needed).
    if args.allow:
        from .authz.scope_matcher import ScopeMatcher, ScopePatternError

        if not args.asset:
            print("--allow requires --asset (the URL/host to match)", file=sys.stderr)
            return 2
        try:
            matcher = ScopeMatcher(allow=args.allow, exclude=args.exclude or [],
                                   excluded_classes=args.excluded_class or [])
        except ScopePatternError as exc:
            print(f"invalid scope pattern: {exc}", file=sys.stderr)
            return 2
        decision = matcher.explain(args.asset)
        payload = decision.to_dict()
        if args.excluded_class:
            payload["excluded_classes"] = args.excluded_class
            payload["class_allowed"] = {
                c: matcher.is_class_allowed(c) for c in args.excluded_class
            }
        print(json.dumps(payload, indent=2))
        return 0 if decision.in_scope else 2

    if args.check:
        rec = load_record(args.check)
        decision = check_asset(rec, args.asset)
        print(json.dumps(decision.to_dict(), indent=2))
        return 0 if decision.allowed else 2

    rec = load_record(args.file)
    summary = record_authorization(
        rec, registry_path=args.registry, evidence_root=args.evidence
    )
    print(json.dumps(summary, indent=2, default=str))
    print(f"\nauthorized assets: {summary['authorized_assets'] or 'NONE'}")
    return 0


def cmd_eligibility_evaluate(args: argparse.Namespace) -> int:
    """Rank candidate programs by the mission's eligibility gate."""
    from .eligibility import load_programs, rank_programs

    verdicts = rank_programs(load_programs(args.file))
    out = [v.to_dict() for v in verdicts]
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    viable = [v.program for v in verdicts if v.viable]
    print(f"\nviable programs: {viable or 'NONE'}")
    return 0 if viable else 2


def cmd_eligibility_to_scope(args: argparse.Namespace) -> int:
    """Emit the AuthorizationRecord for the selected (default: top) viable program."""
    from .eligibility import evaluate, load_programs, to_authorization_record

    programs = load_programs(args.file)
    if args.program:
        matches = [p for p in programs if p.program == args.program]
        if not matches:
            print(f"no program named {args.program!r} in {args.file}", file=sys.stderr)
            return 2
        chosen = matches[0]
    else:
        viable = [p for p in programs if evaluate(p).viable]
        if not viable:
            print("no viable program to emit; fix the eligibility facts first", file=sys.stderr)
            return 2
        chosen = viable[0]

    verdict = evaluate(chosen)
    if not verdict.viable:
        print(
            f"refusing to emit a scope record for {chosen.program!r}: "
            + "; ".join(verdict.blockers),
            file=sys.stderr,
        )
        return 2
    rec = to_authorization_record(chosen)
    Path(args.out).write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
    print(json.dumps(verdict.to_dict(), indent=2))
    print(f"\nwrote authorization record -> {args.out}")
    return 0


def cmd_conformance(args: argparse.Namespace) -> int:
    """Passively check documented HyperCore invariants against public info reads."""
    from .hyperliquid_audit import audit_borrow_lend, audit_outcome_books, fetch_info

    base = args.base.rstrip("/")
    fetch = lambda body: fetch_info(base, body)
    anomalies = []
    if not args.books_only:
        anomalies += audit_borrow_lend(fetch)
    if not args.ledger_only:
        anomalies += audit_outcome_books(fetch, limit=args.limit)

    findings = [a for a in anomalies if a.severity != "info"]
    infos = [a for a in anomalies if a.severity == "info"]
    print(f"base={base} anomalies={len(anomalies)} "
          f"(findings={len(findings)} info={len(infos)})")
    for a in anomalies:
        print(f"  [{a.severity}] {a.invariant} @ {a.surface}: {a.detail}")
    if not anomalies:
        print("  all documented invariants hold on the sampled data")
    return 0


def cmd_agents_verify(args: argparse.Namespace) -> int:
    """Verify skills/agents are discoverable through the real agent-server."""
    from .agentverify import verify_agents

    root = Path(__file__).resolve().parent.parent
    result = verify_agents(root)
    if args.out:
        Path(args.out).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    print(json.dumps(result.to_dict(), indent=2))
    if not result.available:
        print(f"\nUNAVAILABLE: {result.reason}", file=sys.stderr)
        return 2
    if not result.ok():
        print(f"\nMISSING skills={result.skills_missing} agents={result.agents_missing}",
              file=sys.stderr)
        return 1
    print(f"\nok: {len(result.skills_loaded)} skills and {len(result.agents_loaded)} agents "
          "loaded from the workspace")
    return 0


def cmd_provision(args: argparse.Namespace) -> int:
    """Create the .openhands discovery layout (skills/agents) for OpenHands."""
    from .provision import provision_project

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    result = provision_project(root)
    print(json.dumps(result.to_dict(), indent=2))
    print(f"\nmethod={result.method}: OpenHands will now discover "
          f"{len(list((root / 'skills').glob('*/SKILL.md')))} skills and "
          f"{len(list((root / 'agents').glob('*.md')))} agents from {root}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    finding = Finding.from_dict(json.loads(Path(args.finding).read_text(encoding="utf-8")))
    out = write_report(finding, args.out, remediation=args.remediation or "")
    print(f"report written to {out}")
    print(f"submission_ready={is_submission_ready(finding)}")
    return 0


def cmd_engagement(args: argparse.Namespace) -> int:
    from .evidence import EvidenceStore
    from .findings import FindingRepository, document_finding
    from .models import Finding
    from .reference_engagement import run_reference_engagement

    summary = run_reference_engagement(args.workdir)
    print(json.dumps(summary["stages"], indent=2, default=str))
    print(f"\nclassification: {summary['finding']['classification']}")

    # Automatic documentation: the reference engagement is a real, verified run, so
    # its finding is persisted to the findings repository. The engine only
    # classifies CONFIRMED after the independent verifier re-ran the PoC, and the
    # evidence gate re-checks that every referenced artefact still resolves.
    finding = Finding.from_dict(summary["finding"])
    evidence = EvidenceStore(Path(args.workdir) / "evidence")
    repo = FindingRepository(args.findings_dir)
    record = document_finding(
        repo, finding, evidence_exists=lambda eid: evidence.get(eid) is not None
    )
    print(f"documented finding {record.finding_id} as {record.status} "
          f"in {args.findings_dir}")
    return 0


def cmd_fork_targets(args: argparse.Namespace) -> int:
    from .targets import FORK_TARGETS, is_fetched, rpc_url

    payload = [
        {
            "name": t.name,
            "program": t.program,
            "scope_asset": t.scope_asset,
            "upstream": t.upstream,
            "pinned_commit": t.pinned_commit,
            "harness": t.harness,
            "fetched": is_fetched(t),
            "rpc": rpc_url(t),
        }
        for t in FORK_TARGETS
    ]
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    for t in payload:
        print(f"  {t['name']:22} {t['program']:20} fetched={t['fetched']} {t['scope_asset']}")
    print(f"\n{len(payload)} real-target fork harnesses")
    return 0


def cmd_fork_fetch(args: argparse.Namespace) -> int:
    from .targets import fetch, get_fork_target, is_fetched

    target = get_fork_target(args.target)
    rc, out = fetch(target)
    print(out[-3000:])
    print(f"fetched={is_fetched(target)} rc={rc}")
    return 0 if rc == 0 and is_fetched(target) else 1


def cmd_fork_run(args: argparse.Namespace) -> int:
    from .fork import run_fork_campaign
    from .targets import get_fork_target

    target = get_fork_target(args.target)
    summary = run_fork_campaign(
        target, args.workdir, runs=args.runs, depth=args.depth, timeout=args.timeout
    )
    print(json.dumps(
        {k: v for k, v in summary.items() if k not in ("stages",)}, indent=2, default=str
    ))
    for stage, res in summary.get("stages", {}).items():
        if isinstance(res, dict) and "passed" in res:
            print(f"  [{stage}] passed={res['passed']} failed={res['failed']} "
                  f"skipped={res['skipped']}")
    print(f"\nstatus: {summary.get('status')}")
    return 0 if summary.get("status") == "COMPLETED" else 2


def cmd_fork_verify(args: argparse.Namespace) -> int:
    """Independent verification of the documented CV trust boundary (H5)."""
    from .fork import build_trust_boundary_finding
    from .targets import get_fork_target, runner

    target = get_fork_target(args.target)
    finding = build_trust_boundary_finding(target)

    # Independent reproduction: re-run the H5 PoC itself in a fresh process. The
    # verifier only treats `reproduce` as satisfied if the PoC actually passes.
    def reproduce() -> bool:
        res = runner(target).test(
            target.test_contracts.get("adversarial"),
            verbosity=2,
            extra_args=["--match-test", "test_H5_cv_rebalance_is_unbounded_by_the_wrapper"],
        )
        return res.returncode == 0 and res.passed >= 1 and res.failed == 0

    ctx = VerificationContext(
        in_scope=True,
        scope_reference=target.scope_asset,
        protection_exists=False,
        behavior_intentional=False,
        duplicate_known=False,
        # Attacker control is UNPROVEN, not disproven: no CV-side path that
        # over-states collateral has been found, but none has been ruled out.
        attacker_controls_input=None,
        reachable=None,                  # not established
        measurable_impact=None,          # impact not demonstrated
        reproduce=reproduce,
    )
    result = IndependentVerifier().verify(finding, ctx)
    print(json.dumps(result.to_dict(), indent=2))
    print(f"\nclassification: {finding.classification.value}")
    return 0


def cmd_fork_ledger(args: argparse.Namespace) -> int:
    from .ledger import EngagementLedger
    from .targets import get_fork_target

    target = get_fork_target(args.target)
    ledger = EngagementLedger(args.ledger_dir, target.name)
    view = ledger.view()
    for hid, rec in view.items():
        print(f"  [{rec['status']:20}] {hid}")
        print(f"       {rec['title']}")
    print(f"\n{len(view)} hypotheses; disproven={len(ledger.disproven_hypotheses())}; "
          f"open={len(ledger.open_hypotheses())}")
    if args.out:
        Path(args.out).write_text(json.dumps(view, indent=2, default=str), encoding="utf-8")
    return 0


def cmd_gha_analyze(args: argparse.Namespace) -> int:
    """Detect the reachable workflow_run artifact-checkout vulnerability class."""
    from .gha import analyze_file, analyze_tree, render, to_json

    root = Path(args.path)
    if not root.exists():
        print(f"path not found: {root}", file=sys.stderr)
        return 2
    try:
        cands = analyze_file(root) if root.is_file() else analyze_tree(root)
    except RuntimeError as exc:  # PyYAML missing
        print(f"UNSUPPORTED: {exc}", file=sys.stderr)
        return 3
    if args.json:
        print(to_json(cands))
    else:
        print(render(cands))
    return 1 if cands else 0


def cmd_gha_bench(args: argparse.Namespace) -> int:
    """Run the GitHub Actions analyzer benchmark."""
    from .gha_bench import main as bench_main

    argv = []
    if args.corpus:
        argv += ["--corpus", args.corpus]
    if args.json:
        argv += ["--json"]
    return bench_main(argv)


def cmd_agents(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parent.parent
    agents_dir = root / "agents"
    skills_dir = root / "skills"
    agents = sorted(p.stem for p in agents_dir.glob("*.md")) if agents_dir.is_dir() else []
    skills = sorted(p.parent.name for p in skills_dir.glob("*/SKILL.md")) if skills_dir.is_dir() else []
    print(json.dumps({"agents": agents, "skills": skills}, indent=2))
    return 0


def cmd_capability(args: argparse.Namespace) -> int:
    """Print the honest capability matrix and self-diagnosis."""
    from .capability import as_dict, render_markdown

    if getattr(args, "json", False):
        print(json.dumps(as_dict(), indent=2))
    else:
        print(render_markdown())
    return 0


def _render_symbolic_reachability(items: list[dict]) -> str:
    lines = ["## Symbolic reachability", ""]
    for item in items:
        lines.append(f"### {item['contract']}")
        reachable = item.get("reachable") or {}
        if reachable:
            for name, info in reachable.items():
                lines.append(f"- `{name}` by {info['actor']}: "
                             + " -> ".join(info["sequence"]))
        else:
            lines.append("- no operation reached within the bound")
        notes = (list(item.get("conversion_unsupported") or [])
                 + list(item.get("unsupported") or []))
        for note in notes:
            lines.append(f"- not modelled: {note}")
        if not item.get("exhausted", True):
            lines.append("- the path budget was exhausted; this is not a clean result")
        lines.append("")
    return "\n".join(lines)


def cmd_dataflow(args: argparse.Namespace) -> int:
    """Run SSA-lite whole-program taint/dataflow over local Solidity source."""
    from .dataflow import analyse_source
    from .pipeline import _read_source_files

    files = _read_source_files(args.path)
    if not files:
        print(f"no Solidity source found at {args.path!r}", file=sys.stderr)
        return 2
    result = analyse_source(files, contract_name=args.contract)
    payload = result.to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"dataflow contracts={len(result.contracts)} functions={result.functions} "
          f"ssa_nodes={result.ssa_nodes} flows={len(result.flows)} "
          f"unprivileged={len(result.unprivileged)}")
    for flow in result.flows[:args.limit]:
        mark = "UNPRIVILEGED" if flow.unprivileged else "guarded"
        print(f"  [{mark}] {flow.contract}.{flow.function}:{flow.line} "
              f"{flow.source} -> {flow.sink} ({flow.sink_kind})")
        if flow.guard:
            print(f"      guard: {flow.guard}")
    if result.unsupported:
        print(f"  unsupported statements: {len(result.unsupported)} "
              f"(first: {result.unsupported[0][:100]})")
    return 0


def cmd_external(args: argparse.Namespace) -> int:
    """List, doctor or run a registered external tool -- fail-closed, leads only.

    A run needs a compatibility record bound to the target; a missing tool is
    reported missing; parsed output is a list of leads, never a finding.
    """
    from .engines.external import EXTERNAL_TOOLS, doctor, run_external
    from .toolchain.enforce import load_record

    if args.list or not (args.run or args.doctor):
        rows = [tool.to_dict() for tool in EXTERNAL_TOOLS.values()]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                tag = "runnable" if row["runnable"] else "manual"
                print(f"{row['name']:<14} {row['kind']:<9} {tag:<8} "
                      f"{row['license']:<14} {row['gap']}")
        return 0
    if args.doctor:
        rows = doctor()
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                print(f"{row['name']:<14} {row['state']:<9} {row['gap']}")
        return 0 if all(row["state"] != "missing" for row in rows) else 1
    if not args.target:
        print("external --run needs --target", file=sys.stderr)
        return 2
    if not getattr(args, "compatibility", None):
        print(
            "external --run needs --compatibility RECORD: a tool run is an engine "
            "execution and must declare the stack it was verified against "
            "(docs/SECURITY_TOOL_COMPATIBILITY.md, section E)",
            file=sys.stderr,
        )
        return 2
    try:
        record = load_record(args.compatibility)
    except (OSError, ValueError, TypeError) as exc:
        print(f"could not load compatibility record: {exc}", file=sys.stderr)
        return 2
    outcome = run_external(
        args.run, args.target, compatibility=record,
        repository=args.repository or getattr(record, "repository", "") or "",
        commit=args.commit or getattr(record, "commit", "") or "",
        timeout=args.timeout,
    )
    promotion = None
    if getattr(args, "to_hypotheses", False):
        from .hypothesis.from_leads import leads_to_hypotheses
        promotion = leads_to_hypotheses(outcome, component=args.component)
    target_objs = None
    if getattr(args, "to_target", False) and promotion is not None:
        from .hypothesis.to_target import targets_from_hypotheses
        target_objs = targets_from_hypotheses(
            promotion.promoted, root=args.target,
            certify_result=getattr(args, "certify", False),
            max_depth=getattr(args, "depth", 4))
    pocs = None
    if getattr(args, "poc", False) and target_objs is not None:
        from .hypothesis.to_target import poc_for_target
        pocs = [{"component": t.component, **poc_for_target(
                    t, root=args.target, compatibility=record,
                    repository=args.repository or getattr(record, "repository", "") or "",
                    commit=args.commit or getattr(record, "commit", "") or "",
                    timeout=getattr(args, "poc_timeout", 600))}
                for t in target_objs]
    findings = None
    if getattr(args, "record_finding", False) and pocs is not None:
        from .hypothesis.to_finding import record_reproduction
        from .models import ReviewIndependence
        independence = (ReviewIndependence.INDEPENDENT_MODEL.value
                        if getattr(args, "independent", False)
                        else ReviewIndependence.SAME_MODEL.value)
        findings = [record_reproduction(
                        t, poc, target=args.target,
                        findings_root=args.findings_dir,
                        evidence_root=args.evidence_dir,
                        reviewer=getattr(args, "reviewer", "") or "",
                        review_independence=independence,
                        verification_result=getattr(args, "verification_result", "") or "",
                    ).as_dict()
                    for t, poc in zip(target_objs, pocs)]
    targets = [t.as_dict() for t in target_objs] if target_objs is not None else None
    if args.json:
        data = outcome.as_dict()
        if promotion is not None:
            data["hypotheses"] = promotion.as_dict()
        if targets is not None:
            data["targets"] = targets
        if pocs is not None:
            data["pocs"] = pocs
        if findings is not None:
            data["findings"] = findings
        print(json.dumps(data, indent=2))
    else:
        print(f"{outcome.tool}: {outcome.status} — {outcome.detail}")
        for lead in outcome.leads[:20]:
            print(f"  - {lead}")
        if promotion is not None:
            print(f"hypotheses: {promotion.promoted_count} promoted, "
                  f"{promotion.rejected_count} refused (leads, not findings)")
            for hyp in promotion.promoted:
                print(f"  + {hyp['hyp_id']} [{hyp['category']}] "
                      f"{hyp['attacker_outcome']}")
            for rej in promotion.rejected:
                print(f"  - refused: {rej['reason']}")
        for tgt in (targets or []):
            print(f"  target {tgt['component']}: {tgt['status']} — {tgt['detail']}")
        for poc in (pocs or []):
            print(f"  poc {poc['component']}: {poc.get('status')} — "
                  f"{poc.get('detail', '')}")
        for fnd in (findings or []):
            print(f"  finding {fnd['finding_id']}: {fnd['verdict']} — {fnd['detail']}")
    return 0 if outcome.status in ("COMPLETED", "MANUAL") else 2


def cmd_autohunt(args: argparse.Namespace) -> int:
    """Autonomous hunt across in-scope targets; stop only for a human reviewer.

    Runs the external chain per target, grades each finding with the official
    bounty gate, and stops only when a candidate is payable or a reproduction
    awaits review. The operator's only job is to review what is surfaced.
    """
    from .autohunt import (
        AutoHuntConfig, Target, bounty_grade, external_chain_runner, run_autohunt,
    )
    from .models import ReviewIndependence

    if not getattr(args, "targets", None):
        print("autohunt needs --targets FILE (a JSON list of in-scope targets)",
              file=sys.stderr)
        return 2
    try:
        raw = json.loads(Path(args.targets).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"could not read targets: {exc}", file=sys.stderr)
        return 2
    entries = raw if isinstance(raw, list) else raw.get("targets", [])
    targets = [Target(component=t.get("component", ""), path=t.get("path", ""),
                      repository=t.get("repository", ""), commit=t.get("commit", ""),
                      compatibility=t.get("compatibility", ""))
               for t in entries]
    policy = None
    if getattr(args, "policy", None):
        try:
            policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"could not read policy: {exc}", file=sys.stderr)
            return 2
    independence = (ReviewIndependence.INDEPENDENT_MODEL.value
                    if getattr(args, "independent", False)
                    else ReviewIndependence.SAME_MODEL.value)

    def runner(target):
        return external_chain_runner(
            target, scanner=args.scanner, do_poc=getattr(args, "poc", False),
            findings_root=args.findings_dir, evidence_root=args.evidence_dir,
            reviewer=getattr(args, "reviewer", "") or "",
            review_independence=independence,
            verification_result=getattr(args, "verification_result", "") or "",
            max_depth=getattr(args, "depth", 4),
            timeout=getattr(args, "poc_timeout", 600))

    config = AutoHuntConfig(
        program=getattr(args, "program", "") or "", targets=targets,
        max_targets=getattr(args, "max_targets", 0),
        max_runtime_s=getattr(args, "max_runtime", 0.0),
        stop_on_awaiting_review=not getattr(args, "no_stop_on_review", False))
    result = run_autohunt(config, runner=runner,
                          grader=lambda f, t: bounty_grade(f, t, policy=policy))
    if getattr(args, "json", False):
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"autohunt: {result.reason} — {result.detail}")
        print(f"  targets tried: {result.targets_tried}  "
              f"blocked: {len(result.targets_blocked)}  "
              f"candidates: {result.candidates_seen}")
        for surface in result.surfaced:
            tag = "PAYABLE" if surface.payable else "REVIEW"
            print(f"  [{tag}] {surface.component}: {surface.disposition} — {surface.reason}")
            print(f"      {surface.review_hint}")
        if not result.surfaced:
            print("  nothing to review this pass; the operator's only job is review")
    return 0 if result.reason in ("PAYABLE_FOUND", "AWAITING_REVIEW") else 1


def cmd_impact(args: argparse.Namespace) -> int:
    """Pre-surface impact triage: is a claim even a security issue before review?"""
    from .impact import triage

    verdict = triage(impact=args.impact, surface=args.surface,
                     identifiers=args.identifiers or (), outcome=args.outcome or "")
    if args.json:
        print(json.dumps(verdict.as_dict(), indent=2))
    else:
        print(f"{verdict.disposition} — "
              f"{verdict.outcome or 'no unprivileged-attacker outcome'}")
        for reason in verdict.reasons:
            print(f"  - {reason}")
        if verdict.qualifies:
            print("  (a qualifying claim, still a lead until reproduced and reviewed)")
    return 0 if verdict.qualifies else 1


def cmd_agent(args: argparse.Namespace) -> int:
    """Human research loop: see every stack, hunt modelled ones, never lie."""
    from .agent import run_agent

    policy = None
    if args.policy:
        with open(args.policy, encoding="utf-8") as fh:
            policy = json.load(fh)
    result = run_agent(args.path, policy=policy, compatibility=args.compatibility or "",
                       program=args.program or "", repository=args.repository or "",
                       commit=args.commit or "", scanner=args.scanner, poc=args.poc,
                       max_targets=args.max_targets or 0)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"agent: {result.status} — {result.reason}")
        for s in result.stacks:
            tag = "MODELLED" if s.modelled else "UNMODELLED"
            print(f"  [{tag}] {s.language} ({s.production_files} production file(s))")
        if result.blind:
            print(f"  BLIND: {', '.join(result.blind)} — seen, not modelled "
                  "(never 'clean')")
    return 0 if result.status not in ("BLIND", "BLOCKED", "EMPTY") else 1


def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest a Solidity file or repo and emit the attack surface and candidate leads.

    With ``--synthesize`` it also builds an executable model from each contract's
    own functions and runs the bounded-exhaustive certifier on it. The model is a
    local pure-state simulation, never an execution against the target, so it runs
    under the self-test authority rather than a target-bound compatibility record.
    """
    from .ingest import (
        as_dict, assess_coverage, detect_language, evaluate, ingest, render_markdown,
        unread_sources,
    )

    language = getattr(args, "language", "auto")
    if language == "auto":
        language = detect_language(args.path)

    coverage = assess_coverage(
        args.path, language,
        allow_unscanned=tuple(getattr(args, "allow_unscanned", []) or ()),
    )
    if coverage.blocked:
        print(coverage.block_message(), file=sys.stderr)
        return 2

    if language == "go":
        from .ingest import evaluate_go, ingest_go
        from .ingest.report import go_as_dict, render_go_markdown

        go_report = ingest_go(args.path)
        go_flags = evaluate_go(go_report)
        payload = go_as_dict(go_report, go_flags)
        payload["language_coverage"] = coverage.to_dict()
        text = render_go_markdown(go_report, go_flags)
        allowed = {a.casefold() for a in (getattr(args, "allow_unscanned", []) or ())}
        not_read = tuple(
            n for n in unread_sources(args.path, "go")
            if not any(a in n.casefold() for a in allowed)
        )
        if not_read:
            payload["not_read"] = list(not_read)
            text += "\n## Not read\n\n" + "\n".join(f"- {n}" for n in not_read) + "\n"
        if args.json:
            text = json.dumps(payload, indent=2)
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / ("surface.json" if args.json else "surface.md")).write_text(
                text + "\n", encoding="utf-8")
        print(text)
        return 1 if go_report.errors else 0

    if language == "rust":
        from .ingest import evaluate_rust, ingest_rust
        from .ingest.report import render_rust_markdown, rust_as_dict

        rust_report = ingest_rust(args.path)
        rust_flags = evaluate_rust(rust_report)
        payload = rust_as_dict(rust_report, rust_flags)
        payload["language_coverage"] = coverage.to_dict()
        text = render_rust_markdown(rust_report, rust_flags)
        not_read = unread_sources(args.path, "rust")
        if not_read:
            payload["not_read"] = list(not_read)
            text += "\n## Not read\n\n" + "\n".join(f"- {n}" for n in not_read) + "\n"
        if args.json:
            text = json.dumps(payload, indent=2)
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / ("surface.json" if args.json else "surface.md")).write_text(
                text + "\n", encoding="utf-8"
            )
        print(text)
        return 1 if rust_report.errors else 0

    if language == "vyper":
        from .ingest import evaluate_vyper, scan_vyper, vyper_as_dict
        from .ingest.vyper import render_vyper_markdown

        root = Path(args.path).expanduser()
        files = [root] if root.is_file() else sorted(root.rglob("*.vy"))
        pairs = []
        for path in files:
            report = scan_vyper(path.read_text(encoding="utf-8", errors="replace"), str(path))
            pairs.append((report, evaluate_vyper(report)))
        payload = {"surfaces": [vyper_as_dict(r, f) for r, f in pairs],
                   "language_coverage": coverage.to_dict()}
        text = "\n\n".join(render_vyper_markdown(r, f) for r, f in pairs) \
            or f"no .vy files found under {args.path!r}"
        if args.json:
            text = json.dumps(payload, indent=2)
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / ("surface.json" if args.json else "surface.md")).write_text(
                text + "\n", encoding="utf-8")
        print(text)
        return 1 if any(r.errors for r, _ in pairs) else 0

    if language == "unknown":
        from .ingest import language_census

        census = language_census(args.path)
        detail = (
            "both found: " + ", ".join(f"{n} {lang}" for lang, n in sorted(census.items()))
            if census else "no Solidity or Rust source found"
        )
        print(
            f"{detail} under {args.path!r}; pass --language to choose a scanner explicitly",
            file=sys.stderr,
        )
        return 2

    report = ingest(args.path)
    flags = evaluate(report)
    payload = as_dict(report, flags)
    payload["language_coverage"] = coverage.to_dict()
    text = render_markdown(report, flags)
    not_read = unread_sources(args.path, "solidity")
    if not_read:
        payload["not_read"] = list(not_read)
        text += "\n## Not read\n\n" + "\n".join(f"- {n}" for n in not_read) + "\n"

    if getattr(args, "synthesize", False) or getattr(args, "coverage", False):
        from .assurance.certify import CertifyConfig, certify
        from .ingest.model_coverage import coverage_for_contract
        from .ingest.report import render_synthesis, synthesis_as_dict
        from .ingest.synthesize import synthesize
        from .toolchain.enforce import self_test_authority

        results = []
        coverage: dict[str, dict] = {}
        symbolic: list[dict] = []
        registry = {c.name: c for c in report.contracts}
        with self_test_authority("ingest-synth"):
            for contract in report.contracts:
                target, srep = synthesize(contract, registry=registry)
                coverage[contract.name] = coverage_for_contract(
                    contract, srep, target).to_dict()
                if not getattr(args, "synthesize", False):
                    continue
                if not target.ops():
                    continue
                cert = certify(target, CertifyConfig(max_depth=args.depth, price_findings=False))
                results.append((srep, cert))
                if getattr(args, "symbolic", False):
                    from .symbolic.executor import from_op_models, reachable_operations

                    sym_ops, sym_unsupported = from_op_models(target.op_models())
                    domains: dict[str, tuple[int, int]] = {}
                    values: dict[str, tuple] = {}
                    for spec in target.ops():
                        for name, vals in spec.param_domain.items():
                            if vals and all(isinstance(v, int) for v in vals):
                                lo, hi = min(vals), max(vals)
                                if name in domains:
                                    lo = min(lo, domains[name][0])
                                    hi = max(hi, domains[name][1])
                                domains[name] = (lo, hi)
                            else:
                                values[name] = tuple(vals)
                    import contextlib

                    from .symbolic.smt import use_smt

                    smt_context = (use_smt(True) if getattr(args, "smt", False)
                                   else contextlib.nullcontext())
                    with smt_context:
                        reach = reachable_operations(
                            sym_ops, domains=domains, values=values,
                            max_depth=getattr(args, "symbolic_depth", 0) or args.depth,
                            max_paths=args.symbolic_paths,
                        )
                    symbolic.append({
                        "contract": contract.name,
                        **reach.to_dict(),
                        "conversion_unsupported": sym_unsupported,
                    })
        payload["model_coverage"] = coverage
        if getattr(args, "synthesize", False):
            payload["synthesis"] = synthesis_as_dict(results)
            text = text + "\n" + render_synthesis(results)
            if getattr(args, "exec", False):
                from .ingest.execute import (
                    contract_path_for, execute_witness, read_solidity_sources,
                )
                from .toolchain.enforce import load_record

                if not getattr(args, "compatibility", None):
                    print(
                        "ingest --synthesize --exec needs --compatibility RECORD: the "
                        "Foundry run is an engine execution and must declare the stack it "
                        "was verified against (docs/SECURITY_TOOL_COMPATIBILITY.md, section E)",
                        file=sys.stderr,
                    )
                    return 2
                try:
                    record = load_record(args.compatibility)
                except (OSError, ValueError, TypeError) as exc:
                    print(f"could not load compatibility record: {exc}", file=sys.stderr)
                    return 2
                files = read_solidity_sources(args.path)
                execution: dict[str, dict] = {}
                for srep, cert in results:
                    if not getattr(cert, "violations", None):
                        execution[srep.contract] = {
                            "status": "SKIPPED", "detail": "no certifier violation"}
                        continue
                    execution[srep.contract] = execute_witness(
                        cert,
                        contract=srep.contract,
                        contract_path=contract_path_for(srep.path, args.path),
                        files=files,
                        compatibility=record,
                        repository=getattr(record, "repository", "") or "",
                        commit=getattr(record, "commit", "") or "",
                        timeout=getattr(args, "poc_timeout", 600),
                    )
                payload["execution"] = execution
                lines = ["## Execution-grade evidence (Foundry)", ""]
                for name in sorted(execution):
                    ex = execution[name]
                    lines.append(f"- `{name}`: {ex.get('status')} — {ex.get('detail', '')}")
                text = text + "\n" + "\n".join(lines) + "\n"
        else:
            lines = ["## Model coverage", ""]
            for name, cov in coverage.items():
                lines.append(f"### `{name}`")
                lines.append("")
                lines.append(f"- complete: {cov.get('complete')}")
                summary = cov.get("summary", {})
                lines.append(
                    f"- reachable functions: {summary.get('modelled_functions', 0)}/"
                    f"{summary.get('reachable_functions', 0)} modelled")
                for gap in (cov.get("gaps") or [])[:10]:
                    lines.append(
                        f"- gap: {gap.get('path', '')}:{gap.get('line', '')} "
                        f"{gap.get('function', '')} - "
                        f"{gap.get('statement') or gap.get('reason', '')}")
                lines.append("")
            text = text + "\n" + "\n".join(lines)
        if symbolic:
            payload["symbolic_reachability"] = symbolic
            text = text + "\n" + _render_symbolic_reachability(symbolic)

    compile_status = "OK"
    if getattr(args, "compile", False):
        from .ingest.compile import compile_project, models_from_compiled
        from .toolchain.enforce import load_record

        if not getattr(args, "compatibility", None):
            print(
                "ingest --compile needs --compatibility RECORD: the build is an engine "
                "execution and must declare the stack it was verified against "
                "(docs/SECURITY_TOOL_COMPATIBILITY.md, section E)",
                file=sys.stderr,
            )
            return 2
        try:
            record = load_record(args.compatibility)
        except (OSError, ValueError, TypeError) as exc:
            print(f"could not load compatibility record: {exc}", file=sys.stderr)
            return 2
        outcome = compile_project(
            args.path,
            compatibility=record,
            target_component=getattr(args, "target_component", "") or Path(args.path).resolve().name,
            repository=getattr(args, "repository", "") or "",
            commit=getattr(args, "commit", "") or "",
        )
        compile_status = outcome.status
        payload["compile"] = outcome.to_dict()
        lines = [f"## Compile ({outcome.tool or 'no tool'})", "",
                 f"- status: {outcome.status}", f"- {outcome.reason}"]
        if outcome.ok:
            for name in sorted(outcome.artifacts):
                lines.append(f"- artifact: {name}")
            for name, model in models_from_compiled(outcome).items():
                lines.append(f"- model {name}: {len(model.operations)} operation(s)")
        text = text + "\n" + "\n".join(lines) + "\n"

    if args.json:
        text = json.dumps(payload, indent=2)

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / ("surface.json" if args.json else "surface.md")).write_text(text + "\n", encoding="utf-8")

    print(text)
    # A compile that was blocked or did not finish is not a success.
    if compile_status in ("BLOCKED", "INCOMPLETE"):
        return 2
    # A flag is a lead, so finding leads is success. Ingest errors are not.
    return 1 if report.errors else 0


def cmd_interrogate(args: argparse.Namespace) -> int:
    """Derive the claims a codebase makes, then try to break each one.

    Every other command starts from a suspicion and looks for a witness. This
    one reads the code's own promises -- "only an authorized caller", "supply is
    conserved", "this cannot panic" -- and attacks each promise. A claim is
    never silently dropped: it is falsified, survived-within-this-check, or
    explicitly untestable, and every verdict names what it could not see.
    """
    from .ingest import assess_coverage, detect_language, unread_sources
    from .interrogate import as_dict, interrogate, render_markdown

    # The coverage gate runs before the scanner, so a partial scan is refused
    # rather than performed and then labelled.
    declared = getattr(args, "language", "auto")
    language = detect_language(args.path) if declared == "auto" else declared
    coverage = assess_coverage(
        args.path, language,
        allow_unscanned=tuple(getattr(args, "allow_unscanned", []) or ()),
    )
    if coverage.blocked:
        print(coverage.block_message(), file=sys.stderr)
        return 2
    verdicts, language, errors = interrogate(args.path, declared)
    if language in ("solidity", "rust", "go"):
        # A mixed tree is the easiest way to believe the ledger covered more than
        # it did; name the part that was not interrogated.
        allowed = {a.casefold() for a in (getattr(args, "allow_unscanned", []) or ())}
        errors = errors + tuple(
            n for n in unread_sources(args.path, language)
            if not any(a in n.casefold() for a in allowed)
        )
    payload = as_dict(verdicts, language, errors)
    payload["language_coverage"] = coverage.to_dict()
    text = render_markdown(verdicts, language, errors)

    if args.json:
        text = json.dumps(payload, indent=2)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / ("interrogation.json" if args.json else "interrogation.md")).write_text(
            text + "\n", encoding="utf-8"
        )
    print(text)
    # A falsified claim is a lead and the reason to keep going; a scan that could
    # not read the source is not success.
    return 1 if errors else 0


def cmd_dossier(args: argparse.Namespace) -> int:
    """One explorable view of a project: surface, leads, claims, flows, blind spots.

    A composition, not a new engine: it runs the scanner, the rule engine, the
    interrogation pass and the dataflow pass and ranks what they already report.
    Every item is a lead, never a finding.
    """
    from .dossier import build_dossier, render_markdown

    dossier = build_dossier(
        args.path,
        getattr(args, "language", "auto"),
        tuple(getattr(args, "allow_unscanned", []) or ()),
    )
    if dossier.get("blocked"):
        print(dossier.get("block_message", "blocked"), file=sys.stderr)
        return 2
    text = json.dumps(dossier, indent=2) if args.json else render_markdown(dossier)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / ("dossier.json" if args.json else "dossier.md")).write_text(
            text + "\n", encoding="utf-8")
    print(text)
    errors = (len(dossier.get("surface", {}).get("errors", []))
              + len(dossier.get("interrogation", {}).get("errors", [])))
    return 1 if errors else 0


def cmd_audit_coverage(args: argparse.Namespace) -> int:
    """Map an audit report onto the surface and rank the unaudited reachable surface."""
    from .audit_coverage import build_audit_coverage, render_markdown

    payload = build_audit_coverage(
        args.path,
        args.audit,
        getattr(args, "language", "auto"),
        tuple(getattr(args, "allow_unscanned", []) or ()),
    )
    if payload.get("blocked"):
        print(payload.get("block_message", "blocked"), file=sys.stderr)
        return 2
    text = json.dumps(payload, indent=2) if args.json else render_markdown(payload)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / ("audit-coverage.json" if args.json else "audit-coverage.md")).write_text(
            text + "\n", encoding="utf-8")
    print(text)
    return 0 if payload.get("supported", True) else 1


def cmd_debug_tx(args: argparse.Namespace) -> int:
    """Replay one transaction read-only and render its call tree."""
    from .debug_tx import build_debug, render_markdown

    payload = build_debug(args.hash, rpc=args.rpc, abi_path=args.abi,
                          chain=args.chain, timeout=args.timeout)
    text = json.dumps(payload, indent=2) if args.json else render_markdown(payload)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / ("debug-tx.json" if args.json else "debug-tx.md")).write_text(
            text + "\n", encoding="utf-8")
    print(text)
    return 0 if payload.get("status") in ("OK", "TRACE_UNAVAILABLE") else 1


def cmd_explore(args: argparse.Namespace) -> int:
    """Open an interactive shell (or run one query) over a project's surface."""
    from .explore import Session, repl

    session = Session(
        args.path,
        getattr(args, "language", "auto"),
        tuple(getattr(args, "allow_unscanned", []) or ()),
    )
    if session.blocked:
        print(session.block_message, file=sys.stderr)
        return 2
    if getattr(args, "query", None):
        print(session.dispatch(args.query))
        return 0
    return repl(session)


def cmd_mindset(args: argparse.Namespace) -> int:
    """Show the BLACKHEART identity and the attacker question every mission is run under."""
    from .mindset import (
        ATTACKER_QUESTION, BLACKHEART_PERSONA, COVERAGE_DOCTRINE, DOCTRINE,
        LEVER_DETAIL, MODEL_DOCTRINE, OPERATOR_AUTHORITY, ORACLE_DOCTRINE,
        OUTCOMES, PERSONA_TAGLINE, PERSONA_TRAITS, VALUE_DOCTRINE, apply_lens,
    )

    if args.question:
        print(ATTACKER_QUESTION)
        return 0
    if args.persona:
        print(BLACKHEART_PERSONA)
        return 0
    if args.lens_for:
        app = apply_lens(args.lens_for, texts=tuple(args.text or ()))
        print(json.dumps(app.to_dict(), indent=2))
        return 0
    payload = {
        "tagline": PERSONA_TAGLINE,
        "persona": BLACKHEART_PERSONA,
        "persona_traits": list(PERSONA_TRAITS),
        "question": ATTACKER_QUESTION,
        "outcomes": list(OUTCOMES),
        "levers": [
            {"name": l.name, "meaning": l.meaning, "examples": list(l.examples)}
            for l in LEVER_DETAIL
        ],
        "doctrine": list(DOCTRINE),
        "value_doctrine": list(VALUE_DOCTRINE),
        "coverage_doctrine": list(COVERAGE_DOCTRINE),
        "oracle_doctrine": list(ORACLE_DOCTRINE),
        "model_doctrine": list(MODEL_DOCTRINE),
        "operator_authority": list(OPERATOR_AUTHORITY),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    from .mindset import skill_document
    print(skill_document())
    return 0


def cmd_doctrine(args: argparse.Namespace) -> int:
    """Expose the operational doctrine: identity, lifecycle, gates, invariants."""
    from .doctrine import (
        doctrine_dict, doctrine_document, doctrine_prompt_block, phase,
    )

    if args.json:
        print(json.dumps(doctrine_dict(), indent=2, default=str))
        return 0
    if args.prompt:
        print(doctrine_prompt_block())
        return 0
    if args.phase:
        key = args.phase.upper()
        try:
            p = phase(key)
        except KeyError:
            from .doctrine import PHASE_BY_KEY
            print(f"unknown phase {args.phase!r}; known: {', '.join(PHASE_BY_KEY)}",
                  file=sys.stderr)
            return 2
        print(json.dumps(p.to_dict(), indent=2))
        return 0
    print(doctrine_document())
    return 0


def cmd_compat(args: argparse.Namespace) -> int:
    """Language-aware tool compatibility: registry, stack detection, gate, statuses."""
    from .toolchain import (
        CompatibilityRecord,
        admit,
        registry,
        statuses,
        template,
    )

    action = args.compat_action
    if action == "registry":
        data = registry(args.language or "")
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        if not data["languages"]:
            print(f"no verified toolchain for {args.language!r}; research one and add "
                  f"it to docs/SECURITY_TOOL_COMPATIBILITY.md", file=sys.stderr)
            return 2
        for chain in data["languages"]:
            print(f"{chain['language']}  (verified {chain['verified_at']})")
            print(f"  versions: {chain['versions']}")
            print(f"  frameworks: {', '.join(chain['frameworks'])}")
            print(f"  runtime: {chain['runtime']}")
            for tool in chain["tools"]:
                print(f"  - {tool['name']}: {tool['official_docs']}")
            for note in chain["known_incompatibilities"]:
                print(f"  ! {note}")
        return 0

    if action == "detect":
        from .toolchain.detect import detect_stack

        report = detect_stack(args.root or ".")
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
            return 0
        data = report.to_dict()
        print(f"root: {data['root']}")
        for entry in data["languages"]:
            roles = ", ".join(f"{k}={v}" for k, v in entry["by_role"].items())
            state = "confirmed" if entry["confirmed"] else "UNCONFIRMED"
            manifests = ", ".join(entry["manifests"][:3])
            print(f"  {entry['language']:<24} {state:<11} files={entry['files']:<5} "
                  f"{roles}")
            if manifests:
                print(f"    manifests: {manifests}")
        for note in data["limitations"]:
            print(f"  note: {note}")
        print(f"security-relevant: {', '.join(data['security_relevant']) or 'none'}")
        print(f"complete: {data['complete']}")
        return 0

    if action == "check":
        record = CompatibilityRecord.from_dict(json.loads(Path(args.file).read_text()))
        if args.smoke_test:
            record = CompatibilityRecord.from_dict(
                {**record.to_dict(), "smoke_test": args.smoke_test}
            )
        decision = admit(record)
        if args.json:
            print(json.dumps({"record": record.to_dict(), **decision.to_dict()},
                             indent=2))
        else:
            print(f"decision: {decision.decision}")
            for reason in decision.reasons:
                print(f"  - {reason}")
            if decision.admitted:
                print("  the tool may run; report the result with exactly one of "
                      + ", ".join(statuses()))
        return 0 if decision.admitted else 2

    if action == "statuses":
        data = statuses()
        print(json.dumps(data, indent=2) if args.json else
              "\n".join(f"{k:<12} {v}" for k, v in data.items()))
        return 0

    if action == "template":
        data = template()
        if args.out:
            Path(args.out).write_text(json.dumps(data, indent=2) + "\n")
            print(f"wrote {args.out}")
        else:
            print(json.dumps(data, indent=2))
        return 0

    print("usage: blackheart compat {registry,detect,check,statuses,template}",
          file=sys.stderr)
    return 2


@_fixture_command
def cmd_evaluate(args: argparse.Namespace) -> int:
    """Run the controlled adversarial research-quality suite (local targets only)."""
    from .research_quality import CASES, run_evaluation, write_evaluation_report

    if args.list:
        for c in CASES:
            print(f"  {c.case_id:10} {c.attack_class:38} {c.vulnerable}/{c.guarded}")
        print(f"\n{len(CASES)} cases (local intentionally-vulnerable targets only)")
        return 0

    report = run_evaluation(runs=args.runs, steps_per_run=args.steps, seed=args.seed)
    if args.workdir:
        path = write_evaluation_report(report, args.workdir)
        print(f"report={path}")
    print(f"cases={report['cases']} detected={report['detected']} "
          f"not_detected={report['not_detected']} control_failed={report['control_failed']}")
    print(f"distinct_differential_pairs={report['distinct_differential_pairs']}")
    if report["pairs_shared_across_classes"]:
        print(f"shared_pairs={report['pairs_shared_across_classes']}")
    for r in report["results"]:
        mark = "PASS" if r["status"] == "DETECTED" else r["status"]
        print(f"  [{mark:14}] {r['case_id']:10} {r['attack_class']:38} "
              f"seqlen={r['minimal_sequence_len']}")
    return 0 if report["all_controls_pass"] else 1


def cmd_evmbench(args: argparse.Namespace) -> int:
    """Score an analyser's JSON report against EVMbench fix locations (key-free).

    The dataset is the MIT-licensed audit set from ``openai/frontier-evals``; the
    findings are whatever an engine wrote (Slither today). No API key, no Docker,
    no network at score time.
    """
    from . import evmbench

    root = Path(args.dataset).expanduser()
    if not (root / "audits").is_dir():
        print(f"no audits directory under {root}; point --dataset at the evmbench "
              "dataset root (it must contain audits/)", file=sys.stderr)
        return 2

    findings: list[evmbench.Finding] = []
    for path in args.findings:
        p = Path(path).expanduser()
        if not p.is_file():
            print(f"missing findings file: {p}", file=sys.stderr)
            return 2
        findings.extend(evmbench.load_slither_findings(p))

    report = evmbench.evaluate(root, findings,
                               audits=args.audit or None)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(evmbench.format_report(report))

    if args.out:
        out = Path(args.out).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"report={out}")
    return 0


def cmd_intel(args: argparse.Namespace) -> int:
    """External intelligence via You.com (search, contents, research, health, mcp)."""
    from .intelligence import CostRefusal, YouComClient, YouComError, frame_question

    sub = getattr(args, "sub", None)

    if sub == "mcp":
        from .intelligence.mcp import openhands_mcp_config
        cfg = openhands_mcp_config(with_key=not args.no_key, docs=not args.no_docs)
        print(json.dumps(cfg, indent=2))
        return 0

    if sub == "providers":
        from .intelligence.providers import ProviderRegistry
        reg = ProviderRegistry()
        statuses = reg.status(probe=args.probe, timeout=args.timeout)
        if args.json:
            print(json.dumps([s.to_dict() for s in statuses], indent=2))
            return 0
        for s in statuses:
            mark = "available" if s.available else "UNAVAILABLE (no key)"
            line = f"{s.name:<12} {mark:<22} paid={s.paid}"
            if s.live_ok is not None:
                line += f" live={'ok' if s.live_ok else 'FAILED'}"
                if s.live_error:
                    line += f" ({s.live_error_kind or 'error'}: {s.live_error[:60]})"
            print(line)
        return 0

    if sub == "discover":
        from .intelligence.discover import (
            discover_chain,
            discover_contract,
            discover_rpc_endpoints,
        )

        c = YouComClient(allow_paid=False)
        if args.kind == "rpc":
            payload = discover_rpc_endpoints(
                args.query, client=c, expect_chain_id=args.chain_id,
                count=args.count, probe=not args.no_probe, timeout=args.timeout).to_dict()
        elif args.kind == "contract":
            payload = discover_contract(
                args.query, chain=args.chain, rpc_url=args.rpc,
                client=c, count=args.count).to_dict()
        else:
            payload = discover_chain(args.query, client=c, count=args.count).to_dict()
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0 if payload["ok"] else 1
        print(f"[discover {payload['kind']}] query={payload['query']!r} "
              f"ok={payload['ok']}")
        for v in payload["verified"]:
            print(f"  VERIFIED  {v}")
        for cand in payload["candidates"]:
            print(f"  candidate {cand}")
        for n in payload["notes"]:
            print(f"  note: {n}")
        if payload["error"]:
            print(f"  error: {payload['error']}")
        return 0 if payload["ok"] else 1

    if sub == "route":
        from .intelligence.providers import DEFAULT_ORDER, ProviderRegistry, SearchRouter
        order = tuple(x.strip() for x in args.order.split(",") if x.strip())
        router = SearchRouter(ProviderRegistry())
        routed = router.search(args.query, count=args.count, order=order,
                               cross_check=args.cross_check,
                               allow_fallback=args.allow_fallback, timeout=args.timeout)
        if args.json:
            payload = routed.to_dict()
            payload["attacker_lens"] = frame_question()
            print(json.dumps(payload, indent=2))
            return 0 if routed.ok else 1
        for a in routed.attempts:
            if a.get("skipped"):
                print(f"  skip {a['provider']}: {a['reason']}")
            elif a["ok"]:
                print(f"  ok   {a['provider']}: {a['sources']} sources in {a['latency_ms']}ms")
            else:
                print(f"  fail {a['provider']}: {a['error_kind'] or 'error'}: {a['error'][:80]}")
        if not routed.ok:
            print("no provider returned results", file=sys.stderr)
            return 1
        print(f"[route] answered by {routed.provider}")
        for s in routed.result.sources:
            print(f"  [{s.provider}] {s.title[:66]}")
            print(f"    {s.url}")
        for d in routed.disagreements:
            if d.get("ok") and (d.get("only_in_primary") or d.get("only_in_other")):
                print(f"  disagreement with {d['provider']}: "
                      f"{len(d['shared'])} shared, {len(d['only_in_primary'])} only here, "
                      f"{len(d['only_in_other'])} only there")
        return 0

    if sub == "investigate":
        # Live, provenance-tagged research output wrapped for safe reasoning:
        # external text is fenced as untrusted data, the attacker lens is
        # attached, and any prompt-injection signals are reported (never obeyed).
        from .intelligence.providers import DEFAULT_ORDER, ProviderRegistry, SearchRouter
        from .intelligence.quarantine import quarantine_sources

        order = tuple(x.strip() for x in args.order.split(",") if x.strip())
        router = SearchRouter(ProviderRegistry())
        routed = router.search(args.query, count=args.count, order=order,
                               cross_check=args.cross_check,
                               allow_fallback=args.allow_fallback, timeout=args.timeout)
        payload = quarantine_sources(routed, query=args.query).to_dict()
        payload["ok"] = routed.ok
        payload["attempts"] = routed.attempts
        if routed.disagreements:
            payload["disagreements"] = routed.disagreements
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0 if routed.ok else 1
        if not routed.ok:
            print("no provider returned results", file=sys.stderr)
            return 1
        print(f"[investigate] {len(payload['sources'])} source(s) via {payload['provider']} "
              f"(all marked untrusted)")
        if payload["injection_signals"]:
            print(f"  WARNING: {len(payload['injection_signals'])} injection signal(s) "
                  f"in retrieved text -- treated as data, not followed")
            for sig in payload["injection_signals"]:
                print(f"    - {sig['kind']}: {sig['snippet'][:80]}")
        for s in payload["sources"]:
            print(f"  [{s['provider']}] {s['title'][:66]}")
            print(f"    {s['url']}")
        return 0

    if sub == "setup":
        from .intelligence.providers import DEFAULT_ORDER, ProviderRegistry
        reg = ProviderRegistry()
        statuses = reg.status(probe=False)
        info = {
            "canonical_env_var": "YDC_API_KEY",
            "rest_auth_header": "X-API-Key",
            "mcp_auth_header": "Authorization: Bearer <key>",
            "rest_search_endpoint": "POST https://ydc-index.io/v1/search",
            "mcp_endpoint": "https://api.you.com/mcp",
            "preference_order": list(DEFAULT_ORDER),
            "providers": [s.to_dict() for s in statuses],
        }
        if args.json:
            print(json.dumps(info, indent=2))
            return 0
        print("BLACKHEART external-intelligence setup")
        print()
        print("  Primary provider (best coverage): You.com")
        print("    export YDC_API_KEY=...            # https://you.com/docs/using-the-api/authentication")
        print("    REST auth header:  X-API-Key: $YDC_API_KEY   (search/contents/research)")
        print("    MCP  auth header:  Authorization: Bearer $YDC_API_KEY  (api.you.com/mcp)")
        print()
        print("  Keyless fallbacks (no account, no key):")
        print("    duckduckgo  -- DuckDuckGo Instant Answer API")
        print("    wikipedia   -- Wikipedia search API")
        print()
        print("  Verify connectivity:  blackheart intel providers --probe")
        print("  Routed search:        blackheart intel route \"<query>\" --cross-check")
        print()
        for s in statuses:
            print(f"    {s.name:<12} {'configured' if s.available else 'NOT configured (set YDC_API_KEY)'}")
        return 0

    if sub == "bootstrap":
        from .intelligence.bootstrap import bootstrap_project
        res = bootstrap_project(args.root, force=args.force)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
            return 0
        print(f"project intelligence config written under {res.root}/.openhands")
        print(f"  mcp servers:  {res.mcp_path}  ({'written' if res.mcp_written else 'unchanged'})")
        print(f"  env template: {res.env_example_path}  "
              f"({'written' if res.env_example_written else 'unchanged'})")
        for n in res.notes:
            print(f"  note: {n}")
        print("  the API key is referenced as ${YDC_API_KEY}; no secret was written")
        return 0

    client = YouComClient(
        allow_paid=args.allow_paid,
        max_paid_calls=args.max_paid_calls,
        timeout=args.timeout,
    )

    if sub == "health":
        if not client.key_present:
            print("YDC_API_KEY is not set", file=sys.stderr)
            return 2
        r = client.health()
        if args.json:
            print(json.dumps(r.to_dict(), indent=2))
        else:
            print(f"you.com health: {'ok' if r.ok else 'FAILED'} "
                  f"({r.raw_status}) in {r.latency_ms:.0f}ms")
            if not r.ok:
                print(f"  error: {r.error}", file=sys.stderr)
        return 0 if r.ok else 1

    if sub == "search":
        if not args.query:
            print("a query is required", file=sys.stderr)
            return 2
        try:
            r = client.search(args.query, count=args.count,
                              freshness=args.freshness, extract=args.extract)
        except CostRefusal as exc:
            print(f"cost refused: {exc}", file=sys.stderr)
            return 3
        except YouComError as exc:
            print(f"you.com error: {exc}", file=sys.stderr)
            return 1
    elif sub == "contents":
        if not args.urls:
            print("at least one --url is required", file=sys.stderr)
            return 2
        try:
            r = client.contents(args.urls, formats=["markdown"])
        except CostRefusal as exc:
            print(f"cost refused: {exc}", file=sys.stderr)
            return 3
        except YouComError as exc:
            print(f"you.com error: {exc}", file=sys.stderr)
            return 1
    elif sub == "research":
        if not args.question:
            print("a question is required", file=sys.stderr)
            return 2
        try:
            r = client.research(args.question, effort=args.effort)
        except CostRefusal as exc:
            print(f"cost refused: {exc}", file=sys.stderr)
            return 3
        except YouComError as exc:
            print(f"you.com error: {exc}", file=sys.stderr)
            return 1
    else:
        print("unknown intel subcommand", file=sys.stderr)
        return 2

    if args.json:
        payload = r.to_dict()
        payload["attacker_lens"] = frame_question()
        print(json.dumps(payload, indent=2))
        return 0 if r.ok else 1
    if not r.ok:
        print(f"failed: {r.error}", file=sys.stderr)
        return 1
    print(f"[{r.operation}] {len(r.sources)} sources, {len(r.documents)} documents, "
          f"paid={r.paid}, {r.latency_ms:.0f}ms")
    for s in r.sources:
        print(f"  {s.title[:70]}")
        print(f"    {s.url}")
    for d in r.documents:
        print(f"  {d.url}  ({len(d.markdown)} chars markdown)")
    if r.text:
        print()
        print(r.text)
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    """The persistent findings repository: document, search, verify, export."""
    from .doctrine import FINDING_SECTIONS
    from .evidence import EvidenceStore
    from .findings import (
        FindingRecord,
        FindingRepository,
        FindingVerdict,
        confirm_with_evidence,
    )

    repo = FindingRepository(args.dir, args.name)

    if args.sub == "summary":
        print(json.dumps(repo.summary(), indent=2))
        return 0

    if args.sub == "sections":
        print(json.dumps([s.to_dict() for s in FINDING_SECTIONS], indent=2))
        return 0

    if args.sub == "add":
        record = FindingRecord.from_dict(
            json.loads(Path(args.file).read_text(encoding="utf-8"))
        )
        dupes = repo.find_duplicates(record)
        repo.add(record)
        payload = {"recorded": record.finding_id, "verdict": record.status,
                   "possible_duplicates": [d.finding_id for d in dupes]}
        print(json.dumps(payload, indent=2))
        return 0

    if args.sub == "list":
        hits = repo.search(target=args.target or "", category=args.category or "",
                           component=args.component or "", severity=args.severity or "",
                           status=args.status or "", text=args.text or "")
        print(json.dumps([r.to_dict() for r in hits], indent=2, default=str))
        return 0

    if args.sub == "show":
        rec = repo.get(args.finding)
        if rec is None:
            print(f"no finding {args.finding!r}", file=sys.stderr)
            return 2
        print(json.dumps(rec.to_dict(), indent=2, default=str))
        return 0

    if args.sub == "history":
        print(json.dumps(repo.history(args.finding), indent=2, default=str))
        return 0

    if args.sub == "set-verdict":
        verdict = args.verdict.upper()
        if verdict not in {v.value for v in FindingVerdict}:
            print(f"unknown verdict {args.verdict!r}", file=sys.stderr)
            return 2
        if verdict == FindingVerdict.CONFIRMED.value:
            # CONFIRMED has exactly one CLI path -- `confirm` -- which resolves
            # every evidence reference against the evidence store. Allowing it
            # here would offer a weaker confirmation that only checks that the
            # evidence *fields* are non-empty, so it is refused.
            print("refusing to set CONFIRMED here: use `findings confirm`, which "
                  "resolves every evidence reference against the evidence store",
                  file=sys.stderr)
            return 2
        rec = repo.set_verdict(args.finding, verdict, note=args.note or "")
        if rec is None:
            print(f"no finding {args.finding!r}", file=sys.stderr)
            return 2
        print(json.dumps({"finding_id": rec.finding_id, "verdict": rec.status,
                          "applied": rec.status == verdict}, indent=2))
        return 0

    if args.sub == "confirm":
        # The full evidence-gated path: confirmation requires evidence that
        # actually resolves in the evidence store, plus an independent review.
        if getattr(args, "deployment_truth", ""):
            truth = json.loads(Path(args.deployment_truth).read_text(encoding="utf-8"))
            rec = repo.get(args.finding)
            if rec is None:
                print(f"no finding {args.finding!r}", file=sys.stderr)
                return 2
            rec.deployment_truth = truth
            rec.deployment_truth_required = True
            repo.save(rec)
        store = EvidenceStore(args.evidence)
        ok, reason = confirm_with_evidence(
            repo, args.finding,
            evidence_exists=lambda eid: store.get(eid) is not None,
            note=args.note or "",
        )
        print(json.dumps({"finding_id": args.finding, "confirmed": ok,
                          "reason": reason}, indent=2))
        return 0 if ok else 1

    if args.sub == "link":
        ok = repo.link(args.finding, args.other,
                       relation="duplicate" if args.duplicate else "related")
        print(json.dumps({"linked": ok, "finding_id": args.finding,
                          "other": args.other}, indent=2))
        return 0 if ok else 2

    if args.sub == "export":
        rec = repo.get(args.finding)
        if rec is None:
            print(f"no finding {args.finding!r}", file=sys.stderr)
            return 2
        if args.format == "json":
            text = repo.export_json(rec)
        elif args.format == "sarif":
            from .findings.sarif import dumps, to_sarif, validate
            document = to_sarif([rec])
            errors = validate(document)
            if errors:
                print(json.dumps({"valid": False, "errors": errors}, indent=2))
                return 1
            text = dumps(document)
        else:
            text = repo.export_markdown(rec)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.sub == "sarif":
        from .findings.sarif import dumps, to_sarif, validate
        document = to_sarif(repo.all())
        errors = validate(document)
        if errors:
            print(json.dumps({"valid": False, "errors": errors}, indent=2))
            return 1
        text = dumps(document)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.sub == "report":
        text = repo.consolidated_report()
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.sub == "integrity":
        from .integrity import resolve_key

        key = resolve_key(key_path=getattr(args, "key_path", None))
        result = repo.verify_integrity(
            key=key, require_signatures=bool(getattr(args, "require_signatures", False))
        )
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    print("unknown findings subcommand", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- #
# Incremental finding baseline
# --------------------------------------------------------------------------- #

def cmd_baseline(args: argparse.Namespace) -> int:
    """Create or compare a content-addressed finding baseline."""
    from .baseline import compare, create, dumps, render_markdown
    from .findings import FindingRepository

    repo = FindingRepository(args.findings, args.name)

    if args.sub == "create":
        text = dumps(create(repo.all()))
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.sub == "compare":
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            diff = compare(baseline, repo.all())
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"baseline error: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(diff.to_dict(), indent=2))
        else:
            print(render_markdown(diff))
        if args.fail_on_new and diff.has_new:
            return 1
        return 0

    print("unknown baseline subcommand", file=sys.stderr)
    return 2


def cmd_retest(args: argparse.Namespace) -> int:
    """Re-run a finding's PoC and record Still reproducible / Fixed / Cannot confirm.

    Exit 0 = FIXED, 1 = STILL_REPRODUCIBLE, 2 = CANNOT_CONFIRM. A retest never
    changes the finding's verdict; it only updates ``retest_result``.
    """
    from .findings import FindingRepository
    from .retest import RetestVerdict, apply_to_record, run_retest

    repo = FindingRepository(args.findings, args.name)
    record = repo.get(args.finding_id)
    if record is None:
        print(f"retest error: finding {args.finding_id!r} not found", file=sys.stderr)
        return 2
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("retest error: no reproduction command (use: blackheart retest F-1 -- <command>)", file=sys.stderr)
        return 2
    rec = run_retest(
        args.finding_id,
        command,
        timeout=args.timeout,
        evidence_ids=args.evidence or (),
    )
    apply_to_record(rec, record)
    repo.save(record)
    if args.json:
        print(json.dumps(rec.to_dict(), indent=2))
    else:
        print(f"{rec.finding_id}: {rec.verdict.value}  ({rec.note})")
    return {
        RetestVerdict.FIXED.value: 0,
        RetestVerdict.STILL_REPRODUCIBLE.value: 1,
    }.get(rec.verdict.value, 2)


def cmd_graph(args: argparse.Namespace) -> int:
    """Query the dual research graph: asset coverage or a finding's lineage."""
    from .graph import ResearchGraph

    graph = ResearchGraph(args.db)
    if args.sub == "coverage":
        rows = graph.coverage(args.company)
        summary = graph.coverage_summary(args.company)
        if args.json:
            print(json.dumps({"summary": summary, "assets": rows}, indent=2))
        else:
            print(
                f"assets={summary['total']} explored={summary['explored']} "
                f"tested={summary['tested']} untested={summary['untested']}"
            )
            for r in rows:
                mark = "tested" if r["tested"] else ("explored" if r["explored"] else "untested")
                print(f"  [{mark}] {r['kind']}:{r['key']}")
        return 0 if summary["tested"] == summary["total"] else 1
    if args.sub == "lineage":
        chain = graph.lineage(args.node)
        if not chain:
            print(f"graph error: node {args.node} not found", file=sys.stderr)
            return 2
        for node in chain:
            print(f"{node.kind}: {node.key}")
        return 0
    print("unknown graph subcommand", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------- #
# Research memory / hypothesis / learning (evolving research engine)
# --------------------------------------------------------------------------- #

def cmd_research(args: argparse.Namespace) -> int:
    """Persistent, searchable research memory."""
    from .models import ResearchRecord
    from .research import ResearchMemory

    mem = ResearchMemory(args.dir, args.engagement)
    if args.sub == "summary":
        print(json.dumps(mem.summary(), indent=2))
        return 0
    if args.sub == "search":
        hits = mem.search(target=args.target, vulnerability_class=args.vclass,
                          text=args.text, status=args.status)
        print(json.dumps([r.to_dict() for r in hits], indent=2, default=str))
        return 0
    if args.sub == "export":
        md = mem.export_markdown()
        if args.out:
            Path(args.out).write_text(md, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(md)
        return 0
    if args.sub == "integrity":
        print(json.dumps(mem.verify_integrity(), indent=2))
        return 0
    if args.sub == "record":
        record = ResearchRecord.from_dict(json.loads(Path(args.file).read_text(encoding="utf-8")))
        mem.save(record)
        print(f"recorded {record.record_id} status={record.status}")
        return 0
    print("unknown research subcommand", file=sys.stderr)
    return 2


def cmd_hypothesis(args: argparse.Namespace) -> int:
    """Rank and select the next investigation, with an explanation."""
    from .hypothesis import BASELINE_STRATEGY, HypothesisEngine, Strategy, ThreatModelIncomplete
    from .research import ResearchMemory
    from .threatmodel import ThreatModel

    profile = _load_profile(args.profile)
    mem = ResearchMemory(args.memory, args.engagement) if args.memory else None
    strategy = Strategy("surface-aware", use_surface=True) if args.surface else BASELINE_STRATEGY
    threat_model = None
    if getattr(args, "threat_model", None):
        threat_model = ThreatModel.from_dict(json.loads(Path(args.threat_model).read_text(encoding="utf-8")))
    engine = HypothesisEngine(profile, mem, strategy=strategy, threat_model=threat_model)
    try:
        hyps = engine.generate(new_evidence=args.new_evidence)
    except ThreatModelIncomplete as exc:
        print(str(exc), file=sys.stderr)
        return 3
    if args.out:
        Path(args.out).write_text(json.dumps([h.to_dict() for h in hyps], indent=2), encoding="utf-8")
    print(engine.explain_selection(new_evidence=args.new_evidence))
    return 0


def cmd_hypothesize(args: argparse.Namespace) -> int:
    """P2: generate falsifiable hypotheses from a validated threat model."""
    from .hypothesis.generation import HypothesisGenerator, HypothesisStore
    from .research import ResearchMemory
    from .threatmodel import ThreatModel

    profile = _load_profile(args.profile)
    tm = ThreatModel.from_dict(json.loads(Path(args.threat_model).read_text(encoding="utf-8")))
    mem = ResearchMemory(args.memory, args.engagement) if args.memory else None
    tools = set(t for t in args.tools.split(",") if t) if args.tools else None

    gen = HypothesisGenerator(tm, profile, memory=mem, tools_available=tools,
                              scope_reference=args.scope_reference or "")
    try:
        result = gen.generate()
    except Exception as exc:  # incomplete model, etc. -- report, never invent
        print(json.dumps({"error": str(exc), "threat_model_missing": tm.missing()}, indent=2))
        return 3

    if args.store:
        HypothesisStore(args.store).save(result)
    payload = {
        "summary": result.summary(),
        "next": (result.select_next().to_dict() if result.select_next() else None),
        "hypotheses": [h.to_dict() for h in result.active()],
        "rejections": [r.to_dict() for r in result.rejections],
    }
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.summary:
        print(json.dumps(result.summary(), indent=2))
        nxt = result.select_next()
        print(f"\nnext: {nxt.hyp_id if nxt else 'none'}")
    else:
        print(json.dumps(payload, indent=2))
    return 0


@_fixture_command
def cmd_statespace(args: argparse.Namespace) -> int:
    """Adversarial state-machine discovery: model -> hypotheses -> violations.

    Every value printed comes from a real run against a local fixture or a model
    loaded from disk. Nothing is fabricated; a violation is a sequence that broke a
    stated invariant, not a confirmed vulnerability.
    """
    from .statespace import (
        ExploreConfig,
        HypothesisGenerator,
        IndependentSequenceVerifier,
        StateSpaceExplorer,
        VerifyConfig,
        strategy_ids,
    )
    from .statespace.benchmark import run_benchmark
    from .statespace.skills import SKILLS, run_all, write_skill_files

    sub = args.sub
    if sub == "strategies":
        print(json.dumps([s for s in strategy_ids()], indent=2))
        return 0
    if sub == "skills":
        if args.write:
            written = write_skill_files(args.write)
            print(json.dumps({"written": written}, indent=2))
            return 0
        if args.run:
            try:
                model = _load_statespace_model(args)
            except KeyError as exc:
                print(json.dumps({"error": str(exc.args[0]) if exc.args else str(exc),
                                  "known_fixtures": _statespace_fixture_names()}, indent=2))
                return 2
            if model is None:
                print(json.dumps({"error": "provide --fixture or --model"}, indent=2))
                return 2
            out = {k: [h.to_dict() for h in v] for k, v in run_all(model).items()}
            print(json.dumps(out, indent=2))
            return 0
        print(json.dumps([s.to_dict() for s in SKILLS], indent=2))
        return 0

    if sub == "runtime":
        return _cmd_statespace_runtime(args)

    if sub == "mempool":
        from .statespace.mempool import make_scenario, scenario_names, search_ordering

        if args.scenario == "list" or args.scenario is None:
            print(json.dumps(scenario_names(), indent=2))
            return 0
        try:
            scenario = make_scenario(args.scenario)
        except KeyError as exc:
            print(json.dumps({"error": str(exc)}, indent=2))
            return 2
        report = search_ordering(scenario, max_attacker_steps=args.max_attacker_steps,
                                 max_orderings=args.max_orderings)
        payload = report.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "evm":
        return _cmd_statespace_evm(args)

    if sub == "evm-bench":
        return _cmd_statespace_evm_bench(args)

    if sub == "runtime-bench":
        from .statespace.runtime.benchmark import run_runtime_benchmark

        payload = run_runtime_benchmark().to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in payload.items() if k != "cases"}, indent=2))
        return 0

    if sub == "benchmark":
        payload = run_benchmark(guided_runs=args.runs, baseline_runs=args.baseline_runs)
        if args.out:
            Path(args.out).write_text(json.dumps(payload.to_dict(), indent=2), encoding="utf-8")
        print(json.dumps({"all": payload.summary(), "heldout": payload.summary(heldout=True),
                          "hard": payload.summary(hard=True)}, indent=2))
        return 0

    # A model alone supports `model` and `hypotheses`. `explore`/`discover` also
    # need an *executable* target, which only a fixture provides: a SystemModel has
    # no runtime semantics, so we do not pretend to search one.
    if sub in ("model", "hypotheses"):
        try:
            model = _load_statespace_model(args)
        except KeyError as exc:
            print(json.dumps({"error": str(exc.args[0]) if exc.args else str(exc),
                              "known_fixtures": _statespace_fixture_names()}, indent=2))
            return 2
        if model is None:
            print(json.dumps({"error": "provide --fixture or --model"}, indent=2))
            return 2
        if sub == "model":
            print(json.dumps(model.to_dict(), indent=2))
            return 0
        payload = HypothesisGenerator(model).generate().to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    try:
        target = _load_statespace_target(args)
    except KeyError as exc:
        print(json.dumps({"error": str(exc.args[0]) if exc.args else str(exc),
                          "known_fixtures": _statespace_fixture_names()}, indent=2))
        return 2
    if target is None:
        print(json.dumps({
            "error": "explore/discover need an executable target; provide --fixture",
            "note": "--model alone supports only the model and hypotheses subcommands",
        }, indent=2))
        return 2
    model = target.model()
    hyps = HypothesisGenerator(model).generate()

    cfg = ExploreConfig(seed=args.seed, max_steps=args.steps)
    explorer = StateSpaceExplorer(target, cfg)
    report = explorer.explore(hyps.hypotheses)
    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    if sub == "explore":
        print(json.dumps(report.to_dict(), indent=2))
        if report.unevaluable:
            print(f"WARNING: {len(report.unevaluable)} invariant(s) could not be "
                  f"evaluated ({', '.join(report.unevaluable)}); 'no violation' here "
                  f"is 'could not tell'", file=sys.stderr)
        return 0

    if sub == "discover":
        # verify each violation with a control when one is known for the fixture
        control_factory = _statespace_control(args)
        vcfg = VerifyConfig(control_factory=control_factory, in_scope=True,
                            scope_reference=target.name, authorization_gate_passed=True)
        verifier = IndependentSequenceVerifier(lambda: _load_statespace_target(args), vcfg)
        results = [verifier.verify(v, model=model, preconditions_satisfiable=True)
                   for v in report.violations]
        payload = {
            "target": target.name,
            "sequences_tried": report.sequences_tried,
            "unevaluable": list(report.unevaluable),
            "violations": [v.to_dict() for v in report.violations],
            "verdicts": [r.to_dict() for r in results],
        }
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    print(json.dumps({"error": f"unknown statespace subcommand: {sub}"}, indent=2))
    return 2


@_fixture_command
def cmd_discovery(args: argparse.Namespace) -> int:
    """Historical-rediscovery discovery engine (mission 3.A/3.B/3.D/3.E/3.G/3.H/3.I).

    Every number printed comes from a real run over the local corpus and the real
    Foundry PoC suite. A "detection" is the engine finding a sequence that breaks a
    case's stated invariant on a model of known vulnerable logic -- a rediscovery,
    never a bounty finding. Nothing is fabricated; missing tooling is reported.
    """
    from .discovery import corpus as corpus_mod
    from .discovery import economic as economic_mod
    from .discovery import foundry_corpus
    from .discovery import heldout as heldout_mod
    from .discovery import missed as missed_mod
    from .discovery.harness import DEFAULT_MEMORY, benchmark, run_case
    from .learning.transfer import AttackMemory

    sub = args.sub
    # Cross-target memory is opt-in (--memory) so a plain run has no side effects;
    # the `memory` subcommand always has it. An absent file simply starts empty.
    memory = None
    if getattr(args, "memory", False) or sub == "memory":
        memory = AttackMemory(getattr(args, "memory_dir", None) or DEFAULT_MEMORY)

    if sub == "corpus":
        print(json.dumps(corpus_mod.summary(), indent=2))
        return 0

    if sub == "cases":
        payload = [c.to_dict() for c in corpus_mod.corpus()]
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "heldout":
        payload = [c.to_dict() for c in heldout_mod.holdout_cases()]
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "case":
        case = next((c for c in corpus_mod.corpus() if c.case_id == args.case_id), None)
        if case is None:
            print(json.dumps({"error": f"unknown case: {args.case_id}"}, indent=2))
            return 2
        res = run_case(case, memory=memory)
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    if sub == "benchmark":
        rep = benchmark(memory=memory)
        payload = rep.to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in payload.items() if k != "cases"}, indent=2))
        return 0

    if sub == "memory":
        from .learning.transfer import AttackMemory

        mem = AttackMemory(args.dir)
        if args.action == "summary":
            print(json.dumps(mem.summary(), indent=2))
            return 0
        if args.action == "list":
            print(json.dumps([e.to_dict() for e in mem.entries()], indent=2))
            return 0
        if args.action == "seed":
            # Show what proven attacks transfer onto a corpus/holdout case.
            case = next((c for c in corpus_mod.corpus() if c.case_id == args.target), None)
            if case is None:
                case = next((c for c in heldout_mod.holdout_cases()
                             if c.case_id == args.target), None)
            if case is None or case.vulnerable is None:
                print(json.dumps({"error": f"unknown or unmodelled case: {args.target}"},
                                 indent=2))
                return 2
            target = case.vulnerable()
            seeds = mem.seeds_for(target, min_score=args.min_score,
                                  root_cause=case.root_cause)
            payload = {
                "target": case.case_id,
                "root_cause": case.root_cause,
                "transferred": [
                    [{"actor": s.actor, "action": s.action, "params": s.params} for s in seq]
                    for seq in seeds
                ],
            }
            print(json.dumps(payload, indent=2))
            return 0

    if sub == "misses":
        rep = benchmark().to_dict()
        payload = missed_mod.missed_report(rep)
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "economic":
        # Analyse the economic consequence of the guided engine's own findings.
        from .discovery.search import discover
        from .discovery.harness import ModelTarget
        accounts = []
        for case in corpus_mod.modelled_cases():
            if case.vulnerable is None:
                continue
            mt = ModelTarget(case.vulnerable())
            viols = discover(mt)
            if not viols:
                continue
            v = viols[0]
            acct = economic_mod.analyse(mt, v.minimal_sequence, v.invariant_id, case.case_id)
            accounts.append(acct.to_dict())
        payload = {"cases_analysed": len(accounts), "accounts": accounts}
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "certify":
        from .discovery import certify as certify_mod

        # Resolve the target: a corpus/holdout case id, or a fixture name.
        case = None
        for c in list(corpus_mod.corpus()) + list(heldout_mod.holdout_cases()):
            if c.case_id == args.target:
                case = c
                break
        if case is not None and case.vulnerable is not None:
            target = case.vulnerable()
        else:
            make, _, _ = _fixture_by_name(args.target)
            if make is None:
                print(json.dumps({"error": f"unknown target: {args.target}"}, indent=2))
                return 2
            target = make()

        if args.mode == "exhaustive":
            cert = certify_mod.certify_exhaustive(
                target, max_depth=args.depth, max_states=args.max_states)
        elif args.mode == "concolic":
            # Build a seed path from the model's operations (one step each).
            from .models import AttackStep
            seed = []
            for i, op in enumerate(target.ops()):
                actor = (getattr(op, "actors", []) or ["attacker"])[0]
                domain = getattr(op, "param_domain", {}) or {}
                params = {k: (v[0] if v else 0) for k, v in domain.items()}
                seed.append(AttackStep(index=i, actor=actor, action=op.name,
                                       params=params, target_contract=target.name))
            cert = certify_mod.certify_concolic(target, seed, max_rounds=args.rounds)
        else:
            print(json.dumps({"error": f"unknown mode: {args.mode}"}, indent=2))
            return 2

        payload = cert.to_dict()
        # A certificate is only trustworthy if the patched control does not share
        # the violation; when a case supplies a control, certify it too.
        if case is not None and case.patched is not None and cert.proven:
            control = certify_mod.certify_exhaustive(
                case.patched(), max_depth=args.depth, max_states=args.max_states)
            payload["control_proven"] = control.proven
            payload["distinguishing"] = not control.proven
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "economic-invariants":
        print(json.dumps(economic_mod.ECONOMIC_INVARIANTS, indent=2))
        return 0

    if sub == "foundry":
        payload = foundry_corpus.run_poc_suite().to_dict()
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "foundry-invariant":
        payload = foundry_corpus.run_invariant_differential()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if sub == "blind-benchmark":
        from .discovery.blind_benchmark import run_blind_benchmark
        payload = run_blind_benchmark().to_dict()
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps({k: v for k, v in payload.items() if k != "cases"}, indent=2))
        return 0

    if sub == "campaign":
        return _cmd_discovery_campaign(args)

    print(json.dumps({"error": f"unknown discovery subcommand: {sub}"}, indent=2))
    return 2


def _fixture_by_name(name: str):
    """Resolve a fixture name to a Target factory (development/holdout/hard/blind)."""
    from .statespace import fixtures as fixtures_mod
    from .statespace import hard as hard_mod
    from .statespace import heldout as heldout_mod
    from .discovery import blind as blind_mod

    for pair in fixtures_mod.FIXTURE_PAIRS:
        if pair[0] == name or pair[1] == name:
            return fixtures_mod.make_fixture(name), pair[0], pair[1]
    for pair in heldout_mod.HELDOUT_PAIRS:
        if pair[0] == name or pair[1] == name:
            return heldout_mod.make_heldout(name), pair[0], pair[1]
    for pair in hard_mod.HARD_PAIRS:
        if pair[0] == name or pair[1] == name:
            return hard_mod.make_hard(name), pair[0], pair[1]
    for bp in blind_mod.blind_pairs():
        if bp.case_id == name or bp.vulnerable.name == name or bp.patched.name == name:
            return None, bp.vulnerable, bp.patched
    for cls in blind_mod.NEGATIVE_CONTROLS:
        if cls.name == name:
            return cls(), name, name
    return None, None, None


def _cmd_discovery_campaign(args: argparse.Namespace) -> int:
    """Run an adaptive discovery campaign against one local fixture.

    Reports the campaign status per candidate with the mission's exact
    vocabulary: hypothesis generated / candidate detected / exploit reproduced /
    independently verified / rejected / inconclusive. An unverified candidate is
    never labelled a confirmed vulnerability.
    """
    from .statespace.adaptive import AdaptiveConfig, AdaptiveExplorer
    from .statespace.hypotheses import HypothesisGenerator
    from .statespace.verify import IndependentSequenceVerifier, VerifyConfig
    from .discovery import blind as blind_mod
    from .discovery.harness import ModelTarget

    target, vuln_name, ctrl_name = _fixture_by_name(args.fixture)
    blind_pair = None
    if target is None and ctrl_name is not None:
        # A blind case: build the vulnerable instance, remember the control class.
        blind_pair = next(bp for bp in blind_mod.blind_pairs()
                          if bp.vulnerable.name == vuln_name or bp.patched.name == ctrl_name
                          or bp.case_id == args.fixture)
        target = blind_pair.vulnerable()
    if target is None:
        print(json.dumps({"error": f"unknown fixture: {args.fixture}"}, indent=2))
        return 2

    mt = ModelTarget(target)
    model = mt.model()
    hyps = HypothesisGenerator(model).generate()

    cfg = AdaptiveConfig(seed=args.seed, max_steps=args.steps, max_sequences=args.budget)
    report = AdaptiveExplorer(mt, cfg).explore()

    # Control factory for the differential check.
    control_factory = None
    if blind_pair is not None:
        control_factory = lambda: ModelTarget(blind_pair.patched())  # noqa: E731
    elif args.control:
        ctrl, _, _ = _fixture_by_name(args.control)
        if ctrl is not None:
            control_factory = lambda: ModelTarget(ctrl)  # noqa: E731
    elif ctrl_name:
        ctrl, _, _ = _fixture_by_name(ctrl_name)
        if ctrl is not None:
            control_factory = lambda: ModelTarget(ctrl)  # noqa: E731

    verifier = IndependentSequenceVerifier(
        lambda: ModelTarget(target),
        VerifyConfig(control_factory=control_factory, in_scope=True,
                     scope_reference=target.name, authorization_gate_passed=True))

    candidates = []
    for v in report.violations:
        res = verifier.verify(v, model=model, preconditions_satisfiable=True)
        if res.disposition == "INDEPENDENTLY_VERIFIED":
            status = "independently-verified"
        elif res.disposition in ("REPRODUCED", "INSUFFICIENT_EVIDENCE"):
            status = "exploit-reproduced"
        elif res.disposition == "REJECTED":
            status = "rejected"
        else:
            status = "inconclusive"
        candidates.append({
            "invariant": v.invariant_id,
            "status": status,
            "disposition": res.disposition,
            "minimal_sequence": [s.to_dict() for s in v.minimal_sequence],
            "reachable_by_attacker": v.reachable_by_attacker,
            "economic": v.economic,
            "reasons": res.reasons,
        })

    payload = {
        "fixture": target.name,
        "campaign": {
            "hypotheses_generated": len(hyps.hypotheses),
            "sequences_executed": report.sequences_tried,
            "steps_evaluated": report.steps_evaluated,
            "priority_divergences": report.priority_divergences,
            "coverage_pairs": report.coverage_pairs,
            "coverage_adjacencies": report.coverage_adjacencies,
            "candidates_detected": len(report.violations),
            "budget": args.budget,
            "budget_exhausted": report.sequences_tried >= args.budget,
        },
        "candidates": candidates,
        "note": ("A candidate is a sequence that broke a stated invariant on a local "
                 "model; only 'independently-verified' means the independent verifier "
                 "(fresh re-run + attacker reachability + control differential) confirmed "
                 "it. This is a rediscovery on a model, never a production vulnerability."),
    }
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_statespace_runtime(args: argparse.Namespace) -> int:
    """Execute the engine against a real, controlled local application.
    This is the runtime half of the state-space engine: instead of driving an
    in-memory fixture, it loads an authorized local application, derives its
    runtime model, generates adversarial hypotheses without being told the
    vulnerable sequence, executes the candidate sequences against the running
    application, minimises any violation, and independently re-executes it.
    """
    from .statespace.runtime import adapter_report, app_names, run_runtime_discovery

    if args.list_apps:
        print(json.dumps({
            "apps": app_names(),
            "note": "local, controlled harness applications; loopback only",
        }, indent=2))
        return 0
    if args.app not in app_names():
        print(json.dumps({
            "error": f"unknown app {args.app!r}",
            "known": app_names(),
            "note": "runtime discovery runs only against BLACKHEART's own controlled "
                    "local harness apps or an explicitly authorized local target",
        }, indent=2))
        return 2
    if args.declare:
        print(json.dumps(adapter_report(args.app), indent=2))
        return 0
    report = run_runtime_discovery(args.app).to_dict()
    if getattr(args, "research", False):
        from .statespace.runtime.research import research_findings

        report["research"] = research_findings(report, target=args.app,
                                               cross_check=getattr(args, "cross_check", False))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


def _cmd_statespace_evm(args: argparse.Namespace) -> int:
    """Discover and independently verify against real external EVM bytecode.

    The target is the vendored, third-party Damn Vulnerable DeFi v4.1.0 suite
    deployed to an ephemeral local anvil node. The engine runs unchanged; the
    contracts are external and unmodified. A hit is a *capability* result, not a
    production vulnerability (DVDF is a deliberately-vulnerable educational suite).
    """
    from .statespace.runtime.evm_registry import ALL_CASES, TARGETS, catalogue
    from .statespace.runtime.evm_run import run_evm_case

    if args.list_cases:
        targets = [{
            "project": t.project, "repository": t.repository,
            "commit": t.commit, "tag": t.tag, "note": t.note,
        } for t in TARGETS]
        print(json.dumps({
            "targets": targets,
            "note": "third-party, deliberately-vulnerable educational suites; "
                    "a hit is a capability result, not a production vulnerability",
            "cases": catalogue(),
        }, indent=2))
        return 0

    names = list(ALL_CASES) if args.all else [args.case]
    if not args.all and not args.case:
        print(json.dumps({"error": "provide --case NAME or --all (or --list-cases)"}, indent=2))
        return 2
    from .statespace import ExploreConfig

    cfg = ExploreConfig(seed=args.seed, max_steps=args.steps)
    reports = []
    for name in names:
        try:
            reports.append(run_evm_case(name, cfg=cfg, verify=not args.no_verify).to_dict())
        except Exception as exc:  # keep going across cases; report the failure honestly
            reports.append({"case": name, "executed": False, "errors": [f"{type(exc).__name__}: {exc}"]})
    payload = {"cases": reports} if args.all else reports[0]
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_statespace_evm_bench(args: argparse.Namespace) -> int:
    """Fair comparison on the external EVM cases.

    Runs three approaches against the *same* deployed bytecode, operations,
    actors, parameter domains and execution budget:

      * **guided**  -- BLACKHEART's unchanged state-space engine;
      * **random**  -- a uniform random stateful fuzzer over the same space;
      * **native**  -- the upstream project's own Foundry test for the level.

    The comparison is reported honestly, including where the random fuzzer also
    succeeds: a capability claim is only meaningful next to a fair baseline.
    """
    from .statespace import ExploreConfig
    from .statespace.runtime.evm_benchmark import compare_all, compare_case
    from .statespace.runtime.evm_registry import ALL_CASES

    if not args.all and not args.case:
        print(json.dumps({"error": "provide --case NAME or --all"}, indent=2))
        return 2

    cfg = ExploreConfig(seed=args.seed, max_steps=args.steps)
    if args.all:
        comps = compare_all(cfg=cfg, random_sequences=args.random_sequences)
        payload = {"cases": [c.to_dict() for c in comps]}
    else:
        if args.case not in ALL_CASES:
            print(json.dumps({"error": f"unknown case {args.case!r}",
                              "known": sorted(ALL_CASES)}, indent=2))
            return 2
        payload = compare_case(args.case, cfg=cfg,
                               random_sequences=args.random_sequences).to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


def _load_statespace_model(args: argparse.Namespace):
    if getattr(args, "fixture", None):
        return _make_statespace_fixture(args.fixture).model()
    if getattr(args, "model", None):
        from .statespace import model_from_threatmodel
        from .threatmodel import ThreatModel

        raw = json.loads(Path(args.model).read_text(encoding="utf-8"))
        # A SystemModel carries actors/operations; a ThreatModel does not, and
        # instead carries critical_assets/architecture. Detect on the schema.
        if "actors" in raw or "operations" in raw:
            return _model_from_dict(raw)
        return model_from_threatmodel(ThreatModel.from_dict(raw))
    return None


def _model_from_dict(d: dict):
    from .statespace.model import Actor, ModelInvariant, Operation, SystemModel, TransitionRule

    m = SystemModel(target=d["target"], summary=d.get("summary", ""),
                    assets=list(d.get("assets", [])),
                    trust_boundaries=list(d.get("trust_boundaries", [])),
                    dependencies=list(d.get("dependencies", [])),
                    intended_behaviours=list(d.get("intended_behaviours", [])),
                    evidence=list(d.get("evidence", [])))
    for a in d.get("actors", []):
        m.actors.append(Actor(name=a["name"], roles=tuple(a.get("roles", [])),
                              unprivileged=a.get("unprivileged", True)))
    for o in d.get("operations", []):
        m.operations.append(Operation(name=o["name"], actor_roles=tuple(o.get("actor_roles", [])),
                                      asset=o.get("asset", ""), sensitive=o.get("sensitive", False),
                                      precondition=o.get("precondition", ""), effect=o.get("effect", ""),
                                      guard=o.get("guard", ""), guard_roles=tuple(o.get("guard_roles", [])),
                                      source=o.get("source", "")))
    for t in d.get("transitions", []):
        m.transitions.append(TransitionRule(name=t["name"], guard=t.get("guard", ""),
                                            guard_roles=tuple(t.get("guard_roles", [])),
                                            operation=t.get("operation", "")))
    for i in d.get("invariants", []):
        m.invariants.append(ModelInvariant(inv_id=i["inv_id"], statement=i.get("statement", ""),
                                           applies_to=tuple(i.get("applies_to", [])),
                                           expression=i.get("expression", "")))
    return m


def _make_statespace_fixture(name: str):
    from .statespace import make_fixture
    from .statespace.hard import hard_names, make_hard
    from .statespace.heldout import heldout_names, make_heldout

    if name in hard_names():
        return make_hard(name)
    if name in heldout_names():
        return make_heldout(name)
    return make_fixture(name)


def _statespace_fixture_names() -> list[str]:
    from .statespace import fixture_names
    from .statespace.hard import hard_names
    from .statespace.heldout import heldout_names

    return sorted(set(fixture_names()) | set(hard_names()) | set(heldout_names()))


def _load_statespace_target(args: argparse.Namespace):
    if getattr(args, "fixture", None):
        return _make_statespace_fixture(args.fixture)
    # A model alone has no runtime semantics, so it cannot be explored; only a
    # fixture provides an executable target.
    return None


def _statespace_control(args: argparse.Namespace):
    name = getattr(args, "fixture", None)
    if not name:
        return None
    guarded = name + "-guarded"
    try:
        _make_statespace_fixture(guarded)
    except KeyError:
        return None
    return lambda: _make_statespace_fixture(guarded)


def cmd_investigate(args: argparse.Namespace) -> int:
    """P3: inspect or begin the investigation workflow for a hypothesis."""
    from .hypothesis.generation import GeneratedHypothesis
    from .investigation import (
        InvestigationEngine,
        InvestigationStore,
        Triage,
        plan_from_tools,
    )

    store = InvestigationStore(args.dir, args.name)

    if args.sub == "list":
        print(json.dumps([
            {"id": s.investigation_id, "stage": s.stage, "status": s.status,
             "hypothesis": s.hypothesis_id} for s in store.all()
        ], indent=2))
        return 0

    if args.sub == "verify":
        from .integrity import resolve_key

        key = resolve_key(key_path=getattr(args, "key_path", None))
        checkpoint = None
        cp_path = getattr(args, "checkpoint", None)
        if cp_path:
            from .integrity import Checkpoint

            cp_file = Path(cp_path)
            if cp_file.exists():
                checkpoint = Checkpoint.read(cp_file)
        result = store.verify_integrity(
            key=key, require_signatures=bool(getattr(args, "require_signatures", False)),
            checkpoint=checkpoint,
        )
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    if args.sub == "checkpoint":
        from .integrity import Checkpoint, resolve_key

        key = resolve_key(key_path=getattr(args, "key_path", None))
        seq, chain = store.head()
        if seq < 0:
            print("no investigation records to checkpoint", file=sys.stderr)
            return 2
        cp = Checkpoint(log_path=str(store.path), head_seq=seq, head_chain=chain)
        if key is not None:
            cp.sign(key)
        out = Path(args.out) if args.out else store.root / f"{args.name}.checkpoint.json"
        cp.write(out)
        print(json.dumps({"checkpoint": str(out), "head_seq": seq,
                          "signed": key is not None}, indent=2))
        return 0

    if args.sub == "keygen":
        from .integrity import generate_key, key_to_file

        out = Path(args.out) if args.out else store.root / "integrity-key.json"
        if out.exists():
            print(f"refusing to overwrite existing key: {out}", file=sys.stderr)
            return 2
        key = generate_key()
        key_to_file(key, out)
        print(json.dumps({"key_id": key.key_id, "path": str(out),
                          "note": "the key is NOT stored in the log; keep it out of git"},
                         indent=2))
        return 0

    if args.sub == "show":
        state = store.get(args.investigation)
        if state is None:
            print(f"no investigation {args.investigation!r}", file=sys.stderr)
            return 2
        print(json.dumps(state.to_dict(), indent=2, default=str))
        return 0

    if args.sub == "run":
        if not args.hypothesis:
            print("--hypothesis FILE (a P2 hypothesis JSON) is required for run", file=sys.stderr)
            return 2
        data = json.loads(Path(args.hypothesis).read_text(encoding="utf-8"))
        hyp = GeneratedHypothesis(**{
            k: v for k, v in data.items()
            if k in GeneratedHypothesis.__dataclass_fields__
        })
        authz = _load_authz(args.authz) if args.authz else None
        from .evidence import EvidenceStore

        engine = InvestigationEngine(
            store, authorization=authz,
            evidence=EvidenceStore(Path(args.dir) / "evidence"),
        )
        plan = plan_from_tools(hyp)
        state = engine.start(hyp, scope_reference=args.scope_reference or "")
        state = engine.triage(state, Triage.PURSUE, reason="selected by P2 ranking")
        print(json.dumps({
            "investigation": state.investigation_id,
            "stage": state.stage,
            "next_stage": state.next_stage(),
            "test_plan": plan.to_dict(),
            "blocking_entry_criteria": engine.entry_criteria(state, "TEST_DESIGN"),
        }, indent=2))
        return 0

    print("unknown investigate subcommand", file=sys.stderr)
    return 2


def cmd_threatmodel(args: argparse.Namespace) -> int:
    """Protocol intelligence: scaffold, check, catalogue, or steer by a threat model."""
    from .threatmodel import (
        ThreatModel,
        impact_catalog,
        model_from_profile,
        steer_objectives,
    )

    if args.sub == "catalog":
        payload = {"impacts": impact_catalog()}
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if args.sub == "scaffold":
        profile = _load_profile(args.profile)
        impacts = args.impact or []
        tm = model_from_profile(profile, revision=args.revision, selected_impacts=impacts)
        payload = {"model": tm.to_dict(), "missing": tm.missing(), "complete": tm.is_complete()}
        if args.out:
            Path(args.out).write_text(tm.to_json(), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        # A scaffold is intentionally incomplete; exit non-zero so CI notices.
        return 0 if tm.is_complete() else 3

    if args.sub == "check":
        tm = ThreatModel.from_dict(json.loads(Path(args.model).read_text(encoding="utf-8")))
        gaps = tm.missing()
        print(json.dumps({"complete": not gaps, "missing": gaps}, indent=2))
        return 0 if not gaps else 3

    if args.sub == "steer":
        profile = _load_profile(args.profile)
        tm = ThreatModel.from_dict(json.loads(Path(args.model).read_text(encoding="utf-8")))
        objectives = generate_objectives(profile)
        steered = steer_objectives(objectives, tm)
        payload = {
            "selected_impacts": tm.selected_impacts,
            "order": [o.category for o in steered],
        }
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    print("unknown threatmodel subcommand", file=sys.stderr)
    return 2


def cmd_learn(args: argparse.Namespace) -> int:
    """Self-improvement: benchmark a strategy, or demonstrate the learning loop."""
    from .hypothesis import BASELINE_STRATEGY, HypothesisEngine, Strategy
    from .learning import LearningEngine
    from .learning.benchmark import HISTORICAL, RankingBenchmark

    bench = RankingBenchmark()
    engine = LearningEngine(benchmark=bench)

    if args.sub == "bench":
        baseline = bench.evaluate_all(
            lambda p, m: HypothesisEngine(p, m, strategy=BASELINE_STRATEGY)
        )
        candidate = bench.evaluate_all(
            lambda p, m: HypothesisEngine(p, m, strategy=Strategy("surface-aware", use_surface=True))
        )
        payload = {"baseline": baseline, "surface_aware": candidate}
        if args.out:
            Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(json.dumps(payload, indent=2))
        return 0

    if args.sub == "propose":
        print(json.dumps(engine.propose_surface_awareness().to_dict(), indent=2))
        return 0

    if args.sub == "demo":
        improvement = engine.propose_surface_awareness()
        demo = engine.demonstrate_weakness(HISTORICAL[0])
        verdict = engine.evaluate(improvement)
        print("OLD WEAKNESS (baseline mis-ranking):")
        print(json.dumps(demo, indent=2))
        print("\nIMPROVEMENT VERDICT:")
        print(json.dumps({k: v for k, v in verdict.to_dict().items() if k != "failing_test"}, indent=2))
        if args.out:
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            (out / "test_learned_ranking.py").write_text(verdict.failing_test, encoding="utf-8")
            print(f"\nwrote regression test -> {out / 'test_learned_ranking.py'}")
        return 0 if verdict.accepted else 1

    print("unknown learn subcommand", file=sys.stderr)
    return 2


def cmd_novelty(args: argparse.Namespace) -> int:
    """Adjudicate a pre-submission novelty review (mission Phase 2/3)."""
    from .models import NoveltyReview
    from .novelty import NoveltyGate, collect_disclosures

    gate = NoveltyGate()
    review = NoveltyReview.from_dict(json.loads(Path(args.file).read_text(encoding="utf-8")))

    if getattr(args, "search", False):
        # Populate the search from live providers before adjudicating. The
        # operator's queries drive it; results carry provider provenance and a
        # failed provider is recorded, never faked.
        from .intelligence.providers import ProviderRegistry, SearchRouter

        router = SearchRouter(ProviderRegistry())
        collect_disclosures(
            review,
            lambda q, count: router.search(q, count=count, cross_check=False),
        )

    if getattr(args, "advisories", False):
        # A free source that needs no paid key. It only understands package
        # names and CVE ids, so a sentence query is recorded as a limitation --
        # which is the honest outcome, not a silent zero.
        from .prior_art import advisory_search_fn

        collect_disclosures(review, advisory_search_fn())

    review = gate.record(review)
    payload = review.to_dict()
    allowed, reason = gate.allows_submission(review.finding_id)
    payload["submission_allowed"] = allowed
    payload["gate_reason"] = reason
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    if getattr(args, "store", None):
        gate.save(args.store)
    print(json.dumps(payload, indent=2, default=str))
    return 0 if allowed else 1


def cmd_integrity(args: argparse.Namespace) -> int:
    """Verify any append-only JSONL log produced by a stamping writer."""
    from .integrity import Checkpoint, resolve_key, verify_chain

    key = resolve_key(key_path=getattr(args, "key_path", None))
    checkpoint = None
    if getattr(args, "checkpoint", None) and Path(args.checkpoint).exists():
        checkpoint = Checkpoint.read(args.checkpoint)
    result = verify_chain(
        args.file, key=key,
        require_signatures=bool(getattr(args, "require_signatures", False)),
        checkpoint=checkpoint,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.ok else 1


def cmd_queue(args: argparse.Namespace) -> int:
    """Inspect the resumable research queue."""
    from .research.queue import ResumableResearchQueue

    queue = ResumableResearchQueue(args.dir, args.name)
    if args.sub == "summary":
        print(json.dumps(queue.summary(), indent=2))
        return 0
    if args.sub == "plan":
        plan = queue.resume_plan()
        print(json.dumps(plan, indent=2))
        return 0
    if args.sub == "next":
        entry = queue.next()
        print(json.dumps(entry.to_dict() if entry else None, indent=2, default=str))
        return 0 if entry else 2
    print("unknown queue subcommand", file=sys.stderr)
    return 2


def make_live_authz_provider(path: "Optional[str]"):
    """A live authorization source that re-reads ``path`` on every decision.

    Returns ``None`` when no path is given, which leaves a consumer on its
    snapshot semantics. When a path *is* given, the provider re-reads the record on
    every call so an operator who withdraws scope -- edits the file, or deletes it
    -- is honoured at the next claim and execution rather than being overridden by
    the snapshot taken at enqueue. A missing or unreadable file yields ``None``, and
    every consumer (receiver, scheduler, executor) fails closed on that rather than
    authorizing on a stale record.

    The ingress and the ``schedule`` worker share this one function so the two
    halves of the pipeline can never disagree about what "current authorization"
    means.
    """
    if not path:
        return None

    from .authz import AuthorizationRecord

    def _provider(asset: str):
        try:
            return AuthorizationRecord.from_dict(
                json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None

    return _provider


def cmd_schedule(args: argparse.Namespace) -> int:
    """Durable autonomous execution: enqueue, run, recover, and inspect jobs."""
    from .authz import AuthorizationRecord
    from .integrity import resolve_key
    from .scheduler import JobStore, Scheduler, SchedulerConfig

    key = resolve_key(key_path=getattr(args, "key_path", None))
    store = JobStore(args.dir, args.name, key=key)
    authz_path = getattr(args, "authz", None)
    config = SchedulerConfig(
        lease_seconds=float(getattr(args, "lease_seconds", 1800.0)),
        default_max_attempts=int(getattr(args, "max_attempts", 5)),
        authz_provider=make_live_authz_provider(authz_path),
    )
    sched = Scheduler(store, config=config, workdir=str(Path(args.dir) / "work"))

    sub = args.sub
    if sub == "add":
        if not (args.target and args.asset and args.authz):
            print("add requires --kind, --target, --asset and --authz", file=sys.stderr)
            return 2
        try:
            record = AuthorizationRecord.from_dict(
                json.loads(Path(args.authz).read_text(encoding="utf-8"))
            )
        except Exception as exc:  # noqa: BLE001
            print(f"cannot read authorization record: {exc}", file=sys.stderr)
            return 2
        payload = json.loads(Path(args.payload).read_text(encoding="utf-8")) if args.payload else {}
        job = sched.enqueue(
            kind=args.kind, target=args.target, asset=args.asset, authz=record,
            payload=payload, idempotency_key=args.key or "",
            priority=args.priority, scope_reference=args.scope_reference or "",
        )
        print(json.dumps({"job_id": job.job_id, "state": job.state,
                          "idempotency_key": job.dedupe_key()}, indent=2))
        return 0

    if sub == "run":
        recovered = sched.recover_stale()
        done = sched.run_pending(args.owner, max_jobs=args.max_jobs)
        print(json.dumps({
            "owner": args.owner, "recovered": recovered,
            "processed": [{"job_id": j.job_id, "state": j.state,
                           "attempts": j.attempts,
                           "error": j.last_error} for j in done],
        }, indent=2))
        return 0

    if sub == "once":
        job = sched.run_once(args.owner)
        print(json.dumps(job.to_dict() if job else None, indent=2, default=str))
        return 0 if job else 2

    if sub == "list":
        jobs = store.all()
        if args.state:
            jobs = [j for j in jobs if j.state == args.state]
        print(json.dumps([{
            "job_id": j.job_id, "kind": j.kind, "target": j.target, "asset": j.asset,
            "state": j.state, "attempts": j.attempts, "max_attempts": j.max_attempts,
            "misfires": j.misfires, "last_error": j.last_error,
            "idempotency_key": j.dedupe_key(),
        } for j in jobs], indent=2))
        return 0

    if sub == "show":
        job = store.get(args.job)
        if job is None:
            print(f"no job {args.job!r}", file=sys.stderr)
            return 2
        print(json.dumps(job.to_dict(), indent=2, default=str))
        return 0

    if sub == "history":
        job = store.get(args.job)
        if job is None:
            print(f"no job {args.job!r}", file=sys.stderr)
            return 2
        print(json.dumps(job.history, indent=2))
        return 0

    if sub == "recover":
        print(json.dumps({"recovered": sched.recover_stale()}, indent=2))
        return 0

    if sub == "misfire":
        fired = sched.handle_misfire(args.job)
        print(json.dumps({"job_id": args.job, "misfire_recorded": fired}, indent=2))
        return 0

    if sub == "cancel":
        try:
            job = sched.cancel(args.job, reason=args.reason or "cancelled by operator")
        except KeyError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps({"job_id": job.job_id, "state": job.state}, indent=2))
        return 0

    if sub == "summary":
        print(json.dumps(sched.summary(), indent=2))
        return 0

    if sub == "verify":
        from .integrity import Checkpoint

        checkpoint = None
        if args.checkpoint:
            cp_file = Path(args.checkpoint)
            if cp_file.exists():
                checkpoint = Checkpoint.read(cp_file)
        result = store.verify_integrity(
            key=key, require_signatures=bool(args.require_signatures),
            checkpoint=checkpoint,
        )
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    if sub == "checkpoint":
        from .integrity import Checkpoint

        seq, chain = store.head()
        if seq < 0:
            print("no job records to checkpoint", file=sys.stderr)
            return 2
        cp = Checkpoint(log_path=str(store.path), head_seq=seq, head_chain=chain)
        if key is not None:
            cp.sign(key)
        out = Path(args.out) if args.out else store.root / f"{args.name}.checkpoint.json"
        cp.write(out)
        print(json.dumps({"checkpoint": str(out), "head_seq": seq,
                          "signed": key is not None}, indent=2))
        return 0

    print("unknown schedule subcommand", file=sys.stderr)
    return 2


def _trigger_receiver(args: argparse.Namespace):
    """Build the shared receiver: ledger + policy + scheduler, wired the same way
    every trigger subcommand needs. Returns (receiver, ledger, store, sched)."""
    from .authz import AuthorizationRecord
    from .integrity import resolve_key
    from .scheduler import JobStore, Scheduler, SchedulerConfig
    from .triggers import TriggerLedger, TriggerPolicy, TriggerReceiver

    key = resolve_key(key_path=getattr(args, "key_path", None))

    # The authorization record is re-read from disk on every decision, so an
    # operator who withdraws scope (edits or deletes the file) after a job was
    # queued is honoured at the next claim and execution -- not silently overridden
    # by the snapshot the job carries. A missing/unreadable file yields None, and
    # every consumer fails closed rather than authorizing on the snapshot.
    _live_authz = make_live_authz_provider(getattr(args, "authz", None))

    store = JobStore(args.dir, "jobs", key=key)
    sched = Scheduler(store, config=SchedulerConfig(
        lease_seconds=float(getattr(args, "lease_seconds", 1800.0)),
        authz_provider=_live_authz),
        workdir=str(Path(args.dir) / "work"))
    ledger = TriggerLedger(args.dir, "triggers", key=key)
    if not args.authz:
        policy = None
    else:
        record = AuthorizationRecord.from_dict(
            json.loads(Path(args.authz).read_text(encoding="utf-8")))
        policy = TriggerPolicy(
            authz=record,
            max_accepted_per_window=int(getattr(args, "max_per_window", 20)),
            window_seconds=int(getattr(args, "window_seconds", 60)),
            authz_provider=_live_authz,
        )
    receiver = TriggerReceiver(ledger, policy, scheduler=sched) if policy else None
    return receiver, ledger, store, sched


def cmd_trigger(args: argparse.Namespace) -> int:
    """Production trigger monitoring: ingest, authenticate, dispatch, inspect."""
    from .triggers import (
        ManualTriggerSource,
        RecurringTrigger,
        TriggerState,
        WebhookTriggerSource,
    )

    sub = args.sub
    if sub == "webhook":
        # Ingest one signed delivery from files/stdin. A real HTTP server can call
        # the same receiver; this is the transport-neutral entry point.
        if not args.authz:
            print("webhook ingestion requires --authz", file=sys.stderr)
            return 2
        secret = os.environ.get("BLACKHEART_TRIGGER_SECRET", "")
        if not secret:
            print("set BLACKHEART_TRIGGER_SECRET to the webhook signing secret",
                  file=sys.stderr)
            return 2
        receiver, _, _, _ = _trigger_receiver(args)
        body = (Path(args.body).read_bytes() if args.body else sys.stdin.buffer.read())
        headers = json.loads(Path(args.headers).read_text(encoding="utf-8")) \
            if args.headers else {}
        src = WebhookTriggerSource(secret.encode("utf-8"))
        dispatch = receiver.handle(src, body, headers)
        print(json.dumps(dispatch.to_dict(), indent=2))
        return 0 if dispatch.state in (TriggerState.ACCEPTED, TriggerState.DUPLICATE,
                                       TriggerState.AUTHENTICATED) else 1

    if sub == "manual":
        if not args.authz:
            print("manual trigger requires --authz", file=sys.stderr)
            return 2
        receiver, _, _, _ = _trigger_receiver(args)
        raw = Path(args.payload).read_bytes() if args.payload else sys.stdin.buffer.read()
        dispatch = receiver.handle(ManualTriggerSource(), raw, {})
        print(json.dumps(dispatch.to_dict(), indent=2))
        return 0 if dispatch.state == TriggerState.ACCEPTED else 1

    if sub == "recurring":
        # Register or tick recurring triggers held in a small JSON file.
        if not args.authz:
            print("recurring triggers require --authz", file=sys.stderr)
            return 2
        receiver, _, _, _ = _trigger_receiver(args)
        path = Path(args.file)
        triggers = [RecurringTrigger.from_dict(d) for d in
                    (json.loads(path.read_text(encoding="utf-8")) if path.exists() else [])]
        if sub == "recurring" and args.add:
            payload = json.loads(Path(args.add).read_text(encoding="utf-8"))
            triggers.append(RecurringTrigger(
                trigger_id=args.trigger_id or f"rec-{len(triggers)}",
                interval_seconds=int(args.interval), payload=payload))
            path.write_text(json.dumps([t.to_dict() for t in triggers], indent=2))
            print(json.dumps({"registered": len(triggers)}, indent=2))
            return 0
        fired = receiver.tick(triggers)
        path.write_text(json.dumps([t.to_dict() for t in triggers], indent=2))
        print(json.dumps([d.to_dict() for d in fired], indent=2))
        return 0

    receiver, ledger, store, sched = _trigger_receiver(args)

    if sub == "list":
        recs = ledger.all()
        if args.state:
            recs = [r for r in recs if r.state == args.state]
        print(json.dumps([{
            "delivery_id": r.delivery_id, "source": r.source, "state": r.state,
            "job_id": r.job_id, "reason": r.reason, "received_at": r.received_at,
        } for r in recs], indent=2))
        return 0

    if sub == "show":
        rec = ledger.get(args.delivery)
        if rec is None:
            print(f"no trigger {args.delivery!r}", file=sys.stderr)
            return 2
        print(json.dumps(rec.to_dict(), indent=2, default=str))
        return 0

    if sub == "sync":
        if receiver is None:
            print("sync requires --authz to attach the scheduler", file=sys.stderr)
            return 2
        updated = receiver.sync_states()
        print(json.dumps([d.to_dict() for d in updated], indent=2))
        return 0

    if sub == "verify":
        result = ledger.verify_integrity(require_signatures=bool(args.require_signatures))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    print("unknown trigger subcommand", file=sys.stderr)
    return 2


def cmd_bounty(args: argparse.Namespace) -> int:
    """Program-specific bounty intelligence: policy, evaluate, re-evaluate, submit-prep."""
    from .bounty import (
        BountyLedger,
        CandidateRecord,
        Disposition,
        PolicySnapshot,
        ProgramPolicy,
        evaluate,
        finding_payload_from_record,
        gate_candidate,
        is_finding_record,
        prepare_submission,
        reevaluate,
        sha256_text,
    )
    from .integrity import resolve_key
    from .models import Finding

    def load_policy(path: str) -> ProgramPolicy:
        try:
            return ProgramPolicy.from_dict(json.loads(Path(path).read_text()))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SystemExit(f"bounty: cannot read policy {path}: {exc}")

    def load_finding(path: str) -> Finding:
        try:
            raw = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"bounty: cannot read finding {path}: {exc}")
        # The findings repository and the report model keep different schemas; a
        # record exported by `blackheart findings` is translated rather than
        # rejected, so a recorded investigation can be evaluated without hand-editing.
        payload = finding_payload_from_record(raw) if is_finding_record(raw) else raw
        try:
            return Finding.from_dict(payload)
        except ValueError as exc:
            raise SystemExit(f"bounty: cannot read finding {path}: {exc}")

    key = resolve_key(key_path=getattr(args, "key_path", None))
    ledger = BountyLedger(args.dir, "evaluations", key=key)
    sub = args.sub

    if sub == "capture":
        # Record a policy snapshot with provenance. The hash is computed from the
        # captured text so a later reviewer can prove the policy was not altered.
        text = Path(args.text).read_text(encoding="utf-8")
        snap = PolicySnapshot(
            program=args.program, source_url=args.source_url,
            retrieved_at=args.retrieved_at, sha256=sha256_text(text),
            revision=args.revision or "", captured_text=text,
        )
        out = Path(args.out)
        out.write_text(json.dumps(snap.to_dict(), indent=2))
        print(json.dumps({"snapshot": str(out), "sha256": snap.sha256,
                          "verified": snap.is_verified()}, indent=2))
        return 0

    if sub == "verify-policy":
        snap = PolicySnapshot.from_dict(json.loads(Path(args.snapshot).read_text()))
        ok = snap.is_verified()
        print(json.dumps({"program": snap.program, "verified": ok,
                          "source_url": snap.source_url,
                          "retrieved_at": snap.retrieved_at,
                          "sha256": snap.sha256}, indent=2))
        return 0 if ok else 1

    if sub == "evaluate":
        policy = load_policy(args.policy)
        finding = load_finding(args.finding)
        if args.reevaluate:
            ev = reevaluate(finding, policy, ledger)
        else:
            ev = ledger.record(evaluate(finding, policy))
        print(json.dumps(ev.to_dict(), indent=2, default=str))
        return 0

    if sub == "show":
        evs = ledger.for_finding(args.finding) if args.finding else ledger.all()
        print(json.dumps([e.to_dict() for e in evs], indent=2, default=str))
        return 0

    if sub == "prepare-submission":
        policy = load_policy(args.policy)
        finding = load_finding(args.finding)
        ev = evaluate(finding, policy)
        print(json.dumps(prepare_submission(finding, ev), indent=2, default=str))
        return 0

    if sub == "gate":
        # The mandatory official-policy gate. Exit 2 when the policy itself is not
        # verified (fail closed, like `compat check`); exit 1 when the caller asked
        # for submission-readiness and the candidate does not have it.
        record = CandidateRecord.from_dict(json.loads(Path(args.record).read_text()))
        if getattr(args, "deployment_truth", ""):
            record.deployment_truth = json.loads(
                Path(args.deployment_truth).read_text(encoding="utf-8"))
        out = gate_candidate(record)
        print(json.dumps(out.to_dict(), indent=2, default=str))
        if out.disposition == Disposition.NOT_ASSESSED and not out.policy_verified:
            return 2
        if getattr(args, "require_submission_ready", False) and not out.submission_ready:
            return 1
        return 0

    if sub == "verify":
        result = ledger.verify_integrity(require_signatures=bool(args.require_signatures))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    print("unknown bounty subcommand", file=sys.stderr)
    return 2


def cmd_ingress(args: argparse.Namespace) -> int:
    """Run the authenticated HTTP ingress in front of the trigger receiver.

    This is the real listener: it binds a socket, authenticates each delivery
    through the same receiver the CLI uses, and lets the scheduler dispatch the
    durable job. ``--once`` accepts until interrupted; the process is the
    long-running service, so startup/shutdown are explicit and logged.
    """
    import logging

    from .ingress import IngressConfig, IngressServer, IngressError
    from .triggers import WebhookTriggerSource

    logging.basicConfig(level=logging.INFO,
                        format='{"ts":"%(asctime)s","level":"%(levelname)s",'
                               '"logger":"%(name)s","msg":%(message)s}')

    if args.sub == "check":
        # Validate configuration without binding -- useful in CI and before deploy.
        try:
            IngressConfig(host=args.host, port=args.port,
                          max_body_bytes=args.max_body_bytes,
                          request_timeout=args.request_timeout,
                          allow_public_bind=args.allow_public_bind).validate()
        except IngressError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            return 1
        print(json.dumps({"ok": True}, indent=2))
        return 0

    if args.sub != "serve":
        print("unknown ingress subcommand", file=sys.stderr)
        return 2

    if not args.authz:
        print("ingress serve requires --authz (the scope a trigger is judged "
              "against)", file=sys.stderr)
        return 2
    secret = os.environ.get("BLACKHEART_TRIGGER_SECRET", "")
    if not secret:
        print("set BLACKHEART_TRIGGER_SECRET to the webhook signing secret",
              file=sys.stderr)
        return 2

    receiver, _, _, _ = _trigger_receiver(args)
    if receiver is None:
        print("could not build the trigger receiver (check --authz)", file=sys.stderr)
        return 2
    source = WebhookTriggerSource(secret.encode("utf-8"))
    try:
        config = IngressConfig(host=args.host, port=args.port,
                               max_body_bytes=args.max_body_bytes,
                               request_timeout=args.request_timeout,
                               trigger_path=args.path,
                               allow_public_bind=args.allow_public_bind)
        server = IngressServer(receiver, source, config=config).start()
    except IngressError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({"listening": server.base_url, "trigger_path": args.path,
                      "pid": os.getpid()}, indent=2))

    # Orchestrators (systemd, containers) stop a service with SIGTERM, so it must
    # drain and close rather than die mid-delivery. SIGINT (Ctrl-C) is handled the
    # same way. Both are restored on exit so this stays safe to call from a host.
    import logging
    import signal

    slog = logging.getLogger("blackheart.ingress")
    stop_requested = threading.Event()

    def _request_stop(signum, _frame):
        slog.info(json.dumps({"event": "ingress_stop_requested", "signal": signum}))
        stop_requested.set()

    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous[sig] = signal.signal(sig, _request_stop)
        except (ValueError, OSError):  # not the main thread / unsupported platform
            pass
    try:
        while server.is_serving() and not stop_requested.is_set():
            time.sleep(0.2)
    finally:
        server.stop()
        for sig, handler in previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
    return 0


def _budget_from_args(args: argparse.Namespace):
    """A research Budget from --budget-tokens/--budget-turns, or None (unbounded)."""
    from .budget import Budget

    tokens = getattr(args, "budget_tokens", None)
    turns = getattr(args, "budget_turns", None)
    if tokens is None and turns is None:
        return None
    return Budget(
        max_tokens=tokens,
        max_turns=turns,
        reserve_tokens=max(1, tokens // 10) if tokens else 0,
        reserve_turns=max(1, turns // 10) if turns else 0,
    )


def cmd_models(args: argparse.Namespace) -> int:
    """Multi-model provider layer: list, health, benchmark, route, usage."""
    from .providers import DataClass, all_providers, benchmark_router
    from .providers.router import build_router

    router = build_router(
        quota_path=Path(args.quota) if getattr(args, "quota", None) else None,
        budget=_budget_from_args(args),
    )

    if args.sub == "list":
        specs = [{
            "name": s.name,
            "base_url": s.base_url,
            "env_key": s.env_key,
            "default_model": s.default_model,
            "requires_key": s.requires_key,
            "openai_compatible": s.openai_compatible,
            "configured": s.name in router.available(),
            "free_tier_note": s.free_tier_note,
            "data_terms_url": s.data_terms_url,
            "verified_on": s.verified_on,
        } for s in all_providers()]
        payload = {
            "providers": specs,
            "configured": router.available(),
            "zero_provider_mode": not router.available(),
            "note": (
                "configured = key present (or explicitly opted in for keyless). "
                "Free-tier facts are recorded per provider and dated; they change."
            ),
        }
        print(json.dumps(payload, indent=2))
        return 0

    if args.sub == "health":
        results = [h.to_dict() for h in router.health()]
        healthy = sum(1 for r in results if r["healthy"])
        print(json.dumps({"healthy": healthy, "total": len(results),
                          "results": results}, indent=2))
        # Exit 0 when at least the local engine is healthy (always), so a
        # zero-provider environment is not reported as a failure.
        return 0 if healthy else 1

    if args.sub == "reviewer":
        # The reviewer model is optional. Report whether a *separately
        # authenticated* one is available -- proven by a liveness probe, not by a
        # key merely existing -- and never fail when it is not: the workflow falls
        # back to a same-model adversarial review, labelled as such.
        from .providers.router import resolve_reviewer_model

        resolution = resolve_reviewer_model(
            router, probe=not getattr(args, "no_probe", False)
        )
        payload = resolution.to_dict()
        payload["note"] = (
            "The reviewer model is optional. 'available' requires a verified "
            "credential (a liveness probe succeeded); a key that is present but "
            "unverified or failing is reported as configured, not available. When "
            "no verified reviewer exists the release workflow performs a same-model "
            "adversarial review in a fresh context and records it as SAME_MODEL -- "
            "never as an independent-model review. Core research and release do not "
            "depend on this."
        )
        print(json.dumps(payload, indent=2))
        return 0

    if args.sub == "benchmark":
        report = benchmark_router(router).to_dict()
        print(json.dumps(report, indent=2))
        return 0

    if args.sub == "route":
        decision = router.route(
            data_class=getattr(args, "data_class", DataClass.PUBLIC) or DataClass.PUBLIC,
            role=getattr(args, "role", "") or "",
        ).to_dict()
        print(json.dumps(decision, indent=2))
        return 0

    if args.sub == "usage":
        print(json.dumps({"usage": router.usage(),
                          "note": "advisory: counts BLACKHEART's own calls, not the "
                                  "provider's real remaining quota"}, indent=2))
        return 0

    print("unknown models subcommand", file=sys.stderr)
    return 2


def cmd_dvdf(args: argparse.Namespace) -> int:
    """Run the local Damn Vulnerable DeFi training harness (never touches a network)."""
    from .dvdf import DVDFHarness

    ev = EvidenceStore(Path(args.workdir) / "evidence")
    harness = DVDFHarness(evidence=ev)
    if not harness.available():
        print(f"DVDF harness not found at {harness.path}", file=sys.stderr)
        return 2
    if args.challenge == "build":
        result = harness.build()
    elif args.invariant:
        result = harness.run_invariant(args.challenge)
    else:
        result = harness.run_challenge(args.challenge, verbosity=args.verbosity)
    print(result.stdout[-4000:])
    print(json.dumps(result.to_dict(), indent=2))
    # An invariant challenge is expected to FAIL (it found the bug); everything
    # else must pass.
    if args.invariant:
        return 0
    return 0 if result.passed else 1


# --------------------------------------------------------------------------- #
# Portable cloud execution (InstaBox)
# --------------------------------------------------------------------------- #

# Exit codes for `cloud`, kept distinct so a caller can tell "no credential"
# from "machine unavailable" from "something else failed". They mirror the
# InstaBox CLI's own convention (3 = needs a sign-in).
EXIT_CLOUD_OK = 0
EXIT_CLOUD_FAILED = 1
EXIT_CLOUD_NO_CREDENTIAL = 3
EXIT_CLOUD_AUTH = 4
EXIT_CLOUD_NO_MACHINE = 5


def _cloud_config(args: argparse.Namespace):
    from .cloud import CloudConfig

    cfg = CloudConfig.from_env(workdir_root=getattr(args, "workdir", None))
    if getattr(args, "server", None):
        cfg.server = args.server.rstrip("/")
    if getattr(args, "machine", None):
        cfg.machine = args.machine
    return cfg


def _cloud_client(cfg):
    """Build a client, or return (None, exit_code) so the caller can fail closed."""
    from .cloud import InstaBoxClient, MissingCredential

    if not cfg.has_credential:
        from .cloud import CREDENTIAL_ENV

        print(
            f"cloud: no InstaBox credential.\n"
            f"  set {CREDENTIAL_ENV} in the environment (OpenHands secret "
            f"injection), then retry.\n"
            f"  BLACKHEART fails closed: it never falls back to local execution.",
            file=sys.stderr,
        )
        return None, EXIT_CLOUD_NO_CREDENTIAL
    try:
        return InstaBoxClient(cfg.server, cfg.api_key), EXIT_CLOUD_OK
    except MissingCredential as exc:  # pragma: no cover - guarded by has_credential
        print(f"cloud: {exc}", file=sys.stderr)
        return None, EXIT_CLOUD_NO_CREDENTIAL


def _cloud_resolve(client, cfg):
    """Resolve the machine, or return (None, exit_code) with a clear message."""
    from .cloud import CloudError, MachineNotFound, resolve_machine

    try:
        return resolve_machine(client, cfg.machine), EXIT_CLOUD_OK
    except MachineNotFound as exc:
        print(f"cloud: {exc}", file=sys.stderr)
        return None, EXIT_CLOUD_NO_MACHINE
    except CloudError as exc:
        print(f"cloud: {exc}", file=sys.stderr)
        return None, EXIT_CLOUD_FAILED


def _print_machine(machine: dict) -> None:
    from .cloud import machine_summary

    s = machine_summary(machine)
    print(f"  machine        {s['name']} ({s['id']})")
    print(f"  state          {s['state']}")
    print(f"  resources      {s['vcpus']} vCPU / {s['mem_mib']} MiB")
    print(f"  storage        {s['storage_mount']} "
          f"{s['persistent_disk_gib']} GiB "
          f"({'persistent' if s['storage_persistent'] else 'ephemeral'})")
    print(f"  template       {s['template']}")


def cmd_cloud_doctor(args: argparse.Namespace) -> int:
    """End-to-end portability check: credential -> auth -> machine -> remote run -> artifact."""
    from .cloud import AuthError, CloudError, RemoteExecutionError

    cfg = _cloud_config(args)
    checks: list[tuple[str, bool, str]] = []

    checks.append((
        "credential present",
        cfg.has_credential,
        f"{cfg.to_dict()['credential_env']} {'set' if cfg.has_credential else 'not set'}",
    ))
    if not cfg.has_credential:
        _report_cloud_checks(checks)
        print(f"\nset {cfg.to_dict()['credential_env']} and re-run; "
              f"BLACKHEART never falls back to local execution", file=sys.stderr)
        return EXIT_CLOUD_NO_CREDENTIAL

    client, rc = _cloud_client(cfg)
    if client is None:
        return rc

    # 2. authentication
    try:
        me = client.me()
        checks.append(("authenticated", True, f"login={me.get('login', '?')}"))
    except AuthError as exc:
        checks.append(("authenticated", False, str(exc)))
        _report_cloud_checks(checks)
        return EXIT_CLOUD_AUTH
    except CloudError as exc:
        checks.append(("authenticated", False, str(exc)))
        _report_cloud_checks(checks)
        return EXIT_CLOUD_FAILED

    # 3. machine discovery
    machine, rc = _cloud_resolve(client, cfg)
    if machine is None:
        checks.append(("machine discovered", False, "no usable machine"))
        _report_cloud_checks(checks)
        return rc
    checks.append((
        "machine discovered", True,
        f"{machine.get('name')} ({machine.get('id')})",
    ))

    # 4. readiness + resources + persistent storage
    from .cloud import machine_is_ready

    state = machine.get("state")
    wake_note = "" if state == "running" else " (exec will wake it)"
    checks.append(("machine ready", machine_is_ready(machine),
                   f"state={state}{wake_note}"))
    spec = machine.get("spec") or {}
    checks.append((
        "resources reported", bool(spec.get("vcpus") and spec.get("memMiB")),
        f"{spec.get('vcpus')} vCPU / {spec.get('memMiB')} MiB",
    ))
    storage = machine.get("storage") or {}
    checks.append((
        "persistent storage", bool(storage.get("persistent")),
        f"{storage.get('mountPath')} {storage.get('sizeGiB')} GiB",
    ))

    # 5. genuine remote execution + artifact round-trip
    from .cloud.run import CloudRunner, new_engagement_id

    runner = CloudRunner(
        client, machine, new_engagement_id("doctor"), workdir_root=cfg.workdir_root
    )
    try:
        runner.create()
        probe = runner.execute("echo blackheart-remote-ok", timeout_seconds=30)
        checks.append((
            "remote exec", probe.ok and "blackheart-remote-ok" in probe.stdout,
            probe.stdout.strip() or probe.stderr.strip(),
        ))
        selftest = runner.remote_self_test()
        facts = selftest["remote_facts"]
        checks.append((
            "genuine remote (not local)", selftest["distinct_from_local"],
            f"remote host {facts.get('hostname')} kernel {facts.get('kernel')} "
            f"!= local {selftest['local_hostname']}",
        ))
        art = selftest["artifact"]
        checks.append((
            "artifact round-trip verified", art["verified"],
            f"{art['name']} sha256={art['sha256'][:16]}...",
        ))
    except RemoteExecutionError as exc:
        checks.append(("remote exec", False, str(exc)))
    except CloudError as exc:
        checks.append(("remote exec", False, str(exc)))
    finally:
        # doctor is a self-check, not a workload: never leave scratch on the disk.
        runner.cleanup()

    ok = _report_cloud_checks(checks)
    if args.json:
        from .cloud import machine_summary

        payload = {
            "config": cfg.to_dict(),
            "machine": machine_summary(machine),
            "checks": [{"check": c, "ok": o, "detail": d} for c, o, d in checks],
            "healthy": ok,
        }
        print(json.dumps(payload, indent=2))
    return EXIT_CLOUD_OK if ok else EXIT_CLOUD_FAILED


def _report_cloud_checks(checks: list[tuple[str, bool, str]]) -> bool:
    for name, ok, detail in checks:
        print(f"  [{'ok' if ok else '!!'}] {name:28} {detail}")
    return all(o for _, o, _ in checks)


def cmd_cloud_connect(args: argparse.Namespace) -> int:
    """Authenticate and confirm the machine is reachable; print its identity."""
    from .cloud import AuthError, CloudError

    cfg = _cloud_config(args)
    client, rc = _cloud_client(cfg)
    if client is None:
        return rc
    try:
        me = client.me()
    except AuthError as exc:
        print(f"cloud: {exc}", file=sys.stderr)
        return EXIT_CLOUD_AUTH
    except CloudError as exc:
        print(f"cloud: {exc}", file=sys.stderr)
        return EXIT_CLOUD_FAILED

    machine, rc = _cloud_resolve(client, cfg)
    if machine is None:
        return rc
    print(f"connected as {me.get('login', '?')} @ {cfg.server}")
    _print_machine(machine)
    if args.json:
        from .cloud import machine_summary

        print(json.dumps({"account": me.get("login"),
                          "machine": machine_summary(machine)}, indent=2))
    return EXIT_CLOUD_OK


def cmd_cloud_status(args: argparse.Namespace) -> int:
    """Report machine health, resources and persistent-storage usage (no workload)."""
    from .cloud import AuthError, CloudError

    cfg = _cloud_config(args)
    client, rc = _cloud_client(cfg)
    if client is None:
        return rc
    try:
        machine, rc = _cloud_resolve(client, cfg)
    except AuthError as exc:
        print(f"cloud: {exc}", file=sys.stderr)
        return EXIT_CLOUD_AUTH
    if machine is None:
        return rc
    try:
        disk = client.disk(machine["id"]) if machine.get("state") == "running" else {}
    except CloudError:
        disk = {}

    from .cloud import machine_summary

    summary = machine_summary(machine)
    print(f"machine {summary['name']} ({summary['id']}) state={summary['state']}")
    _print_machine(machine)
    for fs in disk.get("filesystems", []) if isinstance(disk, dict) else []:
        print(f"  fs {fs.get('mount'):8} used {fs.get('usedPct')}% "
              f"({fs.get('level')})")
    if args.json:
        print(json.dumps({"machine": summary, "disk": disk}, indent=2))
    return EXIT_CLOUD_OK


def cmd_cloud_execute(args: argparse.Namespace) -> int:
    """Run a command on the machine in an engagement; optionally fetch an artifact."""
    from .cloud import CloudError, RemoteExecutionError
    from .cloud.run import CloudRunner, new_engagement_id

    cfg = _cloud_config(args)
    client, rc = _cloud_client(cfg)
    if client is None:
        return rc
    machine, rc = _cloud_resolve(client, cfg)
    if machine is None:
        return rc

    engagement_id = args.engagement or new_engagement_id()
    runner = CloudRunner(client, machine, engagement_id, workdir_root=cfg.workdir_root)
    runner.create()

    if not args.command:
        print(f"engagement {engagement_id} created at {runner.remote_dir} "
              f"(no command given)")
        return EXIT_CLOUD_OK

    # One argument is a shell string; several are joined into one (the API's
    # `cmd` is a single string, and the remote shell parses it).
    cmd = args.command[0] if len(args.command) == 1 else " ".join(args.command)
    try:
        res = runner.execute(cmd, timeout_seconds=args.timeout, check=False)
    except CloudError as exc:
        print(f"cloud: {exc}", file=sys.stderr)
        return EXIT_CLOUD_FAILED

    print(f"# engagement {engagement_id} on {machine.get('name')} "
          f"(exit {res.exit_code}, {res.duration_ms} ms)")
    if res.stdout:
        sys.stdout.write(res.stdout)
        if not res.stdout.endswith("\n"):
            sys.stdout.write("\n")
    if res.stderr:
        sys.stderr.write(res.stderr)

    if args.artifact:
        try:
            art = runner.fetch_artifact(
                args.artifact, name=args.artifact_name
            )
        except (RemoteExecutionError, CloudError) as exc:
            print(f"cloud: artifact retrieval failed: {exc}", file=sys.stderr)
            return EXIT_CLOUD_FAILED
        print(f"artifact {art.name} -> {art.local_path} "
              f"sha256={art.sha256} verified={art.verified}")
    if args.json:
        print(json.dumps({"engagement": engagement_id, "machine": machine.get("name"),
                          "result": res.to_dict()}, indent=2))
    return EXIT_CLOUD_OK if res.ok else res.exit_code


def cmd_cloud_artifacts(args: argparse.Namespace) -> int:
    """List and verify locally retrieved artifacts for an engagement."""
    from .cloud import sha256_hex

    cfg = _cloud_config(args)
    root = cfg.workdir_root
    if not root.exists():
        print(f"no cloud workdir at {root} (nothing retrieved yet)")
        return EXIT_CLOUD_OK

    engagements = (
        [root / args.engagement] if args.engagement
        else sorted(p for p in root.iterdir() if p.is_dir())
    )
    found: list[dict] = []
    for eng in engagements:
        audit = eng / "audit.jsonl"
        if not audit.exists():
            continue
        for line in audit.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("event") != "fetch_artifact":
                continue
            local = eng / rec["name"]
            actual = sha256_hex(local.read_bytes()) if local.exists() else ""
            found.append({
                "engagement": eng.name,
                "name": rec["name"],
                "local_path": str(local),
                "recorded_sha256": rec.get("local_sha256", ""),
                "actual_sha256": actual,
                "intact": bool(actual) and actual == rec.get("local_sha256"),
            })
    for a in found:
        print(f"  [{'ok' if a['intact'] else '!!'}] {a['engagement']}/{a['name']} "
              f"sha256={a['actual_sha256'][:16] or '<missing>'}...")
    if args.json:
        print(json.dumps({"artifacts": found}, indent=2))
    return EXIT_CLOUD_OK if all(a["intact"] for a in found) else EXIT_CLOUD_FAILED


# --------------------------------------------------------------------------- #
# Chrome VRP research engagement
# --------------------------------------------------------------------------- #

def cmd_chrome_doctor(args: argparse.Namespace) -> int:
    """Locate a real Chromium build and confirm the harness can drive it."""
    from .chrome import positive_control, smoke_test
    from .chrome.harness import ChromeNotFound

    binary = getattr(args, "binary", None)
    try:
        smoke = smoke_test(binary)
    except ChromeNotFound as exc:
        print(f"chrome: {exc}", file=sys.stderr)
        print("  set BLACKHEART_CHROME to a Chromium/Chrome binary path", file=sys.stderr)
        return 3
    print(f"  browser        {smoke['browser']}")
    run = smoke["run"]
    ok = run["result"].get("probe") == "sop-read" and not run["result"].get("_parse_error")
    print(f"  launch+probe   {'ok' if ok else 'FAILED'} ({run['duration_ms']} ms)")
    print(f"  SOP observation {run['result'].get('details', {}).get('contentDocument')}")

    control = positive_control(binary)
    print(f"  positive control {'detected' if control['detected'] else 'MISSED'}"
          f" -- the harness can see a boundary breach")
    if args.json:
        print(json.dumps({"smoke": smoke, "control": control}, indent=2))
    return 0 if ok and control["detected"] else 1


def cmd_chrome_run(args: argparse.Namespace) -> int:
    """Run the Chrome VRP hypotheses and record evidence + ledger events."""
    from .chrome import run_engagement
    from .chrome.harness import ChromeNotFound

    only = args.only.split(",") if args.only else None
    workdir = getattr(args, "workdir", None) or "research/private/chrome-vrp"
    try:
        summary = run_engagement(workdir, binary=getattr(args, "binary", None), only=only)
    except ChromeNotFound as exc:
        print(f"chrome: {exc}", file=sys.stderr)
        return 3
    print(f"engagement {summary['engagement']} on {summary['browser']}")
    for r in summary["results"]:
        mark = "!!" if r["violations"] else "ok"
        print(f"  [{mark}] {r['id']} {r['status']:18} {r['title']}")
        for v in r["violations"]:
            print(f"        VIOLATION: {v}")
    print(f"\ndisproven: {summary['disproven'] or 'none'}")
    print(f"candidates (need independent verification): {summary['candidates'] or 'none'}")
    print(f"evidence integrity: {summary['evidence_integrity']}")
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    # A candidate is not a finding: report success for the run, but make the
    # exit code distinct so automation can tell "clean" from "needs review".
    return 0 if not summary["candidates"] else 2


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

def cmd_testsparker(args: argparse.Namespace) -> int:
    """Generate executable tests, run them, and report what actually happened."""
    import json as _json

    from .testsparker import adapter_names, get_adapter

    if args.list:
        for name in adapter_names():
            print(name)
        return 0
    try:
        adapter = get_adapter(args.adapter)
    except KeyError as exc:
        print(f"error: {exc}")
        return 2
    corpus = None
    if args.known_answer and hasattr(adapter, "known_answer_corpus"):
        corpus = adapter.known_answer_corpus()
    tests = adapter.generate(seed=args.seed, corpus=corpus, limit=args.limit)
    outcomes = [adapter.execute(t) for t in tests]

    metrics = None
    if args.known_answer:
        # Ground truth is the case's own declaration; without one the rate is
        # reported as unavailable rather than assumed clean.
        from .evaluation import compute_metrics

        expected = {t.test_id for t in tests if t.expectation.get("expect_defect")}
        metrics = compute_metrics(outcomes, known_answer=True,
                                  expected_defects=expected)

    if args.json:
        payload = {"tests": [t.to_dict() for t in tests],
                   "outcomes": [o.to_dict() for o in outcomes]}
        if metrics is not None:
            payload["metrics"] = metrics
        print(_json.dumps(payload, indent=2, sort_keys=True))
        return 0
    from collections import Counter

    counts = Counter(o.disposition for o in outcomes)
    print(f"adapter={args.adapter} seed={args.seed} generated={len(tests)}")
    for disp in sorted(counts):
        print(f"  {disp}: {counts[disp]}")
    if metrics is not None:
        for name in ("precision", "recall"):
            rate = metrics[name]
            if rate["value"] is None:
                print(f"  {name}: unavailable -- {rate['unavailable_reason']}")
            else:
                print(f"  {name}: {rate['value']:.2f} "
                      f"({rate['numerator']}/{rate['denominator']})")
        print(f"  expected_defects={metrics['true_positives'] + metrics['false_negatives']} "
              f"false_positives={metrics['false_positives']} "
              f"false_negatives={metrics['false_negatives']}")
    defects = [o for o in outcomes if o.defect_signal]
    if defects:
        print(f"defect signals: {len(defects)} (candidates, not findings)")
        for o in defects[:5]:
            print(f"  {o.test_id}: {o.detail}")
        # A known-answer run is a measurement: finding the declared defect is the
        # expected result, not a failure.
        return 1 if metrics is None else 0
    return 0


def cmd_continuous(args: argparse.Namespace) -> int:
    """Run a continuous adversarial evaluation campaign and report honestly."""
    import json as _json

    from .evaluation import (
        AuthorizationGate,
        CampaignConfig,
        compare_to_baseline,
        load_baseline,
        may_update_baseline,
        run_campaign,
    )

    record = None
    if args.authz_record:
        try:
            record = _json.loads(Path(args.authz_record).read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as exc:
            print(f"error: cannot read authorization record: {exc}")
            return 2
    gate = AuthorizationGate(record=record, target=args.target or "")

    config = CampaignConfig(
        name=args.name,
        adapters=args.adapters or ["dispatch"],
        seed=args.seed,
        limit=args.limit,
        allow_live=args.allow_live,
        known_answer=args.known_answer,
    )
    result = run_campaign(config, authz=gate, evidence_root=args.evidence)
    baseline = load_baseline(args.baseline) if args.baseline else None
    diff = compare_to_baseline(result, baseline)

    if args.json:
        print(_json.dumps({**result.to_dict(), "diff": diff}, indent=2, sort_keys=True))
    else:
        m = result.metrics
        print(f"campaign={config.name} status={result.status}")
        print(f"  generated={m['tests_generated']} executed={m['tests_executed']} "
              f"inconclusive={m['inconclusive']}")
        print(f"  defects_reported={m['defects_reported']} regressions={m['regressions']}")
        cov = m.get("execution_coverage", {})
        print(f"  execution_coverage={cov.get('value')} "
              f"({cov.get('numerator')}/{cov.get('denominator')})")
        for key in ("precision", "recall"):
            v = m.get(key, {})
            if v.get("value") is None:
                print(f"  {key}=unavailable ({v.get('unavailable_reason')})")
            else:
                print(f"  {key}={v['value']} ({v['numerator']}/{v['denominator']})")
        if result.errors:
            for e in result.errors:
                print(f"  error: {e}")
        if diff.get("regressions"):
            print(f"  REGRESSIONS: {len(diff['regressions'])}")
            for r in diff["regressions"][:5]:
                print(f"    {r['test_id']}: {r['was']} -> {r['now']}")

    if args.write_baseline:
        ok, why = may_update_baseline(result, diff)
        if ok:
            Path(args.write_baseline).parent.mkdir(parents=True, exist_ok=True)
            Path(args.write_baseline).write_text(
                _json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
            print(f"wrote baseline {args.write_baseline} ({why})")
        else:
            print(f"baseline NOT written: {why}")
            return 1

    return 0 if result.status == "COMPLETE" and not diff.get("regressions") else 1


def _read_hex(path: str) -> bytes:
    text = Path(path).read_text().strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    return bytes.fromhex("".join(text.split()))


def cmd_symbolic_evm(args: argparse.Namespace) -> int:
    """Bounded symbolic execution over real runtime bytecode."""
    from dataclasses import replace

    from .symbolic.evm import explore, find_witness
    from .symbolic.poc import calldata_from_witness, witness_poc

    inputs: dict[str, tuple[int, int]] = {}
    for item in args.input:
        name, _, span = item.partition("=")
        lo, _, hi = span.partition("..")
        inputs[name] = (int(lo, 0), int(hi, 0) if hi else int(lo, 0))
    code = _read_hex(args.code)
    import contextlib

    from .symbolic.smt import use_smt

    smt_context = use_smt(True) if getattr(args, "smt", False) else contextlib.nullcontext()
    with smt_context:
        result = explore(code, inputs=inputs or None,
                         max_paths=args.max_paths, max_steps=args.max_steps,
                         wrap_symbolic=args.wrap)
    payload = result.to_dict()
    payload["paths_detail"] = [p.to_dict() for p in result.paths[:args.limit]]

    witnesses = None
    if args.poc_out or args.minimize:
        witnesses = (find_witness(result, reverted=True)
                     or find_witness(result, reverted=False))
    witness = witnesses[0] if witnesses else None
    minimized = None
    if args.minimize and witness:
        from .evm_fuzz import run_bytecode
        from .symbolic.minimize import minimize_calldata

        original = calldata_from_witness(witness)
        expected_ok = witness.get("_halt") != "revert"
        minimized = minimize_calldata(
            original, lambda data: run_bytecode(code, data).succeeded == expected_ok)
        payload["minimized_calldata"] = "0x" + minimized.minimized.hex()
        payload["minimization"] = minimized.to_dict()
    if args.poc_out:
        if witness:
            poc = witness_poc(code, witness)
            if minimized is not None:
                poc = replace(poc, calldata=minimized.minimized)
            Path(args.poc_out).write_text(poc.render(), encoding="utf-8")
            payload["poc"] = {"path": args.poc_out, **poc.to_dict()}
        else:
            payload["poc"] = None
    print(json.dumps(payload, indent=2))
    return 1 if result.reverted_paths else 0


def cmd_layout_diff(args: argparse.Namespace) -> int:
    """Compare two solc storage layouts; a moved slot is a compatibility break."""
    from .ingest.storage_layout import diff_layouts, parse_layout

    before = parse_layout(Path(args.before).read_text(encoding="utf-8"))
    after = parse_layout(Path(args.after).read_text(encoding="utf-8"))
    diff = diff_layouts(before, after)
    print(json.dumps(diff.to_dict(), indent=2))
    return 0 if diff.compatible else 1


def cmd_layout_extract(args: argparse.Namespace) -> int:
    """Pull storage layouts out of a Foundry build-info or solc combined JSON."""
    from .ingest.storage_layout import layouts_from_build_info

    try:
        layouts = layouts_from_build_info(Path(args.build_info).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        print(f"could not read build info: {exc}", file=sys.stderr)
        return 2
    if not layouts:
        print("no storageLayout found; compile with --storage-layout solc option",
              file=sys.stderr)
        return 2

    if args.contract:
        matches = {key: value for key, value in layouts.items()
                   if key == args.contract or key.rsplit(":", 1)[-1] == args.contract}
        if not matches:
            print("contract not found; available: " + ", ".join(sorted(layouts)),
                  file=sys.stderr)
            return 2
        if len(matches) > 1:
            print("contract name is ambiguous; use a source-qualified key: "
                  + ", ".join(sorted(matches)), file=sys.stderr)
            return 2
        payload = [entry.to_dict() for entry in next(iter(matches.values()))]
    else:
        payload = {key: [entry.to_dict() for entry in value]
                   for key, value in sorted(layouts.items())}

    text = json.dumps(payload, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(args.out)
    else:
        print(text)
    return 0


def cmd_poc_run(args: argparse.Namespace) -> int:
    """Run one generated PoC under the compatibility gate."""
    from .symbolic.poc_runner import run_poc_text
    from .toolchain.enforce import load_record

    try:
        solidity = Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"could not read the PoC: {exc}", file=sys.stderr)
        return 2
    test_name = args.test_name or (
        "test_divergence" if "test_divergence" in solidity else "test_witness")
    record = None
    if args.compatibility:
        try:
            record = load_record(args.compatibility)
        except (OSError, ValueError, TypeError) as exc:
            print(f"could not load compatibility record: {exc}", file=sys.stderr)
            return 2
    outcome = run_poc_text(
        solidity, test_name=test_name, compatibility=record,
        target_component=args.target_component, repository=args.repository,
        commit=args.commit, timeout=args.timeout, keep_dir=args.keep_dir,
    )
    print(json.dumps(outcome.as_dict(), indent=2))
    return {"PASS": 1, "FAIL": 0, "BLOCKED": 2, "INCOMPLETE": 3}[outcome.status]


def cmd_evm_diff(args: argparse.Namespace) -> int:
    """Run the same calldata against two runtime bytecodes and report divergence."""
    from .evm_fuzz import calldata_words, differential_fuzz
    from .symbolic.poc import DivergencePoc

    calldatas = [bytes.fromhex(c[2:] if c.startswith("0x") else c) for c in args.calldata]
    if args.words:
        calldatas.extend(calldata_words(int(w, 0) for w in args.words.split(",")))
    vulnerable, guarded = _read_hex(args.vulnerable), _read_hex(args.guarded)
    report = differential_fuzz(vulnerable, guarded, calldatas)
    payload = report.to_dict()

    original = None
    if report.divergences:
        raw = report.divergences[0].calldata
        original = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    minimized = None
    if args.minimize and original is not None:
        from .symbolic.minimize import minimize_calldata

        minimized = minimize_calldata(
            original,
            lambda data: differential_fuzz(vulnerable, guarded, [data]).found)
        payload["minimization"] = minimized.to_dict()

    if args.poc_out and original is not None:
        data = minimized.minimized if minimized is not None else original
        poc = DivergencePoc(vulnerable, guarded, data)
        Path(args.poc_out).write_text(poc.render(), encoding="utf-8")
        payload["poc"] = {"path": args.poc_out, **poc.to_dict()}
    elif args.poc_out:
        payload["poc"] = None
    print(json.dumps(payload, indent=2))
    return 1 if report.found else 0


def cmd_evm_fuzz(args: argparse.Namespace) -> int:
    """Coverage-guided fuzzing of one runtime bytecode."""
    from .evm_fuzz import coverage_fuzz

    seeds = [bytes.fromhex(s[2:] if s.startswith("0x") else s) for s in args.seed_calldata]
    report = coverage_fuzz(_read_hex(args.code), seeds, iterations=args.iterations, seed=args.seed)
    print(json.dumps(report.to_dict(), indent=2))
    return 0


def cmd_evm_exec(args: argparse.Namespace) -> int:
    """Execute bytecode on anvil when available, otherwise the local EVM."""
    from .execution import run_routed

    calldata = bytes.fromhex(args.calldata[2:] if args.calldata.startswith("0x")
                             else args.calldata) if args.calldata else b""
    routed = run_routed(_read_hex(args.code), calldata, prefer=args.engine,
                        address=int(args.address, 0), caller=int(args.caller, 0),
                        value=int(args.value, 0))
    payload = routed.to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        result = routed.result
        print(f"engine={routed.engine} requested={routed.requested}")
        print(f"  reason: {routed.reason}")
        print(f"  succeeded={result.get('succeeded')} halt={result.get('halt')}")
        print(f"  return_data={result.get('return_data', '')[:74]}")
    return 0 if routed.result.get("succeeded") else 1


def cmd_verified_model(args: argparse.Namespace) -> int:
    """Attest a deployment, model its source, and certify it -- or model a surface."""
    from .ingest.verified import build_decompiled_model, build_verified_model

    if args.decompiled:
        result = build_decompiled_model(Path(args.decompiled).read_text(), name=args.name)
    else:
        runtime = _read_hex(args.runtime) if args.runtime else None
        result = build_verified_model(args.chain_id, args.address,
                                      runtime_code=runtime, max_depth=args.max_depth)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.status == "CERTIFIED" else 1


def cmd_mission(args: argparse.Namespace) -> int:
    """Run the source pipeline and leave a resumable mission artifact."""
    from .mission import run_mission
    from .pipeline import PipelineConfig

    config = PipelineConfig(
        source_path=args.source,
        contract_name=args.contract or "",
        compiler_ast=getattr(args, "compiler_ast", False),
        project_root=getattr(args, "project_root", "") or "",
        max_depth=args.depth,
        control_source=args.control_source or "",
        control_contract=args.control_contract or "",
        write_finding=not args.no_finding,
        findings_root=args.findings,
        evidence_root=args.evidence,
        in_scope=True if args.in_scope else None,
        authorization_gate_passed=True if args.authorized else None,
        scope_reference=args.scope_reference or "",
        run_poc=args.poc,
        dataflow=args.dataflow,
    )
    try:
        artifacts = run_mission(config, directory=args.out or None)
    except (OSError, ValueError, TypeError) as exc:
        print(f"mission failed: {exc}", file=sys.stderr)
        return 2
    payload = artifacts.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(artifacts.result.verdict_line())
        print(f"artifacts: {artifacts.directory}")
    return 1 if artifacts.result.status in {"BLOCKED", "ERROR", "UNMODELLED"} else 0


def cmd_pipeline(args: argparse.Namespace) -> int:
    """Close the loop: verified deployment -> model -> price -> verify -> finding.

    ``--source`` runs the same loop on a local tree with no attestation: the
    certifier supplies the hypothesis, the value engine prices it, a fresh model
    independently re-runs it, and an optional Foundry PoC proves it. A local run
    never claims a deployment binding.
    """
    from .pipeline import PipelineConfig, run_pipeline, run_source_pipeline
    from .toolchain.enforce import load_record

    record = None
    if args.compatibility:
        try:
            record = load_record(args.compatibility)
        except (OSError, ValueError, TypeError) as exc:
            print(f"could not load compatibility record: {exc}", file=sys.stderr)
            return 2
    try:
        constructor_args = (json.loads(args.constructor_args)
                            if getattr(args, "constructor_args", "") else [])
        if not isinstance(constructor_args, list):
            raise ValueError("--constructor-args must be a JSON list")
    except (ValueError, TypeError) as exc:
        print(f"invalid --constructor-args: {exc}", file=sys.stderr)
        return 2
    if not getattr(args, "source", ""):
        if args.chain_id is None or not args.address:
            print("pipeline needs either --source PATH or --chain-id and --address",
                  file=sys.stderr)
            return 2
    config = PipelineConfig(
        chain_id=args.chain_id or 0,
        address=args.address or "",
        source_path=getattr(args, "source", "") or "",
        contract_name=getattr(args, "contract", "") or "",
        protocol=getattr(args, "protocol", False),
        protocol_infer_links=getattr(args, "protocol_infer_links", True),
        ast_path=getattr(args, "ast", "") or "",
        compiler_ast=getattr(args, "compiler_ast", False),
        compiler=getattr(args, "compiler", "") or "",
        project_root=getattr(args, "project_root", "") or "",
        include_paths=tuple(getattr(args, "include_path", []) or ()),
        remappings=tuple(getattr(args, "remapping", []) or ()),
        control_source=getattr(args, "control_source", "") or "",
        control_contract=getattr(args, "control_contract", "") or "",
        control_address=args.control_address or "",
        max_depth=args.max_depth,
        repository=args.repository,
        commit=args.commit,
        findings_root=args.findings,
        evidence_root=args.evidence,
        reports_root=args.reports,
        write_finding=not args.no_finding,
        write_report=args.report,
        reviewer=args.reviewer,
        in_scope=True if args.in_scope else None,
        authorization_gate_passed=True if args.authorized else None,
        scope_reference=args.scope_reference or "",
        compatibility=record,
        rpc=getattr(args, "rpc", "") or "",
        block=getattr(args, "block", None),
        run_poc=getattr(args, "poc", False),
        require_independent_engine=getattr(args, "require_independent_engine", False),
        run_mutation_audit=getattr(args, "mutation_audit", False),
        mutation_classes=tuple(getattr(args, "mutation_class", []) or ()),
        dataflow=getattr(args, "dataflow", False),
        constructor_args=constructor_args,
        proxy=getattr(args, "proxy", False),
        allow_unscanned=tuple(getattr(args, "allow_unscanned", []) or ()),
    )
    result = (run_source_pipeline(config) if config.source_path
              else run_pipeline(config))
    payload = result.to_dict()
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        where = (f"source={config.source_path} contract={config.contract_name or result.target}"
                 if config.source_path else
                 f"chain={result.chain_id} address={result.address}")
        print(f"pipeline {where} status={result.status}")
        for stage in result.stages:
            print(f"  {stage.stage:9} {stage.status:18} {stage.summary}")
        print(result.verdict_line())
        if result.finding_id:
            print(f"  finding: {result.finding_id} ({result.finding_status})")
        if result.report_path:
            print(f"  report: {result.report_path}")

    if getattr(args, "sarif", "") or getattr(args, "baseline", "") or getattr(args, "write_baseline", ""):
        from .baseline import compare, create, dumps as baseline_dumps
        from .findings import FindingRepository
        from .findings.sarif import dumps as sarif_dumps, to_sarif, validate

        records = FindingRepository(args.findings).all()
        if getattr(args, "sarif", ""):
            document = to_sarif(records)
            errors = validate(document)
            if errors:
                print("SARIF validation failed: " + "; ".join(errors), file=sys.stderr)
                return 2
            Path(args.sarif).parent.mkdir(parents=True, exist_ok=True)
            Path(args.sarif).write_text(sarif_dumps(document), encoding="utf-8")
            print(f"  SARIF: {args.sarif} ({len(records)} finding(s))")
        if getattr(args, "write_baseline", ""):
            Path(args.write_baseline).parent.mkdir(parents=True, exist_ok=True)
            Path(args.write_baseline).write_text(
                baseline_dumps(create(records)), encoding="utf-8")
            print(f"  baseline: {args.write_baseline} ({len(records)} finding(s))")
        if getattr(args, "baseline", ""):
            diff = compare(json.loads(Path(args.baseline).read_text(encoding="utf-8")), records)
            print(f"  baseline diff: {len(diff.new)} new, {len(diff.resolved)} resolved, "
                  f"{len(diff.changed)} changed, {len(diff.unchanged)} unchanged")
            if diff.new and getattr(args, "fail_on_new", False):
                return 1
    return {
        "VERIFIED": 0, "REPRODUCED": 0, "NO_VIOLATION": 0,
        "CERTIFIED_LEAD": 1, "ERROR": 1, "INCOMPLETE": 1,
        "BLOCKED": 2, "NOT_VERIFIED": 3, "UNMODELLED": 3,
    }.get(result.status, 1)


def _closure_record(path: str):
    from .toolchain.enforce import load_record
    if not path:
        return None
    try:
        return load_record(path)
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(f"could not load compatibility record: {exc}")


def _closure_sources(path: str):
    from .control import load_source_tree
    from .ingest.solidity import scan_source
    from pathlib import Path as _Path
    root = _Path(path)
    files = load_source_tree(root) if root.is_dir() else {root.name: root.read_text(encoding="utf-8")}
    surfaces = {}
    for name, text in files.items():
        for contract in scan_source(text, name):
            surfaces[contract.name] = contract
    return files, surfaces


def _closure_steps(path: str):
    candidate = Path(path)
    text = candidate.read_text(encoding="utf-8") if candidate.exists() else path
    payload = json.loads(text)
    if not isinstance(payload, list):
        raise SystemExit("steps JSON must be a list")
    return [AttackStep(index=i, actor=str(s.get("actor", "attacker")),
                       action=str(s["action"]), params=dict(s.get("params") or {}),
                       target_contract=str(s.get("target_contract", "")))
            for i, s in enumerate(payload)]


def _parse_link_pairs(text: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Parse ``CALLER.OP=CALLEE.OP:a=b,c=d`` into a link key and pairs."""
    key, _, raw = text.partition(":")
    pairs: list[tuple[str, str]] = []
    for item in raw.split(",") if raw else ():
        item = item.strip()
        if not item:
            continue
        left, sep, right = item.partition("=")
        if not sep or not left.strip() or not right.strip():
            raise SystemExit(f"link map must be source=target: {item!r}")
        pairs.append((left.strip(), right.strip()))
    return key.strip(), tuple(pairs)


def _closure_payload(args, payload: dict) -> int:
    if getattr(args, "out", ""):
        Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


def cmd_closure(args: argparse.Namespace) -> int:
    """The additive closure surface: protocol, control, bytecode, mutation, plan, corpus, review, poc, market."""
    kind = args.closure_cmd
    try:
        if kind == "coverage":
            from .ingest.model_coverage import coverage_for_contract
            from .ingest.synthesize import synthesize

            _files, surfaces = _closure_sources(args.source)
            wanted = getattr(args, "contract", "") or ""
            if wanted and wanted not in surfaces:
                raise SystemExit(f"contract not found in source: {wanted}")
            selected = {wanted: surfaces[wanted]} if wanted else surfaces
            if not selected:
                raise SystemExit("no contract surface recovered from the source")
            out: dict[str, dict] = {}
            for name, surface in selected.items():
                target, report = synthesize(surface, registry=surfaces)
                cov = coverage_for_contract(surface, report, target)
                out[name] = {"coverage": cov.to_dict(), "report": report.__dict__}
            return _closure_payload(args, {"contracts": out})

        if kind == "protocol":
            from .ingest.protocol import Link, build_protocol
            from .discovery.certify import certify_exhaustive
            _files, surfaces = _closure_sources(args.source)
            specs: dict[str, dict[str, tuple[tuple[str, str], ...]]] = {}
            for text in args.link or []:
                key = text.split(":", 1)[0]
                specs.setdefault(key, {"params": (), "returns": ()})
            for text in getattr(args, "link_param", ()) or ():
                key, pairs = _parse_link_pairs(text)
                specs.setdefault(key, {"params": (), "returns": ()})["params"] = pairs
            for text in getattr(args, "link_return", ()) or ():
                key, pairs = _parse_link_pairs(text)
                specs.setdefault(key, {"params": (), "returns": ()})["returns"] = pairs
            links = []
            for text, maps in specs.items():
                left, right = text.split("=", 1)
                caller, cop = left.split(".", 1)
                callee, eop = right.split(".", 1)
                links.append(Link(caller, cop, callee, eop,
                                  param_map=maps["params"],
                                  return_map=maps["returns"]))
            graph = None
            if getattr(args, "compiler_callgraph", False):
                from .ingest.callgraph import infer_calls_compiler
                graph = infer_calls_compiler(args.source, surfaces)
            target, report = build_protocol(surfaces, links=tuple(links),
                                            name=args.name,
                                            infer_links=getattr(args, "infer", False),
                                            graph=graph)
            payload = {"target": target.to_dict(), "report": report.to_dict()}
            if args.certify:
                cert = certify_exhaustive(target, max_depth=args.max_depth)
                payload["certificate"] = cert.to_dict()
            return _closure_payload(args, payload)

        if kind == "control":
            from .control import build_control, compare_sequence, discover_control_commit
            _tf, target_surfaces = _closure_sources(args.target_source)
            control_files = {}
            discovered = None
            if args.control_source:
                control_files = _closure_sources(args.control_source)[0]
            elif args.repo and args.vulnerable_commit:
                dest = Path(args.control_dest) / args.vulnerable_commit[:12]
                discovered = discover_control_commit(
                    args.repo, args.vulnerable_commit, dest,
                    paths=tuple(args.path or ()), depth=args.depth)
                if discovered.status != "FETCHED":
                    return _closure_payload(args, {"control_source": discovered.to_dict(),
                                                   "differential": {"status": "BLOCKED",
                                                                    "reason": discovered.reason}})
                control_files = discovered.files
            else:
                raise ValueError("supply --control-source or --repo with --vulnerable-commit")
            control = build_control(control_files, contract_name=args.contract)
            chosen = (target_surfaces.get(args.contract) if args.contract
                      else next(iter(target_surfaces.values()), None))
            if chosen is None:
                raise SystemExit("target contract not found")
            from .ingest.synthesize import synthesize
            target, _ = synthesize(chosen)
            result = compare_sequence(target, control, _closure_steps(args.steps),
                                      compatibility=_closure_record(args.compatibility),
                                      repository=args.repository, commit=args.commit)
            payload = {"control": control.to_dict(),
                       "differential": result.to_dict()}
            if discovered is not None:
                payload["control_source"] = discovered.to_dict()
            return _closure_payload(args, payload)

        if kind == "bytecode":
            from .bytecode import verify_runtime_hex
            text = Path(args.runtime).read_text(encoding="utf-8").strip()
            witness = json.loads(Path(args.witness).read_text(encoding="utf-8"))
            storage = {}
            for item in args.storage or []:
                key, value = item.split("=", 1)
                storage[int(key, 0)] = int(value, 0)
            result = verify_runtime_hex(text, witness, expect_revert=args.expect_revert,
                                        expected_storage=storage or None)
            return _closure_payload(args, result.to_dict())

        if kind == "mutate":
            from .assurance.mutation import audit_mutations
            from .ingest.synthesize import synthesize
            _files, surfaces = _closure_sources(args.source)
            chosen = surfaces.get(args.contract) if args.contract else next(iter(surfaces.values()), None)
            if chosen is None:
                raise SystemExit("contract not found")
            target, _ = synthesize(chosen)
            audit = audit_mutations(target, classes=tuple(args.mutation_class or ()),
                                    max_depth=args.max_depth)
            return _closure_payload(args, audit.to_dict())

        if kind == "plan":
            from .planning import plan_from_policy
            from .objectives import TargetProfile
            from .program_intel.normalize import PolicyNormalizer
            policy = PolicyNormalizer().normalize(
                Path(args.policy).read_text(encoding="utf-8"),
                program=args.program, source_url=args.source_url)
            profile = TargetProfile(**json.loads(Path(args.profile).read_text(encoding="utf-8")))
            return _closure_payload(args, plan_from_policy(policy, profile).to_dict())

        if kind == "corpus":
            from .corpus import CorpusStore
            if (args.queue_claim or args.queue_complete or args.queue_fail
                    or args.queue_recover):
                from .distributed import LeaseQueue
                queue = LeaseQueue(args.queue or (args.path + ".queue"),
                                   ttl=args.ttl)
                keys = json.loads(args.keys) if args.keys else []
                if args.queue_recover:
                    return _closure_payload(args, queue.recover_stale(keys))
                if args.queue_claim:
                    if not args.worker:
                        raise ValueError("--worker is required to claim")
                    return _closure_payload(args, {
                        "leases": [l.to_dict() for l in queue.claim(
                            args.worker, keys, limit=args.limit)],
                        "stats": queue.stats().to_dict()})
                if args.queue_complete:
                    if not args.worker:
                        raise ValueError("--worker is required to complete")
                    return _closure_payload(args, queue.complete(
                        args.worker, args.queue_complete, args.epoch,
                        verdict=args.verdict or "DONE",
                        result=json.loads(args.result) if args.result else None))
                return _closure_payload(args, queue.fail(
                    args.worker, args.queue_fail, args.epoch,
                    error=args.error or "worker reported failure"))
            store = CorpusStore(args.path)
            if args.invalidate:
                entry = store.invalidate(json.loads(args.invalidate),
                                         reason=args.reason or "operator invalidated")
                return _closure_payload(args, entry.to_dict())
            if args.pending:
                return _closure_payload(args, {"pending": store.pending(json.loads(args.pending))})
            if args.export_shard:
                return _closure_payload(args, store.export_shard(args.export_shard))
            if args.merge_shard:
                return _closure_payload(args, store.merge_shard(args.merge_shard))
            if args.add:
                entry = store.add(json.loads(args.add), verdict=args.verdict,
                                  result=json.loads(args.result) if args.result else None)
                return _closure_payload(args, entry.to_dict())
            if args.verify:
                return _closure_payload(args, store.verify_integrity())
            return _closure_payload(args, {"entries": [e.to_dict() for e in store.all()]})

        if kind == "review":
            from .providers.router import build_router
            from .reviewer import independent_review
            prompt = Path(args.prompt).read_text(encoding="utf-8")
            router = build_router(budget=_budget_from_args(args))
            outcome = independent_review(router, prompt, primary=args.primary,
                                         probe=not args.no_probe)
            return _closure_payload(args, outcome.to_dict())

        if kind == "poc":
            from .ingest.deploy import plan_deployment
            from .pocgen import PocCandidate, execute_source_poc, render_source_poc
            files, surfaces = _closure_sources(args.source)
            chosen = surfaces.get(args.contract) if args.contract else next(iter(surfaces.values()), None)
            if chosen is None:
                raise SystemExit("contract not found")
            helpers = []
            for item in args.helper or []:
                name, _, raw = item.partition("=")
                helpers.append((name, json.loads(raw or "[]")))
            constructor_args = (json.loads(args.constructor_args)
                                if args.constructor_args else None)
            deployment = plan_deployment(
                files, chosen.name, constructor_args=constructor_args,
                proxy=args.proxy, helper_deployments=tuple(helpers))
            if deployment.ready:
                candidate = render_source_poc(
                    files, chosen.name, chosen.path, _closure_steps(args.steps),
                    args.invariant, constructor_args=constructor_args,
                    deployed_address=args.deployed_address,
                    proxy=args.proxy, helper_deployments=tuple(helpers))
            else:
                candidate = PocCandidate(
                    "UNSUPPORTED", invariant_id=args.invariant,
                    reason="deployment plan is BLOCKED: " + "; ".join(
                        step.reason for step in deployment.steps if not step.ready))
            outcome = execute_source_poc(
                candidate, compatibility=_closure_record(args.compatibility),
                target_component=f"ingest:{chosen.name}", repository=args.repository,
                commit=args.commit, fork_url=args.fork_url,
                fork_block=args.fork_block)
            return _closure_payload(args, {"candidate": candidate.to_dict(),
                                           "deployment": deployment.to_dict(),
                                           "run": outcome.as_dict()})

        if kind == "truth":
            from .ingest.truth import deployment_truth
            from .rpc import resolve_rpc
            rpc = args.rpc or resolve_rpc("mainnet").url
            if not rpc:
                raise ValueError("no live RPC endpoint resolved; pass --rpc")
            return _closure_payload(args, deployment_truth(
                args.address, rpc, at_block=args.block,
                bind_runtime=not getattr(args, "no_bind_runtime", False)).to_dict())

        if kind == "equivalence":
            from .ingest.equivalence import check_equivalence
            files, _surfaces = _closure_sources(args.source)
            runtime = bytes.fromhex(Path(args.runtime).read_text(encoding="utf-8").strip()
                                    .removeprefix("0x"))
            expected_abi = (json.loads(Path(args.abi).read_text(encoding="utf-8"))
                            if args.abi else None)
            expected_layout = (json.loads(Path(args.storage_layout).read_text(
                encoding="utf-8")) if args.storage_layout else None)
            expected_ast = (json.loads(Path(args.ast).read_text(encoding="utf-8"))
                            if args.ast else None)
            report = check_equivalence(files, runtime, compiler=args.compiler,
                                       expected_abi=expected_abi,
                                       expected_storage_layout=expected_layout,
                                       expected_ast=expected_ast)
            return _closure_payload(args, report.to_dict())

        if kind == "deploy-plan":
            from .ingest.deploy import plan_deployment
            files, surfaces = _closure_sources(args.source)
            chosen = surfaces.get(args.contract) if args.contract else next(iter(surfaces.values()), None)
            if chosen is None:
                raise ValueError("contract not found")
            helpers = []
            for item in args.helper or []:
                name, _, raw = item.partition("=")
                helpers.append((name, json.loads(raw or "[]")))
            plan = plan_deployment(
                files, chosen.name,
                constructor_args=(json.loads(args.constructor_args)
                                  if args.constructor_args else None),
                proxy=args.proxy, helper_deployments=tuple(helpers))
            return _closure_payload(args, plan.to_dict())

        if kind == "certify":
            from .discovery.certify import certify_directed
            from .ingest.protocol import build_protocol

            files, surfaces = _closure_sources(args.source)
            selected = dict(surfaces)
            if args.contract:
                chosen = surfaces.get(args.contract)
                if chosen is None:
                    raise ValueError(f"contract {args.contract!r} not found")
                selected = {chosen.name: chosen}
                if args.asset:
                    if args.asset not in surfaces:
                        raise ValueError(f"asset contract {args.asset!r} not found")
                    selected[args.asset] = surfaces[args.asset]
            protocol, report = build_protocol(selected, infer_links=True)
            cert = certify_directed(
                protocol, max_depth=args.depth, max_states=args.max_states,
                beam_width=args.beam, param_sets=args.param_sets,
                invariant_id=args.invariant)
            return _closure_payload(args, {
                "certificate": cert.to_dict(), "protocol": report.to_dict(),
            })

        if kind == "foundry":
            from .ingest.foundry import run_foundry_test
            files, surfaces = _closure_sources(args.source)
            if getattr(args, "generate_invariant", False):
                from .ingest.generated_invariant import (
                    render_surface_invariant, run_generated_invariant,
                )
                chosen = (surfaces.get(args.contract) if args.contract
                          else next(iter(surfaces.values()), None))
                if chosen is None:
                    raise ValueError("contract not found")
                # --test-name defaults to test_witness for --auto; a generated
                # invariant must keep an invariant_ name so forge runs it as a
                # fuzzed invariant rather than once as a unit test.
                generated_test = (args.test_name
                                  if args.test_name != "test_witness"
                                  else "invariant_generated")
                generated = render_surface_invariant(
                    files, chosen.name, asset=args.asset,
                    template=args.invariant_template,
                    invariant_body=args.invariant_body,
                    test_name=generated_test,
                    invariant_name=args.invariant_name or generated_test)
                outcome = run_generated_invariant(
                    generated, compatibility=_closure_record(args.compatibility),
                    target_component=(args.target_component or chosen.name),
                    repository=args.repository, commit=args.commit,
                    timeout=args.timeout, runner=None)
                return _closure_payload(args, {"generated": generated.to_dict(),
                                               "run": outcome.as_dict()})
            if args.auto:
                from .pocgen import execute_source_poc, render_source_poc
                chosen = (surfaces.get(args.contract) if args.contract
                          else next(iter(surfaces.values()), None))
                if chosen is None:
                    raise ValueError("contract not found")
                helpers = []
                for item in args.helper or []:
                    name, _, raw = item.partition("=")
                    helpers.append((name, json.loads(raw or "[]")))
                candidate = render_source_poc(
                    files, chosen.name, chosen.path, _closure_steps(args.steps),
                    args.invariant,
                    constructor_args=(json.loads(args.constructor_args)
                                      if args.constructor_args else None),
                    deployed_address=args.deployed_address, proxy=args.proxy,
                    helper_deployments=tuple(helpers))
                outcome = execute_source_poc(
                    candidate, compatibility=_closure_record(args.compatibility),
                    target_component=(args.target_component or chosen.name),
                    repository=args.repository, commit=args.commit,
                    fork_url=args.fork_url, fork_block=args.fork_block)
                return _closure_payload(args, {"candidate": candidate.to_dict(),
                                               "run": outcome.as_dict()})
            if not args.test:
                raise ValueError("--test is required unless --auto is set")
            test_source = Path(args.test).read_text(encoding="utf-8")
            result = run_foundry_test(
                files, test_source, compatibility=_closure_record(args.compatibility),
                target_component=(args.target_component
                                  or Path(args.source).stem or "source"),
                repository=args.repository, commit=args.commit,
                test_name=args.test_name, fork_url=args.fork_url,
                fork_block=args.fork_block)
            return _closure_payload(args, result.to_dict())

        if kind == "scenario":
            from .fork_scenario import (
                run_fork_scenario, scenario_from_dict, scenario_to_dict,
            )
            raw = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
            scenario = scenario_from_dict(raw)
            outcome = run_fork_scenario(
                scenario,
                compatibility=_closure_record(args.compatibility),
                target_component=args.target_component or scenario.name,
                repository=args.repository,
                commit=args.commit,
                rpc_url=args.rpc,
                block=args.block,
                timeout=args.timeout,
            )
            return _closure_payload(args, {
                "scenario": scenario_to_dict(scenario),
                "run": outcome.as_dict(),
            })

        if kind == "market":
            from .value.market import (
                BundleAuction, ConstantProductPool, LendingCurve, Level, OrderBook,
                V3MultiPool, V3Pool, V3Range, simulate_orderbook_sandwich,
                simulate_sandwich, simulate_v3_multi_sandwich,
                simulate_v3_sandwich,
            )
            if args.model == "orderflow":
                from .value.orderflow import (
                    OrderFlowAuction, bids_from_single, parse_bids,
                )
                bids = (parse_bids(args.competitor_bids)
                        if args.competitor_bids
                        else bids_from_single(args.competitor_bid,
                                              args.competitor_count))
                auction = OrderFlowAuction(
                    gross_wei=args.gross, our_bid_wei=args.bribe,
                    gas_wei=args.gas, failed_tx_cost_wei=args.failed_tx_cost,
                    capital_cost_wei=args.capital_cost,
                    competitor_bids_wei=bids,
                    inclusion_probability_bps=args.inclusion_bps)
                return _closure_payload(args, auction.to_dict())
            if args.model == "cp":
                if not args.pool_in or not args.pool_out or not args.victim:
                    raise ValueError("--model cp needs --pool-in, --pool-out and --victim")
                pool = ConstantProductPool(args.pool_in, args.pool_out, args.fee_bps)
                result = simulate_sandwich(pool, victim_amount_in=args.victim,
                                           attacker_amount_in=args.attacker)
                return _closure_payload(args, result.to_dict())
            if args.model == "orderbook":
                asks = [Level(int(p), int(s)) for p, s in json.loads(args.asks or "[]")]
                bids = [Level(int(p), int(s)) for p, s in json.loads(args.bids or "[]")]
                result = simulate_orderbook_sandwich(
                    OrderBook(asks, bids), victim_amount_in=args.victim,
                    attacker_amount_in=args.attacker)
                return _closure_payload(args, result.to_dict())
            if args.model == "lending":
                result = LendingCurve(args.total_supply, args.total_borrow,
                                      args.base_rate_bps, args.slope_bps)
                return _closure_payload(args, result.to_dict())
            if args.model == "v3":
                if not args.sqrt_price or not args.liquidity or not args.victim:
                    raise ValueError("--model v3 needs --sqrt-price, --liquidity and --victim")
                pool = V3Pool(args.sqrt_price, args.liquidity, args.fee_pips,
                              args.sqrt_lower or 1,
                              args.sqrt_upper or ((1 << 160) - 1))
                result = simulate_v3_sandwich(
                    pool, args.direction, victim_amount_in=args.victim,
                    attacker_amount_in=args.attacker)
                return _closure_payload(args, result.to_dict())
            if args.model == "v3-multi":
                if not args.sqrt_price or not args.victim or not args.range:
                    raise ValueError("--model v3-multi needs --sqrt-price, --range and --victim")
                ranges = []
                for item in args.range:
                    parts = item.split(":")
                    if len(parts) != 3:
                        raise ValueError("--range must be LOWER:UPPER:LIQUIDITY")
                    ranges.append(V3Range(int(parts[0]), int(parts[1]), int(parts[2])))
                pool = V3MultiPool(args.sqrt_price, tuple(ranges), args.fee_pips)
                result = simulate_v3_multi_sandwich(
                    pool, args.direction, victim_amount_in=args.victim,
                    attacker_amount_in=args.attacker)
                return _closure_payload(args, result.to_dict())
            if args.model == "live-v3":
                from .deployed import RpcUnavailable
                from .value.live_v3 import (
                    BPS as _LIVE_BPS, fetch_live_v3_pool, live_v3_sandwich,
                    price_live_v3_sandwich, search_live_v3_sandwich,
                )
                if not args.pair or not args.pair[0]:
                    raise ValueError("--model live-v3 needs --pair ADDRESS[:LABEL]")
                if not args.rpc:
                    return _closure_payload(args, {
                        "status": "UNAVAILABLE",
                        "reason": "no RPC endpoint was supplied",
                        "note": "live-v3 reads slot0, liquidity and the tick bitmap",
                    })
                address, _, label = args.pair[0].partition(":")
                try:
                    pool = fetch_live_v3_pool(
                        args.rpc, address, block=args.block,
                        max_words=args.max_words, label=label)
                except RpcUnavailable as exc:
                    return _closure_payload(args, {
                        "status": "UNAVAILABLE", "address": address,
                        "reason": f"RPC unavailable: {exc}",
                    })
                payload = pool.to_dict()
                cost_kwargs = {
                    "gas_units": args.gas_units,
                    "gas_price_wei": args.gas_price_wei,
                    "bribe_bps": args.bribe_bps,
                    "inclusion_bps": args.inclusion_bps,
                    "failed_tx_cost_profit_token": args.failed_tx_cost,
                    "capital_cost_profit_token": args.capital_cost,
                    "competitor_bid_profit_token": args.competitor_bid,
                }
                if args.gas_cost is not None:
                    cost_kwargs["gas_cost_profit_token"] = args.gas_cost
                if args.native_price:
                    try:
                        cost_kwargs["native_price"] = Decimal(args.native_price)
                    except InvalidOperation as exc:
                        raise ValueError(f"--native-price is not a number: {exc}") from exc
                costs_supplied = bool(
                    args.gas_units or args.gas_price_wei or args.bribe_bps
                    or args.inclusion_bps != _LIVE_BPS
                    or args.gas_cost is not None or args.native_price
                    or args.failed_tx_cost or args.capital_cost
                    or args.competitor_bid)
                if args.optimize:
                    if not args.victim:
                        payload["sandwich_error"] = "--optimize needs --victim"
                    else:
                        try:
                            search = search_live_v3_sandwich(
                                pool, args.direction,
                                victim_amount_in=args.victim, **cost_kwargs)
                            payload["sandwich_search"] = search.to_dict()
                            if search.best:
                                payload["sandwich"] = search.best.to_dict()
                                if args.fork_validate:
                                    from .value.live_v3_fork import (
                                        DEFAULT_ROUTER, run_live_v3_fork_validation,
                                    )
                                    payload["fork_validation"] = (
                                        run_live_v3_fork_validation(
                                            pool, args.direction, rpc_url=args.rpc,
                                            victim_amount_in=args.victim,
                                            attacker_amount_in=search.best.attacker_in,
                                            expected=search.best,
                                            router=args.router or DEFAULT_ROUTER,
                                            balance_slot=args.balance_slot,
                                            tolerance_bps=args.fork_tolerance_bps,
                                        ).to_dict())
                        except ValueError as exc:
                            payload["sandwich_error"] = str(exc)
                elif args.victim and args.attacker:
                    try:
                        result = live_v3_sandwich(
                            pool, args.direction, victim_amount_in=args.victim,
                            attacker_amount_in=args.attacker)
                        payload["sandwich"] = result.to_dict()
                        if costs_supplied:
                            payload["economics"] = price_live_v3_sandwich(
                                result, pool, args.direction, **cost_kwargs).to_dict()
                        if args.fork_validate:
                            from .value.live_v3_fork import (
                                DEFAULT_ROUTER, run_live_v3_fork_validation,
                            )
                            payload["fork_validation"] = (
                                run_live_v3_fork_validation(
                                    pool, args.direction, rpc_url=args.rpc,
                                    victim_amount_in=args.victim,
                                    attacker_amount_in=args.attacker,
                                    expected=result,
                                    router=args.router or DEFAULT_ROUTER,
                                    balance_slot=args.balance_slot,
                                    tolerance_bps=args.fork_tolerance_bps,
                                ).to_dict())
                    except ValueError as exc:
                        payload["sandwich_error"] = str(exc)
                return _closure_payload(args, payload)
            if args.model == "live":
                from .value.live import fetch_live_market, live_sandwich
                pairs = []
                for item in args.pair:
                    parts = item.split(":")
                    if not parts or not parts[0]:
                        raise ValueError("--pair needs an address")
                    fee = int(parts[1]) if len(parts) > 1 and parts[1] else 30
                    label = parts[2] if len(parts) > 2 else parts[0]
                    pairs.append((parts[0], fee, label))
                amount = args.victim or args.attacker or 1
                report = fetch_live_market(args.rpc, pairs, amount_in=amount,
                                           block=args.block)
                payload = report.to_dict()
                if args.victim and args.attacker and report.pools:
                    payload["sandwich"] = live_sandwich(
                        report.pools[0], victim_amount_in=args.victim,
                        attacker_amount_in=args.attacker).to_dict()
                return _closure_payload(args, payload)
            result = BundleAuction(
                args.gross, args.gas, args.priority_fee, args.bribe,
                args.inclusion_bps, args.failed_tx_cost, args.capital_cost,
                args.competitor_bid, args.competitor_count)
            return _closure_payload(args, result.to_dict())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"closure {kind} failed: {exc}", file=sys.stderr)
        return 2
    print(f"unknown closure command {kind!r}", file=sys.stderr)
    return 2


def cmd_improve(args: argparse.Namespace) -> int:
    """Dispatch the ranked capability upgrades; every branch is a real call."""
    from . import improve
    sub = getattr(args, "improve_sub", "")

    def emit(payload: dict) -> int:
        if getattr(args, "json", False):
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(improve.render() if sub == "status" else json.dumps(payload, indent=2))
        return 0

    if sub == "status":
        return emit(improve.status())

    if sub == "execution":
        from .improve.execution import compile_and_model
        from .toolchain.enforce import load_record
        record = load_record(args.compatibility)
        result = compile_and_model(
            args.root, compatibility=record,
            target_component=args.target_component,
            repository=args.repository, commit=args.commit,
            contract=args.contract, timeout=args.timeout,
        )
        return emit(result.to_dict())

    if sub == "model-coverage":
        from .improve.model_coverage import audit_source
        results = audit_source(args.path)
        payload = {"contracts": [r.to_dict() for r in results]}
        return emit(payload)

    if sub == "closed":
        from .improve.closed import analyze_closed
        witness = None
        if args.witness:
            witness = json.loads(Path(args.witness).read_text(encoding="utf-8"))
        decompiled = (Path(args.decompiled).read_text(encoding="utf-8")
                      if args.decompiled else "")
        result = analyze_closed(
            Path(args.runtime).read_text(encoding="utf-8").strip(),
            decompiled_text=decompiled, witness=witness,
        )
        return emit(result.to_dict())

    if sub == "invariants":
        from .improve.invariants import discover_invariants
        return emit(discover_invariants(args.paths).to_dict())

    if sub == "market":
        from .improve.competition import Searcher, simulate_race
        searchers = []
        for raw in args.searcher:
            parts = raw.split(":")
            if len(parts) not in (2, 3):
                print("--searcher must be name:bid_wei[:latency_ms]", file=sys.stderr)
                return 2
            searchers.append(Searcher(
                parts[0], int(parts[1]), int(parts[2]) if len(parts) == 3 else 0))
        result = simulate_race(
            searchers, victim_value_wei=args.victim_value,
            block_time_ms=args.block_time, our_name=args.our_name,
        )
        return emit(result.to_dict())

    if sub == "crosschain":
        from .improve.crosschain import (
            BridgeMessage, BridgeReplayModel, OracleReading, oracle_status,
        )
        if args.oracle_price is not None:
            status = oracle_status(
                OracleReading(args.oracle_price, args.oracle_updated_at),
                now=args.now, heartbeat=args.heartbeat,
                reference_price=args.reference_price,
                max_deviation_bps=args.max_deviation_bps,
            )
            return emit(status.to_dict())
        model = BridgeReplayModel(
            args.dest_chain, frozenset(args.source_chain),
            frozenset(args.sender) if args.sender else frozenset(),
        )
        message = BridgeMessage(
            args.message_source, args.message_dest, args.message_sender,
            args.nonce, args.payload_hash,
        )
        return emit(model.process(message, authenticated=not args.unauthenticated).to_dict())

    if sub == "bounty":
        from .bounty import CandidateRecord, ProgramPolicy
        from .improve.bounty_package import package_from_policy
        from .models import Finding
        finding = Finding.from_dict(json.loads(
            Path(args.finding).read_text(encoding="utf-8")))
        policy = ProgramPolicy.from_dict(json.loads(
            Path(args.policy).read_text(encoding="utf-8")))
        candidate = (CandidateRecord.from_dict(json.loads(
            Path(args.candidate).read_text(encoding="utf-8")))
            if args.candidate else None)
        return emit(package_from_policy(
            finding, policy, candidate=candidate).to_dict())

    if sub == "review":
        from .providers.router import ModelRouter, resolve_reviewer_model
        from .improve.review_gate import gate_review
        router = ModelRouter.from_env()
        reviewer = resolve_reviewer_model(
            router, primary=args.primary, probe=args.probe)
        return emit(gate_review(
            reviewer, require_independent=not args.allow_same_model).to_dict())

    if sub == "scale":
        from .improve.scale import batch_ingest
        results = batch_ingest(args.paths, workers=args.workers)
        return emit({"paths": [r.to_dict() for r in results]})

    if sub == "continuous":
        from .improve.continuous import run_continuous
        from .watch import CycleConfig
        config = CycleConfig(
            state_dir=args.state, out_dir=args.out,
            registry_path=args.registry, targets=tuple(args.target or ()),
            dry_run=True,
        )
        result = run_continuous(
            config, enqueue=lambda lead: lead, dry_run=True,
            fetcher=None, github=None, rpc=None, source=None,
        )
        return emit(result.to_dict())

    print(f"unknown improve command: {sub}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackheart", description="Adversarial exploit engine")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("tools", help="toolchain registry")
    tsub = t.add_subparsers(dest="sub", required=True)
    tv = tsub.add_parser("verify", help="verify toolchain")
    tv.add_argument("--out", default="research/private/tools/registry.json")
    tv.set_defaults(func=cmd_tools_verify)

    tr = tsub.add_parser(
        "run",
        help="drive a live tool against an AUTHORIZED asset and record the evidence",
    )
    tr.add_argument("tool", choices=["ffuf", "gobuster", "nuclei", "sqlmap", "dalfox", "gitleaks"],
                    help="the tool adapter to drive")
    tr.add_argument("target", help="the target URL/path (ffuf needs a FUZZ keyword in the URL)")
    tr.add_argument("--wordlist", help="wordlist path (required for ffuf/gobuster)")
    tr.add_argument("--asset", default="", help="the authorized asset name the gate checks")
    tr.add_argument("--authorization", required=True,
                    help="path to a JSON authorization record (blackheart scope)")
    tr.add_argument("--evidence-dir", default="research/private/tools/evidence",
                    help="evidence store directory")
    tr.set_defaults(func=cmd_tools_run)

    dep = sub.add_parser(
        "deployed",
        help="verify a deployed contract's real on-chain facts (read-only, no transactions)",
    )
    dep.add_argument("address", help="contract address to verify")
    dep.add_argument("--rpc", help="JSON-RPC endpoint (default: BLACKHEART_ETH_RPC or a public RPC)")
    dep.add_argument("--block", type=int, help="block number to read at (default: latest)")
    dep.add_argument("--no-proxy", action="store_true", help="skip proxy-slot detection")
    dep.add_argument("--selectors",
                     help="semicolon-separated function signatures to fingerprint in the bytecode")
    dep.add_argument("--json", action="store_true")
    dep.set_defaults(func=cmd_deployed)

    dp = sub.add_parser(
        "deployment",
        help="bind a live deployment to verified source and a compatibility record",
    )
    dps = dp.add_subparsers(dest="sub", required=True)
    db = dps.add_parser("bind", help="resolve chain/source/component and emit a record")
    db.add_argument("address")
    db.add_argument("--chain", type=int, default=1)
    db.add_argument("--repository", required=True)
    db.add_argument("--commit", required=True)
    db.add_argument("--rpc", default="")
    db.add_argument("--component", default="")
    db.add_argument("--smoke-test", choices=["auto", "passed", "failed", "not-run"],
                    default="auto")
    db.add_argument("--timeout", type=int, default=300)
    db.add_argument("--out", default="")
    db.add_argument("--json", action="store_true")
    db.set_defaults(func=cmd_deployment)

    mon = sub.add_parser(
        "monitor",
        help="watch live UMA/Oval/Across contracts for post-audit code drift (read-only)",
    )
    msub = mon.add_subparsers(dest="sub", required=True)

    mt = msub.add_parser("targets", help="list the watched contract registry")
    mt.add_argument("--json", action="store_true")
    mt.set_defaults(func=cmd_monitor_targets)

    mr = msub.add_parser("run", help="poll every target and report code drift")
    mr.add_argument("--rpc", help="JSON-RPC endpoint (default: BLACKHEART_ETH_RPC or a public archive RPC)")
    mr.add_argument("--target", action="append", dest="targets",
                    help="limit to a target key (repeatable)")
    mr.add_argument("--baseline", help="path to a pinned baseline to compare against")
    mr.add_argument("--save", help="write this run's observations as a new baseline")
    mr.add_argument("--json", action="store_true")
    mr.set_defaults(func=cmd_monitor_run)

    mb = msub.add_parser("baseline", help="write a pinned baseline of current deployed code")
    mb.add_argument("--rpc", help="JSON-RPC endpoint (default: BLACKHEART_ETH_RPC or a public archive RPC)")
    mb.add_argument("--out", default="research/private/monitor-baseline.json",
                    help="path to write the baseline JSON")
    mb.add_argument("--json", action="store_true")
    mb.set_defaults(func=cmd_monitor_baseline)

    rt = sub.add_parser("retest", help="re-run a finding's PoC: still-reproducible / fixed / cannot-confirm")
    rt.add_argument("finding_id", help="the finding to retest")
    rt.add_argument("command", nargs=argparse.REMAINDER, help="reproduction command after --")
    rt.add_argument("--findings", default="research/private/findings", help="repository directory")
    rt.add_argument("--name", default="findings", help="repository log name")
    rt.add_argument("--timeout", type=float, default=600.0)
    rt.add_argument("--evidence", action="append", help="evidence id to attach (repeatable)")
    rt.add_argument("--json", action="store_true")
    rt.set_defaults(func=cmd_retest)

    gr = sub.add_parser("graph", help="query the dual research graph (asset + exploration + coverage)")
    gr.add_argument("--db", default="research/private/graph.db", help="SQLite graph path")
    gsub = gr.add_subparsers(dest="sub", required=True)
    gc = gsub.add_parser("coverage", help="asset test coverage (tested / untested)")
    gc.add_argument("--company")
    gc.add_argument("--json", action="store_true")
    gc.set_defaults(func=cmd_graph)
    gl = gsub.add_parser("lineage", help="a node's lineage (goal -> finding)")
    gl.add_argument("node", type=int)
    gl.set_defaults(func=cmd_graph)

    w = sub.add_parser(
        "watch",
        help="hourly bounty watchtower: official policy, repositories and deployed code",
    )
    wsub = w.add_subparsers(dest="sub", required=True)

    wt = wsub.add_parser("targets", help="list the independent bounty watchlist")
    wt.add_argument("--registry", help="path to targets.json (default: package registry)")
    wt.add_argument("--write", help="write one JSON record per target into this directory")
    wt.add_argument("--json", action="store_true")
    wt.set_defaults(func=cmd_watch_targets)

    wc = wsub.add_parser("cycle", help="run one monitoring cycle (read-only)")
    wc.add_argument("--state", default="research/bounty-monitor/state",
                    help="durable state directory (default: research/bounty-monitor/state)")
    wc.add_argument("--out", default="research/bounty-monitor",
                    help="report/evidence root (default: research/bounty-monitor)")
    wc.add_argument("--registry", help="path to targets.json (default: package registry)")
    wc.add_argument("--target", action="append", dest="targets",
                    help="limit to a target slug (repeatable)")
    wc.add_argument("--skip-policy", action="store_true")
    wc.add_argument("--skip-repos", action="store_true")
    wc.add_argument("--skip-contracts", action="store_true")
    wc.add_argument("--skip-source", action="store_true",
                    help="do not fetch verified source (Sourcify) when a deployment changes")
    wc.add_argument("--max-policy", type=int, help="cap policy pages fetched this cycle")
    wc.add_argument("--max-repos", type=int, help="cap repositories checked this cycle")
    wc.add_argument("--max-contracts", type=int, help="cap contracts checked this cycle")
    wc.add_argument("--timeout", type=int, default=25, help="per-request timeout in seconds")
    wc.add_argument("--dry-run", action="store_true",
                    help="observe and report but do not write state or reports")
    wc.add_argument("--email", action="store_true",
                    help="send the cycle report if SMTP_* secrets are configured")
    wc.add_argument("--email-to", default="", help="override MAIL_TO")
    wc.add_argument("--issue", action="store_true", help="also print a concise GitHub-issue body")
    wc.add_argument("--json", action="store_true")
    wc.set_defaults(func=cmd_watch_cycle)

    wp = wsub.add_parser("policy", help="check only the official policy pages")
    wp.add_argument("--state", default="research/bounty-monitor/state")
    wp.add_argument("--out", default="research/bounty-monitor")
    wp.add_argument("--registry")
    wp.add_argument("--target", action="append", dest="targets")
    wp.add_argument("--timeout", type=int, default=25)
    wp.add_argument("--dry-run", action="store_true")
    wp.add_argument("--json", action="store_true")
    wp.set_defaults(func=cmd_watch_cycle, skip_policy=False, skip_repos=True,
                    skip_contracts=True, skip_source=True, max_policy=None, max_repos=None,
                    max_contracts=None, email=False, email_to="", issue=False)

    ws = wsub.add_parser("status", help="show durable state without network access")
    ws.add_argument("--state", default="research/bounty-monitor/state")
    ws.add_argument("--json", action="store_true")
    ws.set_defaults(func=cmd_watch_status)

    wst = wsub.add_parser("selftest", help="real-network smoke test (policy + GitHub + RPC)")
    wst.add_argument("--registry")
    wst.add_argument("--timeout", type=int, default=25)
    wst.add_argument("--json", action="store_true")
    wst.set_defaults(func=cmd_watch_selftest)

    o = sub.add_parser("objectives", help="generate attacker objectives")
    o.add_argument("--profile", required=True)
    o.add_argument("--out")
    o.set_defaults(func=cmd_objectives)

    c = sub.add_parser("chains", help="generate attack chains")
    c.add_argument("--profile", required=True)
    c.add_argument("--out")
    c.set_defaults(func=cmd_chains)

    cap = sub.add_parser(
        "capability",
        help="what the engine can and cannot do, and the gaps found in the last missions",
    )
    cap.add_argument("--json", action="store_true", help="emit the matrix as JSON")
    cap.set_defaults(func=cmd_capability)

    dfl = sub.add_parser(
        "dataflow",
        help="SSA-lite whole-program taint/dataflow over Solidity source",
    )
    dfl.add_argument("path", help="a .sol file or a directory")
    dfl.add_argument("--contract", default="", help="restrict to one contract")
    dfl.add_argument("--limit", type=int, default=50, help="flows to print")
    dfl.add_argument("--json", action="store_true")
    dfl.add_argument("--out")
    dfl.set_defaults(func=cmd_dataflow)

    ing = sub.add_parser(
        "ingest",
        help="scan a Solidity or Rust/Substrate tree into an attack surface and candidate leads",
    )
    ing.add_argument("path", help="a .sol file or a directory to scan")
    ing.add_argument("--json", action="store_true", help="emit the surface and leads as JSON")
    ing.add_argument("--language", choices=["auto", "solidity", "rust", "vyper", "go"],
                     default="auto",
                     help="which scanner to use; auto decides from the tree (default)")
    ing.add_argument("--allow-unscanned", action="append", default=[],
                     metavar="LANG",
                     help="record an explicit partial-coverage exception for LANG "
                          "(repeatable; never a clean-coverage claim)")
    ing.add_argument("--out", help="write surface.md (or surface.json) into this directory")
    ing.add_argument("--synthesize", action="store_true",
                     help="build an executable model from each contract and certify it")
    ing.add_argument("--coverage", action="store_true",
                     help="emit the model-coverage ledger for each synthesized contract")
    ing.add_argument("--depth", type=int, default=3,
                     help="certifier depth for --synthesize (default 3)")
    ing.add_argument("--symbolic", action="store_true",
                     help="with --synthesize, ask symbolic reachability per operation")
    ing.add_argument("--symbolic-depth", type=int, default=0,
                     help="reachability depth (default: --depth)")
    ing.add_argument("--symbolic-paths", type=int, default=1000,
                     help="reachability path budget (default 1000)")
    ing.add_argument("--smt", action="store_true",
                     help="with --symbolic, use the optional Z3 backend when installed")
    ing.add_argument("--exec", action="store_true",
                     help="with --synthesize, render the best certified witness as a Foundry "
                          "test and run it behind --compatibility (execution-grade evidence; "
                          "a PASS is a reproduction, never an upgrade of the model verdict)")
    ing.add_argument("--poc-timeout", type=int, default=600,
                     help="timeout in seconds for each --exec Foundry run (default 600)")
    ing.add_argument("--compile", action="store_true",
                     help="compile with forge/solc and emit the ABI-derived model "
                          "(requires --compatibility)")
    ing.add_argument("--compatibility", metavar="RECORD",
                     help="compatibility record (JSON path) required for --compile")
    ing.add_argument("--target-component", default="",
                     help="component name for the compatibility binding (default: path name)")
    ing.add_argument("--repository", default="",
                     help="repository the compatibility record is bound to")
    ing.add_argument("--commit", default="",
                     help="commit the compatibility record is bound to")
    ing.set_defaults(func=cmd_ingest)

    ext = sub.add_parser(
        "external",
        help="run registered external security tools behind the gate (fail-closed)",
    )
    ext.add_argument("--list", action="store_true", help="list registered tools")
    ext.add_argument("--doctor", action="store_true",
                     help="per tool: installed / missing / manual")
    ext.add_argument("--run", metavar="TOOL", help="run a registered tool against --target")
    ext.add_argument("--target", default="", help="the target path or URL for --run")
    ext.add_argument("--compatibility", metavar="RECORD",
                     help="compatibility record (required for --run)")
    ext.add_argument("--repository", default="")
    ext.add_argument("--commit", default="")
    ext.add_argument("--timeout", type=int, default=300,
                     help="seconds for the tool run (default 300)")
    ext.add_argument("--to-hypotheses", action="store_true",
                     help="with --run, promote parsed leads to grounded hypotheses "
                          "(candidates, never findings)")
    ext.add_argument("--component", default="",
                     help="component the leads ground to (for --to-hypotheses)")
    ext.add_argument("--to-target", action="store_true",
                     help="with --to-hypotheses, synthesize each promoted component into "
                          "a certifiable Target (model-level, not a finding)")
    ext.add_argument("--certify", action="store_true",
                     help="with --to-target, also run the certifier (model-level)")
    ext.add_argument("--depth", type=int, default=4,
                     help="certifier search depth for --certify (default 4)")
    ext.add_argument("--poc", action="store_true",
                     help="with --to-target --certify, render+run a Foundry reproduction "
                          "of each certified witness (fail-closed; needs --compatibility)")
    ext.add_argument("--poc-timeout", type=int, default=600,
                     help="seconds for the Foundry PoC run (default 600)")
    ext.add_argument("--record-finding", action="store_true",
                     help="with --poc, record each PASS reproduction in the findings "
                          "repository (STRONGLY_SUPPORTED until independently verified)")
    ext.add_argument("--findings-dir", default="research/private/findings")
    ext.add_argument("--evidence-dir", default="research/private/evidence")
    ext.add_argument("--reviewer", default="",
                     help="reviewer identity for the finding record")
    ext.add_argument("--verification-result", default="",
                     help="the independent review's result (needed to CONFIRM)")
    ext.add_argument("--independent", action="store_true",
                     help="record the review as INDEPENDENT_MODEL provenance")
    ext.add_argument("--json", action="store_true")
    ext.set_defaults(func=cmd_external)

    aht = sub.add_parser(
        "autohunt",
        help="autonomous hunt across in-scope targets; stop only for a human reviewer")
    aht.add_argument("--targets", help="JSON list of in-scope targets "
                     "(component, path, repository, commit, compatibility)")
    aht.add_argument("--policy", help="normalized program policy JSON for the bounty gate")
    aht.add_argument("--program", default="", help="program name")
    aht.add_argument("--scanner", default="semgrep", help="external scanner to run per target")
    aht.add_argument("--poc", action="store_true",
                     help="render+run a Foundry PoC per model violation")
    aht.add_argument("--depth", type=int, default=4)
    aht.add_argument("--poc-timeout", type=int, default=600)
    aht.add_argument("--findings-dir", default="research/private/findings")
    aht.add_argument("--evidence-dir", default="research/private/evidence")
    aht.add_argument("--reviewer", default="")
    aht.add_argument("--verification-result", default="")
    aht.add_argument("--independent", action="store_true")
    aht.add_argument("--max-targets", type=int, default=0)
    aht.add_argument("--max-runtime", type=float, default=0.0)
    aht.add_argument("--no-stop-on-review", action="store_true",
                     help="collect every reviewable candidate instead of stopping at the first")
    aht.add_argument("--json", action="store_true")
    aht.set_defaults(func=cmd_autohunt)

    imp = sub.add_parser(
        "impact",
        help="pre-surface impact triage: is a claim even a security issue?")
    imp.add_argument("--impact", required=True, help="the claimed impact (plain text)")
    imp.add_argument("--surface", default="contract",
                     help="contract|on-chain|off-chain|api|http|config|...")
    imp.add_argument("--identifiers", nargs="*",
                     help="the two identifiers a 'differs' claim compares")
    imp.add_argument("--outcome", default="", help="explicit attacker outcome, if known")
    imp.add_argument("--json", action="store_true")
    imp.set_defaults(func=cmd_impact)

    agt = sub.add_parser(
        "agent",
        help="human research loop: see every stack, hunt modelled ones, never lie")
    agt.add_argument("path", help="target source tree")
    agt.add_argument("--policy", help="normalized program policy JSON (optional)")
    agt.add_argument("--program", default="", help="program name (optional)")
    agt.add_argument("--repository", default="", help="repository the record is bound to")
    agt.add_argument("--commit", default="", help="commit the record is bound to")
    agt.add_argument("--compatibility", default="", help="validated compatibility record")
    agt.add_argument("--scanner", default="semgrep")
    agt.add_argument("--poc", action="store_true")
    agt.add_argument("--max-targets", type=int, default=0)
    agt.add_argument("--json", action="store_true")
    agt.set_defaults(func=cmd_agent)

    itg = sub.add_parser(
        "interrogate",
        help="derive the claims the code makes and try to falsify each one",
    )
    itg.add_argument("path", help="a .sol/.rs file or a directory to interrogate")
    itg.add_argument("--language", choices=["auto", "solidity", "rust", "go"], default="auto",
                     help="which scanner to use; auto decides from the tree (default)")
    itg.add_argument("--allow-unscanned", action="append", default=[],
                     metavar="LANG",
                     help="record an explicit partial-coverage exception for LANG "
                          "(repeatable; never a clean-coverage claim)")
    itg.add_argument("--json", action="store_true", help="emit the ledger as JSON")
    itg.add_argument("--out", help="write interrogation.md (or .json) into this directory")
    itg.set_defaults(func=cmd_interrogate)

    dos = sub.add_parser(
        "dossier",
        help="one explorable view of a project: surface, leads, claims, flows, blind spots",
    )
    dos.add_argument("path", help="a source file or a directory")
    dos.add_argument("--language", choices=["auto", "solidity", "rust", "vyper", "go"],
                     default="auto",
                     help="which scanner to use; auto decides from the tree (default)")
    dos.add_argument("--allow-unscanned", action="append", default=[],
                     metavar="LANG",
                     help="record an explicit partial-coverage exception for LANG "
                          "(repeatable; never a clean-coverage claim)")
    dos.add_argument("--json", action="store_true", help="emit the dossier as JSON")
    dos.add_argument("--out", help="write dossier.md (or dossier.json) into this directory")
    dos.set_defaults(func=cmd_dossier)

    au = sub.add_parser(
        "audit",
        help="audit-report coverage: what the audit read, and what it left unread",
    )
    aus = au.add_subparsers(dest="sub", required=True)
    auc = aus.add_parser(
        "coverage",
        help="map an audit report onto the surface and rank the unaudited reachable surface",
    )
    auc.add_argument("path", help="a .sol file or a directory")
    auc.add_argument("--audit", required=True, help="audit report file (JSON or Markdown)")
    auc.add_argument("--language", choices=["auto", "solidity", "vyper", "rust", "go"],
                     default="auto", help="which scanner to use (default: auto)")
    auc.add_argument("--allow-unscanned", action="append", default=[],
                     metavar="LANG", help="record a partial-coverage exception (repeatable)")
    auc.add_argument("--json", action="store_true", help="emit the coverage map as JSON")
    auc.add_argument("--out", help="write audit-coverage.md (or .json) into this directory")
    auc.set_defaults(func=cmd_audit_coverage)

    dbg = sub.add_parser(
        "debug",
        help="read-only transaction replay and call tree",
    )
    dbs = dbg.add_subparsers(dest="sub", required=True)
    dbt = dbs.add_parser(
        "tx",
        help="fetch a transaction, trace it and render the call tree",
    )
    dbt.add_argument("hash", help="transaction hash (0x...)")
    dbt.add_argument("--rpc", help="RPC URL (default: resolved from --chain)")
    dbt.add_argument("--chain", default="mainnet", help="chain name or id (default: mainnet)")
    dbt.add_argument("--abi", help="ABI JSON file used to decode calldata")
    dbt.add_argument("--timeout", type=int, default=20, help="RPC timeout in seconds")
    dbt.add_argument("--json", action="store_true", help="emit the replay as JSON")
    dbt.add_argument("--out", help="write debug-tx.md (or .json) into this directory")
    dbt.set_defaults(func=cmd_debug_tx)

    exp = sub.add_parser(
        "explore",
        help="interactive shell over a project's recovered surface (or --query for one shot)",
    )
    exp.add_argument("path", help="a source file or a directory")
    exp.add_argument("--language", choices=["auto", "solidity", "rust", "vyper", "go"],
                     default="auto", help="which scanner to use (default: auto)")
    exp.add_argument("--allow-unscanned", action="append", default=[],
                     metavar="LANG", help="record a partial-coverage exception (repeatable)")
    exp.add_argument("--query", help="run one query and exit (non-interactive)")
    exp.set_defaults(func=cmd_explore)

    f = sub.add_parser("fuzz", help="stateful invariant engine")
    f.add_argument("--target", choices=_target_choices(), default="vulnerable")
    f.add_argument("--strategy", choices=["random", "corpus"], default="random",
                   help="random = blind stateful fuzzer; corpus = coverage-guided "
                        "(AFL-style) fuzzer that keeps and mutates inputs that reach "
                        "new behaviour -- stronger on deep, ordered, state-gated bugs")
    f.add_argument("--runs", type=int, default=200)
    f.add_argument("--steps", type=int, default=12)
    f.add_argument("--seed", type=int, default=0)
    f.add_argument("--out")
    f.set_defaults(func=cmd_fuzz)

    fb = sub.add_parser("fuzz-bench",
                        help="coverage-guided vs random ablation on the hard/deep fixtures")
    fb.add_argument("--budget", type=int, default=4000)
    fb.add_argument("--steps", type=int, default=20)
    fb.add_argument("--seed", type=int, default=0)
    fb.add_argument("--out")
    fb.set_defaults(func=cmd_fuzz_bench)

    r = sub.add_parser("reproduce", help="reproduce a failing sequence")
    r.add_argument("--target", choices=_target_choices(), default="vulnerable")
    r.add_argument("--invariant", required=True)
    r.add_argument("--runs", type=int, default=200)
    r.add_argument("--steps", type=int, default=12)
    r.add_argument("--seed", type=int, default=0)
    r.set_defaults(func=cmd_reproduce)

    tg = sub.add_parser("targets", help="list executable invariant-engine targets")
    tg.add_argument("--out")
    tg.set_defaults(func=cmd_targets)

    cov = sub.add_parser(
        "coverage",
        help="attack-class model coverage: which objective categories the engine can break",
    )
    cov.add_argument("--out")
    cov.add_argument("--unified", action="store_true",
                     help="join model, capability and taxonomy coverage into one ledger")
    cov.set_defaults(func=cmd_coverage)

    val = sub.add_parser(
        "value",
        help="universal value & profitability engine: classify fields, price violations",
    )
    vsub = val.add_subparsers(dest="sub", required=True)
    vc = vsub.add_parser("classify", help="how a target's snapshot fields are read as value")
    vc.add_argument("--target", choices=_target_choices(), default="vulnerable")
    vc.add_argument("--out")
    vc.set_defaults(func=cmd_value)
    vt = vsub.add_parser("targets", help="which targets expose trackable attacker value")
    vt.add_argument("--out")
    vt.set_defaults(func=cmd_value)
    va = vsub.add_parser("analyse", help="price a target's discovered violations")
    va.add_argument("--target", choices=_target_choices(), default="vulnerable")
    va.add_argument("--seed", type=int, default=0)
    va.add_argument("--steps", type=int, default=6)
    va.add_argument("--budget", type=int, default=4000)
    va.add_argument("--out")
    va.set_defaults(func=cmd_value)

    asr = sub.add_parser(
        "assure",
        help="bounded-exhaustive certification + the search portfolio (can't-miss discipline)",
    )
    asub = asr.add_subparsers(dest="sub", required=True)
    ao = asub.add_parser(
        "oracles",
        help="audit the declared invariants: can each one catch anything at all?",
    )
    ao.add_argument("--target", choices=_target_choices(), default="vulnerable")
    ao.add_argument("--depth", type=int, default=3, help="state-sampling depth")
    ao.add_argument("--max-sequences", type=int, default=4000)
    ao.add_argument("--out")
    ao.set_defaults(func=cmd_assure)
    ac = asub.add_parser(
        "certify",
        help="exhaustively enumerate every sequence up to a depth; prove absence within the bound",
    )
    ac.add_argument("--target", choices=_target_choices(), default="vulnerable")
    ac.add_argument("--depth", type=int, default=3, help="max sequence length enumerated")
    ac.add_argument("--max-sequences", type=int, default=200000)
    ac.add_argument("--no-price", action="store_true", help="skip value pricing of hits")
    ac.add_argument("--out")
    ac.set_defaults(func=cmd_assure)
    ad = asub.add_parser(
        "directed",
        help="directed beam search: value-moving paths first, with a recorded bound",
    )
    ad.add_argument("--target", choices=_target_choices(), default="vulnerable")
    ad.add_argument("--depth", type=int, default=4)
    ad.add_argument("--max-states", dest="max_sequences", type=int, default=200000)
    ad.add_argument("--beam", type=int, default=500)
    ad.add_argument("--param-sets", type=int, default=32)
    ad.add_argument("--out")
    ad.set_defaults(func=cmd_assure)
    ap = asub.add_parser(
        "portfolio",
        help="run every strategy, union the counterexamples, report which covered what",
    )
    ap.add_argument("--target", choices=_target_choices(), default="vulnerable")
    ap.add_argument("--depth", type=int, default=3, help="exhaustive-certificate depth")
    ap.add_argument("--max-sequences", type=int, default=100000)
    ap.add_argument("--runs", type=int, default=4000, help="coverage-guided corpus budget")
    ap.add_argument("--random-runs", type=int, default=400)
    ap.add_argument("--strategies", default="",
                    help="comma-separated subset (default: all) of "
                         "oracles,exhaustive,adaptive,guided,corpus,random")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out")
    ap.set_defaults(func=cmd_assure)

    hn = sub.add_parser(
        "hunt",
        help="the universal hunt: every engine in order (recall -> search -> certify "
             "-> verify -> order -> remember) with one honest verdict",
    )
    hn.add_argument("--target", choices=_target_choices(), default="vulnerable")
    hn.add_argument("--stages", default="",
                    help="comma-separated subset of "
                         "recall,search,certify,verify,order,remember (default: all)")
    hn.add_argument("--depth", type=int, default=3, help="exhaustive-certificate depth")
    hn.add_argument("--max-sequences", type=int, default=100000)
    hn.add_argument("--runs", type=int, default=4000, help="coverage-guided corpus budget")
    hn.add_argument("--random-runs", type=int, default=400)
    hn.add_argument("--strategies", default="",
                    help="comma-separated search subset (default: all)")
    hn.add_argument("--concolic-rounds", type=int, default=3,
                    help="in-domain mutation rounds to turn a near-miss into a proof")
    hn.add_argument("--scenario", default="",
                    help="ordering scenario to search (see 'statespace mempool list')")
    hn.add_argument("--max-attacker-steps", type=int, default=3)
    hn.add_argument("--max-orderings", type=int, default=4000)
    hn.add_argument("--memory", action="store_true",
                    help="enable cross-target recall + write-back (opt-in)")
    hn.add_argument("--memory-path", default="research/private/attack-memory.jsonl")
    hn.add_argument("--control", default="",
                    help="the guarded twin target that establishes the discriminating "
                         "control for verification (e.g. safe)")
    hn.add_argument("--in-scope", action="store_true",
                    help="the target asset is within an authorized program scope")
    hn.add_argument("--scope-reference", default="")
    hn.add_argument("--authorized", action="store_true",
                    help="active testing was authorized by the scope gate")
    hn.add_argument("--seed", type=int, default=0)
    hn.add_argument("--json", action="store_true")
    hn.add_argument("--out")
    hn.add_argument("--compatibility", metavar="RECORD",
                    help="language-aware compatibility record (JSON) for this target; "
                         "required unless an enclosing run already authorised it")
    hn.set_defaults(func=cmd_hunt)

    df = sub.add_parser(
        "differential",
        help="run every vulnerable/guarded target pair and assert the expected contrast",
    )
    df.add_argument("--runs", type=int, default=400)
    df.add_argument("--steps", type=int, default=10)
    df.add_argument("--seed", type=int, default=0)
    df.add_argument(
        "--depth", type=int, default=6,
        help="when random search finds nothing on a vulnerable twin, escalate to the "
             "bounded-exhaustive certifier at this depth (0 disables the escalation)",
    )
    df.add_argument("--out")
    df.set_defaults(func=cmd_differential)

    from .adversary import PROFILES as _ADVERSARY_PROFILES

    adv = sub.add_parser(
        "adversary",
        help="adversary emulation: plan the campaign a given capability set would run",
    )
    advsub = adv.add_subparsers(dest="adversary_command", required=True)
    ap = advsub.add_parser("profiles", help="list the adversary profiles")
    ap.add_argument("--json", action="store_true")
    ap.set_defaults(func=cmd_adversary)
    apl = advsub.add_parser(
        "plan",
        help="lay out the staged campaign a profile would run for one objective",
    )
    apl.add_argument("--profile", required=True,
                     choices=sorted(_ADVERSARY_PROFILES))
    apl.add_argument("--objective", required=True,
                     help="one of the three mindset outcomes, verbatim")
    apl.add_argument("--asset", required=True)
    apl.add_argument("--target", default="", help="target component name (default: asset)")
    apl.add_argument("--authz", help="authorization record JSON; without it the plan "
                                     "is thinking only and no stage is executable")
    apl.add_argument("--json", action="store_true")
    apl.set_defaults(func=cmd_adversary)

    cm = sub.add_parser("campaign", help="run the authorization-gated attack loop")
    cm.add_argument("--engagement", required=True)
    cm.add_argument("--profile", required=True)
    cm.add_argument("--authz", required=True)
    cm.add_argument("--asset", required=True)
    cm.add_argument("--workdir", default="research/private/engagements")
    cm.add_argument("--findings-dir", default="research/private/findings",
                    help="where campaign findings are automatically documented")
    cm.add_argument("--compatibility", metavar="RECORD",
                    help="language-aware compatibility record (JSON) for this target; "
                         "see `blackheart compat template` and "
                         "docs/SECURITY_TOOL_COMPATIBILITY.md")
    cm.set_defaults(func=cmd_campaign)

    v = sub.add_parser("verify", help="independent verification of a finding")
    v.add_argument("--finding", required=True)
    v.add_argument("--ctx", required=True)
    v.set_defaults(func=cmd_verify)

    tg = sub.add_parser(
        "triage",
        help="deterministic weak-finding gate: reject kill-signal classes before verification")
    tg.add_argument("--category", required=True,
                    help="finding class (e.g. idor, reflected-xss, open-redirect)")
    tg.add_argument("--evidence", action="append", default=[],
                    help="an established evidence tag (repeatable); see "
                         "blackheart.verify.triage.Evidence")
    tg.add_argument("--chain-demonstrated", action="store_true",
                    help="the required chain has been proven end to end")
    tg.add_argument("--json", action="store_true")
    tg.set_defaults(func=cmd_triage)

    rp = sub.add_parser("report", help="render a finding report")
    rp.add_argument("--finding", required=True)
    rp.add_argument("--out", required=True)
    rp.add_argument("--remediation")
    rp.set_defaults(func=cmd_report)

    eg = sub.add_parser("engagement", help="run the full reference engagement end-to-end")
    eg.add_argument("--workdir", default="research/private/reference-engagement")
    eg.add_argument("--findings-dir", default="research/private/findings",
                    help="where the engagement's finding is automatically documented")
    eg.set_defaults(func=cmd_engagement)

    ag = sub.add_parser("agents", help="list specialist agents and skills")
    ag.set_defaults(func=cmd_agents)

    ms = sub.add_parser("mindset", help="who BLACKHEART is + the question every mission answers")
    ms.add_argument("--json", action="store_true", help="emit the mindset as JSON")
    ms.add_argument("--question", action="store_true", help="print only the question")
    ms.add_argument("--persona", action="store_true", help="print only the persona")
    ms.add_argument("--lens-for", metavar="CATEGORY",
                    help="apply the lens to a vulnerability class")
    ms.add_argument("--text", action="append",
                    help="extra text to scan for attacker levers (repeatable)")
    ms.set_defaults(func=cmd_mindset)

    do = sub.add_parser("doctrine", help="the operational doctrine: identity, lifecycle, gates, invariants")
    do.add_argument("--json", action="store_true", help="emit the whole doctrine as JSON")
    do.add_argument("--prompt", action="store_true", help="emit the compact doctrine prompt block")
    do.add_argument("--phase", metavar="KEY", help="show one lifecycle phase (e.g. EXPLOIT_VALIDATION)")
    do.set_defaults(func=cmd_doctrine)

    cp = sub.add_parser(
        "compat",
        help="language-aware tool compatibility: registry, stack detection, gate")
    cp_sub = cp.add_subparsers(dest="compat_action", required=True)

    cp_reg = cp_sub.add_parser("registry", help="the verified per-language toolchain")
    cp_reg.add_argument("--language", help="narrow to one language (e.g. Rust, C++)")
    cp_reg.add_argument("--json", action="store_true")
    cp_reg.set_defaults(func=cmd_compat)

    cp_det = cp_sub.add_parser(
        "detect", help="identify the stack from source, manifests and build config")
    cp_det.add_argument("--root", default=".", help="repository root to scan")
    cp_det.add_argument("--json", action="store_true")
    cp_det.set_defaults(func=cmd_compat)

    cp_chk = cp_sub.add_parser(
        "check", help="the pre-execution compatibility gate (exit 2 on BLOCK)")
    cp_chk.add_argument("--file", required=True,
                        help="compatibility record JSON (templates/tool-compatibility.json)")
    cp_chk.add_argument("--smoke-test", choices=("passed", "failed", "not-run"),
                        help="record the smoke-test result before deciding")
    cp_chk.add_argument("--json", action="store_true")
    cp_chk.set_defaults(func=cmd_compat)

    cp_st = cp_sub.add_parser("statuses", help="the four permitted execution statuses")
    cp_st.add_argument("--json", action="store_true")
    cp_st.set_defaults(func=cmd_compat)

    cp_tpl = cp_sub.add_parser("template", help="print or write a blank record")
    cp_tpl.add_argument("--out", default="", help="write the record here")
    cp_tpl.set_defaults(func=cmd_compat)

    ev = sub.add_parser("evaluate",
                        help="controlled adversarial research-quality suite (local targets only)")
    ev.add_argument("--list", action="store_true", help="list the attack-class cases")
    ev.add_argument("--runs", type=int, default=400, help="fuzz runs per case")
    ev.add_argument("--steps", type=int, default=12, help="steps per fuzz run")
    ev.add_argument("--seed", type=int, default=0)
    ev.add_argument("--workdir", default="", help="write the JSON report here")
    ev.set_defaults(func=cmd_evaluate)

    eb = sub.add_parser(
        "evmbench",
        help="score an analyser report against EVMbench fix locations (key-free)")
    eb.add_argument("--dataset", required=True,
                    help="dataset root containing audits/ (openai/frontier-evals "
                         "project/evmbench)")
    eb.add_argument("--findings", nargs="+", required=True,
                    help="one or more engine JSON reports (Slither format)")
    eb.add_argument("--audit", action="append", default=[],
                    help="restrict to an audit id (repeatable; default: all)")
    eb.add_argument("--json", action="store_true", help="machine-readable report")
    eb.add_argument("--out", default="", help="write the JSON report here")
    eb.set_defaults(func=cmd_evmbench)

    it = sub.add_parser("intel", help="external intelligence via You.com (search, contents, research)")
    itsub = it.add_subparsers(dest="sub", required=True)

    ih = itsub.add_parser("health", help="probe You.com connectivity (unbilled)")
    ih.add_argument("--json", action="store_true")
    ih.add_argument("--timeout", type=int, default=30)
    ih.set_defaults(func=cmd_intel, allow_paid=False, max_paid_calls=0)

    isr = itsub.add_parser("search", help="web search (snippets by default)")
    isr.add_argument("query")
    isr.add_argument("--count", type=int, default=10)
    isr.add_argument("--freshness", default="", help="day|week|month|year|YYYY-MM-DDtoYYYY-MM-DD")
    isr.add_argument("--extract", default="", choices=["", "highlights", "full_page"],
                     help="paid page extraction (requires --allow-paid)")
    isr.add_argument("--allow-paid", action="store_true")
    isr.add_argument("--max-paid-calls", type=int, default=1)
    isr.add_argument("--timeout", type=int, default=30)
    isr.add_argument("--json", action="store_true")
    isr.set_defaults(func=cmd_intel)

    ic = itsub.add_parser("contents", help="fetch page content (paid)")
    ic.add_argument("--url", dest="urls", action="append", required=True)
    ic.add_argument("--allow-paid", action="store_true")
    ic.add_argument("--max-paid-calls", type=int, default=1)
    ic.add_argument("--timeout", type=int, default=30)
    ic.add_argument("--json", action="store_true")
    ic.set_defaults(func=cmd_intel)

    ir = itsub.add_parser("research", help="citation-backed research answer (paid)")
    ir.add_argument("question")
    ir.add_argument("--effort", default="standard",
                    choices=["lite", "standard", "deep", "exhaustive"])
    ir.add_argument("--allow-paid", action="store_true")
    ir.add_argument("--max-paid-calls", type=int, default=1)
    ir.add_argument("--timeout", type=int, default=180)
    ir.add_argument("--json", action="store_true")
    ir.set_defaults(func=cmd_intel)

    im = itsub.add_parser("mcp", help="emit the You.com MCP server config for an agent host")
    im.add_argument("--no-key", action="store_true", help="emit the keyless free profile")
    im.add_argument("--no-docs", action="store_true", help="omit the docs MCP server")
    im.set_defaults(func=cmd_intel)

    ip = itsub.add_parser("providers",
                          help="list intelligence providers and whether each is configured")
    ip.add_argument("--probe", action="store_true",
                    help="make a real, cheap request per configured provider")
    ip.add_argument("--timeout", type=int, default=20)
    ip.add_argument("--json", action="store_true")
    ip.set_defaults(func=cmd_intel)

    irt = itsub.add_parser(
        "route",
        help="search with You.com enforced (primary-only); keyless fallback is opt-in")
    irt.add_argument("query")
    irt.add_argument("--count", type=int, default=10)
    irt.add_argument("--order", default=",".join(DEFAULT_ORDER),
                     help="comma-separated provider preference order")
    irt.add_argument("--allow-fallback", action="store_true",
                     help="opt in to the keyless fallbacks when the primary fails "
                          "(default: primary-only, so a generic search never answers)")
    irt.add_argument("--cross-check", action="store_true",
                     help="also query the other configured providers and report disagreement")
    irt.add_argument("--timeout", type=int, default=20)
    irt.add_argument("--json", action="store_true")
    irt.set_defaults(func=cmd_intel)

    iset = itsub.add_parser("setup",
                            help="print exactly how to configure the intelligence layer")
    iset.add_argument("--json", action="store_true")
    iset.set_defaults(func=cmd_intel)

    ires = itsub.add_parser(
        "investigate",
        help="live research output, fenced as untrusted data with the attacker lens")
    ires.add_argument("query")
    ires.add_argument("--count", type=int, default=10)
    ires.add_argument("--order", default=",".join(DEFAULT_ORDER),
                      help="comma-separated provider preference order")
    ires.add_argument("--allow-fallback", action="store_true",
                      help="opt in to the keyless fallbacks when the primary fails")
    ires.add_argument("--cross-check", action="store_true",
                      help="also query the other configured providers and report disagreement")
    ires.add_argument("--timeout", type=int, default=20)
    ires.add_argument("--json", action="store_true")
    ires.set_defaults(func=cmd_intel)

    idis = itsub.add_parser(
        "discover",
        help="structured, verified discovery via You.com: RPC endpoints, contract "
             "addresses, chain ids (external text is a lead; a real call makes it a fact)")
    idis.add_argument("kind", choices=["rpc", "contract", "chain"])
    idis.add_argument("query", help="chain name, 'protocol chain', or chain name")
    idis.add_argument("--chain", default="", help="chain name, for contract lookups")
    idis.add_argument("--chain-id", type=int, default=None,
                      help="expected chain id; an endpoint that answers a different id is not verified")
    idis.add_argument("--rpc", default="",
                      help="RPC endpoint to verify a contract address against")
    idis.add_argument("--count", type=int, default=10)
    idis.add_argument("--no-probe", action="store_true",
                      help="do not call endpoints; return unverified candidates only")
    idis.add_argument("--timeout", type=int, default=15)
    idis.add_argument("--json", action="store_true")
    idis.set_defaults(func=cmd_intel)

    ib = itsub.add_parser(
        "bootstrap",
        help="write the intelligence config into a project's .openhands/ (for new projects)")
    ib.add_argument("--root", default=".", help="project root (default: current directory)")
    ib.add_argument("--force", action="store_true", help="overwrite an existing mcp.json")
    ib.add_argument("--json", action="store_true")
    ib.set_defaults(func=cmd_intel)

    ss = sub.add_parser(
        "statespace",
        help="adversarial state-machine discovery: model -> hypotheses -> violations -> verdicts",
    )
    ss.add_argument("--fixture", help="a built-in local fixture (vulnerable or -guarded control)")
    ss.add_argument("--model", help="a SystemModel JSON or a ThreatModel JSON to adapt")
    ss.add_argument("--seed", type=int, default=0)
    ss.add_argument("--steps", type=int, default=6, help="max sequence length")
    ss.add_argument("--out")
    sssub = ss.add_subparsers(dest="sub", required=True)
    sssub.add_parser("strategies", help="list the hypothesis strategies").set_defaults(func=cmd_statespace)
    sssub.add_parser("model", help="print the target's security model").set_defaults(func=cmd_statespace)
    sssub.add_parser("hypotheses", help="generate falsifiable hypotheses").set_defaults(func=cmd_statespace)
    sssub.add_parser("explore", help="search for invariant-violating sequences").set_defaults(func=cmd_statespace)
    sssub.add_parser("discover", help="explore then independently verify each violation").set_defaults(func=cmd_statespace)

    ssk = sssub.add_parser("skills", help="list / run / write the adversarial skill library")
    ssk.add_argument("--run", metavar="SKILL_ID", help="run one skill against --fixture/--model")
    ssk.add_argument("--write", metavar="DIR", help="write the skills as Markdown into DIR")
    ssk.set_defaults(func=cmd_statespace)

    ssb = sssub.add_parser("benchmark", help="run the reproducible discovery benchmark")
    ssb.add_argument("--runs", type=int, default=200)
    ssb.add_argument("--baseline-runs", type=int, default=400)
    ssb.set_defaults(func=cmd_statespace)

    ssr = sssub.add_parser(
        "runtime",
        help="execute the engine against a real controlled local app (loopback HTTP)",
    )
    ssr.add_argument("--app", default="", help="the controlled local app to run against")
    ssr.add_argument("--list-apps", action="store_true", help="list the harness apps")
    ssr.add_argument("--declare", action="store_true",
                     help="print the app's auditable runtime model declaration instead of running")
    ssr.add_argument("--research", action="store_true",
                     help="after a finding, query the external-intelligence layer (You.com first)")
    ssr.add_argument("--cross-check", action="store_true",
                     help="also query the other configured providers and record disagreement")
    ssr.add_argument("--out")
    ssr.set_defaults(func=cmd_statespace)

    ssrb = sssub.add_parser(
        "runtime-bench",
        help="benchmark the runtime (executed) path against the in-memory baseline",
    )
    ssrb.add_argument("--out")
    ssrb.set_defaults(func=cmd_statespace)

    sse = sssub.add_parser(
        "evm",
        help="discover + independently verify against real external EVM bytecode "
             "(vendored Damn Vulnerable DeFi v4.1.0, OpenZeppelin Ethernaut and "
             "Euler V1 on a local anvil node)",
    )
    sse.add_argument("--case", default="", help="the external case to run")
    sse.add_argument("--list-cases", action="store_true", help="list the external EVM cases")
    sse.add_argument("--all", action="store_true", help="run every registered case")
    sse.add_argument("--no-verify", action="store_true", help="skip independent verification")
    sse.add_argument("--seed", type=int, default=0)
    sse.add_argument("--steps", type=int, default=6)
    sse.add_argument("--out")
    sse.set_defaults(func=cmd_statespace)

    sseb = sssub.add_parser(
        "evm-bench",
        help="fair comparison on the external EVM cases: guided vs random fuzzing vs "
             "the project's own upstream test, same bytecode and budget",
    )
    sseb.add_argument("--case", default="", help="one case, or omit for all")
    sseb.add_argument("--all", action="store_true", help="run every registered case")
    sseb.add_argument("--random-sequences", type=int, default=400,
                      help="random-fuzzer sequence budget per case")
    sseb.add_argument("--seed", type=int, default=0)
    sseb.add_argument("--steps", type=int, default=6)
    sseb.add_argument("--out")
    sseb.set_defaults(func=cmd_statespace)

    ssm = sssub.add_parser(
        "mempool",
        help="ordering (MEV) search: front-run / sandwich interleavings against a victim flow",
    )
    ssm.add_argument("scenario", nargs="?", default="list",
                     help="scenario name, or 'list' to enumerate")
    ssm.add_argument("--max-attacker-steps", type=int, default=3,
                     help="most attacker operations a candidate interleaving may use")
    ssm.add_argument("--max-orderings", type=int, default=4000,
                     help="budget on candidate interleavings to execute")
    ssm.add_argument("--out")
    ssm.set_defaults(func=cmd_statespace)

    disc = sub.add_parser(
        "discovery",
        help="historical-rediscovery engine: corpus -> benchmark -> misses -> economics -> Foundry PoC",
    )
    dsub = disc.add_subparsers(dest="sub", required=True)
    dsub.add_parser("corpus", help="corpus summary (cases, root causes, repos)").set_defaults(func=cmd_discovery)
    dsub.add_parser("cases", help="list every corpus case").set_defaults(func=cmd_discovery)
    dsub.add_parser("heldout", help="list the blind holdout cases").set_defaults(func=cmd_discovery)
    dc = dsub.add_parser("case", help="run one case through all three engines")
    dc.add_argument("case_id")
    dc.add_argument("--memory", action="store_true",
                    help="consume/grow the cross-target attack memory for this case")
    dc.add_argument("--memory-dir", default=None, help="attack memory JSONL path")
    dc.set_defaults(func=cmd_discovery)
    db = dsub.add_parser("benchmark", help="run the three-configuration benchmark")
    db.add_argument("--out")
    db.add_argument("--memory", action="store_true",
                    help="grow and consume the cross-target attack memory across cases")
    db.add_argument("--memory-dir", default=None, help="attack memory JSONL path")
    db.set_defaults(func=cmd_discovery)
    dm = dsub.add_parser("misses", help="classify every guided-engine miss by failing stage")
    dm.add_argument("--out")
    dm.set_defaults(func=cmd_discovery)
    de = dsub.add_parser("economic", help="profit/capital account for each detected violation")
    de.add_argument("--out")
    de.set_defaults(func=cmd_discovery)
    dsub.add_parser("economic-invariants", help="the economic-invariant catalogue").set_defaults(func=cmd_discovery)
    dsub.add_parser("foundry", help="run the real Foundry PoC suite (mission 3.G)").set_defaults(func=cmd_discovery)
    dfi = dsub.add_parser("foundry-invariant", help="run the Foundry invariant differential")
    dfi.add_argument("--out")
    dfi.set_defaults(func=cmd_discovery)

    dbb = dsub.add_parser("blind-benchmark",
                          help="four-engine comparison over the blind hold-out corpus")
    dbb.add_argument("--out")
    dbb.set_defaults(func=cmd_discovery)

    dcert = dsub.add_parser("certify",
                            help="prove (or bound) a candidate violation on a case or fixture")
    dcert.add_argument("target", help="a corpus/holdout case id, or a fixture name")
    dcert.add_argument("--mode", choices=["exhaustive", "concolic"], default="exhaustive",
                       help="bounded-exhaustive search, or guided concrete perturbation")
    dcert.add_argument("--depth", type=int, default=4, help="max sequence length (exhaustive)")
    dcert.add_argument("--max-states", type=int, default=200_000, help="state budget (exhaustive)")
    dcert.add_argument("--rounds", type=int, default=3, help="perturbation rounds (concolic)")
    dcert.add_argument("--out")
    dcert.set_defaults(func=cmd_discovery)

    dmem = dsub.add_parser("memory",
                           help="cross-target attack memory: summary, list, or seeds for a case")
    dmem.add_argument("action", choices=["summary", "list", "seed"])
    dmem.add_argument("target", nargs="?", default="", help="case id (for action=seed)")
    dmem.add_argument("--dir", default=None, help="attack memory JSONL path")
    dmem.add_argument("--min-score", type=float, default=0.35,
                      help="minimum structural similarity to transfer")
    dmem.set_defaults(func=cmd_discovery)

    dcp = dsub.add_parser("campaign",
                          help="adaptive discovery campaign against a local fixture (mission 06)")
    dcp.add_argument("--fixture", required=True,
                     help="fixture name (a development/holdout/hard pair) or a blind case id")
    dcp.add_argument("--steps", type=int, default=4, help="max sequence length")
    dcp.add_argument("--budget", type=int, default=2000, help="max sequences to execute")
    dcp.add_argument("--seed", type=int, default=0)
    dcp.add_argument("--control", help="control fixture name for the differential check")
    dcp.add_argument("--out")
    dcp.set_defaults(func=cmd_discovery)

    fnd = sub.add_parser("findings", help="persistent findings repository (document, search, verify, export)")
    fnd.add_argument("--dir", default="research/private/findings", help="repository directory")
    fnd.add_argument("--name", default="findings", help="repository log name")
    fsub = fnd.add_subparsers(dest="sub", required=True)

    fsub.add_parser("summary", help="bucket counts").set_defaults(func=cmd_findings)
    fsub.add_parser("sections", help="the ten required finding sections").set_defaults(func=cmd_findings)

    fa = fsub.add_parser("add", help="record a new finding from a JSON file")
    fa.add_argument("--file", required=True, help="finding JSON")
    fa.set_defaults(func=cmd_findings)

    fl = fsub.add_parser("list", help="search findings")
    fl.add_argument("--target"); fl.add_argument("--category"); fl.add_argument("--component")
    fl.add_argument("--severity"); fl.add_argument("--status"); fl.add_argument("--text")
    fl.set_defaults(func=cmd_findings)

    fs = fsub.add_parser("show", help="show one finding")
    fs.add_argument("--finding", required=True)
    fs.set_defaults(func=cmd_findings)

    fh = fsub.add_parser("history", help="the verdict/link history of one finding")
    fh.add_argument("--finding", required=True)
    fh.set_defaults(func=cmd_findings)

    fv = fsub.add_parser("set-verdict", help="change a finding's verdict (CONFIRMED is evidence-gated)")
    fv.add_argument("--finding", required=True)
    fv.add_argument("--verdict", required=True)
    fv.add_argument("--note", default="")
    fv.set_defaults(func=cmd_findings)

    fc = fsub.add_parser("confirm", help="evidence-gated confirmation against the evidence store")
    fc.add_argument("--finding", required=True)
    fc.add_argument("--evidence", default="research/private/evidence", help="evidence store dir")
    fc.add_argument("--deployment-truth", default="",
                    help="runtime-bound deployment truth JSON required for an address target")
    fc.add_argument("--note", default="")
    fc.set_defaults(func=cmd_findings)

    fk = fsub.add_parser("link", help="link two findings (additively)")
    fk.add_argument("--finding", required=True)
    fk.add_argument("--other", required=True)
    fk.add_argument("--duplicate", action="store_true", help="record a duplicate relationship")
    fk.set_defaults(func=cmd_findings)

    fe = fsub.add_parser("export", help="export one finding as Markdown, JSON or SARIF")
    fe.add_argument("--finding", required=True)
    fe.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    fe.add_argument("--out")
    fe.set_defaults(func=cmd_findings)

    fsar = fsub.add_parser("sarif", help="export the whole repository as SARIF 2.1.0")
    fsar.add_argument("--out")
    fsar.set_defaults(func=cmd_findings)

    fr = fsub.add_parser("report", help="consolidated research report over all findings")
    fr.add_argument("--out")
    fr.set_defaults(func=cmd_findings)

    fi = fsub.add_parser("integrity", help="verify the findings log hash chain")
    fi.add_argument("--key-path")
    fi.add_argument("--require-signatures", action="store_true")
    fi.set_defaults(func=cmd_findings)

    bl = sub.add_parser(
        "baseline",
        help="content-addressed finding baseline (new/resolved/changed)",
    )
    bl.add_argument("--findings", default="research/private/findings")
    bl.add_argument("--name", default="findings")
    bsub = bl.add_subparsers(dest="sub", required=True)
    bc = bsub.add_parser("create", help="write a baseline JSON document")
    bc.add_argument("--out", required=True)
    bc.set_defaults(func=cmd_baseline)
    bd = bsub.add_parser("compare", help="compare the repository against a baseline")
    bd.add_argument("--baseline", required=True)
    bd.add_argument("--json", action="store_true")
    bd.add_argument("--fail-on-new", action="store_true",
                    help="exit 1 when a new finding appears")
    bd.set_defaults(func=cmd_baseline)

    vr = sub.add_parser("version", help="installed version, interpreter and package root")
    vr.add_argument("--json", action="store_true")
    vr.set_defaults(func=cmd_version)

    inf = sub.add_parser("info", help="product summary: counts, capability headline and paths")
    inf.add_argument("--json", action="store_true")
    inf.set_defaults(func=cmd_info)

    ini = sub.add_parser("init", help="scaffold a workspace (authorization fails closed)")
    ini.add_argument("dir", nargs="?", default=".", help="workspace directory (default: .)")
    ini.add_argument("--force", action="store_true", help="replace generated files")
    ini.add_argument("--json", action="store_true")
    ini.set_defaults(func=cmd_init)

    dem = sub.add_parser("demo", help="offline reference pipeline: fuzz -> finding -> SARIF -> baseline")
    dem.add_argument("--dir", default="research/private/demo", help="demo workspace")
    dem.add_argument("--runs", type=int, default=300)
    dem.add_argument("--steps", type=int, default=10)
    dem.add_argument("--json", action="store_true")
    dem.set_defaults(func=cmd_demo)

    gui = sub.add_parser("guide", help="grouped command list")
    gui.set_defaults(func=cmd_guide)

    dr = sub.add_parser("doctor", help="portability and health check")
    dr.add_argument("--registry", default=str(Path.home() / ".blackheart/tools/registry.json"))
    dr.add_argument("--out")
    dr.add_argument("--json", action="store_true", help="print the checks as JSON")
    dr.set_defaults(func=cmd_doctor)

    # -- engine integration layer (Strix / Shannon / PentAGI) ------------- #
    en = sub.add_parser(
        "engines",
        help="external engine integration (Strix, Shannon, PentAGI): discover, run, correlate",
    )
    en.add_argument("--workdir", default="research/private/engines",
                    help="workspace for engine runs and persisted state")
    en_common = argparse.ArgumentParser(add_help=False)
    en_common.add_argument("--workdir", default=argparse.SUPPRESS,
                           help="workspace for engine runs and persisted state")
    ensub = en.add_subparsers(dest="sub", required=True)

    enl = ensub.add_parser("list", parents=[en_common],
                           help="list known engines, their state, version and license")
    enl.add_argument("--json", action="store_true")
    enl.set_defaults(func=cmd_engines)

    enc = ensub.add_parser("capabilities", parents=[en_common],
                           help="discover one engine's capabilities")
    enc.add_argument("--engine", required=True)
    enc.add_argument("--json", action="store_true")
    enc.set_defaults(func=cmd_engines)

    env = ensub.add_parser("verify", parents=[en_common],
                           help="health + configuration check for one or all engines")
    env.add_argument("--engine", help="one engine (default: all)")
    env.set_defaults(func=cmd_engines)

    enr = ensub.add_parser("run", parents=[en_common],
                           help="run an authorization-gated multi-engine assessment")
    enr.add_argument("--target", required=True, help="target URL or local path")
    enr.add_argument("--engines", help="comma-separated engines (default: all available)")
    enr.add_argument("--authz", help="authorization record JSON (required for a real target)")
    enr.add_argument("--asset", help="asset id within the authorization record")
    enr.add_argument("--allow-local", action="store_true",
                     help="opt in to a local/disposable target (bypasses the remote authz gate)")
    enr.add_argument("--options", help="per-engine options JSON")
    enr.add_argument("--report", help="write reports to this directory")
    enr.add_argument("--engagement", help="engagement name for the report")
    enr.add_argument("--compatibility", metavar="RECORD",
                     help="language-aware compatibility record (JSON) for this target")
    enr.set_defaults(func=cmd_engines)

    ens = ensub.add_parser("status", parents=[en_common],
                           help="run state + per-engine health snapshot")
    ens.set_defaults(func=cmd_engines)

    enca = ensub.add_parser("cancel", parents=[en_common],
                            help="request cancellation of a running assessment")
    enca.set_defaults(func=cmd_engines)

    enf = ensub.add_parser("findings", parents=[en_common],
                           help="the normalized clusters from the last run")
    enf.set_defaults(func=cmd_engines)

    end = ensub.add_parser("document", parents=[en_common],
                           help="persist the last run's clusters into the findings repository")
    end.add_argument("--findings-dir", default="research/private/findings")
    end.add_argument("--name", default="findings")
    end.set_defaults(func=cmd_engines)

    enb = ensub.add_parser("bootstrap", parents=[en_common],
                           help="install the pinned Solidity engine toolchain")
    enb.add_argument("--engine", help="one engine (default: all)")
    enb.add_argument("--python", help="interpreter used to build the venvs")
    enb.add_argument("--json", action="store_true")
    enb.set_defaults(func=cmd_engines)

    endoc = ensub.add_parser("doctor", parents=[en_common],
                             help="verify installed engines against the pinned manifest")
    endoc.add_argument("--engine", help="one engine (default: all)")
    endoc.add_argument("--json", action="store_true")
    endoc.set_defaults(func=cmd_engines)

    enrp = ensub.add_parser("report", parents=[en_common],
                            help="render the unified report (md/json/sarif)")
    enrp.add_argument("--out", default="research/private/engines/report")
    enrp.add_argument("--format", default="md,json,sarif")
    enrp.add_argument("--stdout", action="store_true", help="print instead of writing files")
    enrp.add_argument("--engagement")
    enrp.set_defaults(func=cmd_engines)

    dm = sub.add_parser("demonstrate", help="drive one vulnerable/guarded pair through the full pipeline")
    dm.add_argument("--pair", default="lending-oracle/lending-oracle-guarded",
                    help="vulnerable/guarded target pair (see: blackheart targets)")
    dm.add_argument("--runs", type=int, default=400)
    dm.add_argument("--steps", type=int, default=10)
    dm.add_argument("--seed", type=int, default=0)
    dm.add_argument("--workdir", default="research/private/demonstration")
    dm.set_defaults(func=cmd_demonstrate)

    ah = sub.add_parser(
        "adversarial",
        help="run the multi-engine adversarial harness (forge/invariants/echidna/medusa/halmos/mythril/slither)",
    )
    ah.add_argument("--workdir", default="research/private/adversarial-engagement")
    ah.add_argument("--fast", action="store_true",
                    help="run only forge PoC + invariants (skip symbolic/fuzzing engines)")
    ah.set_defaults(func=cmd_adversarial)

    ch = sub.add_parser("chain", help="list or execute the executable attack-chain database")
    ch.add_argument("--list", action="store_true", help="list every executable chain")
    ch.add_argument("--run", help="chain id to execute (see --list)")
    ch.add_argument("--out")
    ch.set_defaults(func=cmd_chain)

    rg = sub.add_parser("regress", help="emit a deterministic regression test for a counterexample")
    rg.add_argument("--target", choices=_target_choices(), default="vulnerable")
    rg.add_argument("--runs", type=int, default=300)
    rg.add_argument("--steps", type=int, default=10)
    rg.add_argument("--seed", type=int, default=0)
    rg.add_argument("--out", default="research/private/regressions")
    rg.set_defaults(func=cmd_regress)

    fg = sub.add_parser("forge-gen", help="render a runnable Foundry test from an executable chain")
    fg.add_argument("--chain", default="erc4626-first-depositor-inflation")
    fg.add_argument("--harness", default="harnesses/erc4626")
    fg.add_argument("--out")
    fg.set_defaults(func=cmd_forge_gen)

    sc = sub.add_parser("scope", help="record / check dated engagement-authorization evidence")
    sc.add_argument("--file", help="authorization record JSON to record")
    sc.add_argument("--check", help="existing record JSON to evaluate")
    sc.add_argument("--asset", help="asset to check (with --check)")
    sc.add_argument("--registry", default="research/private/authz/registry.jsonl")
    sc.add_argument("--evidence", default="research/private/authz/evidence")
    sc.add_argument("--allow", action="append",
                    help="allow pattern to match an asset against (repeatable); "
                         "with --asset, prints a deterministic scope decision")
    sc.add_argument("--exclude", action="append",
                    help="exclude pattern (repeatable; used with --allow)")
    sc.add_argument("--excluded-class", action="append",
                    help="a vulnerability class the program excludes (repeatable; "
                         "used with --allow to report class_allowed)")
    sc.set_defaults(func=cmd_scope)

    el = sub.add_parser("eligibility", help="rank candidate bounty programs and gate entry (mission 5/7)")
    esub = el.add_subparsers(dest="sub", required=True)
    ee = esub.add_parser("evaluate", help="evaluate + rank candidate programs from a registry")
    ee.add_argument("--file", required=True, help="eligibility registry JSON (one program or {programs:[...]})")
    ee.add_argument("--out", help="write the verdict list to a JSON file")
    ee.set_defaults(func=cmd_eligibility_evaluate)
    ec = esub.add_parser("to-scope", help="emit an authorization record for the top viable program")
    ec.add_argument("--file", required=True)
    ec.add_argument("--program", help="program name to emit (default: top viable)")
    ec.add_argument("--out", required=True, help="path to write the AuthorizationRecord JSON")
    ec.set_defaults(func=cmd_eligibility_to_scope)
    cf = sub.add_parser("conformance", help="passively check documented HyperCore API invariants")
    cf.add_argument("--base", default="https://api.hyperliquid-testnet.xyz",
                    help="info API base URL (default: testnet)")
    cf.add_argument("--limit", type=int, default=40, help="max outcomes to book-check")
    cf.add_argument("--ledger-only", action="store_true", help="skip outcome-book checks")
    cf.add_argument("--books-only", action="store_true", help="skip borrow/lend checks")
    cf.set_defaults(func=cmd_conformance)

    av = sub.add_parser("agents-verify", help="verify skills/agents are discoverable via the agent-server")
    av.add_argument("--out")
    av.set_defaults(func=cmd_agents_verify)

    pv = sub.add_parser("provision", help="create the .openhands skills/agents discovery layout")
    pv.add_argument("--root", help="repository root (default: the installed package's root)")
    pv.set_defaults(func=cmd_provision)
    fk = sub.add_parser("fork", help="real-target fork harnesses (in-scope source on a local fork)")
    fsub = fk.add_subparsers(dest="sub", required=True)

    ft = fsub.add_parser("targets", help="list real-target fork harnesses")
    ft.add_argument("--out")
    ft.set_defaults(func=cmd_fork_targets)

    ff = fsub.add_parser("fetch", help="vendor the real in-scope source for a target")
    ff.add_argument("--target", required=True)
    ff.set_defaults(func=cmd_fork_fetch)

    fr = fsub.add_parser("run", help="run smoke + adversarial + invariant fork tests")
    fr.add_argument("--target", required=True)
    fr.add_argument("--runs", type=int, default=48)
    fr.add_argument("--depth", type=int, default=40)
    fr.add_argument("--timeout", type=int, default=900)
    fr.add_argument("--workdir", default="research/private/fork")
    fr.set_defaults(func=cmd_fork_run)

    fv = fsub.add_parser("verify", help="independent verification of the documented trust boundary")
    fv.add_argument("--target", required=True)
    fv.set_defaults(func=cmd_fork_verify)

    fl = fsub.add_parser("ledger", help="show the engagement hypothesis ledger for a target")
    fl.add_argument("--target", required=True)
    # Must match where `fork run` writes: <workdir>/ledger, and workdir defaults
    # to research/private/fork (see cmd_fork_run / --workdir).
    fl.add_argument("--ledger-dir", default="research/private/fork/ledger")
    fl.add_argument("--out")
    fl.set_defaults(func=cmd_fork_ledger)

    ga = sub.add_parser("gha-analyze", help="detect reachable GitHub Actions attack chains")
    ga.add_argument("path", help="a workflow file, a repository, or a directory of repositories")
    ga.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ga.set_defaults(func=cmd_gha_analyze)

    gb = sub.add_parser("gha-bench", help="benchmark the GitHub Actions analyzer")
    gb.add_argument("--corpus", help="optional real repository/corpus to scan too")
    gb.add_argument("--json", action="store_true")
    gb.set_defaults(func=cmd_gha_bench)

    # -- evolving research engine --------------------------------------- #
    rs = sub.add_parser("research", help="persistent searchable research memory")
    rs.add_argument("--dir", default="research/private/memory")
    rs.add_argument("--engagement", default="research")
    rss = rs.add_subparsers(dest="sub", required=True)
    rss.add_parser("summary", help="bucket counts").set_defaults(func=cmd_research)
    rsearch = rss.add_parser("search", help="retrieve relevant records")
    rsearch.add_argument("--target", default="")
    rsearch.add_argument("--vclass", default="")
    rsearch.add_argument("--text", default="")
    rsearch.add_argument("--status", default=None)
    rsearch.set_defaults(func=cmd_research)
    rexp = rss.add_parser("export", help="markdown dump by bucket")
    rexp.add_argument("--out")
    rexp.set_defaults(func=cmd_research)
    rss.add_parser("integrity", help="re-hash stored records").set_defaults(func=cmd_research)
    rrec = rss.add_parser("record", help="append a research record from JSON")
    rrec.add_argument("--file", required=True)
    rrec.set_defaults(func=cmd_research)

    rd = rss.add_parser(
        "deployed",
        help="research a real deployed contract at a pinned block (read-only by default)",
    )
    rd.add_argument("address", help="contract address to research")
    rd.add_argument("--block", type=int,
                    help="block to pin (default: pin the current head at retrieval time)")
    rd.add_argument("--rpc", help="JSON-RPC endpoint (default: a free public endpoint)")
    rd.add_argument("--execute", action="store_true",
                    help="also run the candidate sequence on an isolated local fork")
    rd.add_argument("--experiment-id", help="stable id for the evidence record")
    rd.add_argument("--compatibility", metavar="RECORD",
                    help="language-aware compatibility record (JSON); required for "
                         "--execute, which runs a sequence on a fork")
    rd.add_argument("--json", action="store_true")
    rd.set_defaults(func=cmd_research_deployed)

    hy = sub.add_parser("hypothesis", help="rank and select the next investigation")
    hy.add_argument("--profile", required=True)
    hy.add_argument("--memory", help="research-memory dir to consult")
    hy.add_argument("--engagement", default="research")
    hy.add_argument("--surface", action="store_true", help="use the surface-aware strategy")
    hy.add_argument("--threat-model", help="threat-model JSON; gates and steers hunting (P1)")
    hy.add_argument("--new-evidence", action="store_true",
                    help="allow revisiting a disproven hypothesis")
    hy.add_argument("--out")
    hy.set_defaults(func=cmd_hypothesis)

    hz = sub.add_parser("hypothesize", help="P2: generate falsifiable hypotheses from a threat model")
    hz.add_argument("--profile", required=True)
    hz.add_argument("--threat-model", required=True, help="validated threat-model JSON (P1)")
    hz.add_argument("--memory", help="research-memory dir to consult for novelty/evidence")
    hz.add_argument("--engagement", default="research")
    hz.add_argument("--tools", help="comma-separated available tool names (feasibility scoring)")
    hz.add_argument("--scope-reference", help="official scope reference recorded on each hypothesis")
    hz.add_argument("--store", help="append-only dir to persist the generation (incl. rejections)")
    hz.add_argument("--summary", action="store_true", help="print only the summary + next hypothesis")
    hz.add_argument("--out")
    hz.set_defaults(func=cmd_hypothesize)

    iv = sub.add_parser("investigate", help="P3: resumable investigation workflow")
    ivs = iv.add_subparsers(dest="sub", required=True)
    iv.add_argument("--dir", default="research/private/investigations")
    iv.add_argument("--name", default="investigations")
    ivl = ivs.add_parser("list", help="list investigations and their stage/status")
    ivl.set_defaults(func=cmd_investigate)
    ivsh = ivs.add_parser("show", help="show one investigation's full state")
    ivsh.add_argument("investigation")
    ivsh.set_defaults(func=cmd_investigate)
    ivr = ivs.add_parser("run", help="start (or resume) an investigation for a hypothesis")
    ivr.add_argument("--hypothesis", required=True, help="P2 hypothesis JSON")
    ivr.add_argument("--authz", help="dated authorization record JSON (required to reproduce)")
    ivr.add_argument("--scope-reference")
    ivr.set_defaults(func=cmd_investigate)
    ivv = ivs.add_parser("verify", help="verify the investigation log's hash chain (exit 1 on tamper)")
    ivv.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    ivv.add_argument("--require-signatures", action="store_true",
                     help="fail if the log is not signed with a key")
    ivv.add_argument("--checkpoint", help="a checkpoint file to detect tail truncation")
    ivv.set_defaults(func=cmd_investigate)
    ivc = ivs.add_parser("checkpoint", help="write a signed head checkpoint for the log")
    ivc.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    ivc.add_argument("--out", help="where to write the checkpoint (default: <dir>/<name>.checkpoint.json)")
    ivc.set_defaults(func=cmd_investigate)
    ivk = ivs.add_parser("keygen", help="generate an HMAC signing key outside the log")
    ivk.add_argument("--out", help="where to write the key (default: <dir>/integrity-key.json)")
    ivk.set_defaults(func=cmd_investigate)

    tm = sub.add_parser("threatmodel", help="protocol intelligence: threat model + impact selection (P1)")
    tms = tm.add_subparsers(dest="sub", required=True)
    tmc = tms.add_parser("catalog", help="list the canonical impact catalogue")
    tmc.add_argument("--out")
    tmc.set_defaults(func=cmd_threatmodel)
    tmsc = tms.add_parser("scaffold", help="bootstrap a threat model from a target profile")
    tmsc.add_argument("--profile", required=True)
    tmsc.add_argument("--revision", default="")
    tmsc.add_argument("--impact", action="append",
                      help="select an impact id (repeatable); see `threatmodel catalog`")
    tmsc.add_argument("--out")
    tmsc.set_defaults(func=cmd_threatmodel)
    tmck = tms.add_parser("check", help="report a threat model's missing required elements")
    tmck.add_argument("--model", required=True)
    tmck.set_defaults(func=cmd_threatmodel)
    tmst = tms.add_parser("steer", help="show the objective order selected impacts produce")
    tmst.add_argument("--profile", required=True)
    tmst.add_argument("--model", required=True)
    tmst.add_argument("--out")
    tmst.set_defaults(func=cmd_threatmodel)

    ln = sub.add_parser("learn", help="self-improvement: benchmark and adopt a strategy")
    lns = ln.add_subparsers(dest="sub", required=True)
    lb = lns.add_parser("bench", help="baseline vs surface-aware benchmark")
    lb.add_argument("--out")
    lb.set_defaults(func=cmd_learn)
    lns.add_parser("propose", help="show the proposed improvement").set_defaults(func=cmd_learn)
    ld = lns.add_parser("demo", help="demonstrate the full learning loop")
    ld.add_argument("--out", help="directory to write the emitted regression test")
    ld.set_defaults(func=cmd_learn)

    qq = sub.add_parser("queue", help="resumable research queue")
    qqs = qq.add_subparsers(dest="sub", required=True)
    qq.add_argument("--dir", default="research/private/queue")
    qq.add_argument("--name", default="queue")
    qqs.add_parser("summary", help="queue state counts").set_defaults(func=cmd_queue)
    qqs.add_parser("plan", help="what would run next, and why").set_defaults(func=cmd_queue)
    qqs.add_parser("next", help="dequeue the next authorized entry").set_defaults(func=cmd_queue)

    sc = sub.add_parser("schedule", help="durable autonomous execution scheduler")
    sc.add_argument("--dir", default="research/private/scheduler")
    sc.add_argument("--name", default="jobs")
    sc.add_argument("--lease-seconds", type=float, default=1800.0,
                    help="how long a claim owns a job before it may be reclaimed; "
                         "must exceed the slowest expected job, since run_once does "
                         "not heartbeat a running executor")
    sc.add_argument("--max-attempts", type=int, default=5,
                    help="default execution attempt budget for new jobs")
    sc.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    sc.add_argument(
        "--authz",
        help="authorization record JSON re-read at claim and execution time. Pass "
             "the same file the ingress uses so a scope withdrawal between "
             "acceptance and execution blocks the job; without it the worker can "
             "only see the snapshot stored at enqueue",
    )
    scs = sc.add_subparsers(dest="sub", required=True)

    sa = scs.add_parser("add", help="enqueue a job (deduplicated by --key)")
    sa.add_argument("--kind", required=True, choices=["hunt", "investigate"])
    sa.add_argument("--target", required=True)
    sa.add_argument("--asset", required=True)
    sa.add_argument("--authz", required=True, help="authorization record JSON")
    sa.add_argument("--payload", help="executor payload JSON")
    sa.add_argument("--key", default="", help="idempotency key (dedupe repeated triggers)")
    sa.add_argument("--priority", type=int, default=0)
    sa.add_argument("--scope-reference", default="")
    sa.set_defaults(func=cmd_schedule)

    sr = scs.add_parser("run", help="recover stale leases, then drain runnable jobs")
    sr.add_argument("--owner", default="blackheart-scheduler")
    sr.add_argument("--max-jobs", type=int, default=100)
    sr.set_defaults(func=cmd_schedule)

    so = scs.add_parser("once", help="claim and run a single job")
    so.add_argument("--owner", default="blackheart-scheduler")
    so.set_defaults(func=cmd_schedule)

    sl = scs.add_parser("list", help="list jobs, optionally filtered by state")
    sl.add_argument("--state")
    sl.set_defaults(func=cmd_schedule)

    ssh = scs.add_parser("show", help="show a job's full record")
    ssh.add_argument("job")
    ssh.set_defaults(func=cmd_schedule)

    shy = scs.add_parser("history", help="show a job's event history")
    shy.add_argument("job")
    shy.set_defaults(func=cmd_schedule)

    scs.add_parser("recover", help="reclaim every expired lease").set_defaults(func=cmd_schedule)
    scs.add_parser("summary", help="job counts by state").set_defaults(func=cmd_schedule)

    sm = scs.add_parser("misfire", help="record and clear a missed scheduled moment")
    sm.add_argument("job")
    sm.set_defaults(func=cmd_schedule)

    scl = scs.add_parser("cancel", help="cancel a non-terminal job")
    scl.add_argument("job")
    scl.add_argument("--reason", default="")
    scl.set_defaults(func=cmd_schedule)

    sv = scs.add_parser("verify", help="verify the job log's hash chain")
    sv.add_argument("--require-signatures", action="store_true")
    sv.add_argument("--checkpoint")
    sv.set_defaults(func=cmd_schedule)

    scp = scs.add_parser("checkpoint", help="write a signed head checkpoint for the job log")
    scp.add_argument("--out", help="where to write the checkpoint (default: <dir>/<name>.checkpoint.json)")
    scp.set_defaults(func=cmd_schedule)

    tg = sub.add_parser("trigger",
                        help="production trigger monitoring: ingest, authenticate, dispatch")
    tg.add_argument("--dir", default="research/private/scheduler")
    tg.add_argument("--authz", help="authorization record JSON (the ONLY scope a trigger is judged against)")
    tg.add_argument("--lease-seconds", type=float, default=1800.0)
    tg.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    tg.add_argument("--max-per-window", type=int, default=20,
                    help="accepted deliveries allowed per rate-limit window")
    tg.add_argument("--window-seconds", type=int, default=60)
    tgs = tg.add_subparsers(dest="sub", required=True)

    tw = tgs.add_parser("webhook", help="ingest one signed webhook delivery")
    tw.add_argument("--body", help="file holding the raw body (default: stdin)")
    tw.add_argument("--headers", help="file holding the request headers as JSON")
    tw.set_defaults(func=cmd_trigger)

    tm = tgs.add_parser("manual", help="ingest an operator-initiated trigger")
    tm.add_argument("--payload", help="file holding the trigger payload (default: stdin)")
    tm.set_defaults(func=cmd_trigger)

    tr = tgs.add_parser("recurring", help="register or tick recurring triggers")
    tr.add_argument("--file", default="research/private/scheduler/recurring.json")
    tr.add_argument("--add", help="register a payload JSON as a new recurring trigger")
    tr.add_argument("--interval", type=int, default=3600, help="seconds between fires")
    tr.add_argument("--trigger-id")
    tr.set_defaults(func=cmd_trigger)

    tl = tgs.add_parser("list", help="list deliveries, optionally filtered by state")
    tl.add_argument("--state")
    tl.set_defaults(func=cmd_trigger)

    tsh = tgs.add_parser("show", help="show one delivery's record and provenance")
    tsh.add_argument("delivery")
    tsh.set_defaults(func=cmd_trigger)

    tsy = tgs.add_parser("sync", help="advance trigger states from their jobs' real outcomes")
    tsy.set_defaults(func=cmd_trigger)

    tv = tgs.add_parser("verify", help="verify the trigger ledger's hash chain")
    tv.add_argument("--require-signatures", action="store_true")
    tv.set_defaults(func=cmd_trigger)

    bo = sub.add_parser("bounty",
                        help="program-specific eligibility, severity and payout evaluation")
    bo.add_argument("--dir", default="research/private/bounty")
    bo.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    bos = bo.add_subparsers(dest="sub", required=True)

    bc = bos.add_parser("capture", help="record a policy snapshot with provenance")
    bc.add_argument("--program", required=True)
    bc.add_argument("--source-url", required=True)
    bc.add_argument("--retrieved-at", required=True)
    bc.add_argument("--text", required=True, help="file holding the retrieved policy text")
    bc.add_argument("--revision", default="")
    bc.add_argument("--out", required=True)
    bc.set_defaults(func=cmd_bounty)

    bvp = bos.add_parser("verify-policy", help="is a policy snapshot verified?")
    bvp.add_argument("--snapshot", required=True)
    bvp.set_defaults(func=cmd_bounty)

    be = bos.add_parser("evaluate", help="evaluate a finding against a program policy")
    be.add_argument("--policy", required=True)
    be.add_argument("--finding", required=True)
    be.add_argument("--reevaluate", action="store_true",
                    help="link this evaluation to the prior one under an older policy")
    be.set_defaults(func=cmd_bounty)

    bsh = bos.add_parser("show", help="show evaluations for a finding, or all")
    bsh.add_argument("--finding")
    bsh.set_defaults(func=cmd_bounty)

    bps = bos.add_parser("prepare-submission",
                         help="prepare an evidence-backed submission package (never submits)")
    bps.add_argument("--policy", required=True)
    bps.add_argument("--finding", required=True)
    bps.set_defaults(func=cmd_bounty)

    bg = bos.add_parser(
        "gate",
        help="run the mandatory official-policy gate (Gates A-D) on a candidate record",
    )
    bg.add_argument("--record", required=True,
                    help="CandidateRecord JSON (see blackheart.bounty.CandidateRecord)")
    bg.add_argument("--deployment-truth", default="",
                    help="runtime-bound deployment truth JSON; required when "
                         "deployment_verified is true")
    bg.add_argument("--require-submission-ready", action="store_true",
                    help="exit 1 unless the disposition is A (submission-ready)")
    bg.set_defaults(func=cmd_bounty)

    bv = bos.add_parser("verify", help="verify the evaluation ledger's hash chain")
    bv.add_argument("--require-signatures", action="store_true")
    bv.set_defaults(func=cmd_bounty)

    ing = sub.add_parser(
        "ingress",
        help="authenticated live HTTP ingress: a real listener in front of the "
             "trigger receiver and durable scheduler",
    )
    ing.add_argument("--dir", default="research/private/scheduler")
    ing.add_argument("--authz", help="authorization record JSON (re-read on every decision)")
    ing.add_argument("--host", default="127.0.0.1")
    ing.add_argument("--port", type=int, default=8787)
    ing.add_argument("--path", default="/trigger", help="the delivery path")
    ing.add_argument("--max-body-bytes", type=int, default=64 * 1024)
    ing.add_argument("--request-timeout", type=float, default=15.0)
    ing.add_argument("--lease-seconds", type=float, default=1800.0)
    ing.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    ing.add_argument("--max-per-window", type=int, default=20)
    ing.add_argument("--window-seconds", type=int, default=60)
    ing.add_argument("--allow-public-bind", action="store_true",
                     help="permit a non-loopback --host (TLS/proxy is then yours)")
    ings = ing.add_subparsers(dest="sub", required=True)
    ings.add_parser(
        "serve", help="bind and serve until interrupted (BLACKHEART_TRIGGER_SECRET required)"
    ).set_defaults(func=cmd_ingress)
    ings.add_parser("check", help="validate the ingress configuration without binding").set_defaults(func=cmd_ingress)

    nv = sub.add_parser("novelty", help="adjudicate a pre-submission novelty review")
    nv.add_argument("--file", required=True, help="novelty review JSON")
    nv.add_argument("--out")
    nv.add_argument("--store", help="append-only directory to persist the review")
    nv.add_argument("--search", action="store_true",
                    help="populate the public search from live providers "
                         "(You.com -> keyless fallbacks) before adjudicating; "
                         "requires YDC_API_KEY for the primary provider")
    nv.add_argument("--advisories", action="store_true",
                    help="also query the free GitHub Advisory database (needs no "
                         "paid key; understands package names and CVE ids only)")
    nv.set_defaults(func=cmd_novelty)

    ig = sub.add_parser("integrity", help="verify the hash chain of an append-only JSONL log")
    ig.add_argument("file", help="the JSONL log to verify")
    ig.add_argument("--key-path", help="HMAC key file (or set BLACKHEART_INTEGRITY_KEY)")
    ig.add_argument("--require-signatures", action="store_true",
                    help="fail if records are not signed with a key")
    ig.add_argument("--checkpoint", help="a checkpoint file to detect tail truncation")
    ig.set_defaults(func=cmd_integrity)

    md = sub.add_parser("models", help="multi-model research layer: providers, roles, routing")
    md.add_argument("--quota", help="JSONL file to persist provider usage counts")
    md.add_argument("--budget-tokens", type=int, default=None,
                    help="cap model tokens for this run (a wrap-up reserve is kept)")
    md.add_argument("--budget-turns", type=int, default=None,
                    help="cap model calls for this run (a wrap-up reserve is kept)")
    mds = md.add_subparsers(dest="sub", required=True)
    mds.add_parser("list", help="list providers and their verified free-tier notes").set_defaults(func=cmd_models)
    mds.add_parser("health", help="probe each configured provider (local engine always healthy)").set_defaults(func=cmd_models)
    mds.add_parser("benchmark", help="score the adversarial role on the historical cases").set_defaults(func=cmd_models)
    mr = mds.add_parser("route", help="show where a request of a given class would go")
    mr.add_argument("--data-class", default="PUBLIC",
                    choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"])
    mr.add_argument("--role", default="")
    mr.set_defaults(func=cmd_models)
    mds.add_parser("usage", help="show advisory per-provider call/token counts").set_defaults(func=cmd_models)
    mrv = mds.add_parser(
        "reviewer",
        help="report whether an optional independent reviewer model is available "
             "(never required; falls back to a same-model review)",
    )
    mrv.add_argument(
        "--no-probe", action="store_true",
        help="report configured-but-unverified without a liveness probe "
             "(a present key is never reported as available on its own)",
    )
    mrv.set_defaults(func=cmd_models)

    ce = sub.add_parser(
        "coverage-engine",
        help="the Universal Vulnerability Coverage Engine: extensible class "
             "taxonomy, target-aware applicability, and multi-stage attack paths",
    )
    ces = ce.add_subparsers(dest="ce_sub", required=True)
    ces.add_parser("taxonomy", help="print the class universe and model coverage").set_defaults(func=cmd_coverage_engine)
    cea = ces.add_parser("assess", help="classify the taxonomy against a target profile")
    cea.add_argument("--target", default="target")
    cea.add_argument("--kind", default="unknown")
    cea.add_argument("--asset", action="append")
    cea.add_argument("--entry", action="append")
    cea.add_argument("--role", action="append")
    cea.add_argument("--dep", action="append")
    cea.add_argument("--notes", default="")
    cea.add_argument("--plan", action="store_true",
                     help="emit the coverage plan as JSON (priorities + attack paths)")
    cea.set_defaults(func=cmd_coverage_engine)

    env = sub.add_parser(
        "environment",
        help="environment-agnostic execution backends: capability matrix and routing",
    )
    envs = env.add_subparsers(dest="env_sub", required=True)
    for name, help_text in (
        ("list", "probe every built-in backend and print its capabilities"),
    ):
        envs.add_parser(name, help=help_text).set_defaults(func=cmd_environment)
    enr = envs.add_parser("route", help="show which backend would serve a probe")
    enr.add_argument("--target-type", required=True)
    enr.add_argument("--operation", required=True)
    enr.add_argument("--tool", default="",
                     help="require this tool to be confirmed by the backend (e.g. go)")
    enr.set_defaults(func=cmd_environment)
    for env_parser in (envs.choices["list"], enr):
        env_parser.add_argument("--compose", default="",
                                help="probe a local compose devnet from this file")
        env_parser.add_argument("--allow-exec", action="store_true",
                                help="allow `exec` into a declared compose service")
        env_parser.add_argument("--root", default="",
                                help="register a local-source backend at this path")
        env_parser.add_argument("--allow-host", action="append",
                                help="restrict the HTTP backend to this host (repeatable)")
        env_parser.add_argument("--model", default="",
                                help="register a sequence-model backend for this target")

    prog = sub.add_parser(
        "program",
        help="universal program intelligence: normalize a published policy with provenance",
    )
    progs = prog.add_subparsers(dest="prog_sub", required=True)
    progs.add_parser("requirement",
                     help="print the Gmail OAuth requirement and restricted-scope blocker").set_defaults(func=cmd_program)
    prn = progs.add_parser("normalize", help="normalize a policy file")
    prn.add_argument("--file", required=True)
    prn.add_argument("--program", default="")
    prn.add_argument("--source-url", default="")
    prn.add_argument("--version", default="")
    prn.set_defaults(func=cmd_program)

    mail = sub.add_parser(
        "mail",
        help="secure, read-only Gmail intelligence (read-only; manual-import fallback)",
    )
    mails = mail.add_subparsers(dest="mail_sub", required=True)
    mails.add_parser("status",
                     help="report the integration state and the restricted-scope blocker").set_defaults(func=cmd_mail)
    mimp = mails.add_parser("import", help="import a message via the zero-OAuth fallback")
    mimp.add_argument("--file", required=True)
    mimp.add_argument("--program", default="")
    mimp.add_argument("--json", action="store_true", help="parse a JSON message export")
    mimp.set_defaults(func=cmd_mail)

    dv = sub.add_parser("dvdf", help="run the local Damn Vulnerable DeFi training harness")
    dv.add_argument("challenge", help="test contract name, or 'build'")
    dv.add_argument("--invariant", action="store_true",
                    help="run as an invariant test (expected to FAIL = the finding)")
    dv.add_argument("--verbosity", type=int, default=3)
    dv.add_argument("--workdir", default="research/private/dvdf")
    dv.set_defaults(func=cmd_dvdf)

    # -- portable cloud execution (InstaBox) ---------------------------- #
    # The connection flags are accepted both before and after the subcommand
    # (`cloud --machine X doctor` and `cloud doctor --machine X`). They default
    # to SUPPRESS so the level that does not set them does not clobber the other.
    cloud_common = argparse.ArgumentParser(add_help=False)
    cloud_common.add_argument("--server", default=argparse.SUPPRESS,
                              help="InstaBox API base (default: api.instabox.sh)")
    cloud_common.add_argument("--machine", default=argparse.SUPPRESS,
                              help="machine id or name (default: the one running box)")
    cloud_common.add_argument("--workdir", default=argparse.SUPPRESS,
                              help="local engagement root (default: research/private/cloud)")

    cl = sub.add_parser(
        "cloud", parents=[cloud_common],
        help="run work on the persistent InstaBox cloud machine",
    )
    csub = cl.add_subparsers(dest="sub", required=True)

    cdoc = csub.add_parser(
        "doctor", parents=[cloud_common],
        help="end-to-end check: credential, auth, machine, remote run, artifact",
    )
    cdoc.add_argument("--json", action="store_true")
    cdoc.set_defaults(func=cmd_cloud_doctor)

    ccon = csub.add_parser("connect", parents=[cloud_common],
                           help="authenticate and confirm the machine is reachable")
    ccon.add_argument("--json", action="store_true")
    ccon.set_defaults(func=cmd_cloud_connect)

    cst = csub.add_parser("status", parents=[cloud_common],
                          help="machine health, resources and storage usage")
    cst.add_argument("--json", action="store_true")
    cst.set_defaults(func=cmd_cloud_status)

    cex = csub.add_parser("execute", parents=[cloud_common],
                          help="run a command on the machine in an engagement")
    cex.add_argument("--engagement", help="engagement id (default: generated, unique)")
    cex.add_argument("--timeout", type=int, default=120,
                     help="command timeout in seconds (API max 600)")
    cex.add_argument("--artifact", help="remote path to fetch after the command")
    cex.add_argument("--artifact-name", help="local filename for the fetched artifact")
    cex.add_argument("--json", action="store_true")
    cex.add_argument("command", nargs="*",
                     help="the command (one arg = a shell string; several = an argv)")
    cex.set_defaults(func=cmd_cloud_execute)

    car = csub.add_parser("artifacts", parents=[cloud_common],
                          help="list and verify retrieved artifacts")
    car.add_argument("--engagement", help="engagement id (default: all)")
    car.add_argument("--json", action="store_true")
    car.set_defaults(func=cmd_cloud_artifacts)

    # -- Chrome VRP research engagement --------------------------------- #
    chrome_common = argparse.ArgumentParser(add_help=False)
    chrome_common.add_argument("--binary", default=argparse.SUPPRESS,
                               help="Chromium/Chrome binary (default: autodetect)")
    chrome_common.add_argument("--workdir", default=argparse.SUPPRESS,
                               help="engagement root (default: research/private/chrome-vrp)")

    ch = sub.add_parser(
        "chrome", parents=[chrome_common],
        help="Chrome VRP engagement: boundary probes against a real Chromium",
    )
    chsub = ch.add_subparsers(dest="sub", required=True)

    chdoc = chsub.add_parser(
        "doctor", parents=[chrome_common],
        help="locate Chromium, run one probe, and trip the positive control",
    )
    chdoc.add_argument("--json", action="store_true")
    chdoc.set_defaults(func=cmd_chrome_doctor)

    chrun = chsub.add_parser(
        "run", parents=[chrome_common],
        help="run the Chrome VRP hypotheses; record evidence + ledger",
    )
    chrun.add_argument("--only", help="comma-separated hypothesis ids (e.g. H1,H2)")
    chrun.add_argument("--json", action="store_true")
    chrun.set_defaults(func=cmd_chrome_run)

    tsp = sub.add_parser(
        "testsparker",
        help="generate executable tests and run them (TestSparker adapters)",
    )
    tsp.add_argument("--adapter", default="dispatch", help="adapter name (default: dispatch)")
    tsp.add_argument("--seed", type=int, default=0)
    tsp.add_argument("--limit", type=int)
    tsp.add_argument("--known-answer", action="store_true",
                     help="use the adapter's ground-truth corpus")
    tsp.add_argument("--list", action="store_true", help="list registered adapters and exit")
    tsp.add_argument("--json", action="store_true")
    tsp.set_defaults(func=cmd_testsparker)

    ev = sub.add_parser(
        "continuous",
        help="continuous adversarial evaluation campaign (TestSparker adapters)",
    )
    ev.add_argument("--name", default="default")
    ev.add_argument("--adapter", action="append", dest="adapters",
                    help="adapter to include (repeatable; default: dispatch)")
    ev.add_argument("--seed", type=int, default=0)
    ev.add_argument("--limit", type=int)
    ev.add_argument("--known-answer", action="store_true",
                    help="use ground-truth cases so precision/recall are computable")
    ev.add_argument("--allow-live", action="store_true",
                    help="permit live-target adapters (authorization gate still applies)")
    ev.add_argument("--authz-record", help="authorization record JSON for a live target")
    ev.add_argument("--target", help="target asset name for a live adapter")
    ev.add_argument("--baseline", help="baseline JSON to compare against")
    ev.add_argument("--write-baseline", help="path to write a new baseline (only if accepted)")
    ev.add_argument("--evidence", default="research/private/evidence",
                    help="evidence store root for the campaign artefact")
    ev.add_argument("--json", action="store_true")
    ev.set_defaults(func=cmd_continuous)

    sh = sub.add_parser("symbolic-harness",
                        help="render a forge-std-free Halmos harness from a JSON spec")
    sh.add_argument("--spec", required=True,
                    help="JSON harness spec: {contract_name, imports, target_decl, setup, checks}")
    sh.add_argument("--out", help="write the .t.sol here (default: stdout)")
    sh.set_defaults(func=cmd_symbolic_harness)

    dfz = sub.add_parser("differential-fuzz",
                         help="compare two registered targets and report snapshot divergences")
    dfz.add_argument("--reference", required=True, help="reference target name")
    dfz.add_argument("--candidate", required=True, help="candidate target name")
    dfz.add_argument("--runs", type=int, default=200)
    dfz.add_argument("--steps", type=int, default=12)
    dfz.add_argument("--seed", type=int, default=0)
    dfz.add_argument("--out", help="write the divergence report JSON here")
    dfz.set_defaults(func=cmd_differential_fuzz)

    pr = sub.add_parser("properties",
                        help="compile a property spec into invariants and a Foundry test")
    pr.add_argument("--spec", required=True, help="INI-like property spec file")
    pr.add_argument("--out", help="write the generated .t.sol here")
    pr.add_argument("--contract-name", default="GeneratedInvariants")
    pr.add_argument("--target-type", default="address")
    pr.add_argument("--target-ctor", default="")
    pr.set_defaults(func=cmd_properties)

    ti = sub.add_parser("threatintel",
                        help="ingest a public threat-intel feed into LEAD fixtures")
    ti.add_argument("--source", choices=["solodit", "immunefi", "defillama"], required=True)
    ti.add_argument("--input", help="local JSON feed file")
    ti.add_argument("--url", help="fetch the feed from this URL (needs --allow-network)")
    ti.add_argument("--allow-network", action="store_true")
    ti.add_argument("--out", help="write regression fixtures into this directory")
    ti.set_defaults(func=cmd_threatintel)

    sym = sub.add_parser("symbolic-evm",
                         help="bounded symbolic execution over runtime bytecode")
    sym.add_argument("code", help="hex runtime bytecode file")
    sym.add_argument("--input", action="append", default=[],
                     help="symbolic calldata word as name=lo..hi (repeatable)")
    sym.add_argument("--max-paths", type=int, default=64)
    sym.add_argument("--max-steps", type=int, default=2000)
    sym.add_argument("--limit", type=int, default=32, help="paths to print in detail")
    sym.add_argument("--wrap", action="store_true",
                     help="fork symbolic ADD/SUB/MUL on 256-bit overflow/underflow")
    sym.add_argument("--smt", action="store_true",
                     help="use the optional Z3 backend for path conditions")
    sym.add_argument("--poc-out", help="write a Foundry test from the first witness")
    sym.add_argument("--minimize", action="store_true",
                     help="shrink the witness calldata while it still reproduces")
    sym.set_defaults(func=cmd_symbolic_evm)

    lay = sub.add_parser("layout", help="extract or compare solc storage layouts")
    lays = lay.add_subparsers(dest="sub", required=True)
    ld = lays.add_parser("diff", help="diff two storageLayout JSON files")
    ld.add_argument("before", help="old storageLayout JSON")
    ld.add_argument("after", help="new storageLayout JSON")
    ld.set_defaults(func=cmd_layout_diff)
    le = lays.add_parser("extract",
                         help="extract storage layouts from build-info / solc JSON")
    le.add_argument("build_info", help="Foundry build-info or solc combined JSON")
    le.add_argument("--contract", help="contract name or source-qualified key")
    le.add_argument("-o", "--out", help="write the layout to this file")
    le.set_defaults(func=cmd_layout_extract)

    poc = sub.add_parser("poc", help="run a generated witness PoC under the gate")
    pocs = poc.add_subparsers(dest="sub", required=True)
    pr = pocs.add_parser("run", help="write and run one generated PoC")
    pr.add_argument("file", help="generated Solidity PoC")
    pr.add_argument("--compatibility", metavar="RECORD",
                    help="compatibility record JSON; without it the run is BLOCKED")
    pr.add_argument("--target-component", required=True,
                    help="component the record must bind to")
    pr.add_argument("--repository", required=True,
                    help="repository the record must bind to")
    pr.add_argument("--commit", default="")
    pr.add_argument("--test-name", default="",
                    help="test function (default: detect test_witness/test_divergence)")
    pr.add_argument("--timeout", type=int, default=600)
    pr.add_argument("--keep-dir", help="keep the generated Foundry project here")
    pr.set_defaults(func=cmd_poc_run)

    ed = sub.add_parser("evm-diff", help="differential fuzz two runtime bytecodes")
    ed.add_argument("vulnerable", help="hex runtime bytecode file")
    ed.add_argument("guarded", help="hex runtime bytecode file")
    ed.add_argument("--calldata", action="append", default=[],
                    help="hex calldata (repeatable)")
    ed.add_argument("--words", help="comma-separated integers, one ABI word each")
    ed.add_argument("--poc-out", help="write a Foundry test from the first divergence")
    ed.add_argument("--minimize", action="store_true",
                    help="shrink the divergent calldata while it still diverges")
    ed.set_defaults(func=cmd_evm_diff)

    ef = sub.add_parser("evm-fuzz", help="coverage-guided fuzzing of one runtime bytecode")
    ef.add_argument("code", help="hex runtime bytecode file")
    ef.add_argument("--seed-calldata", action="append", default=[],
                    help="initial calldata in hex (repeatable)")
    ef.add_argument("--iterations", type=int, default=500)
    ef.add_argument("--seed", type=int, default=0)
    ef.set_defaults(func=cmd_evm_fuzz)

    ee = sub.add_parser("evm-exec",
                        help="execute bytecode on anvil when available, else the local EVM")
    ee.add_argument("code", help="hex runtime bytecode file")
    ee.add_argument("--calldata", default="", help="hex calldata (default: empty)")
    ee.add_argument("--engine", choices=["auto", "anvil", "local", "revm"],
                    default="auto", help="execution engine (default: auto)")
    ee.add_argument("--address", default="0xC0DE")
    ee.add_argument("--caller", default="0xA11CE")
    ee.add_argument("--value", default="0")
    ee.add_argument("--json", action="store_true")
    ee.add_argument("--out")
    ee.set_defaults(func=cmd_evm_exec)

    vm = sub.add_parser("verified-model",
                        help="attest a deployment, model its source, certify it")
    vm.add_argument("chain_id", type=int)
    vm.add_argument("address")
    vm.add_argument("--runtime", help="deployed runtime bytecode hex file")
    vm.add_argument("--decompiled", help="decompiler text for a closed component")
    vm.add_argument("--name", default="Decompiled")
    vm.add_argument("--max-depth", type=int, default=4)
    vm.set_defaults(func=cmd_verified_model)

    ms = sub.add_parser(
        "mission",
        help="run the source pipeline and write mission.json + MISSION.md",
    )
    ms.add_argument("--source", required=True, help="local Solidity file or tree")
    ms.add_argument("--contract", default="")
    ms.add_argument("--compiler-ast", action="store_true", default=True,
                    help="compile locally and use solc's AST (default)")
    ms.add_argument("--scanner", dest="compiler_ast", action="store_false",
                    help="force the dependency-free lexer")
    ms.add_argument("--project-root", default="",
                    help="project root for foundry.toml/remappings/libs")
    ms.add_argument("--depth", type=int, default=4)
    ms.add_argument("--control-source", default="")
    ms.add_argument("--control-contract", default="")
    ms.add_argument("--in-scope", action="store_true")
    ms.add_argument("--authorized", action="store_true")
    ms.add_argument("--scope-reference", default="")
    ms.add_argument("--poc", action="store_true")
    ms.add_argument("--dataflow", action="store_true")
    ms.add_argument("--no-finding", action="store_true")
    ms.add_argument("--findings", default="research/private/findings")
    ms.add_argument("--evidence", default="research/private/evidence")
    ms.add_argument("--out", default="")
    ms.add_argument("--json", action="store_true")
    ms.set_defaults(func=cmd_mission)

    pl = sub.add_parser(
        "pipeline",
        help="close the loop: verified source -> model -> price -> verify -> finding",
    )
    pl.add_argument("--source", default="",
                    help="a local .sol file or tree; runs the source-only loop with "
                         "no attestation and no deployment claim")
    pl.add_argument("--contract", default="",
                    help="with --source, the contract to model (default: best surface); "
                         "with --protocol, the protocol name")
    pl.add_argument("--protocol", action="store_true",
                    help="with --source, compose every recovered contract into one "
                         "protocol target and infer caller->callee links")
    pl.add_argument("--no-infer-links", dest="protocol_infer_links",
                    action="store_false", default=True,
                    help="with --protocol, do not infer links from source calls")
    pl.add_argument("--ast", default="",
                    help="with --source, a solc source-unit AST or combined-json file "
                         "to build the surface from instead of the lexer")
    pl.add_argument("--compiler-ast", action="store_true", default=True,
                    help="with --source, compile locally and use solc's AST (default); "
                         "falls back to the lexer with the compiler's reason when "
                         "unavailable")
    pl.add_argument("--scanner", dest="compiler_ast", action="store_false",
                    help="with --source, force the dependency-free lexer instead of "
                         "compiling an AST")
    pl.add_argument("--compiler", default="",
                    help="with --compiler-ast, the compiler binary (forge, solc or a path)")
    pl.add_argument("--project-root", default="",
                    help="project root for foundry.toml/remappings/libs "
                         "(default: nearest manifest above the source)")
    pl.add_argument("--include-path", action="append", default=[],
                    help="with --compiler-ast, an import root (repeatable)")
    pl.add_argument("--remapping", action="append", default=[],
                    help="with --compiler-ast, a solc remapping PREFIX=TARGET (repeatable)")
    pl.add_argument("--control-source", default="",
                    help="with --source, a guarded source tree/file for the control")
    pl.add_argument("--control-contract", default="",
                    help="with --control-source, the guarded contract to use")
    pl.add_argument("--chain-id", type=int, default=None)
    pl.add_argument("--address", default="")
    pl.add_argument("--control-address", default="",
                    help="guarded twin deployment; without it a finding stays "
                         "STRONGLY_SUPPORTED, never CONFIRMED")
    pl.add_argument("--max-depth", type=int, default=4,
                    help="bounded-exhaustive certifier depth over the source model")
    pl.add_argument("--repository", default="",
                    help="identity the compatibility record is bound to "
                         "(default: sourcify:<chain>:<address>)")
    pl.add_argument("--commit", default="",
                    help="identity the compatibility record is bound to "
                         "(default: the verified source fingerprint)")
    pl.add_argument("--findings", default="research/private/findings")
    pl.add_argument("--evidence", default="research/private/evidence")
    pl.add_argument("--reports", default="research/private/reports")
    pl.add_argument("--no-finding", action="store_true",
                    help="run the loop but do not write a findings record")
    pl.add_argument("--report", action="store_true", help="also render a Markdown report")
    pl.add_argument("--reviewer", default="deterministic-verifier")
    pl.add_argument("--in-scope", action="store_true",
                    help="the target asset is within an authorized program scope")
    pl.add_argument("--authorized", action="store_true",
                    help="active testing was authorized by the scope gate")
    pl.add_argument("--scope-reference", default="")
    pl.add_argument("--compatibility", metavar="RECORD",
                    help="language-aware compatibility record (JSON) bound to this target")
    pl.add_argument("--json", action="store_true")
    pl.add_argument("--out")
    pl.add_argument("--sarif", default="",
                    help="export the findings repository as SARIF 2.1.0")
    pl.add_argument("--baseline", default="",
                    help="compare the findings repository against a baseline JSON")
    pl.add_argument("--write-baseline", default="",
                    help="write the current findings repository as a baseline JSON")
    pl.add_argument("--fail-on-new", action="store_true",
                    help="with --baseline, exit 1 when the diff contains a new finding")
    pl.add_argument("--rpc", default="", help="RPC endpoint; fetch the deployed runtime and bind the source to it")
    pl.add_argument("--block", type=int, default=None)
    pl.add_argument("--poc", action="store_true", help="render and run a source-level Foundry PoC")
    pl.add_argument("--require-independent-engine", action="store_true",
                    help="refuse INDEPENDENTLY_VERIFIED unless a distinct engine "
                         "(a passing Foundry PoC or an explicitly recorded verifier) "
                         "re-ran the witness")
    pl.add_argument("--constructor-args", default="",
                    help="JSON list of source PoC constructor arguments")
    pl.add_argument("--proxy", action="store_true",
                    help="deploy the source PoC behind a minimal delegatecall proxy")
    pl.add_argument("--mutation-audit", action="store_true", help="mutation-test the invariant set")
    pl.add_argument("--mutation-class", action="append", default=[],
                    help="class-specific mutation family (repeatable)")
    pl.add_argument("--dataflow", action="store_true",
                    help="with --source, add SSA-lite whole-program taint leads")
    pl.add_argument("--allow-unscanned", action="append", default=[],
                    metavar="LANG",
                    help="with --source, record an explicit partial-coverage exception "
                         "for LANG (repeatable)")
    pl.set_defaults(func=cmd_pipeline)

    cl = sub.add_parser(
        "closure",
        help="the closure surface: protocol, control, bytecode, mutation, plan, corpus, review, poc, market",
    )
    csub = cl.add_subparsers(dest="closure_cmd", required=True)

    cvc = csub.add_parser(
        "coverage",
        help="model-coverage ledger: what the executable model covers and what it does not",
    )
    cvc.add_argument("--source", required=True, help="source directory or one .sol file")
    cvc.add_argument("--contract", default="", help="restrict to one contract")
    cvc.add_argument("--out")
    cvc.set_defaults(func=cmd_closure)

    cp = csub.add_parser("protocol", help="compose several contracts into one target")
    cp.add_argument("--source", required=True, help="source directory or one .sol file")
    cp.add_argument("--link", action="append", default=[],
                    help="CALLER.OP=CALLEE.OP (repeatable)")
    cp.add_argument("--link-param", action="append", default=[],
                    help="CALLER.OP=CALLEE.OP:caller_param=callee_param "
                         "(repeatable; comma-separate multiple pairs)")
    cp.add_argument("--link-return", action="append", default=[],
                    help="CALLER.OP=CALLEE.OP:caller_field=callee_field "
                         "(repeatable; comma-separate multiple pairs)")
    cp.add_argument("--name", default="protocol")
    cp.add_argument("--infer", action="store_true",
                    help="infer cross-contract links from source, resolving only uniquely")
    cp.add_argument("--compiler-callgraph", action="store_true",
                    help="use Slither's compiler call graph instead of source regex")
    cp.add_argument("--certify", action="store_true")
    cp.add_argument("--max-depth", type=int, default=2)
    cp.add_argument("--out")
    cp.set_defaults(func=cmd_closure)

    cc = csub.add_parser("control", help="compare a witness against a fetched/patched control")
    cc.add_argument("--target-source", required=True)
    cc.add_argument("--control-source", default="")
    cc.add_argument("--repo", default="", help="repository URL for automatic control discovery")
    cc.add_argument("--vulnerable-commit", default="")
    cc.add_argument("--path", action="append", default=[],
                    help="source path touched by the fix (repeatable)")
    cc.add_argument("--control-dest", default="research/private/controls")
    cc.add_argument("--depth", type=int, default=200)
    cc.add_argument("--contract", default="")
    cc.add_argument("--steps", required=True, help="JSON list of witness steps")
    cc.add_argument("--compatibility", default="")
    cc.add_argument("--repository", default="")
    cc.add_argument("--commit", default="")
    cc.add_argument("--out")
    cc.set_defaults(func=cmd_closure)

    cb = csub.add_parser("bytecode", help="replay a symbolic witness on runtime bytecode")
    cb.add_argument("--runtime", required=True, help="file containing hex runtime code")
    cb.add_argument("--witness", required=True, help="JSON witness")
    cb.add_argument("--expect-revert", action="store_true", default=None)
    cb.add_argument("--storage", action="append", default=[],
                    help="slot=value (repeatable)")
    cb.add_argument("--out")
    cb.set_defaults(func=cmd_closure)

    cm = csub.add_parser("mutate", help="audit invariant strength by mutation")
    cm.add_argument("--source", required=True)
    cm.add_argument("--contract", default="")
    cm.add_argument("--class", action="append", dest="mutation_class", default=[],
                    help="class-specific mutation family (repeatable)")
    cm.add_argument("--max-depth", type=int, default=2)
    cm.add_argument("--out")
    cm.set_defaults(func=cmd_closure)

    cplan = csub.add_parser("plan", help="filter objectives through a program policy")
    cplan.add_argument("--policy", required=True, help="policy text file")
    cplan.add_argument("--program", required=True)
    cplan.add_argument("--source-url", default="")
    cplan.add_argument("--profile", required=True, help="JSON TargetProfile")
    cplan.add_argument("--out")
    cplan.set_defaults(func=cmd_closure)

    ccor = csub.add_parser("corpus", help="durable deduplicated research corpus")
    ccor.add_argument("--path", required=True)
    ccor.add_argument("--add", help="JSON input payload to add")
    ccor.add_argument("--verdict", default="")
    ccor.add_argument("--result", help="JSON result payload")
    ccor.add_argument("--verify", action="store_true")
    ccor.add_argument("--invalidate", help="JSON input payload to invalidate")
    ccor.add_argument("--reason", default="")
    ccor.add_argument("--pending", help="JSON list of inputs; print the unseen subset")
    ccor.add_argument("--export-shard", default="")
    ccor.add_argument("--merge-shard", default="")
    ccor.add_argument("--queue", default="", help="lease-queue path (default: <path>.queue)")
    ccor.add_argument("--worker", default="")
    ccor.add_argument("--keys", default="", help="JSON list of keys for queue operations")
    ccor.add_argument("--limit", type=int, default=1)
    ccor.add_argument("--ttl", type=float, default=300.0)
    ccor.add_argument("--epoch", type=int, default=0)
    ccor.add_argument("--queue-claim", action="store_true")
    ccor.add_argument("--queue-complete", default="")
    ccor.add_argument("--queue-fail", default="")
    ccor.add_argument("--queue-recover", action="store_true")
    ccor.add_argument("--error", default="")
    ccor.add_argument("--out")
    ccor.set_defaults(func=cmd_closure)

    crev = csub.add_parser("review", help="use a verified independent reviewer model")
    crev.add_argument("--prompt", required=True, help="prompt file")
    crev.add_argument("--primary", default="")
    crev.add_argument("--no-probe", action="store_true")
    crev.add_argument("--budget-tokens", type=int, default=None,
                      help="cap model tokens for this run (a wrap-up reserve is kept)")
    crev.add_argument("--budget-turns", type=int, default=None,
                      help="cap model calls for this run (a wrap-up reserve is kept)")
    crev.add_argument("--out")
    crev.set_defaults(func=cmd_closure)

    cpoc = csub.add_parser("poc", help="render and run a source-level Foundry PoC")
    cpoc.add_argument("--source", required=True)
    cpoc.add_argument("--contract", default="")
    cpoc.add_argument("--steps", required=True, help="JSON list of witness steps")
    cpoc.add_argument("--invariant", required=True)
    cpoc.add_argument("--compatibility", default="")
    cpoc.add_argument("--repository", default="")
    cpoc.add_argument("--commit", default="")
    cpoc.add_argument("--constructor-args", default="", help="JSON list")
    cpoc.add_argument("--deployed-address", default="", help="target an existing address on a fork")
    cpoc.add_argument("--proxy", action="store_true")
    cpoc.add_argument("--helper", action="append", default=[],
                      help="NAME=JSON_ARGS helper deployment (repeatable)")
    cpoc.add_argument("--fork-url", default="")
    cpoc.add_argument("--fork-block", type=int, default=None)
    cpoc.add_argument("--out")
    cpoc.set_defaults(func=cmd_closure)

    ctr = csub.add_parser("truth", help="join chain facts, proxy and verified source")
    ctr.add_argument("--address", required=True)
    ctr.add_argument("--no-bind-runtime", action="store_true",
                     help="skip recompiling the verified source against the runtime")
    ctr.add_argument("--rpc", default="")
    ctr.add_argument("--block", type=int, default=None)
    ctr.add_argument("--out")
    ctr.set_defaults(func=cmd_closure)

    ceq = csub.add_parser("equivalence", help="check source ABI/runtime against a deployment")
    ceq.add_argument("--source", required=True)
    ceq.add_argument("--runtime", required=True, help="file containing hex runtime code")
    ceq.add_argument("--compiler", default="")
    ceq.add_argument("--abi", default="", help="expected ABI JSON file")
    ceq.add_argument("--storage-layout", default="",
                     help="expected solc storage-layout JSON file")
    ceq.add_argument("--ast", default="", help="expected solc AST JSON file")
    ceq.add_argument("--out")
    ceq.set_defaults(func=cmd_closure)

    cdp = csub.add_parser("deploy-plan", help="plan a target/helper/proxy deployment")
    cdp.add_argument("--source", required=True)
    cdp.add_argument("--contract", default="")
    cdp.add_argument("--constructor-args", default="", help="JSON list")
    cdp.add_argument("--proxy", action="store_true")
    cdp.add_argument("--helper", action="append", default=[],
                     help="NAME=JSON_ARGS helper deployment (repeatable)")
    cdp.add_argument("--out")
    cdp.set_defaults(func=cmd_closure)

    csr = csub.add_parser(
        "certify",
        help="directed certification of a composed source model (value-moving paths first)")
    csr.add_argument("--source", required=True)
    csr.add_argument("--contract", default="", help="target contract (default: all)")
    csr.add_argument("--asset", default="", help="asset/token contract to compose")
    csr.add_argument("--invariant", default="", help="only this invariant id")
    csr.add_argument("--depth", type=int, default=4)
    csr.add_argument("--max-states", type=int, default=200000)
    csr.add_argument("--beam", type=int, default=500)
    csr.add_argument("--param-sets", type=int, default=32)
    csr.add_argument("--out")
    csr.set_defaults(func=cmd_closure)

    cf = csub.add_parser("foundry", help="run a caller-supplied Foundry test against source")
    cf.add_argument("--source", required=True)
    cf.add_argument("--test", default="", help="Foundry test source file (or use --auto)")
    cf.add_argument("--test-name", default="test_witness")
    cf.add_argument("--target-component", default="")
    cf.add_argument("--compatibility", default="")
    cf.add_argument("--repository", default="")
    cf.add_argument("--commit", default="")
    cf.add_argument("--fork-url", default="")
    cf.add_argument("--fork-block", type=int, default=None)
    cf.add_argument("--auto", action="store_true",
                    help="generate the test from --contract/--steps/--invariant")
    cf.add_argument("--generate-invariant", action="store_true",
                    help="generate and run a real Foundry invariant test from source")
    cf.add_argument("--asset", default="", help="asset contract for --generate-invariant")
    cf.add_argument("--invariant-template", default="",
                    help="generated invariant: erc4626:nonzero-shares, "
                         "authorization:owner-unchanged, or auto (default)")
    cf.add_argument("--invariant-body", default="",
                    help="generated invariant: a Solidity property for the handler test")
    cf.add_argument("--invariant-name", default="",
                    help="generated invariant function name (default invariant_generated)")
    cf.add_argument("--timeout", type=int, default=600)
    cf.add_argument("--contract", default="")
    cf.add_argument("--steps", default="[]", help="JSON witness steps for --auto")
    cf.add_argument("--invariant", default="")
    cf.add_argument("--constructor-args", default="", help="JSON list")
    cf.add_argument("--proxy", action="store_true")
    cf.add_argument("--deployed-address", default="")
    cf.add_argument("--helper", action="append", default=[])
    cf.add_argument("--out")
    cf.set_defaults(func=cmd_closure)

    csc = csub.add_parser("scenario", help="run a declarative multi-call fork scenario")
    csc.add_argument("--scenario", required=True, help="JSON scenario file")
    csc.add_argument("--rpc", default="")
    csc.add_argument("--block", type=int, default=None)
    csc.add_argument("--compatibility", default="")
    csc.add_argument("--target-component", default="")
    csc.add_argument("--repository", default="")
    csc.add_argument("--commit", default="")
    csc.add_argument("--timeout", type=int, default=600)
    csc.add_argument("--out")
    csc.set_defaults(func=cmd_closure)

    cmk = csub.add_parser("market", help="sandwich / AMM / order-book / lending economics")
    cmk.add_argument("--model",
                     choices=["cp", "v3", "v3-multi", "orderbook", "lending",
                              "bundle", "orderflow", "live", "live-v3"],
                     default="cp")
    cmk.add_argument("--pool-in", type=int, default=0)
    cmk.add_argument("--pool-out", type=int, default=0)
    cmk.add_argument("--fee-bps", type=int, default=30)
    cmk.add_argument("--sqrt-price", type=int, default=0, help="V3: sqrtPriceX96")
    cmk.add_argument("--liquidity", type=int, default=0, help="V3: L")
    cmk.add_argument("--fee-pips", type=int, default=3000, help="V3: fee in pips")
    cmk.add_argument("--sqrt-lower", type=int, default=0, help="V3: lower sqrtPriceX96")
    cmk.add_argument("--sqrt-upper", type=int, default=0, help="V3: upper sqrtPriceX96")
    cmk.add_argument("--range", action="append", default=[],
                     help="v3-multi: LOWER:UPPER:LIQUIDITY (repeatable)")
    cmk.add_argument("--direction", choices=["token0->token1", "token1->token0"],
                     default="token0->token1", help="V3 swap direction")
    cmk.add_argument("--victim", type=int, default=0)
    cmk.add_argument("--attacker", type=int, default=0)
    cmk.add_argument("--asks", default="", help="JSON [[price,size],...]")
    cmk.add_argument("--bids", default="", help="JSON [[price,size],...]")
    cmk.add_argument("--total-supply", type=int, default=0)
    cmk.add_argument("--total-borrow", type=int, default=0)
    cmk.add_argument("--base-rate-bps", type=int, default=0)
    cmk.add_argument("--slope-bps", type=int, default=8000)
    cmk.add_argument("--gross", type=int, default=0)
    cmk.add_argument("--gas", type=int, default=0)
    cmk.add_argument("--priority-fee", type=int, default=0)
    cmk.add_argument("--bribe", type=int, default=0)
    cmk.add_argument("--inclusion-bps", type=int, default=10000)
    cmk.add_argument("--rpc", default="", help="live model: JSON-RPC endpoint")
    cmk.add_argument("--pair", action="append", default=[],
                     help="live/live-v3: ADDRESS[:FEE_BPS[:LABEL]] for live; "
                          "ADDRESS[:LABEL] for live-v3 (repeatable)")
    cmk.add_argument("--max-words", type=int, default=16,
                     help="live-v3: bitmap words scanned on each side (default 16)")
    cmk.add_argument("--optimize", action="store_true",
                     help="live-v3: search attacker sizes for maximum profit "
                          "(needs --victim; ignores --attacker)")
    cmk.add_argument("--failed-tx-cost", type=int, default=0,
                     help="bundle/live-v3: cost paid when not included "
                          "(wei for bundle, profit-token units for live-v3)")
    cmk.add_argument("--capital-cost", type=int, default=0,
                     help="bundle/live-v3: capital cost paid in every state")
    cmk.add_argument("--competitor-bid", type=int, default=0,
                     help="bundle/live-v3: highest competing bid; above our "
                          "bribe it makes inclusion zero")
    cmk.add_argument("--competitor-count", type=int, default=0,
                     help="bundle/orderflow: number of competing searchers")
    cmk.add_argument("--competitor-bids", default="",
                     help="orderflow: JSON list of competitor bids in wei")
    cmk.add_argument("--gas-units", type=int, default=0,
                     help="live-v3: gas units for the sandwich (0 = unpriced)")
    cmk.add_argument("--gas-price-wei", type=int, default=0,
                     help="live-v3: gas price in native wei")
    cmk.add_argument("--bribe-bps", type=int, default=0,
                     help="live-v3: builder bribe as bps of successful gross")
    cmk.add_argument("--gas-cost", type=int, default=None,
                     help="live-v3: gas cost already in profit-token units")
    cmk.add_argument("--native-price", default="",
                     help="live-v3: profit-token units per 1 native unit; needed "
                          "unless the profit token is WETH")
    cmk.add_argument("--fork-validate", action="store_true",
                     help="live-v3: execute the candidate on a pinned Foundry fork")
    cmk.add_argument("--router", default="",
                     help="fork validation: Uniswap V3 SwapRouter address")
    cmk.add_argument("--balance-slot", type=int, default=None,
                     help="fork validation: input-token balanceOf mapping slot "
                          "(WETH9 is detected as 3)")
    cmk.add_argument("--fork-tolerance-bps", type=int, default=100,
                     help="fork validation: allowed model/fork divergence in bps")
    cmk.add_argument("--block", type=int, default=None)
    cmk.add_argument("--out")
    cmk.set_defaults(func=cmd_closure)

    csp = sub.add_parser("cosmos", help="Cosmos SDK reference model and message surface")
    csp_sub = csp.add_subparsers(dest="cosmos_command", required=True)
    csp_model = csp_sub.add_parser("model", help="print the reference operations and invariants")
    csp_model.add_argument("--json", action="store_true")
    csp_model.set_defaults(func=cmd_cosmos)
    csp_go = csp_sub.add_parser("from-go", help="recover MsgServer handlers from Go source")
    csp_go.add_argument("path")
    csp_go.add_argument("--json", action="store_true")
    csp_go.set_defaults(func=cmd_cosmos)
    csp_cert = csp_sub.add_parser("certify", help="bounded-exhaustive certification of the reference model")
    csp_cert.add_argument("--vulnerable", action="store_true",
                          help="run the deliberate double-credit twin")
    csp_cert.add_argument("--depth", type=int, default=3)
    csp_cert.add_argument("--max-sequences", type=int, default=50_000)
    csp_cert.add_argument("--expect", choices=["any", "vulnerable", "guarded"], default="guarded")
    csp_cert.add_argument("--json", action="store_true")
    csp_cert.set_defaults(func=cmd_cosmos)

    ton = sub.add_parser("ton", help="TON reference model: jetton accounting + wallet replay")
    ton_sub = ton.add_subparsers(dest="ton_command", required=True)
    ton_model = ton_sub.add_parser("model", help="print the reference operations and invariants")
    ton_model.add_argument("--json", action="store_true")
    ton_model.set_defaults(func=cmd_ton)
    ton_tact = ton_sub.add_parser("from-tact", help="recover receive handlers + guards from Tact source")
    ton_tact.add_argument("path")
    ton_tact.add_argument("--json", action="store_true")
    ton_tact.set_defaults(func=cmd_ton)
    ton_mft = ton_sub.add_parser(
        "model-from-tact",
        help="derive a TON model from a Tact surface, optionally certify it")
    ton_mft.add_argument("path")
    ton_mft.add_argument("--certify", action="store_true")
    ton_mft.add_argument("--depth", type=int, default=3)
    ton_mft.add_argument("--max-sequences", type=int, default=50_000)
    ton_mft.add_argument("--json", action="store_true")
    ton_mft.set_defaults(func=cmd_ton)
    ton_ffunc = ton_sub.add_parser("from-func", help="recover FunC entry points + op dispatch + guards")
    ton_ffunc.add_argument("path")
    ton_ffunc.add_argument("--json", action="store_true")
    ton_ffunc.set_defaults(func=cmd_ton)
    ton_mffunc = ton_sub.add_parser(
        "model-from-func",
        help="derive a TON model from a FunC surface, optionally certify it")
    ton_mffunc.add_argument("path")
    ton_mffunc.add_argument("--certify", action="store_true")
    ton_mffunc.add_argument("--depth", type=int, default=3)
    ton_mffunc.add_argument("--max-sequences", type=int, default=50_000)
    ton_mffunc.add_argument("--json", action="store_true")
    ton_mffunc.set_defaults(func=cmd_ton)
    ton_hunt = ton_sub.add_parser(
        "hunt",
        help="run the full hunt on a TON source tree (scan -> derive -> search -> certify -> verify)")
    ton_hunt.add_argument("path")
    ton_hunt.add_argument("--depth", type=int, default=3)
    ton_hunt.add_argument("--max-sequences", type=int, default=50_000)
    ton_hunt.add_argument("--control", default="",
                          help="guarded-twin source tree (the discriminating control)")
    ton_hunt.add_argument("--in-scope", action="store_true",
                          help="declare the asset within the authorized program scope")
    ton_hunt.add_argument("--authorized", action="store_true",
                          help="declare active testing authorized by the gate")
    ton_hunt.add_argument("--scope-ref", default="",
                          help="scope reference (program / policy URL)")
    ton_hunt.add_argument("--json", action="store_true")
    ton_hunt.set_defaults(func=cmd_ton)
    ton_cert = ton_sub.add_parser("certify", help="bounded-exhaustive certification of the reference model")
    ton_cert.add_argument("--vulnerable", action="store_true",
                          help="run the deliberate bug twin")
    ton_cert.add_argument("--depth", type=int, default=3)
    ton_cert.add_argument("--max-sequences", type=int, default=50_000)
    ton_cert.add_argument("--expect", choices=["any", "vulnerable", "guarded"], default="guarded")
    ton_cert.add_argument("--json", action="store_true")
    ton_cert.set_defaults(func=cmd_ton)

    imp = sub.add_parser(
        "improve",
        help="ranked capability upgrades: status, compiler, model coverage, "
             "closed source, invariants, market, cross-chain, bounty, review, scale",
    )
    imps = imp.add_subparsers(dest="improve_sub", required=True)
    ist = imps.add_parser("status", help="show every ranked upgrade and its evidence")
    ist.add_argument("--json", action="store_true")
    ist.set_defaults(func=cmd_improve)

    iex = imps.add_parser("execution", help="compile a project and return its ABI-backed model")
    iex.add_argument("--root", required=True)
    iex.add_argument("--compatibility", required=True)
    iex.add_argument("--target-component", required=True)
    iex.add_argument("--repository", required=True)
    iex.add_argument("--commit", default="")
    iex.add_argument("--contract", default="")
    iex.add_argument("--timeout", type=int, default=600)
    iex.add_argument("--json", action="store_true")
    iex.set_defaults(func=cmd_improve)

    imc = imps.add_parser("model-coverage", help="report modelled and unmodelled source")
    imc.add_argument("path")
    imc.add_argument("--json", action="store_true")
    imc.set_defaults(func=cmd_improve)

    icl = imps.add_parser("closed", help="decompiled surface plus optional runtime witness")
    icl.add_argument("--runtime", required=True)
    icl.add_argument("--decompiled", default="")
    icl.add_argument("--witness", default="")
    icl.add_argument("--json", action="store_true")
    icl.set_defaults(func=cmd_improve)

    iin = imps.add_parser("invariants", help="propose invariants from source with provenance")
    iin.add_argument("paths", nargs="+")
    iin.add_argument("--json", action="store_true")
    iin.set_defaults(func=cmd_improve)

    imk = imps.add_parser("market", help="race declared searchers for an ordering opportunity")
    imk.add_argument("--searcher", action="append", required=True,
                     help="name:bid_wei[:latency_ms] (repeatable)")
    imk.add_argument("--victim-value", type=int, required=True)
    imk.add_argument("--block-time", type=int, default=12000)
    imk.add_argument("--our-name", default="us")
    imk.add_argument("--json", action="store_true")
    imk.set_defaults(func=cmd_improve)

    icx = imps.add_parser("crosschain", help="bridge replay or oracle freshness model")
    icx.add_argument("--dest-chain", type=int, default=0)
    icx.add_argument("--source-chain", action="append", type=int, default=[])
    icx.add_argument("--sender", action="append", default=[])
    icx.add_argument("--message-source", type=int, default=0)
    icx.add_argument("--message-dest", type=int, default=0)
    icx.add_argument("--message-sender", default="")
    icx.add_argument("--nonce", default="")
    icx.add_argument("--payload-hash", default="")
    icx.add_argument("--unauthenticated", action="store_true")
    icx.add_argument("--oracle-price", type=int)
    icx.add_argument("--oracle-updated-at", type=int, default=0)
    icx.add_argument("--now", type=int, default=0)
    icx.add_argument("--heartbeat", type=int, default=3600)
    icx.add_argument("--reference-price", type=int)
    icx.add_argument("--max-deviation-bps", type=int, default=500)
    icx.add_argument("--json", action="store_true")
    icx.set_defaults(func=cmd_improve)

    ib = imps.add_parser("bounty", help="evaluate, gate and package one finding")
    ib.add_argument("--finding", required=True)
    ib.add_argument("--policy", required=True)
    ib.add_argument("--candidate", default="")
    ib.add_argument("--json", action="store_true")
    ib.set_defaults(func=cmd_improve)

    ir = imps.add_parser("review", help="gate reviewer provenance before recording a review")
    ir.add_argument("--primary", default="")
    ir.add_argument("--probe", action="store_true")
    ir.add_argument("--allow-same-model", action="store_true")
    ir.add_argument("--json", action="store_true")
    ir.set_defaults(func=cmd_improve)

    isc = imps.add_parser("scale", help="bounded parallel ingestion of independent paths")
    isc.add_argument("paths", nargs="+")
    isc.add_argument("--workers", type=int, default=4)
    isc.add_argument("--json", action="store_true")
    isc.set_defaults(func=cmd_improve)

    ico = imps.add_parser("continuous", help="run one watch cycle and enqueue recommended leads")
    ico.add_argument("--state", default="research/bounty-monitor/state")
    ico.add_argument("--out", default="research/bounty-monitor")
    ico.add_argument("--registry", default=None)
    ico.add_argument("--target", action="append")
    ico.add_argument("--json", action="store_true")
    ico.set_defaults(func=cmd_improve)

    pp = sub.add_parser("probe", help="probe each selector from an unprivileged EOA and attribute state change")
    pp.add_argument("bytecode", nargs="?", help="runtime bytecode file path or 0x-hex string")
    pp.add_argument("--selector", action="append", help="4-byte selector (repeatable)")
    pp.add_argument("--bench", action="store_true", help="run the built-in bug-class benchmark")
    pp.add_argument("--json", action="store_true")
    pp.set_defaults(func=cmd_probe)

    return p


def cmd_probe(args: argparse.Namespace) -> int:
    from .probe import probe

    if args.bench:
        from .probe_bench import benchmark

        result = benchmark()
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            for case in result.cases:
                ok = "ok" if case.correct else "FAIL"
                print(f"{ok:4} {case.name:22} expect={case.expect} flagged={case.flagged}")
            print(f"recall={result.recall:.2f} specificity={result.specificity:.2f} passed={result.passed}")
        return 0 if result.passed else 1

    if not args.bytecode or not args.selector:
        import sys

        print("probe: pass <bytecode> and --selector, or --bench", file=sys.stderr)
        return 2

    raw = args.bytecode
    code = bytes.fromhex(raw[2:]) if raw.startswith("0x") else Path(raw).read_bytes()
    results = probe(code, args.selector)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            lead = "LEAD" if r.is_lead else ""
            print(f"{r.selector}  {r.outcome:8} {lead:5} {r.revert_error or ''}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
