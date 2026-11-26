"""The search portfolio: run every strategy, union the results, be honest about it.

BLACKHEART has several search strategies, each strong where the others are weak:

  * **oracle audit** (:mod:`blackheart.assurance.oracles`) -- not a search: it asks
    whether the target's *declared invariants* can catch anything at all. Every
    other strategy is bounded by those oracles, so a weak oracle is reported here
    before any clean result can be trusted;
  * **bounded-exhaustive** (:mod:`blackheart.assurance.certify`) -- complete to a
    depth, the only one that can certify absence within a bound;
  * **coverage-guided corpus** (:mod:`blackheart.fuzz`) -- strongest on deep,
    ordered, state-gated sequences;
  * **adaptive** (:mod:`blackheart.statespace.adaptive`) -- iterative deepening
    with parameter-boundary variation and profit-guided feedback;
  * **model-guided** (:mod:`blackheart.statespace.explore`) -- hypothesis-driven
    sequence enumeration;
  * **random** (:mod:`blackheart.invariants.engine`) -- the cheap breadth baseline.

Running one and trusting it is how a bug is *missed*. This module runs all of
them on the same target, **unions** the counterexamples (deduplicated by the
invariant and the exact sequence), prices each once with the universal value
engine, and reports a **coverage ledger**: which strategy found which invariant,
what each covered, and -- crucially -- what none of them could. A strategy that
found nothing is reported as *"not found within budget"*, never as "clean"; only
the bounded-exhaustive stage is allowed to say "no counterexample exists", and
only up to its declared depth.

The portfolio is a strict superset of any single strategy: its detection set is
the union, so it can only ever find *more* than the best single search. That is
the honest sense in which it "can't miss what the others find" -- it does not, and
cannot, promise to find everything, and it says so.

Nothing here touches a network or a real system: every stage drives a local
``Target``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..fuzz import CorpusConfig, CoverageGuidedFuzzer
from ..invariants.engine import FuzzConfig, StatefulFuzzer
from ..models import AttackStep
from ..statespace.adaptive import AdaptiveConfig, AdaptiveExplorer
from ..statespace.hypotheses import HypothesisGenerator
from ..value import analyse
from .certify import CertifyConfig, CoverageCertificate, certify
from .oracles import OracleAudit, OracleAuditConfig, audit_oracles

#: The strategies the portfolio runs, in the order it runs them (cheapest and
#: most-certain first, so the certificate is known before the sampling begins).
#: ``oracles`` is not a search: it audits whether the declared invariants can
#: catch anything at all, because every other stage is bounded by them.
STRATEGIES: tuple[str, ...] = ("oracles", "exhaustive", "adaptive", "guided", "corpus", "random")


@dataclass
class PortfolioConfig:
    """Budgets for every stage. Deterministic; no wall-clock dependence."""

    seed: int = 0
    #: Bounded-exhaustive depth (the certificate bound).
    certify_depth: int = 3
    certify_max_sequences: int = 100_000
    #: Which stages to run (default: all).
    strategies: tuple[str, ...] = STRATEGIES
    #: Adaptive / guided depth and budget.
    adaptive_depth: int = 4
    adaptive_sequences: int = 2000
    guided_depth: int = 5
    #: Coverage-guided corpus budget.
    corpus_sequences: int = 4000
    corpus_depth: int = 12
    #: Random baseline budget.
    random_runs: int = 400
    random_depth: int = 12
    #: Price every counterexample once with the universal value engine.
    price_findings: bool = True

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "certify_depth": self.certify_depth,
            "certify_max_sequences": self.certify_max_sequences,
            "strategies": list(self.strategies),
            "adaptive_depth": self.adaptive_depth,
            "adaptive_sequences": self.adaptive_sequences,
            "guided_depth": self.guided_depth,
            "corpus_sequences": self.corpus_sequences,
            "corpus_depth": self.corpus_depth,
            "random_runs": self.random_runs,
            "random_depth": self.random_depth,
            "price_findings": self.price_findings,
        }


@dataclass
class StageResult:
    """What one strategy covered and found."""

    strategy: str
    ran: bool = False
    sequences: int = 0
    invariants_found: list[str] = field(default_factory=list)
    #: Invariants this strategy reached a state for but could not evaluate.
    unevaluable: list[str] = field(default_factory=list)
    note: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "ran": self.ran,
            "sequences": self.sequences,
            "invariants_found": list(self.invariants_found),
            "unevaluable": list(self.unevaluable),
            "note": self.note,
            "error": self.error,
        }


@dataclass
class PortfolioResult:
    """The union of every strategy, plus the honest coverage ledger."""

    target: str
    violations: list[dict] = field(default_factory=list)
    stages: list[StageResult] = field(default_factory=list)
    certificate: Optional[CoverageCertificate] = None
    oracle_audit: Optional[OracleAudit] = None
    config: Optional[PortfolioConfig] = None
    #: The model-coverage ledger for the target the portfolio searched.
    model_coverage: dict = field(default_factory=dict)

    @property
    def coverage_complete(self) -> bool:
        return bool(self.model_coverage.get("complete", True))

    @property
    def invariants_found(self) -> list[str]:
        return sorted({v["invariant_id"] for v in self.violations})

    @property
    def unevaluable(self) -> list[str]:
        """Invariants no strategy could evaluate: an empty result is not 'clean'."""
        return sorted({i for s in self.stages for i in s.unevaluable})

    @property
    def weak_oracles(self) -> list[str]:
        """Declared invariants the audit could not establish as trustworthy."""
        if self.oracle_audit is None:
            return []
        return [f.inv_id for f in self.oracle_audit.weak]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "violations": self.violations,
            "invariants_found": self.invariants_found,
            "weak_oracles": self.weak_oracles,
            "unevaluable": self.unevaluable,
            "stages": [s.to_dict() for s in self.stages],
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "oracle_audit": self.oracle_audit.to_dict() if self.oracle_audit else None,
            "model_coverage": dict(self.model_coverage),
            "verdict": self.verdict_line(),
            "config": self.config.to_dict() if self.config else None,
        }

    def verdict_line(self) -> str:
        """The honest one-line verdict for the whole portfolio run."""
        found = self.invariants_found
        weak = self.weak_oracles
        if found:
            line = (
                f"FOUND: {len(found)} invariant(s) broken by the portfolio "
                f"({', '.join(found)}); union of {len(self.stages)} strategies."
            )
            if weak:
                line += (f" NOTE: {len(weak)} declared invariant(s) are weak or "
                         f"unaudited ({', '.join(weak)}); a clean result on those "
                         f"proves nothing.")
            if not self.coverage_complete:
                line += " NOTE: model coverage is incomplete; the union is over the modelled surface only."
            return line
        cert = self.certificate
        if not self.coverage_complete:
            gaps = self.model_coverage.get("gaps") or []
            first = gaps[0] if gaps else {}
            where = f"{first.get('path', '')}:{first.get('line', '')}"
            what = (first.get("statement") or first.get("callee_op")
                    or first.get("name") or "unknown")
            return (
                f"INCOMPLETE MODEL COVERAGE: no strategy found a violation, but "
                f"{len(gaps)} reachable item(s) are outside the model; first at "
                f"{where} ({first.get('kind', 'gap')}: {what}). This is not a clean "
                f"target result -- model the gap before trusting a negative."
            )
        if weak:
            return (
                f"NO FINDING, BUT WEAK ORACLES: no strategy found a violation, but "
                f"{len(weak)} declared invariant(s) could not be shown to catch "
                f"anything ({', '.join(weak)}). A clean result on a weak oracle is "
                f"not evidence of safety -- strengthen the oracle before trusting it."
            )
        if cert is not None and cert.exhaustive:
            return (
                f"CERTIFIED CLEAN to depth {cert.complete_to_depth} by exhaustive "
                f"enumeration, and no other strategy found anything either, and every "
                f"declared invariant is live. Bounded: does NOT cover longer sequences, "
                f"undeclared operations/parameters, or undeclared properties."
            )
        return (
            "NOT FOUND within budget by any strategy. This is 'not found within "
            "budget', NOT a proof of absence -- the sampling strategies are "
            "incomplete, and the exhaustive stage did not complete its bound."
        )


def _dedup_key(v: dict) -> tuple:
    seq = v.get("minimal_sequence") or v.get("sequence") or []
    return (
        v["invariant_id"],
        tuple((s.get("actor"), s.get("action"), tuple(sorted(s.get("params", {}).items(), key=str)))
              for s in seq),
    )


def _normalise(violation: dict, strategy: str) -> dict:
    """A uniform counterexample record regardless of which engine produced it.

    The engines do not agree on the key for the invariant id -- the state-space
    and portfolio records use ``invariant_id``, the invariant-engine's
    ``InvariantFailure`` uses ``inv_id`` -- so both are accepted here and folded
    into one shape.
    """
    inv_id = violation.get("invariant_id") or violation.get("inv_id")
    seq = violation.get("minimal_sequence") or violation.get("sequence") or []
    return {
        "invariant_id": inv_id,
        "minimal_sequence": seq,
        "length": len(seq),
        "reachable_by_attacker": bool(violation.get("reachable_by_attacker", False)),
        "strategy": strategy,
        "observed": violation.get("observed", {}),
        "economic": violation.get("economic"),
    }


def _price_once(target: Any, v: dict, price: bool) -> None:
    """Ensure every unioned counterexample carries a priced economic account."""
    if not price or v.get("economic"):
        return
    steps = [AttackStep(index=i, actor=s["actor"], action=s["action"],
                        params=dict(s.get("params", {})),
                        target_contract=getattr(target, "name", "target"))
             for i, s in enumerate(v["minimal_sequence"])]
    v["economic"] = analyse(target, steps, v["invariant_id"],
                            getattr(target, "name", "")).to_dict()


def run_portfolio(target: Any, config: Optional[PortfolioConfig] = None) -> PortfolioResult:
    """Run every strategy on ``target``, union the results, report the ledger.

    The detection set is the union, so the portfolio is a strict superset of any
    single strategy. Each stage is isolated: a stage that raises is recorded as an
    error and does not abort the others (a search that crashes must not hide the
    counterexamples the other searches already found).
    """
    cfg = config or PortfolioConfig()
    name = getattr(target, "name", "target")
    result = PortfolioResult(target=name, config=cfg)
    try:
        from ..ingest.model_coverage import coverage_for_target

        result.model_coverage = coverage_for_target(target).to_dict()
    except Exception:  # noqa: BLE001 -- unknown coverage is not clean coverage
        result.model_coverage = {"available": False, "complete": False,
                                 "gaps": [{"kind": "coverage_error",
                                           "reason": "model coverage could not be read"}]}

    union: dict[tuple, dict] = {}

    def add(violations: list[dict], strategy: str) -> list[str]:
        found: list[str] = []
        for v in violations:
            norm = _normalise(v, strategy)
            _price_once(target, norm, cfg.price_findings)
            key = _dedup_key(norm)
            found.append(norm["invariant_id"])
            if key not in union:
                union[key] = norm
        return sorted(set(found))

    for strategy in cfg.strategies:
        stage = StageResult(strategy=strategy)
        try:
            if strategy == "oracles":
                audit = audit_oracles(target, OracleAuditConfig(
                    max_depth=min(cfg.certify_depth, 3),
                ))
                result.oracle_audit = audit
                stage.ran = True
                stage.sequences = audit.states_sampled
                stage.invariants_found = [f.inv_id for f in audit.weak]
                stage.note = (f"{len(audit.findings)} invariant(s) audited, "
                              f"{len(audit.weak)} weak")
            elif strategy == "exhaustive":
                cert = certify(target, CertifyConfig(
                    max_depth=cfg.certify_depth,
                    max_sequences=cfg.certify_max_sequences,
                    price_findings=False,
                ))
                result.certificate = cert
                stage.ran = True
                stage.sequences = cert.sequences_tested
                stage.invariants_found = add(cert.violations, "exhaustive")
                stage.note = (
                    f"exhaustive to depth {cert.complete_to_depth} "
                    f"(space={cert.sequences_in_space}, exhaustive={cert.exhaustive})"
                )
            elif strategy == "adaptive":
                rep = AdaptiveExplorer(target, AdaptiveConfig(
                    seed=cfg.seed, max_steps=cfg.adaptive_depth,
                    max_sequences=cfg.adaptive_sequences,
                )).explore()
                stage.ran = True
                stage.sequences = rep.sequences_tried
                stage.invariants_found = add([v.to_dict() for v in rep.violations], "adaptive")
            elif strategy == "guided":
                from ..statespace.explore import ExploreConfig, StateSpaceExplorer
                from ..discovery.harness import model_from_target

                # The guided explorer is model-driven. An invariant-engine target
                # (the registry targets) exposes no model, so one is derived from
                # its declared operations and invariants rather than skipped --
                # otherwise the portfolio would silently drop a strategy on
                # exactly the targets the rest of the engine uses.
                model = target.model() if hasattr(target, "model") else model_from_target(target)
                hyps = HypothesisGenerator(model).generate().hypotheses
                rep = StateSpaceExplorer(target, ExploreConfig(
                    seed=cfg.seed, max_steps=cfg.guided_depth,
                )).explore(hyps)
                stage.ran = True
                stage.sequences = rep.sequences_tried
                stage.invariants_found = add([v.to_dict() for v in rep.violations], "guided")
                stage.unevaluable = list(rep.unevaluable)
            elif strategy == "corpus":
                rep = CoverageGuidedFuzzer(target, CorpusConfig(
                    seed=cfg.seed, max_sequences=cfg.corpus_sequences,
                    max_steps=cfg.corpus_depth,
                )).run()
                stage.ran = True
                stage.sequences = rep.sequences_executed
                stage.invariants_found = add(
                    [{"invariant_id": f.inv_id,
                      "minimal_sequence": [s.to_dict() for s in f.minimal_sequence],
                      "reachable_by_attacker": f.reachable_by_attacker,
                      "observed": f.observed,
                      "economic": e}
                     for f, e in zip(rep.failures, rep.economic + [None] * len(rep.failures))],
                    "corpus")
            elif strategy == "random":
                rep = StatefulFuzzer(target, FuzzConfig(
                    runs=cfg.random_runs, steps_per_run=cfg.random_depth, seed=cfg.seed,
                )).run()
                stage.ran = True
                stage.sequences = rep.seeds_tried
                stage.invariants_found = add([f.to_dict() for f in rep.failures], "random")
                stage.unevaluable = list(rep.unevaluable)
            else:
                stage.note = f"unknown strategy {strategy!r} (skipped)"
        except Exception as exc:  # noqa: BLE001 -- one stage must not sink the portfolio
            stage.error = f"{type(exc).__name__}: {exc}"
        result.stages.append(stage)

    # A stable, useful order: shortest first, then by invariant id.
    result.violations = sorted(
        union.values(),
        key=lambda v: (v["length"], v["invariant_id"],
                       tuple((s["actor"], s["action"]) for s in v["minimal_sequence"])),
    )
    return result
