"""The universal hunt orchestrator -- compose every engine into one operation.

This module is the composition described in the package docstring. It adds no
search, no verifier, and no accounting of its own: it *sequences* the existing
engines, passes each stage's real output to the next, and records what each stage
did. A stage that raises is recorded as an error and does not sink the hunt -- the
counterexamples the earlier stages already found must survive a later stage's
failure, exactly as in :mod:`blackheart.assurance.portfolio`.

The result is a :class:`HuntResult` whose ``verdict_line`` is the one honest
sentence a caller can trust: whether anything was *independently verified*, or
only *certified*, or only a *candidate*, or *not found within the bound*, and the
bound it reached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..models import AttackStep
from ..toolchain.enforce import CompatibilityError, ExecutionTarget, guarded

#: The stages, in the order the doctrine requires. Named so a caller can run a
#: prefix of the hunt (``stages=("search", "certify")``) without editing code.
HUNT_STAGES: tuple[str, ...] = ("recall", "search", "certify", "verify", "order", "remember")

#: Where the cross-target memory lives by default. Kept identical to
#: :data:`blackheart.discovery.harness.DEFAULT_MEMORY` so the hunt and the
#: discovery engine share one store.
DEFAULT_MEMORY = "research/private/attack-memory.jsonl"


@dataclass
class HuntConfig:
    """Every budget the hunt uses. Deterministic; no wall-clock dependence."""

    #: Which stages to run (default: all, in order).
    stages: tuple[str, ...] = HUNT_STAGES
    seed: int = 0
    #: Search portfolio budgets (see :class:`blackheart.assurance.portfolio.PortfolioConfig`).
    certify_depth: int = 3
    certify_max_sequences: int = 100_000
    corpus_sequences: int = 4000
    random_runs: int = 400
    strategies: tuple[str, ...] = ()
    #: Certification: how hard to try to turn a candidate into a proof.
    concolic_rounds: int = 3
    #: Ordering search: the named mempool scenario, or "" to skip unless the
    #: target itself maps to one. ``max_attacker_steps``/``max_orderings`` bound it.
    scenario: str = ""
    max_attacker_steps: int = 3
    max_orderings: int = 4000
    #: Cross-target memory: opt-in so a plain hunt has no side effects on disk.
    memory: bool = False
    memory_path: str = DEFAULT_MEMORY
    #: A fresh-instance factory for the verifier's independent re-run. When set it
    #: replaces the default (registry lookup, else ``type(target)()``) so a derived
    #: target that needs constructor arguments -- a TON model derived from source --
    #: can re-derive itself for the re-run.
    target_factory: Optional[Callable[[], Any]] = None
    #: A control factory for the verifier's discriminating check (the guarded
    #: twin). ``None`` leaves control integrity UNKNOWN -- never assumed-pass.
    control_factory: Optional[Callable[[], Any]] = None
    #: The control's *declared* name (``--control``). It lets the hunt resolve the
    #: name the factory's target actually reports (a registry alias and its
    #: canonical name are one component), so a record that authorises the control
    #: covers the nested execution too. Empty means "unresolved": the differential
    #: check then fails closed at the gate rather than borrowing the target's grant.
    control_name: str = ""
    #: Scope/authorization facts passed straight to the verifier. ``None`` means
    #: not established (the verifier records UNKNOWN, it does not assume pass).
    in_scope: Optional[bool] = None
    scope_reference: str = ""
    authorization_gate_passed: Optional[bool] = None

    def to_dict(self) -> dict:
        return {
            "stages": list(self.stages),
            "seed": self.seed,
            "certify_depth": self.certify_depth,
            "certify_max_sequences": self.certify_max_sequences,
            "corpus_sequences": self.corpus_sequences,
            "random_runs": self.random_runs,
            "strategies": list(self.strategies),
            "concolic_rounds": self.concolic_rounds,
            "scenario": self.scenario,
            "max_attacker_steps": self.max_attacker_steps,
            "max_orderings": self.max_orderings,
            "memory": self.memory,
            "memory_path": self.memory_path,
            "control_name": self.control_name,
            "in_scope": self.in_scope,
            "scope_reference": self.scope_reference,
            "authorization_gate_passed": self.authorization_gate_passed,
        }


@dataclass
class StageOutcome:
    """What one stage did: its own verdict, and a reference to its raw payload."""

    stage: str
    ran: bool = False
    summary: str = ""
    error: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "ran": self.ran,
            "summary": self.summary,
            "error": self.error,
            "detail": self.detail,
        }


@dataclass
class HuntResult:
    """The whole hunt: every stage's outcome and one honest verdict."""

    target: str
    config: Optional[HuntConfig] = None
    stages: list[StageOutcome] = field(default_factory=list)
    #: Candidate counterexamples from the search stage, deduplicated.
    candidates: list[dict] = field(default_factory=list)
    #: Candidates the certifier turned into a *proof* (reproducible, minimal).
    certified: list[dict] = field(default_factory=list)
    #: The independent verifier's verdict per certified candidate.
    verifications: list[dict] = field(default_factory=list)
    #: Ordering-search report, when the stage ran.
    ordering: Optional[dict] = None
    #: Attack seeds recalled from the cross-target memory.
    recalled_seeds: int = 0
    #: Proven attacks written back to the memory.
    remembered: int = 0
    #: The bounded-exhaustive coverage certificate, when the search produced one.
    certificate: Optional[dict] = None
    #: The oracle audit, when the search produced one.
    oracle_audit: Optional[dict] = None
    #: Declared invariants the search reached a state for but could not evaluate.
    #: Non-empty means an empty result is "could not tell", not "clean".
    unevaluable: list[str] = field(default_factory=list)
    #: The model-coverage ledger for the hunted target.
    model_coverage: dict = field(default_factory=dict)

    # -- derived verdicts ------------------------------------------------ #

    @property
    def coverage_complete(self) -> bool:
        return bool(self.model_coverage.get("complete", True))

    @property
    def verified(self) -> list[dict]:
        """Candidates an independent verifier reproduced, reachable and controlled."""
        return [v for v in self.verifications
                if v.get("disposition") == "INDEPENDENTLY_VERIFIED"]

    @property
    def reproduced(self) -> list[dict]:
        """Reproduced and reachable, but the discriminating control was not proven."""
        return [v for v in self.verifications if v.get("disposition") == "REPRODUCED"]

    @property
    def weak_oracles(self) -> list[str]:
        """Declared invariants the audit could not establish as trustworthy."""
        audit = self.oracle_audit or {}
        if audit.get("weak_invariants"):
            return list(audit["weak_invariants"])
        return [f["inv_id"] for f in audit.get("findings", [])
                if not f.get("trustworthy", True)]

    def verdict_line(self) -> str:
        """The one honest sentence for the whole hunt."""
        if self.verified:
            invs = sorted({v["invariant_id"] for v in self.verified})
            line = (f"VERIFIED: {len(self.verified)} candidate(s) independently "
                    f"reproduced, attacker-reachable, and controlled "
                    f"({', '.join(invs)}).")
            return line + self._weak_note()
        if self.reproduced:
            invs = sorted({v["invariant_id"] for v in self.reproduced})
            line = (f"REPRODUCED, NOT YET CONTROLLED: {len(self.reproduced)} "
                    f"candidate(s) reproduced and attacker-reachable "
                    f"({', '.join(invs)}), but the discriminating control was not "
                    f"established -- supply the guarded twin before calling it a finding.")
            return line + self._weak_note()
        if self.certified:
            invs = sorted({c["invariant_id"] for c in self.certified})
            line = (f"CERTIFIED LEAD: {len(self.certified)} candidate(s) proven to "
                    f"break an invariant with a reproducible witness "
                    f"({', '.join(invs)}), but not yet independently verified.")
            return line + self._weak_note()
        if self.candidates:
            return (f"CANDIDATE LEADS ONLY: {len(self.candidates)} counterexample(s) "
                    f"found, none certified to a reproducible witness and none "
                    f"verified. Treat as leads, not findings." + self._weak_note())
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
                + self._weak_note()
            )
        cert = self.certificate or {}
        if cert.get("exhaustive"):
            return (f"NOT FOUND to depth {cert.get('complete_to_depth')} by exhaustive "
                    f"enumeration, no other strategy found anything, and every "
                    f"declared invariant is live. Bounded: does NOT cover longer "
                    f"sequences, undeclared operations/parameters, or undeclared "
                    f"properties." + self._weak_note())
        return ("NOT FOUND within budget by any strategy. This is 'not found within "
                "budget', NOT a proof of absence." + self._weak_note())

    def _weak_note(self) -> str:
        parts: list[str] = []
        weak = self.weak_oracles
        if weak:
            parts.append(
                f" NOTE: {len(weak)} declared invariant(s) could not be shown to "
                f"catch anything ({', '.join(weak)}); a clean result on a weak "
                f"oracle proves nothing."
            )
        if self.unevaluable:
            parts.append(
                f" NOTE: {len(self.unevaluable)} declared invariant(s) could not be "
                f"evaluated at all ({', '.join(self.unevaluable)}); an empty result "
                f"is 'could not tell', not 'clean'."
            )
        if not self.coverage_complete:
            gaps = self.model_coverage.get("gaps") or []
            parts.append(
                f" NOTE: model coverage is INCOMPLETE ({len(gaps)} reachable gap(s)); "
                f"the result is over the modelled surface only."
            )
        return "".join(parts)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "config": self.config.to_dict() if self.config else None,
            "stages": [s.to_dict() for s in self.stages],
            "candidates": list(self.candidates),
            "certified": list(self.certified),
            "verifications": list(self.verifications),
            "ordering": self.ordering,
            "recalled_seeds": self.recalled_seeds,
            "remembered": self.remembered,
            "certificate": self.certificate,
            "oracle_audit": self.oracle_audit,
            "unevaluable": list(self.unevaluable),
            "model_coverage": dict(self.model_coverage),
            "verdict": self.verdict_line(),
        }


# --------------------------------------------------------------------------- #
# Stage helpers -- each returns (StageOutcome, extra payload)
# --------------------------------------------------------------------------- #

def _steps_from_violation(v: dict) -> list[AttackStep]:
    seq = v.get("minimal_sequence") or v.get("sequence") or []
    return [
        AttackStep(index=i, actor=s.get("actor", "attacker"),
                   action=s.get("action", ""), params=dict(s.get("params", {})),
                   target_contract=s.get("target_contract", ""))
        for i, s in enumerate(seq)
    ]


def _recall(target: Any, cfg: HuntConfig) -> tuple[StageOutcome, list[list[AttackStep]]]:
    if not cfg.memory:
        return StageOutcome("recall", ran=False,
                            summary="memory disabled (--memory to enable)"), []
    try:
        from ..learning.transfer import AttackMemory

        mem = AttackMemory(cfg.memory_path)
        seeds = mem.seeds_for(target, limit=5, min_score=0.35)
        summary = (f"{len(seeds)} seed(s) recalled from {mem.summary()['entries']} "
                   f"remembered attack(s)") if seeds else (
                   f"no transferable seed ({mem.summary()['entries']} remembered)")
        return StageOutcome("recall", ran=True, summary=summary,
                            detail=mem.summary()), seeds
    except Exception as exc:  # noqa: BLE001 -- a failed recall must not sink the hunt
        return StageOutcome("recall", ran=True, error=f"{type(exc).__name__}: {exc}"), []


def _search(target: Any, cfg: HuntConfig) -> tuple[StageOutcome, dict]:
    from ..assurance import PortfolioConfig, run_portfolio

    kwargs: dict[str, Any] = dict(
        seed=cfg.seed,
        certify_depth=cfg.certify_depth,
        certify_max_sequences=cfg.certify_max_sequences,
        corpus_sequences=cfg.corpus_sequences,
        random_runs=cfg.random_runs,
    )
    if cfg.strategies:
        kwargs["strategies"] = cfg.strategies
    res = run_portfolio(target, PortfolioConfig(**kwargs))
    payload = res.to_dict()
    found = res.invariants_found
    summary = (f"{len(res.violations)} counterexample(s) across "
               f"{sum(1 for s in res.stages if s.ran)} strateg(ies); "
               f"invariants broken: {', '.join(found) or 'none'}")
    stage = StageOutcome("search", ran=True, summary=summary, detail=payload)
    return stage, payload


def _certify(target: Any, cfg: HuntConfig,
             candidates: list[dict]) -> tuple[StageOutcome, list[dict]]:
    from ..discovery.certify import certify_concolic, certify_numeric, certify_path

    proven: list[dict] = []
    seen: set[tuple] = set()
    for v in candidates:
        inv = v.get("invariant_id", "")
        steps = _steps_from_violation(v)
        if not steps:
            continue
        cert = certify_path(target, steps, invariant_id=inv)
        if not cert.proven:
            # Try to turn the near-miss into a proof by in-domain input mutation.
            cert = certify_concolic(target, steps, invariant_id=inv,
                                    max_rounds=cfg.concolic_rounds)
        if not cert.proven:
            # Last resort: a numeric-window ladder (fractions/ratios of the
            # declared maximum), which reaches windows boundary values miss.
            cert = certify_numeric(
                target,
                max_depth=max(cfg.certify_depth + 1, len(steps)),
                max_states=50_000,
                seed_path=steps,
            )
        if not cert.proven:
            continue
        key = (inv, tuple((s.actor, s.action, tuple(sorted(s.params.items(), key=str)))
                          for s in cert.witness))
        if key in seen:
            continue
        seen.add(key)
        proven.append({"invariant_id": inv, "certificate": cert.to_dict(),
                       "witness": [s.to_dict() for s in cert.witness],
                       "strategy": v.get("strategy", ""),
                       "economic": v.get("economic")})
    summary = (f"{len(proven)} of {len(candidates)} candidate(s) certified to a "
               f"reproducible, prefix-minimal witness")
    return StageOutcome("certify", ran=True, summary=summary), proven


def _verify(target: Any, target_factory: Callable[[], Any], cfg: HuntConfig,
            certified: list[dict]) -> tuple[StageOutcome, list[dict]]:
    from ..statespace.explore import Violation
    from ..statespace.verify import IndependentSequenceVerifier, VerifyConfig

    vcfg = VerifyConfig(
        control_factory=cfg.control_factory,
        in_scope=cfg.in_scope,
        scope_reference=cfg.scope_reference,
        authorization_gate_passed=cfg.authorization_gate_passed,
    )
    verifier = IndependentSequenceVerifier(target_factory, vcfg)
    results: list[dict] = []
    for c in certified:
        steps = [AttackStep(**s) for s in c["witness"]]
        viol = Violation(
            invariant_id=c["invariant_id"], sequence=steps, minimal_sequence=steps,
            seed=cfg.seed, actor_roles=sorted({s.actor for s in steps}),
            observed={}, reachable_by_attacker=True,
        )
        try:
            # A certified witness uses only parameters the operation declares it
            # accepts (the certifier is domain-bounded), so the attacker can
            # satisfy its own preconditions by construction -- that is a fact the
            # certifier established, not an assumption.
            r = verifier.verify(viol, preconditions_satisfiable=True)
            results.append({"invariant_id": c["invariant_id"], **r.to_dict(),
                            "economic": c.get("economic")})
        except Exception as exc:  # noqa: BLE001 -- one bad candidate must not sink the rest
            results.append({"invariant_id": c["invariant_id"],
                            "disposition": "VERIFY_ERROR",
                            "reasons": [f"{type(exc).__name__}: {exc}"]})
    by_disp: dict[str, int] = {}
    for r in results:
        by_disp[r["disposition"]] = by_disp.get(r["disposition"], 0) + 1
    summary = ("; ".join(f"{k}={v}" for k, v in sorted(by_disp.items()))
               or "no certified candidate to verify")
    if by_disp.get("VERIFY_ERROR"):
        # A count with no cause is not a status an operator can act on.
        first = next((r["reasons"][0] for r in results
                      if r["disposition"] == "VERIFY_ERROR" and r.get("reasons")), "")
        if first:
            summary += f" (first error: {_first_reason(first)})"
    return StageOutcome("verify", ran=True, summary=summary), results


def _order(target: Any, cfg: HuntConfig) -> tuple[StageOutcome, Optional[dict]]:
    from ..statespace.mempool import make_scenario, scenario_names, search_ordering

    scenario_name = cfg.scenario
    if not scenario_name:
        return StageOutcome("order", ran=False,
                            summary="no ordering scenario named (--scenario)"), None
    try:
        scenario = make_scenario(scenario_name)
    except KeyError:
        return StageOutcome("order", ran=True,
                            error=f"unknown scenario {scenario_name!r} "
                                  f"(known: {', '.join(scenario_names())})"), None
    report = search_ordering(scenario, max_attacker_steps=cfg.max_attacker_steps,
                             max_orderings=cfg.max_orderings)
    payload = report.to_dict()
    viol = report.violating
    prof = report.most_profitable
    summary = (f"{report.orderings_tried} ordering(s) tried; "
               f"violating={'yes' if viol else 'no'}, "
               f"most_profitable={prof.attacker_profit if prof else 0}")
    return StageOutcome("order", ran=True, summary=summary, detail=payload), payload


def _remember(cfg: HuntConfig, target: Any, certified: list[dict],
              verifications: list[dict]) -> tuple[StageOutcome, int]:
    if not cfg.memory:
        return StageOutcome("remember", ran=False,
                            summary="memory disabled (--memory to enable)"), 0
    # Only promote a *fully verified* attack -- one an independent verifier
    # reproduced, found attacker-reachable, and held under a discriminating
    # control. A merely-certified or reproduced-but-uncontrolled shape is still a
    # lead, and writing a lead into the universal memory would propagate an
    # unproven idea to every later target. That is the rule that keeps the memory
    # honest.
    from ..learning.transfer import AttackMemory

    verified_ids = {v["invariant_id"] for v in verifications
                    if v.get("disposition") == "INDEPENDENTLY_VERIFIED"}
    mem = AttackMemory(cfg.memory_path)
    written = 0
    for c in certified:
        if c["invariant_id"] not in verified_ids:
            continue
        steps = [AttackStep(**s) for s in c["witness"]]
        entry = mem.record_from_certificate(
            target=target, sequence=steps,
            root_cause=c["invariant_id"], invariant_id=c["invariant_id"],
            certificate=c["certificate"], outcome="verified",
            evidence="hunt: certified + independently reproduced",
        )
        if entry is not None:
            written += 1
    summary = f"{written} proven attack(s) written to {cfg.memory_path}"
    return StageOutcome("remember", ran=True, summary=summary), written


# --------------------------------------------------------------------------- #
# The hunt
# --------------------------------------------------------------------------- #

def _identity_for(target: Any) -> ExecutionTarget:
    """The identity the gate binds, with a registry alias resolved.

    An alias (``vulnerable``) and the model's canonical name (``vulnerable-vault``)
    denote the same component. The gate is told both, so a record naming either
    binds *and* the nested executions -- which re-authorise the canonical
    ``target.name`` -- stay covered. Without this the hunt boundary and the engine
    boundary compare the record against two different strings and no record can
    satisfy both.
    """
    repository = str(getattr(target, "repository", "") or "")
    commit = str(getattr(target, "commit", "") or "")
    if not isinstance(target, str):
        return ExecutionTarget(name=str(getattr(target, "name", "target")),
                               repository=repository, commit=commit)
    try:
        from ..invariants.registry import make_target

        resolved = make_target(target)
    except Exception:  # noqa: BLE001 -- an unregistered name is its own identity
        return ExecutionTarget(name=target, repository=repository, commit=commit)
    canonical = str(getattr(resolved, "name", target) or target)
    aliases = (target,) if canonical != target else ()
    return ExecutionTarget(name=canonical, repository=repository, commit=commit,
                           aliases=aliases)


def _grant_names(primary: ExecutionTarget, control_name: str) -> tuple[str, ...]:
    """Every name the record's two components denote, after alias resolution.

    Derived strictly from the primary (already resolved) and the *declared*
    control name, so it names only the components the record authorises -- never a
    third one. An unresolvable control contributes its literal name only, and the
    gate then decides.
    """
    names = {primary.name, *primary.aliases}
    if control_name:
        names.add(control_name)
        try:
            from ..invariants.registry import make_target

            resolved = make_target(control_name)
        except Exception:  # noqa: BLE001 -- an unknown name is its own identity
            pass
        else:
            names.add(str(getattr(resolved, "name", control_name)))
    return tuple(sorted(n for n in names if n))


def _first_reason(reason: str, limit: int = 200) -> str:
    """One line of a multi-line gate reason, short enough for a stage summary."""
    line = " ".join(reason.split())
    return line if len(line) <= limit else line[: limit - 3] + "..."


def hunt(target: Any, config: Optional[HuntConfig] = None,
         compatibility: object = None) -> HuntResult:
    """Run the whole pipeline on ``target`` and return the one honest verdict.

    ``target`` may be a live :class:`~blackheart.statespace.model.SequenceTarget`
    (the invariant-engine targets, an EVM adapter, or a model-derived target) or a
    target *name*; a name is resolved through the invariant-engine registry.

    Compatibility-gated: the hunt runs only under a validated record bound to this
    target, supplied here or inherited from an enclosing authorised execution. A
    differential control must be declared in that record (``control_component``);
    the hunt cannot widen the authority it was given.
    """
    identity = _identity_for(target)
    cfg = config or HuntConfig()
    with guarded(compatibility, identity, "hunt",
                 grants=_grant_names(identity, cfg.control_name)):
        return _hunt(target, cfg)


def _hunt(target: Any, config: Optional[HuntConfig] = None) -> HuntResult:
    cfg = config or HuntConfig()
    target_name = target if isinstance(target, str) else getattr(target, "name", "target")
    if isinstance(target, str):
        from ..invariants.registry import make_target

        target = make_target(target)

    name = getattr(target, "name", "target")
    result = HuntResult(target=name, config=cfg)
    try:
        from ..ingest.model_coverage import coverage_for_target

        result.model_coverage = coverage_for_target(target).to_dict()
    except Exception:  # noqa: BLE001 -- unknown coverage is not clean coverage
        result.model_coverage = {"available": False, "complete": False,
                                 "gaps": [{"kind": "coverage_error",
                                           "reason": "model coverage could not be read"}]}

    def _factory() -> Any:
        """A fresh instance of the target for an independent re-run."""
        # Prefer a name-based factory (registry) so the verifier gets a clean
        # instance; fall back to the class when the target is a bare object.
        try:
            from ..invariants.registry import make_target
            return make_target(target_name)
        except Exception:  # noqa: BLE001 -- a non-registry target re-runs itself
            return type(target)()

    target_factory: Callable[[], Any] = cfg.target_factory or _factory

    def record(stage: str, fn: Callable[[], tuple[StageOutcome, Any]]) -> Any:
        if stage not in cfg.stages:
            result.stages.append(StageOutcome(stage, ran=False, summary="skipped"))
            return None
        try:
            outcome, extra = fn()
        except CompatibilityError:
            raise
        except Exception as exc:  # noqa: BLE001 -- one stage must not sink the hunt
            result.stages.append(StageOutcome(stage, ran=True,
                                              error=f"{type(exc).__name__}: {exc}"))
            return None
        result.stages.append(outcome)
        return extra

    seeds = record("recall", lambda: _recall(target, cfg))
    result.recalled_seeds = len(seeds) if seeds else 0

    search_payload = record("search", lambda: _search(target, cfg))
    if search_payload:
        result.candidates = search_payload.get("violations", [])
        result.certificate = search_payload.get("certificate")
        result.oracle_audit = search_payload.get("oracle_audit")
        result.unevaluable = list(search_payload.get("unevaluable") or [])

    certified = record("certify", lambda: _certify(target, cfg, result.candidates))
    if certified is None:
        certified = []
    result.certified = certified

    verifications = record("verify", lambda: _verify(target, target_factory, cfg, certified))
    if verifications is None:
        verifications = []
    result.verifications = verifications

    ordering = record("order", lambda: _order(target, cfg))
    if ordering is not None:
        result.ordering = ordering

    remembered = record("remember", lambda: _remember(cfg, target, certified, verifications))
    result.remembered = remembered or 0

    return result
